//! Purging a Vessel (P4 spec rev. 25 §6.3, §6.4, §6.7, D81; file 11).
//!
//! [`Purger::purge`] runs §6.3 on a Vessel the caller has opened here (the
//! open is the fence: a new epoch; open attempts are closed by the open,
//! D69), in order:
//!
//! 2. **Pre-check**: what the coordinator says keeps it from being purged
//!    is accepted as `PurgeDeferred { checked_at: <the log's tail>, reason }`.
//!    Else the inventory (the coordinator's projection) and the local state
//!    (the dataset's guid and its layers) are put as content objects.
//! 3. **Commit** `PurgeCommitted`.  A `Predicate` refusal at accept is final
//!    for that submission: what blocks it now is accepted as
//!    `PurgeDeferred` (§10.2 row 11), and a later purge is a new
//!    submission.
//! 4. **Finish** every item by the matrix (§6.4): the replacement put and
//!    its `ReplacementInstalled` accepted before the original is deleted;
//!    an item with neither is `ItemLost`, never fabricated.
//! 6. **Verify** the retained history (`Packs::chain_after_purge`); the
//!    attestation is the chain's frames digest (D81).
//! 7. **End**: `PurgeComplete`, or `PurgeDamaged` if an item was lost.
//! 5. **Local delete**, after the end (D81: a Vessel whose dataset is gone
//!    cannot be opened to append its end record): the dataset and its
//!    layers, by the guid the local-state object names
//!    ([`Purger::delete_local`], which needs no open Vessel).  The local
//!    log stays: it is history, as the retained packs are.
//!
//! Running it again continues from what is accepted: a committed purge is
//! finished, an ended one answered.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 25, BLAKE3
//! `2a969bc87edeface4953a9f02e9d1538368fed9ced0ffbe4be52c80c7c9abf16`.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Read;
use std::sync::Arc;

use taso_core::contract::{
    logical_id, ContractRecord, Cutoff, DeferReason, Inventory, InventoryItem, ItemLost,
    LocalState, LogicalKey, ObjectKind, PurgeCommitted, PurgeComplete, PurgeDamaged, PurgeDeferred,
    ReplacementInstalled, SealRef,
};
use taso_core::coordlog::{Final, Submitted};
use taso_core::envelope::{HashVal, Lsn, Stream};
use taso_core::model::WardenId;
use taso_core::record::{LayerRef, Payload};

use crate::attempt::Failpoint;
use crate::chronicle::{ChronicleError, Layers};
use crate::coordinator::{Coord, CoordError};
use crate::coordstore::object_key_path;
use crate::pack::{frames_digest, PackError, Packs};
use crate::ship::{Sender, SharedStore};
use crate::submit::SubmitError;
use crate::verdict::{Recorded, VerdictError, Verdicts};
use crate::vessel::{Pool, Vessel, VesselError};

/// The failpoints of a purge (§10.2 rows 2 and 11), in order.
pub const FAILPOINTS: [&str; 10] = [
    "purge.after_fence",
    "ttl.between_check_and_commit",
    "purge.after_accept",
    "purge.after_replacement_put",
    "purge.before_replacement_accept",
    "purge.after_replacement_accept",
    "purge.after_original_delete",
    "purge.before_history_verify",
    "purge.before_complete",
    "purge.after_local_delete",
];

/// How a purge ended (this run, or an earlier one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Purged {
    /// Something keeps it: `PurgeDeferred` is accepted.
    Deferred(DeferReason),
    /// The commit was refused for a reason no deferral names (the
    /// coordinator's rule): Live; nothing more recorded.
    Refused(&'static str),
    /// `PurgeComplete` is accepted.
    Complete {
        /// Items replaced.
        items: u64,
        /// The retained history's frames digest.
        attestation: HashVal,
    },
    /// `PurgeDamaged` is accepted.
    Damaged {
        /// Items replaced.
        replaced: u64,
        /// Items lost.
        lost: u64,
    },
}

/// Why a purge stopped.  Nothing it did is undone; running it again
/// continues.
#[derive(Debug)]
pub enum PurgeError {
    /// The coordinator failed.
    Coord(CoordError),
    /// The store failed.
    Pack(PackError),
    /// The Vessel failed.
    Vessel(VesselError),
    /// A submission failed.
    Submit(SubmitError),
    /// An object or record does not agree with the log.
    Inconsistent(String),
    /// Not finished, nothing wrong (an accept's outcome unknown, the newest
    /// Seal not shipped): run it again.
    NotYet(String),
    /// A deliberate stop at a named failpoint (tests).
    Failpoint(&'static str),
}

impl fmt::Display for PurgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Pack(e) => write!(f, "store: {e}"),
            Self::Vessel(e) => write!(f, "vessel: {e}"),
            Self::Submit(e) => write!(f, "submit: {e}"),
            Self::Inconsistent(why) => write!(f, "inconsistent: {why}"),
            Self::NotYet(why) => write!(f, "not yet: {why}"),
            Self::Failpoint(p) => write!(f, "stopped at failpoint {p}"),
        }
    }
}

impl std::error::Error for PurgeError {}

impl From<CoordError> for PurgeError {
    fn from(e: CoordError) -> Self {
        Self::Coord(e)
    }
}
impl From<PackError> for PurgeError {
    fn from(e: PackError) -> Self {
        Self::Pack(e)
    }
}
impl From<VesselError> for PurgeError {
    fn from(e: VesselError) -> Self {
        Self::Vessel(e)
    }
}

/// Purges on this Warden.
pub struct Purger {
    /// The coordinator.
    pub coord: Arc<dyn Coord>,
    /// The store.
    pub store: SharedStore,
    /// Its key prefix.
    pub prefix: String,
    /// This Warden.
    pub warden: WardenId,
    /// `true` stops at that failpoint.
    pub failpoint: Failpoint,
}

enum Commit {
    Committed(PurgeCommitted),
    Deferred(DeferReason),
    Refused(&'static str),
}

impl Purger {
    fn stop(&self, p: &'static str) -> Result<(), PurgeError> {
        if (self.failpoint)(p) {
            Err(PurgeError::Failpoint(p))
        } else {
            Ok(())
        }
    }

    fn accepted(&self, key: LogicalKey) -> Result<Option<ContractRecord>, PurgeError> {
        Ok(match self.coord.query_logical(logical_id(&key))? {
            Some((_, Submitted::Contract(r))) => Some(r),
            Some((_, other)) => {
                return Err(PurgeError::Inconsistent(format!(
                    "a contract logical id holds {other:?}"
                )))
            }
            None => None,
        })
    }

    /// Record `rec` through the Vessel's log: the accepted record, or the
    /// coordinator's final refusal.
    fn record<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        rec: ContractRecord,
    ) -> Result<Result<ContractRecord, Final>, PurgeError> {
        let v = Verdicts {
            coord: self.coord.clone(),
            warden: self.warden,
            failpoint: crate::attempt::no_failpoints(),
        };
        match v.record(vessel, packs, rec) {
            Ok(Recorded::Accepted(r)) => Ok(Ok(r)),
            Ok(Recorded::Unknown(why)) => Err(PurgeError::NotYet(why)),
            Err(VerdictError::Submit(SubmitError::Refused(f))) => Ok(Err(f)),
            Err(VerdictError::Submit(e)) => Err(PurgeError::Submit(e)),
            Err(VerdictError::Vessel(e)) => Err(PurgeError::Vessel(e)),
            Err(VerdictError::Coord(e)) => Err(PurgeError::Coord(e)),
            Err(e) => Err(PurgeError::Inconsistent(e.to_string())),
        }
    }

    /// Record `rec`, which no rule refuses once its prerequisites hold.
    fn must<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        rec: ContractRecord,
    ) -> Result<ContractRecord, PurgeError> {
        let want = rec.logical_id();
        match self.record(vessel, packs, rec)? {
            Ok(r) if r.logical_id() == want => Ok(r),
            Ok(r) => Err(PurgeError::Inconsistent(format!("accepted {r:?}"))),
            Err(f) => Err(PurgeError::Inconsistent(format!("refused: {f:?}"))),
        }
    }

    fn put_content(&self, kind: ObjectKind, key: HashVal, bytes: &[u8]) -> Result<(), PurgeError> {
        let path = object_key_path(&self.prefix, kind, key).expect("a content kind");
        if let Some(mut r) = self.store.get(&path).map_err(PackError::Io)? {
            let mut have = Vec::new();
            r.read_to_end(&mut have).map_err(PackError::Io)?;
            if have != bytes {
                return Err(PurgeError::Inconsistent(format!(
                    "{path} holds other bytes"
                )));
            }
            return Ok(());
        }
        self.store
            .put(&path, &mut std::io::Cursor::new(bytes))
            .map_err(PackError::Io)?;
        Ok(())
    }

    fn inventory(&self, key: HashVal) -> Result<Inventory, PurgeError> {
        let path =
            object_key_path(&self.prefix, ObjectKind::Inventory, key).expect("a content kind");
        let mut r = self
            .store
            .get(&path)
            .map_err(PackError::Io)?
            .ok_or_else(|| PurgeError::Inconsistent(format!("{path} is not in the store")))?;
        let mut b = Vec::new();
        r.read_to_end(&mut b).map_err(PackError::Io)?;
        let inv = Inventory::decode(&b)
            .map_err(|e| PurgeError::Inconsistent(format!("{path}: {e:?}")))?;
        if inv.key() != key {
            return Err(PurgeError::Inconsistent(format!("{path} is not its key's")));
        }
        Ok(inv)
    }

    /// Purge `vessel`, opened here (the fence), on `pool`.
    pub fn purge<P: Pool, X: Sender>(
        &self,
        pool: &P,
        vessel: &mut Vessel<P::Layers>,
        packs: &Packs<SharedStore, X>,
    ) -> Result<Purged, PurgeError> {
        let id = vessel.id();
        // Ended already: only the local delete may be left.
        if let Some(out) = self.ended(id)? {
            if let Some(ContractRecord::PurgeCommitted(p)) = self.accepted(LogicalKey::Purge(id))? {
                self.delete_local(pool, vessel.dataset(), p.local_key)?;
            }
            return Ok(out);
        }
        self.stop("purge.after_fence")?;
        let commit = match self.accepted(LogicalKey::Purge(id))? {
            Some(ContractRecord::PurgeCommitted(p)) => p,
            Some(other) => return Err(PurgeError::Inconsistent(format!("{other:?}"))),
            None => match self.commit(pool, vessel, packs)? {
                Commit::Committed(p) => p,
                Commit::Deferred(r) => return Ok(Purged::Deferred(r)),
                Commit::Refused(rule) => return Ok(Purged::Refused(rule)),
            },
        };
        let inv = self.inventory(commit.inventory_key)?;
        // 4.
        let mut replaced: BTreeSet<Lsn> = BTreeSet::new();
        let (mut n_replaced, mut n_lost) = (0u64, 0u64);
        for item in inv.items() {
            if self.finish_item(vessel, packs, item)? {
                n_replaced += 1;
                replaced.extend(item.sections.iter().copied());
            } else {
                n_lost += 1;
            }
        }
        // 6.
        self.stop("purge.before_history_verify")?;
        let attestation = if n_lost == 0 {
            let anchor = self.coord.shipped(id)?;
            let chain = packs.chain_after_purge(Some(anchor), &replaced)?;
            Some(frames_digest(&chain.frames))
        } else {
            None
        };
        // 7.
        self.stop("purge.before_complete")?;
        let end = match attestation {
            Some(a) => ContractRecord::PurgeComplete(PurgeComplete {
                chronicle: id,
                inventory_key: commit.inventory_key,
                items_replaced: n_replaced,
                history_attestation: a,
            }),
            None => ContractRecord::PurgeDamaged(PurgeDamaged {
                chronicle: id,
                inventory_key: commit.inventory_key,
                items_replaced: n_replaced,
                items_lost: n_lost,
            }),
        };
        let out = match self.must(vessel, packs, end)? {
            ContractRecord::PurgeComplete(p) => Purged::Complete {
                items: p.items_replaced,
                attestation: p.history_attestation,
            },
            ContractRecord::PurgeDamaged(p) => Purged::Damaged {
                replaced: p.items_replaced,
                lost: p.items_lost,
            },
            other => return Err(PurgeError::Inconsistent(format!("{other:?}"))),
        };
        // 5., after the end (D81).
        self.delete_local(pool, vessel.dataset(), commit.local_key)?;
        self.stop("purge.after_local_delete")?;
        Ok(out)
    }

    /// How Chronicle `id`'s purge ended, if it did.
    pub fn ended(
        &self,
        id: taso_core::envelope::ChronicleId,
    ) -> Result<Option<Purged>, PurgeError> {
        Ok(match self.accepted(LogicalKey::PurgeEnd(id))? {
            Some(ContractRecord::PurgeComplete(p)) => Some(Purged::Complete {
                items: p.items_replaced,
                attestation: p.history_attestation,
            }),
            Some(ContractRecord::PurgeDamaged(p)) => Some(Purged::Damaged {
                replaced: p.items_replaced,
                lost: p.items_lost,
            }),
            Some(other) => return Err(PurgeError::Inconsistent(format!("{other:?}"))),
            None => None,
        })
    }

    /// Step 5 for Chronicle `id` without an open Vessel: its dataset `ds`
    /// destroyed if it is still the one its committed purge's local state
    /// names.  `Ok(false)` if there is nothing to delete (no committed
    /// purge, or the dataset is gone).
    pub fn delete_ended<P: Pool>(
        &self,
        pool: &P,
        id: taso_core::envelope::ChronicleId,
        ds: &crate::zfs::Dataset,
    ) -> Result<bool, PurgeError> {
        if self.ended(id)?.is_none() {
            return Ok(false);
        }
        let Some(ContractRecord::PurgeCommitted(p)) = self.accepted(LogicalKey::Purge(id))? else {
            return Ok(false);
        };
        if pool
            .guid(ds)
            .map_err(|e| PurgeError::Vessel(VesselError::Pool(e)))?
            .is_none()
        {
            return Ok(false);
        }
        self.delete_local(pool, ds, p.local_key)?;
        Ok(true)
    }

    /// Steps 2–3.
    fn commit<P: Pool, X: Sender>(
        &self,
        pool: &P,
        vessel: &mut Vessel<P::Layers>,
        packs: &Packs<SharedStore, X>,
    ) -> Result<Commit, PurgeError> {
        let id = vessel.id();
        if let Some(reason) = self.coord.purge_blocker(id)? {
            return self.defer(vessel, packs, reason);
        }
        let inv = Inventory::new(self.coord.purge_projection(id)?)
            .map_err(|e| PurgeError::Inconsistent(format!("the projection: {e:?}")))?;
        let local = self.local_state(pool, vessel)?;
        self.put_content(ObjectKind::Inventory, inv.key(), &inv.bytes())?;
        self.put_content(ObjectKind::Local, local.key(), &local.bytes())?;
        let cutoff = cutoff(vessel)?;
        self.stop("ttl.between_check_and_commit")?;
        let rec = ContractRecord::PurgeCommitted(PurgeCommitted {
            chronicle: id,
            cutoff,
            inventory_key: inv.key(),
            local_key: local.key(),
        });
        match self.record(vessel, packs, rec)? {
            Ok(ContractRecord::PurgeCommitted(p)) => {
                self.stop("purge.after_accept")?;
                Ok(Commit::Committed(p))
            }
            Ok(other) => Err(PurgeError::Inconsistent(format!("{other:?}"))),
            // Final for this submission (§6.3 step 3): what blocks it now.
            Err(Final::Predicate(rule)) => match self.coord.purge_blocker(id)? {
                Some(reason) => self.defer(vessel, packs, reason),
                None => Ok(Commit::Refused(rule)),
            },
            Err(f) => Err(PurgeError::Inconsistent(format!(
                "PurgeCommitted refused: {f:?}"
            ))),
        }
    }

    fn defer<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        reason: DeferReason,
    ) -> Result<Commit, PurgeError> {
        let rec = ContractRecord::PurgeDeferred(PurgeDeferred {
            chronicle: vessel.id(),
            checked_at: vessel.tail().lsn,
            reason,
        });
        match self.must(vessel, packs, rec)? {
            ContractRecord::PurgeDeferred(d) => Ok(Commit::Deferred(d.reason)),
            other => Err(PurgeError::Inconsistent(format!("{other:?}"))),
        }
    }

    /// The dataset's guid and the layers of its Seals (§6.2).
    fn local_state<P: Pool>(
        &self,
        pool: &P,
        vessel: &Vessel<P::Layers>,
    ) -> Result<LocalState, PurgeError> {
        let guid = pool
            .guid(vessel.dataset())
            .map_err(|e| PurgeError::Vessel(VesselError::Pool(e)))?
            .unwrap_or(0);
        let present: BTreeSet<Lsn> = vessel
            .chronicle()
            .layers()
            .list()
            .map_err(|e| PurgeError::Vessel(VesselError::Pool(e)))?
            .into_iter()
            .map(|(l, _)| l)
            .collect();
        let mut layers: Vec<LayerRef> = Vec::new();
        for f in frames(vessel)? {
            if let Ok(Payload::Seal(s)) = Payload::decode(&f.payload) {
                if present.contains(&f.envelope.lsn) && !layers.contains(&s.layer) {
                    layers.push(s.layer);
                }
            }
        }
        layers.sort_by_key(|l| l.get());
        Ok(LocalState {
            dataset_guid: guid,
            layers,
        })
    }

    /// One item (§6.4): `true` replaced, `false` lost.
    fn finish_item<L: Layers, X: Sender>(
        &self,
        vessel: &mut Vessel<L>,
        packs: &Packs<SharedStore, X>,
        item: &InventoryItem,
    ) -> Result<bool, PurgeError> {
        let id = vessel.id();
        let installed = match self.accepted(LogicalKey::Replacement(id, item.pack.digest))? {
            Some(ContractRecord::ReplacementInstalled(r)) => Some(r.replacement_key),
            None => None,
            Some(other) => return Err(PurgeError::Inconsistent(format!("{other:?}"))),
        };
        if self
            .accepted(LogicalKey::ItemLost(id, item.pack.digest))?
            .is_some()
        {
            return Ok(false);
        }
        let original = packs.has_pack(&item.pack.name)?;
        match (original, installed) {
            (true, None) => {
                let key = packs.install_replacement(item)?;
                self.stop("purge.after_replacement_put")?;
                self.stop("purge.before_replacement_accept")?;
                let name =
                    taso_core::contract::replacement_name(&item.pack.name).ok_or_else(|| {
                        PurgeError::Inconsistent(format!(
                            "{} has no replacement name",
                            item.pack.name
                        ))
                    })?;
                self.must(
                    vessel,
                    packs,
                    ContractRecord::ReplacementInstalled(ReplacementInstalled {
                        chronicle: id,
                        pack: item.pack.clone(),
                        replacement_key: key,
                        replacement_name: name,
                    }),
                )?;
                self.stop("purge.after_replacement_accept")?;
                packs.delete_original(item, key)?;
                self.stop("purge.after_original_delete")?;
                Ok(true)
            }
            (true, Some(key)) => {
                packs.delete_original(item, key)?;
                self.stop("purge.after_original_delete")?;
                Ok(true)
            }
            (false, Some(key)) => match packs.verify_replacement(item)? {
                Some(k) if k == key => Ok(true),
                other => Err(PurgeError::Inconsistent(format!(
                    "the replacement of {} is {other:?}, its ReplacementInstalled names {key}",
                    item.pack.name
                ))),
            },
            (false, None) => {
                if packs.verify_replacement(item)?.is_some() {
                    // A replacement put before a lost accept: install it.
                    let key = packs.install_replacement(item)?;
                    let name = taso_core::contract::replacement_name(&item.pack.name)
                        .ok_or_else(|| PurgeError::Inconsistent(item.pack.name.clone()))?;
                    self.must(
                        vessel,
                        packs,
                        ContractRecord::ReplacementInstalled(ReplacementInstalled {
                            chronicle: id,
                            pack: item.pack.clone(),
                            replacement_key: key,
                            replacement_name: name,
                        }),
                    )?;
                    return Ok(true);
                }
                self.must(
                    vessel,
                    packs,
                    ContractRecord::ItemLost(ItemLost {
                        chronicle: id,
                        pack: item.pack.clone(),
                    }),
                )?;
                Ok(false)
            }
        }
    }

    /// Step 5: the dataset and its layers, only if it is still the one the
    /// local-state object names.
    fn delete_local<P: Pool>(
        &self,
        pool: &P,
        ds: &crate::zfs::Dataset,
        local_key: HashVal,
    ) -> Result<(), PurgeError> {
        let path =
            object_key_path(&self.prefix, ObjectKind::Local, local_key).expect("a content kind");
        let mut r = self
            .store
            .get(&path)
            .map_err(PackError::Io)?
            .ok_or_else(|| PurgeError::Inconsistent(format!("{path} is not in the store")))?;
        let mut b = Vec::new();
        r.read_to_end(&mut b).map_err(PackError::Io)?;
        let local = LocalState::decode(&b)
            .map_err(|e| PurgeError::Inconsistent(format!("{path}: {e:?}")))?;
        if local.key() != local_key {
            return Err(PurgeError::Inconsistent(format!("{path} is not its key's")));
        }
        match pool
            .guid(ds)
            .map_err(|e| PurgeError::Vessel(VesselError::Pool(e)))?
        {
            None => Ok(()),
            Some(g) if g == local.dataset_guid => {
                pool.destroy(ds, g)
                    .map_err(|e| PurgeError::Vessel(VesselError::Pool(e)))?;
                Ok(())
            }
            Some(g) => Err(PurgeError::Inconsistent(format!(
                "{ds} has guid {g}, the purge's local state names {}: not deleted",
                local.dataset_guid
            ))),
        }
    }
}

fn frames<L: Layers>(vessel: &Vessel<L>) -> Result<Vec<crate::segment::Frame>, PurgeError> {
    vessel
        .chronicle()
        .frames()
        .map_err(|e| PurgeError::Vessel(VesselError::Chronicle(ChronicleError::Segment(e))))
}

/// The last Seal and the last `FsShipped` record (§6.2).
fn cutoff<L: Layers>(vessel: &Vessel<L>) -> Result<Cutoff, PurgeError> {
    let seal = vessel
        .last_seal()
        .ok_or_else(|| PurgeError::Inconsistent("a Vessel with no Seal".into()))?;
    let mut fs = Lsn::new(0);
    for f in frames(vessel)? {
        if f.envelope.stream == Stream::Ctl || f.envelope.stream == Stream::Fs {
            if let Ok(Payload::FsShipped(_)) = Payload::decode(&f.payload) {
                fs = f.envelope.lsn;
            }
        }
    }
    Ok(Cutoff {
        seal: SealRef {
            lsn: seal.lsn,
            hash: seal.hash,
        },
        fs_shipped: fs,
    })
}
