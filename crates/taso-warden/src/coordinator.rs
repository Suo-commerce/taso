//! The coordinator: ownership and the anchored head, durable (v1.0 §1 P1,
//! v0.4 §8).
//!
//! Phase 1 runs a single-node coordinator on `redb`.  It holds exactly
//! two things per Chronicle and nothing more:
//!
//! - [`Ownership`] `{ epoch, holder, sealed_prefix }`, and
//! - the anchored [`ChronicleHead`] `{ lsn, hash, epoch }`.
//!
//! Record bodies are not here.  They live with the Warden (a local
//! segment, later shipped to Garage).  The coordinator only decides which
//! head is accepted.  The Warden's order is: write the record locally and
//! fsync, then [`Coordinator::append`].  A record that was written locally
//! but refused here is outside the accepted prefix by definition and is
//! never replayed (v0.4 §8.3).
//!
//! The semantics are those of [`taso_core::model::Coordinator`], and a
//! differential property test below holds the two in lockstep: every
//! accept/refuse decision, every head and every ownership state must
//! match.  This module adds two checks the model leaves implicit — the
//! envelope's hash must verify, and its lsn must be exactly one past the
//! anchored head — and makes every state change one fsynced transaction.
//!
//! The database file is locked by `redb` while open, so a second process
//! cannot open the same coordinator.
//!
//! Normative references: v0.4 §4 (`Ownership`, `ChronicleHead`), §8.1–8.3,
//! §8.7; v1.0 §1 (P1), §3.

use std::fmt;
use std::path::Path;

use redb::{Database, Durability, ReadableDatabase, ReadableTable, Table, TableDefinition};
use taso_core::envelope::{ChronicleHead, ChronicleId, Envelope, Epoch, HashVal, Lsn};
use taso_core::model::{Ownership, WardenId};

// ── Storage layout ──────────────────────────────────────────────────

/// One row per Chronicle: key = `ChronicleId` bytes, value = [`State`]
/// in the fixed layout of [`State::encode`].
const CHRONICLES: TableDefinition<[u8; 16], &[u8]> = TableDefinition::new("taso.coordinator.chronicles");

/// Layout version byte at the start of every row.
const LAYOUT_V1: u8 = 1;

/// Encoded size of a [`ChronicleHead`]: lsn (8) + hash (32) + epoch (8).
const HEAD_LEN: usize = 8 + 32 + 8;

/// Encoded size of a row: version (1) + holder (8) + epoch (8)
/// + sealed_prefix + head.
const ROW_LEN: usize = 1 + 8 + 8 + HEAD_LEN + HEAD_LEN;

// ── Errors ──────────────────────────────────────────────────────────

/// Why the coordinator refused an operation.
///
/// The first group are decisions: the request was well-formed and the
/// answer is no.  [`CoordError::Corrupt`] and [`CoordError::Storage`] are
/// failures; nothing was changed.
#[derive(Debug)]
pub enum CoordError {
    /// No such Chronicle is registered.
    UnknownChronicle(ChronicleId),
    /// [`Coordinator::register`] on a Chronicle that already exists.
    AlreadyRegistered(ChronicleId),
    /// The envelope's hash does not verify over its own fields.
    BadHash {
        /// The lsn the envelope claimed.
        lsn: Lsn,
    },
    /// The Warden is not the current holder.
    NotHolder {
        /// Who tried.
        warden: WardenId,
        /// Who actually holds it.
        holder: WardenId,
    },
    /// The envelope's epoch is not the current epoch.
    EpochMismatch {
        /// What the envelope carried.
        record_epoch: Epoch,
        /// What the coordinator has.
        current: Epoch,
    },
    /// The envelope's `prev` is not the anchored head's hash.
    HeadMismatch {
        /// What the envelope pointed to.
        prev: HashVal,
        /// What the coordinator has.
        anchored: HashVal,
    },
    /// The envelope's lsn is not exactly one past the anchored head.
    LsnNotNext {
        /// What the envelope carried.
        lsn: Lsn,
        /// What the coordinator expected.
        expected: Lsn,
    },
    /// A stored row could not be decoded.
    Corrupt {
        /// Which Chronicle's row.
        chronicle: ChronicleId,
        /// What was wrong with it.
        reason: &'static str,
    },
    /// The storage layer failed.
    Storage(redb::Error),
}

impl fmt::Display for CoordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownChronicle(c) => write!(f, "unknown chronicle {c:?}"),
            Self::AlreadyRegistered(c) => write!(f, "chronicle {c:?} is already registered"),
            Self::BadHash { lsn } => write!(f, "envelope at lsn {} does not verify", lsn.get()),
            Self::NotHolder { warden, holder } => write!(
                f,
                "warden {} is not the holder (holder is {})",
                warden.get(),
                holder.get()
            ),
            Self::EpochMismatch { record_epoch, current } => write!(
                f,
                "epoch {} is not the current epoch {}",
                record_epoch.get(),
                current.get()
            ),
            Self::HeadMismatch { .. } => write!(f, "prev does not match the anchored head"),
            Self::LsnNotNext { lsn, expected } => write!(
                f,
                "lsn {} is not the next lsn {}",
                lsn.get(),
                expected.get()
            ),
            Self::Corrupt { chronicle, reason } => {
                write!(f, "corrupt row for chronicle {chronicle:?}: {reason}")
            }
            Self::Storage(e) => write!(f, "storage: {e}"),
        }
    }
}

impl std::error::Error for CoordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            _ => None,
        }
    }
}

/// Wrap any `redb` error.
fn storage<E: Into<redb::Error>>(e: E) -> CoordError {
    CoordError::Storage(e.into())
}

// ── State (one row) ─────────────────────────────────────────────────

/// Everything the coordinator holds for one Chronicle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    holder: WardenId,
    epoch: Epoch,
    sealed_prefix: ChronicleHead,
    head: ChronicleHead,
}

impl State {
    /// Fixed big-endian layout: version, holder, epoch, sealed_prefix, head.
    fn encode(&self) -> [u8; ROW_LEN] {
        let mut out = [0u8; ROW_LEN];
        out[0] = LAYOUT_V1;
        out[1..9].copy_from_slice(&self.holder.get().to_be_bytes());
        out[9..17].copy_from_slice(&self.epoch.get().to_be_bytes());
        encode_head(&self.sealed_prefix, &mut out[17..17 + HEAD_LEN]);
        encode_head(&self.head, &mut out[17 + HEAD_LEN..]);
        out
    }

    fn decode(chronicle: ChronicleId, b: &[u8]) -> Result<Self, CoordError> {
        let corrupt = |reason| CoordError::Corrupt { chronicle, reason };
        if b.len() != ROW_LEN {
            return Err(corrupt("wrong row length"));
        }
        if b[0] != LAYOUT_V1 {
            return Err(corrupt("unknown layout version"));
        }
        let state = Self {
            holder: WardenId::new(be_u64(&b[1..9])),
            epoch: Epoch::new(be_u64(&b[9..17])),
            sealed_prefix: decode_head(&b[17..17 + HEAD_LEN]),
            head: decode_head(&b[17 + HEAD_LEN..]),
        };
        // The anchored head always carries the current epoch (see
        // `transfer`); anything else was not written by this module.
        if state.head.epoch != state.epoch {
            return Err(corrupt("head epoch differs from ownership epoch"));
        }
        if state.sealed_prefix.lsn > state.head.lsn {
            return Err(corrupt("sealed prefix is ahead of the head"));
        }
        Ok(state)
    }

    fn ownership(&self) -> Ownership {
        Ownership {
            epoch: self.epoch,
            holder: self.holder,
            sealed_prefix: self.sealed_prefix,
        }
    }
}

fn encode_head(h: &ChronicleHead, out: &mut [u8]) {
    out[0..8].copy_from_slice(&h.lsn.get().to_be_bytes());
    out[8..40].copy_from_slice(h.hash.as_bytes());
    out[40..48].copy_from_slice(&h.epoch.get().to_be_bytes());
}

fn decode_head(b: &[u8]) -> ChronicleHead {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&b[8..40]);
    ChronicleHead {
        lsn: Lsn::new(be_u64(&b[0..8])),
        hash: HashVal::from_bytes(hash),
        epoch: Epoch::new(be_u64(&b[40..48])),
    }
}

fn be_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    u64::from_be_bytes(a)
}

// ── Coordinator ─────────────────────────────────────────────────────

type Rows<'t> = Table<'t, [u8; 16], &'static [u8]>;

/// The durable single-node coordinator (v1.0 §3: "single-node `redb`,
/// fsync").
///
/// Methods take `&self`; `redb` serialises write transactions, so one
/// `Coordinator` can be shared across a Warden's threads.
pub struct Coordinator {
    db: Database,
}

impl Coordinator {
    /// Open the coordinator at `path`, creating the file if it does not
    /// exist.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CoordError> {
        let db = Database::create(path).map_err(storage)?;
        let coord = Self { db };
        // Make sure the table exists so reads never see "no such table".
        coord.write(|_| Ok(()))?;
        Ok(coord)
    }

    /// Register a fresh Chronicle with its first holder.
    ///
    /// Epoch is [`Epoch::FIRST`], the head and the sealed prefix are the
    /// genesis head (lsn 0, [`HashVal::GENESIS`]).  Returns that head.
    pub fn register(
        &self,
        chronicle: ChronicleId,
        holder: WardenId,
    ) -> Result<ChronicleHead, CoordError> {
        self.write(|rows| {
            if load(rows, chronicle)?.is_some() {
                return Err(CoordError::AlreadyRegistered(chronicle));
            }
            let genesis = ChronicleHead {
                lsn: Lsn::new(0),
                hash: HashVal::GENESIS,
                epoch: Epoch::FIRST,
            };
            let state = State {
                holder,
                epoch: Epoch::FIRST,
                sealed_prefix: genesis,
                head: genesis,
            };
            store(rows, chronicle, &state)?;
            Ok(genesis)
        })
    }

    /// CAS append (v0.4 §8.3).
    ///
    /// The Chronicle is the envelope's.  Accepted only when, in this order:
    /// 1. the envelope's hash verifies,
    /// 2. `warden` is the current holder,
    /// 3. the envelope's epoch is the current epoch,
    /// 4. the envelope's `prev` is the anchored head's hash,
    /// 5. the envelope's lsn is the anchored head's lsn + 1.
    ///
    /// Checks 2–4 are the model's, in the model's order.  On success the
    /// anchored head advances to the envelope's head, durably, and is
    /// returned.  On refusal nothing changes.
    ///
    /// The coordinator re-validates ownership on every append; there is no
    /// separate heartbeat (v0.4 §8.7).
    pub fn append(
        &self,
        warden: WardenId,
        envelope: &Envelope,
    ) -> Result<ChronicleHead, CoordError> {
        let chronicle = envelope.chronicle;
        self.write(|rows| {
            let mut state =
                load(rows, chronicle)?.ok_or(CoordError::UnknownChronicle(chronicle))?;
            if !envelope.verify() {
                return Err(CoordError::BadHash { lsn: envelope.lsn });
            }
            if warden != state.holder {
                return Err(CoordError::NotHolder { warden, holder: state.holder });
            }
            if envelope.epoch != state.epoch {
                return Err(CoordError::EpochMismatch {
                    record_epoch: envelope.epoch,
                    current: state.epoch,
                });
            }
            if envelope.prev != state.head.hash {
                return Err(CoordError::HeadMismatch {
                    prev: envelope.prev,
                    anchored: state.head.hash,
                });
            }
            let expected = state.head.lsn.next();
            if envelope.lsn != expected {
                return Err(CoordError::LsnNotNext { lsn: envelope.lsn, expected });
            }
            state.head = ChronicleHead {
                lsn: envelope.lsn,
                hash: envelope.hash,
                epoch: state.epoch,
            };
            store(rows, chronicle, &state)?;
            Ok(state.head)
        })
    }

    /// Atomic ownership transfer (v0.4 §8.2).
    ///
    /// In one transaction: `sealed_prefix = head`, `epoch += 1`,
    /// `holder = new_holder`, and the head is re-stamped with the new epoch
    /// (as in the model).  Returns the new epoch.
    ///
    /// Transferring to the current holder is allowed: a restarted Warden
    /// takes a new epoch so that anything its previous incarnation still
    /// has in flight is fenced.
    pub fn transfer(
        &self,
        chronicle: ChronicleId,
        new_holder: WardenId,
    ) -> Result<Epoch, CoordError> {
        self.write(|rows| {
            let mut state =
                load(rows, chronicle)?.ok_or(CoordError::UnknownChronicle(chronicle))?;
            state.sealed_prefix = state.head;
            state.epoch = state.epoch.next();
            state.holder = new_holder;
            state.head.epoch = state.epoch;
            store(rows, chronicle, &state)?;
            Ok(state.epoch)
        })
    }

    /// Current ownership of a Chronicle.
    pub fn ownership(&self, chronicle: ChronicleId) -> Result<Ownership, CoordError> {
        Ok(self.read(chronicle)?.ownership())
    }

    /// The anchored head of a Chronicle (the authority, not a cache).
    pub fn head(&self, chronicle: ChronicleId) -> Result<ChronicleHead, CoordError> {
        Ok(self.read(chronicle)?.head)
    }

    // ── internals ───────────────────────────────────────────────────

    /// Run `f` in one write transaction, committed with fsync on `Ok` and
    /// aborted on `Err`.
    fn write<T>(
        &self,
        f: impl FnOnce(&mut Rows<'_>) -> Result<T, CoordError>,
    ) -> Result<T, CoordError> {
        let mut txn = self.db.begin_write().map_err(storage)?;
        // Immediate is redb's default; stated so it cannot drift.
        txn.set_durability(Durability::Immediate).map_err(storage)?;
        let out = {
            let mut rows = txn.open_table(CHRONICLES).map_err(storage)?;
            f(&mut rows)
        };
        match out {
            Ok(v) => {
                txn.commit().map_err(storage)?;
                Ok(v)
            }
            Err(e) => {
                txn.abort().map_err(storage)?;
                Err(e)
            }
        }
    }

    fn read(&self, chronicle: ChronicleId) -> Result<State, CoordError> {
        let txn = self.db.begin_read().map_err(storage)?;
        let rows = txn.open_table(CHRONICLES).map_err(storage)?;
        let guard = rows
            .get(*chronicle.as_bytes())
            .map_err(storage)?
            .ok_or(CoordError::UnknownChronicle(chronicle))?;
        State::decode(chronicle, guard.value())
    }
}

fn load(rows: &Rows<'_>, chronicle: ChronicleId) -> Result<Option<State>, CoordError> {
    match rows.get(*chronicle.as_bytes()).map_err(storage)? {
        Some(guard) => State::decode(chronicle, guard.value()).map(Some),
        None => Ok(None),
    }
}

fn store(rows: &mut Rows<'_>, chronicle: ChronicleId, state: &State) -> Result<(), CoordError> {
    rows.insert(*chronicle.as_bytes(), state.encode().as_slice())
        .map_err(storage)?;
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use taso_core::envelope::{BranchId, Stream};
    use taso_core::model::{AppendError as ModelError, Coordinator as Model, WardenModel};
    use taso_core::record::{Payload, Record};

    const A: WardenId = WardenId::new(1);
    const B: WardenId = WardenId::new(2);

    fn chron(n: u8) -> ChronicleId {
        ChronicleId::from_bytes([n; 16])
    }

    fn raw(n: u64) -> Payload {
        Payload::Raw(n.to_be_bytes().to_vec())
    }

    fn fresh() -> (tempfile::TempDir, std::path::PathBuf, Coordinator) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("coordinator.redb");
        let coord = Coordinator::open(&path).unwrap();
        (dir, path, coord)
    }

    /// A Warden that picks up the coordinator's current epoch and head.
    fn resumed(id: WardenId, c: ChronicleId, coord: &Coordinator) -> WardenModel {
        let o = coord.ownership(c).unwrap();
        let h = coord.head(c).unwrap();
        WardenModel::resume(id, c, o.epoch, h, h.lsn.next())
    }

    /// Build, submit, and on success advance the Warden.
    fn submit(
        coord: &Coordinator,
        w: &mut WardenModel,
        c: ChronicleId,
        n: u64,
    ) -> Result<ChronicleHead, CoordError> {
        let rec = w.build_record(Stream::Fs, raw(n));
        let head = coord.append(w.id(), &rec.envelope)?;
        *w = WardenModel::resume(w.id(), c, w.epoch(), head, head.lsn.next());
        Ok(head)
    }

    // ── basics ──────────────────────────────────────────────────────

    #[test]
    fn register_gives_genesis() {
        let (_d, _p, coord) = fresh();
        let h = coord.register(chron(1), A).unwrap();
        assert_eq!(h.lsn, Lsn::new(0));
        assert_eq!(h.hash, HashVal::GENESIS);
        assert_eq!(h.epoch, Epoch::FIRST);
        let o = coord.ownership(chron(1)).unwrap();
        assert_eq!((o.holder, o.epoch, o.sealed_prefix), (A, Epoch::FIRST, h));
    }

    #[test]
    fn register_twice_refused() {
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        assert!(matches!(
            coord.register(chron(1), B),
            Err(CoordError::AlreadyRegistered(_))
        ));
        assert_eq!(coord.ownership(chron(1)).unwrap().holder, A);
    }

    #[test]
    fn unknown_chronicle() {
        let (_d, _p, coord) = fresh();
        assert!(matches!(coord.head(chron(9)), Err(CoordError::UnknownChronicle(_))));
        assert!(matches!(coord.transfer(chron(9), A), Err(CoordError::UnknownChronicle(_))));
        let mut w = WardenModel::new(A, chron(9), Epoch::FIRST);
        assert!(matches!(
            submit(&coord, &mut w, chron(9), 0),
            Err(CoordError::UnknownChronicle(_))
        ));
    }

    #[test]
    fn appends_advance_the_head() {
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        let mut w = resumed(A, chron(1), &coord);
        for n in 1..=5 {
            let h = submit(&coord, &mut w, chron(1), n).unwrap();
            assert_eq!(h.lsn, Lsn::new(n));
            assert_eq!(coord.head(chron(1)).unwrap(), h);
        }
    }

    #[test]
    fn bad_hash_refused() {
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        let w = resumed(A, chron(1), &coord);
        let mut env = w.build_record(Stream::Fs, raw(1)).envelope;
        env.hash = HashVal::from_bytes([7; 32]);
        assert!(matches!(coord.append(A, &env), Err(CoordError::BadHash { .. })));
        assert_eq!(coord.head(chron(1)).unwrap().lsn, Lsn::new(0));
    }

    #[test]
    fn lsn_gap_refused() {
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        // Correct prev and epoch, lsn skips ahead.
        let rec = Record::new(
            chron(1),
            BranchId::TRUNK,
            Epoch::FIRST,
            Stream::Fs,
            Lsn::new(5),
            HashVal::GENESIS,
            raw(1),
        );
        assert!(matches!(
            coord.append(A, &rec.envelope),
            Err(CoordError::LsnNotNext { .. })
        ));
    }

    #[test]
    fn chronicles_are_independent() {
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        coord.register(chron(2), B).unwrap();
        let mut w = resumed(A, chron(1), &coord);
        submit(&coord, &mut w, chron(1), 1).unwrap();
        coord.transfer(chron(1), B).unwrap();
        assert_eq!(coord.head(chron(2)).unwrap().lsn, Lsn::new(0));
        assert_eq!(coord.ownership(chron(2)).unwrap().epoch, Epoch::FIRST);
        assert_eq!(coord.ownership(chron(2)).unwrap().holder, B);
    }

    // ── durability ──────────────────────────────────────────────────

    #[test]
    fn state_survives_reopen() {
        let (_d, path, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        let mut w = resumed(A, chron(1), &coord);
        for n in 1..=3 {
            submit(&coord, &mut w, chron(1), n).unwrap();
        }
        coord.transfer(chron(1), B).unwrap();
        let (o1, h1) = (coord.ownership(chron(1)).unwrap(), coord.head(chron(1)).unwrap());
        drop(coord);

        let coord = Coordinator::open(&path).unwrap();
        let (o2, h2) = (coord.ownership(chron(1)).unwrap(), coord.head(chron(1)).unwrap());
        assert_eq!(h1, h2);
        assert_eq!(
            (o1.epoch, o1.holder, o1.sealed_prefix),
            (o2.epoch, o2.holder, o2.sealed_prefix)
        );
        // And the new holder carries on from it.
        let mut b = resumed(B, chron(1), &coord);
        assert_eq!(submit(&coord, &mut b, chron(1), 4).unwrap().lsn, Lsn::new(4));
    }

    #[test]
    fn second_open_while_open_is_refused() {
        let (_d, path, _coord) = fresh();
        assert!(matches!(Coordinator::open(&path), Err(CoordError::Storage(_))));
    }

    #[test]
    fn corrupt_row_is_reported() {
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        coord
            .write(|rows| {
                rows.insert(*chron(1).as_bytes(), [0u8; 3].as_slice()).map_err(storage)?;
                Ok(())
            })
            .unwrap();
        assert!(matches!(coord.head(chron(1)), Err(CoordError::Corrupt { .. })));
        assert!(matches!(coord.transfer(chron(1), B), Err(CoordError::Corrupt { .. })));
    }

    #[test]
    fn row_roundtrip() {
        let s = State {
            holder: WardenId::new(u64::MAX),
            epoch: Epoch::new(7),
            sealed_prefix: ChronicleHead {
                lsn: Lsn::new(3),
                hash: HashVal::from_bytes([1; 32]),
                epoch: Epoch::new(6),
            },
            head: ChronicleHead {
                lsn: Lsn::new(9),
                hash: HashVal::from_bytes([2; 32]),
                epoch: Epoch::new(7),
            },
        };
        assert_eq!(State::decode(chron(1), &s.encode()).unwrap(), s);
    }

    // ── the reviewer interleavings (v0.4 §12 P0) ────────────────────

    /// Old Warden's CAS lands after transfer: refused, head unchanged.
    #[test]
    fn old_warden_cas_after_transfer() {
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        let mut a = resumed(A, chron(1), &coord);
        submit(&coord, &mut a, chron(1), 1).unwrap();
        // A builds (and, in the real Warden, fsyncs locally) a record…
        let stale = a.build_record(Stream::Fs, raw(2));
        // …then ownership moves to B.
        coord.transfer(chron(1), B).unwrap();
        let before = coord.head(chron(1)).unwrap();
        assert!(matches!(
            coord.append(A, &stale.envelope),
            Err(CoordError::NotHolder { .. })
        ));
        assert_eq!(coord.head(chron(1)).unwrap(), before);
        assert_eq!(coord.ownership(chron(1)).unwrap().sealed_prefix.lsn, Lsn::new(1));
    }

    /// Same, but the transfer is to A itself (a restarted A): the old
    /// incarnation's record is fenced by epoch.
    #[test]
    fn old_incarnation_fenced_by_epoch() {
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        let a_old = resumed(A, chron(1), &coord);
        let stale = a_old.build_record(Stream::Fs, raw(1));
        coord.transfer(chron(1), A).unwrap();
        assert!(matches!(
            coord.append(A, &stale.envelope),
            Err(CoordError::EpochMismatch { .. })
        ));
        let mut a_new = resumed(A, chron(1), &coord);
        submit(&coord, &mut a_new, chron(1), 1).unwrap();
    }

    /// Two Wardens both believe they own the Chronicle: exactly one wins
    /// each slot, and the loser cannot catch up by guessing.
    #[test]
    fn two_wardens_believe_ownership() {
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        let mut a = resumed(A, chron(1), &coord);
        // B starts at genesis believing it holds epoch 1 too.
        let mut b = WardenModel::new(B, chron(1), Epoch::FIRST);
        submit(&coord, &mut a, chron(1), 1).unwrap();
        assert!(matches!(
            submit(&coord, &mut b, chron(1), 1),
            Err(CoordError::NotHolder { .. })
        ));
        coord.transfer(chron(1), B).unwrap();
        // A still believes; refused.  B's stale view (epoch 1, genesis)
        // is refused too until it resumes from the coordinator.
        assert!(submit(&coord, &mut a, chron(1), 2).is_err());
        assert!(matches!(
            submit(&coord, &mut b, chron(1), 2),
            Err(CoordError::EpochMismatch { .. })
        ));
        let mut b = resumed(B, chron(1), &coord);
        assert_eq!(submit(&coord, &mut b, chron(1), 2).unwrap().lsn, Lsn::new(2));
    }

    // ── differential: redb coordinator == model coordinator ─────────

    #[derive(Clone, Debug)]
    enum Op {
        /// Warden `i` builds a record from its own view and submits it.
        Append(usize),
        /// Ownership moves to Warden `i`.
        Transfer(usize),
        /// Warden `i` re-reads epoch and head from the coordinator.
        Resume(usize),
        /// Close and reopen the database file.
        Reopen,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            5 => (0..2usize).prop_map(Op::Append),
            1 => (0..2usize).prop_map(Op::Transfer),
            2 => (0..2usize).prop_map(Op::Resume),
            1 => Just(Op::Reopen),
        ]
    }

    fn same_refusal(m: &ModelError, r: &CoordError) -> bool {
        match (m, r) {
            (
                ModelError::NotHolder { warden: w1, holder: h1 },
                CoordError::NotHolder { warden: w2, holder: h2 },
            ) => w1 == w2 && h1 == h2,
            (
                ModelError::EpochMismatch { record_epoch: e1, current: c1 },
                CoordError::EpochMismatch { record_epoch: e2, current: c2 },
            ) => e1 == e2 && c1 == c2,
            (
                ModelError::HeadMismatch { prev: p1, anchored: a1 },
                CoordError::HeadMismatch { prev: p2, anchored: a2 },
            ) => p1 == p2 && a1 == a2,
            _ => false,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn redb_coordinator_matches_model(ops in proptest::collection::vec(op(), 1..60)) {
            let c = chron(1);
            let ids = [A, B];
            let (_d, path, coord) = fresh();
            let mut coord = Some(coord);
            coord.as_ref().unwrap().register(c, A).unwrap();
            let mut model = Model::new(c, A);
            // Both start at genesis believing they hold epoch 1.
            let mut wardens = [
                WardenModel::new(A, c, Epoch::FIRST),
                WardenModel::new(B, c, Epoch::FIRST),
            ];

            for (n, op) in ops.into_iter().enumerate() {
                match op {
                    Op::Append(i) => {
                        let rec = wardens[i].build_record(Stream::Fs, raw(n as u64));
                        let m = model.append(ids[i], rec.clone());
                        let r = coord.as_ref().unwrap().append(ids[i], &rec.envelope);
                        match (m, r) {
                            (Ok(hm), Ok(hr)) => {
                                prop_assert_eq!(hm, hr);
                                wardens[i] = WardenModel::resume(
                                    ids[i], c, wardens[i].epoch(), hr, hr.lsn.next(),
                                );
                            }
                            (Err(em), Err(er)) => prop_assert!(
                                same_refusal(&em, &er),
                                "model {:?} vs redb {:?}", em, er
                            ),
                            (m, r) => prop_assert!(false, "model {:?} vs redb {:?}", m, r),
                        }
                    }
                    Op::Transfer(i) => {
                        let em = model.transfer(ids[i]);
                        let er = coord.as_ref().unwrap().transfer(c, ids[i]).unwrap();
                        prop_assert_eq!(em, er);
                    }
                    Op::Resume(i) => {
                        wardens[i] = resumed(ids[i], c, coord.as_ref().unwrap());
                    }
                    Op::Reopen => {
                        drop(coord.take());
                        coord = Some(Coordinator::open(&path).unwrap());
                    }
                }
                let co = coord.as_ref().unwrap();
                let (mo, ro) = (model.ownership(), co.ownership(c).unwrap());
                prop_assert_eq!(model.head(), co.head(c).unwrap());
                prop_assert_eq!(mo.epoch, ro.epoch);
                prop_assert_eq!(mo.holder, ro.holder);
                prop_assert_eq!(mo.sealed_prefix, ro.sealed_prefix);
            }
        }
    }
}
