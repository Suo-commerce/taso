//! Submitting a record that a Chronicle's own log carries to the
//! coordinator log (P4 spec rev. 17 §1.2; file 5f-1).
//!
//! [`submit`] takes a record already appended to the Chronicle's local
//! log (a contract record, or a Lineage for the Birth row) and has it
//! accepted, in the order every P4 submission follows:
//!
//! 1. **Logical lookup first.**  An accepted record for its logical id is
//!    the answer, whatever its digest (the caller compares).
//! 2. **Put, then accept** (principle 5).  The log is shipped up to the
//!    record and the shipped anchor advanced, so the pack carrying it is
//!    in the store before anything is announced.
//! 3. **Announce, accept** with the head `query { chronicle }` reports;
//!    `HeadMoved` cancels and announces a new submission; `NotReadable`
//!    retries the same one; `Conflict` answers the accepted record.
//!
//! The submission counter (`attempt_no`, §9) lives with the caller, one
//! per epoch.
//!
//! [`crate::genesis`] and [`crate::template`] carry their own copies of
//! this path; they are to be joined to this one when P4 is simplified.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 17, BLAKE3
//! `097a3eb0375596aa60927260b971deeaf350b70c08067234ad2e656cb88ae369`.

use std::fmt;

use taso_core::contract::submission_id;
use taso_core::coordlog::{Answer, Final, Head, Submitted, Transient};
use taso_core::envelope::{HashVal, Stream};
use taso_core::model::WardenId;
use taso_core::record::Payload;

use crate::chronicle::{Chronicle, ChronicleError, Layers};
use crate::coordinator::{Coord, CoordError};
use crate::pack::{name_bounds, PackError, Packs};
use crate::segment::Position;
use crate::ship::{ObjectStore, Sender};

/// How often a `NotReadable` accept is retried.
const NOT_READABLE_TRIES: u32 = 5;

/// How many times a record is resubmitted after `HeadMoved`.
const HEAD_MOVED_TRIES: u64 = 3;

/// Why a submission was not accepted.
#[derive(Debug)]
pub enum SubmitError {
    /// The coordinator failed (maybe with an unknown outcome).
    Coord(CoordError),
    /// The local log failed.
    Chronicle(ChronicleError),
    /// Shipping failed.
    Pack(PackError),
    /// The record is not in the Chronicle's local log.
    NotInLog,
    /// This submission can never be accepted (not a `Conflict`: that
    /// answers the accepted record).
    Refused(Final),
    /// It stayed transiently refused past the retries.
    NotAccepted(Transient),
    /// The log's answers do not agree with each other.
    Inconsistent(&'static str),
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Chronicle(e) => write!(f, "log: {e}"),
            Self::Pack(e) => write!(f, "packs: {e}"),
            Self::NotInLog => f.write_str("the record is not in the Chronicle's local log"),
            Self::Refused(r) => write!(f, "refused: {r:?}"),
            Self::NotAccepted(t) => write!(f, "not accepted: {t:?}"),
            Self::Inconsistent(why) => write!(f, "inconsistent: {why}"),
        }
    }
}

impl std::error::Error for SubmitError {}

impl From<CoordError> for SubmitError {
    fn from(e: CoordError) -> Self {
        Self::Coord(e)
    }
}

impl From<ChronicleError> for SubmitError {
    fn from(e: ChronicleError) -> Self {
        Self::Chronicle(e)
    }
}

impl From<PackError> for SubmitError {
    fn from(e: PackError) -> Self {
        Self::Pack(e)
    }
}

/// The record accepted for `logical`, if any.
pub fn accepted(coord: &dyn Coord, logical: HashVal) -> Result<Option<Submitted>, CoordError> {
    Ok(coord.query_logical(logical)?.map(|(_, r)| r))
}

/// Where in the local log the frame carrying `record` is.
fn position_of<L: Layers>(
    chronicle: &Chronicle<L>,
    record: &Submitted,
) -> Result<Position, SubmitError> {
    let digest = record.digest();
    for f in chronicle.frames().map_err(ChronicleError::from)? {
        if f.envelope.stream != Stream::Ctl {
            continue;
        }
        let carried = match Payload::decode(&f.payload) {
            Ok(Payload::Contract(r)) => Submitted::Contract(*r).digest() == digest,
            Ok(Payload::Lineage(lineage)) => {
                Submitted::Birth {
                    chronicle: chronicle.id(),
                    lineage,
                }
                .digest()
                    == digest
            }
            _ => false,
        };
        if carried {
            return Ok(Position {
                lsn: f.envelope.lsn,
                hash: f.envelope.hash,
            });
        }
    }
    Err(SubmitError::NotInLog)
}

/// Have `record`, which `chronicle`'s local log already carries,
/// accepted; the record accepted for its logical id (this one, or the
/// one another submission got accepted first: compare).  `attempt` is
/// the caller's submission counter for this epoch.
pub fn submit<L: Layers, S: ObjectStore, X: Sender>(
    coord: &dyn Coord,
    warden: WardenId,
    chronicle: &Chronicle<L>,
    packs: &Packs<S, X>,
    record: Submitted,
    attempt: &mut u64,
) -> Result<Submitted, SubmitError> {
    if let Some(r) = accepted(coord, record.logical_id())? {
        return Ok(r);
    }
    let pack = put(coord, warden, chronicle, packs, &record)?;
    accept(coord, warden, chronicle, record, pack, attempt)
}

/// The put half of [`submit`]: ship `chronicle`'s log up to the frame
/// carrying `record` and advance the shipped anchor to it; the name of the
/// shipped pack that carries it.
pub fn put<L: Layers, S: ObjectStore, X: Sender>(
    coord: &dyn Coord,
    warden: WardenId,
    chronicle: &Chronicle<L>,
    packs: &Packs<S, X>,
    record: &Submitted,
) -> Result<String, SubmitError> {
    let at = position_of(chronicle, record)?;
    // Put, then accept: the log up to the record, and the anchor.
    packs.ship_log(&chronicle.segments(), at)?;
    coord.advance_shipped(warden, chronicle.id(), chronicle.epoch(), at)?;
    let pack = packs
        .pack_names()?
        .into_iter()
        .find(|n| {
            name_bounds(n)
                .is_some_and(|(end, base, fs)| fs.is_none() && base < at.lsn && at.lsn <= end)
        })
        .ok_or(SubmitError::Inconsistent(
            "no shipped pack carries the record",
        ))?;
    Ok(pack)
}

/// The accept half of [`submit`]: announce and accept `record`, carried
/// by the shipped `pack` ([`put`]); the record accepted for its logical
/// id.
pub fn accept<L: Layers>(
    coord: &dyn Coord,
    warden: WardenId,
    chronicle: &Chronicle<L>,
    record: Submitted,
    pack: String,
    attempt: &mut u64,
) -> Result<Submitted, SubmitError> {
    let logical = record.logical_id();
    let digest = record.digest();
    let (id, epoch) = (chronicle.id(), chronicle.epoch());
    for _ in 0..HEAD_MOVED_TRIES {
        let sub = submission_id(logical, digest, epoch, *attempt);
        *attempt += 1;
        if let Err(a) = coord.announce(warden, id, epoch, sub, logical, digest)? {
            return final_answer(coord, logical, a);
        }
        let mut tries = 0;
        loop {
            let head = coord.query_chronicle(id)?.map_or(Head::EMPTY, |v| v.head);
            let a = coord.accept(warden, id, epoch, sub, head, pack.clone(), record.clone())?;
            match a {
                Answer::Accepted { .. } | Answer::AlreadyAccepted { .. } => {
                    return accepted(coord, logical)?
                        .ok_or(SubmitError::Inconsistent("accepted, but not in the log"));
                }
                Answer::Refused(Transient::NotReadable) if tries + 1 < NOT_READABLE_TRIES => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(200 << tries));
                }
                Answer::Refused(Transient::HeadMoved { .. }) => {
                    coord.cancel(warden, id, epoch, sub)?;
                    break;
                }
                Answer::Refused(last) => {
                    let _ = coord.cancel(warden, id, epoch, sub);
                    return Err(SubmitError::NotAccepted(last));
                }
                Answer::FinalRefused(_) => return final_answer(coord, logical, a),
            }
        }
    }
    Err(SubmitError::NotAccepted(Transient::HeadMoved {
        head: coord.query_chronicle(id)?.map_or(Head::EMPTY, |v| v.head),
    }))
}

fn final_answer(coord: &dyn Coord, logical: HashVal, a: Answer) -> Result<Submitted, SubmitError> {
    match a {
        Answer::FinalRefused(Final::Conflict)
        | Answer::Accepted { .. }
        | Answer::AlreadyAccepted { .. } => accepted(coord, logical)?.ok_or(
            SubmitError::Inconsistent("answered accepted or Conflict, but nothing is accepted"),
        ),
        Answer::FinalRefused(r) => Err(SubmitError::Refused(r)),
        Answer::Refused(t) => Err(SubmitError::NotAccepted(t)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use taso_core::contract::{ContractRecord, NominationRefusal, NominationRefused, SealRef};
    use taso_core::coordlog::ClaimAuthority;
    use taso_core::envelope::{ChronicleId, Lsn};

    use crate::chronicle::LayerError;
    use crate::coordinator::{Coordinator, LogConfig};
    use crate::coordstore::CoordStore;
    use crate::ship::{ByteStream, LocalStore, SharedStore};
    use crate::zfs::Dataset;

    const PREFIX: &str = "taso";

    struct NoLayers;
    impl Layers for NoLayers {
        fn snapshot(&mut self, _: Lsn, _: HashVal) -> Result<(), LayerError> {
            Err("no layers".into())
        }
        fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError> {
            Ok(Vec::new())
        }
        fn destroy(&mut self, _: Lsn) -> Result<(), LayerError> {
            Ok(())
        }
    }
    struct NoSend;
    impl Sender for NoSend {
        fn send(&self, _: &Dataset, _: Option<&str>, _: Lsn) -> std::io::Result<ByteStream> {
            Err(std::io::Error::other("no fs"))
        }
    }

    struct World {
        dir: tempfile::TempDir,
        store: SharedStore,
        coord: Arc<Coordinator>,
    }

    fn world() -> World {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("store")).unwrap();
        let store: SharedStore = Arc::new(LocalStore::new(dir.path().join("store")));
        let coord = Arc::new(
            Coordinator::open_with(
                dir.path().join("coord.redb"),
                LogConfig {
                    store: Arc::new(CoordStore::new(store.clone(), PREFIX)),
                    ..LogConfig::default()
                },
            )
            .unwrap(),
        );
        World { dir, store, coord }
    }

    /// A Chronicle of warden `w`, claimed and open, and its packs.
    fn chron(w: &World, id: u8, warden: u64) -> (Chronicle<NoLayers>, Packs<SharedStore, NoSend>) {
        let c = ChronicleId::from_bytes([id; 16]);
        w.coord
            .claim_chronicle(c, WardenId::new(warden), ClaimAuthority::Vessel)
            .unwrap();
        let d = w.dir.path().join(format!("c{id}"));
        std::fs::create_dir_all(&d).unwrap();
        let (ch, _) =
            Chronicle::open(&d, w.coord.clone(), c, WardenId::new(warden), NoLayers).unwrap();
        (ch, Packs::new(w.store.clone(), NoSend, PREFIX, c).unwrap())
    }

    /// A diagnostic record (no predicate): the NominationRefused row.
    fn refused(c: ChronicleId, reason: NominationRefusal) -> ContractRecord {
        ContractRecord::NominationRefused(NominationRefused {
            chronicle: c,
            seal: SealRef {
                lsn: Lsn::new(4),
                hash: HashVal::from_bytes([4; 32]),
            },
            exclude: BTreeSet::new(),
            reason,
            input_manifest_key: None,
        })
    }

    #[test]
    fn a_record_in_the_log_is_shipped_and_accepted_once() {
        let w = world();
        let (mut ch, packs) = chron(&w, 1, 1);
        let rec = refused(ch.id(), NominationRefusal::SealNotAccepted);
        let mut attempt = 0;
        // Not in the log yet: refused before anything is shipped.
        assert!(matches!(
            submit(
                &*w.coord,
                WardenId::new(1),
                &ch,
                &packs,
                Submitted::Contract(rec.clone()),
                &mut attempt
            ),
            Err(SubmitError::NotInLog)
        ));
        ch.append(Stream::Ctl, Payload::Contract(Box::new(rec.clone())))
            .unwrap();
        let got = submit(
            &*w.coord,
            WardenId::new(1),
            &ch,
            &packs,
            Submitted::Contract(rec.clone()),
            &mut attempt,
        )
        .unwrap();
        assert_eq!(got, Submitted::Contract(rec.clone()));
        // Shipped and anchored before it was accepted.
        assert_eq!(w.coord.shipped(ch.id()).unwrap().lsn, Lsn::new(1));
        // Again: the logical lookup answers; nothing new is announced.
        let before = attempt;
        let again = submit(
            &*w.coord,
            WardenId::new(1),
            &ch,
            &packs,
            Submitted::Contract(rec),
            &mut attempt,
        )
        .unwrap();
        assert_eq!(again, got);
        assert_eq!(attempt, before);
        assert_eq!(
            w.coord
                .query_chronicle(ch.id())
                .unwrap()
                .unwrap()
                .accepted
                .len(),
            1
        );
    }

    #[test]
    fn another_record_accepted_first_is_the_answer() {
        let w = world();
        let (mut ch, packs) = chron(&w, 1, 1);
        let first = refused(ch.id(), NominationRefusal::SealNotAccepted);
        let second = refused(ch.id(), NominationRefusal::BadExclude);
        assert_eq!(
            first.logical_id(),
            second.logical_id(),
            "one Seal and exclusion"
        );
        let mut attempt = 0;
        ch.append(Stream::Ctl, Payload::Contract(Box::new(first.clone())))
            .unwrap();
        submit(
            &*w.coord,
            WardenId::new(1),
            &ch,
            &packs,
            Submitted::Contract(first.clone()),
            &mut attempt,
        )
        .unwrap();
        ch.append(Stream::Ctl, Payload::Contract(Box::new(second.clone())))
            .unwrap();
        let got = submit(
            &*w.coord,
            WardenId::new(1),
            &ch,
            &packs,
            Submitted::Contract(second),
            &mut attempt,
        )
        .unwrap();
        assert_eq!(
            got,
            Submitted::Contract(first),
            "the accepted one, for the caller to compare"
        );
    }

    #[test]
    fn a_fenced_epoch_is_refused_stale() {
        let w = world();
        let (mut ch, packs) = chron(&w, 1, 1);
        let rec = refused(ch.id(), NominationRefusal::SealNotAccepted);
        ch.append(Stream::Ctl, Payload::Contract(Box::new(rec.clone())))
            .unwrap();
        // Another Warden takes the Chronicle over before the submission.
        let own = w.coord.ownership(ch.id()).unwrap();
        w.coord
            .transfer_if(ch.id(), WardenId::new(2), (own.holder, own.epoch))
            .unwrap();
        let mut attempt = 0;
        let e = submit(
            &*w.coord,
            WardenId::new(1),
            &ch,
            &packs,
            Submitted::Contract(rec),
            &mut attempt,
        )
        .unwrap_err();
        assert!(
            matches!(
                e,
                SubmitError::Coord(_) | SubmitError::Refused(Final::StaleEpoch)
            ),
            "{e}"
        );
        assert!(w
            .coord
            .query_chronicle(ch.id())
            .unwrap()
            .unwrap()
            .accepted
            .is_empty());
    }
}
