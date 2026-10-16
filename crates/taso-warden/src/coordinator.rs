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
//! # The `Coord` trait
//!
//! Everything a Warden asks of a coordinator is the [`Coord`] trait.
//! [`Coordinator`] (redb, in-process) is one implementation; a coordinator
//! behind a socket, so that a Warden on another node can be reborn against
//! it (v1.0 §1 P2), is another.  Both must pass the same differential test
//! against the model (`conformance`, in the tests).
//!
//! A failure whose outcome is unknown — storage, a corrupt row, a lost
//! connection — is told apart from a refusal by
//! [`CoordError::outcome_unknown`].  The difference matters: after a
//! refusal the Warden cuts its frame and is fenced; after an unknown
//! outcome it must not cut anything, because the CAS may have landed, and
//! only recovery against the anchored head can settle it.
//!
//! Normative references: v0.4 §4 (`Ownership`, `ChronicleHead`), §8.1–8.3,
//! §8.7; v1.0 §1 (P1), §3.

use std::fmt;
use std::path::Path;

use redb::{Database, Durability, ReadableDatabase, ReadableTable, Table, TableDefinition};
use taso_core::envelope::{ChronicleHead, ChronicleId, Envelope, Epoch, HashVal, Lsn};
use taso_core::model::{Ownership, WardenId};

use crate::segment::Position;

// ── Storage layout ──────────────────────────────────────────────────

/// One row per Chronicle: key = `ChronicleId` bytes, value = [`State`]
/// in the fixed layout of [`State::encode`].
const CHRONICLES: TableDefinition<[u8; 16], &[u8]> = TableDefinition::new("taso.coordinator.chronicles");

/// Layout version byte at the start of every row.
const LAYOUT_V1: u8 = 1;

/// Layout version with the shipped anchor.  Rows written before it read
/// as shipped = genesis.
const LAYOUT_V2: u8 = 2;

/// Encoded size of a [`ChronicleHead`]: lsn (8) + hash (32) + epoch (8).
const HEAD_LEN: usize = 8 + 32 + 8;

/// Encoded size of a row: version (1) + holder (8) + epoch (8)
/// + sealed_prefix + head.
const ROW_LEN_V1: usize = 1 + 8 + 8 + HEAD_LEN + HEAD_LEN;

/// Encoded size of a v2 row: v1, then shipped lsn (8) + hash (32).
const ROW_LEN: usize = ROW_LEN_V1 + 8 + 32;

// ── Errors ──────────────────────────────────────────────────────────

/// Why the coordinator refused an operation.
///
/// The first group are decisions: the request was well-formed and the
/// answer is no; nothing was changed.  [`CoordError::Corrupt`],
/// [`CoordError::Storage`] and [`CoordError::Unavailable`] are failures
/// whose outcome is unknown ([`CoordError::outcome_unknown`]).
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
    /// A batch append that is empty, or holds an envelope of another
    /// Chronicle than its first.
    BadBatch {
        /// The lsn of the offending envelope (0 for an empty batch).
        lsn: Lsn,
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
    /// A shipped position past the anchored head.
    ShippedAhead {
        /// What was reported.
        to: Lsn,
        /// The anchored head.
        head: Lsn,
    },
    /// A shipped position that names another record than the coordinator
    /// knows at that lsn (the head, or the current shipped anchor).
    ShippedConflict {
        /// Where.
        lsn: Lsn,
    },
    /// The coordinator could not be reached, or the connection broke before
    /// an answer arrived.  The request may or may not have been applied.
    Unavailable(std::io::Error),
}

impl CoordError {
    /// True if it is unknown whether the request was applied.
    ///
    /// For an append this means the CAS may have landed: the Warden must
    /// not cut its frame, and must reopen to let recovery decide.  False
    /// means the coordinator answered and the answer was no: nothing
    /// changed.
    ///
    /// The match is exhaustive on purpose: a new variant does not compile
    /// until it is classified.
    pub fn outcome_unknown(&self) -> bool {
        match self {
            Self::Corrupt { .. } | Self::Storage(_) | Self::Unavailable(_) => true,
            Self::UnknownChronicle(_)
            | Self::AlreadyRegistered(_)
            | Self::BadHash { .. }
            | Self::NotHolder { .. }
            | Self::EpochMismatch { .. }
            | Self::HeadMismatch { .. }
            | Self::LsnNotNext { .. }
            | Self::BadBatch { .. }
            | Self::ShippedAhead { .. }
            | Self::ShippedConflict { .. } => false,
        }
    }
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
            Self::BadBatch { lsn } => write!(f, "bad batch at lsn {}: empty, or another chronicle", lsn.get()),
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
            Self::ShippedAhead { to, head } => {
                write!(f, "shipped lsn {} is past the anchored head {}", to.get(), head.get())
            }
            Self::ShippedConflict { lsn } => write!(f, "shipped position at lsn {} names another record", lsn.get()),
            Self::Unavailable(e) => write!(f, "coordinator unavailable: {e}"),
        }
    }
}

impl std::error::Error for CoordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Unavailable(e) => Some(e),
            _ => None,
        }
    }
}

// ── The trait ───────────────────────────────────────────────────────

/// What a Warden asks of a coordinator (v0.4 §8.1–8.3, §8.7).
///
/// Semantics are those of [`taso_core::model::Coordinator`]; every
/// implementation must pass `conformance` (in the tests).  Each method is one atomic,
/// durable step: on `Ok` it happened, on a refusal nothing changed, and on
/// an error with [`CoordError::outcome_unknown`] either may be true.
pub trait Coord: Send + Sync {
    /// Register a fresh Chronicle with its first holder; returns the
    /// genesis head (lsn 0, [`HashVal::GENESIS`], [`Epoch::FIRST`]).
    fn register(&self, chronicle: ChronicleId, holder: WardenId) -> Result<ChronicleHead, CoordError>;

    /// CAS append: accept `envelope` as the next record of its Chronicle,
    /// or refuse it.  On success returns the new anchored head.
    fn append(&self, warden: WardenId, envelope: &Envelope) -> Result<ChronicleHead, CoordError>;

    /// CAS append of consecutive records of one Chronicle, all or none, in
    /// one durable transaction: each must pass [`Coord::append`]'s checks
    /// against the head the one before it leaves.  On success returns the
    /// new anchored head.
    fn append_batch(&self, warden: WardenId, envelopes: &[Envelope]) -> Result<ChronicleHead, CoordError>;

    /// Atomic ownership transfer: `sealed_prefix = head`, `epoch += 1`,
    /// `holder = new_holder`.  Returns the new epoch.
    fn transfer(&self, chronicle: ChronicleId, new_holder: WardenId) -> Result<Epoch, CoordError>;

    /// Current ownership of a Chronicle.
    fn ownership(&self, chronicle: ChronicleId) -> Result<Ownership, CoordError>;

    /// The anchored head of a Chronicle (the authority, not a cache).
    fn head(&self, chronicle: ChronicleId) -> Result<ChronicleHead, CoordError>;

    /// The holder reports that its log up to `to` is durable in the object
    /// store (a pack put returned).  Same holder and epoch checks as an
    /// append; `to` may not be past the head, nor name another record at
    /// the head or at the current anchor.  The anchor only moves forward:
    /// a report at or below it changes nothing.  Returns the anchor after.
    ///
    /// Rebirth verifies the shipped chain against this anchor: a store
    /// holding a forged history, or missing packs, cannot pass.
    fn advance_shipped(
        &self,
        warden: WardenId,
        chronicle: ChronicleId,
        epoch: Epoch,
        to: Position,
    ) -> Result<Position, CoordError>;

    /// How far the Chronicle is known to be shipped (genesis if never).
    fn shipped(&self, chronicle: ChronicleId) -> Result<Position, CoordError>;
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
    shipped: Position,
}

impl State {
    /// Fixed big-endian layout v2: version, holder, epoch, sealed_prefix,
    /// head, shipped lsn, shipped hash.
    fn encode(&self) -> [u8; ROW_LEN] {
        let mut out = [0u8; ROW_LEN];
        out[0] = LAYOUT_V2;
        out[1..9].copy_from_slice(&self.holder.get().to_be_bytes());
        out[9..17].copy_from_slice(&self.epoch.get().to_be_bytes());
        encode_head(&self.sealed_prefix, &mut out[17..17 + HEAD_LEN]);
        encode_head(&self.head, &mut out[17 + HEAD_LEN..ROW_LEN_V1]);
        out[ROW_LEN_V1..ROW_LEN_V1 + 8].copy_from_slice(&self.shipped.lsn.get().to_be_bytes());
        out[ROW_LEN_V1 + 8..].copy_from_slice(self.shipped.hash.as_bytes());
        out
    }

    /// Reads v2 rows, and v1 rows (written before the shipped anchor
    /// existed) as shipped = genesis.
    fn decode(chronicle: ChronicleId, b: &[u8]) -> Result<Self, CoordError> {
        let corrupt = |reason| CoordError::Corrupt { chronicle, reason };
        let shipped = match (b.first(), b.len()) {
            (Some(&LAYOUT_V1), ROW_LEN_V1) => Position::GENESIS,
            (Some(&LAYOUT_V2), ROW_LEN) => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&b[ROW_LEN_V1 + 8..]);
                Position { lsn: Lsn::new(be_u64(&b[ROW_LEN_V1..ROW_LEN_V1 + 8])), hash: HashVal::from_bytes(h) }
            }
            (Some(&LAYOUT_V1 | &LAYOUT_V2), _) => return Err(corrupt("wrong row length")),
            _ => return Err(corrupt("unknown layout version")),
        };
        let state = Self {
            holder: WardenId::new(be_u64(&b[1..9])),
            epoch: Epoch::new(be_u64(&b[9..17])),
            sealed_prefix: decode_head(&b[17..17 + HEAD_LEN]),
            head: decode_head(&b[17 + HEAD_LEN..ROW_LEN_V1]),
            shipped,
        };
        // The anchored head always carries the current epoch (see
        // `transfer`); anything else was not written by this module.
        if state.head.epoch != state.epoch {
            return Err(corrupt("head epoch differs from ownership epoch"));
        }
        if state.sealed_prefix.lsn > state.head.lsn {
            return Err(corrupt("sealed prefix is ahead of the head"));
        }
        if state.shipped.lsn > state.head.lsn {
            return Err(corrupt("shipped anchor is ahead of the head"));
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

/// The redb coordinator.  Each method is one `redb` write (or read)
/// transaction, committed with fsync before it returns.
impl Coord for Coordinator {
    /// Register a fresh Chronicle with its first holder.
    ///
    /// Epoch is [`Epoch::FIRST`], the head and the sealed prefix are the
    /// genesis head (lsn 0, [`HashVal::GENESIS`]).  Returns that head.
    fn register(
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
                shipped: Position::GENESIS,
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
    fn append(
        &self,
        warden: WardenId,
        envelope: &Envelope,
    ) -> Result<ChronicleHead, CoordError> {
        self.append_batch(warden, std::slice::from_ref(envelope))
    }

    fn append_batch(&self, warden: WardenId, envelopes: &[Envelope]) -> Result<ChronicleHead, CoordError> {
        let chronicle = envelopes.first().ok_or(CoordError::BadBatch { lsn: Lsn::new(0) })?.chronicle;
        self.write(|rows| {
            let mut state =
                load(rows, chronicle)?.ok_or(CoordError::UnknownChronicle(chronicle))?;
            // Checked against a running head; stored once, or not at all
            // (an error drops the transaction).
            for envelope in envelopes {
                if envelope.chronicle != chronicle {
                    return Err(CoordError::BadBatch { lsn: envelope.lsn });
                }
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
            }
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
    fn transfer(
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
    fn ownership(&self, chronicle: ChronicleId) -> Result<Ownership, CoordError> {
        Ok(self.read(chronicle)?.ownership())
    }

    /// The anchored head of a Chronicle (the authority, not a cache).
    fn head(&self, chronicle: ChronicleId) -> Result<ChronicleHead, CoordError> {
        Ok(self.read(chronicle)?.head)
    }

    /// The model's rule exactly ([`taso_core::model::Coordinator::advance_shipped`]),
    /// in one fsynced transaction when it changes.
    fn advance_shipped(
        &self,
        warden: WardenId,
        chronicle: ChronicleId,
        epoch: Epoch,
        to: Position,
    ) -> Result<Position, CoordError> {
        self.write(|rows| {
            let mut state = load(rows, chronicle)?.ok_or(CoordError::UnknownChronicle(chronicle))?;
            if warden != state.holder {
                return Err(CoordError::NotHolder { warden, holder: state.holder });
            }
            if epoch != state.epoch {
                return Err(CoordError::EpochMismatch { record_epoch: epoch, current: state.epoch });
            }
            if to.lsn > state.head.lsn {
                return Err(CoordError::ShippedAhead { to: to.lsn, head: state.head.lsn });
            }
            if (to.lsn == state.head.lsn && to.hash != state.head.hash)
                || (to.lsn == state.shipped.lsn && to.hash != state.shipped.hash)
            {
                return Err(CoordError::ShippedConflict { lsn: to.lsn });
            }
            if to.lsn > state.shipped.lsn {
                state.shipped = to;
                store(rows, chronicle, &state)?;
            }
            Ok(state.shipped)
        })
    }

    fn shipped(&self, chronicle: ChronicleId) -> Result<Position, CoordError> {
        Ok(self.read(chronicle)?.shipped)
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
    use taso_core::model::WardenModel;
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

    /// `n` records chained after `from`, in its epoch.
    fn chain_after(c: ChronicleId, from: ChronicleHead, n: u64) -> Vec<Envelope> {
        let mut prev = (from.lsn, from.hash);
        (0..n)
            .map(|i| {
                let rec = Record::new(c, BranchId::TRUNK, from.epoch, Stream::Fs, prev.0.next(), prev.1, raw(100 + i));
                prev = (rec.envelope.lsn, rec.envelope.hash);
                rec.envelope
            })
            .collect()
    }

    #[test]
    fn a_batch_is_all_or_none() {
        let (_d, _p, coord) = fresh();
        let g = coord.register(chron(1), A).unwrap();
        let three = chain_after(chron(1), g, 3);
        let h = coord.append_batch(A, &three).unwrap();
        assert_eq!((h.lsn, h.hash), (Lsn::new(3), three[2].hash));
        assert_eq!(coord.head(chron(1)).unwrap(), h);
        // One bad envelope anywhere: nothing of the batch is accepted.
        let mut more = chain_after(chron(1), h, 3);
        more[2].hash = HashVal::from_bytes([9; 32]);
        assert!(matches!(coord.append_batch(A, &more), Err(CoordError::BadHash { lsn }) if lsn == Lsn::new(6)));
        assert_eq!(coord.head(chron(1)).unwrap(), h);
        let next = chain_after(chron(1), h, 1)[0];
        assert!(matches!(coord.append_batch(A, &[next, next]), Err(CoordError::HeadMismatch { .. })), "not chained");
        assert!(matches!(coord.append_batch(B, &chain_after(chron(1), h, 2)), Err(CoordError::NotHolder { .. })));
        assert_eq!(coord.head(chron(1)).unwrap(), h);
        // Empty, or another Chronicle in it.
        assert!(matches!(coord.append_batch(A, &[]), Err(CoordError::BadBatch { lsn }) if lsn == Lsn::new(0)));
        let g2 = coord.register(chron(2), A).unwrap();
        let mixed = [chain_after(chron(1), h, 1)[0], chain_after(chron(2), g2, 1)[0]];
        assert!(matches!(coord.append_batch(A, &mixed), Err(CoordError::BadBatch { .. })));
        assert_eq!(coord.head(chron(1)).unwrap(), h);
        assert_eq!(coord.head(chron(2)).unwrap(), g2);
        assert!(!CoordError::BadBatch { lsn: Lsn::new(0) }.outcome_unknown());
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
            shipped: Position { lsn: Lsn::new(8), hash: HashVal::from_bytes([3; 32]) },
        };
        assert_eq!(State::decode(chron(1), &s.encode()).unwrap(), s);
        // A v1 row (written before the shipped anchor) reads as shipped = genesis.
        let mut v1 = s.encode()[..ROW_LEN_V1].to_vec();
        v1[0] = LAYOUT_V1;
        assert_eq!(State::decode(chron(1), &v1).unwrap(), State { shipped: Position::GENESIS, ..s });
        // Wrong lengths for either version, and a shipped anchor past the head.
        assert!(State::decode(chron(1), &s.encode()[..ROW_LEN_V1]).is_err());
        let mut long_v1 = s.encode().to_vec();
        long_v1[0] = LAYOUT_V1;
        assert!(State::decode(chron(1), &long_v1).is_err());
        let ahead = State { shipped: Position { lsn: Lsn::new(10), hash: HashVal::GENESIS }, ..s };
        assert!(State::decode(chron(1), &ahead.encode()).is_err());
    }

    #[test]
    fn shipped_anchor_rules() {
        let (_d, path, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        let mut w = resumed(A, chron(1), &coord);
        let mut heads = vec![Position::GENESIS];
        for n in 1..=5 {
            heads.push(submit(&coord, &mut w, chron(1), n).unwrap().into());
        }
        let e = Epoch::FIRST;
        assert_eq!(coord.shipped(chron(1)).unwrap(), Position::GENESIS);
        assert_eq!(coord.advance_shipped(A, chron(1), e, heads[3]).unwrap(), heads[3]);
        // Lower or equal: no change.
        assert_eq!(coord.advance_shipped(A, chron(1), e, heads[2]).unwrap(), heads[3]);
        assert_eq!(coord.advance_shipped(A, chron(1), e, heads[3]).unwrap(), heads[3]);
        // Refusals: not the holder, a stale epoch, past the head, another
        // record at the head or at the anchor; nothing changes.
        assert!(matches!(coord.advance_shipped(B, chron(1), e, heads[4]), Err(CoordError::NotHolder { .. })));
        assert!(matches!(coord.advance_shipped(A, chron(1), Epoch::new(9), heads[4]), Err(CoordError::EpochMismatch { .. })));
        let ahead = Position { lsn: Lsn::new(6), hash: heads[5].hash };
        assert!(matches!(coord.advance_shipped(A, chron(1), e, ahead), Err(CoordError::ShippedAhead { .. })));
        let bad_head = Position { lsn: Lsn::new(5), hash: heads[4].hash };
        assert!(matches!(coord.advance_shipped(A, chron(1), e, bad_head), Err(CoordError::ShippedConflict { .. })));
        let bad_anchor = Position { lsn: Lsn::new(3), hash: heads[4].hash };
        assert!(matches!(coord.advance_shipped(A, chron(1), e, bad_anchor), Err(CoordError::ShippedConflict { .. })));
        assert!(matches!(coord.advance_shipped(A, chron(9), e, heads[4]), Err(CoordError::UnknownChronicle(_))));
        assert_eq!(coord.shipped(chron(1)).unwrap(), heads[3]);
        // Transfer keeps it; the old holder can no longer move it; it survives a reopen.
        coord.transfer(chron(1), B).unwrap();
        assert_eq!(coord.shipped(chron(1)).unwrap(), heads[3]);
        assert!(matches!(coord.advance_shipped(A, chron(1), e, heads[5]), Err(CoordError::NotHolder { .. })));
        assert_eq!(coord.advance_shipped(B, chron(1), Epoch::new(2), heads[5]).unwrap(), heads[5]);
        drop(coord);
        let coord = Coordinator::open(&path).unwrap();
        assert_eq!(coord.shipped(chron(1)).unwrap(), heads[5]);
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

    // ── classification of failures ──────────────────────────────────

    /// Every variant, classified: refusals are certain, failures are not.
    #[test]
    fn outcome_unknown_classifies_every_variant() {
        let h = HashVal::from_bytes([1; 32]);
        let refusals = [
            CoordError::UnknownChronicle(chron(1)),
            CoordError::AlreadyRegistered(chron(1)),
            CoordError::BadHash { lsn: Lsn::new(1) },
            CoordError::NotHolder { warden: A, holder: B },
            CoordError::EpochMismatch { record_epoch: Epoch::FIRST, current: Epoch::new(2) },
            CoordError::HeadMismatch { prev: h, anchored: HashVal::GENESIS },
            CoordError::LsnNotNext { lsn: Lsn::new(5), expected: Lsn::new(1) },
            CoordError::ShippedAhead { to: Lsn::new(5), head: Lsn::new(4) },
            CoordError::ShippedConflict { lsn: Lsn::new(4) },
        ];
        for e in &refusals {
            assert!(!e.outcome_unknown(), "{e:?} is a refusal");
        }
        let failures = [
            CoordError::Corrupt { chronicle: chron(1), reason: "x" },
            CoordError::Storage(redb::Error::Corrupted("x".into())),
            CoordError::Unavailable(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
        ];
        for e in &failures {
            assert!(e.outcome_unknown(), "{e:?} has an unknown outcome");
        }
    }

    // ── differential: redb coordinator == model coordinator ─────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn redb_coordinator_matches_model(ops in conformance::ops()) {
            let (_d, path, coord) = fresh();
            let mut first = Some(coord);
            conformance::run(ops, &mut || match first.take() {
                Some(c) => Box::new(c),
                None => Box::new(Coordinator::open(&path).unwrap()),
            })?;
        }
    }
}

/// The differential test every [`Coord`] implementation must pass: a
/// random sequence of appends, transfers, resumes and reopens, run against
/// the implementation and against [`taso_core::model::Coordinator`] side
/// by side.  Every accept/refuse decision, every head and every ownership
/// state must match.
#[cfg(test)]
pub(crate) mod conformance {
    use super::*;
    use proptest::prelude::*;
    use taso_core::envelope::Stream;
    use taso_core::model::{AppendError as ModelError, Anchor, Coordinator as Model, ShipError, WardenModel};
    use taso_core::record::Payload;

    const IDS: [WardenId; 2] = [WardenId::new(1), WardenId::new(2)];

    /// One step of the test.
    #[derive(Clone, Debug)]
    pub(crate) enum Op {
        /// Warden `i` builds a record from its own view and submits it.
        Append(usize),
        /// Ownership moves to Warden `i`.
        Transfer(usize),
        /// Warden `i` re-reads epoch and head from the coordinator.
        Resume(usize),
        /// Drop the coordinator and open it again (reopen the file,
        /// restart the server, reconnect).
        Reopen,
        /// Warden `i` reports a shipped position under its own epoch:
        /// `pick` 0..=7 an accepted one (or genesis), 8..=9 the head's lsn
        /// with another hash, 10 one past the head, 11 the current
        /// anchor's lsn with another hash.
        Ship(usize, u8),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            5 => (0..2usize).prop_map(Op::Append),
            1 => (0..2usize).prop_map(Op::Transfer),
            2 => (0..2usize).prop_map(Op::Resume),
            1 => Just(Op::Reopen),
            3 => (0..2usize, 0..12u8).prop_map(|(i, p)| Op::Ship(i, p)),
        ]
    }

    /// Up to 60 steps.
    pub(crate) fn ops() -> impl Strategy<Value = Vec<Op>> {
        proptest::collection::vec(op(), 1..60)
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

    fn same_ship_refusal(m: &ShipError, r: &CoordError) -> bool {
        match (m, r) {
            (ShipError::NotHolder { warden: w1, holder: h1 }, CoordError::NotHolder { warden: w2, holder: h2 }) => {
                w1 == w2 && h1 == h2
            }
            (
                ShipError::EpochMismatch { epoch: e1, current: c1 },
                CoordError::EpochMismatch { record_epoch: e2, current: c2 },
            ) => e1 == e2 && c1 == c2,
            (ShipError::Ahead { to: t1, head: h1 }, CoordError::ShippedAhead { to: t2, head: h2 }) => t1 == t2 && h1 == h2,
            (ShipError::Conflict { lsn: l1 }, CoordError::ShippedConflict { lsn: l2 }) => l1 == l2,
            _ => false,
        }
    }

    fn pos(a: Anchor) -> Position {
        Position { lsn: a.lsn, hash: a.hash }
    }

    fn other(h: HashVal) -> HashVal {
        let mut b = *h.as_bytes();
        b[0] ^= 0xFF;
        HashVal::from_bytes(b)
    }

    /// The position Warden reports for `pick` (see [`Op::Ship`]).
    fn report(model: &Model, pick: u8) -> Anchor {
        let head = model.head();
        match pick {
            0..=7 => {
                let log = model.log();
                match (pick as usize) % (log.len() + 1) {
                    0 => Anchor::GENESIS,
                    k => Anchor { lsn: log[k - 1].envelope.lsn, hash: log[k - 1].envelope.hash },
                }
            }
            8 | 9 => Anchor { lsn: head.lsn, hash: other(head.hash) },
            10 => Anchor { lsn: head.lsn.next(), hash: head.hash },
            _ => Anchor { lsn: model.shipped().lsn, hash: other(model.shipped().hash) },
        }
    }

    fn resumed(id: WardenId, c: ChronicleId, coord: &dyn Coord) -> WardenModel {
        let o = coord.ownership(c).unwrap();
        let h = coord.head(c).unwrap();
        WardenModel::resume(id, c, o.epoch, h, h.lsn.next())
    }

    /// Run `ops`.  `open` returns the coordinator under test: the first
    /// call a fresh, empty one; every later call the same coordinator
    /// opened again (the previous handle is dropped before the call).
    pub(crate) fn run(ops: Vec<Op>, open: &mut dyn FnMut() -> Box<dyn Coord>) -> Result<(), TestCaseError> {
        let c = ChronicleId::from_bytes([1; 16]);
        let mut coord = Some(open());
        coord.as_ref().unwrap().register(c, IDS[0]).unwrap();
        let mut model = Model::new(c, IDS[0]);
        // Both start at genesis believing they hold epoch 1.
        let mut wardens = [WardenModel::new(IDS[0], c, Epoch::FIRST), WardenModel::new(IDS[1], c, Epoch::FIRST)];

        for (n, op) in ops.into_iter().enumerate() {
            match op {
                Op::Append(i) => {
                    let rec = wardens[i].build_record(Stream::Fs, Payload::Raw((n as u64).to_be_bytes().to_vec()));
                    let m = model.append(IDS[i], rec.clone());
                    let r = coord.as_ref().unwrap().append(IDS[i], &rec.envelope);
                    match (m, r) {
                        (Ok(hm), Ok(hr)) => {
                            prop_assert_eq!(hm, hr);
                            wardens[i] = WardenModel::resume(IDS[i], c, wardens[i].epoch(), hr, hr.lsn.next());
                        }
                        (Err(em), Err(er)) => {
                            prop_assert!(!er.outcome_unknown(), "a failure, not a decision: {:?}", er);
                            prop_assert!(same_refusal(&em, &er), "model {:?} vs coordinator {:?}", em, er);
                        }
                        (m, r) => prop_assert!(false, "model {:?} vs coordinator {:?}", m, r),
                    }
                }
                Op::Transfer(i) => {
                    let em = model.transfer(IDS[i]);
                    let er = coord.as_ref().unwrap().transfer(c, IDS[i]).unwrap();
                    prop_assert_eq!(em, er);
                }
                Op::Resume(i) => {
                    wardens[i] = resumed(IDS[i], c, coord.as_deref().unwrap());
                }
                Op::Reopen => {
                    drop(coord.take());
                    coord = Some(open());
                }
                Op::Ship(i, pick) => {
                    let to = report(&model, pick);
                    let epoch = wardens[i].epoch();
                    let m = model.advance_shipped(IDS[i], epoch, to);
                    let r = coord.as_ref().unwrap().advance_shipped(IDS[i], c, epoch, pos(to));
                    match (m, r) {
                        (Ok(am), Ok(ar)) => prop_assert_eq!(pos(am), ar),
                        (Err(em), Err(er)) => {
                            prop_assert!(!er.outcome_unknown(), "a failure, not a decision: {:?}", er);
                            prop_assert!(same_ship_refusal(&em, &er), "model {:?} vs coordinator {:?}", em, er);
                        }
                        (m, r) => prop_assert!(false, "model {:?} vs coordinator {:?}", m, r),
                    }
                }
            }
            let co = coord.as_deref().unwrap();
            let (mo, ro) = (model.ownership(), co.ownership(c).unwrap());
            prop_assert_eq!(model.head(), co.head(c).unwrap());
            prop_assert_eq!(mo.epoch, ro.epoch);
            prop_assert_eq!(mo.holder, ro.holder);
            prop_assert_eq!(mo.sealed_prefix, ro.sealed_prefix);
            prop_assert_eq!(pos(model.shipped()), co.shipped(c).unwrap());
        }
        Ok(())
    }
}
