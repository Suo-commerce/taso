//! The coordinator: ownership and the anchored head, durable (v1.0 §1 P1,
//! v0.4 §8).
//!
//! Phase 1 runs a single-node coordinator on `redb`.  It holds exactly
//! two things per Chronicle and nothing more:
//!
//! - [`Ownership`] `{ epoch, holder, sealed_prefix }`, and
//! - the anchored [`ChronicleHead`] `{ lsn, hash, epoch }`.
//!
//! P4 adds the coordinator log of contract records (P4 spec rev. 11 §1),
//! journalled in the same database ([`crate::coordjournal`]; see "The
//! coordinator log" on [`Coordinator`]), and the bytes of `Effect` records
//! with an append, from which it derives open obligations (D33).
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
//! anchored head — and makes every state change durable before it is
//! answered.  Concurrent writes share a transaction and its fsync (group
//! commit, see [`Coordinator`]); each is still checked on its own.
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
use std::sync::{mpsc, Arc, Mutex};

use redb::{Database, Durability, ReadableDatabase, ReadableTable, Table, TableDefinition};
use taso_core::contract::{Inventory, InventoryItem};
use taso_core::coordlog::{
    self, Answer, ChronicleView, ClaimAuthority, ClaimError, CoordLog, Head, ObjectId, StoreView,
    SubmissionStatus, Submitted,
};
use taso_core::envelope::{
    payload_hash, ChronicleHead, ChronicleId, Envelope, Epoch, HashVal, Lsn, Stream,
};
use taso_core::model::{Ownership, WardenId};
use taso_core::record::{OutcomeState, Payload};

use crate::coordjournal::{self, Done, Entry, JournalError, Op};
use crate::segment::Position;

// ── Storage layout ──────────────────────────────────────────────────

/// One row per Chronicle: key = `ChronicleId` bytes, value = [`State`]
/// in the fixed layout of [`State::encode`].
const CHRONICLES: TableDefinition<[u8; 16], &[u8]> =
    TableDefinition::new("taso.coordinator.chronicles");

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
    /// A conditional transfer named an ownership that is not the current
    /// one: the caller's read is stale (fencing review F1).  Nothing changed.
    OwnershipChanged {
        /// Who holds the Chronicle now.
        holder: WardenId,
        /// At which epoch.
        epoch: Epoch,
    },
    /// The connection is authenticated as one Warden and the request named
    /// another (v0.4 §10: the network cannot forge an identity).  Only a
    /// served coordinator with a peer map refuses this; see `coordsrv`.
    NotYou {
        /// The Warden the request named.
        claimed: WardenId,
        /// The Warden the connection is authenticated as.
        peer: WardenId,
    },
    /// The connection's uid is in no peer map: it is nobody to the
    /// coordinator, and every request on it is refused.
    UnknownPeer {
        /// The peer's uid.
        uid: u32,
    },
    /// The coordinator could not be reached, or the connection broke before
    /// an answer arrived.  The request may or may not have been applied.
    Unavailable(std::io::Error),
    /// An `Effect` record's bytes are missing, extra, do not match its
    /// envelope's `payload_hash`, or do not decode (P4 spec D33).  Nothing
    /// was appended.
    EffectPayload {
        /// The envelope's lsn (0: bytes with no `Effect` envelope left).
        lsn: Lsn,
        /// What was wrong.
        fault: EffectFault,
    },
    /// `claim_chronicle` or `takeover_target` was refused by the
    /// coordinator log (P4 spec §5.3, §7, D21).  Nothing changed.
    Claim(ClaimError),
    /// The coordinator log's journal does not decode or does not replay to
    /// the answers it recorded.
    Journal(JournalError),
}

/// What was wrong with an `Effect` record's bytes ([`CoordError::EffectPayload`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectFault {
    /// An `Effect` envelope came without its bytes (code 0).
    Missing,
    /// More bytes than `Effect` envelopes (code 1).
    Extra,
    /// The bytes do not hash to the envelope's `payload_hash` (code 2).
    Mismatch,
    /// The bytes are not a payload (code 3).
    Undecodable,
}

impl EffectFault {
    /// Its wire code.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// From a wire code.
    pub fn from_code(c: u8) -> Option<Self> {
        [
            Self::Missing,
            Self::Extra,
            Self::Mismatch,
            Self::Undecodable,
        ]
        .get(usize::from(c))
        .copied()
    }
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
            Self::Corrupt { .. } | Self::Storage(_) | Self::Unavailable(_) | Self::Journal(_) => {
                true
            }
            Self::UnknownChronicle(_)
            | Self::AlreadyRegistered(_)
            | Self::BadHash { .. }
            | Self::NotHolder { .. }
            | Self::EpochMismatch { .. }
            | Self::HeadMismatch { .. }
            | Self::LsnNotNext { .. }
            | Self::BadBatch { .. }
            | Self::ShippedAhead { .. }
            | Self::ShippedConflict { .. }
            | Self::NotYou { .. }
            | Self::UnknownPeer { .. }
            | Self::OwnershipChanged { .. }
            | Self::EffectPayload { .. }
            | Self::Claim(_) => false,
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
            Self::EpochMismatch {
                record_epoch,
                current,
            } => write!(
                f,
                "epoch {} is not the current epoch {}",
                record_epoch.get(),
                current.get()
            ),
            Self::HeadMismatch { .. } => write!(f, "prev does not match the anchored head"),
            Self::BadBatch { lsn } => write!(
                f,
                "bad batch at lsn {}: empty, or another chronicle",
                lsn.get()
            ),
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
                write!(
                    f,
                    "shipped lsn {} is past the anchored head {}",
                    to.get(),
                    head.get()
                )
            }
            Self::ShippedConflict { lsn } => write!(
                f,
                "shipped position at lsn {} names another record",
                lsn.get()
            ),
            Self::OwnershipChanged { holder, epoch } => write!(
                f,
                "ownership is not what was read: warden {} holds it at epoch {}",
                holder.get(),
                epoch.get()
            ),
            Self::NotYou { claimed, peer } => write!(
                f,
                "request names warden {} but the connection is warden {}",
                claimed.get(),
                peer.get()
            ),
            Self::UnknownPeer { uid } => write!(f, "peer uid {uid} is not a known warden"),
            Self::Unavailable(e) => write!(f, "coordinator unavailable: {e}"),
            Self::EffectPayload { lsn, fault } => write!(
                f,
                "effect record at lsn {}: bytes {}",
                lsn.get(),
                match fault {
                    EffectFault::Missing => "missing",
                    EffectFault::Extra => "with no effect record",
                    EffectFault::Mismatch => "do not match its payload hash",
                    EffectFault::Undecodable => "do not decode",
                }
            ),
            Self::Claim(e) => write!(f, "claim refused: {e:?}"),
            Self::Journal(e) => write!(f, "{e}"),
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
    fn register(
        &self,
        chronicle: ChronicleId,
        holder: WardenId,
    ) -> Result<ChronicleHead, CoordError>;

    /// CAS append: accept `envelope` as the next record of its Chronicle,
    /// or refuse it.  On success returns the new anchored head.
    fn append(&self, warden: WardenId, envelope: &Envelope) -> Result<ChronicleHead, CoordError>;

    /// CAS append of consecutive records of one Chronicle, all or none, in
    /// one durable transaction: each must pass [`Coord::append`]'s checks
    /// against the head the one before it leaves.  On success returns the
    /// new anchored head.  No `Effect` record may be in it (its bytes are
    /// required: [`Coord::append_batch_with`]).
    fn append_batch(
        &self,
        warden: WardenId,
        envelopes: &[Envelope],
    ) -> Result<ChronicleHead, CoordError> {
        self.append_batch_with(warden, envelopes, &[])
    }

    /// [`Coord::append_batch`], with the payload bytes of every `Effect`
    /// envelope in it, in order (P4 spec D33).  The coordinator checks each
    /// against its envelope's `payload_hash` and derives the Chronicle's
    /// open obligations from them (§1.5); bytes missing, extra, mismatched
    /// or undecodable refuse the whole batch ([`CoordError::EffectPayload`]).
    fn append_batch_with(
        &self,
        warden: WardenId,
        envelopes: &[Envelope],
        effects: &[Vec<u8>],
    ) -> Result<ChronicleHead, CoordError>;

    /// Atomic ownership transfer, conditional on the ownership being
    /// exactly `expected` (holder, epoch) — what the caller read before
    /// deciding: `sealed_prefix = head`, `epoch += 1`, `holder =
    /// new_holder`; returns the new epoch.  Otherwise refused with
    /// [`CoordError::OwnershipChanged`] naming the current ownership, and
    /// nothing changed.  A Warden takes only ownership it has read
    /// (fencing review F1): the one for every open and takeover.
    fn transfer_if(
        &self,
        chronicle: ChronicleId,
        new_holder: WardenId,
        expected: (WardenId, Epoch),
    ) -> Result<Epoch, CoordError>;

    /// Atomic ownership transfer, unconditional.  For tests and tooling
    /// only: a Warden deciding from what it read uses
    /// [`Coord::transfer_if`], since this takes a Vessel back from whoever
    /// took it over in the meantime.
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
                Position {
                    lsn: Lsn::new(be_u64(&b[ROW_LEN_V1..ROW_LEN_V1 + 8])),
                    hash: HashVal::from_bytes(h),
                }
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
type Journal<'t> = Table<'t, u64, &'static [u8]>;

/// The coordinator log's journal (P4 spec §1.1; [`crate::coordjournal`]):
/// key = sequence number from 1, value = one [`Entry`].
const JOURNAL: TableDefinition<u64, &[u8]> = TableDefinition::new("taso.coordinator.journal");

/// The tables one group transaction writes.
struct Tables<'t> {
    rows: Rows<'t>,
    journal: Journal<'t>,
    /// A journal entry was written: the group must commit, whatever the
    /// request that wrote it answered (the in-memory log has it).
    journalled: bool,
}

/// The durable single-node coordinator (v1.0 §3: "single-node `redb`,
/// fsync").
///
/// Methods take `&self`, so one `Coordinator` is shared across a node's
/// threads.  Writes are **group-committed**: a request joins a queue; if
/// no commit is in progress its caller leads, running every queued
/// request in order in one transaction and committing once, and each
/// caller gets its answer only after that commit.  Every request is
/// checked on its own against the state the ones before it left, and
/// writes nothing unless it is accepted, so grouping changes no answer:
/// only how many fsyncs a busy node pays (the p64 Seal finding,
/// 2026-10-16).
///
/// # The coordinator log (P4)
///
/// The P4 coordinator log ([`CoordLog`]) lives in memory and is made
/// durable by its journal ([`crate::coordjournal`]), written in the same
/// transactions as the ownership rows: every operation that changes it is
/// journalled with the store answers it read and its own answer, and
/// opening the coordinator replays the journal and checks every answer.
/// Its operations, and its queries, run as requests in the same queue, so
/// they see exactly the committed order and an answer is given only once
/// its transaction committed.  A transaction that fails, or a request that
/// fails with an unknown outcome, discards the in-memory log; the next
/// request rebuilds it from the journal.
///
/// The log's epoch of a Chronicle is the ownership epoch: registering
/// claims it, every transfer fences it, in the same transaction.  A
/// Chronicle registered before the log existed is brought in on first use
/// ([`Op::Sync`]); if it already had records, it gets an obligation that
/// never closes ([`crate::coordjournal::LEGACY_OBLIGATION`]), since its
/// effects were never seen (fail closed).
pub struct Coordinator {
    db: Database,
    queue: Mutex<Queue>,
    shared: Arc<Shared>,
    /// Transactions led so far (tests check that writes were grouped).
    #[cfg(test)]
    groups: std::sync::atomic::AtomicUsize,
}

/// What the coordinator log needs, shared with the requests that run it.
struct Shared {
    /// The log, or `None` when it must be rebuilt from the journal.
    log: Mutex<Option<CoordLog>>,
    config: LogConfig,
}

/// The coordinator log's configuration.
#[derive(Clone)]
pub struct LogConfig {
    /// What the coordinator reads from the store (P4 spec §0.4, §1.2 step
    /// 5).  It never takes a Warden's word for these.
    pub store: Arc<dyn StoreView + Send + Sync>,
    /// Timing (spec §11.1), in seconds.
    pub timing: coordlog::Config,
    /// The coordinator's clock: seconds since the Unix epoch.
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl Default for LogConfig {
    /// No store (nothing is readable: every accept is `NotReadable`),
    /// `announce.ttl` 10 min, `store.deleted_quarantine` 7 d, the system
    /// clock.
    fn default() -> Self {
        Self {
            store: Arc::new(NoStore),
            timing: coordlog::Config {
                announce_ttl: 600,
                deleted_quarantine: 7 * 24 * 3600,
            },
            clock: Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            }),
        }
    }
}

/// A store with nothing in it.
struct NoStore;

impl StoreView for NoStore {
    fn carries(&self, _: ChronicleId, _: &str, _: HashVal) -> bool {
        false
    }
    fn exists(&self, _: &ObjectId) -> bool {
        false
    }
    fn inventory(&self, _: HashVal) -> Option<Inventory> {
        None
    }
    fn fs_packs(&self, _: ChronicleId) -> Vec<InventoryItem> {
        Vec::new()
    }
    fn seal_closure(&self, _: ChronicleId, _: Lsn) -> Vec<ObjectId> {
        Vec::new()
    }
    fn verify_replacement(&self, _: ChronicleId, _: &InventoryItem) -> Option<HashVal> {
        None
    }
}

/// What a request does once its transaction has committed (`None`) or
/// failed to: send its answer.
type Deliver = Box<dyn FnOnce(Option<&CoordError>) + Send>;

/// A queued request: run against the group's tables (or told why there
/// are none); returns whether it wrote, whether it failed with an unknown
/// outcome (which aborts the whole group), and how to answer.
type Job = Box<
    dyn for<'a, 't> FnOnce(Result<&'a mut Tables<'t>, &'a CoordError>) -> (bool, bool, Deliver)
        + Send,
>;

#[derive(Default)]
struct Queue {
    jobs: Vec<Job>,
    leading: bool,
}

impl Coordinator {
    /// Open the coordinator at `path`, creating the file if it does not
    /// exist, with the default [`LogConfig`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CoordError> {
        Self::open_with(path, LogConfig::default())
    }

    /// Open the coordinator at `path` with `config`; the coordinator log
    /// is replayed from its journal, and every journalled answer checked.
    pub fn open_with(path: impl AsRef<Path>, config: LogConfig) -> Result<Self, CoordError> {
        let db = Database::create(path).map_err(storage)?;
        let coord = Self {
            db,
            queue: Mutex::default(),
            shared: Arc::new(Shared {
                log: Mutex::new(None),
                config,
            }),
            #[cfg(test)]
            groups: std::sync::atomic::AtomicUsize::new(0),
        };
        // Make sure the tables exist so reads never see "no such table".
        coord.write(|_| Ok(()))?;
        // Replay now: a journal that does not replay is found at open.
        coord.read_log(|_| ())?;
        Ok(coord)
    }

    // ── internals ───────────────────────────────────────────────────

    /// Run `f` in a write transaction shared with whatever else is queued
    /// (group commit, see [`Coordinator`]), and return its answer once
    /// that transaction is committed with fsync.  `f` must write only if
    /// it returns `Ok`.  If the commit fails, an `Ok` becomes an error
    /// whose outcome is unknown.
    fn write<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Tables<'_>) -> Result<T, CoordError> + Send + 'static,
    ) -> Result<T, CoordError> {
        self.queued(f, true)
    }

    /// As [`Coordinator::write`] for a request that writes nothing (a
    /// query of the coordinator log): it sees the queue's order and is
    /// answered only once the requests before it committed.
    fn queued<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Tables<'_>) -> Result<T, CoordError> + Send + 'static,
        writes: bool,
    ) -> Result<T, CoordError> {
        let (tx, rx) = mpsc::channel::<Result<T, CoordError>>();
        let job: Job = Box::new(move |tables| {
            let out = match tables {
                Ok(tables) => f(tables),
                Err(e) => Err(group_failed(e)),
            };
            let wrote = writes && out.is_ok();
            let poison = out.as_ref().is_err_and(CoordError::outcome_unknown);
            let deliver: Deliver = Box::new(move |commit| {
                let answer = match (out, commit) {
                    (Ok(_), Some(e)) => Err(group_failed(e)),
                    (out, _) => out,
                };
                let _ = tx.send(answer);
            });
            (wrote, poison, deliver)
        });
        let lead = {
            let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
            q.jobs.push(job);
            !std::mem::replace(&mut q.leading, true)
        };
        if lead {
            self.lead();
        }
        rx.recv().unwrap_or_else(|_| {
            Err(CoordError::Unavailable(std::io::Error::other(
                "the group commit leader is gone",
            )))
        })
    }

    /// Commit queued requests, group after group, until the queue is empty.
    fn lead(&self) {
        // If a request panics, give up leading and drop what is queued:
        // dropped requests answer their callers with an error, and the
        // next caller leads.  Without this every later write would wait.
        // The in-memory log may be half-changed: discard it.
        struct Abdicate<'a>(&'a Mutex<Queue>, &'a Shared);
        impl Drop for Abdicate<'_> {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    let mut q = self.0.lock().unwrap_or_else(|e| e.into_inner());
                    q.jobs.clear();
                    q.leading = false;
                    *self.1.log.lock().unwrap_or_else(|e| e.into_inner()) = None;
                }
            }
        }
        let _abdicate = Abdicate(&self.queue, &self.shared);
        loop {
            let jobs = {
                let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
                if q.jobs.is_empty() {
                    q.leading = false;
                    return;
                }
                std::mem::take(&mut q.jobs)
            };
            self.commit_group(jobs);
        }
    }

    /// One transaction for `jobs`, in order; commit if any wrote, else
    /// abort; then answer each.  A request that failed with an unknown
    /// outcome aborts the whole group: its partial writes are never
    /// committed by another request's commit.
    fn commit_group(&self, jobs: Vec<Job>) {
        let _t = crate::timing::span("coord.group");
        #[cfg(test)]
        self.groups
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let fail_all = |jobs: Vec<Job>, e: CoordError| {
            for job in jobs {
                let (_, _, deliver) = job(Err(&e));
                deliver(Some(&e));
            }
        };
        let begun = self.db.begin_write().map_err(storage).and_then(|mut txn| {
            // Immediate is redb's default; stated so it cannot drift.
            txn.set_durability(Durability::Immediate).map_err(storage)?;
            Ok(txn)
        });
        let txn = match begun {
            Ok(t) => t,
            Err(e) => return fail_all(jobs, e),
        };
        let mut delivers = Vec::with_capacity(jobs.len());
        let mut any = false;
        let mut poisoned = false;
        {
            let opened = txn.open_table(CHRONICLES).and_then(|rows| {
                let journal = txn.open_table(JOURNAL)?;
                Ok(Tables {
                    rows,
                    journal,
                    journalled: false,
                })
            });
            let mut tables = match opened.map_err(storage) {
                Ok(t) => t,
                Err(e) => return fail_all(jobs, e),
            };
            for job in jobs {
                let (wrote, poison, deliver) = job(Ok(&mut tables));
                any |= wrote;
                poisoned |= poison;
                delivers.push(deliver);
            }
            any |= tables.journalled;
        }
        let ended = if poisoned {
            let _ = txn.abort();
            Err(CoordError::Unavailable(std::io::Error::other(
                "a request in the group failed with an unknown outcome",
            )))
        } else if any {
            txn.commit().map_err(storage)
        } else {
            txn.abort().map_err(storage)
        };
        let failed = ended.err();
        if failed.is_some() {
            // What the log holds in memory was not committed.
            *self.shared.log.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
        for deliver in delivers {
            deliver(failed.as_ref());
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

    /// Read the coordinator log, in the queue's order.
    fn read_log<T: Send + 'static>(
        &self,
        f: impl FnOnce(&CoordLog) -> T + Send + 'static,
    ) -> Result<T, CoordError> {
        let shared = self.shared.clone();
        self.queued(
            move |t| {
                let mut g = shared.log.lock().unwrap_or_else(|e| e.into_inner());
                Ok(f(loaded(&mut g, &shared, &t.journal)?))
            },
            false,
        )
    }

    // ── The coordinator log (P4 spec §1) ────────────────────────────

    /// `claim_chronicle { id, authority }` (§1.6, §5.3, §7): a new
    /// Chronicle id, held by `holder` at epoch 1 — an ownership row and
    /// the log's claim, in one transaction.  Refused if the id is known
    /// ([`CoordError::AlreadyRegistered`]) or the authority does not name
    /// it ([`CoordError::Claim`]).
    pub fn claim_chronicle(
        &self,
        id: ChronicleId,
        holder: WardenId,
        authority: ClaimAuthority,
    ) -> Result<Epoch, CoordError> {
        let shared = self.shared.clone();
        self.write(move |t| {
            if load(&t.rows, id)?.is_some() {
                return Err(CoordError::AlreadyRegistered(id));
            }
            let done = journal_if(&shared, t, Op::Claim { id, authority }, |d| {
                matches!(d, Done::Claim(Ok(_)))
            })?;
            let epoch = match done {
                Done::Claim(Ok(e)) => e,
                Done::Claim(Err(e)) => return Err(CoordError::Claim(e)),
                _ => unreachable!("a claim answers a claim"),
            };
            let genesis = ChronicleHead {
                lsn: Lsn::new(0),
                hash: HashVal::GENESIS,
                epoch,
            };
            store(
                &mut t.rows,
                id,
                &State {
                    holder,
                    epoch,
                    sealed_prefix: genesis,
                    head: genesis,
                    shipped: Position::GENESIS,
                },
            )?;
            Ok(epoch)
        })
    }

    /// `takeover_target { id, authority, current_epoch }` (§5.3, D21):
    /// verified by the log, conditional on `current_epoch`; the ownership
    /// moves to `holder` at the next epoch, fencing the old owner, in the
    /// same transaction.  Returns the epoch and the target's head in the
    /// log.
    pub fn takeover_target(
        &self,
        id: ChronicleId,
        holder: WardenId,
        authority: ClaimAuthority,
        current_epoch: Epoch,
    ) -> Result<(Epoch, Head), CoordError> {
        let shared = self.shared.clone();
        self.write(move |t| {
            let mut state = load(&t.rows, id)?.ok_or(CoordError::UnknownChronicle(id))?;
            sync(&shared, t, id, &state)?;
            let op = Op::Takeover {
                id,
                authority,
                current_epoch,
            };
            let (epoch, head) =
                match journal_if(&shared, t, op, |d| matches!(d, Done::Takeover(Ok(_))))? {
                    Done::Takeover(Ok(v)) => v,
                    Done::Takeover(Err(e)) => return Err(CoordError::Claim(e)),
                    _ => unreachable!("a takeover answers a takeover"),
                };
            if epoch != state.epoch.next() {
                *shared.log.lock().unwrap_or_else(|e| e.into_inner()) = None;
                return Err(CoordError::Corrupt {
                    chronicle: id,
                    reason: "the log's epoch is not the ownership epoch",
                });
            }
            state.sealed_prefix = state.head;
            state.epoch = epoch;
            state.holder = holder;
            state.head.epoch = epoch;
            store(&mut t.rows, id, &state)?;
            Ok((epoch, head))
        })
    }

    /// `announce` (§1.2).  `Err` is the log's refusal.
    pub fn announce(
        &self,
        chronicle: ChronicleId,
        epoch: Epoch,
        submission: HashVal,
        logical: HashVal,
        digest: HashVal,
    ) -> Result<Result<(), Answer>, CoordError> {
        let shared = self.shared.clone();
        self.write(move |t| {
            sync_if_known(&shared, t, chronicle)?;
            let now = (shared.config.clock)();
            let op = Op::Announce {
                chronicle,
                epoch,
                submission,
                logical,
                digest,
                now,
            };
            match journal(&shared, t, op)? {
                Done::Announce(r) => Ok(r),
                _ => unreachable!("an announce answers an announce"),
            }
        })
    }

    /// `accept` (§1.2): `record` is what `pack` carries; the log checks the
    /// store agrees (step 5), then the row's predicate and effects.
    pub fn accept(
        &self,
        chronicle: ChronicleId,
        epoch: Epoch,
        submission: HashVal,
        expected_head: Head,
        pack: String,
        record: Submitted,
    ) -> Result<Answer, CoordError> {
        let shared = self.shared.clone();
        self.write(move |t| {
            sync_if_known(&shared, t, chronicle)?;
            let now = (shared.config.clock)();
            let op = Op::Accept {
                chronicle,
                epoch,
                submission,
                expected_head,
                pack,
                record,
                now,
            };
            match journal(&shared, t, op)? {
                Done::Answer(a) => Ok(a),
                _ => unreachable!("an accept answers"),
            }
        })
    }

    /// `cancel` (§1.2): idempotent.
    pub fn cancel(
        &self,
        chronicle: ChronicleId,
        epoch: Epoch,
        submission: HashVal,
    ) -> Result<Answer, CoordError> {
        let shared = self.shared.clone();
        self.write(move |t| {
            sync_if_known(&shared, t, chronicle)?;
            let op = Op::Cancel {
                chronicle,
                epoch,
                submission,
            };
            match journal(&shared, t, op)? {
                Done::Answer(a) => Ok(a),
                _ => unreachable!("a cancel answers"),
            }
        })
    }

    /// `set_retention_pin` (§1.6): an operator's call; a pinned Chronicle
    /// cannot retire.
    pub fn set_retention_pin(
        &self,
        chronicle: ChronicleId,
        pinned: bool,
    ) -> Result<(), CoordError> {
        let shared = self.shared.clone();
        self.write(move |t| {
            let state = load(&t.rows, chronicle)?.ok_or(CoordError::UnknownChronicle(chronicle))?;
            sync(&shared, t, chronicle, &state)?;
            journal(&shared, t, Op::Pin { chronicle, pinned })?;
            Ok(())
        })
    }

    /// `query { submission }` (§1.3).
    pub fn query_submission(
        &self,
        chronicle: ChronicleId,
        submission: HashVal,
    ) -> Result<SubmissionStatus, CoordError> {
        self.read_log(move |log| log.query_submission(chronicle, submission))
    }

    /// `query { logical }` (§1.3): the accepted record and its position.
    pub fn query_logical(&self, logical: HashVal) -> Result<Option<(u64, Submitted)>, CoordError> {
        self.read_log(move |log| log.query_logical(logical).map(|(p, s)| (p, s.clone())))
    }

    /// `query { chronicle }` (§1.3).
    pub fn query_chronicle(
        &self,
        chronicle: ChronicleId,
    ) -> Result<Option<ChronicleView>, CoordError> {
        self.read_log(move |log| log.query_chronicle(chronicle))
    }

    /// The Chronicle's open obligations as the log derives them (§1.5).
    pub fn obligations(&self, chronicle: ChronicleId) -> Result<Vec<u64>, CoordError> {
        self.read_log(move |log| log.obligations(chronicle))
    }
}

/// The log, rebuilt from `journal` if it was discarded.
fn loaded<'g>(
    g: &'g mut Option<CoordLog>,
    shared: &Shared,
    journal: &impl ReadableTable<u64, &'static [u8]>,
) -> Result<&'g mut CoordLog, CoordError> {
    if g.is_none() {
        let mut log = CoordLog::new(shared.config.timing);
        for row in journal.range::<u64>(..).map_err(storage)? {
            let (_, v) = row.map_err(storage)?;
            let entry = Entry::decode(v.value()).map_err(CoordError::Journal)?;
            coordjournal::replay(&mut log, &entry).map_err(CoordError::Journal)?;
        }
        *g = Some(log);
    }
    Ok(g.as_mut().expect("just loaded"))
}

/// Run `op` on the log and journal it.
fn journal(shared: &Shared, t: &mut Tables<'_>, op: Op) -> Result<Done, CoordError> {
    journal_if(shared, t, op, |_| true)
}

/// Run `op` on the log; journal it if `keep` says so.  An operation not
/// kept must not have changed the log (a refused claim or takeover).
fn journal_if(
    shared: &Shared,
    t: &mut Tables<'_>,
    op: Op,
    keep: impl FnOnce(&Done) -> bool,
) -> Result<Done, CoordError> {
    let mut g = shared.log.lock().unwrap_or_else(|e| e.into_inner());
    let log = loaded(&mut g, shared, &t.journal)?;
    let (done, entry) = coordjournal::run(log, op, &*shared.config.store);
    if keep(&done) {
        let seq = match t.journal.last().map_err(storage)? {
            Some((k, _)) => k.value() + 1,
            None => 1,
        };
        if let Err(e) = t.journal.insert(seq, entry.bytes().as_slice()) {
            *g = None;
            return Err(storage(e));
        }
        t.journalled = true;
    }
    Ok(done)
}

/// Bring the log's epoch for `chronicle` to the ownership row's
/// ([`Op::Sync`]); journalled only if it changes anything.
fn sync(
    shared: &Shared,
    t: &mut Tables<'_>,
    chronicle: ChronicleId,
    state: &State,
) -> Result<(), CoordError> {
    let known = {
        let mut g = shared.log.lock().unwrap_or_else(|e| e.into_inner());
        loaded(&mut g, shared, &t.journal)?
            .query_chronicle(chronicle)
            .map(|v| v.epoch)
    };
    if known == Some(state.epoch) {
        return Ok(());
    }
    let op = Op::Sync {
        chronicle,
        epoch: state.epoch,
        legacy: known.is_none() && state.head.lsn.get() > 0,
    };
    match journal(shared, t, op)? {
        Done::Sync(Ok(_)) => Ok(()),
        _ => {
            *shared.log.lock().unwrap_or_else(|e| e.into_inner()) = None;
            Err(CoordError::Corrupt {
                chronicle,
                reason: "the log's epoch is past the ownership epoch",
            })
        }
    }
}

/// [`sync`] if `chronicle` has an ownership row; otherwise the log answers
/// for an unknown Chronicle itself.
fn sync_if_known(
    shared: &Shared,
    t: &mut Tables<'_>,
    chronicle: ChronicleId,
) -> Result<(), CoordError> {
    match load(&t.rows, chronicle)? {
        Some(state) => sync(shared, t, chronicle, &state),
        None => Ok(()),
    }
}

/// The obligation changes an accepted batch makes (§1.5, D34): an intent
/// with a barrier opens one; a terminal outcome closes it.
fn obligation_changes(
    envelopes: &[Envelope],
    effects: &[Vec<u8>],
) -> Result<Vec<(u64, bool)>, CoordError> {
    let mut bytes = effects.iter();
    let mut changes = Vec::new();
    for e in envelopes {
        if e.stream != Stream::Effect {
            continue;
        }
        let Some(b) = bytes.next() else {
            return Err(CoordError::EffectPayload {
                lsn: e.lsn,
                fault: EffectFault::Missing,
            });
        };
        if payload_hash(b) != e.payload_hash {
            return Err(CoordError::EffectPayload {
                lsn: e.lsn,
                fault: EffectFault::Mismatch,
            });
        }
        match Payload::decode(b) {
            Ok(Payload::Intent(i)) if i.barrier.is_some() => changes.push((i.op.get(), true)),
            Ok(Payload::Outcome(o))
                if matches!(
                    o.state,
                    OutcomeState::ConfirmedApplied
                        | OutcomeState::ConfirmedNotApplied
                        | OutcomeState::AcceptedUnknown
                        | OutcomeState::Proposed
                ) =>
            {
                changes.push((o.op.get(), false))
            }
            Ok(_) => {}
            Err(_) => {
                return Err(CoordError::EffectPayload {
                    lsn: e.lsn,
                    fault: EffectFault::Undecodable,
                })
            }
        }
    }
    if bytes.next().is_some() {
        return Err(CoordError::EffectPayload {
            lsn: Lsn::new(0),
            fault: EffectFault::Extra,
        });
    }
    Ok(changes)
}

/// The redb coordinator.  Each write is checked on its own and committed
/// with fsync before it returns, in a transaction it may share with
/// concurrent writes (group commit, see [`Coordinator`]); a refused write
/// changes nothing.
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
        let shared = self.shared.clone();
        self.write(move |t| {
            if load(&t.rows, chronicle)?.is_some() {
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
            store(&mut t.rows, chronicle, &state)?;
            // The log claims it in the same transaction (P4): its epoch is
            // this one.
            sync(&shared, t, chronicle, &state)?;
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
    fn append(&self, warden: WardenId, envelope: &Envelope) -> Result<ChronicleHead, CoordError> {
        self.append_batch_with(warden, std::slice::from_ref(envelope), &[])
    }

    /// The CAS checks of [`Coord::append`] for each envelope, in order;
    /// then, for an accepted batch, the obligation changes its `Effect`
    /// records make (P4 spec §1.5, D33), journalled in the same
    /// transaction.  The bytes are checked before anything else: a batch
    /// whose bytes are wrong is refused whole.
    fn append_batch_with(
        &self,
        warden: WardenId,
        envelopes: &[Envelope],
        effects: &[Vec<u8>],
    ) -> Result<ChronicleHead, CoordError> {
        let chronicle = envelopes
            .first()
            .ok_or(CoordError::BadBatch { lsn: Lsn::new(0) })?
            .chronicle;
        let changes = obligation_changes(envelopes, effects)?;
        // Owned: the request may run on the thread leading the group.
        let envelopes = envelopes.to_vec();
        let shared = self.shared.clone();
        self.write(move |t| {
            let mut state =
                load(&t.rows, chronicle)?.ok_or(CoordError::UnknownChronicle(chronicle))?;
            // Checked against a running head; stored once, or not at all
            // (an error drops the transaction).
            for envelope in &envelopes {
                if envelope.chronicle != chronicle {
                    return Err(CoordError::BadBatch { lsn: envelope.lsn });
                }
                if !envelope.verify() {
                    return Err(CoordError::BadHash { lsn: envelope.lsn });
                }
                if warden != state.holder {
                    return Err(CoordError::NotHolder {
                        warden,
                        holder: state.holder,
                    });
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
                    return Err(CoordError::LsnNotNext {
                        lsn: envelope.lsn,
                        expected,
                    });
                }
                state.head = ChronicleHead {
                    lsn: envelope.lsn,
                    hash: envelope.hash,
                    epoch: state.epoch,
                };
            }
            if !changes.is_empty() {
                // `legacy` is judged on the head before this batch.
                let before = load(&t.rows, chronicle)?.expect("loaded above");
                sync(&shared, t, chronicle, &before)?;
                for (op, open) in changes {
                    journal(
                        &shared,
                        t,
                        Op::Obligation {
                            chronicle,
                            op,
                            open,
                        },
                    )?;
                }
            }
            store(&mut t.rows, chronicle, &state)?;
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
    fn transfer_if(
        &self,
        chronicle: ChronicleId,
        new_holder: WardenId,
        expected: (WardenId, Epoch),
    ) -> Result<Epoch, CoordError> {
        let shared = self.shared.clone();
        self.write(move |t| {
            let mut state =
                load(&t.rows, chronicle)?.ok_or(CoordError::UnknownChronicle(chronicle))?;
            if (state.holder, state.epoch) != expected {
                return Err(CoordError::OwnershipChanged {
                    holder: state.holder,
                    epoch: state.epoch,
                });
            }
            fenced(&shared, t, chronicle, &mut state, new_holder)
        })
    }

    fn transfer(&self, chronicle: ChronicleId, new_holder: WardenId) -> Result<Epoch, CoordError> {
        let shared = self.shared.clone();
        self.write(move |t| {
            let mut state =
                load(&t.rows, chronicle)?.ok_or(CoordError::UnknownChronicle(chronicle))?;
            fenced(&shared, t, chronicle, &mut state, new_holder)
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
        self.write(move |t| {
            let mut state =
                load(&t.rows, chronicle)?.ok_or(CoordError::UnknownChronicle(chronicle))?;
            if warden != state.holder {
                return Err(CoordError::NotHolder {
                    warden,
                    holder: state.holder,
                });
            }
            if epoch != state.epoch {
                return Err(CoordError::EpochMismatch {
                    record_epoch: epoch,
                    current: state.epoch,
                });
            }
            if to.lsn > state.head.lsn {
                return Err(CoordError::ShippedAhead {
                    to: to.lsn,
                    head: state.head.lsn,
                });
            }
            if (to.lsn == state.head.lsn && to.hash != state.head.hash)
                || (to.lsn == state.shipped.lsn && to.hash != state.shipped.hash)
            {
                return Err(CoordError::ShippedConflict { lsn: to.lsn });
            }
            if to.lsn > state.shipped.lsn {
                state.shipped = to;
                store(&mut t.rows, chronicle, &state)?;
            }
            Ok(state.shipped)
        })
    }

    fn shipped(&self, chronicle: ChronicleId) -> Result<Position, CoordError> {
        Ok(self.read(chronicle)?.shipped)
    }
}

/// The answer for a request whose group transaction could not begin or
/// commit: its outcome is unknown (the error is not `Clone`; its text is
/// kept).
fn group_failed(e: &CoordError) -> CoordError {
    CoordError::Unavailable(std::io::Error::other(format!("group commit failed: {e}")))
}

/// The transfer of `state` to `holder` at the next epoch (v0.4 §8.2), and
/// the log's fence to the same epoch, in one transaction.
fn fenced(
    shared: &Shared,
    t: &mut Tables<'_>,
    chronicle: ChronicleId,
    state: &mut State,
    holder: WardenId,
) -> Result<Epoch, CoordError> {
    // The log first knows the Chronicle at its current epoch (legacy is
    // judged on the head as it is), then follows it to the next.
    sync(shared, t, chronicle, state)?;
    state.sealed_prefix = state.head;
    state.epoch = state.epoch.next();
    state.holder = holder;
    state.head.epoch = state.epoch;
    sync(shared, t, chronicle, state)?;
    store(&mut t.rows, chronicle, state)?;
    Ok(state.epoch)
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
        assert!(matches!(
            coord.head(chron(9)),
            Err(CoordError::UnknownChronicle(_))
        ));
        assert!(matches!(
            coord.transfer(chron(9), A),
            Err(CoordError::UnknownChronicle(_))
        ));
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
        assert!(matches!(
            coord.append(A, &env),
            Err(CoordError::BadHash { .. })
        ));
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
                let rec = Record::new(
                    c,
                    BranchId::TRUNK,
                    from.epoch,
                    Stream::Fs,
                    prev.0.next(),
                    prev.1,
                    raw(100 + i),
                );
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
        assert!(
            matches!(coord.append_batch(A, &more), Err(CoordError::BadHash { lsn }) if lsn == Lsn::new(6))
        );
        assert_eq!(coord.head(chron(1)).unwrap(), h);
        let next = chain_after(chron(1), h, 1)[0];
        assert!(
            matches!(
                coord.append_batch(A, &[next, next]),
                Err(CoordError::HeadMismatch { .. })
            ),
            "not chained"
        );
        assert!(matches!(
            coord.append_batch(B, &chain_after(chron(1), h, 2)),
            Err(CoordError::NotHolder { .. })
        ));
        assert_eq!(coord.head(chron(1)).unwrap(), h);
        // Empty, or another Chronicle in it.
        assert!(
            matches!(coord.append_batch(A, &[]), Err(CoordError::BadBatch { lsn }) if lsn == Lsn::new(0))
        );
        let g2 = coord.register(chron(2), A).unwrap();
        let mixed = [
            chain_after(chron(1), h, 1)[0],
            chain_after(chron(2), g2, 1)[0],
        ];
        assert!(matches!(
            coord.append_batch(A, &mixed),
            Err(CoordError::BadBatch { .. })
        ));
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

    // ── group commit ────────────────────────────────────────────────

    /// Many Wardens, each on its own Chronicle, appending at once: every
    /// append accepted exactly once, every head right, durably, and the
    /// writes really shared transactions.
    #[test]
    fn concurrent_appends_are_grouped_and_exact() {
        const THREADS: u8 = 16;
        const EACH: u64 = 40;
        let (_d, path, coord) = fresh();
        for t in 0..THREADS {
            coord
                .register(chron(t), WardenId::new(u64::from(t) + 1))
                .unwrap();
        }
        let start = std::sync::Barrier::new(usize::from(THREADS));
        let heads: Vec<ChronicleHead> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..THREADS)
                .map(|t| {
                    let (coord, start) = (&coord, &start);
                    s.spawn(move || {
                        let me = WardenId::new(u64::from(t) + 1);
                        let mut w = resumed(me, chron(t), coord);
                        start.wait();
                        let mut last = None;
                        for n in 1..=EACH {
                            let h = submit(coord, &mut w, chron(t), n).unwrap();
                            assert_eq!(h.lsn, Lsn::new(n));
                            last = Some(h);
                        }
                        last.unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let writes = usize::from(THREADS) * EACH as usize + usize::from(THREADS);
        let groups = coord.groups.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            groups < writes,
            "{groups} transactions for {writes} writes: nothing was grouped"
        );
        drop(coord);
        let coord = Coordinator::open(&path).unwrap();
        for (t, h) in heads.iter().enumerate() {
            assert_eq!(coord.head(chron(t as u8)).unwrap(), *h);
            assert_eq!(h.lsn, Lsn::new(EACH));
        }
    }

    /// Two Wardens racing for every position of one Chronicle (a split
    /// brain inside one epoch): each position is accepted exactly once,
    /// the loser is refused, and a refusal never fails a request grouped
    /// with it.
    #[test]
    fn racing_appends_one_wins_each_position() {
        const RACERS: u64 = 8;
        const ROUNDS: u64 = 30;
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        for t in 0..4u8 {
            coord.register(chron(10 + t), B).unwrap();
        }
        let start = std::sync::Barrier::new(RACERS as usize + 4);
        let wins: u64 = std::thread::scope(|s| {
            let racers: Vec<_> = (0..RACERS)
                .map(|r| {
                    let (coord, start) = (&coord, &start);
                    s.spawn(move || {
                        start.wait();
                        let mut wins = 0;
                        for n in 0..ROUNDS {
                            // Build on whatever is anchored now; others race.
                            let head = coord.head(chron(1)).unwrap();
                            let env = Record::new(
                                chron(1),
                                BranchId::TRUNK,
                                head.epoch,
                                Stream::Fs,
                                head.lsn.next(),
                                head.hash,
                                raw(r * 1000 + n),
                            )
                            .envelope;
                            match coord.append(A, &env) {
                                Ok(h) => {
                                    assert_eq!(h.hash, env.hash);
                                    wins += 1;
                                }
                                Err(e) => assert!(
                                    matches!(
                                        e,
                                        CoordError::HeadMismatch { .. }
                                            | CoordError::LsnNotNext { .. }
                                    ),
                                    "{e}"
                                ),
                            }
                        }
                        wins
                    })
                })
                .collect();
            // Bystanders on other Chronicles must never see a refusal.
            for t in 0..4u8 {
                let (coord, start) = (&coord, &start);
                s.spawn(move || {
                    let mut w = resumed(B, chron(10 + t), coord);
                    start.wait();
                    for n in 1..=ROUNDS {
                        submit(coord, &mut w, chron(10 + t), n).unwrap();
                    }
                });
            }
            racers.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!(
            coord.head(chron(1)).unwrap().lsn,
            Lsn::new(wins),
            "every accepted append advanced the head once"
        );
        assert!(wins >= ROUNDS, "each round has a winner");
        for t in 0..4u8 {
            assert_eq!(coord.head(chron(10 + t)).unwrap().lsn, Lsn::new(ROUNDS));
        }
    }

    /// A request that panics while leading a group: its group's callers
    /// get an error, and the coordinator keeps working.
    #[test]
    fn a_panicking_request_does_not_wedge_the_queue() {
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        let hit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            coord.write(|_rows| -> Result<(), CoordError> { panic!("boom") })
        }));
        assert!(hit.is_err());
        let mut w = resumed(A, chron(1), &coord);
        assert_eq!(
            submit(&coord, &mut w, chron(1), 1).unwrap().lsn,
            Lsn::new(1)
        );
    }

    /// A caller queued behind a leader that panics is answered (outcome
    /// unknown), not left waiting for a leader that never comes.
    #[test]
    fn callers_queued_behind_a_panic_are_answered() {
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        let mut w = resumed(A, chron(1), &coord);
        let (leading, go) = (mpsc::channel(), mpsc::channel::<()>());
        let (answered, got) = mpsc::channel();
        std::thread::scope(|s| {
            let coord = &coord;
            let (leading_tx, go_rx) = (leading.0, go.1);
            s.spawn(move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    coord.write(move |_rows| -> Result<(), CoordError> {
                        leading_tx.send(()).unwrap();
                        go_rx.recv().unwrap();
                        panic!("boom")
                    })
                }));
            });
            leading.1.recv().unwrap();
            s.spawn(move || {
                let _ = answered.send(submit(coord, &mut w, chron(1), 1));
            });
            // Let the second caller queue behind the stuck leader.
            while coord.queue.lock().unwrap().jobs.is_empty() {
                std::thread::yield_now();
            }
            go.0.send(()).unwrap();
            let r = got.recv_timeout(std::time::Duration::from_secs(10));
            if r.is_err() {
                // Lead the stranded request ourselves so the scope can end.
                let _ = coord.write(|_rows| Ok(()));
                panic!("queued caller never answered");
            }
            assert!(r.unwrap().unwrap_err().outcome_unknown());
        });
        // The queued append never ran; the next one is lsn 1.
        assert_eq!(coord.head(chron(1)).unwrap().lsn, Lsn::new(0));
    }

    /// A group that cannot commit answers every caller "outcome unknown",
    /// never a refusal: the CAS may have landed.
    #[test]
    fn a_failed_group_is_outcome_unknown() {
        let e = group_failed(&CoordError::Unavailable(std::io::Error::other("disk gone")));
        assert!(e.outcome_unknown());
        assert!(
            e.to_string().contains("group commit failed") && e.to_string().contains("disk gone"),
            "{e}"
        );
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
        let (o1, h1) = (
            coord.ownership(chron(1)).unwrap(),
            coord.head(chron(1)).unwrap(),
        );
        drop(coord);

        let coord = Coordinator::open(&path).unwrap();
        let (o2, h2) = (
            coord.ownership(chron(1)).unwrap(),
            coord.head(chron(1)).unwrap(),
        );
        assert_eq!(h1, h2);
        assert_eq!(
            (o1.epoch, o1.holder, o1.sealed_prefix),
            (o2.epoch, o2.holder, o2.sealed_prefix)
        );
        // And the new holder carries on from it.
        let mut b = resumed(B, chron(1), &coord);
        assert_eq!(
            submit(&coord, &mut b, chron(1), 4).unwrap().lsn,
            Lsn::new(4)
        );
    }

    #[test]
    fn second_open_while_open_is_refused() {
        let (_d, path, _coord) = fresh();
        assert!(matches!(
            Coordinator::open(&path),
            Err(CoordError::Storage(_))
        ));
    }

    #[test]
    fn corrupt_row_is_reported() {
        let (_d, _p, coord) = fresh();
        coord.register(chron(1), A).unwrap();
        coord
            .write(|t| {
                t.rows
                    .insert(*chron(1).as_bytes(), [0u8; 3].as_slice())
                    .map_err(storage)?;
                Ok(())
            })
            .unwrap();
        assert!(matches!(
            coord.head(chron(1)),
            Err(CoordError::Corrupt { .. })
        ));
        assert!(matches!(
            coord.transfer(chron(1), B),
            Err(CoordError::Corrupt { .. })
        ));
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
            shipped: Position {
                lsn: Lsn::new(8),
                hash: HashVal::from_bytes([3; 32]),
            },
        };
        assert_eq!(State::decode(chron(1), &s.encode()).unwrap(), s);
        // A v1 row (written before the shipped anchor) reads as shipped = genesis.
        let mut v1 = s.encode()[..ROW_LEN_V1].to_vec();
        v1[0] = LAYOUT_V1;
        assert_eq!(
            State::decode(chron(1), &v1).unwrap(),
            State {
                shipped: Position::GENESIS,
                ..s
            }
        );
        // Wrong lengths for either version, and a shipped anchor past the head.
        assert!(State::decode(chron(1), &s.encode()[..ROW_LEN_V1]).is_err());
        let mut long_v1 = s.encode().to_vec();
        long_v1[0] = LAYOUT_V1;
        assert!(State::decode(chron(1), &long_v1).is_err());
        let ahead = State {
            shipped: Position {
                lsn: Lsn::new(10),
                hash: HashVal::GENESIS,
            },
            ..s
        };
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
        assert_eq!(
            coord.advance_shipped(A, chron(1), e, heads[3]).unwrap(),
            heads[3]
        );
        // Lower or equal: no change.
        assert_eq!(
            coord.advance_shipped(A, chron(1), e, heads[2]).unwrap(),
            heads[3]
        );
        assert_eq!(
            coord.advance_shipped(A, chron(1), e, heads[3]).unwrap(),
            heads[3]
        );
        // Refusals: not the holder, a stale epoch, past the head, another
        // record at the head or at the anchor; nothing changes.
        assert!(matches!(
            coord.advance_shipped(B, chron(1), e, heads[4]),
            Err(CoordError::NotHolder { .. })
        ));
        assert!(matches!(
            coord.advance_shipped(A, chron(1), Epoch::new(9), heads[4]),
            Err(CoordError::EpochMismatch { .. })
        ));
        let ahead = Position {
            lsn: Lsn::new(6),
            hash: heads[5].hash,
        };
        assert!(matches!(
            coord.advance_shipped(A, chron(1), e, ahead),
            Err(CoordError::ShippedAhead { .. })
        ));
        let bad_head = Position {
            lsn: Lsn::new(5),
            hash: heads[4].hash,
        };
        assert!(matches!(
            coord.advance_shipped(A, chron(1), e, bad_head),
            Err(CoordError::ShippedConflict { .. })
        ));
        let bad_anchor = Position {
            lsn: Lsn::new(3),
            hash: heads[4].hash,
        };
        assert!(matches!(
            coord.advance_shipped(A, chron(1), e, bad_anchor),
            Err(CoordError::ShippedConflict { .. })
        ));
        assert!(matches!(
            coord.advance_shipped(A, chron(9), e, heads[4]),
            Err(CoordError::UnknownChronicle(_))
        ));
        assert_eq!(coord.shipped(chron(1)).unwrap(), heads[3]);
        // Transfer keeps it; the old holder can no longer move it; it survives a reopen.
        coord.transfer(chron(1), B).unwrap();
        assert_eq!(coord.shipped(chron(1)).unwrap(), heads[3]);
        assert!(matches!(
            coord.advance_shipped(A, chron(1), e, heads[5]),
            Err(CoordError::NotHolder { .. })
        ));
        assert_eq!(
            coord
                .advance_shipped(B, chron(1), Epoch::new(2), heads[5])
                .unwrap(),
            heads[5]
        );
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
        assert_eq!(
            coord.ownership(chron(1)).unwrap().sealed_prefix.lsn,
            Lsn::new(1)
        );
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
        assert_eq!(
            submit(&coord, &mut b, chron(1), 2).unwrap().lsn,
            Lsn::new(2)
        );
    }

    // ── classification of failures ──────────────────────────────────

    /// Every variant, classified: refusals are certain, failures are not.
    /// F1 against redb: A reads, B takes over on its read, A's stale claim
    /// is refused with the current ownership and nothing moves; B keeps
    /// appending; the same claim cannot win twice.
    #[test]
    fn transfer_if_takes_only_what_was_read() {
        let (_dir, _path, coord) = fresh();
        let g = coord.register(chron(1), A).unwrap();
        let a = chain_after(chron(1), g, 1);
        coord.append(A, &a[0]).unwrap();
        let o = coord.ownership(chron(1)).unwrap();
        let read = (o.holder, o.epoch);
        assert_eq!(read, (A, Epoch::FIRST));

        assert_eq!(coord.transfer_if(chron(1), B, read).unwrap(), Epoch::new(2));
        let h = coord.head(chron(1)).unwrap();
        let b = chain_after(chron(1), h, 1);
        coord.append(B, &b[0]).unwrap();

        let before = coord.head(chron(1)).unwrap();
        assert!(matches!(
            coord.transfer_if(chron(1), A, read),
            Err(CoordError::OwnershipChanged { holder, epoch }) if holder == B && epoch == Epoch::new(2)
        ));
        let o = coord.ownership(chron(1)).unwrap();
        assert_eq!((o.holder, o.epoch), (B, Epoch::new(2)));
        assert_eq!(coord.head(chron(1)).unwrap(), before);
        let b2 = chain_after(chron(1), before, 1);
        coord.append(B, &b2[0]).unwrap();

        let now = (B, Epoch::new(2));
        assert_eq!(coord.transfer_if(chron(1), B, now).unwrap(), Epoch::new(3));
        assert!(
            matches!(coord.transfer_if(chron(1), B, now), Err(CoordError::OwnershipChanged { epoch, .. }) if epoch == Epoch::new(3))
        );
        assert!(matches!(
            coord.transfer_if(chron(9), B, now),
            Err(CoordError::UnknownChronicle(_))
        ));
        assert!(!CoordError::OwnershipChanged {
            holder: B,
            epoch: Epoch::new(3)
        }
        .outcome_unknown());
    }

    #[test]
    fn outcome_unknown_classifies_every_variant() {
        let h = HashVal::from_bytes([1; 32]);
        let refusals = [
            CoordError::UnknownChronicle(chron(1)),
            CoordError::AlreadyRegistered(chron(1)),
            CoordError::BadHash { lsn: Lsn::new(1) },
            CoordError::NotHolder {
                warden: A,
                holder: B,
            },
            CoordError::EpochMismatch {
                record_epoch: Epoch::FIRST,
                current: Epoch::new(2),
            },
            CoordError::HeadMismatch {
                prev: h,
                anchored: HashVal::GENESIS,
            },
            CoordError::LsnNotNext {
                lsn: Lsn::new(5),
                expected: Lsn::new(1),
            },
            CoordError::ShippedAhead {
                to: Lsn::new(5),
                head: Lsn::new(4),
            },
            CoordError::ShippedConflict { lsn: Lsn::new(4) },
            CoordError::NotYou {
                claimed: A,
                peer: B,
            },
            CoordError::UnknownPeer { uid: 1000 },
            CoordError::OwnershipChanged {
                holder: B,
                epoch: Epoch::new(2),
            },
        ];
        for e in &refusals {
            assert!(!e.outcome_unknown(), "{e:?} is a refusal");
        }
        let failures = [
            CoordError::Corrupt {
                chronicle: chron(1),
                reason: "x",
            },
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
    use taso_core::model::{
        Anchor, AppendError as ModelError, Coordinator as Model, ShipError, WardenModel,
    };
    use taso_core::record::Payload;

    const IDS: [WardenId; 2] = [WardenId::new(1), WardenId::new(2)];

    /// One step of the test.
    #[derive(Clone, Debug)]
    pub(crate) enum Op {
        /// Warden `i` builds a record from its own view and submits it.
        Append(usize),
        /// Ownership moves to Warden `i`.
        Transfer(usize),
        /// Warden `i` claims the Chronicle on the ownership it last read
        /// (`Resume`, or the start): `fresh` true re-reads first and wins,
        /// false uses the stale read, which is refused once the ownership
        /// moved.
        TransferIf(usize, bool),
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
            2 => (0..2usize, any::<bool>()).prop_map(|(i, f)| Op::TransferIf(i, f)),
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
                ModelError::NotHolder {
                    warden: w1,
                    holder: h1,
                },
                CoordError::NotHolder {
                    warden: w2,
                    holder: h2,
                },
            ) => w1 == w2 && h1 == h2,
            (
                ModelError::EpochMismatch {
                    record_epoch: e1,
                    current: c1,
                },
                CoordError::EpochMismatch {
                    record_epoch: e2,
                    current: c2,
                },
            ) => e1 == e2 && c1 == c2,
            (
                ModelError::HeadMismatch {
                    prev: p1,
                    anchored: a1,
                },
                CoordError::HeadMismatch {
                    prev: p2,
                    anchored: a2,
                },
            ) => p1 == p2 && a1 == a2,
            _ => false,
        }
    }

    fn same_ship_refusal(m: &ShipError, r: &CoordError) -> bool {
        match (m, r) {
            (
                ShipError::NotHolder {
                    warden: w1,
                    holder: h1,
                },
                CoordError::NotHolder {
                    warden: w2,
                    holder: h2,
                },
            ) => w1 == w2 && h1 == h2,
            (
                ShipError::EpochMismatch {
                    epoch: e1,
                    current: c1,
                },
                CoordError::EpochMismatch {
                    record_epoch: e2,
                    current: c2,
                },
            ) => e1 == e2 && c1 == c2,
            (
                ShipError::Ahead { to: t1, head: h1 },
                CoordError::ShippedAhead { to: t2, head: h2 },
            ) => t1 == t2 && h1 == h2,
            (ShipError::Conflict { lsn: l1 }, CoordError::ShippedConflict { lsn: l2 }) => l1 == l2,
            _ => false,
        }
    }

    fn pos(a: Anchor) -> Position {
        Position {
            lsn: a.lsn,
            hash: a.hash,
        }
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
                    k => Anchor {
                        lsn: log[k - 1].envelope.lsn,
                        hash: log[k - 1].envelope.hash,
                    },
                }
            }
            8 | 9 => Anchor {
                lsn: head.lsn,
                hash: other(head.hash),
            },
            10 => Anchor {
                lsn: head.lsn.next(),
                hash: head.hash,
            },
            _ => Anchor {
                lsn: model.shipped().lsn,
                hash: other(model.shipped().hash),
            },
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
    pub(crate) fn run(
        ops: Vec<Op>,
        open: &mut dyn FnMut() -> Box<dyn Coord>,
    ) -> Result<(), TestCaseError> {
        let c = ChronicleId::from_bytes([1; 16]);
        let mut coord = Some(open());
        coord.as_ref().unwrap().register(c, IDS[0]).unwrap();
        let mut model = Model::new(c, IDS[0]);
        // Both start at genesis believing they hold epoch 1.
        let mut wardens = [
            WardenModel::new(IDS[0], c, Epoch::FIRST),
            WardenModel::new(IDS[1], c, Epoch::FIRST),
        ];
        // What each Warden last read of the ownership (holder, epoch).
        let mut read = [(IDS[0], Epoch::FIRST); 2];

        for (n, op) in ops.into_iter().enumerate() {
            match op {
                Op::Append(i) => {
                    let rec = wardens[i]
                        .build_record(Stream::Fs, Payload::Raw((n as u64).to_be_bytes().to_vec()));
                    let m = model.append(IDS[i], rec.clone());
                    let r = coord.as_ref().unwrap().append(IDS[i], &rec.envelope);
                    match (m, r) {
                        (Ok(hm), Ok(hr)) => {
                            prop_assert_eq!(hm, hr);
                            wardens[i] = WardenModel::resume(
                                IDS[i],
                                c,
                                wardens[i].epoch(),
                                hr,
                                hr.lsn.next(),
                            );
                        }
                        (Err(em), Err(er)) => {
                            prop_assert!(
                                !er.outcome_unknown(),
                                "a failure, not a decision: {:?}",
                                er
                            );
                            prop_assert!(
                                same_refusal(&em, &er),
                                "model {:?} vs coordinator {:?}",
                                em,
                                er
                            );
                        }
                        (m, r) => prop_assert!(false, "model {:?} vs coordinator {:?}", m, r),
                    }
                }
                Op::Transfer(i) => {
                    let em = model.transfer(IDS[i]);
                    let er = coord.as_ref().unwrap().transfer(c, IDS[i]).unwrap();
                    prop_assert_eq!(em, er);
                }
                Op::TransferIf(i, fresh) => {
                    if fresh {
                        let o = coord.as_ref().unwrap().ownership(c).unwrap();
                        read[i] = (o.holder, o.epoch);
                    }
                    let m = model.transfer_if(IDS[i], read[i]);
                    let r = coord.as_ref().unwrap().transfer_if(c, IDS[i], read[i]);
                    match (m, r) {
                        (Ok(em), Ok(er)) => prop_assert_eq!(em, er),
                        (Err(em), Err(CoordError::OwnershipChanged { holder, epoch })) => {
                            prop_assert_eq!((em.holder, em.epoch), (holder, epoch));
                        }
                        (m, r) => prop_assert!(false, "model {:?} vs coordinator {:?}", m, r),
                    }
                }
                Op::Resume(i) => {
                    wardens[i] = resumed(IDS[i], c, coord.as_deref().unwrap());
                    let o = coord.as_ref().unwrap().ownership(c).unwrap();
                    read[i] = (o.holder, o.epoch);
                }
                Op::Reopen => {
                    drop(coord.take());
                    coord = Some(open());
                }
                Op::Ship(i, pick) => {
                    let to = report(&model, pick);
                    let epoch = wardens[i].epoch();
                    let m = model.advance_shipped(IDS[i], epoch, to);
                    let r = coord
                        .as_ref()
                        .unwrap()
                        .advance_shipped(IDS[i], c, epoch, pos(to));
                    match (m, r) {
                        (Ok(am), Ok(ar)) => prop_assert_eq!(pos(am), ar),
                        (Err(em), Err(er)) => {
                            prop_assert!(
                                !er.outcome_unknown(),
                                "a failure, not a decision: {:?}",
                                er
                            );
                            prop_assert!(
                                same_ship_refusal(&em, &er),
                                "model {:?} vs coordinator {:?}",
                                em,
                                er
                            );
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

// ── The coordinator log (P4, file 1d-1) ─────────────────────────────

#[cfg(test)]
mod log_tests {
    use super::*;
    use std::collections::BTreeSet;
    use taso_core::canon::Canonical;
    use taso_core::contract::{
        genesis_id, submission_id, Consistency, ContractRecord, GenesisStarted, Peer,
        TRANSFORM_VERSION,
    };
    use taso_core::coordlog::{Final, Transient};
    use taso_core::envelope::BranchId;
    use taso_core::record::{
        Authority, Consequence, Dispatch, IntentRecord, OpId, OutcomeRecord, Record, RetryPolicy,
    };

    use crate::coordjournal::LEGACY_OBLIGATION;

    const A: WardenId = WardenId::new(1);
    const B: WardenId = WardenId::new(2);

    fn h(n: u8) -> HashVal {
        HashVal::from_bytes([n; 32])
    }

    fn chron(n: u8) -> ChronicleId {
        ChronicleId::from_bytes([n; 16])
    }

    /// A store whose contents the test sets.
    type Carried = BTreeSet<([u8; 16], String, [u8; 32])>;

    #[derive(Default)]
    struct Fake {
        objects: Mutex<BTreeSet<ObjectId>>,
        carried: Mutex<Carried>,
    }

    impl Fake {
        fn put(&self, o: ObjectId) {
            self.objects.lock().unwrap().insert(o);
        }
        fn ship(&self, c: ChronicleId, pack: &str, r: &Submitted) {
            self.carried.lock().unwrap().insert((
                *c.as_bytes(),
                pack.to_string(),
                *r.digest().as_bytes(),
            ));
        }
    }

    impl StoreView for Fake {
        fn carries(&self, c: ChronicleId, name: &str, digest: HashVal) -> bool {
            self.carried.lock().unwrap().contains(&(
                *c.as_bytes(),
                name.to_string(),
                *digest.as_bytes(),
            ))
        }
        fn exists(&self, o: &ObjectId) -> bool {
            self.objects.lock().unwrap().contains(o)
        }
        fn inventory(&self, _: HashVal) -> Option<Inventory> {
            None
        }
        fn fs_packs(&self, _: ChronicleId) -> Vec<InventoryItem> {
            Vec::new()
        }
        fn seal_closure(&self, _: ChronicleId, _: Lsn) -> Vec<ObjectId> {
            Vec::new()
        }
        fn verify_replacement(&self, _: ChronicleId, _: &InventoryItem) -> Option<HashVal> {
            None
        }
    }

    fn config(store: Arc<Fake>, now: u64) -> LogConfig {
        LogConfig {
            store,
            clock: Arc::new(move || now),
            ..LogConfig::default()
        }
    }

    fn open(path: &Path, store: Arc<Fake>) -> Coordinator {
        Coordinator::open_with(path, config(store, 1_000)).unwrap()
    }

    fn genesis() -> GenesisStarted {
        GenesisStarted {
            genesis_id: genesis_id(h(0x20), h(0x21), TRANSFORM_VERSION, None, "jarmo"),
            source_key: h(0x20),
            consistency: Consistency::Immutable,
            classmap_key: h(0x21),
            transform_version: TRANSFORM_VERSION,
            hook_waiver: None,
            authority: Authority {
                actor: "jarmo".into(),
                reason: "T(0)".into(),
            },
            peer: Peer { uid: 0, pid: 1 },
        }
    }

    /// Announce, ship and accept `r` under `epoch` as attempt `n`.
    fn submit(
        coord: &Coordinator,
        store: &Fake,
        c: ChronicleId,
        epoch: Epoch,
        n: u64,
        r: Submitted,
    ) -> Answer {
        let s = submission_id(r.logical_id(), r.digest(), epoch, n);
        if let Err(a) = coord
            .announce(c, epoch, s, r.logical_id(), r.digest())
            .unwrap()
        {
            return a;
        }
        let pack = format!("pack-{n}");
        store.ship(c, &pack, &r);
        let head = coord.query_chronicle(c).unwrap().unwrap().head;
        coord.accept(c, epoch, s, head, pack, r).unwrap()
    }

    fn journal_len(coord: &Coordinator) -> u64 {
        let txn = coord.db.begin_read().unwrap();
        let t = txn.open_table(JOURNAL).unwrap();
        t.range::<u64>(..).unwrap().count() as u64
    }

    /// A genesis claimed and started: the log's state after it, as the
    /// queries answer.
    fn started(coord: &Coordinator, store: &Fake) -> (ChronicleId, Submitted) {
        let g = genesis();
        let t0 = g.genesis_id;
        store.put(ObjectId::content(h(0x20)));
        store.put(ObjectId::content(h(0x21)));
        assert_eq!(
            coord
                .claim_chronicle(t0, A, ClaimAuthority::Genesis)
                .unwrap(),
            Epoch::FIRST
        );
        let r = Submitted::Contract(ContractRecord::GenesisStarted(Box::new(g)));
        assert!(matches!(
            submit(coord, store, t0, Epoch::FIRST, 1, r.clone()),
            Answer::Accepted { log_pos: 1, .. }
        ));
        (t0, r)
    }

    #[test]
    fn the_log_survives_a_restart_from_its_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.redb");
        let store = Arc::new(Fake::default());
        let coord = open(&path, store.clone());
        let (t0, r) = started(&coord, &store);
        // A second submission, cancelled; a pin.
        let late = submission_id(r.logical_id(), r.digest(), Epoch::FIRST, 2);
        assert_eq!(
            coord.cancel(t0, Epoch::FIRST, late).unwrap(),
            Answer::FinalRefused(Final::Cancelled)
        );
        coord.set_retention_pin(t0, true).unwrap();
        let view = coord.query_chronicle(t0).unwrap().unwrap();
        assert_eq!(view.holds.len(), 2, "source and classmap held");
        let logical = coord.query_logical(r.logical_id()).unwrap();
        assert_eq!(logical, Some((1, r.clone())));
        drop(coord);

        // Reopened with a store that holds nothing: the state is the
        // journal's, read from the recorded answers, not from the store.
        let coord = open(&path, Arc::new(Fake::default()));
        assert_eq!(coord.query_chronicle(t0).unwrap(), Some(view));
        assert_eq!(coord.query_logical(r.logical_id()).unwrap(), logical);
        assert_eq!(
            coord.query_submission(t0, late).unwrap(),
            SubmissionStatus::FinalRefused(Final::Cancelled)
        );
        // And it goes on: the same record again is AlreadyAccepted.
        assert!(matches!(
            submit(&coord, &store, t0, Epoch::FIRST, 3, r),
            Answer::AlreadyAccepted { log_pos: 1, .. }
        ));
    }

    /// Rewrite the journal entry `seq` with `f`.
    fn tamper(path: &Path, seq: u64, f: impl FnOnce(&mut Entry)) {
        let db = Database::create(path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(JOURNAL).unwrap();
            let mut e = Entry::decode(t.get(seq).unwrap().unwrap().value()).unwrap();
            f(&mut e);
            t.insert(seq, e.bytes().as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }

    #[test]
    fn a_journal_that_does_not_replay_is_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.redb");
        let store = Arc::new(Fake::default());
        let coord = open(&path, store.clone());
        started(&coord, &store);
        let n = journal_len(&coord);
        drop(coord);
        // The accept is the last entry; its answer, then a store answer.
        let copy = dir.path().join("copy.redb");
        std::fs::copy(&path, &copy).unwrap();
        tamper(&path, n, |e| e.done = Done::Unit.bytes());
        assert!(matches!(
            Coordinator::open_with(&path, config(store.clone(), 1_000)),
            Err(CoordError::Journal(_))
        ));
        tamper(&copy, n, |e| {
            let last = e.calls.len() - 1;
            e.calls[last] ^= 1;
        });
        assert!(matches!(
            Coordinator::open_with(&copy, config(store, 1_000)),
            Err(CoordError::Journal(_))
        ));
    }

    #[test]
    fn the_log_epoch_is_the_ownership_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.redb");
        let store = Arc::new(Fake::default());
        let coord = open(&path, store.clone());
        let c = chron(1);
        coord.register(c, A).unwrap();
        assert_eq!(
            coord.query_chronicle(c).unwrap().unwrap().epoch,
            Epoch::FIRST
        );
        let s = h(9);
        coord
            .announce(c, Epoch::FIRST, s, h(10), h(11))
            .unwrap()
            .unwrap();
        // A transfer fences the log in the same transaction: the pending
        // submission of the old epoch expires, the old epoch is stale.
        assert_eq!(coord.transfer(c, B).unwrap(), Epoch::new(2));
        assert_eq!(
            coord.query_chronicle(c).unwrap().unwrap().epoch,
            Epoch::new(2)
        );
        assert_eq!(
            coord.query_submission(c, s).unwrap(),
            SubmissionStatus::FinalRefused(Final::Expired)
        );
        assert_eq!(
            coord
                .announce(c, Epoch::FIRST, h(12), h(10), h(11))
                .unwrap(),
            Err(Answer::FinalRefused(Final::StaleEpoch))
        );
        coord.transfer_if(c, A, (B, Epoch::new(2))).unwrap();
        drop(coord);
        let coord = open(&path, store);
        assert_eq!(coord.ownership(c).unwrap().epoch, Epoch::new(3));
        assert_eq!(
            coord.query_chronicle(c).unwrap().unwrap().epoch,
            Epoch::new(3)
        );
    }

    #[test]
    fn claims_and_takeovers_are_the_logs_and_a_refusal_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Fake::default());
        let coord = open(&dir.path().join("c.redb"), store.clone());
        let (t0, _) = started(&coord, &store);
        let n = journal_len(&coord);
        // An authority that names nothing.
        assert!(matches!(
            coord.claim_chronicle(chron(7), A, ClaimAuthority::Sanction { commit: h(1) }),
            Err(CoordError::Claim(ClaimError::BadAuthority))
        ));
        assert!(matches!(
            coord.ownership(chron(7)),
            Err(CoordError::UnknownChronicle(_))
        ));
        assert!(matches!(
            coord.claim_chronicle(t0, B, ClaimAuthority::Genesis),
            Err(CoordError::AlreadyRegistered(_))
        ));
        // A takeover by the accepted GenesisStarted, conditional on the
        // epoch read.
        assert!(matches!(
            coord.takeover_target(t0, B, ClaimAuthority::GenesisStarted, Epoch::new(5)),
            Err(CoordError::Claim(ClaimError::EpochMoved { epoch })) if epoch == Epoch::FIRST
        ));
        assert_eq!(journal_len(&coord), n, "refusals journal nothing");
        let (e, head) = coord
            .takeover_target(t0, B, ClaimAuthority::GenesisStarted, Epoch::FIRST)
            .unwrap();
        assert_eq!(e, Epoch::new(2));
        assert_eq!(head.pos, 1);
        let o = coord.ownership(t0).unwrap();
        assert_eq!((o.holder, o.epoch), (B, Epoch::new(2)));
        // The old owner's submissions are stale.
        assert_eq!(
            coord.announce(t0, Epoch::FIRST, h(3), h(4), h(5)).unwrap(),
            Err(Answer::FinalRefused(Final::StaleEpoch))
        );
    }

    // ── Effect bytes and obligations (D33, D34) ─────────────────────

    fn intent(op: u64, consequence: Consequence) -> Payload {
        let barrier = (consequence != Consequence::NoExternalMutation)
            .then(|| taso_core::record::BarrierId::new(op));
        Payload::Intent(IntentRecord {
            op: OpId::new(op),
            provider: "mail".into(),
            request: b"send".to_vec(),
            footprint: Vec::new(),
            dispatch: Dispatch::Immediate,
            retry: RetryPolicy::UnsafeToRetry,
            consequence,
            authority: Vec::new(),
            barrier,
        })
    }

    fn outcome(op: u64, state: OutcomeState) -> Payload {
        Payload::Outcome(OutcomeRecord {
            op: OpId::new(op),
            state,
            evidence: None,
        })
    }

    /// The next records of `c` after its head, with the `Effect` ones'
    /// bytes.
    fn next(
        coord: &Coordinator,
        c: ChronicleId,
        recs: Vec<(Stream, Payload)>,
    ) -> (Vec<Envelope>, Vec<Vec<u8>>) {
        let head = coord.head(c).unwrap();
        let mut prev = (head.lsn, head.hash);
        let mut envs = Vec::new();
        let mut fx = Vec::new();
        for (stream, p) in recs {
            if stream == Stream::Effect {
                fx.push(p.canon_bytes());
            }
            let r = Record::new(
                c,
                BranchId::TRUNK,
                head.epoch,
                stream,
                prev.0.next(),
                prev.1,
                p,
            );
            prev = (r.envelope.lsn, r.envelope.hash);
            envs.push(r.envelope);
        }
        (envs, fx)
    }

    #[test]
    fn effect_bytes_are_checked_before_anything_is_appended() {
        let dir = tempfile::tempdir().unwrap();
        let coord = open(&dir.path().join("c.redb"), Arc::new(Fake::default()));
        let c = chron(1);
        coord.register(c, A).unwrap();
        let fault = |r: Result<ChronicleHead, CoordError>| match r {
            Err(CoordError::EffectPayload { fault, .. }) => fault,
            other => panic!("not refused: {other:?}"),
        };
        let (e, fx) = next(
            &coord,
            c,
            vec![(Stream::Effect, intent(1, Consequence::Irreversible))],
        );
        assert_eq!(fault(coord.append(A, &e[0])), EffectFault::Missing);
        assert_eq!(
            fault(coord.append_batch_with(
                A,
                &e,
                &[outcome(1, OutcomeState::Prepared).canon_bytes()]
            )),
            EffectFault::Mismatch
        );
        assert_eq!(
            fault(coord.append_batch_with(A, &e, &[fx[0].clone(), fx[0].clone()])),
            EffectFault::Extra
        );
        let (fs, _) = next(&coord, c, vec![(Stream::Fs, Payload::Raw(vec![1]))]);
        assert_eq!(
            fault(coord.append_batch_with(A, &fs, &[fx[0].clone()])),
            EffectFault::Extra
        );
        // Bytes that hash right but are no payload.
        let junk = vec![0xff, 0xee];
        let head = coord.head(c).unwrap();
        let bad = Envelope::new(
            c,
            BranchId::TRUNK,
            head.epoch,
            Stream::Effect,
            head.lsn.next(),
            head.hash,
            payload_hash(&junk),
        );
        assert_eq!(
            fault(coord.append_batch_with(A, &[bad], &[junk])),
            EffectFault::Undecodable
        );
        assert_eq!(coord.head(c).unwrap().lsn, Lsn::new(0), "nothing appended");
        coord.append_batch_with(A, &e, &fx).unwrap();
        assert_eq!(coord.obligations(c).unwrap(), vec![1]);
    }

    #[test]
    fn obligations_follow_the_effect_records_and_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.redb");
        let store = Arc::new(Fake::default());
        let coord = open(&path, store.clone());
        let c = chron(1);
        coord.register(c, A).unwrap();
        let step = |recs: Vec<(Stream, Payload)>| {
            let (e, fx) = next(&coord, c, recs);
            coord.append_batch_with(A, &e, &fx).unwrap();
            coord.obligations(c).unwrap()
        };
        // An intent and its release in one batch, as the ledger writes.
        assert_eq!(
            step(vec![
                (Stream::Effect, intent(1, Consequence::Irreversible)),
                (Stream::Effect, outcome(1, OutcomeState::DispatchAuthorized)),
            ]),
            vec![1],
            "released and not reported is open (D34)"
        );
        assert_eq!(
            step(vec![(
                Stream::Effect,
                intent(2, Consequence::NoExternalMutation)
            )]),
            vec![1],
            "no barrier, no obligation"
        );
        assert_eq!(
            step(vec![
                (Stream::Fs, Payload::Raw(vec![7])),
                (Stream::Effect, outcome(1, OutcomeState::OutcomeUnknown)),
            ]),
            vec![1]
        );
        assert_eq!(
            step(vec![(Stream::Effect, intent(3, Consequence::Irreversible))]),
            vec![1, 3]
        );
        assert_eq!(
            step(vec![(
                Stream::Effect,
                outcome(1, OutcomeState::AcceptedUnknown)
            )]),
            vec![3]
        );
        drop(coord);
        let coord = open(&path, store);
        assert_eq!(coord.obligations(c).unwrap(), vec![3]);
        let (e, fx) = next(
            &coord,
            c,
            vec![(
                Stream::Effect,
                outcome(3, OutcomeState::ConfirmedNotApplied),
            )],
        );
        coord.append_batch_with(A, &e, &fx).unwrap();
        assert!(coord.obligations(c).unwrap().is_empty());
    }

    #[test]
    fn a_chronicle_older_than_the_log_gets_an_obligation_that_never_closes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.redb");
        let store = Arc::new(Fake::default());
        let coord = open(&path, store.clone());
        coord.register(chron(1), A).unwrap();
        coord.register(chron(2), A).unwrap();
        let (e, _) = next(&coord, chron(1), vec![(Stream::Fs, Payload::Raw(vec![1]))]);
        coord.append(A, &e[0]).unwrap();
        drop(coord);
        // As a database from before the log: no journal.
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            txn.delete_table(JOURNAL).unwrap();
            txn.commit().unwrap();
        }
        let coord = open(&path, store);
        // Brought in on first use; one with records is never sanctionable.
        coord
            .announce(chron(1), Epoch::FIRST, h(1), h(2), h(3))
            .unwrap()
            .unwrap();
        coord
            .announce(chron(2), Epoch::FIRST, h(1), h(2), h(3))
            .unwrap()
            .unwrap();
        assert_eq!(
            coord.obligations(chron(1)).unwrap(),
            vec![LEGACY_OBLIGATION]
        );
        assert!(coord.obligations(chron(2)).unwrap().is_empty());
        // An accept under a stale announce still answers by the rules.
        assert_eq!(
            coord
                .accept(
                    chron(2),
                    Epoch::FIRST,
                    h(1),
                    Head::EMPTY,
                    "p".into(),
                    Submitted::Contract(ContractRecord::GenesisStarted(Box::new(genesis()))),
                )
                .unwrap(),
            Answer::FinalRefused(Final::NotAnnounced)
        );
        let _ = Transient::NotReadable;
    }
}
