//! The store: one append-only log holding both the blocks and the map.
//!
//! Every change to a device is a **record** appended to one file: block
//! data (`Write`), TRIM (`Discard`), and the map operations (`RootSeal`,
//! `Fork`, `Seal`, `DropBranch`, `DropSeal`, `Reset`, `Unseal`).  A `Flush` record ends a
//! **group**.  A map location ([`Loc::Log`]) is the byte offset of a
//! block's data inside its `Write` record, so the log is the only copy.
//!
//! ```text
//!   header | rec | rec | Flush | rec | rec | Flush | rec ...
//!                         ^ group end, fdatasync   ^ group end   ^ not durable
//! ```
//!
//! # The header (64 bytes)
//!
//! ```text
//!   magic "TASOBLK4" | version u32 | flags u32 | log id [16] | flush key [16] | checksum [16]
//!   checksum = BLAKE3(the 48 bytes before it), its first 16 bytes
//! ```
//!
//! The **log id** is random, made when the log is created, and kept by a
//! compaction: it says which log this is.  The chain below is seeded from
//! the whole header, so a record copied from another log does not verify.
//! The **flush key** is random too, for the Flush record's check (below).
//! Flag bit 0:
//! the log was written by a compaction.  [`Store::open`] refuses a header
//! whose checksum fails, a version above its own, a flag it does not know,
//! and the formats before this one (`TASOBLK1` to `3`: no migration).
//!
//! # Durability, as a disk promises it
//!
//! - [`Store::flush`] appends a `Flush` record and calls `fdatasync` once:
//!   everything before it is durable.  ext4 issues a flush at the end of
//!   every journal commit, so a group boundary is a point where ext4's own
//!   state is consistent (Phase 4 plan §2.2).
//! - A FUA write ([`Store::write`] with `fua`) is followed by a flush before
//!   it returns: durable when acknowledged.
//! - Writes after the last flush may be lost in a crash.  A disk may do the
//!   same, and ext4 is built for it.
//! - A device's flush ([`Store::flush_for`]) promises what the kernel's
//!   barrier asks: everything *that branch* completed before it is on the
//!   medium.  When the branch's last record already lies in a group
//!   (closed by any branch's Flush), the flush appends nothing and waits
//!   for **the first group that closed over it** -- at once if done,
//!   joining its sync if running.  Only a branch with records after the
//!   last Flush appends one (P5 bite 4, rev. 2:
//!   the flush join design of 2026-11-03; rev. 1 waited for
//!   the newest group, which under load is never durable yet).
//! - [`Store::seal`] appends the Seal and flushes: a Seal is always
//!   durable, and it stands for every record before it.
//!
//! # Records and recovery
//!
//! ```text
//!   magic u32 | len u32 | kind u8 | body (len bytes) | hash [32]
//!   hash = BLAKE3(previous record's hash || kind || len || body)
//! ```
//!
//! The header's hash seeds the chain.  [`Store::open`] reads the log from
//! the start, checks every record against the chain, and replays it into
//! a fresh [`Map`] (same calls, same ids).  It stops at the first record
//! that is short, has a bad magic or a wrong hash, and cuts the file back
//! to the end of the **last Flush** it verified: what was durable.
//!
//! # The Flush record says what was durable
//!
//! ```text
//!   body (40 bytes): durable end u64 | own offset u64 | check [24]
//!   check = BLAKE3 keyed from the header's flush key, over the 16 bytes before it
//! ```
//!
//! **Durable end** is the end offset of the newest Flush whose
//! `fdatasync` had returned when this Flush was appended: what the store
//! knew to be on the medium.  Never this Flush's own group, whose sync has
//! not run yet; 0 until the first sync after an open, and in every Flush a
//! compaction writes (it claims nothing; claiming less is always safe).
//! The [`Syncer`] and [`Store::flush`] publish the value after each sync.
//! **Own offset** is where the record starts, and the check is keyed, so
//! that a Flush can be told from bytes that only look like one without the
//! chain: a Vessel's agent chooses the bytes of its blocks, which lie in
//! this file, and must not be able to place a Flush's image in it.  A
//! Flush whose body does not check out fails the replay.
//!
//! A record that verifies and has a kind this version does not know was
//! written by a newer one: the open is refused
//! ([`StoreError::UnknownKind`]) and nothing is cut.  (It used to read as
//! the end of the log, and everything after the previous Flush was cut:
//! maturity review of e4a37b2, finding 2.)
//!
//! # A torn tail and damage are told apart
//!
//! The replay stops at the first record that does not verify, at offset
//! X.  Two things leave such a record: a crash while the tail was being
//! written (the kernel may have written later pages and not earlier ones,
//! so well-formed bytes after X prove nothing), and bytes that were on the
//! medium and have changed since.  [`Store::open`] reads the rest of the
//! file for Flush records whose own offset and keyed check hold, and takes
//! the largest durable end D they name.
//!
//! - **No such Flush, or D <= X: a torn tail.**  The file is cut back to
//!   the last verified Flush, as it always was ([`Recovered::cut`]).
//! - **D > X: damage.**  When that later Flush was appended, an
//!   `fdatasync` covering X had returned.  Nothing is dropped: everything
//!   from the last verified Flush to the end of the file is copied to
//!   `<log>.damaged-<offset>`, that file and its directory are synced, and
//!   only then is the log cut there ([`Recovered::set_aside`]).  The
//!   records after X cannot be replayed (their chain starts from a record
//!   that is gone), and replaying them without it would give a state that
//!   never was.  If the copy cannot be made the open is refused
//!   ([`StoreError::SetAside`]) and the log is left whole.
//!
//! (It used to be one case, a cut: one flipped bit early in the log made
//! the next start drop every later group of every Vessel on the node and
//! serve normally.  Maturity review of e4a37b2, finding 1.)  The second
//! copy of what is set aside is the shipped packs, not this file.
//!
//! Not covered: the replay starts at the checkpoint, so damage in a
//! record before it is met only when its block is read.
//!
//! # Tags, origins and names (for the Warden's `Pool` and `Layers`)
//!
//! - A Seal may carry a **tag**: up to [`MAX_TAG`] opaque bytes, written in
//!   its `Seal` record.  The Warden puts its own Seal record's lsn and hash
//!   there.
//! - The store remembers which branch each Seal was made from (its
//!   **origin**), so [`Store::seals_of`] lists a dataset's own layers.
//! - A branch may have a **name** (a `Name` record): the dataset name.
//!   Names are unique among live branches, survive [`Store::seal`] (the
//!   branch keeps its id), and are freed when the branch is dropped.
//!
//! All three are rebuilt from the log on [`Store::open`], held back with
//! their group like every other map change.
//!
//! # Export and import (shipping a Seal to another node)
//!
//! [`Store::export`] writes the blocks that differ between two Seals (or
//! between a Seal and the zero base image) as a stream; [`Store::import`]
//! applies one to a clean branch on another store.  Sealing that branch
//! there gives the same image.  The stream:
//!
//! ```text
//!   "TASOBLKX" | run* | 0u8 | blocks u64 | BLAKE3(everything before) [32]
//!   run = kind u8 (1 data, 2 zeros) | lba u64 | count u32 | data (data runs)
//! ```
//!
//! Import verifies as it goes and resets the branch on any failure (bad
//! magic, truncation, wrong count or hash), so a stream that fails leaves
//! nothing.
//!
//! # Checkpoints (a fast start with a large log)
//!
//! [`Store::open`] would otherwise read and verify the whole log.
//! [`Store::checkpoint`] flushes, then writes `<log>.ckpt` atomically: the
//! map, names, tags and garbage count at that durable point, its end
//! offset and sequence number, and the hashes of that Flush record and the
//! one before it.  `open` loads a checkpoint only if its own BLAKE3 is
//! right and the Flush record at its offset is on disk with exactly that
//! chain hash; then it replays only what follows.  Anything else (no
//! file, damage, a log cut below it, another log's checkpoint) means a
//! full replay, which is always correct.  [`Recovered::checkpoint`] says
//! which happened.  The records before the checkpoint were verified when
//! they were written and when the checkpoint was made from them.
//!
//! # Compaction (taking the garbage out)
//!
//! Overwritten, discarded and dropped blocks stay in the log as garbage.
//! [`Store::compaction`] writes a new log holding only the live blocks
//! and the state that points at them (a **base**), followed by whatever
//! the old log received meanwhile, and swaps it in; layer ids, names,
//! tags, sequence numbers and the log id carry over.  A compacted log has
//! flag bit 0 set and may hold two more record kinds, both only in its first
//! group: `Data` (live blocks, no map effect) and `Base` (pieces of the
//! state, in checkpoint encoding).  See the `compact` module.
//!
//! The base image is zeros: a fresh device reads zeros until written, and
//! ext4 is created by `mkfs` on a branch, then sealed.
//!
//! An I/O error while appending poisons the store: the map may be ahead
//! of the file, so every later call (reads too) fails until it is
//! reopened, and reopening rebuilds the map from the log.  A caller can
//! poison it too ([`Store::poison`]).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read};
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use crate::map::{Kind, LayerId, Loc, Map, MapError, BLOCK};

mod compact;
pub use compact::{Compacted, Compaction, OldLog};

const FILE_MAGIC: &[u8; 8] = b"TASOBLK4";
/// The formats before the header had a version, an identity or a
/// checksum: the first prototype's (1), and the plain (2) and compacted
/// (3) logs up to main e4a37b2.  Refused by name; there is no migration.
const OLD_MAGICS: [&[u8; 8]; 3] = [b"TASOBLK1", b"TASOBLK2", b"TASOBLK3"];
/// The number of this format, in the header.  A log with a larger one was
/// written by a newer version and is refused.
pub const FORMAT_VERSION: u32 = 4;
/// Header flag: the log was written by a compaction, so it may begin with
/// a base ([`K_DATA`] and [`K_BASE`] records).  Otherwise the same records.
const FLAG_COMPACTED: u32 = 1;
/// A log's identity: random, made with the log, kept by a compaction.
pub type LogId = [u8; 16];
/// Largest Seal tag, in bytes.
pub const MAX_TAG: usize = 64;
/// Largest branch name, in bytes.
pub const MAX_NAME: usize = 255;
const HEADER_LEN: u64 = 64;
/// A Flush record's body ([module docs](self)).
const FLUSH_BODY: usize = 40;
/// A whole Flush record.
const FLUSH_LEN: u64 = REC_HEAD + FLUSH_BODY as u64 + HASH as u64;

/// How far past the tail the log's file is kept written with zeros and
/// synced, ahead of the records that will go there (maturity review of
/// e4a37b2, finding 4; F4-a (a), F4-c (a), 2026-11-27).  Two things come
/// of it.  A full disk is met when the reserve is made, not when a record
/// is appended after the map has moved: a write that does not fit is
/// refused alone, and the store goes on.  And a group commit's
/// `fdatasync` then carries data only: appending past the end of the file
/// makes every sync also journal the file's growth, as allocating with
/// `fallocate` does for its unwritten extents.  This is PostgreSQL's
/// `wal_init_zero`, for the reasons and the measurement given in
/// https://www.postgresql.org/message-id/4xaez4hh3cwkclr77tnkdba6wisueu32vza44iugozai5hklyb@5epf6zpo66aa
/// (pgsql-hackers, "Re: Purpose of wal_init_zero", 2025-01-15).
const RESERVE: u64 = if cfg!(test) { 64 << 10 } else { 64 << 20 };
/// The filler is woken when less than this is ready past the tail.
const RESERVE_LOW: u64 = RESERVE / 2;
/// The last part of the reserve, which a write of data may not use: it is
/// kept for the records that close a group or a turn (Flush, Seal, and
/// the small records of forks, names and discards), so that a Seal still
/// closes on a full disk.
const HELD_BACK: u64 = if cfg!(test) { 4 << 10 } else { 64 << 10 };
/// The filler writes and syncs this much at a time, so a write that
/// overtakes it waits for one piece at most.
const FILL_CHUNK: u64 = if cfg!(test) { 16 << 10 } else { 1 << 20 };

/// The body of a Flush record at offset `at` of a log whose flush key
/// (derived, [`Header::flush_mac`]) is `key`, saying that the log was
/// durable up to `durable`.
fn flush_body(key: &[u8; 32], at: u64, durable: u64) -> [u8; FLUSH_BODY] {
    let mut b = [0u8; FLUSH_BODY];
    b[..8].copy_from_slice(&durable.to_le_bytes());
    b[8..16].copy_from_slice(&at.to_le_bytes());
    let check = blake3::keyed_hash(key, &b[..16]);
    b[16..].copy_from_slice(&check.as_bytes()[..FLUSH_BODY - 16]);
    b
}

/// The durable end a Flush record's `body` names, if it is the body of a
/// Flush at offset `at` of the log with this key: its length, its own
/// offset and its check.
fn flush_claim(key: &[u8; 32], body: &[u8], at: u64) -> Option<u64> {
    let durable = u64::from_le_bytes(body.get(..8)?.try_into().ok()?);
    (body == flush_body(key, at, durable)).then_some(durable)
}
const REC_MAGIC: u32 = 0x5442_4c4b; // "TBLK"
/// magic + len + kind
const REC_HEAD: u64 = 4 + 4 + 1;
const HASH: usize = 32;
/// Largest record body accepted: a write of 4096 blocks (16 MiB) plus its
/// fields.  Bounds what recovery allocates for a corrupt length.
const MAX_BODY: u32 = 4096 * BLOCK as u32 + 64;

const K_WRITE: u8 = 1;
const K_DISCARD: u8 = 2;
const K_ROOT: u8 = 3;
const K_FORK: u8 = 4;
const K_SEAL: u8 = 5;
const K_DROP_BRANCH: u8 = 6;
const K_DROP_SEAL: u8 = 7;
const K_FLUSH: u8 = 8;
const K_NAME: u8 = 9;
const K_RESET: u8 = 10;
/// Block data with no map effect: the live blocks a compaction copied.
const K_DATA: u8 = 11;
/// A piece of a compacted log's base state (map, tags, names, sequence
/// number), in checkpoint encoding; the pieces of the first group joined.
const K_BASE: u8 = 12;
/// A branch moved down past the Seal it alone stood on (an orphan, F1,
/// 2026-10-28).  A log with one is refused by a store older than this kind.
const K_UNSEAL: u8 = 13;
/// A Seal folded into the one Seal on top of it (S-c, 2026-11-14).  A log
/// with one is refused by a store older than this kind.
const K_FOLD: u8 = 14;
const K_LAST: u8 = K_FOLD;

/// `TASOCKP2`: the log's id follows the magic (a `TASOCKP1` checkpoint is
/// not read: a full replay).
const CKPT_MAGIC: &[u8; 8] = b"TASOCKP2";

/// Export streams: magic, run kinds, and the longest data run (4 MiB).
const STREAM_MAGIC: &[u8; 8] = b"TASOBLKX";
const RUN_DATA: u8 = 1;
const RUN_ZERO: u8 = 2;
const RUN_MAX: u64 = 1024;

/// Why a store operation failed.
#[derive(Debug)]
pub enum StoreError {
    /// The file system said no.  After a failed append the store is
    /// poisoned.
    Io(io::Error),
    /// The map refused the operation; nothing was appended.
    Map(MapError),
    /// The file is not a block log (bad header).
    NotALog,
    /// A log in a format before this one (`TASOBLK1`, `2` or `3`), which
    /// this version does not read or migrate.
    OldFormat,
    /// The header's checksum fails: the header is damaged, and with it
    /// the log's identity and the chain's seed.  Nothing was changed.
    DamagedHeader,
    /// The header names a format version above [`FORMAT_VERSION`], or a
    /// flag this version does not know: a newer version wrote the log.
    /// Nothing was changed.
    NewerFormat {
        /// The header's version.
        version: u32,
        /// The header's flags.
        flags: u32,
    },
    /// The log is damaged (see [`Recovered::set_aside`]) and the damaged
    /// part could not be copied aside, for want of room or otherwise.
    /// The log was left whole: the only copy is never dropped.
    SetAside {
        /// Bytes the copy needs.
        need: u64,
        /// Where the copy was to go.
        path: PathBuf,
        /// Why it failed.
        error: io::Error,
    },
    /// A record that verifies but whose kind this version does not know:
    /// a newer version wrote it.  Nothing was cut.
    UnknownKind {
        /// The record's kind.
        kind: u8,
        /// Where the record starts in the file.
        at: u64,
    },
    /// A verified record does not replay: the log contradicts itself.
    Replay {
        /// The record's sequence number.
        lsn: u64,
        /// What the map said.
        error: MapError,
    },
    /// A write's length is zero or not a whole number of blocks.
    BadLength(usize),
    /// A write is larger than one record may be.
    TooLarge(usize),
    /// A Seal tag longer than [`MAX_TAG`].
    BadTag(usize),
    /// A branch name that is too long or has characters outside
    /// `A-Z a-z 0-9 _ . : / -`.
    BadName(String),
    /// Another live branch already has this name.
    NameTaken(String),
    /// The layer is not below the exported Seal.
    NotAnAncestor {
        /// The layer given as the base.
        from: LayerId,
        /// The Seal being exported.
        to: LayerId,
    },
    /// Import into a branch that already holds blocks of its own.
    NotClean(LayerId),
    /// An import stream that is not whole or not valid.  Nothing of it was
    /// kept.
    BadStream(&'static str),
    /// A verified record about names or tags does not replay.
    ReplayMeta {
        /// The record's sequence number.
        lsn: u64,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// An earlier append failed; reopen the store.
    Poisoned,
    /// Another store has this log open (its lock file, named here, is
    /// held): nothing was read, cut or created.
    Locked(PathBuf),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Map(e) => write!(f, "map: {e}"),
            Self::NotALog => write!(f, "not a taso-blk log"),
            Self::OldFormat => write!(
                f,
                "a taso-blk log in an older format (TASOBLK1, 2 or 3); this version reads TASOBLK4 and migrates nothing"
            ),
            Self::DamagedHeader => write!(
                f,
                "the log's header fails its checksum: the header is damaged; nothing was changed"
            ),
            Self::NewerFormat { version, flags } => write!(
                f,
                "the log is in format version {version} (flags {flags:#x}); this version reads {FORMAT_VERSION}: a newer taso-blk wrote it; nothing was changed"
            ),
            Self::SetAside { need, path, error } => write!(
                f,
                "the log is damaged and its damaged part ({need} bytes) could not be set aside at {}: {error}; the log was left whole (free {need} bytes there and start again)",
                path.display()
            ),
            Self::UnknownKind { kind, at } => write!(
                f,
                "the record at byte {at} verifies but is of kind {kind}, which this version does not know: a newer taso-blk wrote it; nothing was cut"
            ),
            Self::BadTag(n) => write!(f, "a tag of {n} bytes; at most {MAX_TAG}"),
            Self::BadName(n) => write!(
                f,
                "bad branch name {n:?}: 1 to {MAX_NAME} of A-Z a-z 0-9 _ . : / -"
            ),
            Self::NameTaken(n) => write!(f, "branch name {n:?} is taken"),
            Self::ReplayMeta { lsn, reason } => write!(f, "record {lsn} does not replay: {reason}"),
            Self::NotAnAncestor { from, to } => write!(f, "{from} is not below {to}"),
            Self::NotClean(b) => {
                write!(f, "{b} holds blocks of its own; reset it before importing")
            }
            Self::BadStream(why) => write!(f, "bad import stream ({why}); nothing was kept"),
            Self::Replay { lsn, error } => write!(f, "record {lsn} does not replay: {error}"),
            Self::BadLength(n) => write!(
                f,
                "write of {n} bytes is not a whole number of {BLOCK}-byte blocks"
            ),
            Self::TooLarge(n) => write!(f, "write of {n} bytes exceeds one record"),
            Self::Poisoned => write!(f, "an earlier append failed; reopen the store"),
            Self::Locked(p) => write!(
                f,
                "another store has this log open ({} is locked): two writers would overwrite each other's blocks",
                p.display()
            ),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<MapError> for StoreError {
    fn from(e: MapError) -> Self {
        Self::Map(e)
    }
}

/// What [`Store::open`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recovered {
    /// Records replayed (up to and including the last verified Flush).
    pub records: u64,
    /// Groups (Flush records) replayed.
    pub groups: u64,
    /// Bytes cut from the end of the file: records after the last Flush,
    /// and anything torn or unverifiable.
    pub cut: u64,
    /// The sequence number of the checkpoint the replay started from, or
    /// `None` for a full replay.
    pub checkpoint: Option<u64>,
    /// The log's mode before `open` took away others' access to it (and
    /// to its checkpoint), or `None` if they had none: a log made before
    /// the store made its files private (audit 2026-11-16, S1).  The
    /// caller says so in its own log.
    pub tightened: Option<u32>,
    /// The log's identity, from its header.
    pub id: LogId,
    /// Damage: a part of the log that had been durable no longer
    /// verified, and was set aside whole instead of cut
    /// ([module docs](self)).  `cut` is 0 then.
    pub set_aside: Option<SetAside>,
}

/// A damaged part of the log, kept as a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetAside {
    /// Where the record that did not verify starts.
    pub at: u64,
    /// The durable end a later Flush record names: `at` lies below it.
    pub durable: u64,
    /// Where the part set aside begins: the end of the last verified
    /// Flush, and the log's length now.
    pub from: u64,
    /// Its length: everything from there to the old end of the file.
    pub bytes: u64,
    /// The file it was copied to.
    pub path: PathBuf,
}

/// The header's fields ([module docs](self)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Header {
    flags: u32,
    id: LogId,
    flush_key: [u8; 16],
}

impl Header {
    /// A new log's header: a fresh identity and flush key from the
    /// kernel's random source.
    fn fresh() -> io::Result<Self> {
        let mut r = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut r)?;
        Ok(Self {
            flags: 0,
            id: r[..16].try_into().expect("16 bytes"),
            flush_key: r[16..].try_into().expect("16 bytes"),
        })
    }

    /// This log's header as a compaction writes it: the same identity and
    /// key, the compacted flag set.
    fn compacted(self) -> Self {
        Self {
            flags: self.flags | FLAG_COMPACTED,
            ..self
        }
    }

    /// The key of the Flush records' check, derived from the header's
    /// flush key.
    fn flush_mac(&self) -> [u8; 32] {
        blake3::derive_key("taso-blk 2026-11-25 flush record check", &self.flush_key)
    }

    fn is_compacted(&self) -> bool {
        self.flags & FLAG_COMPACTED != 0
    }

    fn encode(&self) -> [u8; HEADER_LEN as usize] {
        let mut b = [0u8; HEADER_LEN as usize];
        b[..8].copy_from_slice(FILE_MAGIC);
        b[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        b[12..16].copy_from_slice(&self.flags.to_le_bytes());
        b[16..32].copy_from_slice(&self.id);
        b[32..48].copy_from_slice(&self.flush_key);
        let sum = blake3::hash(&b[..48]);
        b[48..].copy_from_slice(&sum.as_bytes()[..16]);
        b
    }

    /// The checksum before anything it covers is believed; then the
    /// version and the flags.
    fn decode(b: &[u8; HEADER_LEN as usize]) -> Result<Self, StoreError> {
        if &b[..8] != FILE_MAGIC {
            return Err(StoreError::NotALog);
        }
        if blake3::hash(&b[..48]).as_bytes()[..16] != b[48..] {
            return Err(StoreError::DamagedHeader);
        }
        let version = u32::from_le_bytes(b[8..12].try_into().expect("4 bytes"));
        let flags = u32::from_le_bytes(b[12..16].try_into().expect("4 bytes"));
        if version != FORMAT_VERSION || flags & !FLAG_COMPACTED != 0 {
            return Err(StoreError::NewerFormat { version, flags });
        }
        Ok(Self {
            flags,
            id: b[16..32].try_into().expect("16 bytes"),
            flush_key: b[32..48].try_into().expect("16 bytes"),
        })
    }
}

/// Counters for measurements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Bytes in the log file.
    pub log_bytes: u64,
    /// Bytes of block data no live layer references any more.
    pub garbage_bytes: u64,
    /// Records appended or replayed.
    pub records: u64,
    /// `fdatasync` calls made by flushes.
    pub syncs: u64,
    /// Device flushes answered from a group already closed: no record, no
    /// sync of their own ([`Store::flush_for`]).
    pub flushes_joined: u64,
    /// Their time: summed, and the longest (µs).  With the [`Syncer`]'s,
    /// what one block-log sync costs (P5, the 50 ms line, bite 3: how much
    /// of a Seal's `seal.log` is the sync and how much waiting for one).
    pub sync_us: u64,
    /// The longest of them (µs).
    pub sync_max_us: u64,
    /// Where a write's time under the lock goes, summed over every write
    /// (µs), for the probe of the serial append (the bare-metal node, 2026-10-26:
    /// 0.8 ms per 512 KiB under the lock, four threads changing nothing).
    /// The map's inserts, one per block.
    pub write_map_us: u64,
    /// The copy of the data into the record's body.
    pub write_copy_us: u64,
    /// The chain hash, with the record's own copy (every record kind).
    pub write_hash_us: u64,
    /// The `pwrite` of the record into the log file (every record kind).
    pub write_pwrite_us: u64,
}

/// One block log file and the map it holds.
pub struct Store {
    /// The log's lock (`<log>.lock`, held exclusively while the store
    /// lives): one store per log (audit 2026-11-06, finding 1).  A file
    /// beside the log, not the log itself, so a compaction's rename does
    /// not take it away: the switch hands it to the new store.
    lock: File,
    file: File,
    /// The log as the [`Syncer`] sees it: a handle the store shares with
    /// it, which a compaction's switch points at the new log
    /// ([`Compaction::finish`]), so a Syncer made before the switch syncs
    /// the log after it.
    shared: Arc<LogFile>,
    path: PathBuf,
    /// The log's header: its identity, its flush key, its flags.
    header: Header,
    /// [`Header::flush_mac`], derived once.
    flush_mac: [u8; 32],
    map: Map,
    meta: Meta,
    /// End of the last record: where the next one goes.
    tail: u64,
    /// Sequence number of the last record (records count from 1).
    lsn: u64,
    /// Hash of the last record (or of the header).
    prev: [u8; HASH],
    stats: Stats,
    poisoned: bool,
    /// Tests: a filesystem with room for the log's file up to this many
    /// bytes; a write that would grow it further fails `StorageFull`, as
    /// a full ext4 does (maturity review finding 4).
    #[cfg(test)]
    room: Option<u64>,
    /// Branches with a record since the last Flush (write, discard, fork,
    /// name, reset, unseal, Seal, drop): their data is in no group yet.
    touched: HashSet<LayerId>,
    /// For a branch not in `touched`, the lsn of the Flush record that
    /// first closed a group over its last record; absent means nothing
    /// since the log was opened, when everything was in a group.
    covered: HashMap<LayerId, u64>,
}

impl Store {
    /// Create a new, empty log at `path` (which must not exist) and make
    /// its existence durable.
    pub fn create(path: &Path) -> Result<Self, StoreError> {
        let lock = lock_log(path)?;
        // Private from the start: a Vessel's file modes do not protect its
        // bytes here (audit 2026-11-16, S1).
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(PRIVATE)
            .open(path)?;
        // A checkpoint of an earlier log under this name is not ours, nor
        // is an unfinished compaction of one.
        for stale in [
            ckpt_path(path),
            compact::temp_path(path),
            ckpt_path(&compact::temp_path(path)),
        ] {
            remove_if_there(&stale)?;
        }
        let fields = Header::fresh()?;
        let header = fields.encode();
        file.write_all_at(&header, 0)?;
        file.sync_all()?;
        sync_dir(path)?;
        Ok(Self {
            lock,
            shared: Arc::new(LogFile::new(file.try_clone()?, HEADER_LEN, HEADER_LEN)),
            file,
            path: path.to_path_buf(),
            header: fields,
            flush_mac: fields.flush_mac(),
            map: Map::new(),
            meta: Meta::default(),
            tail: HEADER_LEN,
            lsn: 0,
            prev: seed(&header),
            stats: Stats {
                log_bytes: HEADER_LEN,
                ..Stats::default()
            },
            poisoned: false,
            #[cfg(test)]
            room: None,
            touched: HashSet::new(),
            covered: HashMap::new(),
        })
    }

    /// Open an existing log: verify, replay to the last Flush, cut the
    /// rest, and make the cut durable.
    ///
    /// One pass.  A group's map changes are held back until its Flush is
    /// verified, then applied together, so records after the last Flush
    /// never reach the map.
    pub fn open(path: &Path) -> Result<(Self, Recovered), StoreError> {
        // Before anything is read, cut or removed: another store's
        // unflushed tail is not ours to cut.
        let lock = lock_log(path)?;
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let len = file.metadata()?.len();
        // The magic first: an older format's header is shorter than ours,
        // and is refused by name whatever its length.
        let mut magic = [0u8; 8];
        if len < 8 {
            return Err(StoreError::NotALog);
        }
        file.read_exact_at(&mut magic, 0)?;
        if OLD_MAGICS.contains(&&magic) {
            return Err(StoreError::OldFormat);
        }
        if &magic != FILE_MAGIC || len < HEADER_LEN {
            return Err(StoreError::NotALog);
        }
        let mut header = [0u8; HEADER_LEN as usize];
        file.read_exact_at(&mut header, 0)?;
        let fields = Header::decode(&header)?;
        let compacted = fields.is_compacted();
        // A log made before the store made its files private: others'
        // access goes, the owner's and the group's stay (an operator's
        // group setting is theirs).  Its checkpoint goes with it.
        let tightened = no_others(&file)?;
        if let Ok(ck) = File::open(ckpt_path(path)) {
            no_others(&ck)?;
        }
        // A compaction that did not finish left its new log beside this
        // one; this one is still the log.
        for stale in [
            compact::temp_path(path),
            ckpt_path(&compact::temp_path(path)),
            lock_path(&compact::temp_path(path)),
        ] {
            remove_if_there(&stale)?;
        }

        // Start from a checkpoint if one checks out, else from the header.
        let flush_mac = fields.flush_mac();
        let ck = load_checkpoint(path, &file, len, &fields.id, &flush_mac);
        let from = ck.as_ref().map(|c| c.lsn);
        let (mut map, mut meta, start, start_lsn, start_prev, mut garbage) = match ck {
            Some(c) => (c.map, c.meta, c.end, c.lsn, c.prev, c.garbage),
            None => (Map::new(), Meta::default(), HEADER_LEN, 0, seed(&header), 0),
        };
        let mut r = BufReader::with_capacity(
            1 << 20,
            ReadAt {
                file: &file,
                pos: start,
                end: len,
            },
        );
        let (mut pos, mut lsn, mut prev) = (start, start_lsn, start_prev);
        // State at the last verified Flush.
        let (mut end, mut good_lsn, mut good_prev, mut groups) = (start, start_lsn, prev, 0u64);
        let mut pending: Vec<Pending> = Vec::new();
        // A compacted log's base: where its data records are, and the
        // joined base pieces.  Only in the first group of the file.
        let mut base = Base::default();
        while let Some((kind, body, hash)) = read_record(&mut r, &prev)? {
            if !(K_WRITE..=K_LAST).contains(&kind) {
                // It verifies, so it is a record, and one a newer version
                // wrote.  Before anything is cut: the file is as it was.
                return Err(StoreError::UnknownKind { kind, at: pos });
            }
            lsn += 1;
            let rec_at = pos;
            let data_at = pos + REC_HEAD;
            pos += REC_HEAD + body.len() as u64 + HASH as u64;
            prev = hash;
            if kind == K_DATA || kind == K_BASE {
                let in_base = compacted && start == HEADER_LEN && groups == 0 && pending.is_empty();
                if !in_base {
                    return Err(StoreError::ReplayMeta {
                        lsn,
                        reason: "a base record outside a compacted log's first group",
                    });
                }
                base.add(kind, &body, data_at)
                    .map_err(|reason| StoreError::ReplayMeta { lsn, reason })?;
            } else if kind == K_FLUSH {
                // The chain verified it, so the store wrote it: a body
                // that does not check out is the writer's fault, not a
                // torn end.
                if flush_claim(&flush_mac, &body, rec_at).is_none() {
                    return Err(StoreError::ReplayMeta {
                        lsn,
                        reason: "a Flush record whose body does not check out",
                    });
                }
                if !base.is_empty() {
                    if !pending.is_empty() {
                        return Err(StoreError::ReplayMeta {
                            lsn,
                            reason: "other records in a base group",
                        });
                    }
                    (map, meta, lsn) = base
                        .decode()
                        .map_err(|reason| StoreError::ReplayMeta { lsn, reason })?;
                    base = Base::default();
                }
                for p in pending.drain(..) {
                    garbage += replay(&mut map, &mut meta, &p)?;
                }
                (end, good_lsn, good_prev) = (pos, lsn, prev);
                groups += 1;
            } else {
                pending.push(Pending::of(kind, &body, data_at, lsn));
            }
        }
        // The replay stopped at `pos`.  If bytes lie there that are no
        // record, a later Flush may say they had been durable: damage, set
        // aside whole; else a torn tail, cut (module docs).  Zeros that run
        // from the last non-zero byte to the end of the file are the
        // reserve the store keeps ahead of its tail ([`RESERVE`]): not a
        // torn tail, never counted as cut, and kept.  Bytes that are not
        // zero, zeros among them, are what they always were.
        let data_end = nonzero_end(&file, end, len)?;
        let mut cut = data_end - end;
        let mut set_aside = None;
        if pos < data_end {
            if let Some(durable) =
                later_durable_end(&file, &flush_mac, pos, data_end)?.filter(|d| *d > pos)
            {
                let refused = |to: &Path, error| StoreError::SetAside {
                    need: cut,
                    path: to.to_path_buf(),
                    error,
                };
                let to = aside_path(path, &file, end, cut).map_err(|e| refused(path, e))?;
                copy_aside(&file, end, cut, &to).map_err(|e| refused(&to, e))?;
                set_aside = Some(SetAside {
                    at: pos,
                    durable,
                    from: end,
                    bytes: cut,
                    path: to,
                });
            }
        }
        // A cut takes the reserve after it too; the filler makes it again.
        let allocated = if cut > 0 {
            file.set_len(end)?;
            file.sync_all()?;
            end
        } else {
            len
        };
        if set_aside.is_some() {
            cut = 0;
        }
        let stats = Stats {
            log_bytes: end,
            garbage_bytes: garbage,
            records: good_lsn,
            ..Stats::default()
        };
        let store = Self {
            lock,
            shared: Arc::new(LogFile::new(file.try_clone()?, end, allocated)),
            file,
            path: path.to_path_buf(),
            header: fields,
            flush_mac,
            map,
            meta,
            tail: end,
            lsn: good_lsn,
            prev: good_prev,
            stats,
            poisoned: false,
            #[cfg(test)]
            room: None,
            touched: HashSet::new(),
            covered: HashMap::new(),
        };
        Ok((
            store,
            Recovered {
                records: good_lsn,
                groups,
                cut,
                checkpoint: from,
                tightened,
                id: fields.id,
                set_aside,
            },
        ))
    }

    /// The log's identity: random, made with the log, kept by a
    /// compaction.  Not poisoned by a failed append: it is the header's.
    pub fn id(&self) -> LogId {
        self.header.id
    }

    /// The map (read-only): layers, kinds, deltas.  Refused once the
    /// store is poisoned, as every read below is: the map may then be
    /// ahead of the file, and an answer from it could name a layer whose
    /// record never reached the log (audit 2026-11-09, poisoned reads).
    pub fn map(&self) -> Result<&Map, StoreError> {
        self.check()?;
        Ok(&self.map)
    }

    /// Where the log lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Sequence number of the last record.
    pub fn lsn(&self) -> u64 {
        self.lsn
    }

    /// A Template's first Seal (empty, over the zero base image).  Durable
    /// when this returns.
    pub fn root_seal(&mut self) -> Result<LayerId, StoreError> {
        self.check()?;
        let lsn = self.lsn + 1;
        let id = self.map.root_seal(lsn);
        self.meta.seals.insert(
            id,
            SealInfo {
                origin: None,
                tag: Vec::new(),
            },
        );
        self.append(K_ROOT, &[])?;
        self.flush()?;
        Ok(id)
    }

    /// A new branch on `seal`.  Ordered with the writes that follow it;
    /// durable at the next flush.
    pub fn fork(&mut self, seal: LayerId) -> Result<LayerId, StoreError> {
        self.check()?;
        let id = self.map.fork(seal)?;
        self.append(K_FORK, &seal.get().to_le_bytes())?;
        self.touched(id);
        Ok(id)
    }

    /// Write `data` (whole blocks) at block `lba` of `branch`.  With `fua`
    /// it is durable when this returns; otherwise at the next flush.
    pub fn write(
        &mut self,
        branch: LayerId,
        lba: u64,
        data: &[u8],
        fua: bool,
    ) -> Result<(), StoreError> {
        self.check()?;
        if data.is_empty() || !(data.len() as u64).is_multiple_of(BLOCK) {
            return Err(StoreError::BadLength(data.len()));
        }
        let count = data.len() as u64 / BLOCK;
        if 16 + data.len() > MAX_BODY as usize {
            return Err(StoreError::TooLarge(data.len()));
        }
        lba.checked_add(count).ok_or(MapError::Overflow)?;
        if self.map.kind(branch)? != Kind::Branch {
            return Err(MapError::NotABranch(branch).into());
        }
        // Room for the record before the map moves (finding 4): a write
        // that does not fit is refused here, and nothing has changed.
        self.room_for(REC_HEAD + 16 + data.len() as u64 + HASH as u64, false)?;
        // The data starts after the record head and the two fields.
        let data_at = self.tail + REC_HEAD + 16;
        let t = std::time::Instant::now();
        for i in 0..count {
            if self
                .map
                .write(branch, lba + i, Loc::Log(data_at + i * BLOCK))?
                .is_some()
            {
                self.stats.garbage_bytes += BLOCK;
            }
        }
        self.stats.write_map_us += t.elapsed().as_micros() as u64;
        let t = std::time::Instant::now();
        let mut body = Vec::with_capacity(16 + data.len());
        body.extend_from_slice(&branch.get().to_le_bytes());
        body.extend_from_slice(&lba.to_le_bytes());
        body.extend_from_slice(data);
        self.stats.write_copy_us += t.elapsed().as_micros() as u64;
        self.append_timed(K_WRITE, &body)?;
        self.touched(branch);
        if fua {
            self.flush()?;
        }
        Ok(())
    }

    /// Discard (TRIM) `count` blocks from `lba`: they read as zeros.
    pub fn discard(&mut self, branch: LayerId, lba: u64, count: u64) -> Result<(), StoreError> {
        self.check()?;
        let freed = self.map.discard(branch, lba, count)?;
        self.stats.garbage_bytes += freed.len() as u64 * BLOCK;
        let mut body = Vec::with_capacity(24);
        body.extend_from_slice(&branch.get().to_le_bytes());
        body.extend_from_slice(&lba.to_le_bytes());
        body.extend_from_slice(&count.to_le_bytes());
        self.append(K_DISCARD, &body)?;
        self.touched(branch);
        Ok(())
    }

    /// Read `buf.len() / BLOCK` blocks from `lba` of `layer`.  Unwritten
    /// and discarded blocks read as zeros.
    pub fn read(&self, layer: LayerId, lba: u64, buf: &mut [u8]) -> Result<(), StoreError> {
        self.check()?;
        if buf.is_empty() || !(buf.len() as u64).is_multiple_of(BLOCK) {
            return Err(StoreError::BadLength(buf.len()));
        }
        // The range checked before any block, as `write` does: unchecked,
        // `lba + i` panicked in a debug build and, optimized, wrapped to
        // LBA 0 and returned another block's data (review fix H1, Kimi's
        // H1, reproduced in both profiles).
        lba.checked_add(buf.len() as u64 / BLOCK)
            .ok_or(MapError::Overflow)?;
        for (i, chunk) in buf.chunks_mut(BLOCK as usize).enumerate() {
            match self.map.read(layer, lba + i as u64)? {
                Some(Loc::Log(off)) => self.file.read_exact_at(chunk, off)?,
                Some(Loc::Zero) | None => chunk.fill(0),
            }
        }
        Ok(())
    }

    /// End a group: append a Flush record and make everything durable.
    /// Returns the Flush record's sequence number.
    pub fn flush(&mut self) -> Result<u64, StoreError> {
        let lsn = self.flush_pending()?;
        let t = std::time::Instant::now();
        if let Err(e) = self.shared.sync(&self.file) {
            // The Syncer syncs the same file description: it must not
            // answer a later sync as durable (finding 3).
            self.poisoned = true;
            self.shared.fail();
            return Err(e.into());
        }
        let us = t.elapsed().as_micros() as u64;
        self.stats.syncs += 1;
        self.stats.sync_us += us;
        self.stats.sync_max_us = self.stats.sync_max_us.max(us);
        self.shared.synced(lsn);
        Ok(lsn)
    }

    /// End a group without making it durable: append the Flush record and
    /// return its sequence number, for [`Syncer::durable`] to sync outside
    /// the store's lock.  Nothing is durable until that returns.
    pub fn flush_pending(&mut self) -> Result<u64, StoreError> {
        self.check()?;
        // What was durable before this Flush: never its own group.
        let body = flush_body(&self.flush_mac, self.tail, self.shared.durable_end());
        self.append(K_FLUSH, &body)?;
        self.shared.ended(self.lsn, self.tail);
        // This Flush closes a group over every branch touched since the
        // last one: the first group each of them is in.
        for b in self.touched.drain() {
            self.covered.insert(b, self.lsn);
        }
        Ok(self.lsn)
    }

    /// A device's flush for `branch` (the kernel's barrier: everything the
    /// device completed before it is on the medium).  Returns the sequence
    /// number to wait for with [`Syncer::durable`], and whether a Flush
    /// record was appended.  When the branch's last record already lies in
    /// a group, nothing is appended: the lsn is the Flush that first closed
    /// a group over it -- not the newest group's, which under load is a
    /// moment old and never durable yet (rev. 1's mistake, measured
    /// 2026-11-03: 65 % joined, the freeze unchanged).  Replay keeps whole
    /// groups, so what this acknowledges is what a replay keeps.
    pub fn flush_for(&mut self, branch: LayerId) -> Result<(u64, bool), StoreError> {
        self.check()?;
        if !self.touched.contains(&branch) {
            self.stats.flushes_joined += 1;
            return Ok((self.covered.get(&branch).copied().unwrap_or(0), false));
        }
        Ok((self.flush_pending()?, true))
    }

    /// `branch` has a record at the current lsn: in no group until the
    /// next Flush.
    fn touched(&mut self, branch: LayerId) {
        self.touched.insert(branch);
    }

    /// Freeze `branch` as a new Seal standing for every record before it.
    /// Durable when this returns.
    pub fn seal(&mut self, branch: LayerId) -> Result<LayerId, StoreError> {
        self.seal_tagged(branch, &[])
    }

    /// [`Store::seal`], with `tag` (at most [`MAX_TAG`] bytes) kept on the
    /// Seal.
    pub fn seal_tagged(&mut self, branch: LayerId, tag: &[u8]) -> Result<LayerId, StoreError> {
        let seal = self.seal_record(branch, tag)?;
        self.flush()?;
        Ok(seal)
    }

    /// [`Store::seal_tagged`] with the sync left to [`Syncer::durable`]:
    /// returns the Seal and the Flush record's sequence number to wait for.
    pub fn seal_pending(
        &mut self,
        branch: LayerId,
        tag: &[u8],
    ) -> Result<(LayerId, u64), StoreError> {
        let seal = self.seal_record(branch, tag)?;
        let lsn = self.flush_pending()?;
        Ok((seal, lsn))
    }

    fn seal_record(&mut self, branch: LayerId, tag: &[u8]) -> Result<LayerId, StoreError> {
        self.check()?;
        if tag.len() > MAX_TAG {
            return Err(StoreError::BadTag(tag.len()));
        }
        let lsn = self.lsn + 1;
        let seal = self.map.seal(branch, lsn)?;
        self.meta.seals.insert(
            seal,
            SealInfo {
                origin: Some(branch),
                tag: tag.to_vec(),
            },
        );
        let mut body = Vec::with_capacity(8 + tag.len());
        body.extend_from_slice(&branch.get().to_le_bytes());
        body.extend_from_slice(tag);
        self.append(K_SEAL, &body)?;
        self.touched(branch);
        Ok(seal)
    }

    /// A [`Syncer`] over this log's file, for syncing outside the lock.
    pub fn syncer(&self) -> io::Result<Syncer> {
        Ok(Syncer {
            file: Arc::clone(&self.shared),
            state: std::sync::Mutex::new(SyncState::default()),
            done: std::sync::Condvar::new(),
        })
    }

    /// The tag of a live Seal (empty if it has none); `None` if `seal` is
    /// not a live Seal.
    pub fn tag(&self, seal: LayerId) -> Result<Option<&[u8]>, StoreError> {
        self.check()?;
        Ok(self.meta.seals.get(&seal).map(|i| i.tag.as_slice()))
    }

    /// The branch a live Seal was made from; `None` for a root Seal or if
    /// `seal` is not a live Seal.
    pub fn origin(&self, seal: LayerId) -> Result<Option<LayerId>, StoreError> {
        self.check()?;
        Ok(self.meta.seals.get(&seal).and_then(|i| i.origin))
    }

    /// The live Seals made from `branch`, oldest first.
    pub fn seals_of(&self, branch: LayerId) -> Result<Vec<LayerId>, StoreError> {
        self.check()?;
        Ok(self
            .meta
            .seals
            .iter()
            .filter(|(_, i)| i.origin == Some(branch))
            .map(|(id, _)| *id)
            .collect())
    }

    /// Give `branch` the name `name`, or take its name away (`name` empty).
    /// A branch has at most one name; naming it again renames it.  Durable
    /// at the next flush.
    pub fn name(&mut self, branch: LayerId, name: &str) -> Result<(), StoreError> {
        self.check()?;
        if !name.is_empty() && !valid_name(name) {
            return Err(StoreError::BadName(name.to_string()));
        }
        if self.map.kind(branch)? != Kind::Branch {
            return Err(MapError::NotABranch(branch).into());
        }
        if let Some(&other) = self.meta.names.get(name) {
            if other != branch {
                return Err(StoreError::NameTaken(name.to_string()));
            }
        }
        self.meta.set_name(branch, name);
        let mut body = Vec::with_capacity(8 + name.len());
        body.extend_from_slice(&branch.get().to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        self.append(K_NAME, &body)?;
        self.touched(branch);
        Ok(())
    }

    /// Whether `name` could be given to a new branch: valid and not taken.
    /// Changes nothing.
    pub fn check_name(&self, name: &str) -> Result<(), StoreError> {
        self.check()?;
        if !valid_name(name) {
            return Err(StoreError::BadName(name.to_string()));
        }
        if self.meta.names.contains_key(name) {
            return Err(StoreError::NameTaken(name.to_string()));
        }
        Ok(())
    }

    /// The live branch named `name`.
    pub fn find(&self, name: &str) -> Result<Option<LayerId>, StoreError> {
        self.check()?;
        Ok(self.meta.names.get(name).copied())
    }

    /// The name of `branch`, if it has one.
    pub fn name_of(&self, branch: LayerId) -> Result<Option<&str>, StoreError> {
        self.check()?;
        Ok(self.meta.by_layer.get(&branch).map(String::as_str))
    }

    /// Drop a branch; its blocks become garbage.
    pub fn drop_branch(&mut self, branch: LayerId) -> Result<(), StoreError> {
        self.check()?;
        let freed = self.map.drop_branch(branch)?;
        self.meta.set_name(branch, "");
        self.stats.garbage_bytes += freed.len() as u64 * BLOCK;
        self.append(K_DROP_BRANCH, &branch.get().to_le_bytes())?;
        self.touched(branch);
        Ok(())
    }

    /// Reset `branch` to the Seal it stands on: its own blocks become
    /// garbage, and it keeps its id, name and Seals.  Durable at the next
    /// flush.  A mounted file system on the branch must be unmounted
    /// first: its blocks change under it.  Returns how many blocks the
    /// branch held of its own — what the reset discards from the
    /// filesystem, which the Warden names (spec rev. 33, D93 class (i):
    /// an agent's write adds no Chronicle record, so only this count says
    /// it was lost; E3 [seal write], the test VM 2026-10-28).
    pub fn reset(&mut self, branch: LayerId) -> Result<u64, StoreError> {
        self.check()?;
        let freed = self.map.reset(branch)?;
        self.stats.garbage_bytes += freed.len() as u64 * BLOCK;
        self.append(K_RESET, &branch.get().to_le_bytes())?;
        self.touched(branch);
        Ok(freed.len() as u64)
    }

    /// Take away the Seal `branch` stands on, which nothing else stands on,
    /// and stand the branch on that Seal's parent with nothing of its own
    /// ([`Map::unseal`]).  For a Seal whose record was never accepted (an
    /// orphan): the branch stood on it since it was taken, so it could not
    /// be dropped.  The branch keeps its id, its name and its other Seals.
    /// Durable at the next flush; a mounted file system on the branch must
    /// be unmounted first.  Returns how many blocks became garbage.
    pub fn unseal(&mut self, branch: LayerId) -> Result<u64, StoreError> {
        self.check()?;
        let seal = self.map.parent(branch)?;
        let freed = self.map.unseal(branch)?;
        if let Some(seal) = seal {
            self.meta.seals.remove(&seal);
        }
        self.stats.garbage_bytes += freed.len() as u64 * BLOCK;
        self.append(K_UNSEAL, &branch.get().to_le_bytes())?;
        self.touched(branch);
        Ok(freed.len() as u64)
    }

    /// Flush, then write a checkpoint of this durable point next to the
    /// log (`<log>.ckpt`, replaced atomically), so the next [`Store::open`]
    /// replays only what comes after it.  Returns its sequence number.
    pub fn checkpoint(&mut self) -> Result<u64, StoreError> {
        let before = self.prev;
        self.flush()?;
        let at = FlushPoint {
            end: self.tail,
            lsn: self.lsn,
            before,
            prev: self.prev,
        };
        write_checkpoint(
            &self.path,
            &self.header.id,
            &at,
            self.stats.garbage_bytes,
            &self.map,
            &self.meta,
        )?;
        Ok(self.lsn)
    }

    /// Write the blocks that make `from` (a Seal below `to`, or the zero
    /// base image if `None`) into the Seal `to`, as an import stream.
    /// Returns the blocks written.  The two steps of [`Store::export_plan`]
    /// and [`ExportPlan::write`] in one call, the store held throughout.
    pub fn export(
        &self,
        to: LayerId,
        from: Option<LayerId>,
        w: &mut impl io::Write,
    ) -> Result<u64, StoreError> {
        self.export_plan(to, from)?.write(w)
    }

    /// Plan the export of `to` from `from` (as [`Store::export`]): the
    /// checks and the block list, which need the store, and a duplicate
    /// of the log's descriptor.  The plan is written with
    /// [`ExportPlan::write`] **without the store**: the reading of the
    /// blocks and the writing of the stream, the I/O, leave the lock.
    ///
    /// Why that is safe (P5 bite 5, 2026-11-04): the log is append-only,
    /// so a block's bytes at an offset never change; a compaction writes a
    /// new file and renames it into place, so the old file this
    /// descriptor holds keeps every byte at every offset until the
    /// descriptor is closed; a Seal dropped meanwhile frees nothing in
    /// the file.  What the plan reads is what the store held at planning.
    /// Measured before: `export` held the store 1.2 ms a Seal at P=64 on
    /// the test VM, 30 ms at the longest, the largest holder of the lock
    /// (the freeze trace design of 2026-11-03, row 3).
    pub fn export_plan(
        &self,
        to: LayerId,
        from: Option<LayerId>,
    ) -> Result<ExportPlan, StoreError> {
        self.check()?;
        if !matches!(self.map.kind(to)?, Kind::Seal { .. }) {
            return Err(MapError::NotASeal(to).into());
        }
        if let Some(f) = from {
            if !matches!(self.map.kind(f)?, Kind::Seal { .. }) {
                return Err(MapError::NotASeal(f).into());
            }
        }
        // Newest first: the first layer that holds a block decides it.
        let mut blocks: BTreeMap<u64, Loc> = BTreeMap::new();
        let mut cur = Some(to);
        loop {
            match cur {
                Some(l) if Some(l) == from => break,
                Some(l) => {
                    for (lba, loc) in self.map.delta(l)? {
                        blocks.entry(lba).or_insert(loc);
                    }
                    cur = self.map.parent(l)?;
                }
                None if from.is_none() => break,
                None => {
                    return Err(StoreError::NotAnAncestor {
                        from: from.expect("checked"),
                        to,
                    })
                }
            }
        }
        Ok(ExportPlan {
            blocks,
            file: self.file.try_clone()?,
        })
    }

    /// Apply an export stream to `branch`, which must hold no blocks of its
    /// own (a fresh branch, or one just reset).  The writes are durable at
    /// the next flush; seal the branch to keep them as a Seal.  On any
    /// failure the branch is reset: nothing of the stream is kept.  Returns
    /// the blocks applied.
    pub fn import(&mut self, branch: LayerId, r: &mut impl Read) -> Result<u64, StoreError> {
        self.check()?;
        if self.map.kind(branch)? != Kind::Branch {
            return Err(MapError::NotABranch(branch).into());
        }
        if self.map.delta(branch)?.next().is_some() {
            return Err(StoreError::NotClean(branch));
        }
        match self.import_runs(branch, r) {
            Ok(n) => Ok(n),
            Err(e) => {
                // Take back what was applied; if even that fails the store
                // is poisoned and reopening replays to a consistent state.
                self.reset(branch)?;
                Err(e)
            }
        }
    }

    fn import_runs(&mut self, branch: LayerId, r: &mut impl Read) -> Result<u64, StoreError> {
        let mut r = HashingReader {
            r,
            h: blake3::Hasher::new(),
        };
        let bad = StoreError::BadStream;
        let mut magic = [0u8; 8];
        if !r.take(&mut magic)? || &magic != STREAM_MAGIC {
            return Err(bad("not an export stream"));
        }
        let mut applied = 0u64;
        let mut buf = vec![0u8; RUN_MAX as usize * BLOCK as usize];
        loop {
            let mut kind = [0u8; 1];
            if !r.take(&mut kind)? {
                return Err(bad("truncated"));
            }
            if kind[0] == 0 {
                break;
            }
            let mut head = [0u8; 12];
            if !r.take(&mut head)? {
                return Err(bad("truncated"));
            }
            let lba = u64::from_le_bytes(head[..8].try_into().unwrap());
            let count = u32::from_le_bytes(head[8..].try_into().unwrap()) as u64;
            if count == 0 || lba.checked_add(count).is_none() {
                return Err(bad("bad run"));
            }
            match kind[0] {
                RUN_DATA => {
                    if count > RUN_MAX {
                        return Err(bad("run too long"));
                    }
                    let n = (count * BLOCK) as usize;
                    if !r.take(&mut buf[..n])? {
                        return Err(bad("truncated"));
                    }
                    self.write(branch, lba, &buf[..n], false)?;
                }
                RUN_ZERO => self.discard(branch, lba, count)?,
                _ => return Err(bad("unknown run kind")),
            }
            applied += count;
        }
        let mut total = [0u8; 8];
        if !r.take(&mut total)? {
            return Err(bad("truncated"));
        }
        let want = r.h.finalize();
        let mut hash = [0u8; HASH];
        if !read_full(&mut r.r, &mut hash)? {
            return Err(bad("truncated"));
        }
        if u64::from_le_bytes(total) != applied {
            return Err(bad("block count does not match"));
        }
        if &hash != want.as_bytes() {
            return Err(bad("hash does not match"));
        }
        let mut extra = [0u8; 1];
        if read_full(&mut r.r, &mut extra)? {
            return Err(bad("bytes after the end"));
        }
        Ok(applied)
    }

    /// Every live branch name, with its branch, in name order.
    pub fn names(&self) -> Result<Vec<(String, LayerId)>, StoreError> {
        self.check()?;
        let mut v: Vec<(String, LayerId)> = self
            .meta
            .names
            .iter()
            .map(|(n, b)| (n.clone(), *b))
            .collect();
        v.sort();
        Ok(v)
    }

    /// Fold `seal` into the one Seal on top of it ([`Map::fold`]): nothing
    /// reads differently, the chain is one shorter, and the blocks the Seal
    /// on top had rewritten become garbage.  `seal`'s tag goes with it.
    /// Durable at the next flush.  Returns the Seal on top and how many
    /// blocks became garbage.
    pub fn fold(&mut self, seal: LayerId) -> Result<(LayerId, u64), StoreError> {
        self.check()?;
        let (top, freed) = self.map.fold(seal)?;
        self.meta.seals.remove(&seal);
        self.stats.garbage_bytes += freed.len() as u64 * BLOCK;
        self.append(K_FOLD, &seal.get().to_le_bytes())?;
        Ok((top, freed.len() as u64))
    }

    /// Drop a Seal nothing stands on; its blocks become garbage.
    pub fn drop_seal(&mut self, seal: LayerId) -> Result<(), StoreError> {
        self.check()?;
        let freed = self.map.drop_seal(seal)?;
        self.meta.seals.remove(&seal);
        self.stats.garbage_bytes += freed.len() as u64 * BLOCK;
        self.append(K_DROP_SEAL, &seal.get().to_le_bytes())
    }

    /// Mark the store unusable until it is reopened, as a failed append
    /// does: every later call fails with [`StoreError::Poisoned`].  For a
    /// caller that cannot vouch for the store any more (a thread that held
    /// it panicked half-way through a call).
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Whether an append or a sync of the store's own has failed, or the
    /// store was [`poison`](Self::poison)ed: every call fails until the log
    /// is reopened.  A failed sync of the [`Syncer`]'s makes every call
    /// fail too, but is not counted here until the Syncer's caller poisons
    /// the store, so that caller still learns it is the first to know (and
    /// names the error: `taso-blkd`'s `durable`).
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// The log's reserve filler, for a thread of its own outside the
    /// store's lock ([`Filler`]).
    pub fn filler(&self) -> Filler {
        Filler(Arc::clone(&self.shared))
    }

    // ── internals ───────────────────────────────────────────────────

    /// Make room in the reserve for a record of `len` bytes at the tail:
    /// with `closing`, the held-back part may be used ([`HELD_BACK`]).
    /// What the filler has not made ready yet is written here with zeros
    /// (not synced: the next group commit carries it).  A disk without
    /// that room answers `StorageFull`, and nothing has changed: no
    /// record, no map, the store not poisoned.  Any other failure to
    /// write the zeros sets the log's failure latch (finding 3): the file
    /// may not be what this store thinks.
    fn room_for(&mut self, len: u64, closing: bool) -> Result<(), StoreError> {
        let need = self.tail + len + if closing { 0 } else { HELD_BACK };
        if need <= self.shared.allocated() {
            return Ok(());
        }
        let _fill = self.shared.fill_lock();
        let from = self.shared.allocated();
        if need <= from {
            return Ok(()); // the filler got there meanwhile
        }
        let to = need.next_multiple_of(BLOCK);
        #[cfg(test)]
        if self.room.is_some_and(|room| to > room) {
            return Err(io::Error::from(io::ErrorKind::StorageFull).into());
        }
        let zeros = vec![0u8; (to - from) as usize];
        match self.file.write_all_at(&zeros, from) {
            Ok(()) => {
                self.shared.made_ready(to);
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::StorageFull => Err(e.into()),
            Err(e) => {
                self.shared.fail();
                Err(e.into())
            }
        }
    }

    fn check(&self) -> Result<(), StoreError> {
        // A sync failed on either path (the store's own or the Syncer's):
        // the map may be ahead of what is on the medium (finding 3).
        if self.poisoned || self.shared.has_failed() {
            Err(StoreError::Poisoned)
        } else {
            Ok(())
        }
    }

    /// Append one record at the tail.  The map has already applied it; if
    /// the file write fails, the two disagree and the store is poisoned.
    fn append(&mut self, kind: u8, body: &[u8]) -> Result<(), StoreError> {
        self.append_timed(kind, body)
    }

    /// [`append`](Self::append), with the hash and the `pwrite` timed into
    /// the write counters of [`Stats`] (every kind of record is appended
    /// this way; the counters are read against the write ops' bytes).
    fn append_timed(&mut self, kind: u8, body: &[u8]) -> Result<(), StoreError> {
        let t = std::time::Instant::now();
        let mut rec = Vec::with_capacity(REC_HEAD as usize + body.len() + HASH);
        let hash = encode_record(&mut rec, &self.prev, kind, body);
        self.stats.write_hash_us += t.elapsed().as_micros() as u64;
        // Every record may use the held-back room (a write of data asked
        // for its room, held-back part kept, before its map moved).  The
        // map has moved already: a failure here poisons, as before.
        if let Err(e) = self.room_for(rec.len() as u64, true) {
            self.poisoned = true;
            return Err(e);
        }
        let t = std::time::Instant::now();
        #[cfg(test)]
        let r = if self
            .room
            .is_some_and(|room| self.tail + rec.len() as u64 > room)
        {
            Err(io::Error::from(io::ErrorKind::StorageFull))
        } else {
            self.file.write_all_at(&rec, self.tail)
        };
        #[cfg(not(test))]
        let r = self.file.write_all_at(&rec, self.tail);
        if let Err(e) = r {
            self.poisoned = true;
            return Err(e.into());
        }
        self.stats.write_pwrite_us += t.elapsed().as_micros() as u64;
        self.tail += rec.len() as u64;
        self.shared.appended(self.tail);
        self.lsn += 1;
        self.prev = hash;
        self.stats.log_bytes = self.tail;
        self.stats.records += 1;
        Ok(())
    }
}

/// The chain's seed: the hash of the header.
fn seed(header: &[u8]) -> [u8; HASH] {
    *blake3::hash(header).as_bytes()
}

/// Append one whole record (head, body, chain hash) to `out`; returns its
/// chain hash.
fn encode_record(out: &mut Vec<u8>, prev: &[u8; HASH], kind: u8, body: &[u8]) -> [u8; HASH] {
    let hash = chain(prev, kind, body);
    out.extend_from_slice(&REC_MAGIC.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out.extend_from_slice(&hash);
    hash
}

fn chain(prev: &[u8; HASH], kind: u8, body: &[u8]) -> [u8; HASH] {
    let mut h = blake3::Hasher::new();
    h.update(prev);
    h.update(&[kind]);
    h.update(&(body.len() as u32).to_le_bytes());
    h.update(body);
    *h.finalize().as_bytes()
}

/// A verified record: its kind, its body and its chain hash.
type Record = (u8, Vec<u8>, [u8; HASH]);

/// Read and verify the next record.  `None` at a clean end or at anything
/// that is not a whole, verified record (torn, bad magic, bad hash).  The
/// kind is whatever the record says: a record that verifies with a kind
/// the caller does not know is a record, not an end, and is the caller's
/// to refuse.
fn read_record(r: &mut impl Read, prev: &[u8; HASH]) -> io::Result<Option<Record>> {
    let mut head = [0u8; REC_HEAD as usize];
    if !read_full(r, &mut head)? {
        return Ok(None);
    }
    let magic = u32::from_le_bytes(head[0..4].try_into().unwrap());
    let len = u32::from_le_bytes(head[4..8].try_into().unwrap());
    let kind = head[8];
    if magic != REC_MAGIC || len > MAX_BODY {
        return Ok(None);
    }
    let mut body = vec![0u8; len as usize];
    let mut hash = [0u8; HASH];
    if !read_full(r, &mut body)? || !read_full(r, &mut hash)? {
        return Ok(None);
    }
    if chain(prev, kind, &body) != hash {
        return Ok(None);
    }
    Ok(Some((kind, body, hash)))
}

/// Fill `buf` completely; `false` if the stream ends first.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => return Ok(false),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// A verified record's effect on the map, without its block data: held
/// until the group's Flush is verified.
struct Pending {
    kind: u8,
    /// The record's fields (for a write: layer and lba; never the data).
    fields: Vec<u8>,
    /// Bytes of block data after the fields (writes only).
    data_len: usize,
    /// Offset of the record's body in the file.
    body_at: u64,
    lsn: u64,
}

impl Pending {
    fn of(kind: u8, body: &[u8], body_at: u64, lsn: u64) -> Self {
        let fields = if kind == K_WRITE {
            body.len().min(16)
        } else {
            body.len()
        };
        Self {
            kind,
            fields: body[..fields].to_vec(),
            data_len: body.len() - fields,
            body_at,
            lsn,
        }
    }
}

/// Apply one verified record to `map`.  Returns the garbage bytes it made.
/// A record that does not fit its kind, or that the map refuses, means the
/// log contradicts itself: refused, never skipped.
fn replay(map: &mut Map, meta: &mut Meta, p: &Pending) -> Result<u64, StoreError> {
    let bad = |error| StoreError::Replay { lsn: p.lsn, error };
    let f = &p.fields;
    let need = |n: usize| {
        if f.len() == n && (p.kind == K_WRITE || p.data_len == 0) {
            Ok(())
        } else {
            Err(bad(MapError::Overflow))
        }
    };
    let layer = |at| LayerId::from_raw(u64_at(f, at));
    let freed = match p.kind {
        K_WRITE => {
            need(16)?;
            if p.data_len == 0 || !(p.data_len as u64).is_multiple_of(BLOCK) {
                return Err(bad(MapError::Overflow));
            }
            let (id, lba) = (layer(0), u64_at(f, 8));
            let count = p.data_len as u64 / BLOCK;
            lba.checked_add(count)
                .ok_or_else(|| bad(MapError::Overflow))?;
            let mut freed = 0;
            for i in 0..count {
                let at = p.body_at + 16 + i * BLOCK;
                if map.write(id, lba + i, Loc::Log(at)).map_err(bad)?.is_some() {
                    freed += 1;
                }
            }
            freed
        }
        K_DISCARD => {
            need(24)?;
            map.discard(layer(0), u64_at(f, 8), u64_at(f, 16))
                .map_err(bad)?
                .len() as u64
        }
        K_ROOT => {
            need(0)?;
            let id = map.root_seal(p.lsn);
            meta.seals.insert(
                id,
                SealInfo {
                    origin: None,
                    tag: Vec::new(),
                },
            );
            0
        }
        K_FORK => {
            need(8)?;
            map.fork(layer(0)).map_err(bad)?;
            0
        }
        K_SEAL => {
            if f.len() < 8 || f.len() > 8 + MAX_TAG {
                return Err(StoreError::ReplayMeta {
                    lsn: p.lsn,
                    reason: "bad Seal record length",
                });
            }
            let branch = layer(0);
            let seal = map.seal(branch, p.lsn).map_err(bad)?;
            meta.seals.insert(
                seal,
                SealInfo {
                    origin: Some(branch),
                    tag: f[8..].to_vec(),
                },
            );
            0
        }
        K_DROP_BRANCH => {
            need(8)?;
            let freed = map.drop_branch(layer(0)).map_err(bad)?.len() as u64;
            meta.set_name(layer(0), "");
            freed
        }
        K_DROP_SEAL => {
            need(8)?;
            let freed = map.drop_seal(layer(0)).map_err(bad)?.len() as u64;
            meta.seals.remove(&layer(0));
            freed
        }
        K_RESET => {
            need(8)?;
            map.reset(layer(0)).map_err(bad)?.len() as u64
        }
        K_FOLD => {
            need(8)?;
            let freed = map.fold(layer(0)).map_err(bad)?.1.len() as u64;
            meta.seals.remove(&layer(0));
            freed
        }
        K_UNSEAL => {
            need(8)?;
            let seal = map.parent(layer(0)).map_err(bad)?;
            let freed = map.unseal(layer(0)).map_err(bad)?.len() as u64;
            if let Some(seal) = seal {
                meta.seals.remove(&seal);
            }
            freed
        }
        K_NAME => {
            let meta_err = |reason| StoreError::ReplayMeta { lsn: p.lsn, reason };
            if f.len() < 8 || f.len() > 8 + MAX_NAME {
                return Err(meta_err("bad Name record length"));
            }
            let branch = layer(0);
            let name = std::str::from_utf8(&f[8..]).map_err(|_| meta_err("name is not UTF-8"))?;
            if !name.is_empty() && !valid_name(name) {
                return Err(meta_err("bad name"));
            }
            if map.kind(branch).map_err(bad)? != Kind::Branch {
                return Err(meta_err("names a Seal"));
            }
            if meta.names.get(name).is_some_and(|&other| other != branch) {
                return Err(meta_err("name taken by another branch"));
            }
            meta.set_name(branch, name);
            0
        }
        _ => unreachable!("read_record checks the kind; Flush is not pending"),
    };
    Ok(freed * BLOCK)
}

/// What a live Seal carries besides its blocks.
#[derive(Debug)]
struct SealInfo {
    /// The branch it was made from; `None` for a root Seal.
    origin: Option<LayerId>,
    tag: Vec<u8>,
}

/// Tags, origins and names, kept beside the map.
#[derive(Debug, Default)]
struct Meta {
    /// Live Seals, by id (ids grow, so this is creation order).
    seals: BTreeMap<LayerId, SealInfo>,
    /// Name to branch, and back.
    names: HashMap<String, LayerId>,
    by_layer: HashMap<LayerId, String>,
}

impl Meta {
    /// Name `branch` (empty: no name), freeing any name it had.  The
    /// caller has checked the name is free.
    fn set_name(&mut self, branch: LayerId, name: &str) {
        if let Some(old) = self.by_layer.remove(&branch) {
            self.names.remove(&old);
        }
        if !name.is_empty() {
            self.names.insert(name.to_string(), branch);
            self.by_layer.insert(branch, name.to_string());
        }
    }
}

impl Meta {
    /// Append the Seal infos and names, for a checkpoint.
    fn encode(&self, out: &mut Vec<u8>) {
        let put = |out: &mut Vec<u8>, v: u64| out.extend_from_slice(&v.to_le_bytes());
        put(out, self.seals.len() as u64);
        for (id, i) in &self.seals {
            put(out, id.get());
            put(out, i.origin.map_or(u64::MAX, |o| o.get()));
            put(out, i.tag.len() as u64);
            out.extend_from_slice(&i.tag);
        }
        let mut names: Vec<(&String, &LayerId)> = self.names.iter().collect();
        names.sort();
        put(out, names.len() as u64);
        for (n, b) in names {
            put(out, b.get());
            put(out, n.len() as u64);
            out.extend_from_slice(n.as_bytes());
        }
    }

    /// Read what [`Meta::encode`] wrote; `None` if it is not that, or if it
    /// does not fit `map` (a tag on something that is not a Seal, a name on
    /// something that is not a branch, a taken or bad name).
    fn decode(b: &mut &[u8], map: &Map) -> Option<Meta> {
        fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            let (h, t) = (b.get(..n)?, b.get(n..)?);
            *b = t;
            Some(h)
        }
        let u = |b: &mut &[u8]| take(b, 8).map(|x| u64::from_le_bytes(x.try_into().unwrap()));
        let live = |n: u64| map.live(n);
        let mut meta = Meta::default();
        for _ in 0..u(b)? {
            let id = live(u(b)?)?;
            if !matches!(map.kind(id).ok()?, Kind::Seal { .. }) {
                return None;
            }
            let origin = match u(b)? {
                u64::MAX => None,
                o => Some(LayerId::from_raw(o)), // the origin branch may since have been dropped
            };
            let n = usize::try_from(u(b)?).ok().filter(|n| *n <= MAX_TAG)?;
            let tag = take(b, n)?.to_vec();
            meta.seals.insert(id, SealInfo { origin, tag });
        }
        for _ in 0..u(b)? {
            let id = live(u(b)?)?;
            let n = usize::try_from(u(b)?).ok().filter(|n| *n <= MAX_NAME)?;
            let name = std::str::from_utf8(take(b, n)?).ok()?;
            if !valid_name(name)
                || map.kind(id).ok()? != Kind::Branch
                || meta.names.contains_key(name)
                || meta.by_layer.contains_key(&id)
            {
                return None;
            }
            meta.set_name(id, name);
        }
        Some(meta)
    }
}

/// Where the checkpoint of the log at `path` lives.
/// The log's lock file: `<log>.lock`.  Never removed (a lock on a file
/// that could be unlinked and made again would let two stores each hold
/// "the" lock).
pub fn lock_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".lock");
    PathBuf::from(p)
}

/// Take the log's lock, or say who holds it: [`StoreError::Locked`].
/// An exclusive `flock` on [`lock_path`]: it conflicts with any other
/// open of the same file, in this process or another, and goes with the
/// last descriptor (a dead daemon's lock is gone).
fn lock_log(path: &Path) -> Result<File, StoreError> {
    let p = lock_path(path);
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(PRIVATE)
        .open(&p)?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(std::fs::TryLockError::WouldBlock) => Err(StoreError::Locked(p)),
        Err(std::fs::TryLockError::Error(e)) => Err(StoreError::Io(e)),
    }
}

/// The mode a store's new files get: the owner's alone.
const PRIVATE: u32 = 0o600;

/// The mode for a file holding what the log at `log` holds: the log's
/// own, without others' access or any execute bit.
fn mode_of_log(log: &Path) -> io::Result<u32> {
    Ok(std::fs::metadata(log)?.permissions().mode() & 0o660)
}

/// Take others' access to `f` away; its mode before, if there was any.
fn no_others(f: &File) -> io::Result<Option<u32>> {
    let mode = f.metadata()?.permissions().mode() & 0o7777;
    if mode & 0o007 == 0 {
        return Ok(None);
    }
    f.set_permissions(std::fs::Permissions::from_mode(mode & !0o007))?;
    Ok(Some(mode))
}

/// The largest durable end named by a Flush record in `from..len` of
/// `file`: a record's head for a Flush at an offset its body names as its
/// own, with the keyed check.  Found without the chain, which is broken
/// at `from`.  `None` if there is none.
/// The offset just past the last byte in `from..len` of `file` that is
/// not zero; `from` if they all are.  Read backwards from the end, a
/// megabyte at a time: the reserve is the zeros this skips.
fn nonzero_end(file: &File, from: u64, len: u64) -> io::Result<u64> {
    const CHUNK: u64 = 1 << 20;
    let mut buf = vec![0u8; CHUNK as usize];
    let mut hi = len;
    while hi > from {
        let lo = hi.saturating_sub(CHUNK).max(from);
        let b = &mut buf[..(hi - lo) as usize];
        file.read_exact_at(b, lo)?;
        if let Some(i) = b.iter().rposition(|x| *x != 0) {
            return Ok(lo + i as u64 + 1);
        }
        hi = lo;
    }
    Ok(from)
}

fn later_durable_end(
    file: &File,
    flush_mac: &[u8; 32],
    from: u64,
    len: u64,
) -> io::Result<Option<u64>> {
    // A Flush record's head: magic, body length, kind.
    let mut head = [0u8; REC_HEAD as usize];
    head[..4].copy_from_slice(&REC_MAGIC.to_le_bytes());
    head[4..8].copy_from_slice(&(FLUSH_BODY as u32).to_le_bytes());
    head[8] = K_FLUSH;
    const CHUNK: usize = 1 << 20;
    // A head and body that straddle two chunks: the next chunk starts
    // this many bytes back.
    let need = REC_HEAD as usize + FLUSH_BODY;
    let mut buf = vec![0u8; CHUNK + need];
    let (mut at, mut best) = (from, None::<u64>);
    while at < len {
        let n = ((len - at) as usize).min(buf.len());
        file.read_exact_at(&mut buf[..n], at)?;
        let mut i = 0;
        while i + need <= n {
            match buf[i..n - FLUSH_BODY].iter().position(|b| *b == head[0]) {
                None => break,
                Some(k) => i += k,
            }
            if i + need > n {
                break;
            }
            if buf[i..i + REC_HEAD as usize] == head {
                let body = &buf[i + REC_HEAD as usize..i + need];
                if let Some(d) = flush_claim(flush_mac, body, at + i as u64) {
                    best = Some(best.map_or(d, |b| b.max(d)));
                }
            }
            i += 1;
        }
        if n < buf.len() {
            break;
        }
        at += CHUNK as u64;
    }
    Ok(best)
}

/// Where the part of the log at `path` that begins at `from` (`bytes`
/// long) is set aside: `<log>.damaged-<from>`.  If a file of that name is
/// there and is this very part (a start that died after the copy, before
/// cutting the log), that name again; if it is anything else (an earlier
/// damage that began at the same offset), the next free name with `.1`,
/// `.2`, ... after it: a part once set aside is never written over.
fn aside_path(path: &Path, file: &File, from: u64, bytes: u64) -> io::Result<PathBuf> {
    for n in 0u32.. {
        let mut p = path.as_os_str().to_owned();
        p.push(format!(".damaged-{from}"));
        if n > 0 {
            p.push(format!(".{n}"));
        }
        let p = PathBuf::from(p);
        match File::open(&p) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(p),
            // A name that cannot even be looked up is no place for it.
            Err(e) => return Err(e),
            Ok(there) if same_bytes(&there, file, from, bytes)? => return Ok(p),
            // Something else of that name: not ours to write over.
            Ok(_) => {}
        }
    }
    unreachable!("a free name is found before u32 runs out")
}

/// Whether `there` is exactly the `bytes` of `file` from `from`.
fn same_bytes(there: &File, file: &File, from: u64, bytes: u64) -> io::Result<bool> {
    if !there.metadata()?.is_file() || there.metadata()?.len() != bytes {
        return Ok(false);
    }
    let (mut a, mut b) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    let mut done = 0u64;
    while done < bytes {
        let n = ((bytes - done) as usize).min(a.len());
        there.read_exact_at(&mut a[..n], done)?;
        file.read_exact_at(&mut b[..n], from + done)?;
        if a[..n] != b[..n] {
            return Ok(false);
        }
        done += n as u64;
    }
    Ok(true)
}

/// Copy `bytes` of `file` from `from` to a new private file at `to`, and
/// make the copy and its name durable ([`aside_path`] chose a name that is
/// free or already holds these bytes).  On an error the partial copy is
/// removed.
fn copy_aside(file: &File, from: u64, bytes: u64, to: &Path) -> io::Result<()> {
    let run = || -> io::Result<()> {
        let out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(PRIVATE)
            .open(to)?;
        let mut buf = vec![0u8; 1 << 20];
        let mut done = 0u64;
        while done < bytes {
            let n = ((bytes - done) as usize).min(buf.len());
            file.read_exact_at(&mut buf[..n], from + done)?;
            out.write_all_at(&buf[..n], done)?;
            done += n as u64;
        }
        out.sync_all()?;
        sync_dir(to)
    };
    run().inspect_err(|_| {
        let _ = std::fs::remove_file(to);
    })
}

fn ckpt_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".ckpt");
    PathBuf::from(p)
}

/// Remove `path` if it exists.
fn remove_if_there(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// A durable point of a log: the end of a Flush record, its sequence
/// number, and the chain hashes before and of it.
struct FlushPoint {
    end: u64,
    lsn: u64,
    before: [u8; HASH],
    prev: [u8; HASH],
}

/// Write the checkpoint of the log at `log` for the state at `at`,
/// atomically (a temporary file, synced, then renamed).
fn write_checkpoint(
    log: &Path,
    id: &LogId,
    at: &FlushPoint,
    garbage: u64,
    map: &Map,
    meta: &Meta,
) -> io::Result<()> {
    let mut b = Vec::with_capacity(1 << 16);
    b.extend_from_slice(CKPT_MAGIC);
    b.extend_from_slice(id);
    for v in [at.end, at.lsn, garbage] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&at.before);
    b.extend_from_slice(&at.prev);
    map.encode(&mut b);
    meta.encode(&mut b);
    let sum = blake3::hash(&b);
    b.extend_from_slice(sum.as_bytes());
    let path = ckpt_path(log);
    let tmp = path.with_extension("ckpt.tmp");
    {
        // The checkpoint holds the log's map and names: the log's mode.
        // Set on the descriptor too, since a leftover temporary file keeps
        // the mode it was made with (audit 2026-11-16, S1).
        let mode = mode_of_log(log)?;
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.write_all_at(&b, 0)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    sync_dir(&path)
}

/// A compacted log's base, as recovery reads it: the data records' places
/// and the joined base pieces.
#[derive(Default)]
struct Base {
    /// (offset, length) of each data record's body, in file order.
    data: Vec<(u64, u64)>,
    state: Vec<u8>,
}

impl Base {
    fn is_empty(&self) -> bool {
        self.data.is_empty() && self.state.is_empty()
    }

    fn add(&mut self, kind: u8, body: &[u8], body_at: u64) -> Result<(), &'static str> {
        if kind == K_DATA {
            if !self.state.is_empty() {
                return Err("a data record after the base state");
            }
            if body.is_empty() || !(body.len() as u64).is_multiple_of(BLOCK) {
                return Err("a data record that is not whole blocks");
            }
            self.data.push((body_at, body.len() as u64));
        } else {
            self.state.extend_from_slice(body);
        }
        Ok(())
    }

    /// The map, tags and names, and the sequence number the log goes on
    /// from.  Every log location must be a block inside a data record.
    fn decode(&self) -> Result<(Map, Meta, u64), &'static str> {
        let mut r = self.state.as_slice();
        let lsn = r.get(..8).ok_or("a short base state")?;
        let lsn = u64::from_le_bytes(lsn.try_into().unwrap());
        r = &r[8..];
        let max = self.data.last().map_or(HEADER_LEN, |(at, n)| at + n);
        let map = Map::decode(&mut r, max).ok_or("a base map that does not decode")?;
        let meta = Meta::decode(&mut r, &map).ok_or("base tags or names that do not decode")?;
        if !r.is_empty() {
            return Err("bytes after the base state");
        }
        for off in map.log_locs() {
            let i = self.data.partition_point(|(at, _)| *at <= off);
            let inside = i > 0 && {
                let (at, n) = self.data[i - 1];
                off + BLOCK <= at + n && (off - at).is_multiple_of(BLOCK)
            };
            if !inside {
                return Err("a base location outside the data records");
            }
        }
        Ok((map, meta, lsn))
    }
}

/// A checkpoint that checks out against the log.
struct Checkpoint {
    end: u64,
    lsn: u64,
    prev: [u8; HASH],
    garbage: u64,
    map: Map,
    meta: Meta,
}

/// The checkpoint of the log at `path`, if there is one and it checks
/// out: its own hash, the log's id, and the Flush record at its end offset
/// on disk with the chain hash it names.  Any doubt: `None` (a full
/// replay).  A checkpoint of another log is not this log's: its id says so
/// before its offsets are looked at.
fn load_checkpoint(
    path: &Path,
    file: &File,
    len: u64,
    id: &LogId,
    flush_mac: &[u8; 32],
) -> Option<Checkpoint> {
    let b = std::fs::read(ckpt_path(path)).ok()?;
    let (body, sum) = b.split_at(b.len().checked_sub(HASH)?);
    if blake3::hash(body).as_bytes() != sum || !body.starts_with(CKPT_MAGIC) {
        return None;
    }
    let mut r = &body[CKPT_MAGIC.len()..];
    if r.get(..id.len())? != id {
        return None;
    }
    r = &r[id.len()..];
    let mut u = || -> Option<u64> {
        let v = u64::from_le_bytes(r.get(..8)?.try_into().ok()?);
        r = &r[8..];
        Some(v)
    };
    let (end, lsn, garbage) = (u()?, u()?, u()?);
    let before: [u8; HASH] = r.get(..HASH)?.try_into().ok()?;
    let prev: [u8; HASH] = r.get(HASH..2 * HASH)?.try_into().ok()?;
    r = &r[2 * HASH..];
    // The Flush record that ends at `end`: exactly where the checkpoint
    // says, with the chain hash it names.
    let flush_len = FLUSH_LEN;
    if end > len || end < HEADER_LEN + flush_len {
        return None;
    }
    let mut rec = vec![0u8; flush_len as usize];
    file.read_exact_at(&mut rec, end - flush_len).ok()?;
    let body = &rec[REC_HEAD as usize..REC_HEAD as usize + FLUSH_BODY];
    let ok = u32::from_le_bytes(rec[0..4].try_into().unwrap()) == REC_MAGIC
        && u32::from_le_bytes(rec[4..8].try_into().unwrap()) == FLUSH_BODY as u32
        && rec[8] == K_FLUSH
        && flush_claim(flush_mac, body, end - flush_len).is_some()
        && chain(&before, K_FLUSH, body) == prev
        && rec[REC_HEAD as usize + FLUSH_BODY..] == prev;
    if !ok {
        return None;
    }
    let map = Map::decode(&mut r, end - flush_len)?;
    let meta = Meta::decode(&mut r, &map)?;
    r.is_empty().then_some(Checkpoint {
        end,
        lsn,
        prev,
        garbage,
        map,
        meta,
    })
}

/// 1 to [`MAX_NAME`] bytes of `A-Z a-z 0-9 _ . : / -`: what dataset names
/// use, and safe in the daemon's line protocol.
fn valid_name(name: &str) -> bool {
    // Round 3, R3-04 (Kimi): "-" alone is the control protocol's "none"
    // (info's fields, export's base), so it is no name.
    name != "-"
        && (1..=MAX_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/' | b'-'))
}

/// A Seal's export, planned under the store ([`Store::export_plan`]) and
/// written without it: the block list as the store held it, and a
/// duplicate of the log's descriptor to read the blocks from.
pub struct ExportPlan {
    /// Every block of the export, newest layer's location first.
    blocks: BTreeMap<u64, Loc>,
    /// The log at planning time; reads at the plan's offsets stay right
    /// through a compaction (a new file, renamed over) and a drop.
    file: File,
}

impl ExportPlan {
    /// The blocks the stream will carry.
    pub fn blocks(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Write the stream.  Returns the blocks written.
    pub fn write(&self, w: &mut impl io::Write) -> Result<u64, StoreError> {
        let mut out = HashingWriter {
            w,
            h: blake3::Hasher::new(),
        };
        out.put(STREAM_MAGIC)?;
        let mut buf = vec![0u8; RUN_MAX as usize * BLOCK as usize];
        let mut it = self.blocks.iter().peekable();
        while let Some((&start, &loc)) = it.next() {
            // A run: consecutive blocks of the same kind, at most RUN_MAX.
            let data = matches!(loc, Loc::Log(_));
            let mut run = vec![loc];
            while run.len() < RUN_MAX as usize {
                match it.peek() {
                    Some((&lba, &l))
                        if lba == start + run.len() as u64 && matches!(l, Loc::Log(_)) == data =>
                    {
                        it.next();
                        run.push(l);
                    }
                    _ => break,
                }
            }
            let count = run.len() as u64;
            out.put(&[if data { RUN_DATA } else { RUN_ZERO }])?;
            out.put(&start.to_le_bytes())?;
            out.put(&(count as u32).to_le_bytes())?;
            if data {
                let n = (count * BLOCK) as usize;
                for (chunk, l) in buf[..n].chunks_mut(BLOCK as usize).zip(&run) {
                    match *l {
                        Loc::Log(off) => self.file.read_exact_at(chunk, off)?,
                        Loc::Zero => chunk.fill(0),
                    }
                }
                out.put(&buf[..n])?;
            }
        }
        out.put(&[0])?;
        out.put(&(self.blocks.len() as u64).to_le_bytes())?;
        let hash = out.h.finalize();
        out.w.write_all(hash.as_bytes())?;
        out.w.flush()?;
        Ok(self.blocks.len() as u64)
    }
}

/// A writer that hashes what goes through it.
struct HashingWriter<'a, W: io::Write> {
    w: &'a mut W,
    h: blake3::Hasher,
}

impl<W: io::Write> HashingWriter<'_, W> {
    fn put(&mut self, b: &[u8]) -> io::Result<()> {
        self.h.update(b);
        self.w.write_all(b)
    }
}

/// A reader that hashes what it reads.
struct HashingReader<'a, R: Read> {
    r: &'a mut R,
    h: blake3::Hasher,
}

impl<R: Read> HashingReader<'_, R> {
    /// Fill `buf`; `false` if the stream ends first.
    fn take(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        let whole = read_full(self.r, buf)?;
        if whole {
            self.h.update(buf);
        }
        Ok(whole)
    }
}

/// A reader over `file[pos..end]` that does not move the file's cursor.
struct ReadAt<'a> {
    file: &'a File,
    pos: u64,
    end: u64,
}

impl Read for ReadAt<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min((self.end - self.pos) as usize);
        if n == 0 {
            return Ok(0);
        }
        let got = self.file.read_at(&mut buf[..n], self.pos)?;
        self.pos += got as u64;
        Ok(got)
    }
}

/// Make a new directory entry durable.
/// Group commit: the log's `fdatasync`, run outside the store's mutex, one
/// for every group ended while the previous sync ran.
///
/// A caller ends its group under the store's lock
/// ([`Store::flush_pending`], [`Store::seal_pending`]), lets the lock go,
/// and asks for `durable(lsn)`.  Whoever asks while no sync is running
/// syncs for everyone who has asked so far; the others wait for it, and
/// whoever it did not cover leads the next.  Holding the mutex through
/// the sync serialised every Vessel's Seal and every device flush behind
/// one disk operation at a time (the bare-metal node, P=64, 2026-10-26: `seal.log`
/// 690 ms p50 for a 1 ms fsync).
pub struct Syncer {
    file: Arc<LogFile>,
    state: std::sync::Mutex<SyncState>,
    done: std::sync::Condvar,
}

#[derive(Default)]
struct SyncState {
    /// The highest sequence number asked for.
    requested: u64,
    /// Everything up to here is on the medium.
    durable: u64,
    /// A sync is running, for everything requested when it started.
    syncing: bool,
    /// A sync failed: nothing after `durable` will ever be.
    failed: bool,
    /// How that sync failed (kept, so the first caller to learn of it can
    /// name the error; the Syncer is the lowest layer that sees it, spec
    /// rev. 34, D93 class (i)).  The later callers get `Poisoned`.
    error: Option<String>,
    /// Syncs made.
    syncs: u64,
    /// Their time, summed, and the longest (µs).
    sync_us: u64,
    sync_max_us: u64,
}

/// The log's reserve filler ([`RESERVE`]): keeps the file written with
/// zeros and synced ahead of the tail, a piece at a time, outside the
/// store's lock.  `taso-blkd` runs it on a thread of its own.
pub struct Filler(Arc<LogFile>);

impl Filler {
    /// Wait until the reserve has fallen low, or `most` has passed.
    pub fn wait(&self, most: std::time::Duration) {
        let lf = &self.0;
        let w = lf.wanted.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut w, _) = lf
            .wake
            .wait_timeout_while(w, most, |w| !*w)
            .unwrap_or_else(PoisonError::into_inner);
        *w = false;
    }

    /// Fill the reserve up to [`RESERVE`] past the tail, one piece at a
    /// time: each piece written with zeros under the fill lock and counted
    /// ready (the room is taken when the write returns), then synced with
    /// the lock let go, so a write that overtakes the filler waits for a
    /// page-cache write at most, never for a sync of the whole log (which
    /// under a burst of births, 64 filesystems made at once, held every
    /// device write on the node; bench at P=64 on the test VM, 2026-11-27).
    /// Returns the bytes made ready.  Two kinds of failure, kept apart:
    /// a disk without room answers `StorageFull` and changes nothing (the
    /// reserve is what it was, the store goes on, and a write that needs
    /// more is refused alone); any other failure, a failed sync above all,
    /// sets the log's failure latch (finding 3: the sync shares one file
    /// description with the records' syncs and may have taken their error).
    pub fn fill_ahead(&self) -> Result<u64, StoreError> {
        let lf = &self.0;
        let mut made = 0;
        loop {
            {
                let _fill = lf.fill_lock();
                if lf.has_failed() {
                    return Err(StoreError::Poisoned);
                }
                let from = lf.allocated();
                let target = lf.tail.load(Ordering::SeqCst) + RESERVE;
                if from >= target {
                    return Ok(made);
                }
                let to = (from + FILL_CHUNK).min(target).next_multiple_of(BLOCK);
                #[cfg(test)]
                {
                    let room = lf.room.load(Ordering::SeqCst);
                    if room != 0 && to > room {
                        return Err(io::Error::from(io::ErrorKind::StorageFull).into());
                    }
                }
                let zeros = vec![0u8; (to - from) as usize];
                if let Err(e) = lf.get().write_all_at(&zeros, from) {
                    if e.kind() != io::ErrorKind::StorageFull {
                        lf.fail();
                    }
                    return Err(e.into());
                }
                lf.made_ready(to);
                made += to - from;
            }
            // The fill lock let go: writes take their room meanwhile.
            if let Err(e) = lf.sync(&lf.get()) {
                lf.fail();
                return Err(e.into());
            }
        }
    }
}

/// The log's file as the [`Syncer`] sees it: swapped by a compaction's
/// switch (the store is held then, and flushed).
pub struct LogFile {
    file: RwLock<File>,
    durable: std::sync::Mutex<DurableEnd>,
    /// A sync of this log failed, the store's or the Syncer's: nothing
    /// after it is ever durable, since both sync one file description and
    /// the kernel reports a failed write-back to one call only (maturity
    /// review of e4a37b2, finding 3).  Set once, never cleared: the log is
    /// reopened to recover.
    failed: std::sync::atomic::AtomicBool,
    /// The end of the reserve: everything below it is the file's, written
    /// (records, or zeros) ([`RESERVE`]).  Moved under `fill`.
    allocated: AtomicU64,
    /// The store's tail, for the filler (set as each record is appended).
    tail: AtomicU64,
    /// One fill at a time: the filler's piece, a write's own zeros, a
    /// compaction's switch.
    fill: std::sync::Mutex<()>,
    /// The filler is wanted: the reserve fell below [`RESERVE_LOW`].
    wanted: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
    /// Tests: the next sync through [`LogFile::sync`] fails.
    #[cfg(test)]
    fail_next_sync: std::sync::atomic::AtomicBool,
    /// Tests: a filesystem with room for the file up to this many bytes
    /// (0: no limit), for the filler's writes.
    #[cfg(test)]
    room: AtomicU64,
    /// Tests: called at each sync through [`LogFile::sync`].
    #[cfg(test)]
    on_sync: std::sync::Mutex<Option<SyncHook>>,
}

/// Tests: what [`LogFile::sync`] calls first.
#[cfg(test)]
type SyncHook = Box<dyn Fn(&LogFile) + Send>;

/// What a Flush record says of the log ([module docs](self)): how far it
/// is known durable, and the Flush records whose sync has not returned.
#[derive(Default)]
struct DurableEnd {
    /// The end offset of the newest Flush a returned `fdatasync` covered.
    /// 0 after an open: this store has synced nothing yet.
    end: u64,
    /// The Flush records appended since: (sequence number, end offset),
    /// oldest first.
    waiting: std::collections::VecDeque<(u64, u64)>,
}

impl LogFile {
    /// Over `file`, whose records end at `tail` and which is written up to
    /// `allocated` (the rest of the reserve, zeros).
    fn new(file: File, tail: u64, allocated: u64) -> Self {
        Self {
            file: RwLock::new(file),
            durable: std::sync::Mutex::default(),
            failed: std::sync::atomic::AtomicBool::new(false),
            allocated: AtomicU64::new(allocated.max(tail)),
            tail: AtomicU64::new(tail),
            fill: std::sync::Mutex::new(()),
            wanted: std::sync::Mutex::new(false),
            wake: std::sync::Condvar::new(),
            #[cfg(test)]
            fail_next_sync: Default::default(),
            #[cfg(test)]
            room: AtomicU64::new(0),
            #[cfg(test)]
            on_sync: std::sync::Mutex::new(None),
        }
    }

    /// `fdatasync` of `f`, a description of this log (the store's own
    /// sync and the filler's go through here; the Syncer's has its own).
    fn sync(&self, f: &File) -> io::Result<()> {
        #[cfg(test)]
        {
            if let Some(hook) = self.on_sync.lock().unwrap().as_ref() {
                hook(self);
            }
            if self.fail_next_sync.swap(false, Ordering::SeqCst) {
                return Err(io::Error::other("test: the sync failed"));
            }
        }
        f.sync_data()
    }

    fn allocated(&self) -> u64 {
        self.allocated.load(Ordering::SeqCst)
    }

    fn fill_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.fill.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Everything below `to` is written: the reserve ends there.
    fn made_ready(&self, to: u64) {
        self.allocated.fetch_max(to, Ordering::SeqCst);
    }

    /// A record was appended; the tail is now `tail`.  Wakes the filler
    /// when the reserve ahead has fallen low.
    fn appended(&self, tail: u64) {
        self.tail.store(tail, Ordering::SeqCst);
        if self.allocated().saturating_sub(tail) < RESERVE_LOW {
            let mut w = self.wanted.lock().unwrap_or_else(PoisonError::into_inner);
            if !*w {
                *w = true;
                self.wake.notify_all();
            }
        }
    }

    fn get(&self) -> std::sync::RwLockReadGuard<'_, File> {
        self.file.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// A compaction's switch to a new file, `file` (the store is held and
    /// flushed; [`LogFile::restart`] follows with the new file's end).  No
    /// fill straddles it, and none runs between the two: the reserve reads
    /// as full until `restart` says where the new file's ends.
    fn set(&self, file: File) {
        let _fill = self.fill_lock();
        *self.file.write().unwrap_or_else(PoisonError::into_inner) = file;
        self.allocated.store(u64::MAX, Ordering::SeqCst);
    }

    /// A sync of the log failed (see [`LogFile::failed`]).
    fn fail(&self) {
        self.failed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether a sync of the log has failed, on either path.
    fn has_failed(&self) -> bool {
        self.failed.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn durable_end(&self) -> u64 {
        self.durable
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .end
    }

    /// A Flush record with sequence number `lsn` was appended and ends at
    /// `end`.  (Under the store's lock: in order.)
    fn ended(&self, lsn: u64, end: u64) {
        self.durable
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .waiting
            .push_back((lsn, end));
    }

    /// An `fdatasync` that began after everything up to `upto` was
    /// appended has returned.
    fn synced(&self, upto: u64) {
        let mut d = self.durable.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some(&(lsn, end)) = d.waiting.front() {
            if lsn > upto {
                break;
            }
            d.end = d.end.max(end);
            d.waiting.pop_front();
        }
    }

    /// A compaction's switch: the file is another, synced whole, `end`
    /// bytes long.  The old file's offsets mean nothing in it.
    fn restart(&self, end: u64) {
        {
            // The new file has no reserve yet: the filler makes it.
            let _fill = self.fill_lock();
            self.allocated.store(end, Ordering::SeqCst);
            self.tail.store(end, Ordering::SeqCst);
        }
        let mut d = self.durable.lock().unwrap_or_else(PoisonError::into_inner);
        d.end = end;
        d.waiting.clear();
    }
}

impl Syncer {
    /// Make everything appended up to `lsn` durable.  Returns whether this
    /// call ran the sync (false: another caller's covered it).  The call
    /// that ran a sync that failed gets that error; every call after it,
    /// and every waiter on it, gets [`StoreError::Poisoned`].
    pub fn durable(&self, lsn: u64) -> Result<bool, StoreError> {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        st.requested = st.requested.max(lsn);
        let mut led = false;
        loop {
            if st.failed || self.file.has_failed() {
                return Err(StoreError::Poisoned);
            }
            if st.durable >= lsn {
                return Ok(led);
            }
            if st.syncing {
                st = self.done.wait(st).unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            let upto = st.requested;
            st.syncing = true;
            drop(st);
            let t = std::time::Instant::now();
            let r = self.file.get().sync_data();
            let us = t.elapsed().as_micros() as u64;
            st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            st.syncing = false;
            // The store's own sync failed while this one ran: the
            // kernel may have reported the error to that call alone, so
            // this one's ok proves nothing (finding 3).
            let r = match r {
                Ok(()) if self.file.has_failed() => {
                    Err(io::Error::other("a sync of the log failed (the store's)"))
                }
                r => r,
            };
            match r {
                Ok(()) => {
                    st.durable = st.durable.max(upto);
                    // For the next Flush record to say: the end of the
                    // newest Flush this sync covered.
                    self.file.synced(upto);
                    st.syncs += 1;
                    st.sync_us += us;
                    st.sync_max_us = st.sync_max_us.max(us);
                    led = true;
                }
                Err(e) => {
                    self.file.fail();
                    st.failed = true;
                    st.error = Some(e.to_string());
                    self.done.notify_all();
                    return Err(e.into());
                }
            }
            self.done.notify_all();
        }
    }

    /// The inode of the file the next sync goes to (a check that it is
    /// the log: after a compaction's switch it must be the new one).
    pub fn log_ino(&self) -> io::Result<u64> {
        use std::os::unix::fs::MetadataExt;
        Ok(self.file.get().metadata()?.ino())
    }

    /// How the sync failed, once one has.
    pub fn failure(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .error
            .clone()
    }

    /// Syncs made so far.
    pub fn syncs(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .syncs
    }

    /// The time of the syncs made so far: summed and the longest (µs).
    pub fn sync_time(&self) -> (u64, u64) {
        let st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        (st.sync_us, st.sync_max_us)
    }
}

fn sync_dir(path: &Path) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(dir)?.sync_all()
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    const B: usize = BLOCK as usize;

    fn blocks(byte: u8, n: usize) -> Vec<u8> {
        vec![byte; n * B]
    }

    /// Where the bytes of a log end that are not the reserve's zeros (the
    /// rule of [`nonzero_end`]): what an open counts from `from` as cut.
    fn data_len(bytes: &[u8], from: u64) -> u64 {
        bytes
            .iter()
            .rposition(|b| *b != 0)
            .map_or(from, |i| (i as u64 + 1).max(from))
    }

    fn read1(s: &Store, layer: LayerId, lba: u64) -> u8 {
        let mut buf = vec![0xEEu8; B];
        s.read(layer, lba, &mut buf).unwrap();
        assert!(
            buf.iter().all(|b| *b == buf[0]),
            "a block is uniform in these tests"
        );
        buf[0]
    }

    fn new_store(dir: &tempfile::TempDir) -> Store {
        Store::create(&dir.path().join("log")).unwrap()
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn chmod(p: &Path, m: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    /// Maturity review of e4a37b2, finding 4 (F4-a (a)): a write that does
    /// not fit on the log's filesystem is refused, and refused alone.  The
    /// map does not move, the store is not poisoned, the writes before it
    /// read back, a Seal still closes in the room held back for it, and once
    /// there is room the same write goes through.  The room the store keeps
    /// ahead of its tail is not a torn tail at the next open.
    #[test]
    fn a_write_that_does_not_fit_is_refused_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        let root = s.root_seal().unwrap();
        let a = s.fork(root).unwrap();
        let b = s.fork(root).unwrap();
        s.write(b, 0, &blocks(0xB0, 1), false).unwrap();
        s.flush().unwrap();
        // The filesystem: room for some forty more blocks.
        s.room = Some(s.tail + 40 * BLOCK);
        let mut refused_at = None;
        for lba in 0..200 {
            match s.write(a, lba, &blocks(lba as u8 + 1, 1), false) {
                Ok(()) => {}
                Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::StorageFull => {
                    refused_at = Some(lba);
                    break;
                }
                Err(e) => panic!("block {lba}: {e}"),
            }
        }
        let at = refused_at.expect("a write was refused before 200 blocks");
        assert!(at > 0, "the room held some writes");
        assert!(!s.is_poisoned(), "one refused write poisoned the store");
        // The refused write changed nothing; the others read back.
        assert_eq!(
            read1(&s, a, at),
            0,
            "the refused block reads as never written"
        );
        assert_eq!(read1(&s, a, at - 1), at as u8);
        assert_eq!(read1(&s, b, 0), 0xB0, "another branch reads");
        // A Seal closes in the room held back for it.
        s.seal(a).unwrap();
        // Room again: the same write goes through.
        s.room = None;
        let a2 = s.fork(root).unwrap();
        s.write(a2, at, &blocks(0xA2, 1), false).unwrap();
        s.flush().unwrap();
        drop(s);
        // The room kept ahead of the tail is not a torn tail.
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.cut, 0, "the reserve was reported as a torn tail");
        assert_eq!((read1(&s, a2, at), read1(&s, b, 0)), (0xA2, 0xB0));
    }

    /// Finding 4, the filler (F4-c (a)): it keeps [`RESERVE`] written and
    /// synced past the tail; writes then need no zeros of their own; an
    /// open keeps the reserve and counts nothing of it as cut; the zeros
    /// are no records to a compaction either, and after its switch the
    /// filler makes the new file's reserve.
    #[test]
    fn the_filler_keeps_the_reserve_ahead_and_an_open_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        let filler = s.filler();
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        assert!(filler.fill_ahead().unwrap() > 0);
        // Ahead by the reserve, to the next whole block.
        let ahead = (s.tail + RESERVE).next_multiple_of(BLOCK);
        assert_eq!(s.shared.allocated(), ahead);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), ahead);
        assert_eq!(filler.fill_ahead().unwrap(), 0, "full: nothing to do");
        for lba in 0..4 {
            s.write(b, lba, &blocks(lba as u8 + 1, 1), false).unwrap();
        }
        s.flush().unwrap();
        assert_eq!(
            s.shared.allocated(),
            std::fs::metadata(&path).unwrap().len(),
            "the writes fitted in the reserve"
        );
        let len = std::fs::metadata(&path).unwrap().len();
        drop(s);
        let (mut s, rec) = Store::open(&path).unwrap();
        assert_eq!((rec.cut, rec.set_aside.is_none()), (0, true));
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            len,
            "the reserve is kept"
        );
        assert_eq!(s.shared.allocated(), len);
        assert_eq!(read1(&s, b, 3), 4);
        // A compaction: the zeros are no records; the new file has no
        // reserve until the filler makes it.
        compact(&mut s);
        assert_eq!(s.shared.allocated(), s.tail);
        let filler = s.filler();
        filler.fill_ahead().unwrap();
        assert_eq!(
            s.shared.allocated(),
            (s.tail + RESERVE).next_multiple_of(BLOCK)
        );
        assert_eq!((read1(&s, b, 0), read1(&s, b, 3)), (1, 4));
        drop(s);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.cut, 0);
        assert_eq!(read1(&s, b, 2), 3);
    }

    /// Finding 4 and finding 3: the filler's two kinds of failure are kept
    /// apart.  No room on the disk changes nothing: the store goes on.  A
    /// failed sync sets the log's latch: the store refuses everything.
    #[test]
    fn the_fillers_two_kinds_of_failure_are_kept_apart() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_store(&dir);
        let filler = s.filler();
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        let before = s.shared.allocated();
        s.shared
            .room
            .store(before + FILL_CHUNK / 2, std::sync::atomic::Ordering::SeqCst);
        match filler.fill_ahead() {
            Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::StorageFull => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(s.shared.allocated(), before, "nothing counted");
        assert!(!s.is_poisoned());
        s.write(b, 0, &blocks(7, 1), false).unwrap();
        s.flush().unwrap();
        assert_eq!(read1(&s, b, 0), 7, "the store goes on");
        // A sync that fails while filling.
        s.shared.room.store(0, std::sync::atomic::Ordering::SeqCst);
        s.shared
            .fail_next_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(filler.fill_ahead().is_err());
        assert!(matches!(
            s.write(b, 1, &blocks(8, 1), false),
            Err(StoreError::Poisoned)
        ));
        assert!(matches!(filler.fill_ahead(), Err(StoreError::Poisoned)));
    }

    /// Finding 4: the filler syncs with its fill lock let go, so a write
    /// that overtakes it never waits for a sync of the whole log (at P=64
    /// on the test VM, 2026-11-27, a burst of births queued every device
    /// write behind the filler's syncs).  At each of the filler's syncs
    /// the fill lock is free, and what it wrote already counts as ready.
    #[test]
    fn the_filler_syncs_with_its_lock_let_go() {
        let dir = tempfile::tempdir().unwrap();
        let s = new_store(&dir);
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        *s.shared.on_sync.lock().unwrap() = Some(Box::new(move |lf: &LogFile| {
            log.lock()
                .unwrap()
                .push((lf.fill.try_lock().is_ok(), lf.allocated()));
        }));
        let before = s.shared.allocated();
        s.filler().fill_ahead().unwrap();
        let seen = seen.lock().unwrap();
        assert!(seen.len() > 1, "a sync per piece: {seen:?}");
        assert!(
            seen.iter().all(|(free, _)| *free),
            "the fill lock held at a sync: {seen:?}"
        );
        assert!(
            seen.iter().all(|(_, ready)| *ready > before),
            "each piece counted ready before its sync: {seen:?}"
        );
    }

    /// Finding 4, the open: only zeros that run to the end of the file are
    /// the reserve.  Bytes that are not zero before them are a torn tail:
    /// counted as cut, and cut with the reserve after them.
    #[test]
    fn a_torn_tail_before_the_reserve_is_cut_and_counted_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        s.write(b, 0, &blocks(1, 1), false).unwrap();
        s.flush().unwrap();
        s.filler().fill_ahead().unwrap();
        let end = s.tail;
        // A torn record: twenty bytes that are not zero, then the zeros.
        s.file.write_all_at(&[0x5Au8; 20], end + 100).unwrap();
        drop(s);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.set_aside, None);
        assert_eq!(rec.cut, 120, "up to the last byte that is not zero");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), end);
        assert_eq!(s.shared.allocated(), end, "the reserve went with the cut");
        assert_eq!(read1(&s, b, 0), 1);
    }

    /// Maturity review of e4a37b2, finding 3: a checkpoint's sync and a
    /// device flush's group commit sync one file description.  When the
    /// checkpoint's `fdatasync` fails, the kernel reports the error to that
    /// call only; a sync after it can return ok with the data never written.
    /// So once the store has seen a failed sync, the Syncer must not answer
    /// any later sync as durable, and the device flush is refused.
    #[test]
    fn a_failed_checkpoint_sync_refuses_the_syncers_next_sync() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_store(&dir);
        let sync = s.syncer().unwrap();
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        // A device flush ends its group under the lock ...
        s.write(b, 0, &blocks(1, 1), false).unwrap();
        let lsn = s.flush_pending().unwrap();
        // ... and before it syncs outside the lock, a checkpoint's sync fails.
        s.shared
            .fail_next_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(s.checkpoint().is_err(), "the checkpoint's sync failed");
        assert!(s.is_poisoned());
        // The device flush's sync now: on a real disk it could return ok,
        // the error already taken by the checkpoint's call.  Refused.
        assert!(
            matches!(sync.durable(lsn), Err(StoreError::Poisoned)),
            "the Syncer answered a sync after a failed one"
        );
    }

    /// Audit 2026-11-16, S1: a Vessel's bytes sit in the log and its
    /// checkpoint whatever the file modes inside the Vessel say, and they
    /// were made 0644 under the usual umask.  Now the log, its lock and
    /// its checkpoint give nobody but the owner access (whatever the
    /// umask, which this test leaves alone: the process shares it).
    #[test]
    fn a_new_logs_files_are_the_owners_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        s.write(b, 0, &blocks(7, 1), false).unwrap();
        s.checkpoint().unwrap();
        for p in [path.clone(), lock_path(&path), ckpt_path(&path)] {
            assert_eq!(mode(&p) & 0o077, 0, "{}: {:o}", p.display(), mode(&p));
        }
    }

    /// Audit 2026-11-16, S1 (D&D S1-a b, S1-b b): a log made before,
    /// readable by others, loses others' access to it and to its
    /// checkpoint when opened, and `open` says what the mode was; a group
    /// the operator gave access keeps it, and a new checkpoint takes the
    /// log's mode, exactly.
    #[test]
    fn opening_an_old_log_takes_others_access_away() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        s.write(b, 0, &blocks(7, 1), false).unwrap();
        s.checkpoint().unwrap();
        drop(s);
        chmod(&path, 0o644);
        chmod(&ckpt_path(&path), 0o644);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.tightened, Some(0o644));
        assert_eq!(mode(&path), 0o640);
        assert_eq!(mode(&ckpt_path(&path)), 0o640);
        assert_eq!(read1(&s, b, 0), 7, "the data is untouched");
        drop(s);
        // The group's access stays: nothing to say.
        let (mut s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.tightened, None);
        assert_eq!(mode(&path), 0o640);
        // A checkpoint written now has the log's mode, whatever the umask.
        std::fs::remove_file(ckpt_path(&path)).unwrap();
        s.checkpoint().unwrap();
        assert_eq!(mode(&ckpt_path(&path)), 0o640);
        drop(s);
        chmod(&path, 0o600);
        let (mut s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.tightened, None);
        s.checkpoint().unwrap();
        assert_eq!(
            mode(&ckpt_path(&path)),
            0o600,
            "the operator took the group's access away"
        );
    }

    #[test]
    fn writes_read_back_and_unwritten_blocks_are_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_store(&dir);
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        s.write(b, 3, &blocks(7, 2), false).unwrap();
        assert_eq!(
            (read1(&s, b, 3), read1(&s, b, 4), read1(&s, b, 5)),
            (7, 7, 0)
        );
        let mut two = vec![0u8; 2 * B];
        s.read(b, 4, &mut two).unwrap();
        assert!(two[..B].iter().all(|x| *x == 7) && two[B..].iter().all(|x| *x == 0));
        s.discard(b, 3, 1).unwrap();
        assert_eq!(read1(&s, b, 3), 0);
        assert_eq!(
            read1(&s, root, 4),
            0,
            "the Seal never sees a branch's writes"
        );
    }

    /// S-c (soak 2026-11-13): a fold is journalled, so a reopened store,
    /// from the log or from a checkpoint, reads the same as before it, the
    /// folded Seal is gone, and the garbage it made is counted.
    #[test]
    fn a_fold_is_replayed_from_the_log_and_from_a_checkpoint() {
        for checkpointed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("log");
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            let b = s.fork(root).unwrap();
            s.write(b, 0, &blocks(1, 2), false).unwrap();
            let s1 = s.seal_tagged(b, b"one").unwrap();
            s.write(b, 1, &blocks(2, 2), false).unwrap(); // rewrites block 1
            let s2 = s.seal_tagged(b, b"two").unwrap();
            s.write(b, 3, &blocks(3, 1), false).unwrap();
            let reads = |s: &Store| -> Vec<u8> {
                (0..4)
                    .flat_map(|l| [read1(s, b, l), read1(s, s2, l)])
                    .collect()
            };
            let before = reads(&s);
            let garbage = s.stats().garbage_bytes;
            assert_eq!(s.fold(s1).unwrap(), (s2, 1), "block 1 of S1 was rewritten");
            assert_eq!(s.stats().garbage_bytes, garbage + BLOCK);
            assert_eq!(reads(&s), before);
            assert_eq!(s.seals_of(b).unwrap(), vec![s2]);
            assert!(
                matches!(s.fold(s2), Err(StoreError::Map(_))),
                "the branch is on top"
            );
            if checkpointed {
                s.checkpoint().unwrap();
            } else {
                s.flush().unwrap();
            }
            drop(s);
            let (s, _) = Store::open(&path).unwrap();
            assert_eq!(reads(&s), before, "checkpointed {checkpointed}");
            assert_eq!(s.seals_of(b).unwrap(), vec![s2]);
            assert_eq!(
                (s.tag(s1).unwrap(), s.tag(s2).unwrap()),
                (None, Some(&b"two"[..]))
            );
            assert_eq!(s.map().unwrap().depth(b).unwrap(), 3);
        }
    }

    /// Audit 2026-11-09, a poisoned store still answered its read
    /// accessors (`find`, `names`, `name_of`, `seals_of`, `tag`, `origin`,
    /// `map`) from a map that may be ahead of the file: here it found a
    /// name whose record never reached the log.
    #[test]
    fn a_poisoned_store_does_not_answer_from_a_map_ahead_of_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        let seal = s.seal_tagged(b, b"tag").unwrap();
        s.flush().unwrap();
        // The next append fails: the file handle cannot be written.
        s.file = File::open(&path).unwrap();
        assert!(s.name(b, "ghost").is_err(), "the append fails");
        assert!(s.is_poisoned());
        // The mutating and data calls do fail.
        assert!(matches!(s.flush(), Err(StoreError::Poisoned)));
        let mut buf = vec![0u8; B];
        assert!(matches!(s.read(b, 0, &mut buf), Err(StoreError::Poisoned)));
        // So do the reads of the map, the names, the tags and the origins.
        assert!(matches!(s.find("ghost"), Err(StoreError::Poisoned)));
        assert!(matches!(s.names(), Err(StoreError::Poisoned)));
        assert!(matches!(s.name_of(b), Err(StoreError::Poisoned)));
        assert!(matches!(s.seals_of(b), Err(StoreError::Poisoned)));
        assert!(matches!(s.tag(seal), Err(StoreError::Poisoned)));
        assert!(matches!(s.origin(seal), Err(StoreError::Poisoned)));
        assert!(matches!(s.map(), Err(StoreError::Poisoned)));
        assert!(matches!(s.check_name("free"), Err(StoreError::Poisoned)));
        // Reopened, the store answers again, from the log: the name whose
        // record never reached it is not there.
        drop(s);
        let (s2, _) = Store::open(&path).unwrap();
        assert_eq!(s2.find("ghost").unwrap(), None);
        assert_eq!(s2.name_of(b).unwrap(), None);
        assert_eq!(s2.seals_of(b).unwrap(), vec![seal]);
    }

    /// Review fix H1 (Kimi's H1): a read whose range passes the last LBA
    /// is refused before any block; it used to wrap (optimized: the second
    /// block returned LBA 0's data; debug: a panic).
    #[test]
    fn a_read_past_the_last_lba_is_refused_and_never_wraps() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::create(&dir.path().join("log")).unwrap();
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        s.write(b, 0, &vec![0x5a; BLOCK as usize], false).unwrap();
        let mut buf = vec![0xee; 2 * BLOCK as usize];
        for lba in [u64::MAX, u64::MAX - 1] {
            assert!(
                matches!(
                    s.read(b, lba, &mut buf),
                    Err(StoreError::Map(MapError::Overflow))
                ),
                "a read of two blocks at {lba}"
            );
        }
        assert!(buf.iter().all(|&x| x == 0xee), "nothing was read");
        // The last whole range that fits still reads (unwritten: zeros).
        s.read(b, u64::MAX - 2, &mut buf).unwrap();
        assert!(buf.iter().all(|&x| x == 0));
    }

    #[test]
    fn bad_writes_are_refused_and_append_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_store(&dir);
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        let before = s.stats();
        assert!(matches!(
            s.write(b, 0, &[1u8; 100], false),
            Err(StoreError::BadLength(100))
        ));
        assert!(matches!(
            s.write(b, 0, &[], false),
            Err(StoreError::BadLength(0))
        ));
        assert!(matches!(
            s.write(root, 0, &blocks(1, 1), false),
            Err(StoreError::Map(MapError::NotABranch(_)))
        ));
        assert!(matches!(
            s.write(b, u64::MAX, &blocks(1, 1), false),
            Err(StoreError::Map(MapError::Overflow))
        ));
        assert!(matches!(
            s.write(b, 0, &blocks(1, 4097), false),
            Err(StoreError::TooLarge(_))
        ));
        assert!(matches!(
            s.fork(b),
            Err(StoreError::Map(MapError::NotASeal(_)))
        ));
        assert_eq!(s.stats(), before, "a refusal appends nothing");
        let mut odd = vec![0u8; 10];
        assert!(matches!(
            s.read(b, 0, &mut odd),
            Err(StoreError::BadLength(10))
        ));
    }

    #[test]
    fn reopen_after_a_flush_rebuilds_the_same_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (root, b, s2, seal_lsn);
        {
            let mut s = Store::create(&path).unwrap();
            root = s.root_seal().unwrap();
            b = s.fork(root).unwrap();
            s.write(b, 1, &blocks(1, 1), false).unwrap();
            s2 = s.seal(b).unwrap();
            seal_lsn = s.map().unwrap().kind(s2).unwrap();
            s.write(b, 1, &blocks(2, 1), false).unwrap();
            s.write(b, 2, &blocks(3, 1), false).unwrap();
            s.discard(b, 2, 1).unwrap();
            s.flush().unwrap();
        }
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.cut, 0);
        assert_eq!(rec.groups, 3, "root, seal, and the explicit flush");
        // root, flush, fork, write, seal: the Seal is record 5, before and after.
        assert_eq!(seal_lsn, Kind::Seal { lsn: 5 });
        assert_eq!(s.map().unwrap().kind(s2).unwrap(), seal_lsn);
        assert_eq!(
            s.map().unwrap().parent(b).unwrap(),
            Some(s2),
            "same ids after replay"
        );
        assert_eq!(
            (read1(&s, b, 1), read1(&s, s2, 1), read1(&s, b, 2)),
            (2, 1, 0)
        );
        assert_eq!(
            s.stats().garbage_bytes,
            BLOCK,
            "block 2's write was discarded in its own layer"
        );
    }

    #[test]
    fn writes_after_the_last_flush_are_cut_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (b, durable_len);
        {
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            b = s.fork(root).unwrap();
            s.write(b, 0, &blocks(1, 1), false).unwrap();
            s.flush().unwrap();
            durable_len = s.stats().log_bytes;
            s.write(b, 0, &blocks(2, 1), false).unwrap();
            s.write(b, 1, &blocks(3, 1), false).unwrap();
        }
        let (mut s, rec) = Store::open(&path).unwrap();
        assert!(rec.cut > 0);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            durable_len,
            "the cut is on disk"
        );
        assert_eq!((read1(&s, b, 0), read1(&s, b, 1)), (1, 0));
        // And the log goes on from there.
        s.write(b, 1, &blocks(4, 1), true).unwrap();
        drop(s);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!((rec.cut, read1(&s, b, 1)), (0, 4));
    }

    #[test]
    fn a_fua_write_is_durable_without_a_flush() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let b;
        {
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            b = s.fork(root).unwrap();
            s.write(b, 9, &blocks(5, 1), true).unwrap();
        }
        let (s, _) = Store::open(&path).unwrap();
        assert_eq!(read1(&s, b, 9), 5);
    }

    #[test]
    fn a_fork_of_a_seal_reads_its_blocks_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (seal, other);
        {
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            let b = s.fork(root).unwrap();
            s.write(b, 0, &blocks(9, 3), false).unwrap();
            seal = s.seal(b).unwrap();
            other = s.fork(seal).unwrap();
            s.write(other, 1, &blocks(8, 1), true).unwrap();
        }
        let (s, _) = Store::open(&path).unwrap();
        assert_eq!(
            (read1(&s, other, 0), read1(&s, other, 1), read1(&s, seal, 1)),
            (9, 8, 9)
        );
    }

    #[test]
    fn a_corrupt_byte_in_the_last_group_falls_back_to_the_flush_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (b, mid);
        {
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            b = s.fork(root).unwrap();
            s.write(b, 0, &blocks(1, 1), false).unwrap();
            s.flush().unwrap();
            mid = s.stats().log_bytes;
            s.write(b, 0, &blocks(2, 1), false).unwrap();
            s.flush().unwrap();
        }
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.write_all_at(&[0xFF], mid + REC_HEAD + 20).unwrap(); // inside the block data
        drop(f);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!(read1(&s, b, 0), 1);
        assert!(rec.cut > 0);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), mid);
    }

    /// Flip each byte of the last group's write record in turn (magic,
    /// length, kind, fields, data, hash): every flip must fall back to the
    /// flush before it, never be replayed as something else.
    #[test]
    fn any_flipped_byte_of_a_record_falls_back_to_the_flush_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (b, mid, end);
        {
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            b = s.fork(root).unwrap();
            s.write(b, 0, &blocks(1, 1), false).unwrap();
            s.flush().unwrap();
            mid = s.stats().log_bytes;
            s.write(b, 0, &blocks(2, 1), false).unwrap();
            end = s.stats().log_bytes; // end of the write record; a Flush follows
            s.flush().unwrap();
        }
        let good = std::fs::read(&path).unwrap();
        let flipped = path.with_extension("flip");
        // 0x01 flips a bit; 0x03 and 0x09 also turn kind Write (1) into
        // Discard (2) and Flush (8): valid kinds only the hash can catch.
        for at in mid..end {
            for mask in [0x01u8, 0x03, 0x09, 0x80] {
                let mut bytes = good.clone();
                bytes[at as usize] ^= mask;
                std::fs::write(&flipped, &bytes).unwrap();
                let (s, rec) = Store::open(&flipped)
                    .unwrap_or_else(|e| panic!("byte {} mask {mask:#x}: {e}", at - mid));
                assert_eq!(s.stats().log_bytes, mid, "byte {} mask {mask:#x}", at - mid);
                assert_eq!(read1(&s, b, 0), 1, "byte {} mask {mask:#x}", at - mid);
                assert_eq!(rec.cut, data_len(&bytes, mid) - mid);
            }
        }
    }

    #[test]
    fn a_file_that_is_not_a_log_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x");
        std::fs::write(&path, b"not a log at all").unwrap();
        assert!(matches!(Store::open(&path), Err(StoreError::NotALog)));
        std::fs::write(&path, b"TASO").unwrap();
        assert!(matches!(Store::open(&path), Err(StoreError::NotALog)));
        assert!(Store::create(&path).is_err(), "create never overwrites");
    }

    #[test]
    fn a_verified_record_that_does_not_replay_is_refused_not_skipped() {
        // Build a log by hand whose chain is valid but whose second record
        // forks from a layer that does not exist.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        s.root_seal().unwrap();
        s.append(K_FORK, &99u64.to_le_bytes()).unwrap();
        s.flush_pending().unwrap();
        drop(s);
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::Replay {
                lsn: 3,
                error: MapError::Unknown(_)
            })
        ));
    }

    #[test]
    fn a_new_log_counts_its_header() {
        let dir = tempfile::tempdir().unwrap();
        let s = new_store(&dir);
        assert_eq!(
            s.stats(),
            Stats {
                log_bytes: HEADER_LEN,
                ..Stats::default()
            }
        );
        assert_eq!(std::fs::metadata(s.path()).unwrap().len(), HEADER_LEN);
    }

    #[test]
    fn tags_origins_and_names_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (root, a, b, s1, s2, s3);
        {
            let mut s = Store::create(&path).unwrap();
            root = s.root_seal().unwrap();
            a = s.fork(root).unwrap();
            s.name(a, "tank/taso/vessel-a").unwrap();
            s.write(a, 0, &blocks(1, 1), false).unwrap();
            s1 = s.seal_tagged(a, b"lsn=7 hash=aa").unwrap();
            s.write(a, 0, &blocks(2, 1), false).unwrap();
            s2 = s.seal_tagged(a, &[0xff; MAX_TAG]).unwrap();
            b = s.fork(s1).unwrap();
            s.name(b, "tank/taso/vessel-b").unwrap();
            s3 = s.seal(b).unwrap();
            s.flush().unwrap();
        }
        let (s, _) = Store::open(&path).unwrap();
        assert_eq!(s.find("tank/taso/vessel-a").unwrap(), Some(a));
        assert_eq!(s.find("tank/taso/vessel-b").unwrap(), Some(b));
        assert_eq!(s.name_of(a).unwrap(), Some("tank/taso/vessel-a"));
        assert_eq!(s.tag(s1).unwrap(), Some(&b"lsn=7 hash=aa"[..]));
        assert_eq!(s.tag(s2).unwrap(), Some(&[0xff; MAX_TAG][..]));
        assert_eq!(s.tag(s3).unwrap(), Some(&b""[..]));
        assert_eq!(s.tag(root).unwrap(), Some(&b""[..]));
        assert_eq!(
            (
                s.origin(s1).unwrap(),
                s.origin(s3).unwrap(),
                s.origin(root).unwrap()
            ),
            (Some(a), Some(b), None)
        );
        assert_eq!(
            s.seals_of(a).unwrap(),
            vec![s1, s2],
            "a's own Seals, oldest first"
        );
        assert_eq!(
            s.seals_of(b).unwrap(),
            vec![s3],
            "b's own Seals only, not the one it was forked from"
        );
        assert_eq!(
            read1(&s, a, 0),
            2,
            "the name stays with the branch across Seals"
        );
    }

    #[test]
    fn name_rules() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_store(&dir);
        let root = s.root_seal().unwrap();
        let (a, b) = (s.fork(root).unwrap(), s.fork(root).unwrap());
        s.name(a, "x").unwrap();
        let lsn = s.lsn();
        assert!(matches!(s.name(b, "x"), Err(StoreError::NameTaken(_))));
        assert!(matches!(
            s.name(root, "r"),
            Err(StoreError::Map(MapError::NotABranch(_)))
        ));
        // "-": the protocol's "none" (round 3, R3-04); "-x" and "a-" are names.
        for bad in ["has space", "tab\t", "ä", "-", &"n".repeat(MAX_NAME + 1)] {
            assert!(
                matches!(s.name(b, bad), Err(StoreError::BadName(_))),
                "{bad:?}"
            );
        }
        assert!(matches!(
            s.seal_tagged(b, &[0; MAX_TAG + 1]),
            Err(StoreError::BadTag(_))
        ));
        assert_eq!(s.lsn(), lsn, "refusals append nothing");
        assert!(matches!(s.check_name("x"), Err(StoreError::NameTaken(_))));
        assert!(matches!(s.check_name("a b"), Err(StoreError::BadName(_))));
        assert!(matches!(s.check_name(""), Err(StoreError::BadName(_))));
        s.check_name("free").unwrap();
        s.check_name("-x").unwrap();
        s.check_name("a-").unwrap();
        s.name(a, "x").unwrap(); // naming again with the same name is fine
        s.name(a, "y").unwrap(); // renaming frees the old name
        assert_eq!(
            (s.find("x").unwrap(), s.find("y").unwrap()),
            (None, Some(a))
        );
        s.name(b, "x").unwrap();
        s.name(b, "").unwrap(); // taking the name away
        assert_eq!((s.find("x").unwrap(), s.name_of(b).unwrap()), (None, None));
        s.drop_branch(a).unwrap(); // dropping frees the name
        assert_eq!(s.find("y").unwrap(), None);
        let c = s.fork(root).unwrap();
        s.name(c, "y").unwrap();
        let sc = s.seal(c).unwrap();
        s.drop_seal(sc).unwrap_err(); // c stands on it
        s.drop_branch(c).unwrap();
        s.drop_seal(sc).unwrap();
        assert_eq!(
            (
                s.tag(sc).unwrap(),
                s.origin(sc).unwrap(),
                s.seals_of(c).unwrap()
            ),
            (None, None, vec![])
        );
        s.flush().unwrap();
        let path = s.path().to_path_buf();
        drop(s);
        let (s, _) = Store::open(&path).unwrap();
        assert_eq!(
            (
                s.find("x").unwrap(),
                s.find("y").unwrap(),
                s.name_of(b).unwrap()
            ),
            (None, None, None)
        );
    }

    #[test]
    fn a_reset_branch_reads_as_its_seal_and_keeps_its_name_and_seals() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (a, s1);
        {
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            a = s.fork(root).unwrap();
            s.name(a, "tank/v-a").unwrap();
            s.write(a, 0, &blocks(1, 2), false).unwrap();
            s1 = s.seal_tagged(a, b"t1").unwrap();
            s.write(a, 0, &blocks(2, 1), false).unwrap();
            s.write(a, 5, &blocks(3, 1), false).unwrap();
            let g = s.stats().garbage_bytes;
            s.reset(a).unwrap();
            assert_eq!(
                s.stats().garbage_bytes,
                g + 2 * BLOCK,
                "the two blocks written after the Seal"
            );
            assert_eq!(
                (read1(&s, a, 0), read1(&s, a, 1), read1(&s, a, 5)),
                (1, 1, 0),
                "reads as the Seal again"
            );
            assert!(matches!(
                s.reset(s1),
                Err(StoreError::Map(MapError::NotABranch(_)))
            ));
            s.flush().unwrap();
        }
        let (s, _) = Store::open(&path).unwrap();
        assert_eq!(
            (read1(&s, a, 0), read1(&s, a, 5)),
            (1, 0),
            "the reset survives a reopen"
        );
        assert_eq!(
            (s.find("tank/v-a").unwrap(), s.seals_of(a).unwrap()),
            (Some(a), vec![s1])
        );
        assert_eq!(s.map().unwrap().parent(a).unwrap(), Some(s1));
    }

    #[test]
    fn an_unsealed_branch_stands_below_its_orphan_and_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (a, s1, orphan);
        {
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            a = s.fork(root).unwrap();
            s.name(a, "tank/v-a").unwrap();
            s.write(a, 0, &blocks(1, 2), false).unwrap();
            s1 = s.seal_tagged(a, b"t1").unwrap();
            s.write(a, 0, &blocks(2, 1), false).unwrap();
            orphan = s.seal_tagged(a, b"t2").unwrap(); // its record never accepted
            s.write(a, 5, &blocks(3, 1), false).unwrap();
            assert!(matches!(
                s.drop_seal(orphan),
                Err(StoreError::Map(MapError::HasChildren(_)))
            ));
            let g = s.stats().garbage_bytes;
            assert_eq!(
                s.unseal(a).unwrap(),
                2,
                "the orphan's block and the branch's"
            );
            assert_eq!(s.stats().garbage_bytes, g + 2 * BLOCK);
            assert_eq!(
                (read1(&s, a, 0), read1(&s, a, 1), read1(&s, a, 5)),
                (1, 1, 0),
                "reads as s1"
            );
            assert_eq!(
                s.seals_of(a).unwrap(),
                vec![s1],
                "the orphan is no Seal of it"
            );
            s.flush().unwrap();
        }
        let (s, _) = Store::open(&path).unwrap();
        assert_eq!(
            (read1(&s, a, 0), read1(&s, a, 5)),
            (1, 0),
            "the unseal survives a reopen"
        );
        assert_eq!(
            (s.find("tank/v-a").unwrap(), s.seals_of(a).unwrap()),
            (Some(a), vec![s1])
        );
        assert_eq!(s.map().unwrap().parent(a).unwrap(), Some(s1));
        assert!(s.map().unwrap().kind(orphan).is_err());
    }

    /// Every block `0..span` of `layer`, one byte each (blocks are filled
    /// with one value).
    fn image(s: &Store, layer: LayerId, span: u64) -> Vec<u8> {
        (0..span).map(|b| read1(s, layer, b)).collect()
    }

    fn export_bytes(s: &Store, to: LayerId, from: Option<LayerId>) -> Vec<u8> {
        let mut out = Vec::new();
        s.export(to, from, &mut out).unwrap();
        out
    }

    #[test]
    fn export_and_import_ship_seals_between_stores() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = Store::create(&dir.path().join("a")).unwrap();
        let mut b = Store::create(&dir.path().join("b")).unwrap();
        let (ra, rb) = (a.root_seal().unwrap(), b.root_seal().unwrap());

        // Seal 1: full.
        let va = a.fork(ra).unwrap();
        a.write(va, 0, &blocks(1, 3), false).unwrap();
        a.write(va, 10, &blocks(2, 1), false).unwrap();
        a.discard(va, 1, 1).unwrap();
        let s1 = a.seal(va).unwrap();
        let vb = b.fork(rb).unwrap();
        // Blocks 0, 2 and 10: block 1 was discarded and nothing below it
        // holds data, so it needs no entry (it reads as the zero base).
        assert_eq!(
            b.import(vb, &mut &export_bytes(&a, s1, None)[..]).unwrap(),
            3
        );
        let t1 = b.seal(vb).unwrap();
        assert_eq!(image(&b, t1, 16), image(&a, s1, 16));

        // Seal 2: incremental, with an overwrite and a discard of an old block.
        a.write(va, 0, &blocks(3, 1), false).unwrap();
        a.discard(va, 10, 1).unwrap();
        a.write(va, 12, &blocks(4, 2), false).unwrap();
        let s2 = a.seal(va).unwrap();
        let inc = export_bytes(&a, s2, Some(s1));
        assert!(
            inc.len() < export_bytes(&a, s2, None).len(),
            "incremental carries only the change"
        );
        assert_eq!(b.import(vb, &mut &inc[..]).unwrap(), 4);
        let t2 = b.seal(vb).unwrap();
        assert_eq!(image(&b, t2, 16), image(&a, s2, 16));
        assert_eq!(image(&b, t2, 16)[10], 0, "the discard travelled");

        // A clone's first Seal: incremental from the parent Seal.
        let ca = a.fork(s1).unwrap();
        a.write(ca, 5, &blocks(9, 1), false).unwrap();
        let c1 = a.seal(ca).unwrap();
        let cb = b.fork(t1).unwrap();
        b.import(cb, &mut &export_bytes(&a, c1, Some(s1))[..])
            .unwrap();
        let u1 = b.seal(cb).unwrap();
        assert_eq!(image(&b, u1, 16), image(&a, c1, 16));

        // Durable on b after a reopen.
        b.flush().unwrap();
        let path = b.path().to_path_buf();
        drop(b);
        let (b, _) = Store::open(&path).unwrap();
        assert_eq!(
            (image(&b, t2, 16), image(&b, u1, 16)),
            (image(&a, s2, 16), image(&a, c1, 16))
        );
    }

    /// P5 bite 5: the export's I/O leaves the store's lock.  A plan made
    /// under the store is written after the log was compacted (a new
    /// file renamed over the old) and the Seal dropped: the stream must be
    /// the one the whole export wrote before.  Without a descriptor of its
    /// own the plan would read its offsets from the compacted file, where
    /// the blocks sit elsewhere (checked by hand on 2026-11-04: reopening
    /// the path at write time fails this test).
    #[test]
    fn an_export_planned_before_a_compaction_and_a_drop_writes_the_same_stream() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = Store::create(&dir.path().join("a")).unwrap();
        let ra = a.root_seal().unwrap();
        let va = a.fork(ra).unwrap();
        a.write(va, 0, &blocks(1, 3), false).unwrap();
        a.write(va, 10, &blocks(2, 1), false).unwrap();
        a.discard(va, 1, 1).unwrap();
        let s1 = a.seal(va).unwrap();
        // Garbage ahead of s1's blocks, so the compaction moves them.
        a.write(va, 0, &blocks(3, 3), false).unwrap();
        a.write(va, 10, &blocks(4, 1), false).unwrap();
        let s2 = a.seal(va).unwrap();
        let whole = export_bytes(&a, s1, None);
        let incremental = export_bytes(&a, s2, Some(s1));

        let plan = a.export_plan(s1, None).unwrap();
        let plan2 = a.export_plan(s2, Some(s1)).unwrap();
        assert_eq!(plan.blocks(), 3);
        let mut c = a.compaction().unwrap();
        c.copy().unwrap();
        let done = c.finish(&mut a).unwrap();
        drop(done);
        // The log is a new file now, and s1's blocks sit at new offsets.
        a.write(va, 20, &blocks(5, 1), false).unwrap();
        a.flush().unwrap();

        let mut out = Vec::new();
        assert_eq!(plan.write(&mut out).unwrap(), 3);
        assert_eq!(out, whole, "the plan reads the log it was made on");
        let mut out2 = Vec::new();
        plan2.write(&mut out2).unwrap();
        assert_eq!(out2, incremental);

        // And after its Seal is gone: a Seal with no child, planned, then dropped.
        a.write(va, 30, &blocks(6, 2), false).unwrap();
        let s3 = a.seal(va).unwrap();
        let since2 = export_bytes(&a, s3, Some(s2));
        let plan3 = a.export_plan(s3, Some(s2)).unwrap();
        a.drop_branch(va).unwrap(); // the branch stood on s3
        a.drop_seal(s3).unwrap();
        let mut out3 = Vec::new();
        assert_eq!(plan3.write(&mut out3).unwrap(), 3); // blocks 20, 30, 31 since s2
        assert_eq!(
            out3, since2,
            "the dropped Seal's blocks are still in the file"
        );
        // The compacted store still exports s2 whole, and the same way.
        assert_eq!(export_bytes(&a, s2, None), {
            let p = a.export_plan(s2, None).unwrap();
            let mut o = Vec::new();
            p.write(&mut o).unwrap();
            o
        });
    }

    #[test]
    fn long_runs_are_split_and_arrive_whole() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = Store::create(&dir.path().join("a")).unwrap();
        let mut b = Store::create(&dir.path().join("b")).unwrap();
        let ra = a.root_seal().unwrap();
        let va = a.fork(ra).unwrap();
        let n = RUN_MAX as usize * 2 + 7;
        let data: Vec<u8> = (0..n)
            .flat_map(|i| [(i % 251) as u8; BLOCK as usize])
            .collect();
        a.write(va, 3, &data, false).unwrap();
        a.discard(va, 5000, 3000).unwrap();
        let s1 = a.seal(va).unwrap();
        let rb = b.root_seal().unwrap();
        let vb = b.fork(rb).unwrap();
        // The discard of blocks nothing holds ships nothing.
        assert_eq!(
            b.import(vb, &mut &export_bytes(&a, s1, None)[..]).unwrap(),
            n as u64
        );
        let mut got = vec![0u8; n * BLOCK as usize];
        b.read(vb, 3, &mut got).unwrap();
        assert!(got == data, "every block of the long run arrived");
    }

    #[test]
    fn exports_that_make_no_sense_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = new_store(&dir);
        let root = a.root_seal().unwrap();
        let v = a.fork(root).unwrap();
        let s1 = a.seal(v).unwrap();
        let w = a.fork(root).unwrap();
        let other = a.seal(w).unwrap();
        let mut sink = Vec::new();
        assert!(
            matches!(
                a.export(v, None, &mut sink),
                Err(StoreError::Map(MapError::NotASeal(_)))
            ),
            "a live branch moves"
        );
        assert!(matches!(
            a.export(s1, Some(other), &mut sink),
            Err(StoreError::NotAnAncestor { .. })
        ));
        assert!(matches!(
            a.export(s1, Some(v), &mut sink),
            Err(StoreError::Map(MapError::NotASeal(_)))
        ));
        a.write(v, 0, &blocks(1, 1), false).unwrap();
        let bytes = export_bytes(&a, s1, None);
        assert!(matches!(
            a.import(v, &mut &bytes[..]),
            Err(StoreError::NotClean(_))
        ));
        assert!(matches!(
            a.import(s1, &mut &bytes[..]),
            Err(StoreError::Map(MapError::NotABranch(_)))
        ));
    }

    #[test]
    fn a_bad_stream_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = Store::create(&dir.path().join("a")).unwrap();
        let ra = a.root_seal().unwrap();
        let va = a.fork(ra).unwrap();
        a.write(va, 0, &blocks(1, 2), false).unwrap();
        a.discard(va, 4, 2).unwrap();
        a.write(va, 9, &blocks(2, 1), false).unwrap();
        let s1 = a.seal(va).unwrap();
        let good = export_bytes(&a, s1, None);

        let mut b = Store::create(&dir.path().join("b")).unwrap();
        let rb = b.root_seal().unwrap();
        let vb = b.fork(rb).unwrap();
        let clean = |b: &Store| b.map().unwrap().delta(vb).unwrap().next().is_none();
        let mut tried = 0;
        // Cut at every length short of whole.
        for len in 0..good.len() {
            assert!(
                matches!(
                    b.import(vb, &mut &good[..len]),
                    Err(StoreError::BadStream(_))
                ),
                "cut at {len}"
            );
            assert!(clean(&b), "cut at {len} left blocks");
            tried += 1;
        }
        // Any one byte changed (each bit pattern that keeps the length).
        for at in 0..good.len() {
            let mut bad = good.clone();
            bad[at] ^= 0x41;
            match b.import(vb, &mut &bad[..]) {
                Err(StoreError::BadStream(_)) => {}
                other => panic!("byte {at} flipped: {other:?}"),
            }
            assert!(clean(&b), "byte {at} flipped left blocks");
            tried += 1;
        }
        let mut longer = good.clone();
        longer.push(0);
        assert!(matches!(
            b.import(vb, &mut &longer[..]),
            Err(StoreError::BadStream("bytes after the end"))
        ));
        assert!(clean(&b));
        assert!(tried > 2 * 8000, "{tried}");
        // And the good one still goes in.
        b.import(vb, &mut &good[..]).unwrap();
        let t1 = b.seal(vb).unwrap();
        assert_eq!(image(&b, t1, 12), image(&a, s1, 12));
    }

    #[test]
    fn names_are_listed_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_store(&dir);
        let root = s.root_seal().unwrap();
        let (x, y) = (s.fork(root).unwrap(), s.fork(root).unwrap());
        s.name(y, "tank/b").unwrap();
        s.name(x, "tank/a").unwrap();
        assert_eq!(
            s.names().unwrap(),
            vec![("tank/a".to_string(), x), ("tank/b".to_string(), y)]
        );
    }

    /// A store with layers, names, tags, discards and garbage, then a
    /// checkpoint, then more of each after it (flushed).
    fn busy_store(path: &Path) -> (Store, Vec<LayerId>, u64) {
        let mut s = Store::create(path).unwrap();
        let root = s.root_seal().unwrap();
        let a = s.fork(root).unwrap();
        s.name(a, "tank/a").unwrap();
        s.write(a, 0, &blocks(1, 3), false).unwrap();
        s.discard(a, 1, 1).unwrap();
        let s1 = s.seal_tagged(a, b"one").unwrap();
        s.write(a, 0, &blocks(2, 1), false).unwrap();
        let b = s.fork(s1).unwrap();
        s.name(b, "tank/b").unwrap();
        s.write(b, 5, &blocks(3, 2), false).unwrap();
        let at = s.checkpoint().unwrap();
        s.write(a, 7, &blocks(4, 1), false).unwrap();
        let s2 = s.seal_tagged(a, b"two").unwrap();
        s.reset(b).unwrap();
        s.write(b, 6, &blocks(5, 1), false).unwrap();
        let c = s.fork(s2).unwrap();
        s.name(c, "tank/c").unwrap();
        s.name(b, "").unwrap();
        s.flush().unwrap();
        (s, vec![root, a, s1, b, s2, c], at)
    }

    #[test]
    fn a_checkpoint_replays_only_the_tail_and_gives_the_same_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (s, layers, at) = busy_store(&path);
        let want = snapshot(&s, &layers, 9);
        let (stats, names) = (s.stats(), s.names().unwrap());
        drop(s);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.checkpoint, Some(at));
        assert!(
            rec.groups < at,
            "only the groups after the checkpoint were replayed"
        );
        assert_eq!(snapshot(&s, &layers, 9), want);
        assert_eq!(
            (
                s.stats().log_bytes,
                s.stats().garbage_bytes,
                s.stats().records
            ),
            (stats.log_bytes, stats.garbage_bytes, stats.records)
        );
        assert_eq!(s.names().unwrap(), names);
        assert_eq!(s.seals_of(layers[1]).unwrap(), vec![layers[2], layers[4]]);
        drop(s);
        // The same as a full replay.
        std::fs::remove_file(ckpt_path(&path)).unwrap();
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.checkpoint, None);
        assert_eq!(snapshot(&s, &layers, 9), want);
        assert_eq!(s.stats().garbage_bytes, stats.garbage_bytes);
    }

    #[test]
    fn a_damaged_or_foreign_checkpoint_means_a_full_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (s, layers, _) = busy_store(&path);
        let want = snapshot(&s, &layers, 9);
        drop(s);
        let good = std::fs::read(ckpt_path(&path)).unwrap();
        for at in (0..good.len()).step_by(7).chain([good.len() - 1]) {
            let mut bad = good.clone();
            bad[at] ^= 0x10;
            std::fs::write(ckpt_path(&path), &bad).unwrap();
            let (s, rec) = Store::open(&path).unwrap();
            assert_eq!(rec.checkpoint, None, "byte {at} flipped");
            assert_eq!(snapshot(&s, &layers, 9), want, "byte {at} flipped");
        }
        std::fs::write(ckpt_path(&path), &good[..good.len() / 2]).unwrap();
        assert_eq!(Store::open(&path).unwrap().1.checkpoint, None, "truncated");

        // Another log's checkpoint, laid next to this one.
        let other = dir.path().join("other");
        let mut o = Store::create(&other).unwrap();
        let r = o.root_seal().unwrap();
        let x = o.fork(r).unwrap();
        o.write(x, 0, &blocks(9, 1), false).unwrap();
        o.checkpoint().unwrap();
        drop(o);
        std::fs::copy(ckpt_path(&other), ckpt_path(&path)).unwrap();
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.checkpoint, None, "not this log's");
        assert_eq!(snapshot(&s, &layers, 9), want);

        // A new log under a used name does not inherit the old checkpoint.
        drop(s);
        std::fs::remove_file(&other).unwrap();
        assert!(ckpt_path(&other).exists());
        drop(Store::create(&other).unwrap());
        assert!(!ckpt_path(&other).exists());
    }

    #[test]
    fn a_name_after_the_last_flush_is_cut_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let a;
        {
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            a = s.fork(root).unwrap();
            s.name(a, "kept").unwrap();
            s.flush().unwrap();
            s.name(a, "lost").unwrap();
        }
        let (s, rec) = Store::open(&path).unwrap();
        assert!(rec.cut > 0);
        assert_eq!(
            (s.find("kept").unwrap(), s.find("lost").unwrap()),
            (Some(a), None)
        );
    }

    /// A log of two groups on one branch; returns the branch.
    fn two_groups(path: &Path) -> LayerId {
        let mut s = Store::create(path).unwrap();
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        s.write(b, 0, &blocks(1, 1), false).unwrap();
        s.flush().unwrap();
        s.write(b, 1, &blocks(2, 1), false).unwrap();
        s.flush().unwrap();
        b
    }

    #[test]
    fn a_record_of_an_unknown_kind_refuses_the_open_and_cuts_nothing() {
        // Maturity review of e4a37b2, finding 2: a kind a newer version
        // wrote read as the end of the log, and every later group was cut.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let at;
        {
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            let b = s.fork(root).unwrap();
            s.write(b, 0, &blocks(1, 1), false).unwrap();
            s.flush().unwrap();
            at = s.stats().log_bytes;
            s.append(K_LAST + 1, b"from a newer version").unwrap();
            s.write(b, 1, &blocks(2, 1), false).unwrap();
            s.flush().unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        match Store::open(&path) {
            Err(StoreError::UnknownKind { kind, at: found }) => {
                assert_eq!((kind, found), (K_LAST + 1, at));
            }
            other => panic!("opened or refused otherwise: {:?}", other.map(|(_, r)| r)),
        }
        assert_eq!(std::fs::read(&path).unwrap(), before, "nothing was cut");
    }

    #[test]
    fn a_header_that_does_not_check_out_is_refused_and_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        two_groups(&path);
        let good = std::fs::read(&path).unwrap();
        let try_with = |header: &[u8]| {
            let mut b = good.clone();
            b[..header.len()].copy_from_slice(header);
            std::fs::write(&path, &b).unwrap();
            let r = Store::open(&path).map(|(_, r)| r);
            assert_eq!(std::fs::read(&path).unwrap(), b, "refused, not changed");
            r
        };
        // One bit of the identity flipped: the checksum catches it.
        let mut h = good[..HEADER_LEN as usize].to_vec();
        h[20] ^= 1;
        assert!(matches!(try_with(&h), Err(StoreError::DamagedHeader)));
        // A newer version's log, and one with a flag this version does not
        // know: both with a good checksum.
        let resum = |h: &mut Vec<u8>| {
            let sum = blake3::hash(&h[..48]);
            h[48..64].copy_from_slice(&sum.as_bytes()[..16]);
        };
        let mut h = good[..HEADER_LEN as usize].to_vec();
        h[8..12].copy_from_slice(&(FORMAT_VERSION + 1).to_le_bytes());
        resum(&mut h);
        assert!(matches!(
            try_with(&h),
            Err(StoreError::NewerFormat { version, flags: 0 }) if version == FORMAT_VERSION + 1
        ));
        let mut h = good[..HEADER_LEN as usize].to_vec();
        h[12..16].copy_from_slice(&2u32.to_le_bytes());
        resum(&mut h);
        assert!(matches!(
            try_with(&h),
            Err(StoreError::NewerFormat { flags: 2, .. })
        ));
        // The magic alone, cut short of a header.
        std::fs::write(&path, &good[..40]).unwrap();
        assert!(matches!(Store::open(&path), Err(StoreError::NotALog)));
        // And the log as it was opens.
        std::fs::write(&path, &good).unwrap();
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!((rec.groups, rec.cut), (3, 0)); // the root Seal's group and the two written
        assert_eq!(rec.id, s.id());
    }

    #[test]
    fn a_log_has_its_own_identity_and_its_records_verify_in_no_other() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        two_groups(&a);
        two_groups(&b);
        let (ida, idb) = (Store::open(&a).unwrap().1.id, Store::open(&b).unwrap().1.id);
        assert_ne!(ida, idb, "two logs, two identities");
        assert_eq!(Store::open(&a).unwrap().1.id, ida, "kept across opens");
        // The same operations made the same records but for the chain,
        // which starts from each log's header: a's records under b's
        // header are no records of b's.
        let (bytes_a, bytes_b) = (std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        assert_eq!(bytes_a.len(), bytes_b.len());
        let mut mixed = bytes_b[..HEADER_LEN as usize].to_vec();
        mixed.extend_from_slice(&bytes_a[HEADER_LEN as usize..]);
        std::fs::write(&b, &mixed).unwrap();
        let (_, rec) = Store::open(&b).unwrap();
        assert_eq!((rec.id, rec.records, rec.groups), (idb, 0, 0));
        assert_eq!(rec.cut, data_len(&mixed, HEADER_LEN) - HEADER_LEN);
    }

    #[test]
    fn a_checkpoint_of_another_log_is_not_used() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        for p in [&a, &b] {
            two_groups(p);
            let (mut s, _) = Store::open(p).unwrap();
            s.checkpoint().unwrap();
        }
        assert!(
            Store::open(&b).unwrap().1.checkpoint.is_some(),
            "its own is used"
        );
        std::fs::copy(ckpt_path(&a), ckpt_path(&b)).unwrap();
        let (s, rec) = Store::open(&b).unwrap();
        assert_eq!(rec.checkpoint, None, "a full replay");
        assert_eq!(s.map().unwrap().log_locs().len(), 2);
    }

    /// The durable end named by the Flush record that ends at `end`.
    fn claim_at(s: &Store, end: u64) -> u64 {
        let at = end - FLUSH_LEN;
        let mut rec = vec![0u8; FLUSH_LEN as usize];
        s.file.read_exact_at(&mut rec, at).unwrap();
        assert_eq!(rec[8], K_FLUSH, "a Flush record ends at {end}");
        let body = &rec[REC_HEAD as usize..REC_HEAD as usize + FLUSH_BODY];
        flush_claim(&s.flush_mac, body, at).expect("its body checks out")
    }

    #[test]
    fn a_flush_record_names_what_was_durable_before_it_never_its_own_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        // A new log has synced nothing: its first Flush claims nothing.
        let root = s.root_seal().unwrap();
        let e0 = s.stats().log_bytes;
        assert_eq!(claim_at(&s, e0), 0);
        // `flush` synced that group, so the next Flush names its end.
        let b = s.fork(root).unwrap();
        s.write(b, 0, &blocks(1, 1), false).unwrap();
        s.flush().unwrap();
        let e1 = s.stats().log_bytes;
        assert_eq!(claim_at(&s, e1), e0);
        // Two groups ended and not synced: neither is named, by either.
        let syncer = s.syncer().unwrap();
        s.write(b, 1, &blocks(2, 1), false).unwrap();
        let l2 = s.flush_pending().unwrap();
        let e2 = s.stats().log_bytes;
        s.write(b, 2, &blocks(3, 1), false).unwrap();
        let l3 = s.flush_pending().unwrap();
        let e3 = s.stats().log_bytes;
        assert_eq!((claim_at(&s, e2), claim_at(&s, e3)), (e1, e1));
        // The Syncer's sync for the first of them returns: the next Flush
        // names that one's end, not the second's.
        assert!(syncer.durable(l2).unwrap());
        s.write(b, 3, &blocks(4, 1), false).unwrap();
        let l4 = s.flush_pending().unwrap();
        let e4 = s.stats().log_bytes;
        assert_eq!(claim_at(&s, e4), e2);
        // A sync for the newest covers the one between as well.
        assert!(l3 < l4);
        syncer.durable(l4).unwrap();
        s.flush_pending().unwrap();
        assert_eq!(claim_at(&s, s.stats().log_bytes), e4);
        // Opened again, the store has synced nothing itself: 0 again.
        drop(s);
        let (mut s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.cut, 0);
        s.flush_pending().unwrap();
        assert_eq!(claim_at(&s, s.stats().log_bytes), 0);
    }

    #[test]
    fn a_flush_record_whose_body_does_not_check_out_fails_the_replay() {
        let dir = tempfile::tempdir().unwrap();
        // Its own offset wrong, another log's key, and the empty body of
        // the formats before this one.
        for case in 0..3 {
            let path = dir.path().join(format!("log{case}"));
            let mut s = Store::create(&path).unwrap();
            s.root_seal().unwrap();
            let at = s.stats().log_bytes;
            let body = match case {
                0 => flush_body(&s.flush_mac, at + 1, 0).to_vec(),
                1 => flush_body(&[7; 32], at, 0).to_vec(),
                _ => Vec::new(),
            };
            s.append(K_FLUSH, &body).unwrap();
            drop(s);
            assert!(
                matches!(
                    Store::open(&path),
                    Err(StoreError::ReplayMeta {
                        reason: "a Flush record whose body does not check out",
                        ..
                    })
                ),
                "case {case}"
            );
        }
    }

    #[test]
    fn a_compaction_gives_every_flush_its_place_in_the_new_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let b = two_groups(&path);
        let (mut s, _) = Store::open(&path).unwrap();
        compact(&mut s);
        // What the next Flush says is durable is the new log, whole.
        let whole_log = s.stats().log_bytes;
        s.write(b, 2, &blocks(3, 1), false).unwrap();
        s.flush_pending().unwrap();
        assert_eq!(claim_at(&s, s.stats().log_bytes), whole_log);
        drop(s);
        // Without its checkpoint the new log is replayed from its header,
        // which checks every Flush's body at its offset.
        std::fs::remove_file(ckpt_path(&path)).unwrap();
        let (_, rec) = Store::open(&path).unwrap();
        assert_eq!((rec.checkpoint, rec.cut), (None, 0));
    }

    /// A log of four groups on one branch, each synced by `flush`, and
    /// the end offset of each (the root Seal's group first).
    fn four_synced_groups(path: &Path) -> (LayerId, Vec<u64>) {
        let mut s = Store::create(path).unwrap();
        let root = s.root_seal().unwrap();
        let mut ends = vec![s.stats().log_bytes];
        let b = s.fork(root).unwrap();
        for i in 0..4u8 {
            s.write(b, i as u64, &blocks(i + 1, 1), false).unwrap();
            s.flush().unwrap();
            ends.push(s.stats().log_bytes);
        }
        (b, ends)
    }

    fn flip(path: &Path, at: u64) {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let mut b = [0u8; 1];
        f.read_exact_at(&mut b, at).unwrap();
        f.write_all_at(&[b[0] ^ 0x40], at).unwrap();
    }

    #[test]
    fn damage_below_a_later_flushs_durable_end_is_set_aside_not_cut() {
        // Maturity review of e4a37b2, finding 1: one flipped bit early in
        // the log made the next open cut every later group and serve.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (b, ends) = four_synced_groups(&path);
        let whole_log = std::fs::read(&path).unwrap();
        // A bit in the second written group's block: the groups after it
        // were synced, and their Flush records say so.
        let at = ends[1] + REC_HEAD + 100;
        flip(&path, at);
        let damaged = std::fs::read(&path).unwrap();
        let (s, rec) = Store::open(&path).unwrap();
        let aside = rec.set_aside.clone().expect("damage, not a torn tail");
        assert_eq!(rec.cut, 0, "nothing was cut as a tail");
        assert_eq!(
            (aside.at, aside.from, aside.bytes),
            (ends[1], ends[1], ends[4] - ends[1]),
            "from the last verified Flush to the old end"
        );
        assert!(aside.durable > aside.at, "a later Flush named it durable");
        assert_eq!(
            aside.path,
            dir.path().join(format!("log.damaged-{}", ends[1]))
        );
        // Every byte the log lost is in the file, as it was found.
        assert_eq!(
            std::fs::read(&aside.path).unwrap(),
            damaged[ends[1] as usize..data_len(&damaged, ends[1]) as usize]
        );
        assert_eq!(std::fs::read(&path).unwrap(), whole_log[..ends[1] as usize]);
        assert_eq!(
            std::fs::metadata(&aside.path).unwrap().permissions().mode() & 0o7777,
            PRIVATE
        );
        // What is served is the state at the last verified Flush.
        let mut buf = vec![0u8; B];
        s.read(b, 0, &mut buf).unwrap();
        assert_eq!(buf, blocks(1, 1));
        s.read(b, 1, &mut buf).unwrap();
        assert_eq!(
            buf,
            vec![0u8; B],
            "the damaged group and those after it are not served"
        );
        drop(s);
        // The next open is clean, and leaves the file alone.
        let (_, rec) = Store::open(&path).unwrap();
        assert_eq!((rec.cut, rec.set_aside), (0, None));
        assert_eq!(
            std::fs::read(&aside.path).unwrap(),
            damaged[ends[1] as usize..data_len(&damaged, ends[1]) as usize]
        );
    }

    #[test]
    fn a_torn_tail_with_well_formed_groups_after_it_is_still_cut() {
        // Groups ended and never synced: a crash may leave a later one
        // whole and an earlier one torn.  No Flush names them durable.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        s.write(b, 0, &blocks(1, 1), false).unwrap();
        s.flush().unwrap();
        let synced = s.stats().log_bytes;
        let mut ends = Vec::new();
        for i in 1..4u8 {
            s.write(b, i as u64, &blocks(i + 1, 1), false).unwrap();
            s.flush_pending().unwrap();
            ends.push(s.stats().log_bytes);
        }
        drop(s);
        flip(&path, ends[0] + REC_HEAD + 100); // in the second of the three
        let len = data_len(&std::fs::read(&path).unwrap(), ends[0]);
        let (_, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.set_aside, None, "no later Flush names it durable");
        assert_eq!(rec.cut, len - ends[0]);
        assert!(ends[0] > synced);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), ends[0]);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            2,
            "the log and its lock"
        );
    }

    #[test]
    fn an_agents_image_of_a_flush_record_does_not_make_a_torn_tail_damage() {
        // A Vessel's agent chooses its blocks' bytes.  Its best forgery: a
        // Flush record's image for the very offset it lands at, naming
        // everything durable, under a key it has to guess.  The control:
        // the same image under the log's own key is believed, so it is the
        // key, and nothing else about the image, that refuses the forgery.
        let dir = tempfile::tempdir().unwrap();
        let run = |name: &str, own_key: bool| {
            let path = dir.path().join(name);
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            let b = s.fork(root).unwrap();
            s.write(b, 0, &blocks(1, 1), false).unwrap();
            s.flush().unwrap();
            let first = s.stats().log_bytes;
            s.write(b, 1, &blocks(2, 1), false).unwrap();
            s.flush_pending().unwrap();
            let torn_at = s.stats().log_bytes - FLUSH_LEN - 50;
            s.write(b, 2, &blocks(0, 1), false).unwrap();
            let data_at = match s.map().unwrap().read(b, 2).unwrap() {
                Some(Loc::Log(off)) => off,
                other => panic!("{other:?}"),
            };
            // The image, written where the block's data lies.
            let key = if own_key { s.flush_mac } else { [0u8; 32] };
            let mut img = Vec::new();
            img.extend_from_slice(&REC_MAGIC.to_le_bytes());
            img.extend_from_slice(&(FLUSH_BODY as u32).to_le_bytes());
            img.push(K_FLUSH);
            img.extend_from_slice(&flush_body(&key, data_at, u64::MAX));
            s.file.write_all_at(&img, data_at).unwrap();
            drop(s);
            flip(&path, torn_at);
            let len = data_len(&std::fs::read(&path).unwrap(), first);
            let (_, rec) = Store::open(&path).unwrap();
            (rec, len - first)
        };
        let (rec, tail) = run("forged", false);
        assert_eq!((rec.set_aside, rec.cut), (None, tail), "a torn tail, cut");
        let (rec, tail) = run("control", true);
        let aside = rec
            .set_aside
            .expect("under the log's key the image is a Flush");
        assert_eq!((aside.durable, aside.bytes, rec.cut), (u64::MAX, tail, 0));
    }

    #[test]
    fn damage_that_cannot_be_set_aside_refuses_the_open_and_leaves_the_log_whole() {
        // No file can be made beside this log for its damaged part: with
        // ".damaged-" and a five-digit offset the name is one byte longer
        // than a name may be, while every other name the store makes
        // beside the log still fits.  (Root is refused that too, and the
        // gates run as root.)
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("l".repeat(242));
        let mut s = Store::create(&path).unwrap();
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        let mut ends = Vec::new();
        for i in 0..6u8 {
            s.write(b, i as u64, &blocks(i + 1, 1), false).unwrap();
            s.flush().unwrap();
            ends.push(s.stats().log_bytes);
        }
        drop(s);
        assert!(ends[3] >= 10_000, "a five-digit offset: {}", ends[3]);
        flip(&path, ends[3] + REC_HEAD + 100);
        let damaged = std::fs::read(&path).unwrap();
        match Store::open(&path).map(|(_, r)| r) {
            Err(StoreError::SetAside { need, .. }) => assert_eq!(need, ends[5] - ends[3]),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            std::fs::read(&path).unwrap(),
            damaged,
            "the only copy is not dropped"
        );
        // And again: refused the same way, not cut on a second try.
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::SetAside { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), damaged);
    }

    #[test]
    fn a_part_set_aside_earlier_is_never_written_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (_, ends) = four_synced_groups(&path);
        flip(&path, ends[1] + REC_HEAD + 100);
        let name = |n: &str| dir.path().join(format!("log.damaged-{}{n}", ends[1]));
        // An earlier damage that began at the same offset left its part.
        std::fs::write(name(""), b"an earlier part").unwrap();
        let (_, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.set_aside.unwrap().path, name(".1"));
        assert_eq!(std::fs::read(name("")).unwrap(), b"an earlier part");
    }

    #[test]
    fn a_log_in_the_spike_format_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old");
        // Each older format, with the 16-byte header those had.
        for old in OLD_MAGICS {
            let mut header = [0u8; 16];
            header[..8].copy_from_slice(old);
            std::fs::write(&path, header).unwrap();
            assert!(
                matches!(Store::open(&path), Err(StoreError::OldFormat)),
                "{old:?}"
            );
            assert_eq!(
                std::fs::read(&path).unwrap(),
                header,
                "refused, not changed"
            );
        }
    }

    #[test]
    fn verified_name_records_that_do_not_replay_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        let root = s.root_seal().unwrap();
        let (a, b) = (s.fork(root).unwrap(), s.fork(root).unwrap());
        s.name(a, "x").unwrap();
        let mut body = b.get().to_le_bytes().to_vec();
        body.extend_from_slice(b"x"); // a second branch with the same name
        s.append(K_NAME, &body).unwrap();
        s.flush_pending().unwrap();
        drop(s);
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::ReplayMeta {
                reason: "name taken by another branch",
                ..
            })
        ));
    }

    #[test]
    fn garbage_is_counted_for_overwrites_discards_and_drops() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_store(&dir);
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        s.write(b, 0, &blocks(1, 2), false).unwrap();
        s.write(b, 0, &blocks(2, 1), false).unwrap(); // 1 block freed
        s.discard(b, 1, 1).unwrap(); // 1 block freed
        s.write(b, 5, &blocks(3, 1), false).unwrap();
        s.drop_branch(b).unwrap(); // blocks 0 and 5 freed
        assert_eq!(s.stats().garbage_bytes, 4 * BLOCK);
        s.drop_seal(root).unwrap();
        assert_eq!(s.map().unwrap().layers(), 0);
    }

    // ── crash injection ─────────────────────────────────────────────
    //
    // Run a sequence of operations, remembering after every flush what
    // each live layer reads.  Then cut the log at every byte boundary
    // and reopen: the store must be exactly at the last flush the cut
    // still contains, never in between.

    /// What every live layer reads, per block, after a flush.
    /// Per live layer: its blocks, and its name, tag and origin.
    type Snapshot = BTreeMap<LayerId, (Vec<u8>, String)>;

    fn snapshot(s: &Store, layers: &[LayerId], span: u64) -> Snapshot {
        layers
            .iter()
            .filter(|l| s.map().unwrap().kind(**l).is_ok())
            .map(|l| {
                let meta = format!(
                    "{:?} {:?} {:?}",
                    s.name_of(*l).unwrap(),
                    s.tag(*l).unwrap(),
                    s.origin(*l).unwrap()
                );
                (*l, ((0..span).map(|b| read1(s, *l, b)).collect(), meta))
            })
            .collect()
    }

    #[derive(Clone, Debug)]
    enum Op {
        Write(usize, u64, u8, u8, bool),
        Discard(usize, u64, u64),
        Fork(usize),
        Seal(usize, u8),
        Name(usize, u8),
        Reset(usize),
        Checkpoint,
        Flush,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            6 => (0usize..6, 0u64..6, 1u8..4, 1u8..255, any::<bool>()).prop_map(|(i, b, n, v, f)| Op::Write(i, b, n, v, f)),
            1 => (0usize..6, 0u64..6, 0u64..3).prop_map(|(i, b, n)| Op::Discard(i, b, n)),
            1 => (0usize..6).prop_map(Op::Fork),
            1 => (0usize..6, 0u8..3).prop_map(|(i, t)| Op::Seal(i, t)),
            1 => (0usize..6, 0u8..3).prop_map(|(i, n)| Op::Name(i, n)),
            1 => (0usize..6).prop_map(Op::Reset),
            2 => Just(Op::Flush),
            1 => Just(Op::Checkpoint),
        ]
    }

    /// Apply one op to the layers made so far; true if it ended at a
    /// durable point.
    fn apply(s: &mut Store, layers: &mut Vec<LayerId>, o: &Op) -> bool {
        let pick = |i: usize| layers[i % layers.len()];
        match *o {
            Op::Write(i, b, n, v, fua) => {
                s.write(pick(i), b, &blocks(v, n as usize), fua).is_ok() && fua
            }
            Op::Discard(i, b, n) => {
                let _ = s.discard(pick(i), b, n);
                false
            }
            Op::Fork(i) => {
                if let Ok(l) = s.fork(pick(i)) {
                    layers.push(l);
                }
                false
            }
            Op::Reset(i) => {
                let _ = s.reset(pick(i));
                false
            }
            Op::Name(i, n) => {
                let name = if n == 0 {
                    String::new()
                } else {
                    format!("n{n}")
                };
                let _ = s.name(pick(i), &name);
                false
            }
            Op::Seal(i, t) => match s.seal_tagged(pick(i), &vec![t; t as usize]) {
                Ok(l) => {
                    layers.push(l);
                    true
                }
                Err(_) => false,
            },
            Op::Flush => s.flush().is_ok(),
            Op::Checkpoint => s.checkpoint().is_ok(),
        }
    }

    /// Apply `ops`; return the layers made and a snapshot at every durable
    /// point: (log length at that point, snapshot).
    fn run(s: &mut Store, ops: &[Op]) -> (Vec<LayerId>, Vec<(u64, Snapshot)>) {
        // Before the root Seal is durable, a recovered log holds no layers.
        let mut points = vec![(HEADER_LEN, Snapshot::new())];
        let root = s.root_seal().unwrap();
        let mut layers = vec![root];
        points.push((s.stats().log_bytes, snapshot(s, &layers, 9)));
        for o in ops {
            if apply(s, &mut layers, o) {
                points.push((s.stats().log_bytes, snapshot(s, &layers, 9)));
            }
        }
        (layers, points)
    }

    fn check_cuts(
        path: &Path,
        layers: &[LayerId],
        points: &[(u64, Snapshot)],
        cuts: impl Iterator<Item = u64>,
    ) {
        let full = std::fs::read(path).unwrap();
        let cut_path = path.with_extension("cut");
        let ckpt = std::fs::read(ckpt_path(path)).ok();
        for len in cuts {
            // With the log's checkpoint (if any), then without: the same.
            for with_ckpt in [true, false] {
                std::fs::write(&cut_path, &full[..len as usize]).unwrap();
                match (&ckpt, with_ckpt) {
                    (Some(c), true) => std::fs::write(ckpt_path(&cut_path), c).unwrap(),
                    _ => {
                        let _ = std::fs::remove_file(ckpt_path(&cut_path));
                    }
                }
                let (s, rec) = Store::open(&cut_path).unwrap();
                let (want_len, want) = points
                    .iter()
                    .rev()
                    .find(|(l, _)| *l <= len)
                    .expect("the header is durable");
                assert_eq!(
                    s.stats().log_bytes,
                    *want_len,
                    "cut at {len}, checkpoint {with_ckpt}"
                );
                assert_eq!(
                    rec.cut,
                    data_len(&full[..len as usize], *want_len) - want_len
                );
                assert_eq!(
                    &snapshot(&s, layers, 9),
                    want,
                    "cut at {len}, checkpoint {with_ckpt}: state must be the last flush"
                );
                if !with_ckpt {
                    assert_eq!(rec.checkpoint, None);
                } else if let Some(c) = &ckpt {
                    // A cut that keeps the checkpoint's Flush must start from it.
                    // (After the checkpoint's magic and the log's id.)
                    let end = u64::from_le_bytes(c[24..32].try_into().unwrap());
                    assert_eq!(
                        rec.checkpoint.is_some(),
                        len >= end,
                        "cut at {len}, checkpoint ends at {end}"
                    );
                }
            }
        }
        let _ = std::fs::remove_file(&cut_path);
        let _ = std::fs::remove_file(ckpt_path(&cut_path));
    }

    #[test]
    fn every_cut_of_a_log_recovers_to_the_last_flush_in_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        let ops = [
            Op::Fork(0),
            Op::Write(1, 0, 1, 10, false),
            Op::Write(1, 1, 2, 11, false),
            Op::Flush,
            Op::Name(1, 1),
            Op::Write(1, 0, 1, 12, false),
            Op::Discard(1, 1, 1),
            Op::Seal(1, 2),
            Op::Fork(2),
            Op::Name(3, 2),
            Op::Write(3, 2, 1, 13, false),
            Op::Write(1, 2, 1, 14, true),
            Op::Reset(3),
            Op::Name(1, 0),
            Op::Checkpoint,
            Op::Write(3, 0, 1, 15, false),
        ];
        let (layers, points) = run(&mut s, &ops);
        drop(s);
        assert!(points.len() >= 4, "several durable points");
        // Every byte from the second-to-last durable point to the end (the
        // last groups and the tail), and every byte around each durable
        // point before that.  A cut elsewhere inside block data is the
        // same case as its neighbours: an incomplete record.  In the
        // reserve's zeros after the records, every 97th byte and the end:
        // each is the same case, a whole reserve or a part of one.
        let len = std::fs::metadata(&path).unwrap().len();
        let data = data_len(&std::fs::read(&path).unwrap(), HEADER_LEN);
        let tail_from = points[points.len() - 2].0;
        let mut cuts: Vec<u64> = (tail_from..=data).collect();
        cuts.extend((data..len).step_by(97));
        cuts.push(len);
        for (at, _) in &points {
            cuts.extend(at.saturating_sub(2).max(HEADER_LEN)..=(at + 2).min(len));
        }
        cuts.extend((HEADER_LEN..tail_from).step_by(97));
        cuts.sort_unstable();
        cuts.dedup();
        check_cuts(&path, &layers, &points, cuts.into_iter());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn a_crash_anywhere_recovers_to_the_last_flush(ops in proptest::collection::vec(op(), 1..25), at in any::<prop::sample::Index>()) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("log");
            let mut s = Store::create(&path).unwrap();
            let (layers, points) = run(&mut s, &ops);
            drop(s);
            let len = std::fs::metadata(&path).unwrap().len();
            let cut = HEADER_LEN + at.index((len - HEADER_LEN + 1) as usize) as u64;
            check_cuts(&path, &layers, &points, [cut, len].into_iter());
        }
    }

    // ── Compaction ──────────────────────────────────────────────────

    /// What a caller can see of a store, for before/after checks (not the
    /// sequence number: a compaction's own flushes move it on).
    type Whole = (Snapshot, Vec<(String, LayerId)>, Vec<Vec<LayerId>>, usize);

    fn whole(s: &Store, layers: &[LayerId]) -> Whole {
        let seals = layers.iter().map(|l| s.seals_of(*l).unwrap()).collect();
        (
            snapshot(s, layers, 9),
            s.names().unwrap(),
            seals,
            s.map().unwrap().layers(),
        )
    }

    fn compact(s: &mut Store) -> Compacted {
        let mut c = s.compaction().unwrap();
        c.copy().unwrap();
        c.finish(s).unwrap()
    }

    /// taso-blkd makes its Syncer once, at start.  A compaction's switch
    /// replaces the store with the new log; before this the Syncer kept the
    /// old, renamed-away file, so every group commit after a compaction
    /// synced a file no one would read again and nothing acknowledged after
    /// it was made durable by its sync (found on the layout branch, P5 L2,
    /// 2026-10-30; on main since the Syncer, lever 1).
    #[test]
    fn a_syncer_made_before_a_compaction_syncs_the_new_log() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (mut s, layers, _) = busy_store(&path);
        let syncer = s.syncer().unwrap();
        let old_ino = std::fs::metadata(&path).unwrap().ino();
        assert_eq!(syncer.log_ino().unwrap(), old_ino);
        compact(&mut s);
        let new_ino = std::fs::metadata(&path).unwrap().ino();
        assert_ne!(new_ino, old_ino, "the compaction made a new file");
        assert_eq!(
            syncer.log_ino().unwrap(),
            new_ino,
            "the Syncer syncs the new log"
        );
        // And a group ended after the switch is made durable by it.
        let b = layers[3];
        s.write(b, 7, &blocks(66, 1), false).unwrap();
        let lsn = s.flush_pending().unwrap();
        syncer.durable(lsn).unwrap();
        drop(s);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!((rec.cut, read1(&s, b, 7)), (0, 66));
    }

    /// Bite 4 (the flush join design of 2026-11-03, f-a): a
    /// device's flush appends a Flush record only when its branch has
    /// records past the last group; otherwise it waits for that group.
    /// And a crash right after a joined flush keeps what it acknowledged:
    /// the data lies in the group another branch closed.
    #[test]
    fn a_device_flush_joins_the_group_another_branch_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        let root = s.root_seal().unwrap();
        let (a, b) = (s.fork(root).unwrap(), s.fork(root).unwrap());
        let syncer = s.syncer().unwrap();
        let records0 = s.stats().records;
        // B writes, A writes, A flushes: A's Flush closes the group that
        // holds B's write too.
        s.write(b, 3, &blocks(0xb3, 1), false).unwrap();
        s.write(a, 5, &blocks(0xa5, 1), false).unwrap();
        let (lsn_a, appended) = s.flush_for(a).unwrap();
        assert!(
            appended,
            "A has records past the last group: a Flush record"
        );
        syncer.durable(lsn_a).unwrap();
        // B's flush: its write is in A's group.  Nothing appended, the
        // same lsn to wait for, and it is durable already.
        let records1 = s.stats().records;
        let (lsn_b, appended) = s.flush_for(b).unwrap();
        assert!(!appended, "B's data is in a closed group: no record");
        assert_eq!((lsn_b, s.stats().records), (lsn_a, records1));
        assert!(!syncer.durable(lsn_b).unwrap(), "no sync of its own");
        assert_eq!(s.stats().flushes_joined, 1);
        // B's second barrier (nothing written since): joins again.
        assert!(!s.flush_for(b).unwrap().1);
        assert_eq!(s.stats().flushes_joined, 2);
        // Rev. 2: a joiner waits for the first group over its data, not
        // the newest.  A later group (A writes and flushes again, its sync
        // still to come) leaves B's wait at lsn_a, durable already.
        s.write(a, 6, &blocks(0xa6, 1), false).unwrap();
        let (lsn_a2, _) = s.flush_for(a).unwrap();
        assert!(lsn_a2 > lsn_a);
        let (lsn_b3, appended) = s.flush_for(b).unwrap();
        assert!(!appended);
        assert_eq!(
            lsn_b3, lsn_a,
            "the first group over B's write, not the newest"
        );
        assert!(!syncer.durable(lsn_b3).unwrap(), "durable already: no wait");
        syncer.durable(lsn_a2).unwrap();
        // B writes again: its next flush appends, as before.
        s.write(b, 4, &blocks(0xb4, 1), false).unwrap();
        let (lsn_b2, appended) = s.flush_for(b).unwrap();
        assert!(appended && lsn_b2 > lsn_a);
        syncer.durable(lsn_b2).unwrap();
        assert!(s.stats().records > records0 + 4, "two Flush records in all");
        // The crash: everything acknowledged is in the log's groups.
        drop(s);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.cut, 0);
        assert_eq!(
            (read1(&s, b, 3), read1(&s, a, 5), read1(&s, b, 4)),
            (0xb3, 0xa5, 0xb4)
        );
        // After an open everything is grouped: any branch's flush joins.
        let mut s = s;
        assert!(!s.flush_for(a).unwrap().1);
    }

    /// The crash the rule must not make worse: a joined flush acknowledged
    /// while the group's sync was still to come.  The owner of the group
    /// asked for the sync; the joiner waits on the same lsn, so nothing
    /// is acknowledged before the group is on the medium.
    #[test]
    fn a_joined_flush_waits_for_the_groups_sync() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        let root = s.root_seal().unwrap();
        let (a, b) = (s.fork(root).unwrap(), s.fork(root).unwrap());
        let syncer = s.syncer().unwrap();
        s.write(b, 3, &blocks(0xb3, 1), false).unwrap();
        s.write(a, 5, &blocks(0xa5, 1), false).unwrap();
        let (lsn_a, _) = s.flush_for(a).unwrap();
        // B joins before A's sync has run: its wait runs the sync.
        let (lsn_b, appended) = s.flush_for(b).unwrap();
        assert!(!appended && lsn_b == lsn_a);
        assert!(
            syncer.durable(lsn_b).unwrap(),
            "the joiner ran the group's sync"
        );
        assert!(!syncer.durable(lsn_a).unwrap(), "A finds it durable");
    }

    #[test]
    fn a_compaction_keeps_everything_and_drops_the_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (mut s, layers, _) = busy_store(&path);
        // Garbage: the same blocks of `a` overwritten many times, and a
        // branch written and dropped.
        for v in 0..50u8 {
            s.write(layers[1], 0, &blocks(v + 10, 3), false).unwrap();
        }
        let d = s.fork(layers[4]).unwrap();
        s.write(d, 0, &blocks(9, 8), false).unwrap();
        s.drop_branch(d).unwrap();
        s.flush().unwrap();
        let want = whole(&s, &layers);
        let before = s.stats();
        assert!(before.garbage_bytes >= 150 * BLOCK);

        let done = compact(&mut s);
        assert_eq!(
            whole(&s, &layers),
            want,
            "the same store, seen from outside"
        );
        assert_eq!(
            done.before,
            before.log_bytes + 2 * FLUSH_LEN,
            "the old log and the two flushes of the compaction"
        );
        assert_eq!(done.after, s.stats().log_bytes);
        assert!(done.checkpoint);
        assert_eq!(s.stats().garbage_bytes, 0);
        assert!(done.after < before.log_bytes / 4, "{done:?}");
        // Live: a has 3 (0..3) + 7; b has 6; the Seals 1 and 3 blocks.
        assert_eq!(done.live, s.map().unwrap().log_locs().len() as u64 * BLOCK);
        let header: [u8; HEADER_LEN as usize] = std::fs::read(&path).unwrap()
            [..HEADER_LEN as usize]
            .try_into()
            .unwrap();
        assert!(Header::decode(&header).unwrap().is_compacted());
        assert!(!compact::temp_path(&path).exists());

        // It goes on as a store, and opens as one: from its checkpoint,
        // and by a full replay of the base.
        s.write(layers[3], 8, &blocks(77, 1), false).unwrap();
        s.flush().unwrap();
        let want = whole(&s, &layers);
        let garbage = s.stats().garbage_bytes;
        drop(s);
        let (s, rec) = Store::open(&path).unwrap();
        assert!(rec.checkpoint.is_some());
        assert_eq!(
            (whole(&s, &layers), s.stats().garbage_bytes),
            (want.clone(), garbage)
        );
        drop(s);
        std::fs::remove_file(ckpt_path(&path)).unwrap();
        let (mut s, rec) = Store::open(&path).unwrap();
        assert_eq!((rec.checkpoint, rec.cut), (None, 0));
        assert_eq!(
            (whole(&s, &layers), s.stats().garbage_bytes),
            (want.clone(), garbage)
        );
        // And it compacts again.
        compact(&mut s);
        assert_eq!(whole(&s, &layers), want);
    }

    #[test]
    fn what_comes_in_during_a_compaction_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (mut s, mut layers, _) = busy_store(&path);
        let a = layers[1];
        let mut c = s.compaction().unwrap();
        // Before the copy, between copy and catch-up, and after it (not
        // flushed: finish flushes).
        s.write(a, 1, &blocks(40, 2), false).unwrap();
        c.copy().unwrap();
        let seal = s.seal_tagged(a, b"three").unwrap();
        let e = s.fork(seal).unwrap();
        s.name(e, "tank/e").unwrap();
        s.write(e, 3, &blocks(41, 1), false).unwrap();
        s.drop_seal(layers[4]).unwrap_err(); // has children: refused, appends nothing
        assert!(c.catch_up().unwrap() > 0);
        s.write(e, 4, &blocks(42, 1), false).unwrap();
        s.discard(a, 0, 1).unwrap();
        layers.extend([seal, e]);
        let want = whole(&s, &layers);
        let done = c.finish(&mut s).unwrap();
        assert!(done.records > 0);
        assert_eq!(whole(&s, &layers), want);
        assert_eq!(s.tag(seal).unwrap(), Some(&b"three"[..]));
        assert_eq!(s.find("tank/e").unwrap(), Some(e));
        drop(s);
        let (s, _) = Store::open(&path).unwrap();
        assert_eq!(
            whole(&s, &layers),
            want,
            "the writes finish flushed are durable"
        );
    }

    #[test]
    fn an_unfinished_compaction_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (mut s, layers, _) = busy_store(&path);
        let temp = compact::temp_path(&path);
        let mut c = s.compaction().unwrap();
        c.copy().unwrap();
        assert!(temp.exists());
        drop(c);
        assert!(!temp.exists(), "dropped: its file is removed");
        s.write(layers[1], 2, &blocks(50, 1), false).unwrap();
        s.flush().unwrap();
        let want = whole(&s, &layers);
        let header: [u8; HEADER_LEN as usize] = std::fs::read(&path).unwrap()
            [..HEADER_LEN as usize]
            .try_into()
            .unwrap();
        assert!(!Header::decode(&header).unwrap().is_compacted());
        drop(s);

        // A crash during a compaction leaves its file beside the log.
        std::fs::write(&temp, b"half a compaction").unwrap();
        std::fs::write(ckpt_path(&temp), b"its checkpoint").unwrap();
        let (s, _) = Store::open(&path).unwrap();
        assert!(
            !temp.exists() && !ckpt_path(&temp).exists(),
            "open removes what an unfinished compaction left"
        );
        assert_eq!(whole(&s, &layers), want);
    }

    #[test]
    fn a_crash_between_the_two_renames_means_a_full_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (mut s, layers, _) = busy_store(&path);
        s.checkpoint().unwrap();
        let old_ckpt = std::fs::read(ckpt_path(&path)).unwrap();
        compact(&mut s);
        let want = whole(&s, &layers);
        drop(s);
        // As if the log was renamed but its checkpoint was not.
        std::fs::write(ckpt_path(&path), &old_ckpt).unwrap();
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!(
            rec.checkpoint, None,
            "the old log's checkpoint does not check out"
        );
        assert_eq!(whole(&s, &layers), want);
    }

    #[test]
    fn base_records_anywhere_else_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        // In a log that was never compacted.
        let path = dir.path().join("log");
        let (mut s, _, _) = busy_store(&path);
        s.append(K_DATA, &blocks(1, 1)).unwrap();
        s.flush().unwrap();
        drop(s);
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::ReplayMeta { .. })
        ));
        // After a compacted log's first group.
        let path = dir.path().join("log2");
        let (mut s, _, _) = busy_store(&path);
        compact(&mut s);
        s.append(K_BASE, &[0; 8]).unwrap();
        s.flush().unwrap();
        drop(s);
        std::fs::remove_file(ckpt_path(&path)).unwrap();
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::ReplayMeta { .. })
        ));
    }

    #[test]
    fn a_compaction_finishes_only_with_its_own_store() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, _, _) = busy_store(&dir.path().join("log"));
        let (mut other, _, _) = busy_store(&dir.path().join("other"));
        let mut c = s.compaction().unwrap();
        c.copy().unwrap();
        assert!(c.finish(&mut other).is_err());
        assert!(!compact::temp_path(&dir.path().join("log")).exists());
        let mut c = s.compaction().unwrap();
        assert!(c.catch_up().is_err(), "catch_up needs the base first");
        c.copy().unwrap();
        assert!(c.copy().is_err(), "the base is written once");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]
        /// A compaction anywhere in a run of operations, with operations
        /// between its steps: afterwards the store reads the same, opens
        /// the same, and a crash after it recovers to the last flush.
        #[test]
        fn a_compaction_in_the_middle_of_anything_changes_nothing_visible(
            ops in proptest::collection::vec(op(), 4..30),
            split in proptest::collection::vec(any::<prop::sample::Index>(), 3),
            at in any::<prop::sample::Index>(),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("log");
            let mut s = Store::create(&path).unwrap();
            let mut cuts: Vec<usize> = split.iter().map(|i| i.index(ops.len() + 1)).collect();
            cuts.sort_unstable();
            let (before, rest) = ops.split_at(cuts[0]);
            let (mut layers, _) = run(&mut s, before);
            let mut c = s.compaction().unwrap();
            for o in &ops[cuts[0]..cuts[1]] {
                apply(&mut s, &mut layers, o);
            }
            c.copy().unwrap();
            for o in &ops[cuts[1]..cuts[2]] {
                apply(&mut s, &mut layers, o);
            }
            c.catch_up().unwrap();
            let after: Vec<Op> = rest[cuts[2] - cuts[0]..].to_vec();
            let (mid, tail) = after.split_at(after.len() / 2);
            for o in mid {
                apply(&mut s, &mut layers, o);
            }
            let want = whole(&s, &layers);
            c.finish(&mut s).unwrap();
            prop_assert_eq!(whole(&s, &layers), want.clone());
            // A durable point right after the switch (finish flushed), then
            // the rest of the operations; a crash anywhere after the switch
            // recovers to the last flush.
            let mut points = vec![(s.stats().log_bytes, want.0)];
            for o in tail {
                if apply(&mut s, &mut layers, o) {
                    points.push((s.stats().log_bytes, snapshot(&s, &layers, 9)));
                }
            }
            drop(s);
            let len = std::fs::metadata(&path).unwrap().len();
            let from = points[0].0;
            let cut = from + at.index((len - from + 1) as usize) as u64;
            check_cuts(&path, &layers, &points, [cut, len].into_iter());
        }
    }

    /// Timing, not a check: `cargo test --release -p taso-blk --lib
    /// compaction_timing -- --ignored --nocapture`.  1 GiB live and 1 GiB
    /// of garbage in 128 KiB writes, then 64 MiB more during the copy.
    #[test]
    #[ignore]
    fn compaction_timing() {
        use std::time::Instant;
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::create(&dir.path().join("log")).unwrap();
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        let chunk = vec![7u8; 128 << 10];
        let n = (1u64 << 30) / chunk.len() as u64;
        for pass in 0..2 {
            for i in 0..n {
                s.write(b, i * 32, &chunk, false).unwrap();
            }
            s.flush().unwrap();
            eprintln!(
                "pass {pass}: log {} MiB, garbage {} MiB",
                s.stats().log_bytes >> 20,
                s.stats().garbage_bytes >> 20
            );
        }
        let t = Instant::now();
        let mut c = s.compaction().unwrap();
        let begin = t.elapsed();
        for i in 0..512 {
            s.write(b, i * 32, &chunk, false).unwrap();
        }
        let t = Instant::now();
        c.copy().unwrap();
        let copy = t.elapsed();
        let t = Instant::now();
        let caught = c.catch_up().unwrap();
        let catch = t.elapsed();
        for i in 0..8 {
            s.write(b, i * 32, &chunk, false).unwrap();
        }
        let t = Instant::now();
        let done = c.finish(&mut s).unwrap();
        let finish = t.elapsed();
        let t = Instant::now();
        drop(done.old_log);
        eprintln!("closing the old log (store not held) {:?}", t.elapsed());
        let done = (done.before, done.after, done.live, done.records);
        eprintln!("begin (store held) {begin:?}; copy {copy:?}; catch_up {caught} records {catch:?}; finish (store held) {finish:?}");
        eprintln!("{done:?}");
    }

    /// Timing, not a check (the maturity review's finding 7, D&D 7-d,
    /// 2026-11-27): how fast taso-blkd's `export` and `import` move a
    /// large stream, to set how the Warden's time limit for the two calls
    /// grows with the size.  `TASO_IMPORT_MIB` (default 2048) of blocks
    /// in 1 MiB writes, every block's bytes its own, sealed; exported to a
    /// file and synced; imported into a fresh branch; sealed.  The export
    /// and the import are made as taso-blkd makes them (a buffered
    /// writer, then a sync; a 1 MiB buffered reader), with a reserve
    /// thread filling ahead.  The log and the stream are in `TMPDIR`: put
    /// it on the block log's own filesystem.  `cargo test --release -p
    /// taso-blk --lib import_timing -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn import_timing() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};
        let mib: u64 = std::env::var("TASO_IMPORT_MIB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2048);
        let rate = |bytes: u64, t: Duration| (bytes >> 20) as f64 / t.as_secs_f64();
        let dir = tempfile::tempdir().unwrap();
        eprintln!("import_timing: {mib} MiB in {}", dir.path().display());
        let mut s = Store::create(&dir.path().join("log")).unwrap();
        let ended = Arc::new(AtomicBool::new(false));
        let reserve = {
            let (f, ended) = (s.filler(), ended.clone());
            std::thread::spawn(move || {
                while !ended.load(Ordering::SeqCst) {
                    f.fill_ahead().unwrap();
                    f.wait(Duration::from_millis(100));
                }
            })
        };
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        let mut chunk = vec![0u8; 1 << 20];
        let per = chunk.len() as u64 / BLOCK;
        let t = Instant::now();
        for i in 0..mib {
            for (j, block) in chunk.chunks_mut(BLOCK as usize).enumerate() {
                let n = (i * per + j as u64).to_le_bytes();
                for w in block.chunks_mut(8) {
                    w.copy_from_slice(&n);
                }
            }
            s.write(b, i * per, &chunk, false).unwrap();
        }
        let seal = s.seal(b).unwrap();
        let wrote = t.elapsed();
        eprintln!(
            "write  {mib} MiB, sealed, in {wrote:.2?}: {:.0} MiB/s",
            rate(mib << 20, wrote)
        );

        let path = dir.path().join("stream");
        let t = Instant::now();
        let file = std::fs::File::create(&path).unwrap();
        let mut w = io::BufWriter::new(file);
        let blocks = s.export_plan(seal, None).unwrap().write(&mut w).unwrap();
        w.into_inner().unwrap().sync_all().unwrap();
        let exported = t.elapsed();
        let len = std::fs::metadata(&path).unwrap().len();
        eprintln!(
            "export {} MiB stream ({blocks} blocks) in {exported:.2?}: {:.0} MiB/s",
            len >> 20,
            rate(len, exported)
        );

        let b2 = s.fork(root).unwrap();
        let t = Instant::now();
        let file = std::fs::File::open(&path).unwrap();
        let mut r = io::BufReader::with_capacity(1 << 20, file);
        assert_eq!(s.import(b2, &mut r).unwrap(), blocks);
        let imported = t.elapsed();
        eprintln!(
            "import {} MiB stream in {imported:.2?}: {:.0} MiB/s (the store held throughout)",
            len >> 20,
            rate(len, imported)
        );
        let t = Instant::now();
        s.seal(b2).unwrap();
        let sealed = t.elapsed();
        eprintln!("seal   after the import in {sealed:.2?}");
        ended.store(true, Ordering::SeqCst);
        reserve.join().unwrap();
    }

    #[test]
    fn syncer_group_commit_covers_every_group_with_fewer_syncs() {
        // 32 threads each end a group under the lock and ask the syncer
        // for it outside: every ask is answered durable, with at least one
        // sync and never more syncs than asks.  How many asks one sync
        // covers depends on how long a sync takes: where it costs nothing
        // (the test VM's temp directory, 2026-10-29) the asks seldom overlap
        // one and each may run its own; the old bound (fewer than asks)
        // failed there 1 run in 3.  Grouping is measured by the bench's
        // Seals, not here (decided 2026-10-29: (a)).
        let dir = tempfile::tempdir().unwrap();
        let store = Store::create(&dir.path().join("log")).unwrap();
        let sync = std::sync::Arc::new(store.syncer().unwrap());
        let store = std::sync::Arc::new(std::sync::Mutex::new(store));
        let root = store.lock().unwrap().root_seal().unwrap();
        let mut threads = Vec::new();
        for i in 0..32u64 {
            let (store, sync) = (store.clone(), sync.clone());
            threads.push(std::thread::spawn(move || {
                for _ in 0..8 {
                    let lsn = {
                        let mut s = store.lock().unwrap();
                        let b = s.fork(root).unwrap();
                        s.write(b, i, &[i as u8; BLOCK as usize], false).unwrap();
                        s.flush_pending().unwrap()
                    };
                    sync.durable(lsn).unwrap();
                }
            }));
        }
        for t in threads {
            t.join().unwrap();
        }
        let syncs = sync.syncs();
        assert!((1..=256).contains(&syncs), "syncs {syncs}");
        // Each sync's time is counted: the longest within the sum.
        let (total, max) = sync.sync_time();
        assert!(max <= total, "longest {max} us, total {total} us");
        // A later ask for an already durable lsn syncs nothing more.
        assert!(!sync.durable(1).unwrap());
        assert_eq!(sync.syncs(), syncs);
        assert_eq!(sync.sync_time(), (total, max), "no sync, no time");
    }

    /// Audit 2026-11-06, finding 1: a second store on a live log is
    /// refused before it reads, cuts or creates anything, so it can never
    /// write over blocks the first acknowledged.  The lock is the log's,
    /// not the file's: it survives a compaction's switch (the rename
    /// replaces the file), and it goes when the store is dropped.
    #[test]
    fn a_second_store_on_a_live_log_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut first = Store::create(&path).unwrap();
        let root = first.root_seal().unwrap();
        let b = first.fork(root).unwrap();
        first.write(b, 0, &blocks(0x11, 1), false).unwrap(); // not flushed
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(
            matches!(Store::open(&path), Err(StoreError::Locked(_))),
            "a second open of a live log"
        );
        assert!(
            matches!(Store::create(&path), Err(StoreError::Locked(_))),
            "a create over a live log"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            len,
            "the refused open cut nothing of the first's unflushed tail"
        );
        // Still refused after a compaction replaced the file.
        compact(&mut first);
        assert!(
            matches!(Store::open(&path), Err(StoreError::Locked(_))),
            "a second open after a compaction"
        );
        first.write(b, 1, &blocks(0x12, 1), true).unwrap();
        assert_eq!(read1(&first, b, 0), 0x11);
        drop(first);
        // Dropped: the log opens, with both blocks.
        let (s, _) = Store::open(&path).unwrap();
        assert_eq!((read1(&s, b, 0), read1(&s, b, 1)), (0x11, 0x12));
    }
}
