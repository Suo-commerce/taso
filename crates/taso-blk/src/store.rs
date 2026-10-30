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
//! - [`Store::seal`] appends the Seal and flushes: a Seal is always
//!   durable, and it stands for every record before it.
//!
//! # Records and recovery (format `TASOBLK4`, the layout revision of P5)
//!
//! A record is a **head block** and zero or more **data blocks**; every
//! block is 4 KiB and every record starts on a block.  The header is one
//! block too.
//!
//! ```text
//!   head block: magic u32 | kind u8 | flen u16 | dlen u32 | hash [32] | fields (flen bytes) | zeros
//!   data blocks: data (dlen bytes) | zeros to the next block
//!   hash = BLAKE3(previous record's hash || kind || flen || dlen || BLAKE3(fields || data))
//! ```
//!
//! The **fields** are a record's small part (a write's branch and lba, a
//! Seal's branch and tag, …), inside the head block; the **data** is its
//! bulk (a write's block data, whole blocks, so no padding; a compacted
//! log's `Data` and `Base` records).  The chain is over the body's
//! digest (the body being `fields || data`), so whoever has the body can
//! hash it before the store's lock and the chain under the lock is one
//! hash of 81 bytes.  Because no two records share a block, a record can
//! be written after the lock is let go ([`Store::reserve_write`]), and
//! with the file open `O_DIRECT` a write lands on the drive, so a group's
//! `fdatasync` has nothing to write back.  (The layout changes once:
//! `TASOBLK2`/`TASOBLK3` logs are refused by name, never migrated.)
//!
//! The header's hash seeds the chain.  [`Store::open`] reads the log from
//! the start, checks every record against the chain, and replays it into
//! a fresh [`Map`] (same calls, same ids).  It stops at the first record
//! that is short, has a bad magic or a wrong hash, and takes the end of
//! the **last Flush** it verified as the tail: what was durable.  It
//! never shrinks the file: the **cut** is made by writing one zero block
//! at the new tail (a block that starts with zeros is never a record),
//! because the file may be written ahead of its tail
//! ([`Store::extend_ahead`]) and those zeros are to be kept.
//! [`Recovered::cut`] counts the bytes from the tail to the first all-zero
//! head block (or the file's end): the records after the last Flush,
//! whole or torn.  A write whose data blocks landed but whose head block
//! did not is not counted (its head reads as zeros); it was not
//! acknowledged either way, and the next records overwrite it.
//!
//! Known limit (spike): a bad record is treated as the end of the log,
//! as PostgreSQL's and SQLite's write-ahead logs do.  A torn tail after a
//! crash looks like that; so would media corruption in the middle of the
//! log, which would cut durable groups.  Protection against media
//! corruption comes later from a second copy (shipped packs), not from
//! this file.
//!
//! # Writes in flight (the split write, for `taso-blkd`)
//!
//! [`Store::reserve_write`] does under the lock only what must be
//! serialised: the map's entries, the head block with the chain hash,
//! the record's place.  The caller writes the record with
//! [`Writer::commit`] after letting the lock go.  Until it does, the map
//! points at blocks that are not yet on disk; the store's **tracker**
//! knows every such reservation, and a read that meets one waits for its
//! write, as do a flush, a checkpoint and a compaction (they wait for the
//! **written floor**: the highest sequence number with nothing
//! outstanding at or below it).  A write that fails outside the lock
//! poisons the store like one that fails inside it.
//!
//! # Tags, origins and names (for the Warden's `Pool` and `Layers`)
//!
//! - A Seal may carry a **tag**: up to [`MAX_TAG`] opaque bytes, written in
//!   its `Seal` record.  The Warden puts its own Seal record's lsn and hash
//!   there, as ZFS keeps them in a snapshot property.
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
//! tags and sequence numbers carry over.  A compacted log starts
//! `TASOBLK3` and may hold two more record kinds, both only in its first
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

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};

use crate::map::{Kind, LayerId, Loc, Map, MapError, BLOCK};

mod compact;
pub use compact::{Compacted, Compaction, OldLog};

const FILE_MAGIC: &[u8; 8] = b"TASOBLK4";
/// A log written by a compaction: it may begin with a base
/// ([`K_DATA`] and [`K_BASE`] records).  Otherwise the same records.  A
/// separate magic, so a version that does not know base records refuses
/// the log instead of taking its first record for a torn end.
const COMPACT_MAGIC: &[u8; 8] = b"TASOBLK5";
/// The formats before the layout revision: the spike's (`TASOBLK1`, no
/// tags, origins or names) and the byte-packed records (`TASOBLK2`, its
/// compacted form `TASOBLK3`).  Refused by name, never read.
const OLD_MAGICS: [&[u8; 8]; 3] = [b"TASOBLK1", b"TASOBLK2", b"TASOBLK3"];
/// Largest Seal tag, in bytes.
pub const MAX_TAG: usize = 64;
/// Largest branch name, in bytes.
pub const MAX_NAME: usize = 255;
/// The header is one block: the magic, then zeros.
const HEADER_LEN: u64 = BLOCK;
const REC_MAGIC: u32 = 0x5442_4c4b; // "TBLK"
/// The fixed part of a head block: magic + kind + flen + dlen + hash.
const REC_HEAD: u64 = 4 + 1 + 2 + 4 + HASH as u64;
const HASH: usize = 32;
/// Largest fields a head block holds.
const MAX_FIELDS: usize = (BLOCK - REC_HEAD) as usize;
/// Largest record data accepted: a write of 4096 blocks (16 MiB).  Bounds
/// what recovery allocates for a corrupt length.
const MAX_DATA: u32 = 4096 * BLOCK as u32;
/// Largest record body (fields and data together), as the compaction's
/// buffer sizes it.
const MAX_BODY: u32 = MAX_DATA + MAX_FIELDS as u32;

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
const K_LAST: u8 = K_UNSEAL;

const CKPT_MAGIC: &[u8; 8] = b"TASOCKP1";

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
    /// A log in a format before the layout revision (`TASOBLK1`,
    /// `TASOBLK2` or `TASOBLK3`), which this version does not read.
    OldFormat,
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
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Map(e) => write!(f, "map: {e}"),
            Self::NotALog => write!(f, "not a taso-blk log"),
            Self::OldFormat => write!(
                f,
                "a taso-blk log in a format before the layout revision (TASOBLK1, TASOBLK2 or TASOBLK3); this version reads TASOBLK4 and TASOBLK5, and a log is made again, never migrated"
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
    /// Bytes after the tail that were records, whole or torn: from the end
    /// of the last Flush to the first all-zero head block or the file's
    /// end.  Never acknowledged as durable.
    pub cut: u64,
    /// The sequence number of the checkpoint the replay started from, or
    /// `None` for a full replay.
    pub checkpoint: Option<u64>,
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
    /// Where a write's time under the lock goes, summed over every write
    /// (µs), for the probe of the serial append (taso-p5, 2026-10-26:
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
    /// The log, open `O_DIRECT` when the file system allows it
    /// ([`Store::is_direct`]): every read and write through it is
    /// block-aligned.
    file: File,
    /// The same log for the [`Writer`]s and the [`Syncer`]: a handle the
    /// store shares with them and a compaction's switch
    /// ([`Compaction::finish`]) points at the new log, so a Syncer made
    /// before the switch syncs the log after it.
    shared: Arc<LogFile>,
    direct: bool,
    path: PathBuf,
    map: Map,
    meta: Meta,
    /// End of the last record: where the next one goes.
    tail: u64,
    /// How far the file is written (its length): at least `tail`, more
    /// when it is written ahead ([`Store::extend_ahead`]).
    edge: u64,
    /// Sequence number of the last record (records count from 1).
    lsn: u64,
    /// Hash of the last record (or of the header).
    prev: [u8; HASH],
    /// The writes reserved and not yet written ([`Store::reserve_write`]).
    tracker: Arc<Tracker>,
    stats: Stats,
    poisoned: bool,
}

impl Store {
    /// Create a new, empty log at `path` (which must not exist) and make
    /// its existence durable.
    pub fn create(path: &Path) -> Result<Self, StoreError> {
        let (file, direct) = open_direct(path, true)?;
        // A checkpoint of an earlier log under this name is not ours, nor
        // is an unfinished compaction of one.
        for stale in [
            ckpt_path(path),
            compact::temp_path(path),
            ckpt_path(&compact::temp_path(path)),
        ] {
            remove_if_there(&stale)?;
        }
        let mut header = AlignedBuf::zeroed(HEADER_LEN as usize);
        header[..8].copy_from_slice(FILE_MAGIC);
        file.write_all_at(&header, 0)?;
        file.sync_all()?;
        sync_dir(path)?;
        let shared = Arc::new(LogFile(RwLock::new(file.try_clone()?)));
        Ok(Self {
            file,
            shared,
            direct,
            path: path.to_path_buf(),
            map: Map::new(),
            meta: Meta::default(),
            tail: HEADER_LEN,
            edge: HEADER_LEN,
            lsn: 0,
            prev: seed(&header),
            tracker: Arc::new(Tracker::default()),
            stats: Stats {
                log_bytes: HEADER_LEN,
                ..Stats::default()
            },
            poisoned: false,
        })
    }

    /// Open an existing log: verify, replay to the last Flush, cut the
    /// rest, and make the cut durable.
    ///
    /// One pass.  A group's map changes are held back until its Flush is
    /// verified, then applied together, so records after the last Flush
    /// never reach the map.  The replay reads through a plain descriptor
    /// (buffered, one pass); the store then serves through a direct one.
    pub fn open(path: &Path) -> Result<(Self, Recovered), StoreError> {
        let plain = OpenOptions::new().read(true).open(path)?;
        let len = plain.metadata()?.len();
        if len < HEADER_LEN {
            return Err(StoreError::NotALog);
        }
        let mut header = [0u8; HEADER_LEN as usize];
        plain.read_exact_at(&mut header, 0)?;
        if OLD_MAGICS.contains(&&header[..8].try_into().expect("8 bytes")) {
            return Err(StoreError::OldFormat);
        }
        let compacted = &header[..8] == COMPACT_MAGIC;
        if &header[..8] != FILE_MAGIC && !compacted {
            return Err(StoreError::NotALog);
        }
        let file = &plain;
        // A compaction that did not finish left its new log beside this
        // one; this one is still the log.
        for stale in [
            compact::temp_path(path),
            ckpt_path(&compact::temp_path(path)),
        ] {
            remove_if_there(&stale)?;
        }

        // Start from a checkpoint if one checks out, else from the header.
        let ck = load_checkpoint(path, file, len);
        let from = ck.as_ref().map(|c| c.lsn);
        let (mut map, mut meta, start, start_lsn, start_prev, mut garbage) = match ck {
            Some(c) => (c.map, c.meta, c.end, c.lsn, c.prev, c.garbage),
            None => (Map::new(), Meta::default(), HEADER_LEN, 0, seed(&header), 0),
        };
        let mut r = BufReader::with_capacity(
            1 << 20,
            ReadAt {
                file,
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
            lsn += 1;
            let data_at = pos + BLOCK;
            pos += record_len(kind, body.len());
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
                if !body.is_empty() {
                    return Err(StoreError::Replay {
                        lsn,
                        error: MapError::Overflow,
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
        drop(r);
        // The cut: what was recorded after the tail, up to the first
        // all-zero head block (the file written ahead, or nothing) or the
        // file's end.  Zeroed, so that beyond the tail the file holds
        // only zeros (the invariant the count rests on: a stale data
        // block could otherwise be counted as a cut at a later open);
        // the block at the tail last, so a crash in the middle of this
        // leaves the records or nothing, never a half.  The file is never
        // shrunk.
        let cut = scan_cut(file, end, len)?;
        drop(plain);
        let (file, direct) = open_direct(path, false)?;
        if end < len {
            let zeros = AlignedBuf::zeroed(1 << 20);
            // Whole blocks: a torn last block is zeroed to its end.
            let stop = (end + cut).next_multiple_of(BLOCK);
            let mut at = end + BLOCK;
            while at < stop {
                let n = ((stop - at) as usize).min(zeros.len());
                file.write_all_at(&zeros[..n], at)?;
                at += n as u64;
            }
            file.write_all_at(&zeros[..BLOCK as usize], end)?;
            file.sync_all()?;
        }
        let stats = Stats {
            log_bytes: end,
            garbage_bytes: garbage,
            records: good_lsn,
            ..Stats::default()
        };
        let shared = Arc::new(LogFile(RwLock::new(file.try_clone()?)));
        let store = Self {
            file,
            shared,
            direct,
            path: path.to_path_buf(),
            map,
            meta,
            tail: end,
            edge: len.max(end),
            lsn: good_lsn,
            prev: good_prev,
            tracker: Arc::new(Tracker::default()),
            stats,
            poisoned: false,
        };
        Ok((
            store,
            Recovered {
                records: good_lsn,
                groups,
                cut,
                checkpoint: from,
            },
        ))
    }

    /// The map (read-only): layers, kinds, deltas.
    pub fn map(&self) -> &Map {
        &self.map
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
        if data.len() > MAX_DATA as usize {
            return Err(StoreError::TooLarge(data.len()));
        }
        lba.checked_add(count).ok_or(MapError::Overflow)?;
        if self.map.kind(branch)? != Kind::Branch {
            return Err(MapError::NotABranch(branch).into());
        }
        // The whole write, in one call: the digest, the reservation, the
        // record written (from an aligned copy of the data), and the
        // reservation closed.  What `taso-blkd` does in three steps.
        let t = std::time::Instant::now();
        let digest = write_digest(branch, lba, data);
        self.stats.write_hash_us += t.elapsed().as_micros() as u64;
        let t = std::time::Instant::now();
        let mut copy = AlignedBuf::zeroed(data.len());
        copy.copy_from_slice(data);
        self.stats.write_copy_us += t.elapsed().as_micros() as u64;
        let r = self.reserve_write(branch, lba, data.len(), &digest)?;
        let t = std::time::Instant::now();
        let written = self
            .file
            .write_all_at(&r.head, r.offset)
            .and_then(|()| self.file.write_all_at(&copy, r.offset + BLOCK));
        self.stats.write_pwrite_us += t.elapsed().as_micros() as u64;
        match written {
            Ok(()) => self.tracker.done(r.lsn),
            Err(e) => {
                self.tracker.fail(r.lsn, &e);
                self.poisoned = true;
                return Err(e.into());
            }
        }
        if fua {
            self.flush()?;
        }
        Ok(())
    }

    /// The first step of a write done in three, for `taso-blkd`: under
    /// the lock, check and enter the write in the map, build its head
    /// block, and reserve its place in the log.  `digest` is the body's
    /// digest, [`write_digest`], computed by the caller before taking the
    /// lock.  The caller then writes the record with [`Writer::commit`]
    /// after letting the lock go; until it does, the blocks are entered
    /// but not on disk, and every read of them waits (the tracker).  A
    /// reservation that is never committed leaves a hole the next open
    /// cuts at — and a sync waits for it forever, so a caller that cannot
    /// commit must [`Writer::fail`] it.
    pub fn reserve_write(
        &mut self,
        branch: LayerId,
        lba: u64,
        data_len: usize,
        digest: &[u8; HASH],
    ) -> Result<Reservation, StoreError> {
        self.check()?;
        if data_len == 0 || !(data_len as u64).is_multiple_of(BLOCK) {
            return Err(StoreError::BadLength(data_len));
        }
        if data_len > MAX_DATA as usize {
            return Err(StoreError::TooLarge(data_len));
        }
        let count = data_len as u64 / BLOCK;
        lba.checked_add(count).ok_or(MapError::Overflow)?;
        if self.map.kind(branch)? != Kind::Branch {
            return Err(MapError::NotABranch(branch).into());
        }
        let data_at = self.tail + BLOCK;
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
        let mut fields = [0u8; 16];
        fields[..8].copy_from_slice(&branch.get().to_le_bytes());
        fields[8..].copy_from_slice(&lba.to_le_bytes());
        let mut head = AlignedBuf::zeroed(BLOCK as usize);
        let hash = encode_head(
            &mut head,
            &self.prev,
            K_WRITE,
            &fields,
            data_len as u32,
            digest,
        );
        let r = Reservation {
            offset: self.tail,
            lsn: self.lsn + 1,
            head,
        };
        let total = BLOCK + data_len as u64;
        self.tracker.add(r.lsn, r.offset, total);
        self.tail += total;
        self.edge = self.edge.max(self.tail);
        self.lsn += 1;
        self.prev = hash;
        self.stats.log_bytes = self.tail;
        self.stats.records += 1;
        Ok(r)
    }

    /// A handle for writing reserved records outside the lock: the log's
    /// shared file and the tracker.  Made once per queue thread; it
    /// follows the store through a compaction's switch.
    pub fn writer(&self) -> Writer {
        Writer {
            file: Arc::clone(&self.shared),
            tracker: Arc::clone(&self.tracker),
        }
    }

    /// Whether the log is open `O_DIRECT` (false where the file system
    /// refused it: tmpfs, some overlays — the layout is the same, the
    /// writes go through the page cache, and the sync writes them back).
    pub fn is_direct(&self) -> bool {
        self.direct
    }

    /// Write `bytes` of zeros past the end of the file (from its current
    /// length), so that the records to come overwrite written extents
    /// instead of extending the file — an extending direct write takes
    /// the inode's lock exclusively and runs one at a time; an overwrite
    /// takes it shared (P5 L0, 2026-10-30).  How far the file is written
    /// ahead of the tail is [`Store::ahead`].
    pub fn extend_ahead(&mut self, bytes: u64) -> Result<(), StoreError> {
        self.check()?;
        let bytes = bytes.next_multiple_of(BLOCK);
        let chunk = AlignedBuf::zeroed((1 << 20).min(bytes) as usize);
        let mut at = self.edge;
        while at < self.edge + bytes {
            let n = ((self.edge + bytes - at) as usize).min(chunk.len());
            self.file.write_all_at(&chunk[..n], at)?;
            at += n as u64;
        }
        self.edge += bytes;
        Ok(())
    }

    /// Bytes written ahead of the tail (zeros the next records overwrite).
    pub fn ahead(&self) -> u64 {
        self.edge - self.tail
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
        self.append(K_DISCARD, &body)
    }

    /// Read `buf.len() / BLOCK` blocks from `lba` of `layer`.  Unwritten
    /// and discarded blocks read as zeros.
    pub fn read(&self, layer: LayerId, lba: u64, buf: &mut [u8]) -> Result<(), StoreError> {
        self.check()?;
        if buf.is_empty() || !(buf.len() as u64).is_multiple_of(BLOCK) {
            return Err(StoreError::BadLength(buf.len()));
        }
        // A direct read needs an aligned buffer; a caller's that is not
        // (tests, export) goes through one block of our own.
        let aligned = (buf.as_ptr() as usize).is_multiple_of(BLOCK as usize);
        let mut bounce = (!aligned).then(|| AlignedBuf::zeroed(BLOCK as usize));
        for (i, chunk) in buf.chunks_mut(BLOCK as usize).enumerate() {
            match self.map.read(layer, lba + i as u64)? {
                Some(Loc::Log(off)) => {
                    // A block whose write is reserved but not yet on disk:
                    // wait for it (the tracker).
                    self.tracker.wait_offset(off)?;
                    match &mut bounce {
                        Some(b) => {
                            self.file.read_exact_at(b, off)?;
                            chunk.copy_from_slice(b);
                        }
                        None => self.file.read_exact_at(chunk, off)?,
                    }
                }
                Some(Loc::Zero) | None => chunk.fill(0),
            }
        }
        Ok(())
    }

    /// End a group: append a Flush record and make everything durable.
    /// Returns the Flush record's sequence number.
    pub fn flush(&mut self) -> Result<u64, StoreError> {
        let lsn = self.flush_pending()?;
        // Every reserved write before the Flush must be on disk first.
        if let Err(e) = self
            .tracker
            .wait_floor(lsn)
            .and_then(|()| self.file.sync_data().map_err(StoreError::Io))
        {
            self.poisoned = true;
            return Err(e);
        }
        self.stats.syncs += 1;
        Ok(lsn)
    }

    /// End a group without making it durable: append the Flush record and
    /// return its sequence number, for [`Syncer::durable`] to sync outside
    /// the store's lock.  Nothing is durable until that returns.
    pub fn flush_pending(&mut self) -> Result<u64, StoreError> {
        self.check()?;
        self.append(K_FLUSH, &[])?;
        Ok(self.lsn)
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
        Ok(seal)
    }

    /// A [`Syncer`] over this log's file, for syncing outside the lock.
    /// It waits for the store's reserved writes before every sync.
    pub fn syncer(&self) -> io::Result<Syncer> {
        Ok(Syncer {
            file: Arc::clone(&self.shared),
            tracker: Arc::clone(&self.tracker),
            state: std::sync::Mutex::new(SyncState::default()),
            done: std::sync::Condvar::new(),
        })
    }

    /// The tag of a live Seal (empty if it has none); `None` if `seal` is
    /// not a live Seal.
    pub fn tag(&self, seal: LayerId) -> Option<&[u8]> {
        self.meta.seals.get(&seal).map(|i| i.tag.as_slice())
    }

    /// The branch a live Seal was made from; `None` for a root Seal or if
    /// `seal` is not a live Seal.
    pub fn origin(&self, seal: LayerId) -> Option<LayerId> {
        self.meta.seals.get(&seal).and_then(|i| i.origin)
    }

    /// The live Seals made from `branch`, oldest first.
    pub fn seals_of(&self, branch: LayerId) -> Vec<LayerId> {
        self.meta
            .seals
            .iter()
            .filter(|(_, i)| i.origin == Some(branch))
            .map(|(id, _)| *id)
            .collect()
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
        self.append(K_NAME, &body)
    }

    /// Whether `name` could be given to a new branch: valid and not taken.
    /// Changes nothing.
    pub fn check_name(&self, name: &str) -> Result<(), StoreError> {
        if !valid_name(name) {
            return Err(StoreError::BadName(name.to_string()));
        }
        if self.meta.names.contains_key(name) {
            return Err(StoreError::NameTaken(name.to_string()));
        }
        Ok(())
    }

    /// The live branch named `name`.
    pub fn find(&self, name: &str) -> Option<LayerId> {
        self.meta.names.get(name).copied()
    }

    /// The name of `branch`, if it has one.
    pub fn name_of(&self, branch: LayerId) -> Option<&str> {
        self.meta.by_layer.get(&branch).map(String::as_str)
    }

    /// Drop a branch; its blocks become garbage.
    pub fn drop_branch(&mut self, branch: LayerId) -> Result<(), StoreError> {
        self.check()?;
        let freed = self.map.drop_branch(branch)?;
        self.meta.set_name(branch, "");
        self.stats.garbage_bytes += freed.len() as u64 * BLOCK;
        self.append(K_DROP_BRANCH, &branch.get().to_le_bytes())
    }

    /// Reset `branch` to the Seal it stands on: its own blocks become
    /// garbage, and it keeps its id, name and Seals.  Durable at the next
    /// flush.  A mounted file system on the branch must be unmounted
    /// first: its blocks change under it.  Returns how many blocks the
    /// branch held of its own — what the reset discards from the
    /// filesystem, which the Warden names (spec rev. 33, D93 class (i):
    /// an agent's write adds no Chronicle record, so only this count says
    /// it was lost; E3 [seal write], taso-test 2026-10-28).
    pub fn reset(&mut self, branch: LayerId) -> Result<u64, StoreError> {
        self.check()?;
        let freed = self.map.reset(branch)?;
        self.stats.garbage_bytes += freed.len() as u64 * BLOCK;
        self.append(K_RESET, &branch.get().to_le_bytes())?;
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
            &at,
            self.stats.garbage_bytes,
            &self.map,
            &self.meta,
        )?;
        Ok(self.lsn)
    }

    /// Write the blocks that make `from` (a Seal below `to`, or the zero
    /// base image if `None`) into the Seal `to`, as an import stream.
    /// Returns the blocks written.
    pub fn export(
        &self,
        to: LayerId,
        from: Option<LayerId>,
        w: &mut impl io::Write,
    ) -> Result<u64, StoreError> {
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
        let mut out = HashingWriter {
            w,
            h: blake3::Hasher::new(),
        };
        out.put(STREAM_MAGIC)?;
        let mut buf = vec![0u8; RUN_MAX as usize * BLOCK as usize];
        let mut it = blocks.iter().peekable();
        while let Some((&start, &loc)) = it.next() {
            // A run: consecutive blocks of the same kind, at most RUN_MAX.
            let data = matches!(loc, Loc::Log(_));
            let mut count = 1u64;
            while count < RUN_MAX {
                match it.peek() {
                    Some((&lba, &l))
                        if lba == start + count && matches!(l, Loc::Log(_)) == data =>
                    {
                        it.next();
                        count += 1;
                    }
                    _ => break,
                }
            }
            out.put(&[if data { RUN_DATA } else { RUN_ZERO }])?;
            out.put(&start.to_le_bytes())?;
            out.put(&(count as u32).to_le_bytes())?;
            if data {
                let n = (count * BLOCK) as usize;
                self.read(to, start, &mut buf[..n])?;
                out.put(&buf[..n])?;
            }
        }
        out.put(&[0])?;
        out.put(&(blocks.len() as u64).to_le_bytes())?;
        let hash = out.h.finalize();
        out.w.write_all(hash.as_bytes())?;
        out.w.flush()?;
        Ok(blocks.len() as u64)
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
    pub fn names(&self) -> Vec<(String, LayerId)> {
        let mut v: Vec<(String, LayerId)> = self
            .meta
            .names
            .iter()
            .map(|(n, b)| (n.clone(), *b))
            .collect();
        v.sort();
        v
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

    /// Whether an append or a sync has failed: every call fails until the
    /// log is reopened.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    // ── internals ───────────────────────────────────────────────────

    fn check(&self) -> Result<(), StoreError> {
        if self.poisoned || self.tracker.failed() {
            Err(StoreError::Poisoned)
        } else {
            Ok(())
        }
    }

    /// Append one record at the tail, whole, under the lock: every kind
    /// but a write's data goes this way (one head block; a compacted
    /// log's data and base records are written by the compaction).  The
    /// map has already applied it; if the file write fails, the two
    /// disagree and the store is poisoned.
    fn append(&mut self, kind: u8, body: &[u8]) -> Result<(), StoreError> {
        let (fields, data) = split_body(kind, body);
        let t = std::time::Instant::now();
        let digest = body_digest(fields, data);
        let mut head = AlignedBuf::zeroed(BLOCK as usize);
        let hash = encode_head(
            &mut head,
            &self.prev,
            kind,
            fields,
            data.len() as u32,
            &digest,
        );
        self.stats.write_hash_us += t.elapsed().as_micros() as u64;
        let t = std::time::Instant::now();
        let r = self.file.write_all_at(&head, self.tail).and_then(|()| {
            if data.is_empty() {
                return Ok(());
            }
            let mut copy = AlignedBuf::zeroed(padded(data.len()));
            copy[..data.len()].copy_from_slice(data);
            self.file.write_all_at(&copy, self.tail + BLOCK)
        });
        if let Err(e) = r {
            self.poisoned = true;
            return Err(e.into());
        }
        self.stats.write_pwrite_us += t.elapsed().as_micros() as u64;
        self.tail += record_len(kind, body.len());
        self.edge = self.edge.max(self.tail);
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

/// Round `n` bytes up to whole blocks.
fn padded(n: usize) -> usize {
    n.next_multiple_of(BLOCK as usize)
}

/// A record's length on disk: its head block and its data blocks.
fn record_len(kind: u8, body_len: usize) -> u64 {
    let (_, data) = split_len(kind, body_len);
    BLOCK + padded(data) as u64
}

/// How a record's body splits into its fields (in the head block) and
/// its data (the blocks after it), by kind: a write's first 16 bytes
/// are its fields, a compacted log's data and base records are all data,
/// everything else is all fields.
fn split_len(kind: u8, body_len: usize) -> (usize, usize) {
    let fields = match kind {
        K_WRITE => body_len.min(16),
        K_DATA | K_BASE => 0,
        _ => body_len,
    };
    (fields, body_len - fields)
}

fn split_body(kind: u8, body: &[u8]) -> (&[u8], &[u8]) {
    body.split_at(split_len(kind, body.len()).0)
}

/// The body's digest, `BLAKE3(fields || data)`: the part of the chain a
/// caller computes before the lock.
fn body_digest(fields: &[u8], data: &[u8]) -> [u8; HASH] {
    let mut h = blake3::Hasher::new();
    h.update(fields);
    h.update(data);
    *h.finalize().as_bytes()
}

/// The body's digest of a write record of `data` at `lba` of `branch`,
/// for [`Store::reserve_write`].  Computed outside the lock.
pub fn write_digest(branch: LayerId, lba: u64, data: &[u8]) -> [u8; HASH] {
    let mut fields = [0u8; 16];
    fields[..8].copy_from_slice(&branch.get().to_le_bytes());
    fields[8..].copy_from_slice(&lba.to_le_bytes());
    body_digest(&fields, data)
}

/// Fill `head` (one zeroed block) with a record's head: magic, kind, the
/// lengths, the chain hash, the fields.  Returns the chain hash.
fn encode_head(
    head: &mut [u8],
    prev: &[u8; HASH],
    kind: u8,
    fields: &[u8],
    dlen: u32,
    digest: &[u8; HASH],
) -> [u8; HASH] {
    debug_assert!(head.len() == BLOCK as usize && fields.len() <= MAX_FIELDS);
    let hash = chain(prev, kind, fields.len() as u16, dlen, digest);
    head[0..4].copy_from_slice(&REC_MAGIC.to_le_bytes());
    head[4] = kind;
    head[5..7].copy_from_slice(&(fields.len() as u16).to_le_bytes());
    head[7..11].copy_from_slice(&dlen.to_le_bytes());
    head[11..11 + HASH].copy_from_slice(&hash);
    head[11 + HASH..11 + HASH + fields.len()].copy_from_slice(fields);
    hash
}

/// Append one whole record (its head block and its data blocks, padded)
/// to `out`, which must hold whole blocks; returns the chain hash.  For
/// a compaction, which gathers records into a buffer of its own.
fn encode_record(out: &mut Vec<u8>, prev: &[u8; HASH], kind: u8, body: &[u8]) -> [u8; HASH] {
    debug_assert!((out.len() as u64).is_multiple_of(BLOCK));
    let (fields, data) = split_body(kind, body);
    let digest = body_digest(fields, data);
    let at = out.len();
    out.resize(at + BLOCK as usize, 0);
    let hash = encode_head(
        &mut out[at..],
        prev,
        kind,
        fields,
        data.len() as u32,
        &digest,
    );
    out.extend_from_slice(data);
    out.resize(at + record_len(kind, body.len()) as usize, 0);
    hash
}

fn chain(prev: &[u8; HASH], kind: u8, flen: u16, dlen: u32, digest: &[u8; HASH]) -> [u8; HASH] {
    let mut h = blake3::Hasher::new();
    h.update(prev);
    h.update(&[kind]);
    h.update(&flen.to_le_bytes());
    h.update(&dlen.to_le_bytes());
    h.update(digest);
    *h.finalize().as_bytes()
}

/// A verified record: its kind, its body (fields, then data) and its
/// chain hash.
type Record = (u8, Vec<u8>, [u8; HASH]);

/// What a head block says, before its chain is checked.
struct Head {
    kind: u8,
    flen: usize,
    dlen: usize,
    hash: [u8; HASH],
}

/// Parse a head block: `None` unless its magic, kind and lengths are
/// those of a record (a zero block, a torn block and a data block are
/// not).
fn parse_head(block: &[u8]) -> Option<Head> {
    if block.len() < BLOCK as usize || block[0..4] != REC_MAGIC.to_le_bytes() {
        return None;
    }
    let kind = block[4];
    let flen = u16::from_le_bytes(block[5..7].try_into().unwrap()) as usize;
    let dlen = u32::from_le_bytes(block[7..11].try_into().unwrap());
    if !(K_WRITE..=K_LAST).contains(&kind) || flen > MAX_FIELDS || dlen > MAX_DATA {
        return None;
    }
    Some(Head {
        kind,
        flen,
        dlen: dlen as usize,
        hash: block[11..11 + HASH].try_into().unwrap(),
    })
}

/// Read and verify the next record.  `None` at a clean end or at anything
/// that is not a whole, verified record (torn, bad magic, bad hash).
fn read_record(r: &mut impl Read, prev: &[u8; HASH]) -> io::Result<Option<Record>> {
    let mut head = vec![0u8; BLOCK as usize];
    if !read_full(r, &mut head)? {
        return Ok(None);
    }
    let Some(h) = parse_head(&head) else {
        return Ok(None);
    };
    let mut body = head[REC_HEAD as usize..REC_HEAD as usize + h.flen].to_vec();
    if h.dlen > 0 {
        let mut data = vec![0u8; padded(h.dlen)];
        if !read_full(r, &mut data)? {
            return Ok(None);
        }
        body.extend_from_slice(&data[..h.dlen]);
    }
    let (fields, data) = body.split_at(h.flen);
    let digest = body_digest(fields, data);
    if chain(prev, h.kind, h.flen as u16, h.dlen as u32, &digest) != h.hash {
        return Ok(None);
    }
    Ok(Some((h.kind, body, h.hash)))
}

/// What was recorded after `tail`, in bytes: the records (whole or
/// torn) up to the first all-zero head block or the file's end.  Walks
/// by record length while blocks parse as heads, block by block once one
/// does not.
fn scan_cut(file: &File, tail: u64, len: u64) -> io::Result<u64> {
    let mut block = vec![0u8; BLOCK as usize];
    let mut at = tail;
    while at < len {
        let n = ((len - at) as usize).min(block.len());
        file.read_exact_at(&mut block[..n], at)?;
        if n < block.len() {
            // A torn block at the end of the file: counted whole.
            return Ok(len - tail);
        }
        if block.iter().all(|b| *b == 0) {
            break;
        }
        at += match parse_head(&block) {
            Some(h) => BLOCK + padded(h.dlen) as u64,
            None => BLOCK,
        };
    }
    Ok(at.min(len) - tail)
}

/// Open the log `O_DIRECT`, or plain where the file system refuses it
/// (`EINVAL`: tmpfs, some overlays); says which.  `create` makes it.
fn open_direct(path: &Path, create: bool) -> io::Result<(File, bool)> {
    let mut o = OpenOptions::new();
    o.read(true).write(true);
    if create {
        o.create_new(true);
    }
    match o.custom_flags(libc::O_DIRECT).open(path) {
        Ok(f) => Ok((f, true)),
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
            let mut o = OpenOptions::new();
            o.read(true).write(true);
            if create {
                o.create_new(true);
            }
            Ok((o.open(path)?, false))
        }
        Err(e) => Err(e),
    }
}

/// A buffer aligned to a block, as direct I/O needs: for the head block
/// of a record, a write's data, a read's blocks.  Owned memory with the
/// aligned part found inside it (no unsafe).
pub struct AlignedBuf {
    mem: Vec<u8>,
    start: usize,
    len: usize,
}

impl AlignedBuf {
    /// `len` zero bytes (a multiple of the block, rounded up), aligned to
    /// a block.
    pub fn zeroed(len: usize) -> Self {
        let len = padded(len.max(1));
        let mem = vec![0u8; len + BLOCK as usize];
        let start = mem.as_ptr().align_offset(BLOCK as usize);
        Self { mem, start, len }
    }
}

impl std::ops::Deref for AlignedBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.mem[self.start..self.start + self.len]
    }
}

impl std::ops::DerefMut for AlignedBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.mem[self.start..self.start + self.len]
    }
}

/// A write's place in the log, reserved under the lock
/// ([`Store::reserve_write`]) and written outside it ([`Writer::commit`]).
pub struct Reservation {
    /// Where the record goes: its head block, then its data.
    pub offset: u64,
    /// The record's sequence number.
    pub lsn: u64,
    head: AlignedBuf,
}

/// The log's file as the [`Writer`]s and the [`Syncer`] see it: swapped
/// by a compaction's switch while they are not writing (the store is
/// held and the floor waited for).
pub struct LogFile(RwLock<File>);

impl LogFile {
    fn get(&self) -> std::sync::RwLockReadGuard<'_, File> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn set(&self, file: File) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = file;
    }
}

/// Writes reserved records outside the lock.  [`Store::writer`].
pub struct Writer {
    file: Arc<LogFile>,
    tracker: Arc<Tracker>,
}

impl Writer {
    /// Write the reserved record: its head block and `data` (the bytes
    /// the digest was computed over, in an aligned buffer, whole blocks)
    /// at its place, and close the reservation.  A failed write poisons
    /// the store.
    pub fn commit(&self, r: &Reservation, data: &[u8]) -> Result<(), StoreError> {
        debug_assert!((data.as_ptr() as usize).is_multiple_of(BLOCK as usize));
        let file = self.file.get();
        let res = file
            .write_all_at(&r.head, r.offset)
            .and_then(|()| file.write_all_at(data, r.offset + BLOCK));
        match res {
            Ok(()) => {
                self.tracker.done(r.lsn);
                Ok(())
            }
            Err(e) => {
                self.tracker.fail(r.lsn, &e);
                Err(e.into())
            }
        }
    }

    /// Give a reservation up without writing it (the caller lost its
    /// data): the store is poisoned, as after a failed write, so nothing
    /// is acknowledged over the hole.
    pub fn fail(&self, r: &Reservation, why: &str) {
        self.tracker.fail(r.lsn, &io::Error::other(why.to_string()));
    }
}

/// The writes reserved and not yet on disk, shared by the store, its
/// [`Writer`]s and its [`Syncer`].
#[derive(Default)]
pub struct Tracker {
    state: Mutex<TrackState>,
    changed: Condvar,
}

#[derive(Default)]
struct TrackState {
    /// Outstanding reservations: sequence number → (offset, length).
    open: BTreeMap<u64, (u64, u64)>,
    /// A write outside the lock failed: the store is poisoned.
    failed: Option<String>,
}

impl Tracker {
    fn lock(&self) -> std::sync::MutexGuard<'_, TrackState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn add(&self, lsn: u64, offset: u64, len: u64) {
        self.lock().open.insert(lsn, (offset, len));
    }

    fn done(&self, lsn: u64) {
        self.lock().open.remove(&lsn);
        self.changed.notify_all();
    }

    fn fail(&self, lsn: u64, e: &io::Error) {
        let mut st = self.lock();
        st.open.remove(&lsn);
        st.failed
            .get_or_insert_with(|| format!("the write of record {lsn} failed: {e}"));
        self.changed.notify_all();
    }

    fn failed(&self) -> bool {
        self.lock().failed.is_some()
    }

    /// How a write outside the lock failed, once one has.
    pub fn failure(&self) -> Option<String> {
        self.lock().failed.clone()
    }

    /// Wait until nothing at or before `lsn` is outstanding.
    pub fn wait_floor(&self, lsn: u64) -> Result<(), StoreError> {
        let mut st = self.lock();
        loop {
            if st.failed.is_some() {
                return Err(StoreError::Poisoned);
            }
            match st.open.keys().next() {
                Some(&first) if first <= lsn => {
                    st = self
                        .changed
                        .wait(st)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                _ => return Ok(()),
            }
        }
    }

    /// Wait while an outstanding reservation covers the byte at `off`.
    fn wait_offset(&self, off: u64) -> Result<(), StoreError> {
        let mut st = self.lock();
        loop {
            if st.failed.is_some() {
                return Err(StoreError::Poisoned);
            }
            let covered = st
                .open
                .values()
                .any(|&(at, len)| at <= off && off < at + len);
            if !covered {
                return Ok(());
            }
            st = self
                .changed
                .wait(st)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Reservations not yet written.
    pub fn outstanding(&self) -> usize {
        self.lock().open.len()
    }
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
    /// Offset of the record's data in the file (its second block).
    data_at: u64,
    lsn: u64,
}

impl Pending {
    fn of(kind: u8, body: &[u8], data_at: u64, lsn: u64) -> Self {
        let (fields, _) = split_len(kind, body.len());
        Self {
            kind,
            fields: body[..fields].to_vec(),
            data_len: body.len() - fields,
            data_at,
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
                let at = p.data_at + i * BLOCK;
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
    at: &FlushPoint,
    garbage: u64,
    map: &Map,
    meta: &Meta,
) -> io::Result<()> {
    let mut b = Vec::with_capacity(1 << 16);
    b.extend_from_slice(CKPT_MAGIC);
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
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
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
/// out: its own hash, and the Flush record at its end offset on disk with
/// the chain hash it names.  Any doubt: `None` (a full replay).
fn load_checkpoint(path: &Path, file: &File, len: u64) -> Option<Checkpoint> {
    let b = std::fs::read(ckpt_path(path)).ok()?;
    let (body, sum) = b.split_at(b.len().checked_sub(HASH)?);
    if blake3::hash(body).as_bytes() != sum || !body.starts_with(CKPT_MAGIC) {
        return None;
    }
    let mut r = &body[CKPT_MAGIC.len()..];
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
    // says (one head block), with the chain hash it names.
    let flush_len = BLOCK;
    let empty = body_digest(&[], &[]);
    if end > len
        || end < HEADER_LEN + flush_len
        || !end.is_multiple_of(BLOCK)
        || chain(&before, K_FLUSH, 0, 0, &empty) != prev
    {
        return None;
    }
    let mut rec = vec![0u8; flush_len as usize];
    file.read_exact_at(&mut rec, end - flush_len).ok()?;
    let ok = parse_head(&rec)
        .is_some_and(|h| h.kind == K_FLUSH && h.flen == 0 && h.dlen == 0 && h.hash == prev);
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
    (1..=MAX_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/' | b'-'))
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
/// one disk operation at a time (taso-p5, P=64, 2026-10-26: `seal.log`
/// 690 ms p50 for a 1 ms fsync).
pub struct Syncer {
    file: Arc<LogFile>,
    tracker: Arc<Tracker>,
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
            if st.failed {
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
            // Every reserved write up to here must be on disk before the
            // sync means anything (the tracker).
            let r = match self.tracker.wait_floor(upto) {
                Ok(()) => self.file.get().sync_data(),
                Err(_) => Err(io::Error::other(
                    self.tracker
                        .failure()
                        .unwrap_or_else(|| "a reserved write failed".to_string()),
                )),
            };
            st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            st.syncing = false;
            match r {
                Ok(()) => {
                    st.durable = st.durable.max(upto);
                    st.syncs += 1;
                    led = true;
                }
                Err(e) => {
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
            seal_lsn = s.map().kind(s2).unwrap();
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
        assert_eq!(s.map().kind(s2).unwrap(), seal_lsn);
        assert_eq!(
            s.map().parent(b).unwrap(),
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
        let len = std::fs::metadata(&path).unwrap().len();
        let (mut s, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.cut, len - durable_len, "two records after the flush");
        assert_eq!(s.stats().log_bytes, durable_len);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            len,
            "the file is never shrunk"
        );
        let mut at_tail = vec![1u8; BLOCK as usize];
        std::fs::File::open(&path)
            .unwrap()
            .read_exact_at(&mut at_tail, durable_len)
            .unwrap();
        assert!(
            at_tail.iter().all(|b| *b == 0),
            "the cut is a zero block at the tail"
        );
        drop(s);
        let (s2, rec) = Store::open(&path).unwrap();
        assert_eq!(rec.cut, 0, "a second open finds the cut made");
        s = s2;
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
        f.write_all_at(&[0xFF], mid + BLOCK + 20).unwrap(); // inside the block data
        drop(f);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!(read1(&s, b, 0), 1);
        assert!(rec.cut > 0);
        assert_eq!(s.stats().log_bytes, mid);
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
        // Every byte of the head block's fixed part and fields, then the
        // data block sampled (its bytes are alike to the chain).
        let head = (mid..mid + REC_HEAD + 16).collect::<Vec<_>>();
        let data = (mid + BLOCK..end).step_by(997);
        for at in head.into_iter().chain(data) {
            for mask in [0x01u8, 0x03, 0x09, 0x80] {
                let mut bytes = good.clone();
                bytes[at as usize] ^= mask;
                std::fs::write(&flipped, &bytes).unwrap();
                let (s, rec) = Store::open(&flipped)
                    .unwrap_or_else(|e| panic!("byte {} mask {mask:#x}: {e}", at - mid));
                assert_eq!(s.stats().log_bytes, mid, "byte {} mask {mask:#x}", at - mid);
                assert_eq!(read1(&s, b, 0), 1, "byte {} mask {mask:#x}", at - mid);
                assert_eq!(rec.cut, good.len() as u64 - mid);
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
        s.append(K_FLUSH, &[]).unwrap();
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
        assert_eq!(s.find("tank/taso/vessel-a"), Some(a));
        assert_eq!(s.find("tank/taso/vessel-b"), Some(b));
        assert_eq!(s.name_of(a), Some("tank/taso/vessel-a"));
        assert_eq!(s.tag(s1), Some(&b"lsn=7 hash=aa"[..]));
        assert_eq!(s.tag(s2), Some(&[0xff; MAX_TAG][..]));
        assert_eq!(s.tag(s3), Some(&b""[..]));
        assert_eq!(s.tag(root), Some(&b""[..]));
        assert_eq!(
            (s.origin(s1), s.origin(s3), s.origin(root)),
            (Some(a), Some(b), None)
        );
        assert_eq!(s.seals_of(a), vec![s1, s2], "a's own Seals, oldest first");
        assert_eq!(
            s.seals_of(b),
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
        for bad in ["has space", "tab\t", "ä", &"n".repeat(MAX_NAME + 1)] {
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
        s.name(a, "x").unwrap(); // naming again with the same name is fine
        s.name(a, "y").unwrap(); // renaming frees the old name
        assert_eq!((s.find("x"), s.find("y")), (None, Some(a)));
        s.name(b, "x").unwrap();
        s.name(b, "").unwrap(); // taking the name away
        assert_eq!((s.find("x"), s.name_of(b)), (None, None));
        s.drop_branch(a).unwrap(); // dropping frees the name
        assert_eq!(s.find("y"), None);
        let c = s.fork(root).unwrap();
        s.name(c, "y").unwrap();
        let sc = s.seal(c).unwrap();
        s.drop_seal(sc).unwrap_err(); // c stands on it
        s.drop_branch(c).unwrap();
        s.drop_seal(sc).unwrap();
        assert_eq!(
            (s.tag(sc), s.origin(sc), s.seals_of(c)),
            (None, None, vec![])
        );
        s.flush().unwrap();
        let path = s.path().to_path_buf();
        drop(s);
        let (s, _) = Store::open(&path).unwrap();
        assert_eq!((s.find("x"), s.find("y"), s.name_of(b)), (None, None, None));
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
        assert_eq!((s.find("tank/v-a"), s.seals_of(a)), (Some(a), vec![s1]));
        assert_eq!(s.map().parent(a).unwrap(), Some(s1));
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
            assert_eq!(s.seals_of(a), vec![s1], "the orphan is no Seal of it");
            s.flush().unwrap();
        }
        let (s, _) = Store::open(&path).unwrap();
        assert_eq!(
            (read1(&s, a, 0), read1(&s, a, 5)),
            (1, 0),
            "the unseal survives a reopen"
        );
        assert_eq!((s.find("tank/v-a"), s.seals_of(a)), (Some(a), vec![s1]));
        assert_eq!(s.map().parent(a).unwrap(), Some(s1));
        assert!(s.map().kind(orphan).is_err());
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
        let clean = |b: &Store| b.map().delta(vb).unwrap().next().is_none();
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
            s.names(),
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
        let (stats, names) = (s.stats(), s.names());
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
        assert_eq!(s.names(), names);
        assert_eq!(s.seals_of(layers[1]), vec![layers[2], layers[4]]);
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
        assert_eq!((s.find("kept"), s.find("lost")), (Some(a), None));
    }

    #[test]
    fn a_log_in_an_old_format_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old");
        for magic in OLD_MAGICS {
            let mut header = [0u8; HEADER_LEN as usize];
            header[..8].copy_from_slice(magic);
            std::fs::write(&path, header).unwrap();
            assert!(
                matches!(Store::open(&path), Err(StoreError::OldFormat)),
                "{}",
                String::from_utf8_lossy(magic)
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
        s.append(K_FLUSH, &[]).unwrap();
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
        assert_eq!(s.map().layers(), 0);
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
            .filter(|l| s.map().kind(**l).is_ok())
            .map(|l| {
                let meta = format!("{:?} {:?} {:?}", s.name_of(*l), s.tag(*l), s.origin(*l));
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
                assert_eq!(rec.cut, len - want_len);
                assert_eq!(
                    &snapshot(&s, layers, 9),
                    want,
                    "cut at {len}, checkpoint {with_ckpt}: state must be the last flush"
                );
                if !with_ckpt {
                    assert_eq!(rec.checkpoint, None);
                } else if let Some(c) = &ckpt {
                    // A cut that keeps the checkpoint's Flush must start from it.
                    let end = u64::from_le_bytes(c[8..16].try_into().unwrap());
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
        // same case as its neighbours: an incomplete record.
        let len = std::fs::metadata(&path).unwrap().len();
        let tail_from = points[points.len() - 2].0;
        let mut cuts: Vec<u64> = (tail_from..=len).collect();
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

    // ── The split write, the tracker and the file written ahead ──────

    /// A store behind a mutex, as `taso-blkd` holds it: reserve under the
    /// lock, write outside it.
    fn shared_store(dir: &tempfile::TempDir) -> (Arc<Mutex<Store>>, LayerId) {
        let mut s = new_store(dir);
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        s.write(b, 0, &blocks(1, 1), false).unwrap();
        s.flush().unwrap();
        (Arc::new(Mutex::new(s)), b)
    }

    #[test]
    fn a_read_of_a_reserved_block_waits_for_its_write() {
        let dir = tempfile::tempdir().unwrap();
        let (store, b) = shared_store(&dir);
        let data = blocks(2, 1);
        let digest = write_digest(b, 0, &data);
        let (r, writer) = {
            let mut s = store.lock().unwrap();
            let r = s.reserve_write(b, 0, data.len(), &digest).unwrap();
            (r, s.writer())
        };
        assert_eq!(store.lock().unwrap().tracker.outstanding(), 1);
        // A reader on another queue: the map already points at the new
        // block, which is not on disk yet.  It must wait and see 2, never
        // the zeros that are there.
        let reader = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                let t = std::time::Instant::now();
                let v = read1(&store.lock().unwrap(), b, 0);
                (v, t.elapsed())
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut copy = AlignedBuf::zeroed(data.len());
        copy.copy_from_slice(&data);
        writer.commit(&r, &copy).unwrap();
        let (v, waited) = reader.join().unwrap();
        assert_eq!(v, 2, "the read saw the write, not the hole");
        assert!(
            waited >= std::time::Duration::from_millis(90),
            "the read waited for the write: {waited:?}"
        );
        assert_eq!(store.lock().unwrap().tracker.outstanding(), 0);
    }

    #[test]
    fn a_flush_waits_for_every_reserved_write_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let (store, b) = shared_store(&dir);
        let data = blocks(3, 2);
        let digest = write_digest(b, 4, &data);
        let (r, writer, syncer) = {
            let mut s = store.lock().unwrap();
            let r = s.reserve_write(b, 4, data.len(), &digest).unwrap();
            let lsn = s.flush_pending().unwrap();
            assert_eq!(lsn, r.lsn + 1, "the Flush follows the reservation");
            (r, s.writer(), s.syncer().unwrap())
        };
        let lsn = r.lsn + 1;
        let sync = std::thread::spawn(move || {
            let t = std::time::Instant::now();
            syncer.durable(lsn).unwrap();
            t.elapsed()
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut copy = AlignedBuf::zeroed(data.len());
        copy.copy_from_slice(&data);
        writer.commit(&r, &copy).unwrap();
        let waited = sync.join().unwrap();
        assert!(
            waited >= std::time::Duration::from_millis(90),
            "the sync waited for the write: {waited:?}"
        );
        // And what was synced is on disk, whole.
        let path = store.lock().unwrap().path().to_path_buf();
        drop(store);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!((rec.cut, read1(&s, b, 4), read1(&s, b, 5)), (0, 3, 3));
    }

    #[test]
    fn a_reserved_write_that_fails_poisons_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let (store, b) = shared_store(&dir);
        let data = blocks(4, 1);
        let digest = write_digest(b, 0, &data);
        let (r, writer) = {
            let mut s = store.lock().unwrap();
            let r = s.reserve_write(b, 0, data.len(), &digest).unwrap();
            (r, s.writer())
        };
        writer.fail(&r, "the queue lost its buffer");
        let mut s = store.lock().unwrap();
        assert!(matches!(s.flush(), Err(StoreError::Poisoned)));
        assert!(matches!(
            s.write(b, 1, &blocks(5, 1), false),
            Err(StoreError::Poisoned)
        ));
        assert!(s.tracker.failure().unwrap().contains("lost its buffer"));
    }

    #[test]
    fn a_log_written_ahead_opens_with_no_cut_and_goes_on_over_the_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (b, tail);
        {
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            b = s.fork(root).unwrap();
            s.write(b, 0, &blocks(1, 1), true).unwrap();
            tail = s.stats().log_bytes;
            s.extend_ahead(1 << 20).unwrap();
            assert_eq!(s.ahead(), 1 << 20);
        }
        let len = std::fs::metadata(&path).unwrap().len();
        assert_eq!(len, tail + (1 << 20), "the zeros are on disk");
        let (mut s, rec) = Store::open(&path).unwrap();
        assert_eq!(
            (rec.cut, s.stats().log_bytes),
            (0, tail),
            "zeros ahead are not a cut"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            len,
            "and not shrunk"
        );
        assert_eq!(s.ahead(), 1 << 20);
        s.write(b, 1, &blocks(2, 1), true).unwrap();
        assert_eq!(s.ahead(), (1 << 20) - 3 * BLOCK, "written over the zeros");
        drop(s);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!((rec.cut, read1(&s, b, 0), read1(&s, b, 1)), (0, 1, 2));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len);
    }

    #[test]
    fn a_data_block_that_landed_without_its_head_is_not_a_record() {
        // Two writes in flight; the later one's data lands, its head does
        // not (the cut hit between them).  Replay stops at the zero head;
        // the data beyond it is overwritten by what comes next.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (b, tail);
        {
            let mut s = Store::create(&path).unwrap();
            let root = s.root_seal().unwrap();
            b = s.fork(root).unwrap();
            s.write(b, 0, &blocks(1, 1), true).unwrap();
            tail = s.stats().log_bytes;
            s.extend_ahead(4 * BLOCK).unwrap();
            let data = blocks(9, 1);
            let r = s
                .reserve_write(b, 3, data.len(), &write_digest(b, 3, &data))
                .unwrap();
            // Only the data block lands.
            let mut copy = AlignedBuf::zeroed(data.len());
            copy.copy_from_slice(&data);
            s.file.write_all_at(&copy, r.offset + BLOCK).unwrap();
            s.file.sync_all().unwrap();
            s.tracker.done(r.lsn);
            std::mem::forget(s); // a crash: no cut made, nothing else written
        }
        let (mut s, rec) = Store::open(&path).unwrap();
        assert_eq!((rec.cut, s.stats().log_bytes), (0, tail));
        assert_eq!(
            read1(&s, b, 3),
            0,
            "the orphan data is no block of the Vessel"
        );
        s.write(b, 1, &blocks(2, 1), true).unwrap();
        drop(s);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!((rec.cut, read1(&s, b, 1), read1(&s, b, 3)), (0, 2, 0));
    }

    // ── Compaction ──────────────────────────────────────────────────

    /// What a caller can see of a store, for before/after checks (not the
    /// sequence number: a compaction's own flushes move it on).
    type Whole = (Snapshot, Vec<(String, LayerId)>, Vec<Vec<LayerId>>, usize);

    fn whole(s: &Store, layers: &[LayerId]) -> Whole {
        let seals = layers.iter().map(|l| s.seals_of(*l)).collect();
        (snapshot(s, layers, 9), s.names(), seals, s.map().layers())
    }

    fn compact(s: &mut Store) -> Compacted {
        let mut c = s.compaction().unwrap();
        c.copy().unwrap();
        c.finish(s).unwrap()
    }

    /// The daemon makes its Syncer and its Writers once; a compaction's
    /// switch must not leave them on the old, renamed-away log (found
    /// reading `finish` for L2, 2026-10-30: before, the group commit's
    /// `fdatasync` after a compaction went to the old file).
    #[test]
    fn a_syncer_and_a_writer_made_before_a_compaction_follow_it_to_the_new_log() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let (mut s, layers, _) = busy_store(&path);
        let syncer = s.syncer().unwrap();
        let writer = s.writer();
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
        // And a reserved write through the old Writer lands in the new log
        // and is waited for by the old Syncer.
        let b = layers[3];
        let data = blocks(66, 1);
        let r = s
            .reserve_write(b, 7, data.len(), &write_digest(b, 7, &data))
            .unwrap();
        let lsn = s.flush_pending().unwrap();
        let mut copy = AlignedBuf::zeroed(data.len());
        copy.copy_from_slice(&data);
        writer.commit(&r, &copy).unwrap();
        syncer.durable(lsn).unwrap();
        drop(s);
        let (s, rec) = Store::open(&path).unwrap();
        assert_eq!((rec.cut, read1(&s, b, 7)), (0, 66));
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
            before.log_bytes + 2 * BLOCK,
            "the old log and the two flushes of the compaction"
        );
        assert_eq!(done.after, s.stats().log_bytes);
        assert!(done.checkpoint);
        assert_eq!(s.stats().garbage_bytes, 0);
        assert!(done.after < before.log_bytes / 4, "{done:?}");
        // Live: a has 3 (0..3) + 7; b has 6; the Seals 1 and 3 blocks.
        assert_eq!(done.live, s.map().log_locs().len() as u64 * BLOCK);
        assert_eq!(std::fs::read(&path).unwrap()[..8], *COMPACT_MAGIC);
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
        assert_eq!(s.tag(seal), Some(&b"three"[..]));
        assert_eq!(s.find("tank/e"), Some(e));
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
        assert_eq!(std::fs::read(&path).unwrap()[..8], *FILE_MAGIC);
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

    #[test]
    fn syncer_group_commit_covers_every_group_with_fewer_syncs() {
        // 32 threads each end a group under the lock and ask the syncer
        // for it outside: every ask is answered durable, with at least one
        // sync and never more syncs than asks.  How many asks one sync
        // covers depends on how long a sync takes: where it costs nothing
        // (taso-test's temp directory, 2026-10-29) the asks seldom overlap
        // one and each may run its own; the old bound (fewer than asks)
        // failed there 1 run in 3.  Grouping is measured by the bench's
        // Seals, not here (Jarmo, 2026-10-29: (a)).
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
        // A later ask for an already durable lsn syncs nothing more.
        assert!(!sync.durable(1).unwrap());
        assert_eq!(sync.syncs(), syncs);
    }
}
