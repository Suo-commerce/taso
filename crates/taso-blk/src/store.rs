//! The store: one append-only log holding both the blocks and the map.
//!
//! Every change to a device is a **record** appended to one file: block
//! data (`Write`), TRIM (`Discard`), and the map operations (`RootSeal`,
//! `Fork`, `Seal`, `DropBranch`, `DropSeal`).  A `Flush` record ends a
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
//! Known limit (spike): a bad record is treated as the end of the log,
//! as PostgreSQL's and SQLite's write-ahead logs do.  A torn tail after a
//! crash looks like that; so would media corruption in the middle of the
//! log, which would cut durable groups.  [`Recovered::cut`] reports what
//! was dropped.  Protection against media corruption comes later from a
//! second copy (shipped packs), not from this file.
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
//! The base image is zeros: a fresh device reads zeros until written, and
//! ext4 is created by `mkfs` on a branch, then sealed.
//!
//! An I/O error while appending poisons the store: the map may be ahead
//! of the file, so every later call fails until it is reopened, and
//! reopening rebuilds the map from the log.

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use crate::map::{Kind, LayerId, Loc, Map, MapError, BLOCK};

const FILE_MAGIC: &[u8; 8] = b"TASOBLK2";
/// The spike's format (no tags, origins or names).
const OLD_MAGIC: &[u8; 8] = b"TASOBLK1";
/// Largest Seal tag, in bytes.
pub const MAX_TAG: usize = 64;
/// Largest branch name, in bytes.
pub const MAX_NAME: usize = 255;
const HEADER_LEN: u64 = 16;
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
    /// A log in the spike's format (`TASOBLK1`), which this version does
    /// not read.
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
            Self::OldFormat => write!(f, "a taso-blk log in the spike's format (TASOBLK1); this version reads TASOBLK2"),
            Self::BadTag(n) => write!(f, "a tag of {n} bytes; at most {MAX_TAG}"),
            Self::BadName(n) => write!(f, "bad branch name {n:?}: 1 to {MAX_NAME} of A-Z a-z 0-9 _ . : / -"),
            Self::NameTaken(n) => write!(f, "branch name {n:?} is taken"),
            Self::ReplayMeta { lsn, reason } => write!(f, "record {lsn} does not replay: {reason}"),
            Self::Replay { lsn, error } => write!(f, "record {lsn} does not replay: {error}"),
            Self::BadLength(n) => write!(f, "write of {n} bytes is not a whole number of {BLOCK}-byte blocks"),
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
    /// Bytes cut from the end of the file: records after the last Flush,
    /// and anything torn or unverifiable.
    pub cut: u64,
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
}

/// One block log file and the map it holds.
pub struct Store {
    file: File,
    path: PathBuf,
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
}

impl Store {
    /// Create a new, empty log at `path` (which must not exist) and make
    /// its existence durable.
    pub fn create(path: &Path) -> Result<Self, StoreError> {
        let file = OpenOptions::new().read(true).write(true).create_new(true).open(path)?;
        let mut header = [0u8; HEADER_LEN as usize];
        header[..8].copy_from_slice(FILE_MAGIC);
        file.write_all_at(&header, 0)?;
        file.sync_all()?;
        sync_dir(path)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            map: Map::new(),
            meta: Meta::default(),
            tail: HEADER_LEN,
            lsn: 0,
            prev: seed(&header),
            stats: Stats { log_bytes: HEADER_LEN, ..Stats::default() },
            poisoned: false,
        })
    }

    /// Open an existing log: verify, replay to the last Flush, cut the
    /// rest, and make the cut durable.
    ///
    /// One pass.  A group's map changes are held back until its Flush is
    /// verified, then applied together, so records after the last Flush
    /// never reach the map.
    pub fn open(path: &Path) -> Result<(Self, Recovered), StoreError> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let len = file.metadata()?.len();
        if len < HEADER_LEN {
            return Err(StoreError::NotALog);
        }
        let mut header = [0u8; HEADER_LEN as usize];
        file.read_exact_at(&mut header, 0)?;
        if &header[..8] == OLD_MAGIC {
            return Err(StoreError::OldFormat);
        }
        if &header[..8] != FILE_MAGIC {
            return Err(StoreError::NotALog);
        }

        let mut r = BufReader::with_capacity(1 << 20, ReadAt { file: &file, pos: HEADER_LEN, end: len });
        let mut map = Map::new();
        let mut meta = Meta::default();
        let (mut pos, mut lsn, mut prev) = (HEADER_LEN, 0u64, seed(&header));
        // State at the last verified Flush.
        let (mut end, mut good_lsn, mut good_prev, mut groups, mut garbage) = (HEADER_LEN, 0u64, prev, 0u64, 0u64);
        let mut pending: Vec<Pending> = Vec::new();
        while let Some((kind, body, hash)) = read_record(&mut r, &prev)? {
            lsn += 1;
            let data_at = pos + REC_HEAD;
            pos += REC_HEAD + body.len() as u64 + HASH as u64;
            prev = hash;
            if kind == K_FLUSH {
                if !body.is_empty() {
                    return Err(StoreError::Replay { lsn, error: MapError::Overflow });
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
        let cut = len - end;
        if cut > 0 {
            file.set_len(end)?;
            file.sync_all()?;
        }
        let stats = Stats { log_bytes: end, garbage_bytes: garbage, records: good_lsn, syncs: 0 };
        let store = Self { file, path: path.to_path_buf(), map, meta, tail: end, lsn: good_lsn, prev: good_prev, stats, poisoned: false };
        Ok((store, Recovered { records: good_lsn, groups, cut }))
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
        self.meta.seals.insert(id, SealInfo { origin: None, tag: Vec::new() });
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
    pub fn write(&mut self, branch: LayerId, lba: u64, data: &[u8], fua: bool) -> Result<(), StoreError> {
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
        // The data starts after the record head and the two fields.
        let data_at = self.tail + REC_HEAD + 16;
        for i in 0..count {
            if self.map.write(branch, lba + i, Loc::Log(data_at + i * BLOCK))?.is_some() {
                self.stats.garbage_bytes += BLOCK;
            }
        }
        let mut body = Vec::with_capacity(16 + data.len());
        body.extend_from_slice(&branch.get().to_le_bytes());
        body.extend_from_slice(&lba.to_le_bytes());
        body.extend_from_slice(data);
        self.append(K_WRITE, &body)?;
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
        self.append(K_DISCARD, &body)
    }

    /// Read `buf.len() / BLOCK` blocks from `lba` of `layer`.  Unwritten
    /// and discarded blocks read as zeros.
    pub fn read(&self, layer: LayerId, lba: u64, buf: &mut [u8]) -> Result<(), StoreError> {
        if buf.is_empty() || !(buf.len() as u64).is_multiple_of(BLOCK) {
            return Err(StoreError::BadLength(buf.len()));
        }
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
        self.check()?;
        self.append(K_FLUSH, &[])?;
        if let Err(e) = self.file.sync_data() {
            self.poisoned = true;
            return Err(e.into());
        }
        self.stats.syncs += 1;
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
        self.check()?;
        if tag.len() > MAX_TAG {
            return Err(StoreError::BadTag(tag.len()));
        }
        let lsn = self.lsn + 1;
        let seal = self.map.seal(branch, lsn)?;
        self.meta.seals.insert(seal, SealInfo { origin: Some(branch), tag: tag.to_vec() });
        let mut body = Vec::with_capacity(8 + tag.len());
        body.extend_from_slice(&branch.get().to_le_bytes());
        body.extend_from_slice(tag);
        self.append(K_SEAL, &body)?;
        self.flush()?;
        Ok(seal)
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
        self.meta.seals.iter().filter(|(_, i)| i.origin == Some(branch)).map(|(id, _)| *id).collect()
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

    /// Drop a Seal nothing stands on; its blocks become garbage.
    pub fn drop_seal(&mut self, seal: LayerId) -> Result<(), StoreError> {
        self.check()?;
        let freed = self.map.drop_seal(seal)?;
        self.meta.seals.remove(&seal);
        self.stats.garbage_bytes += freed.len() as u64 * BLOCK;
        self.append(K_DROP_SEAL, &seal.get().to_le_bytes())
    }

    // ── internals ───────────────────────────────────────────────────

    fn check(&self) -> Result<(), StoreError> {
        if self.poisoned {
            Err(StoreError::Poisoned)
        } else {
            Ok(())
        }
    }

    /// Append one record at the tail.  The map has already applied it; if
    /// the file write fails, the two disagree and the store is poisoned.
    fn append(&mut self, kind: u8, body: &[u8]) -> Result<(), StoreError> {
        let hash = chain(&self.prev, kind, body);
        let mut rec = Vec::with_capacity(REC_HEAD as usize + body.len() + HASH);
        rec.extend_from_slice(&REC_MAGIC.to_le_bytes());
        rec.extend_from_slice(&(body.len() as u32).to_le_bytes());
        rec.push(kind);
        rec.extend_from_slice(body);
        rec.extend_from_slice(&hash);
        if let Err(e) = self.file.write_all_at(&rec, self.tail) {
            self.poisoned = true;
            return Err(e.into());
        }
        self.tail += rec.len() as u64;
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
/// that is not a whole, verified record (torn, bad magic, bad hash).
fn read_record(r: &mut impl Read, prev: &[u8; HASH]) -> io::Result<Option<Record>> {
    let mut head = [0u8; REC_HEAD as usize];
    if !read_full(r, &mut head)? {
        return Ok(None);
    }
    let magic = u32::from_le_bytes(head[0..4].try_into().unwrap());
    let len = u32::from_le_bytes(head[4..8].try_into().unwrap());
    let kind = head[8];
    if magic != REC_MAGIC || len > MAX_BODY || !(K_WRITE..=K_NAME).contains(&kind) {
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
        let fields = if kind == K_WRITE { body.len().min(16) } else { body.len() };
        Self { kind, fields: body[..fields].to_vec(), data_len: body.len() - fields, body_at, lsn }
    }
}

/// Apply one verified record to `map`.  Returns the garbage bytes it made.
/// A record that does not fit its kind, or that the map refuses, means the
/// log contradicts itself: refused, never skipped.
fn replay(map: &mut Map, meta: &mut Meta, p: &Pending) -> Result<u64, StoreError> {
    let bad = |error| StoreError::Replay { lsn: p.lsn, error };
    let f = &p.fields;
    let need = |n: usize| if f.len() == n && (p.kind == K_WRITE || p.data_len == 0) { Ok(()) } else { Err(bad(MapError::Overflow)) };
    let layer = |at| LayerId::from_raw(u64_at(f, at));
    let freed = match p.kind {
        K_WRITE => {
            need(16)?;
            if p.data_len == 0 || !(p.data_len as u64).is_multiple_of(BLOCK) {
                return Err(bad(MapError::Overflow));
            }
            let (id, lba) = (layer(0), u64_at(f, 8));
            let count = p.data_len as u64 / BLOCK;
            lba.checked_add(count).ok_or_else(|| bad(MapError::Overflow))?;
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
            map.discard(layer(0), u64_at(f, 8), u64_at(f, 16)).map_err(bad)?.len() as u64
        }
        K_ROOT => {
            need(0)?;
            let id = map.root_seal(p.lsn);
            meta.seals.insert(id, SealInfo { origin: None, tag: Vec::new() });
            0
        }
        K_FORK => {
            need(8)?;
            map.fork(layer(0)).map_err(bad)?;
            0
        }
        K_SEAL => {
            if f.len() < 8 || f.len() > 8 + MAX_TAG {
                return Err(StoreError::ReplayMeta { lsn: p.lsn, reason: "bad Seal record length" });
            }
            let branch = layer(0);
            let seal = map.seal(branch, p.lsn).map_err(bad)?;
            meta.seals.insert(seal, SealInfo { origin: Some(branch), tag: f[8..].to_vec() });
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

/// 1 to [`MAX_NAME`] bytes of `A-Z a-z 0-9 _ . : / -`: what dataset names
/// use, and safe in the daemon's line protocol.
fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/' | b'-'))
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
fn sync_dir(path: &Path) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
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
        assert!(buf.iter().all(|b| *b == buf[0]), "a block is uniform in these tests");
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
        assert_eq!((read1(&s, b, 3), read1(&s, b, 4), read1(&s, b, 5)), (7, 7, 0));
        let mut two = vec![0u8; 2 * B];
        s.read(b, 4, &mut two).unwrap();
        assert!(two[..B].iter().all(|x| *x == 7) && two[B..].iter().all(|x| *x == 0));
        s.discard(b, 3, 1).unwrap();
        assert_eq!(read1(&s, b, 3), 0);
        assert_eq!(read1(&s, root, 4), 0, "the Seal never sees a branch's writes");
    }

    #[test]
    fn bad_writes_are_refused_and_append_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_store(&dir);
        let root = s.root_seal().unwrap();
        let b = s.fork(root).unwrap();
        let before = s.stats();
        assert!(matches!(s.write(b, 0, &[1u8; 100], false), Err(StoreError::BadLength(100))));
        assert!(matches!(s.write(b, 0, &[], false), Err(StoreError::BadLength(0))));
        assert!(matches!(s.write(root, 0, &blocks(1, 1), false), Err(StoreError::Map(MapError::NotABranch(_)))));
        assert!(matches!(s.write(b, u64::MAX, &blocks(1, 1), false), Err(StoreError::Map(MapError::Overflow))));
        assert!(matches!(s.write(b, 0, &blocks(1, 4097), false), Err(StoreError::TooLarge(_))));
        assert!(matches!(s.fork(b), Err(StoreError::Map(MapError::NotASeal(_)))));
        assert_eq!(s.stats(), before, "a refusal appends nothing");
        let mut odd = vec![0u8; 10];
        assert!(matches!(s.read(b, 0, &mut odd), Err(StoreError::BadLength(10))));
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
        assert_eq!(s.map().parent(b).unwrap(), Some(s2), "same ids after replay");
        assert_eq!((read1(&s, b, 1), read1(&s, s2, 1), read1(&s, b, 2)), (2, 1, 0));
        assert_eq!(s.stats().garbage_bytes, BLOCK, "block 2's write was discarded in its own layer");
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
        assert_eq!(std::fs::metadata(&path).unwrap().len(), durable_len, "the cut is on disk");
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
        assert_eq!((read1(&s, other, 0), read1(&s, other, 1), read1(&s, seal, 1)), (9, 8, 9));
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
                let (s, rec) = Store::open(&flipped).unwrap_or_else(|e| panic!("byte {} mask {mask:#x}: {e}", at - mid));
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
        assert!(matches!(Store::open(&path), Err(StoreError::Replay { lsn: 3, error: MapError::Unknown(_) })));
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
        assert_eq!((s.origin(s1), s.origin(s3), s.origin(root)), (Some(a), Some(b), None));
        assert_eq!(s.seals_of(a), vec![s1, s2], "a's own Seals, oldest first");
        assert_eq!(s.seals_of(b), vec![s3], "b's own Seals only, not the one it was forked from");
        assert_eq!(read1(&s, a, 0), 2, "the name stays with the branch across Seals");
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
        assert!(matches!(s.name(root, "r"), Err(StoreError::Map(MapError::NotABranch(_)))));
        for bad in ["has space", "tab\t", "ä", &"n".repeat(MAX_NAME + 1)] {
            assert!(matches!(s.name(b, bad), Err(StoreError::BadName(_))), "{bad:?}");
        }
        assert!(matches!(s.seal_tagged(b, &[0; MAX_TAG + 1]), Err(StoreError::BadTag(_))));
        assert_eq!(s.lsn(), lsn, "refusals append nothing");
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
        assert_eq!((s.tag(sc), s.origin(sc), s.seals_of(c)), (None, None, vec![]));
        s.flush().unwrap();
        let path = s.path().to_path_buf();
        drop(s);
        let (s, _) = Store::open(&path).unwrap();
        assert_eq!((s.find("x"), s.find("y"), s.name_of(b)), (None, None, None));
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
    fn a_log_in_the_spike_format_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old");
        let mut header = [0u8; HEADER_LEN as usize];
        header[..8].copy_from_slice(OLD_MAGIC);
        std::fs::write(&path, header).unwrap();
        assert!(matches!(Store::open(&path), Err(StoreError::OldFormat)));
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
        assert!(matches!(Store::open(&path), Err(StoreError::ReplayMeta { reason: "name taken by another branch", .. })));
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
        Flush,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            6 => (0usize..6, 0u64..6, 1u8..4, 1u8..255, any::<bool>()).prop_map(|(i, b, n, v, f)| Op::Write(i, b, n, v, f)),
            1 => (0usize..6, 0u64..6, 0u64..3).prop_map(|(i, b, n)| Op::Discard(i, b, n)),
            1 => (0usize..6).prop_map(Op::Fork),
            1 => (0usize..6, 0u8..3).prop_map(|(i, t)| Op::Seal(i, t)),
            1 => (0usize..6, 0u8..3).prop_map(|(i, n)| Op::Name(i, n)),
            2 => Just(Op::Flush),
        ]
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
            let pick = |i: usize| layers[i % layers.len()];
            let durable = match *o {
                Op::Write(i, b, n, v, fua) => s.write(pick(i), b, &blocks(v, n as usize), fua).is_ok() && fua,
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
                Op::Name(i, n) => {
                    let name = if n == 0 { String::new() } else { format!("n{n}") };
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
            };
            if durable {
                points.push((s.stats().log_bytes, snapshot(s, &layers, 9)));
            }
        }
        (layers, points)
    }

    fn check_cuts(path: &Path, layers: &[LayerId], points: &[(u64, Snapshot)], cuts: impl Iterator<Item = u64>) {
        let full = std::fs::read(path).unwrap();
        let cut_path = path.with_extension("cut");
        for len in cuts {
            std::fs::write(&cut_path, &full[..len as usize]).unwrap();
            let (s, rec) = Store::open(&cut_path).unwrap();
            let (want_len, want) = points.iter().rev().find(|(l, _)| *l <= len).expect("the header is durable");
            assert_eq!(s.stats().log_bytes, *want_len, "cut at {len}");
            assert_eq!(rec.cut, len - want_len);
            assert_eq!(&snapshot(&s, layers, 9), want, "cut at {len}: state must be the last flush");
        }
        let _ = std::fs::remove_file(&cut_path);
    }

    #[test]
    fn every_cut_of_a_log_recovers_to_the_last_flush_in_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut s = Store::create(&path).unwrap();
        let ops = [
            Op::Fork(0), Op::Write(1, 0, 1, 10, false), Op::Write(1, 1, 2, 11, false), Op::Flush,
            Op::Name(1, 1), Op::Write(1, 0, 1, 12, false), Op::Discard(1, 1, 1), Op::Seal(1, 2), Op::Fork(2),
            Op::Name(3, 2), Op::Write(3, 2, 1, 13, false), Op::Write(1, 2, 1, 14, true), Op::Name(1, 0),
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
}
