//! Compaction: a new log holding only what is live, swapped in for the old.
//!
//! The log only grows: an overwritten block, a dropped branch, a discarded
//! range leave their bytes behind as garbage ([`Stats::garbage_bytes`]).
//! A compaction writes a new log that starts with a **base**, the live
//! blocks and the state that points at them, and goes on with the records
//! the old log received meanwhile; then it puts the new log in the old
//! one's place.
//!
//! ```text
//!   new log:  "TASOBLK3" | Data* | Base+ | Flush | (old log's later records, re-chained)
//!             Data  = live blocks, packed, no map effect
//!             Base  = pieces of: lsn | map | tags and names (checkpoint encoding),
//!                     every log location pointing into the Data records
//! ```
//!
//! Layer ids, names, tags, Seal sequence numbers and the log's sequence
//! number all carry over: nothing outside the store sees a difference
//! except a smaller file.  Recovery reads a base like any group (verified,
//! applied at its Flush), so a compacted log needs no checkpoint to open;
//! one is written anyway, so that the swap itself is quick.
//!
//! # Three steps, so the store stays usable
//!
//! 1. [`Store::compaction`] (with the store): flush, take a copy of the map
//!    and tags at that durable point, open the new file.
//! 2. [`Compaction::copy`] (without the store): copy the live blocks and
//!    write the base, then [`Compaction::catch_up`] (also without): copy
//!    the records the old log got meanwhile.  The old log is append-only,
//!    so every block the copy of the map points at stays where it is, and
//!    a record read back with its chain hash right is whole.
//! 3. [`Compaction::finish`] (with the store): flush, copy the last
//!    records, write the new log's checkpoint, open the new log and check
//!    it agrees with the store, then rename it over the old one and take
//!    its place.
//!
//! The store is held only in steps 1 and 3; step 3 copies only what came
//! in since the last catch-up.  A device served from the store waits that
//! long and no longer.
//!
//! # Crashes
//!
//! Until the rename the old log is the log, untouched but for the flushes;
//! [`Store::open`] removes an unfinished new log it finds beside it.  The
//! rename is the one switch.  The new log's checkpoint is renamed after
//! it; a crash in between leaves the old log's checkpoint beside the new
//! log, which does not check out against it (another Flush record at its
//! offset), so the next open replays the new log in full: correct, slower.

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use super::{
    ckpt_path, encode_record, read_record, remove_if_there, sync_dir, write_checkpoint, FlushPoint,
    Meta, ReadAt, Stats, Store, StoreError, COMPACT_MAGIC, HASH, HEADER_LEN, K_BASE, K_DATA,
    K_FLUSH, MAX_BODY, REC_HEAD,
};
use crate::map::{Map, BLOCK};

/// Blocks per data record: as many as one record may hold.
const DATA_BLOCKS: u64 = (MAX_BODY as u64 - 64) / BLOCK;
/// Bytes of base state per record.
const BASE_PIECE: usize = 4 << 20;
/// Records are gathered into writes of about this size.
const WRITE_BUF: usize = 8 << 20;

/// Where an unfinished compaction of the log at `log` writes.
pub(super) fn temp_path(log: &Path) -> PathBuf {
    let mut p = log.as_os_str().to_owned();
    p.push(".compact");
    PathBuf::from(p)
}

/// What a finished compaction did.
#[derive(Debug)]
pub struct Compacted {
    /// Bytes of the log it replaced (with the compaction's own flushes).
    pub before: u64,
    /// Bytes of log after.
    pub after: u64,
    /// Live bytes copied into the base.
    pub live: u64,
    /// Records copied after the base (what the old log got meanwhile).
    pub records: u64,
    /// False if the new log's checkpoint could not be put in place: the
    /// next open replays the whole (compacted) log.
    pub checkpoint: bool,
    /// The old log's open handles.  Closing the last one frees its space,
    /// which takes the file system a while for a large file (1.3 s for
    /// 2 GiB in a measurement), so drop this after letting go of the
    /// store, not while holding it.
    pub old_log: OldLog,
}

/// Open handles of a replaced log; dropping it closes them.
#[derive(Debug)]
pub struct OldLog(#[allow(dead_code)] Vec<File>);

/// A compaction under way: see the module documentation.  Dropped before
/// [`Compaction::finish`], it removes what it wrote.
pub struct Compaction {
    log: PathBuf,
    temp: PathBuf,
    /// The old log, read only.
    old: File,
    new: File,
    /// The state at the durable point the base stands for.
    map: Option<Map>,
    meta: Option<Meta>,
    at: FlushPoint,
    /// Live bytes copied.
    live: u64,
    /// The old log: where the next record to copy starts, and the chain
    /// hash before it.
    read_pos: u64,
    read_prev: [u8; HASH],
    /// The new log: written up to `tail` (plus `buf`), chain hash `prev`.
    tail: u64,
    prev: [u8; HASH],
    buf: Vec<u8>,
    /// The base's Flush in the new log.
    base_at: Option<FlushPoint>,
    records: u64,
    done: bool,
}

impl Store {
    /// Begin a compaction: flush, copy the map and tags as they are at
    /// that durable point, and create the new file beside the log.  The
    /// rest runs without the store until [`Compaction::finish`].
    pub fn compaction(&mut self) -> Result<Compaction, StoreError> {
        self.check()?;
        let before = self.prev;
        self.flush()?;
        let at = FlushPoint {
            end: self.tail,
            lsn: self.lsn,
            before,
            prev: self.prev,
        };
        // The copy of the state: through the checkpoint encoding, which is
        // already tested to give back what it was given.
        let mut b = Vec::new();
        self.map.encode(&mut b);
        self.meta.encode(&mut b);
        let mut r = b.as_slice();
        let map = Map::decode(&mut r, at.end).expect("a map decodes from its own encoding");
        let meta =
            Meta::decode(&mut r, &map).expect("tags and names decode from their own encoding");

        let temp = temp_path(&self.path);
        remove_if_there(&ckpt_path(&temp))?;
        let new = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp)?;
        let mut header = [0u8; HEADER_LEN as usize];
        header[..8].copy_from_slice(COMPACT_MAGIC);
        new.write_all_at(&header, 0)?;
        Ok(Compaction {
            log: self.path.clone(),
            temp,
            old: self.file.try_clone()?,
            new,
            map: Some(map),
            meta: Some(meta),
            read_pos: at.end,
            read_prev: at.prev,
            at,
            live: 0,
            tail: HEADER_LEN,
            prev: super::seed(&header),
            buf: Vec::with_capacity(WRITE_BUF + MAX_BODY as usize + 64),
            base_at: None,
            records: 0,
            done: false,
        })
    }
}

impl Compaction {
    /// Copy the live blocks into the new log and write the base after
    /// them.  Without the store; once.
    pub fn copy(&mut self) -> Result<(), StoreError> {
        if self.base_at.is_some() {
            return Err(StoreError::Io(io::Error::other(
                "compaction: the base is already written",
            )));
        }
        let (Some(mut map), Some(meta)) = (self.map.take(), self.meta.take()) else {
            return Err(StoreError::Io(io::Error::other(
                "compaction: an earlier copy failed",
            )));
        };
        let mut locs = map.log_locs();
        locs.sort_unstable();
        // Block i of `locs` goes to data record i / DATA_BLOCKS, slot
        // i % DATA_BLOCKS; every data record but the last is full, so its
        // place follows from i alone.
        let full = REC_HEAD + DATA_BLOCKS * BLOCK + HASH as u64;
        let new_of = |i: usize| {
            HEADER_LEN
                + (i as u64 / DATA_BLOCKS) * full
                + REC_HEAD
                + (i as u64 % DATA_BLOCKS) * BLOCK
        };
        let mut data = vec![0u8; (DATA_BLOCKS * BLOCK) as usize];
        for (k, chunk) in locs.chunks(DATA_BLOCKS as usize).enumerate() {
            debug_assert_eq!(
                self.tail + self.buf.len() as u64 + REC_HEAD,
                new_of(k * DATA_BLOCKS as usize)
            );
            // Read runs that are contiguous in the old log with one call.
            let mut j = 0;
            while j < chunk.len() {
                let mut n = 1;
                while j + n < chunk.len() && chunk[j + n] == chunk[j] + n as u64 * BLOCK {
                    n += 1;
                }
                let dst = &mut data[j * BLOCK as usize..(j + n) * BLOCK as usize];
                self.old.read_exact_at(dst, chunk[j])?;
                j += n;
            }
            self.put(K_DATA, &data[..chunk.len() * BLOCK as usize])?;
        }
        self.live = locs.len() as u64 * BLOCK;
        map.remap(|off| {
            let i = locs
                .binary_search(&off)
                .expect("every live location was copied");
            new_of(i)
        });

        let mut state = Vec::with_capacity(1 << 16);
        state.extend_from_slice(&self.at.lsn.to_le_bytes());
        map.encode(&mut state);
        meta.encode(&mut state);
        for piece in state.chunks(BASE_PIECE) {
            self.put(K_BASE, piece)?;
        }
        let before = self.prev;
        self.put(K_FLUSH, &[])?;
        self.write_buf()?;
        self.new.sync_data()?;
        self.base_at = Some(FlushPoint {
            end: self.tail,
            lsn: self.at.lsn,
            before,
            prev: self.prev,
        });
        self.map = Some(map);
        self.meta = Some(meta);
        Ok(())
    }

    /// Copy the records the old log has received since the last copy, up
    /// to the first one not yet whole.  Without the store; as often as
    /// wanted, after [`Compaction::copy`].
    pub fn catch_up(&mut self) -> Result<u64, StoreError> {
        if self.base_at.is_none() {
            return Err(StoreError::Io(io::Error::other(
                "compaction: catch_up before copy",
            )));
        }
        let mut copied = 0;
        loop {
            // A batch at a time (about WRITE_BUF bytes), so memory stays
            // bounded; the reader borrows the old file, the writes `self`.
            let end = self.old.metadata()?.len();
            let mut batch = Vec::new();
            let mut bytes = 0;
            {
                let mut r = BufReader::with_capacity(
                    1 << 20,
                    ReadAt {
                        file: &self.old,
                        pos: self.read_pos,
                        end,
                    },
                );
                while bytes < WRITE_BUF {
                    let Some((kind, body, hash)) = read_record(&mut r, &self.read_prev)? else {
                        break;
                    };
                    self.read_pos += REC_HEAD + body.len() as u64 + HASH as u64;
                    self.read_prev = hash;
                    bytes += body.len();
                    batch.push((kind, body));
                }
            }
            if batch.is_empty() {
                break;
            }
            copied += batch.len() as u64;
            for (kind, body) in batch {
                self.put(kind, &body)?;
            }
        }
        self.write_buf()?;
        // Synced here, without the store, so finish has little to sync.
        self.new.sync_data()?;
        self.records += copied;
        Ok(copied)
    }

    /// Finish with the store (the same one [`Store::compaction`] began
    /// with): flush it, copy its last records, check the new log, and put
    /// it in the old one's place.  On an error before the switch, the
    /// store is as it was and the new file is removed.
    pub fn finish(mut self, store: &mut Store) -> Result<Compacted, StoreError> {
        if store.path != self.log {
            return Err(StoreError::Io(io::Error::other(
                "compaction: finished with another store",
            )));
        }
        store.flush()?;
        self.catch_up()?;
        if (self.read_pos, self.read_prev) != (store.tail, store.prev) {
            return Err(StoreError::Io(io::Error::other(
                "compaction: the new log does not reach the store's last record",
            )));
        }
        self.new.sync_data()?;
        let base_at = self.base_at.take().expect("catch_up checked copy ran");
        let (map, meta) = (
            self.map.take().expect("copy put it back"),
            self.meta.take().expect("copy put it back"),
        );
        write_checkpoint(&self.temp, &base_at, 0, &map, &meta)?;
        drop((map, meta));

        // Open the new log as the next start would, and check it agrees.
        let (mut fresh, rec) = Store::open(&self.temp)?;
        let agrees = rec.checkpoint == Some(base_at.lsn)
            && rec.cut == 0
            && fresh.lsn == store.lsn
            && fresh.tail == self.tail
            && fresh.map.layers() == store.map.layers()
            && fresh.names() == store.names()
            && fresh.meta.seals.len() == store.meta.seals.len();
        if !agrees {
            return Err(StoreError::Io(io::Error::other(format!(
                "compaction: the new log does not agree with the store (lsn {} vs {}, layers {} vs {}, {:?})",
                fresh.lsn,
                store.lsn,
                fresh.map.layers(),
                store.map.layers(),
                rec
            ))));
        }

        taso_core::hold("compact.written");

        // The switch.  After the rename the old file is gone from the
        // directory, so the store must move to the new one whatever
        // follows.
        std::fs::rename(&self.temp, &self.log)?;
        self.done = true;
        let before = store.tail;
        fresh.path = self.log.clone();
        // The Syncer made from the old store follows it to the new log:
        // the shared handle points at the new file (the store is flushed,
        // nothing is waiting on the old one).
        store.shared.set(fresh.file.try_clone()?);
        fresh.shared = std::sync::Arc::clone(&store.shared);
        fresh.stats = Stats {
            syncs: store.stats.syncs,
            write_map_us: store.stats.write_map_us,
            write_copy_us: store.stats.write_copy_us,
            write_hash_us: store.stats.write_hash_us,
            write_pwrite_us: store.stats.write_pwrite_us,
            ..fresh.stats
        };
        let old = std::mem::replace(store, fresh);
        let old_log = OldLog(vec![old.file, self.old.try_clone()?]);
        // The rename is durable only once the directory is: a failed sync
        // here is the store's device failing, answered as a failed sync is
        // anywhere in the store (poisoned, an error), never `ok` (F3,
        // 2026-10-28: E3 hold:compact.written under error answered
        // `ok ... checkpoint=missing`).  Recovery is correct either way:
        // the two logs agree.
        if let Err(e) = sync_dir(&self.log) {
            let _ = remove_if_there(&ckpt_path(&self.log));
            let _ = remove_if_there(&ckpt_path(&self.temp));
            store.poison();
            return Err(StoreError::Io(e));
        }
        let checkpoint = std::fs::rename(ckpt_path(&self.temp), ckpt_path(&self.log)).is_ok();
        if !checkpoint {
            // The old log's checkpoint would not check out against the new
            // log anyway; take it away rather than leave it.
            let _ = remove_if_there(&ckpt_path(&self.log));
            let _ = remove_if_there(&ckpt_path(&self.temp));
        }
        if let Err(e) = sync_dir(&self.log) {
            store.poison();
            return Err(StoreError::Io(e));
        }
        Ok(Compacted {
            before,
            after: store.tail,
            live: self.live,
            old_log,
            records: self.records,
            checkpoint,
        })
    }

    /// Append one record to the new log (gathered in `buf`).
    fn put(&mut self, kind: u8, body: &[u8]) -> io::Result<()> {
        self.prev = encode_record(&mut self.buf, &self.prev, kind, body);
        if self.buf.len() >= WRITE_BUF {
            self.write_buf()?;
        }
        Ok(())
    }

    fn write_buf(&mut self) -> io::Result<()> {
        self.new.write_all_at(&self.buf, self.tail)?;
        self.tail += self.buf.len() as u64;
        self.buf.clear();
        Ok(())
    }
}

impl Drop for Compaction {
    fn drop(&mut self) {
        if !self.done {
            let _ = std::fs::remove_file(&self.temp);
            let _ = std::fs::remove_file(ckpt_path(&self.temp));
        }
    }
}
