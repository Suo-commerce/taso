//! The block log as a Warden storage backend (adoption step 4 of the plan
//! `Taso_plan_blk_adoption_2026-10-18`).
//!
//! [`BlkPool`] and [`BlkLayers`] implement [`Pool`] and [`Layers`] over
//! `taso-blkd`, the way [`crate::zfs::Zfs`] does over ZFS.  Nothing above
//! the two traits changes: a Vessel's dataset is a named branch, a Seal
//! layer is a block-log Seal tagged with the Seal record's lsn and hash,
//! and a fork is a branch of that Seal.
//!
//! | Trait call | Block log |
//! |---|---|
//! | `create` | a root Seal, a branch named after the dataset, a device, `mkfs.ext4`, mount |
//! | `clone` | a branch of the source's Seal bound to (lsn, hash), a device, mount |
//! | `info` | name → branch; origin and parent read from the branch's ancestry |
//! | `snapshot` | freeze ext4 (only when mounted from the branch's device), Seal with the tag, thaw |
//! | `list` | the branch's own Seals with a Taso tag, in lsn order |
//! | `destroy` | drop that Seal (refused while something stands on it) |
//! | `rollback` | only to the newest layer: unmount, detach, reset the branch to that Seal, remount |
//! | `receive`, `receive_clone` | import a shipped stream into a branch (new, the dataset's, or a clone of the base Seal), then Seal it with the tag |
//!
//! Rebirth uses the Warden's existing shipping: [`BlkSend`] is the
//! [`Sender`] that turns a Seal into a stream (`taso-blkd export`: the
//! blocks changed since the base Seal, or the full image), the pack code
//! ships it, and `receive` applies it on the new node.  A Seal's guid,
//! which the shipped record carries and the receiver must reproduce, is
//! derived from its binding ([`guid`]), so it is the same on every node.
//!
//! # Origin and parent without extra state
//!
//! ZFS keeps a clone's origin (`source@taso-seal-<lsn>`) and `taso:parent`.
//! Here both are read from the store: walk the branch's parents past the
//! Seals the branch made itself; the first Seal that another branch made is
//! the clone's origin, and its tag holds the parent hash.  A walk that ends
//! at a root Seal means a void birth.  A dataset name that ends up there
//! comes from the origin branch's name, so the origin must still exist (as
//! with ZFS, where the origin dataset cannot be destroyed under a clone).
//!
//! # Freezing
//!
//! A Seal stands for every block before it, so a mounted ext4 must be
//! consistent first.  [`BlkLayers::snapshot`] freezes the mountpoint only
//! after checking that it is mounted from this branch's own device, never
//! anything else (the lesson of the 2026-10-18 incident: a freeze of a
//! plain directory freezes the file system holding it).  The thaw always
//! runs, also when the Seal fails.  A branch that is not mounted is sealed
//! without a freeze.
//!
//! The daemon and the mount commands are behind [`Blkd`] and [`Mounts`],
//! so the logic is tested here against the real block-log store with an
//! in-memory mount table; [`Daemon`] and [`System`] are the real ones.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use taso_blk::client::{Client, ClientError, Info};
use taso_blk::map::LayerId;
use taso_core::envelope::{HashVal, Lsn};

use crate::chronicle::{LayerError, Layers};
use crate::ship::{ByteStream, Sender};
use crate::storage::{CloneBase, Dataset, DatasetInfo, Snapshot, SNAP_PREFIX};
use crate::vessel::{Pool, SealView};

// ── tags ────────────────────────────────────────────────────────────

/// Length of a Taso tag: lsn (8 bytes, little-endian) and hash (32).
pub const TAG_LEN: usize = 40;

/// The tag binding a block-log Seal to the Seal record at `lsn` with `hash`.
pub fn tag(lsn: Lsn, hash: HashVal) -> [u8; TAG_LEN] {
    let mut t = [0u8; TAG_LEN];
    t[..8].copy_from_slice(&lsn.get().to_le_bytes());
    t[8..].copy_from_slice(hash.as_bytes());
    t
}

/// The binding in a tag, if it is a Taso tag.
pub fn untag(t: &[u8]) -> Option<(Lsn, HashVal)> {
    if t.len() != TAG_LEN {
        return None;
    }
    let lsn = u64::from_le_bytes(t[..8].try_into().ok()?);
    Some((Lsn::new(lsn), HashVal::from_bytes(t[8..].try_into().ok()?)))
}

/// The guid of the Seal layer bound to (`lsn`, `hash`): the same on every
/// node, since it depends on the binding only (ZFS's guid is the same on
/// every node a snapshot is received on; the Warden checks it).
pub fn guid(lsn: Lsn, hash: HashVal) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(b"taso-blk seal guid v1");
    h.update(&tag(lsn, hash));
    u64::from_le_bytes(h.finalize().as_bytes()[..8].try_into().expect("8 bytes"))
}

/// `(dataset, lsn)` from a full Seal snapshot name `<dataset>@taso-seal-<lsn>`.
fn parse_seal_name(name: &str) -> Option<(Dataset, Lsn)> {
    let (ds, snap) = name.split_once('@')?;
    let lsn = snap.strip_prefix(SNAP_PREFIX)?.parse().ok()?;
    Some((Dataset::new(ds).ok()?, Lsn::new(lsn)))
}

// ── the daemon and the mounts ───────────────────────────────────────

/// What the pool needs from `taso-blkd` (implemented by [`Daemon`]).
pub trait Blkd {
    /// A connection of its own to the same block log, for a Vessel's Seals:
    /// the pool's shared connection serialised every Vessel's commands
    /// through one socket and one serving thread (taso-p5, P=64,
    /// 2026-10-26: 250 ms of queue per Seal after group commit).  `None`
    /// (the default, for in-process fakes): the shared connection is used.
    fn own_connection(&self) -> Option<Self>
    where
        Self: Sized,
    {
        None
    }
    /// A new root Seal (zeros).
    fn root(&mut self) -> Result<LayerId, LayerError>;
    /// A branch of `seal` named `name`; a taken name makes nothing.
    fn branch(&mut self, seal: LayerId, name: &str) -> Result<LayerId, LayerError>;
    /// A block device for `branch`.
    fn attach(&mut self, branch: LayerId) -> Result<PathBuf, LayerError>;
    /// Seal `branch` with `tag`.
    fn seal(&mut self, branch: LayerId, tag: &[u8]) -> Result<LayerId, LayerError>;
    /// The live branch named `name`.
    fn find(&mut self, name: &str) -> Result<Option<LayerId>, LayerError>;
    /// The live Seals made from `branch`, oldest first, with tags.
    fn seals(&mut self, branch: LayerId) -> Result<Vec<(LayerId, Vec<u8>)>, LayerError>;
    /// What a layer is.
    fn info(&mut self, layer: LayerId) -> Result<Info, LayerError>;
    /// Drop a branch or a Seal nothing stands on.
    fn drop_layer(&mut self, layer: LayerId) -> Result<(), LayerError>;
    /// Stop `branch`'s device.
    fn detach(&mut self, branch: LayerId) -> Result<(), LayerError>;
    /// Reset a detached `branch` to the Seal it stands on.  Returns the
    /// blocks it held of its own, now discarded.
    fn reset(&mut self, branch: LayerId) -> Result<u64, LayerError>;
    /// Take away the Seal a detached `branch` alone stands on (an orphan:
    /// taken, its record never accepted); the branch stands on that Seal's
    /// parent with nothing of its own.  Returns the blocks discarded.
    fn unseal(&mut self, branch: LayerId) -> Result<u64, LayerError>;
    /// Write Seal `to` (incremental from the Seal `from`, or full) as a
    /// stream into the new file `path`.
    fn export(
        &mut self,
        to: LayerId,
        from: Option<LayerId>,
        path: &Path,
    ) -> Result<u64, LayerError>;
    /// Apply the stream in `path` to a detached, clean `branch`.
    fn import(&mut self, branch: LayerId, path: &Path) -> Result<u64, LayerError>;
    /// Every named branch.
    fn names(&mut self) -> Result<Vec<(String, LayerId)>, LayerError>;
    /// Make every change so far durable.
    fn flush(&mut self) -> Result<(), LayerError>;
}

/// `taso-blkd` over its socket.  Connects on first use and again after a
/// socket error (an answer may have been lost; the next call starts on a
/// fresh connection).
pub struct Daemon {
    socket: PathBuf,
    client: Option<Client>,
}

impl Daemon {
    /// The daemon listening on `socket`.
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            client: None,
        }
    }

    fn call<T>(
        &mut self,
        f: impl FnOnce(&mut Client) -> Result<T, ClientError>,
    ) -> Result<T, LayerError> {
        if self.client.is_none() {
            self.client = Some(Client::connect(&self.socket)?);
        }
        let c = self.client.as_mut().expect("connected above");
        match f(c) {
            Ok(v) => Ok(v),
            Err(e) => {
                if matches!(e, ClientError::Io(_)) {
                    self.client = None;
                }
                Err(e.into())
            }
        }
    }
}

impl Blkd for Daemon {
    fn own_connection(&self) -> Option<Self> {
        Some(Daemon::new(self.socket.clone()))
    }
    fn root(&mut self) -> Result<LayerId, LayerError> {
        self.call(|c| c.root())
    }
    fn branch(&mut self, seal: LayerId, name: &str) -> Result<LayerId, LayerError> {
        self.call(|c| c.branch(seal, Some(name)))
    }
    fn attach(&mut self, branch: LayerId) -> Result<PathBuf, LayerError> {
        self.call(|c| c.attach(branch))
    }
    fn seal(&mut self, branch: LayerId, tag: &[u8]) -> Result<LayerId, LayerError> {
        self.call(|c| c.seal(branch, tag))
    }
    fn find(&mut self, name: &str) -> Result<Option<LayerId>, LayerError> {
        self.call(|c| c.find(name))
    }
    fn seals(&mut self, branch: LayerId) -> Result<Vec<(LayerId, Vec<u8>)>, LayerError> {
        self.call(|c| c.seals(branch))
    }
    fn info(&mut self, layer: LayerId) -> Result<Info, LayerError> {
        self.call(|c| c.info(layer))
    }
    fn drop_layer(&mut self, layer: LayerId) -> Result<(), LayerError> {
        self.call(|c| c.drop_layer(layer))
    }
    fn detach(&mut self, branch: LayerId) -> Result<(), LayerError> {
        self.call(|c| c.detach(branch))
    }
    fn reset(&mut self, branch: LayerId) -> Result<u64, LayerError> {
        self.call(|c| c.reset(branch))
    }
    fn unseal(&mut self, branch: LayerId) -> Result<u64, LayerError> {
        self.call(|c| c.unseal(branch))
    }
    fn export(
        &mut self,
        to: LayerId,
        from: Option<LayerId>,
        path: &Path,
    ) -> Result<u64, LayerError> {
        self.call(|c| c.export(to, from, path))
    }
    fn import(&mut self, branch: LayerId, path: &Path) -> Result<u64, LayerError> {
        self.call(|c| c.import(branch, path))
    }
    fn names(&mut self) -> Result<Vec<(String, LayerId)>, LayerError> {
        self.call(|c| c.names())
    }
    fn flush(&mut self) -> Result<(), LayerError> {
        self.call(|c| c.flush()).map(|_| ())
    }
}

/// The file-system operations the pool needs (implemented by [`System`]).
pub trait Mounts {
    /// Make an ext4 file system on `dev`.
    fn mkfs(&self, dev: &Path) -> io::Result<()>;
    /// Mount `dev` on the directory `dir` (created if missing).
    fn mount(&self, dev: &Path, dir: &Path) -> io::Result<()>;
    /// Mount `dev` read-only on the directory `dir` (created if missing).
    fn mount_ro(&self, dev: &Path, dir: &Path) -> io::Result<()>;
    /// The device mounted on exactly `dir`, if something is.
    fn source(&self, dir: &Path) -> io::Result<Option<PathBuf>>;
    /// Unmount the file system mounted on `dir`.
    fn umount(&self, dir: &Path) -> io::Result<()>;
    /// Freeze the file system mounted on `dir`.
    fn freeze(&self, dir: &Path) -> io::Result<()>;
    /// Thaw it.
    fn thaw(&self, dir: &Path) -> io::Result<()>;
}

/// The real [`Mounts`]: `mkfs.ext4`, `mount`, `fsfreeze`, and
/// `/proc/self/mountinfo`.
#[derive(Clone, Copy, Debug, Default)]
pub struct System;

fn run(cmd: &mut Command) -> io::Result<()> {
    let out = cmd.output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{cmd:?}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

impl Mounts for System {
    fn mkfs(&self, dev: &Path) -> io::Result<()> {
        // nodiscard: a fresh branch reads zeros already; discarding the
        // whole device would only write records.
        // No journal: the Chronicle is the Vessel's journal and the Seal
        // its recovery point.  A crashed Vessel is never mounted as it
        // was: the Warden resets the branch to the last Seal, whose image
        // was taken frozen with every write complete, so ext4's journal
        // would replay nothing - and it cost ten barriers per Seal (an
        // ordered freeze: 12 log syncs; without the journal: 2; taso-p5,
        // scripts/blk-freeze-probe.sh, 2026-10-26).
        run(Command::new("mkfs.ext4")
            .args(["-q", "-F", "-O", "^has_journal", "-E", "nodiscard"])
            .arg(dev))
    }
    fn mount(&self, dev: &Path, dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dir)?;
        // discard: ext4 tells the device each range it frees.  On the
        // block log that is a cheap map change; without it every block
        // ext4 ever wrote stays live, so compaction cannot drop it and
        // Seals and shipped packs carry it.
        run(Command::new("mount")
            .args(["-o", "discard"])
            .arg(dev)
            .arg(dir))
    }
    fn mount_ro(&self, dev: &Path, dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dir)?;
        run(Command::new("mount").args(["-o", "ro"]).arg(dev).arg(dir))
    }
    fn source(&self, dir: &Path) -> io::Result<Option<PathBuf>> {
        Ok(mount_source(
            &std::fs::read_to_string("/proc/self/mountinfo")?,
            dir,
        ))
    }
    fn umount(&self, dir: &Path) -> io::Result<()> {
        run(Command::new("umount").arg(dir))
    }
    fn freeze(&self, dir: &Path) -> io::Result<()> {
        run(Command::new("fsfreeze").arg("-f").arg(dir))
    }
    fn thaw(&self, dir: &Path) -> io::Result<()> {
        run(Command::new("fsfreeze").arg("-u").arg(dir))
    }
}

/// The source of the last mount on exactly `dir` in a mountinfo text
/// (`proc(5)`: field 5 is the mount point, the field after `-` and the
/// file-system type is the source; spaces are written as `\040`).
fn mount_source(mountinfo: &str, dir: &Path) -> Option<PathBuf> {
    let unescape = |s: &str| {
        s.replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\")
    };
    let want = dir.to_str()?;
    mountinfo
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            let sep = f.iter().position(|x| *x == "-")?;
            let source = f.get(sep + 2)?;
            (unescape(f.get(4)?) == want).then(|| PathBuf::from(unescape(source)))
        })
        .next_back() // the last mount on the point is the one on top
}

// ── the pool ────────────────────────────────────────────────────────

/// Vessel datasets as named branches of a block log.
pub struct BlkPool<D: Blkd = Daemon, M: Mounts = System> {
    blkd: Arc<Mutex<D>>,
    mounts: Arc<M>,
    mount_root: PathBuf,
    spool: PathBuf,
}

impl<D: Blkd, M: Mounts> Clone for BlkPool<D, M> {
    fn clone(&self) -> Self {
        Self {
            blkd: self.blkd.clone(),
            mounts: self.mounts.clone(),
            mount_root: self.mount_root.clone(),
            spool: self.spool.clone(),
        }
    }
}

impl BlkPool<Daemon, System> {
    /// The pool served by the daemon on `socket`; dataset `a/b` is mounted
    /// on `<mount_root>/a/b`; shipped streams pass through files in
    /// `spool` (a directory the daemon can write and read, on this host).
    pub fn new(
        socket: impl Into<PathBuf>,
        mount_root: impl Into<PathBuf>,
        spool: impl Into<PathBuf>,
    ) -> Self {
        Self::with(Daemon::new(socket), System, mount_root, spool)
    }
}

impl<D: Blkd, M: Mounts> BlkPool<D, M> {
    /// A pool over any daemon and mounts (tests use fakes).
    pub fn with(
        blkd: D,
        mounts: M,
        mount_root: impl Into<PathBuf>,
        spool: impl Into<PathBuf>,
    ) -> Self {
        Self {
            blkd: Arc::new(Mutex::new(blkd)),
            mounts: Arc::new(mounts),
            mount_root: mount_root.into(),
            spool: spool.into(),
        }
    }

    /// The [`Sender`] for this pool's Seals.
    pub fn sender(&self) -> BlkSend<D> {
        BlkSend {
            blkd: self.blkd.clone(),
            spool: self.spool.clone(),
        }
    }

    /// The Seal layer of `dataset` at `lsn`, as the publisher wants it
    /// (the shape of a ZFS snapshot), or `None` if there is none.
    pub fn snapshot(&self, dataset: &Dataset, lsn: Lsn) -> Result<Option<Snapshot>, LayerError> {
        let mut d = self.blkd.lock().unwrap();
        let Some(b) = d.find(dataset.as_str())? else {
            return Ok(None);
        };
        Ok(seal_at(&mut *d, b, lsn)?.map(|(_, hash)| Snapshot {
            dataset: dataset.clone(),
            seal: lsn,
            guid: guid(lsn, hash),
            seal_hash: Some(hash),
        }))
    }

    /// The datasets directly under `root`.
    pub fn children(&self, root: &Dataset) -> Result<Vec<Dataset>, LayerError> {
        let prefix = format!("{root}/");
        let names = self.blkd.lock().unwrap().names()?;
        Ok(names
            .into_iter()
            .filter_map(|(n, _)| {
                n.strip_prefix(&prefix)
                    .filter(|rest| !rest.contains('/'))
                    .map(|_| n.clone())
            })
            .filter_map(|n| Dataset::new(&n).ok())
            .collect())
    }

    /// The uids owning files in `dataset` (it is mounted for the walk if
    /// it is not).  What `zfs userspace` answers for ZFS.
    pub fn owner_uids(
        &self,
        dataset: &Dataset,
    ) -> Result<std::collections::BTreeSet<u32>, LayerError> {
        use std::os::unix::fs::MetadataExt;
        self.ensure_mounted(dataset)?;
        let mut uids = std::collections::BTreeSet::new();
        let mut stack = vec![self.mountpoint(dataset)];
        while let Some(dir) = stack.pop() {
            let meta = std::fs::symlink_metadata(&dir)?;
            uids.insert(meta.uid());
            if !meta.is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let m = entry.metadata()?; // does not follow symlinks
                if m.is_dir() {
                    stack.push(entry.path());
                } else {
                    uids.insert(m.uid());
                }
            }
        }
        Ok(uids)
    }

    /// Copy `stream` into a new spool file; the file is removed when the
    /// returned guard drops.
    fn spool_in(&self, stream: &mut dyn io::Read) -> Result<SpoolFile, LayerError> {
        let f = SpoolFile::new(&self.spool, "recv")?;
        let mut out = std::io::BufWriter::new(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&f.0)?,
        );
        io::copy(stream, &mut out)?;
        let file = out.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        Ok(f)
    }

    /// Import the spooled stream into `b`, then Seal it with `to`'s tag.
    fn import_and_seal(
        d: &mut D,
        b: LayerId,
        file: &SpoolFile,
        to: (Lsn, HashVal),
    ) -> Result<u64, LayerError> {
        d.import(b, &file.0)?;
        d.seal(b, &tag(to.0, to.1))?;
        d.flush()?;
        Ok(guid(to.0, to.1))
    }

    /// Where `dataset` is mounted.
    pub fn mountpoint(&self, dataset: &Dataset) -> PathBuf {
        self.mount_root.join(dataset.as_str())
    }

    /// Give `dataset` a device and mount it, if it has none or is not
    /// mounted (after a daemon restart devices are gone: they are lazy).
    pub fn ensure_mounted(&self, dataset: &Dataset) -> Result<PathBuf, LayerError> {
        let mut d = {
            let _t = crate::timing::span("blk.ensure.lock");
            self.blkd.lock().unwrap()
        };
        let b = d
            .find(dataset.as_str())?
            .ok_or_else(|| format!("no dataset {dataset}"))?;
        self.mount_branch(&mut *d, b, dataset)
    }

    fn mount_branch(
        &self,
        d: &mut D,
        b: LayerId,
        dataset: &Dataset,
    ) -> Result<PathBuf, LayerError> {
        mount_branch(d, &*self.mounts, b, &self.mountpoint(dataset))
    }

    fn info_locked(&self, d: &mut D, dataset: &Dataset) -> Result<Option<DatasetInfo>, LayerError> {
        let Some(b) = d.find(dataset.as_str())? else {
            return Ok(None);
        };
        let (origin, parent) = lineage(d, b)?;
        Ok(Some(DatasetInfo {
            dataset: dataset.clone(),
            mountpoint: Some(self.mountpoint(dataset)),
            origin,
            parent,
        }))
    }
}

/// Unmount `mp` if branch `b`'s device is mounted there, detach `b`, and
/// drop it.
fn take_down<D: Blkd, M: Mounts + ?Sized>(
    d: &mut D,
    m: &M,
    b: LayerId,
    mp: &Path,
) -> Result<(), LayerError> {
    let info = d.info(b)?;
    match (info.dev.as_ref(), m.source(mp)?) {
        (Some(dev), Some(src)) if &src == dev => m.umount(mp)?,
        (_, Some(src)) => {
            return Err(format!(
                "{} is mounted from {}, not from branch {b}'s device",
                mp.display(),
                src.display()
            )
            .into())
        }
        (_, None) => {}
    }
    if info.dev.is_some() {
        d.detach(b)?;
    }
    d.drop_layer(b)?;
    d.flush()?;
    Ok(())
}

/// Give branch `b` a device if it has none and mount it on `mp` if nothing
/// is mounted there; refuse if something else is.  Returns the device.
/// Take branch `b` (described by `info`) off its mount and device, run
/// `change` on it detached, make that durable, and put it back as it was.
/// Refused, changing nothing, if the mountpoint is mounted from something
/// else or busy (the unmount fails).  Returns what `change` returned.
fn off_and_back<D: Blkd, M: Mounts>(
    d: &mut D,
    m: &M,
    mp: &Path,
    dataset: &Dataset,
    b: LayerId,
    info: &Info,
    change: impl FnOnce(&mut D) -> Result<u64, LayerError>,
) -> Result<u64, LayerError> {
    let was_mounted = match (info.dev.as_ref(), m.source(mp)?) {
        (Some(dev), Some(src)) if &src == dev => true,
        (_, Some(src)) => {
            return Err(format!(
                "{} is mounted from {}, not from {dataset}'s device",
                mp.display(),
                src.display()
            )
            .into())
        }
        (_, None) => false,
    };
    if was_mounted {
        m.umount(mp)?; // busy: refused here, nothing changed
    }
    if info.dev.is_some() {
        d.detach(b)?;
    }
    let n = change(&mut *d)?;
    d.flush()?;
    if was_mounted {
        mount_branch(d, m, b, mp)?;
    } else if info.dev.is_some() {
        d.attach(b)?;
    }
    Ok(n)
}

fn mount_branch<D: Blkd, M: Mounts>(
    d: &mut D,
    m: &M,
    b: LayerId,
    mp: &Path,
) -> Result<PathBuf, LayerError> {
    let dev = match d.info(b)?.dev {
        Some(dev) => dev,
        None => {
            let _t = crate::timing::span("blk.attach");
            d.attach(b)?
        }
    };
    match m.source(mp)? {
        Some(src) if src == dev => {}
        Some(other) => {
            return Err(format!(
                "{} is mounted from {}, not {}",
                mp.display(),
                other.display(),
                dev.display()
            )
            .into())
        }
        None => {
            let _t = crate::timing::span("blk.mount");
            m.mount(&dev, mp)?
        }
    }
    Ok(dev)
}

/// A clone's origin (`source@taso-seal-<lsn>`) and parent hash, read from
/// the ancestry of branch `b`: `(None, None)` for a void birth.
fn lineage<D: Blkd>(
    d: &mut D,
    b: LayerId,
) -> Result<(Option<String>, Option<HashVal>), LayerError> {
    let mut cur = d.info(b)?.parent;
    while let Some(l) = cur {
        let i = d.info(l)?;
        if i.origin == Some(b) {
            cur = i.parent; // a Seal this branch made: keep walking
            continue;
        }
        let Some(src) = i.origin else {
            return Ok((None, None));
        }; // a root Seal: void birth
        let (lsn, hash) = i
            .tag
            .as_deref()
            .and_then(untag)
            .ok_or_else(|| format!("{b}'s origin Seal {l} has no Taso tag"))?;
        let name = d
            .info(src)?
            .name
            .ok_or_else(|| format!("{b}'s origin branch {src} has no name"))?;
        let source = Dataset::new(&name).map_err(|e| e.to_string())?;
        return Ok((Some(source.seal_snapshot(lsn)), Some(hash)));
    }
    Err(format!("{b} has no root Seal below it").into())
}

/// The Seal of `branch` bound to `lsn`: `Ok(None)` if there is none.
fn seal_at<D: Blkd>(
    d: &mut D,
    branch: LayerId,
    lsn: Lsn,
) -> Result<Option<(LayerId, HashVal)>, LayerError> {
    Ok(d.seals(branch)?
        .into_iter()
        .find_map(|(l, t)| untag(&t).filter(|(n, _)| *n == lsn).map(|(_, h)| (l, h))))
}

impl<D: Blkd + 'static, M: Mounts + 'static> Pool for BlkPool<D, M> {
    type Layers = BlkLayers<D, M>;

    /// A throwaway branch of the Seal, given a device and mounted
    /// read-only under `<mount root>/.views/`; dropping the view unmounts
    /// it, detaches it and drops the branch.  A view left behind by a
    /// crash (same name) is taken down first.
    fn seal_view(&self, dataset: &Dataset, lsn: Lsn) -> Result<SealView, LayerError> {
        let name = format!("{}.view-{}", dataset.as_str(), lsn.get());
        let dir = self.mount_root.join(".views").join(&name);
        let mut d = self.blkd.lock().unwrap();
        let b = d
            .find(dataset.as_str())?
            .ok_or_else(|| format!("no dataset {dataset}"))?;
        let (layer, _) = seal_at(&mut *d, b, lsn)?
            .ok_or_else(|| format!("no Seal layer {}", dataset.seal_snapshot(lsn)))?;
        if let Some(stale) = d.find(&name)? {
            take_down(&mut *d, &*self.mounts, stale, &dir)?;
        }
        let v = d.branch(layer, &name)?;
        let made = (|| -> Result<(), LayerError> {
            d.flush()?;
            let dev = d.attach(v)?;
            self.mounts.mount_ro(&dev, &dir)?;
            Ok(())
        })();
        if let Err(e) = made {
            let _ = take_down(&mut *d, &*self.mounts, v, &dir);
            return Err(e);
        }
        drop(d);
        let (blkd, mounts, at) = (self.blkd.clone(), self.mounts.clone(), dir.clone());
        Ok(SealView::new(
            dir,
            Some(Box::new(move || {
                let mut d = blkd.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(e) = take_down(&mut *d, &*mounts, v, &at) {
                    eprintln!("taso: leaving a Seal view behind at {}: {e}", at.display());
                }
            })),
        ))
    }

    fn guid(&self, dataset: &Dataset) -> Result<Option<u64>, LayerError> {
        let mut d = self.blkd.lock().unwrap();
        Ok(d.find(dataset.as_str())?.map(|b| b.get()))
    }

    /// Unmount, detach, drop the branch, then its own Seals (newest first)
    /// and, for a dataset born from the void, its root Seal.  The block
    /// log refuses to drop a layer something stands on (a clone).
    fn destroy(&self, dataset: &Dataset, guid: u64) -> Result<bool, LayerError> {
        let mut d = self.blkd.lock().unwrap();
        let Some(b) = d.find(dataset.as_str())? else {
            return Ok(false);
        };
        if b.get() != guid {
            return Err(format!(
                "{dataset} is branch {}, not {guid}; not destroying it",
                b.get()
            )
            .into());
        }
        // Its own Seals, newest first, then what it was born on.
        let mut own = Vec::new();
        let mut cur = d.info(b)?.parent;
        let mut root = None;
        while let Some(l) = cur {
            let i = d.info(l)?;
            if i.origin == Some(b) {
                own.push(l);
                cur = i.parent;
                continue;
            }
            if i.parent.is_none() && i.origin.is_none() {
                root = Some(l); // a void birth's own root Seal
            }
            break;
        }
        // Refuse before touching anything if another branch (a clone, an
        // open Seal view) stands on one of its layers.
        let mut mine: Vec<LayerId> = own.clone();
        mine.extend(root);
        for (name, x) in d.names()? {
            if x == b {
                continue;
            }
            let mut cur = d.info(x)?.parent;
            while let Some(l) = cur {
                if mine.contains(&l) {
                    return Err(format!(
                        "{name} stands on {dataset}'s layer {l}; not destroying it"
                    )
                    .into());
                }
                cur = d.info(l)?.parent;
            }
        }
        take_down(&mut *d, &*self.mounts, b, &self.mountpoint(dataset))?;
        for l in own {
            d.drop_layer(l)?;
        }
        if let Some(r) = root {
            d.drop_layer(r)?;
        }
        d.flush()?;
        Ok(true)
    }

    fn adopt(
        &self,
        dataset: &Dataset,
        base: (Lsn, HashVal),
        to: (Lsn, HashVal),
        child: &Dataset,
        child_seal: Lsn,
        sender: &dyn crate::ship::Sender,
    ) -> Result<u64, LayerError> {
        // Out of use first: the branch's blocks change under its ext4.
        {
            let mut d = self.blkd.lock().unwrap();
            let b = d
                .find(dataset.as_str())?
                .ok_or_else(|| format!("no dataset {dataset} to adopt into"))?;
            if seal_at(&mut *d, b, to.0)?.is_none() {
                if let Some(later) = d
                    .seals(b)?
                    .iter()
                    .filter_map(|(_, t)| untag(t))
                    .map(|(n, _)| n)
                    .find(|n| *n > base.0)
                {
                    return Err(format!(
                        "a later layer exists ({}); {} is not the newest",
                        dataset.seal_snapshot(later),
                        dataset.seal_snapshot(base.0)
                    )
                    .into());
                }
                let info = d.info(b)?;
                let mp = self.mountpoint(dataset);
                match (info.dev.as_ref(), self.mounts.source(&mp)?) {
                    (Some(dev), Some(src)) if &src == dev => self.mounts.umount(&mp)?,
                    (_, Some(src)) => {
                        return Err(format!(
                            "{} is mounted from {}, not from {dataset}'s device",
                            mp.display(),
                            src.display()
                        )
                        .into())
                    }
                    (_, None) => {}
                }
                if info.dev.is_some() {
                    d.detach(b)?;
                }
            }
        }
        // The fork's increment from `base`, imported as this branch's own
        // Seal layer `to` (the receive checks `base` and binds `to`).
        let from = dataset.seal_snapshot(base.0);
        let mut stream = sender.send(child, Some(&from), child_seal)?;
        Pool::receive(self, dataset, Some(base), to, &mut stream)
    }

    fn create(&self, dataset: &Dataset) -> Result<DatasetInfo, LayerError> {
        let mut d = self.blkd.lock().unwrap();
        if d.find(dataset.as_str())?.is_some() {
            return Err(format!("dataset {dataset} already exists").into());
        }
        let root = d.root()?;
        let b = d.branch(root, dataset.as_str())?;
        let made = (|| -> Result<(), LayerError> {
            d.flush()?;
            let dev = d.attach(b)?;
            self.mounts.mkfs(&dev)?;
            self.mount_branch(&mut *d, b, dataset)?;
            Ok(())
        })();
        if let Err(e) = made {
            // Take it back so a retry starts clean (an unformatted branch
            // must not be adopted as an interrupted birth).
            let _ = d.drop_layer(b);
            let _ = d.drop_layer(root);
            let _ = d.flush();
            return Err(e);
        }
        Ok(self.info_locked(&mut *d, dataset)?.expect("just made"))
    }

    fn clone(
        &self,
        source: &Dataset,
        seal: Lsn,
        seal_hash: HashVal,
        target: &Dataset,
    ) -> Result<DatasetInfo, LayerError> {
        // The fork probe (P5): the wait for the pool's one connection,
        // apart from the calls made on it.
        let mut d = {
            let _t = crate::timing::span("blk.clone.lock");
            self.blkd.lock().unwrap()
        };
        let find_span = crate::timing::span("blk.clone.find");
        let src = d
            .find(source.as_str())?
            .ok_or_else(|| format!("no dataset {source}"))?;
        let (layer, hash) = seal_at(&mut *d, src, seal)?
            .ok_or_else(|| format!("no Seal layer {}", source.seal_snapshot(seal)))?;
        if hash != seal_hash {
            return Err(format!(
                "Seal layer {} is bound to another record",
                source.seal_snapshot(seal)
            )
            .into());
        }
        if d.find(target.as_str())?.is_some() {
            return Err(format!("dataset {target} already exists").into());
        }
        drop(find_span);
        let branch_span = crate::timing::span("blk.branch");
        let b = d.branch(layer, target.as_str())?;
        let made = (|| -> Result<(), LayerError> {
            d.flush()?;
            drop(branch_span);
            self.mount_branch(&mut *d, b, target)?;
            Ok(())
        })();
        if let Err(e) = made {
            let _ = d.drop_layer(b);
            let _ = d.flush();
            return Err(e);
        }
        let _t = crate::timing::span("blk.clone.info");
        Ok(self.info_locked(&mut *d, target)?.expect("just made"))
    }

    fn info(&self, dataset: &Dataset) -> Result<Option<DatasetInfo>, LayerError> {
        let mut d = {
            let _t = crate::timing::span("blk.info.lock");
            self.blkd.lock().unwrap()
        };
        let _t = crate::timing::span("blk.info.ask");
        self.info_locked(&mut *d, dataset)
    }

    fn layers(&self, dataset: &Dataset) -> BlkLayers<D, M> {
        BlkLayers {
            own: self.blkd.lock().unwrap().own_connection(),
            cached: None,
            blkd: self.blkd.clone(),
            mounts: self.mounts.clone(),
            dataset: dataset.clone(),
            mountpoint: self.mountpoint(dataset),
            discarded: None,
            unsealed: 0,
        }
    }

    fn receive(
        &self,
        dataset: &Dataset,
        from: Option<(Lsn, HashVal)>,
        to: (Lsn, HashVal),
        stream: &mut dyn io::Read,
    ) -> Result<u64, LayerError> {
        // Already here (an interrupted rebirth got this far): bind and return.
        {
            let mut d = self.blkd.lock().unwrap();
            if let Some(b) = d.find(dataset.as_str())? {
                if let Some((_, h)) = seal_at(&mut *d, b, to.0)? {
                    return if h == to.1 {
                        Ok(guid(to.0, to.1))
                    } else {
                        Err(format!(
                            "Seal layer {} is bound to another record",
                            dataset.seal_snapshot(to.0)
                        )
                        .into())
                    };
                }
            }
        }
        let file = self.spool_in(stream)?; // a stream that fails as it is read leaves nothing
        let mut d = self.blkd.lock().unwrap();
        match from {
            None => {
                if d.find(dataset.as_str())?.is_some() {
                    return Err(
                        format!("dataset {dataset} exists; a full stream needs a new one").into(),
                    );
                }
                let root = d.root()?;
                let b = d.branch(root, dataset.as_str())?;
                Self::import_and_seal(&mut *d, b, &file, to).inspect_err(|_| {
                    let _ = d.drop_layer(b);
                    let _ = d.drop_layer(root);
                    let _ = d.flush();
                })
            }
            Some((lsn, hash)) => {
                let b = d
                    .find(dataset.as_str())?
                    .ok_or_else(|| format!("no dataset {dataset} to receive into"))?;
                let (layer, bound) = seal_at(&mut *d, b, lsn)?.ok_or_else(|| {
                    format!(
                        "no Seal layer {} to receive onto",
                        dataset.seal_snapshot(lsn)
                    )
                })?;
                if bound != hash {
                    return Err(format!(
                        "Seal layer {} is bound to another record",
                        dataset.seal_snapshot(lsn)
                    )
                    .into());
                }
                let info = d.info(b)?;
                if info.parent != Some(layer) {
                    return Err(format!(
                        "{dataset} does not stand on {}",
                        dataset.seal_snapshot(lsn)
                    )
                    .into());
                }
                if info.dev.is_some() {
                    return Err(
                        format!("{dataset} is attached; a received dataset is not in use").into(),
                    );
                }
                d.reset(b)?; // whatever an interrupted receive left
                Self::import_and_seal(&mut *d, b, &file, to).inspect_err(|_| {
                    let _ = d.reset(b);
                    let _ = d.flush();
                })
            }
        }
    }

    fn receive_clone(
        &self,
        dataset: &Dataset,
        base: &CloneBase,
        to: (Lsn, HashVal),
        stream: &mut dyn io::Read,
    ) -> Result<u64, LayerError> {
        {
            let mut d = self.blkd.lock().unwrap();
            if let Some(b) = d.find(dataset.as_str())? {
                if let Some((_, h)) = seal_at(&mut *d, b, to.0)? {
                    return if h == to.1 {
                        Ok(guid(to.0, to.1))
                    } else {
                        Err(format!(
                            "Seal layer {} is bound to another record",
                            dataset.seal_snapshot(to.0)
                        )
                        .into())
                    };
                }
                return Err(format!("dataset {dataset} exists without Seal {}", to.0.get()).into());
            }
        }
        if base.guid != guid(base.seal, base.hash) {
            return Err(format!(
                "the base {} has another guid",
                base.dataset.seal_snapshot(base.seal)
            )
            .into());
        }
        let file = self.spool_in(stream)?;
        let mut d = self.blkd.lock().unwrap();
        let src = d
            .find(base.dataset.as_str())?
            .ok_or_else(|| format!("no base dataset {}", base.dataset))?;
        let (layer, bound) = seal_at(&mut *d, src, base.seal)?.ok_or_else(|| {
            format!(
                "no base Seal layer {}",
                base.dataset.seal_snapshot(base.seal)
            )
        })?;
        if bound != base.hash {
            return Err(format!(
                "base Seal layer {} is bound to another record",
                base.dataset.seal_snapshot(base.seal)
            )
            .into());
        }
        let b = d.branch(layer, dataset.as_str())?;
        Self::import_and_seal(&mut *d, b, &file, to).inspect_err(|_| {
            let _ = d.drop_layer(b);
            let _ = d.flush();
        })
    }
}

// ── sending ─────────────────────────────────────────────────────────

/// The [`Sender`] of a [`BlkPool`]: a Seal as a stream of the blocks that
/// changed since the base Seal (full if there is none).
pub struct BlkSend<D: Blkd = Daemon> {
    blkd: Arc<Mutex<D>>,
    spool: PathBuf,
}

impl<D: Blkd> Sender for BlkSend<D> {
    fn send(&self, dataset: &Dataset, from: Option<&str>, to: Lsn) -> io::Result<ByteStream> {
        let err = |e: LayerError| io::Error::other(e.to_string());
        let file = SpoolFile::new(&self.spool, "send")?;
        {
            let mut d = self.blkd.lock().unwrap();
            let b = d
                .find(dataset.as_str())
                .map_err(err)?
                .ok_or_else(|| io::Error::other(format!("no dataset {dataset}")))?;
            let (to_layer, _) = seal_at(&mut *d, b, to).map_err(err)?.ok_or_else(|| {
                io::Error::other(format!("no Seal layer {}", dataset.seal_snapshot(to)))
            })?;
            let from_layer = match from {
                None => None,
                Some(name) => {
                    let (fds, flsn) = parse_seal_name(name).ok_or_else(|| {
                        io::Error::other(format!("{name:?} is not a Seal snapshot name"))
                    })?;
                    let fb = d
                        .find(fds.as_str())
                        .map_err(err)?
                        .ok_or_else(|| io::Error::other(format!("no dataset {fds}")))?;
                    let (l, _) = seal_at(&mut *d, fb, flsn)
                        .map_err(err)?
                        .ok_or_else(|| io::Error::other(format!("no Seal layer {name}")))?;
                    Some(l)
                }
            };
            d.export(to_layer, from_layer, &file.0).map_err(err)?;
        }
        // Opened, then the name removed: the stream lives as long as the
        // reader, and nothing is left in the spool.
        let f = std::fs::File::open(&file.0)?;
        drop(file);
        Ok(Box::new(io::BufReader::with_capacity(1 << 20, f)))
    }
}

/// A file in the spool directory, removed when dropped.
struct SpoolFile(PathBuf);

impl SpoolFile {
    /// A new, unused name in `dir` (created if missing); the file itself
    /// is made by whoever writes it.
    fn new(dir: &Path, kind: &str) -> io::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::fs::create_dir_all(dir)?;
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        Ok(Self(dir.join(format!(
            "{kind}-{}-{n}-{nanos}.blks",
            std::process::id()
        ))))
    }
}

impl Drop for SpoolFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ── layers ──────────────────────────────────────────────────────────

/// The Seal layers of one dataset.
pub struct BlkLayers<D: Blkd = Daemon, M: Mounts = System> {
    blkd: Arc<Mutex<D>>,
    /// This Vessel's own connection for its Seals ([`Blkd::own_connection`]).
    own: Option<D>,
    /// The branch and its device, looked up once: neither changes while
    /// the branch stays mounted from that device (checked at each Seal).
    cached: Option<(LayerId, Option<PathBuf>)>,
    mounts: Arc<M>,
    dataset: Dataset,
    mountpoint: PathBuf,
    /// Blocks the last [`Layers::rollback`] discarded from the filesystem
    /// (the branch's own, below the Seal it went back to); `None` before
    /// any.  The Warden names it (D93 class (i)).
    discarded: Option<u64>,
    /// Blocks an unseal took with an orphan (F1) since the last rollback:
    /// lost from the filesystem as a reset's are, so the next rollback
    /// counts them too.
    unsealed: u64,
}

impl<D: Blkd, M: Mounts> BlkLayers<D, M> {
    fn branch(&self, d: &mut D) -> Result<LayerId, LayerError> {
        Ok(d.find(self.dataset.as_str())?
            .ok_or_else(|| format!("no dataset {}", self.dataset))?)
    }

    /// Run `f` on this Vessel's own connection, or on the shared one.
    fn with_conn<T>(&mut self, f: impl FnOnce(&mut D) -> T) -> T {
        match self.own.as_mut() {
            Some(d) => f(d),
            None => f(&mut *self.blkd.lock().unwrap()),
        }
    }
}

impl<D: Blkd, M: Mounts> Layers for BlkLayers<D, M> {
    fn discarded_blocks(&self) -> Option<u64> {
        self.discarded
    }
    fn snapshot(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
        // On this Vessel's own connection, with the branch and its device
        // cached: a Seal is two commands (the Seals of the branch, to
        // refuse a repeat; the Seal), and no lock is held across the
        // freeze, which is the kernel's work on the mount.
        let lookup = crate::timing::span("seal.lookup");
        let mounted = self.mounts.source(&self.mountpoint)?;
        let fresh = match &self.cached {
            Some((_, dev)) if mounted.is_none() || mounted == *dev => false,
            _ => true, // never looked up, or the device changed (a restart)
        };
        if fresh {
            let dataset = self.dataset.clone();
            let c = self.with_conn(|d| -> Result<_, LayerError> {
                let b = d
                    .find(dataset.as_str())?
                    .ok_or_else(|| format!("no dataset {dataset}"))?;
                Ok((b, d.info(b)?.dev))
            })?;
            self.cached = Some(c);
        }
        let (b, dev) = self.cached.clone().expect("cached above");
        if self.with_conn(|d| seal_at(d, b, lsn))?.is_some() {
            return Err(format!("Seal layer {} exists", self.dataset.seal_snapshot(lsn)).into());
        }
        let t = tag(lsn, hash);
        drop(lookup);
        match (dev, mounted) {
            (Some(dev), Some(src)) if src == dev => {
                // Three spans under seal.snapshot, so a slow Seal names its
                // step: the freeze (ext4's sync of the Vessel), the Seal on
                // the log, the thaw.
                let freeze = crate::timing::span("seal.freeze");
                self.mounts.freeze(&self.mountpoint)?;
                drop(freeze);
                let sealed = {
                    let _log = crate::timing::span("seal.log");
                    self.with_conn(|d| d.seal(b, &t))
                };
                let thaw = crate::timing::span("seal.thaw");
                let thawed = self.mounts.thaw(&self.mountpoint);
                drop(thaw);
                // Both results are read: a thaw that failed after a Seal
                // that failed is the urgent one (the Vessel is still
                // frozen) and must not hide behind the Seal's error.
                match (sealed, thawed) {
                    (Ok(_), Ok(())) => {}
                    (Err(e), Ok(())) => return Err(e),
                    (Ok(_), Err(e)) => return Err(e.into()),
                    (Err(seal), Err(thaw)) => {
                        return Err(format!(
                            "seal failed ({seal}) and {} is still frozen: thaw failed ({thaw})",
                            self.mountpoint.display()
                        )
                        .into());
                    }
                }
            }
            (_, Some(src)) => {
                return Err(format!(
                    "{} is mounted from {}, not from {}'s device; not freezing it",
                    self.mountpoint.display(),
                    src.display(),
                    self.dataset
                )
                .into());
            }
            (_, None) => {
                self.with_conn(|d| d.seal(b, &t))?; // nothing mounted: the device is quiet
            }
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError> {
        let mut d = self.blkd.lock().unwrap();
        let b = self.branch(&mut *d)?;
        let by_lsn: BTreeMap<Lsn, HashVal> = d
            .seals(b)?
            .into_iter()
            .filter_map(|(_, t)| untag(&t))
            .collect();
        Ok(by_lsn.into_iter().collect())
    }

    /// Drop the layer at `lsn`, fast: while the Vessel runs its branch stands
    /// on the orphan of a failed Seal, so this refuses ("has layers on top"),
    /// and the Chronicle stops until the open's [`Layers::destroy_orphan`].
    fn destroy(&mut self, lsn: Lsn) -> Result<(), LayerError> {
        let mut d = self.blkd.lock().unwrap();
        let b = self.branch(&mut *d)?;
        if let Some((layer, _)) = seal_at(&mut *d, b, lsn)? {
            d.drop_layer(layer)?;
            d.flush()?;
        }
        Ok(())
    }

    /// At open, nothing running: an orphan the branch stands on is taken
    /// from under it (unseal), and the next rollback counts what it and the
    /// branch held, never sealed (F1, 2026-10-28).  Any other orphan is
    /// dropped as [`Layers::destroy`] drops it.
    fn destroy_orphan(&mut self, lsn: Lsn) -> Result<(), LayerError> {
        let mut d = self.blkd.lock().unwrap();
        let b = self.branch(&mut *d)?;
        let Some((layer, _)) = seal_at(&mut *d, b, lsn)? else {
            return Ok(());
        };
        let info = d.info(b)?;
        if info.parent != Some(layer) {
            d.drop_layer(layer)?;
            d.flush()?;
            return Ok(());
        }
        let n = off_and_back(
            &mut *d,
            &*self.mounts,
            &self.mountpoint,
            &self.dataset,
            b,
            &info,
            |d| d.unseal(b),
        )?;
        self.unsealed += n;
        self.cached = None;
        Ok(())
    }

    /// Back to the layer at `lsn`, which must be bound to `hash` and be the
    /// newest one: the branch stands on it, so a reset is exactly "discard
    /// everything written after it".  Refused, changing nothing, if a later
    /// layer exists, the hash differs, or the mountpoint is mounted from
    /// something else or busy (unmount fails).
    fn rollback(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
        let mut d = self.blkd.lock().unwrap();
        let b = self.branch(&mut *d)?;
        let own = d.seals(b)?;
        let (layer, bound) = seal_at(&mut *d, b, lsn)?
            .ok_or_else(|| format!("no Seal layer {}", self.dataset.seal_snapshot(lsn)))?;
        if bound != hash {
            return Err(format!(
                "Seal layer {} is bound to another record",
                self.dataset.seal_snapshot(lsn)
            )
            .into());
        }
        if let Some(later) = own
            .iter()
            .filter_map(|(_, t)| untag(t))
            .map(|(n, _)| n)
            .find(|n| *n > lsn)
        {
            return Err(format!(
                "a later layer exists ({}); not rolling back",
                self.dataset.seal_snapshot(later)
            )
            .into());
        }
        let info = d.info(b)?;
        if info.parent != Some(layer) {
            return Err(format!(
                "{} does not stand on its newest layer; not rolling back",
                self.dataset
            )
            .into());
        }
        let n = off_and_back(
            &mut *d,
            &*self.mounts,
            &self.mountpoint,
            &self.dataset,
            b,
            &info,
            |d| d.reset(b),
        )?;
        self.discarded = Some(n + std::mem::take(&mut self.unsealed));
        Ok(())
    }
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::Coordinator;
    use crate::segment::Position;
    use crate::vessel::{Host, Vessel};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use taso_blk::client::LayerKind;
    use taso_blk::map::Kind;
    use taso_blk::store::Store;
    use taso_core::model::WardenId;
    use taso_core::record::{Namespace, StreamCut, TurnId, Verdict};

    /// [`Blkd`] over a real block-log store, without devices: attach
    /// hands out `/dev/fake<n>`.  `fail_seal` makes the next seal fail.
    struct StoreBlkd {
        _dir: tempfile::TempDir,
        store: Store,
        devs: HashMap<LayerId, PathBuf>,
        fail_seal: bool,
    }

    impl StoreBlkd {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = Store::create(&dir.path().join("log")).unwrap();
            Self {
                _dir: dir,
                store,
                devs: HashMap::new(),
                fail_seal: false,
            }
        }
    }

    impl Blkd for StoreBlkd {
        fn root(&mut self) -> Result<LayerId, LayerError> {
            Ok(self.store.root_seal()?)
        }
        fn branch(&mut self, seal: LayerId, name: &str) -> Result<LayerId, LayerError> {
            self.store.check_name(name)?;
            let b = self.store.fork(seal)?;
            self.store.name(b, name)?;
            Ok(b)
        }
        fn attach(&mut self, branch: LayerId) -> Result<PathBuf, LayerError> {
            if self.devs.contains_key(&branch) {
                return Err("already attached".into());
            }
            let dev = PathBuf::from(format!("/dev/fake{}", branch.get()));
            self.devs.insert(branch, dev.clone());
            Ok(dev)
        }
        fn seal(&mut self, branch: LayerId, tag: &[u8]) -> Result<LayerId, LayerError> {
            if std::mem::take(&mut self.fail_seal) {
                return Err("injected seal failure".into());
            }
            Ok(self.store.seal_tagged(branch, tag)?)
        }
        fn find(&mut self, name: &str) -> Result<Option<LayerId>, LayerError> {
            Ok(self.store.find(name))
        }
        fn seals(&mut self, branch: LayerId) -> Result<Vec<(LayerId, Vec<u8>)>, LayerError> {
            Ok(self
                .store
                .seals_of(branch)
                .into_iter()
                .map(|l| (l, self.store.tag(l).unwrap().to_vec()))
                .collect())
        }
        fn info(&mut self, l: LayerId) -> Result<Info, LayerError> {
            let kind = self.store.map().kind(l)?;
            Ok(Info {
                kind: if kind == Kind::Branch {
                    LayerKind::Branch
                } else {
                    LayerKind::Seal
                },
                parent: self.store.map().parent(l)?,
                name: self.store.name_of(l).map(str::to_string),
                tag: self.store.tag(l).map(<[u8]>::to_vec),
                origin: self.store.origin(l),
                dev: self.devs.get(&l).cloned(),
            })
        }
        fn drop_layer(&mut self, l: LayerId) -> Result<(), LayerError> {
            if self.store.map().kind(l)? == Kind::Branch {
                self.devs.remove(&l);
                self.store.drop_branch(l)?;
            } else {
                self.store.drop_seal(l)?;
            }
            Ok(())
        }
        fn detach(&mut self, branch: LayerId) -> Result<(), LayerError> {
            self.devs
                .remove(&branch)
                .map(|_| ())
                .ok_or_else(|| format!("{branch} is not attached").into())
        }
        fn reset(&mut self, branch: LayerId) -> Result<u64, LayerError> {
            if self.devs.contains_key(&branch) {
                return Err("attached; detach first".into());
            }
            Ok(self.store.reset(branch)?)
        }
        fn unseal(&mut self, branch: LayerId) -> Result<u64, LayerError> {
            if self.devs.contains_key(&branch) {
                return Err("attached; detach first".into());
            }
            Ok(self.store.unseal(branch)?)
        }
        fn export(
            &mut self,
            to: LayerId,
            from: Option<LayerId>,
            path: &Path,
        ) -> Result<u64, LayerError> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            Ok(self.store.export(to, from, &mut f)?)
        }
        fn import(&mut self, branch: LayerId, path: &Path) -> Result<u64, LayerError> {
            if self.devs.contains_key(&branch) {
                return Err("attached".into());
            }
            Ok(self.store.import(branch, &mut std::fs::File::open(path)?)?)
        }
        fn names(&mut self) -> Result<Vec<(String, LayerId)>, LayerError> {
            Ok(self.store.names())
        }
        fn flush(&mut self) -> Result<(), LayerError> {
            self.store.flush()?;
            Ok(())
        }
    }

    /// An in-memory mount table that records every call.
    #[derive(Default)]
    struct FakeMounts {
        table: RefCell<HashMap<PathBuf, PathBuf>>,
        frozen: RefCell<Vec<PathBuf>>,
        calls: RefCell<Vec<String>>,
        fail_mkfs: RefCell<bool>,
        busy: RefCell<bool>,
        fail_thaw: RefCell<bool>,
    }

    impl Mounts for FakeMounts {
        fn mkfs(&self, dev: &Path) -> io::Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("mkfs {}", dev.display()));
            if *self.fail_mkfs.borrow() {
                return Err(io::Error::other("mkfs failed"));
            }
            Ok(())
        }
        fn mount(&self, dev: &Path, dir: &Path) -> io::Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("mount {} {}", dev.display(), dir.display()));
            self.table
                .borrow_mut()
                .insert(dir.to_path_buf(), dev.to_path_buf());
            Ok(())
        }
        fn mount_ro(&self, dev: &Path, dir: &Path) -> io::Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("mount-ro {} {}", dev.display(), dir.display()));
            self.table
                .borrow_mut()
                .insert(dir.to_path_buf(), dev.to_path_buf());
            Ok(())
        }
        fn source(&self, dir: &Path) -> io::Result<Option<PathBuf>> {
            Ok(self.table.borrow().get(dir).cloned())
        }
        fn umount(&self, dir: &Path) -> io::Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("umount {}", dir.display()));
            if *self.busy.borrow() {
                return Err(io::Error::other("target is busy"));
            }
            self.table
                .borrow_mut()
                .remove(dir)
                .map(|_| ())
                .ok_or_else(|| io::Error::other("not mounted"))
        }
        fn freeze(&self, dir: &Path) -> io::Result<()> {
            assert!(
                self.table.borrow().contains_key(dir),
                "froze {} which is not a mount",
                dir.display()
            );
            self.calls
                .borrow_mut()
                .push(format!("freeze {}", dir.display()));
            self.frozen.borrow_mut().push(dir.to_path_buf());
            Ok(())
        }
        fn thaw(&self, dir: &Path) -> io::Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("thaw {}", dir.display()));
            if *self.fail_thaw.borrow() {
                return Err(io::Error::other("device gone"));
            }
            self.frozen.borrow_mut().retain(|d| d != dir);
            Ok(())
        }
    }

    type TestPool = BlkPool<StoreBlkd, FakeMounts>;

    fn pool() -> TestPool {
        let spool = tempfile::tempdir().unwrap().keep();
        BlkPool::with(StoreBlkd::new(), FakeMounts::default(), "/mnt/taso", spool)
    }

    fn ds(n: &str) -> Dataset {
        Dataset::new(n).unwrap()
    }

    fn h(b: u8) -> HashVal {
        HashVal::from_bytes([b; 32])
    }

    fn calls(p: &TestPool) -> Vec<String> {
        std::mem::take(&mut *p.mounts.calls.borrow_mut())
    }

    #[test]
    fn tags_round_trip_and_other_tags_are_not_ours() {
        let t = tag(Lsn::new(7), h(9));
        assert_eq!(untag(&t), Some((Lsn::new(7), h(9))));
        assert_eq!(untag(&t[..39]), None);
        assert_eq!(untag(b""), None);
    }

    #[test]
    fn mountinfo_is_read_for_the_exact_mount_point() {
        let mi = "\
22 1 252:2 / / rw,relatime shared:1 - ext4 /dev/vda2 rw
90 22 259:3 / /mnt/taso/tank/v-1 rw,relatime shared:50 - ext4 /dev/ublkb3 rw
91 22 259:4 / /mnt/taso/tank/v-1/sub rw - ext4 /dev/ublkb4 rw
92 22 0:50 / /mnt/with\\040space rw - tmpfs tmp\\040fs rw
93 90 259:9 / /mnt/taso/tank/v-1 rw - ext4 /dev/ublkb9 rw
";
        assert_eq!(
            mount_source(mi, Path::new("/mnt/taso/tank/v-1")),
            Some("/dev/ublkb9".into()),
            "the last mount on top wins"
        );
        assert_eq!(
            mount_source(mi, Path::new("/mnt/with space")),
            Some("tmp fs".into())
        );
        assert_eq!(
            mount_source(mi, Path::new("/mnt/taso/tank")),
            None,
            "a directory under / is not a mount point"
        );
        assert_eq!(mount_source(mi, Path::new("/")), Some("/dev/vda2".into()));
    }

    #[test]
    fn create_makes_a_formatted_mounted_void_born_dataset() {
        let p = pool();
        let a = ds("tank/v-a");
        let info = p.create(&a).unwrap();
        assert_eq!(info.mountpoint, Some(PathBuf::from("/mnt/taso/tank/v-a")));
        assert_eq!((info.origin, info.parent), (None, None));
        let dev = {
            let mut d = p.blkd.lock().unwrap();
            let b = d.find("tank/v-a").unwrap().unwrap();
            d.info(b).unwrap().dev.unwrap()
        };
        assert_eq!(
            calls(&p),
            [
                format!("mkfs {}", dev.display()),
                format!("mount {} /mnt/taso/tank/v-a", dev.display())
            ]
        );
        assert!(p.layers(&a).list().unwrap().is_empty());
        assert!(p.create(&a).is_err(), "a dataset is created once");
        assert_eq!(p.info(&ds("tank/none")).unwrap(), None);
    }

    #[test]
    fn a_failed_create_leaves_nothing_to_adopt() {
        let p = pool();
        *p.mounts.fail_mkfs.borrow_mut() = true;
        assert!(p.create(&ds("tank/v-a")).is_err());
        assert_eq!(
            p.info(&ds("tank/v-a")).unwrap(),
            None,
            "no half-made dataset"
        );
        *p.mounts.fail_mkfs.borrow_mut() = false;
        p.create(&ds("tank/v-a")).unwrap();
    }

    #[test]
    fn snapshots_freeze_only_their_own_mount_and_list_in_order() {
        let p = pool();
        let a = ds("tank/v-a");
        p.create(&a).unwrap();
        calls(&p);
        let mut l = p.layers(&a);
        l.snapshot(Lsn::new(2), h(2)).unwrap();
        l.snapshot(Lsn::new(5), h(5)).unwrap();
        assert_eq!(
            calls(&p),
            [
                "freeze /mnt/taso/tank/v-a",
                "thaw /mnt/taso/tank/v-a",
                "freeze /mnt/taso/tank/v-a",
                "thaw /mnt/taso/tank/v-a"
            ]
        );
        assert_eq!(
            l.list().unwrap(),
            [(Lsn::new(2), h(2)), (Lsn::new(5), h(5))]
        );
        assert!(l.snapshot(Lsn::new(5), h(6)).is_err(), "one layer per lsn");
        assert_eq!(l.list().unwrap().len(), 2);
    }

    #[test]
    fn a_mountpoint_mounted_from_elsewhere_is_never_frozen() {
        let p = pool();
        let a = ds("tank/v-a");
        p.create(&a).unwrap();
        p.mounts
            .table
            .borrow_mut()
            .insert("/mnt/taso/tank/v-a".into(), "/dev/sda1".into());
        calls(&p);
        assert!(p.layers(&a).snapshot(Lsn::new(2), h(2)).is_err());
        assert!(calls(&p).is_empty(), "no freeze, no seal");
        assert!(p.layers(&a).list().unwrap().is_empty());
    }

    #[test]
    fn the_thaw_runs_when_the_seal_fails() {
        let p = pool();
        let a = ds("tank/v-a");
        p.create(&a).unwrap();
        calls(&p);
        p.blkd.lock().unwrap().fail_seal = true;
        assert!(p.layers(&a).snapshot(Lsn::new(2), h(2)).is_err());
        assert_eq!(
            calls(&p),
            ["freeze /mnt/taso/tank/v-a", "thaw /mnt/taso/tank/v-a"]
        );
        assert!(p.mounts.frozen.borrow().is_empty());
    }

    #[test]
    fn a_failed_thaw_is_named_even_when_the_seal_failed_too() {
        let p = pool();
        let a = ds("tank/v-a");
        p.create(&a).unwrap();
        // Thaw alone fails: its error comes back, not a false success.
        *p.mounts.fail_thaw.borrow_mut() = true;
        let e = p
            .layers(&a)
            .snapshot(Lsn::new(2), h(2))
            .unwrap_err()
            .to_string();
        assert!(e.contains("device gone"), "{e}");
        // Both fail: one error names both and the mount that is still frozen.
        p.blkd.lock().unwrap().fail_seal = true;
        let e = p
            .layers(&a)
            .snapshot(Lsn::new(3), h(3))
            .unwrap_err()
            .to_string();
        assert!(e.contains("seal failed"), "{e}");
        assert!(e.contains("device gone"), "{e}");
        assert!(e.contains("/mnt/taso/tank/v-a is still frozen"), "{e}");
    }

    #[test]
    fn an_unmounted_branch_is_sealed_without_a_freeze() {
        let p = pool();
        let a = ds("tank/v-a");
        p.create(&a).unwrap();
        p.mounts.table.borrow_mut().clear(); // as after a reboot
        calls(&p);
        p.layers(&a).snapshot(Lsn::new(2), h(2)).unwrap();
        assert!(calls(&p).is_empty());
        assert_eq!(p.layers(&a).list().unwrap(), [(Lsn::new(2), h(2))]);
    }

    #[test]
    fn clones_carry_origin_and_parent_like_zfs() {
        let p = pool();
        let (a, c) = (ds("tank/v-a"), ds("tank/v-c"));
        p.create(&a).unwrap();
        p.layers(&a).snapshot(Lsn::new(2), h(2)).unwrap();
        p.layers(&a).snapshot(Lsn::new(4), h(4)).unwrap();
        assert!(
            Pool::clone(&p, &a, Lsn::new(2), h(9), &c).is_err(),
            "bound to another record"
        );
        assert!(
            Pool::clone(&p, &a, Lsn::new(3), h(3), &c).is_err(),
            "no such layer"
        );
        assert_eq!(p.info(&c).unwrap(), None, "refusals make nothing");
        calls(&p);
        let info = Pool::clone(&p, &a, Lsn::new(2), h(2), &c).unwrap();
        assert_eq!(
            info.origin.as_deref(),
            Some(a.seal_snapshot(Lsn::new(2)).as_str())
        );
        assert_eq!(info.parent, Some(h(2)));
        assert_eq!(info.origin_seal(), Some((a.clone(), Lsn::new(2))));
        let mounted = calls(&p);
        assert_eq!(mounted.len(), 1, "mounted, not formatted: {mounted:?}");
        assert!(mounted[0].starts_with("mount ") && mounted[0].ends_with(" /mnt/taso/tank/v-c"));
        assert!(
            p.layers(&c).list().unwrap().is_empty(),
            "a clone has no layers of its own"
        );
        p.layers(&c).snapshot(Lsn::new(3), h(33)).unwrap();
        assert_eq!(
            p.info(&c).unwrap().unwrap().origin_seal(),
            Some((a.clone(), Lsn::new(2))),
            "own Seals do not change the origin"
        );
        assert_eq!(
            p.layers(&a).list().unwrap().len(),
            2,
            "the source keeps its layers"
        );
        assert!(
            Pool::clone(&p, &a, Lsn::new(2), h(2), &c).is_err(),
            "a target is made once"
        );
    }

    #[test]
    fn destroy_drops_orphans_and_refuses_layers_that_carry_clones() {
        let p = pool();
        let (a, c) = (ds("tank/v-a"), ds("tank/v-c"));
        p.create(&a).unwrap();
        let mut l = p.layers(&a);
        l.snapshot(Lsn::new(2), h(2)).unwrap();
        l.snapshot(Lsn::new(4), h(4)).unwrap();
        l.destroy(Lsn::new(9)).unwrap(); // absent: fine
        Pool::clone(&p, &a, Lsn::new(2), h(2), &c).unwrap();
        assert!(l.destroy(Lsn::new(2)).is_err(), "the clone stands on it");
        assert_eq!(l.list().unwrap().len(), 2);
    }

    #[test]
    fn the_open_takes_an_orphan_from_under_its_branch_and_the_rollback_counts_it() {
        // F1, 2026-10-28: a Seal's layer taken, its record never accepted.
        let p = pool();
        let a = ds("tank/v-a");
        p.create(&a).unwrap();
        let mut l = p.layers(&a);
        write0(&p, &a, 1);
        l.snapshot(Lsn::new(2), h(2)).unwrap();
        write0(&p, &a, 2);
        l.snapshot(Lsn::new(5), h(5)).unwrap(); // the orphan
        calls(&p);
        assert!(
            l.destroy(Lsn::new(5)).is_err(),
            "while running: refused at once, nothing unmounted"
        );
        assert!(calls(&p).is_empty());
        l.destroy_orphan(Lsn::new(5)).unwrap();
        assert_eq!(
            l.list().unwrap(),
            [(Lsn::new(2), h(2))],
            "the orphan is gone"
        );
        assert_eq!(block0(&p, &a), 1, "reads as the Seal at lsn 2");
        let c = calls(&p);
        assert_eq!(c[0], "umount /mnt/taso/tank/v-a", "{c:?}");
        assert!(c[1].starts_with("mount "), "remounted: {c:?}");
        l.rollback(Lsn::new(2), h(2)).unwrap();
        assert_eq!(
            l.discarded_blocks(),
            Some(1),
            "the orphan's block, lost as a reset's would be, is named (D93 (i))"
        );
        l.snapshot(Lsn::new(7), h(7)).unwrap();
        assert_eq!(l.list().unwrap().len(), 2, "Seals go on as before");
    }

    // ── P4 file 4b-0: Seal views and destroying a dataset ───────────

    #[test]
    fn a_seal_view_is_a_read_only_throwaway_branch_gone_when_dropped() {
        let p = pool();
        let a = ds("tank/v-a");
        p.create(&a).unwrap();
        p.layers(&a).snapshot(Lsn::new(3), h(3)).unwrap();
        assert!(p.seal_view(&a, Lsn::new(9)).is_err(), "no such Seal");
        calls(&p);
        let view = p.seal_view(&a, Lsn::new(3)).unwrap();
        assert_eq!(view.path(), Path::new("/mnt/taso/.views/tank/v-a.view-3"));
        let (vb, dev) = {
            let mut d = p.blkd.lock().unwrap();
            let vb = d
                .find("tank/v-a.view-3")
                .unwrap()
                .expect("the view's branch");
            (vb, d.info(vb).unwrap().dev.unwrap())
        };
        assert_eq!(
            calls(&p),
            [format!(
                "mount-ro {} /mnt/taso/.views/tank/v-a.view-3",
                dev.display()
            )]
        );
        // While the view is open the dataset cannot be destroyed.
        let g = p.guid(&a).unwrap().unwrap();
        assert!(
            Pool::destroy(&p, &a, g).is_err(),
            "the view stands on its Seal"
        );
        drop(view);
        assert_eq!(calls(&p), ["umount /mnt/taso/.views/tank/v-a.view-3"]);
        let mut d = p.blkd.lock().unwrap();
        assert_eq!(
            d.find("tank/v-a.view-3").unwrap(),
            None,
            "the branch is dropped"
        );
        assert!(d.info(vb).is_err());
    }

    #[test]
    fn a_view_left_by_a_crash_is_taken_down_first() {
        let p = pool();
        let a = ds("tank/v-a");
        p.create(&a).unwrap();
        p.layers(&a).snapshot(Lsn::new(3), h(3)).unwrap();
        std::mem::forget(p.seal_view(&a, Lsn::new(3)).unwrap());
        calls(&p);
        let view = p.seal_view(&a, Lsn::new(3)).unwrap();
        let c = calls(&p);
        assert_eq!(c[0], "umount /mnt/taso/.views/tank/v-a.view-3", "{c:?}");
        assert!(c[1].starts_with("mount-ro "));
        drop(view);
    }

    #[test]
    fn destroy_takes_a_dataset_and_its_own_layers_by_guid() {
        let p = pool();
        let (a, c) = (ds("tank/v-a"), ds("tank/v-c"));
        assert_eq!(p.guid(&a).unwrap(), None);
        assert!(!Pool::destroy(&p, &a, 1).unwrap(), "nothing to destroy");
        p.create(&a).unwrap();
        p.layers(&a).snapshot(Lsn::new(2), h(2)).unwrap();
        p.layers(&a).snapshot(Lsn::new(4), h(4)).unwrap();
        let g = p.guid(&a).unwrap().unwrap();
        // A clone on one of its layers: refused, nothing touched.
        Pool::clone(&p, &a, Lsn::new(2), h(2), &c).unwrap();
        calls(&p);
        assert!(Pool::destroy(&p, &a, g).is_err());
        assert!(calls(&p).is_empty(), "nothing unmounted");
        assert_eq!(p.layers(&a).list().unwrap().len(), 2);
        // The clone goes first (it has no layers of its own), then a.
        let gc = p.guid(&c).unwrap().unwrap();
        assert!(Pool::destroy(&p, &c, gc).unwrap());
        assert_eq!(p.layers(&a).list().unwrap().len(), 2, "a's layers stay");
        assert!(
            Pool::destroy(&p, &a, g + 1).is_err(),
            "another guid: refused"
        );
        let layers: Vec<LayerId> = {
            let mut d = p.blkd.lock().unwrap();
            let b = d.find("tank/v-a").unwrap().unwrap();
            let mut v = Vec::new();
            let mut cur = d.info(b).unwrap().parent;
            while let Some(l) = cur {
                v.push(l);
                cur = d.info(l).unwrap().parent;
            }
            v
        };
        assert_eq!(layers.len(), 3, "two Seals and the root");
        assert!(Pool::destroy(&p, &a, g).unwrap());
        {
            let mut d = p.blkd.lock().unwrap();
            for l in &layers {
                assert!(d.info(*l).is_err(), "layer {l} is dropped");
            }
        }
        assert_eq!(p.info(&a).unwrap(), None);
        assert!(calls(&p).contains(&"umount /mnt/taso/tank/v-a".to_string()));
        // Every layer it made is gone: only the store's own state is left.
        let mut d = p.blkd.lock().unwrap();
        assert!(d.names().unwrap().is_empty());
        drop(d);
        // A new dataset of the same name has another guid.
        p.create(&a).unwrap();
        assert_ne!(p.guid(&a).unwrap(), Some(g));
    }

    #[test]
    fn ensure_mounted_reattaches_after_a_restart() {
        let p = pool();
        let a = ds("tank/v-a");
        p.create(&a).unwrap();
        p.blkd.lock().unwrap().devs.clear(); // the daemon restarted: devices are lazy
        p.mounts.table.borrow_mut().clear();
        calls(&p);
        let dev = p.ensure_mounted(&a).unwrap();
        assert_eq!(
            calls(&p),
            [format!("mount {} /mnt/taso/tank/v-a", dev.display())]
        );
        assert_eq!(p.ensure_mounted(&a).unwrap(), dev);
        assert!(calls(&p).is_empty(), "already mounted: nothing to do");
    }

    #[test]
    fn guids_follow_the_binding_and_names_parse() {
        assert_eq!(guid(Lsn::new(3), h(1)), guid(Lsn::new(3), h(1)));
        assert_ne!(guid(Lsn::new(3), h(1)), guid(Lsn::new(4), h(1)));
        assert_ne!(guid(Lsn::new(3), h(1)), guid(Lsn::new(3), h(2)));
        let a = ds("tank/v-a");
        assert_eq!(
            parse_seal_name(&a.seal_snapshot(Lsn::new(7))),
            Some((a, Lsn::new(7)))
        );
        assert_eq!(parse_seal_name("tank/v-a@other-7"), None);
        assert_eq!(parse_seal_name("tank/v-a"), None);
    }

    #[test]
    fn snapshots_children_and_owner_uids() {
        let mounts = tempfile::tempdir().unwrap();
        let p = BlkPool::with(
            StoreBlkd::new(),
            FakeMounts::default(),
            mounts.path(),
            mounts.path().join("spool"),
        );
        let (a, c) = (ds("tank/vessels/v-a"), ds("tank/vessels/v-c"));
        p.create(&a).unwrap();
        p.create(&c).unwrap();
        p.create(&ds("tank/other")).unwrap();
        p.create(&ds("tank/vessels/v-a/deeper")).unwrap();
        p.layers(&a).snapshot(Lsn::new(2), h(2)).unwrap();
        let snap = p.snapshot(&a, Lsn::new(2)).unwrap().unwrap();
        assert_eq!(
            (snap.name(), snap.guid, snap.seal_hash),
            (
                a.seal_snapshot(Lsn::new(2)),
                guid(Lsn::new(2), h(2)),
                Some(h(2))
            )
        );
        assert_eq!(p.snapshot(&a, Lsn::new(3)).unwrap(), None);
        assert_eq!(p.snapshot(&ds("tank/none"), Lsn::new(2)).unwrap(), None);
        assert_eq!(
            p.children(&ds("tank/vessels")).unwrap(),
            [a.clone(), c.clone()],
            "direct children only"
        );
        // owner_uids walks the mounted tree (here a plain directory).
        let mp = p.mountpoint(&a);
        std::fs::create_dir_all(mp.join("d")).unwrap();
        std::fs::write(mp.join("d/f"), b"x").unwrap();
        let me = std::fs::metadata(&mp)
            .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
            .unwrap();
        assert_eq!(
            p.owner_uids(&a).unwrap().into_iter().collect::<Vec<_>>(),
            [me]
        );
    }

    /// A stream of `to`, from node `src` (incremental from `from`).
    fn sent(src: &TestPool, d: &Dataset, from: Option<&str>, to: Lsn) -> Vec<u8> {
        let mut out = Vec::new();
        io::copy(&mut src.sender().send(d, from, to).unwrap(), &mut out).unwrap();
        out
    }

    #[test]
    fn seals_travel_between_nodes_by_send_and_receive() {
        let (na, nb) = (pool(), pool());
        let (a, c) = (ds("tank/v-a"), ds("tank/v-c"));
        na.create(&a).unwrap();
        write0(&na, &a, 1);
        na.layers(&a).snapshot(Lsn::new(2), h(2)).unwrap();
        write0(&na, &a, 2);
        na.layers(&a).snapshot(Lsn::new(5), h(5)).unwrap();

        // Full, then incremental, as rebirth does.
        let g = nb
            .receive(
                &a,
                None,
                (Lsn::new(2), h(2)),
                &mut &sent(&na, &a, None, Lsn::new(2))[..],
            )
            .unwrap();
        assert_eq!(g, guid(Lsn::new(2), h(2)));
        assert_eq!(block0(&nb, &a), 1);
        let inc = sent(&na, &a, Some(&a.seal_snapshot(Lsn::new(2))), Lsn::new(5));
        nb.receive(
            &a,
            Some((Lsn::new(2), h(2))),
            (Lsn::new(5), h(5)),
            &mut &inc[..],
        )
        .unwrap();
        assert_eq!(block0(&nb, &a), 2);
        assert_eq!(nb.layers(&a).list().unwrap(), na.layers(&a).list().unwrap());
        // Again: already there, bound: returns the guid, changes nothing.
        assert_eq!(
            nb.receive(
                &a,
                Some((Lsn::new(2), h(2))),
                (Lsn::new(5), h(5)),
                &mut io::empty()
            )
            .unwrap(),
            guid(Lsn::new(5), h(5))
        );
        assert!(
            nb.receive(
                &a,
                Some((Lsn::new(2), h(2))),
                (Lsn::new(5), h(6)),
                &mut io::empty()
            )
            .is_err(),
            "bound to another record"
        );

        // A clone of a's first Seal, received as a clone on the other node.
        Pool::clone(&na, &a, Lsn::new(2), h(2), &c).unwrap();
        write0(&na, &c, 9);
        na.layers(&c).snapshot(Lsn::new(3), h(33)).unwrap();
        let first = sent(&na, &c, Some(&a.seal_snapshot(Lsn::new(2))), Lsn::new(3));
        let base = CloneBase {
            dataset: a.clone(),
            seal: Lsn::new(2),
            hash: h(2),
            guid: guid(Lsn::new(2), h(2)),
        };
        let wrong = CloneBase {
            guid: 1,
            ..base.clone()
        };
        assert!(
            nb.receive_clone(&c, &wrong, (Lsn::new(3), h(33)), &mut &first[..])
                .is_err(),
            "base guid checked"
        );
        assert_eq!(nb.info(&c).unwrap(), None);
        nb.receive_clone(&c, &base, (Lsn::new(3), h(33)), &mut &first[..])
            .unwrap();
        assert_eq!(block0(&nb, &c), 9);
        assert_eq!(
            nb.info(&c).unwrap().unwrap().origin_seal(),
            Some((a.clone(), Lsn::new(2)))
        );
        assert!(
            std::fs::read_dir(&nb.spool).unwrap().next().is_none(),
            "the spool is left empty"
        );
        assert!(
            std::fs::read_dir(&na.spool).unwrap().next().is_none(),
            "the spool is left empty"
        );
    }

    #[test]
    fn a_bad_stream_received_leaves_nothing() {
        let (na, nb) = (pool(), pool());
        let a = ds("tank/v-a");
        na.create(&a).unwrap();
        write0(&na, &a, 1);
        na.layers(&a).snapshot(Lsn::new(2), h(2)).unwrap();
        write0(&na, &a, 2);
        na.layers(&a).snapshot(Lsn::new(5), h(5)).unwrap();
        let full = sent(&na, &a, None, Lsn::new(2));
        assert!(nb
            .receive(
                &a,
                None,
                (Lsn::new(2), h(2)),
                &mut &full[..full.len() - 1][..]
            )
            .is_err());
        assert_eq!(nb.info(&a).unwrap(), None, "no half-received dataset");
        nb.receive(&a, None, (Lsn::new(2), h(2)), &mut &full[..])
            .unwrap();
        let inc = sent(&na, &a, Some(&a.seal_snapshot(Lsn::new(2))), Lsn::new(5));
        let mut bad = inc.clone();
        bad[20] ^= 1;
        assert!(nb
            .receive(
                &a,
                Some((Lsn::new(2), h(2))),
                (Lsn::new(5), h(5)),
                &mut &bad[..]
            )
            .is_err());
        assert_eq!(
            nb.layers(&a).list().unwrap(),
            [(Lsn::new(2), h(2))],
            "no Seal from a bad stream"
        );
        assert_eq!(block0(&nb, &a), 1, "and none of its blocks");
        nb.receive(
            &a,
            Some((Lsn::new(2), h(2))),
            (Lsn::new(5), h(5)),
            &mut &inc[..],
        )
        .unwrap();
        assert_eq!(block0(&nb, &a), 2);
    }

    /// The bytes of block 0 of the dataset's branch, through the store.
    fn block0(p: &TestPool, a: &Dataset) -> u8 {
        let d = p.blkd.lock().unwrap();
        let b = d.store.find(a.as_str()).unwrap();
        let mut buf = vec![0u8; 4096];
        d.store.read(b, 0, &mut buf).unwrap();
        buf[0]
    }

    fn write0(p: &TestPool, a: &Dataset, v: u8) {
        let mut d = p.blkd.lock().unwrap();
        let b = d.store.find(a.as_str()).unwrap();
        d.store.write(b, 0, &[v; 4096], false).unwrap();
    }

    #[test]
    fn rollback_discards_what_came_after_the_newest_layer_and_remounts() {
        let p = pool();
        let a = ds("tank/v-a");
        p.create(&a).unwrap();
        let mut l = p.layers(&a);
        write0(&p, &a, 1);
        l.snapshot(Lsn::new(2), h(2)).unwrap();
        write0(&p, &a, 2);
        calls(&p);
        assert_eq!(l.discarded_blocks(), None, "nothing rolled back yet");
        l.rollback(Lsn::new(2), h(2)).unwrap();
        assert_eq!(block0(&p, &a), 1, "back to the layer");
        assert_eq!(
            l.discarded_blocks(),
            Some(1),
            "the one block written after the Seal is what the reset discarded (D93 (i))"
        );
        let c = calls(&p);
        assert_eq!(c.len(), 2, "{c:?}");
        assert_eq!(c[0], "umount /mnt/taso/tank/v-a");
        assert!(
            c[1].starts_with("mount ") && c[1].ends_with(" /mnt/taso/tank/v-a"),
            "{c:?}"
        );
        assert_eq!(l.list().unwrap(), [(Lsn::new(2), h(2))], "the layer stays");
        assert_eq!(p.info(&a).unwrap().unwrap().origin, None);
    }

    #[test]
    fn rollback_refuses_and_changes_nothing() {
        let p = pool();
        let a = ds("tank/v-a");
        p.create(&a).unwrap();
        let mut l = p.layers(&a);
        l.snapshot(Lsn::new(2), h(2)).unwrap();
        l.snapshot(Lsn::new(4), h(4)).unwrap();
        write0(&p, &a, 9);
        calls(&p);
        assert!(l
            .rollback(Lsn::new(2), h(2))
            .unwrap_err()
            .to_string()
            .contains("later layer"));
        assert!(
            l.rollback(Lsn::new(4), h(5)).is_err(),
            "bound to another record"
        );
        assert!(l.rollback(Lsn::new(3), h(3)).is_err(), "no such layer");
        *p.mounts.busy.borrow_mut() = true;
        assert!(l.rollback(Lsn::new(4), h(4)).is_err(), "busy mount");
        *p.mounts.busy.borrow_mut() = false;
        p.mounts
            .table
            .borrow_mut()
            .insert("/mnt/taso/tank/v-a".into(), "/dev/sda1".into());
        assert!(
            l.rollback(Lsn::new(4), h(4)).is_err(),
            "mounted from elsewhere"
        );
        assert_eq!(block0(&p, &a), 9, "nothing was discarded");
        assert!(
            calls(&p).iter().all(|c| c.starts_with("umount")),
            "only the refused unmount was tried"
        );
    }

    // ── Vessels on the block log ────────────────────────────────────

    fn host(dir: &Path) -> Host<TestPool> {
        Host {
            coord: Arc::new(Coordinator::open(dir.join("coord.redb")).unwrap()),
            pool: pool(),
            root: ds("tank/vessels"),
            state_dir: dir.join("state"),
            warden: WardenId::new(1),
        }
    }

    fn seal<L: Layers>(v: &mut Vessel<L>, turn: u64) -> Position {
        v.seal(
            StreamCut::EMPTY,
            Verdict::Clean,
            Lsn::new(0),
            TurnId::new(turn),
        )
        .unwrap()
        .seal
    }

    #[test]
    fn vessels_are_born_sealed_forked_and_reopened_on_the_block_log() {
        let tmp = tempfile::tempdir().unwrap();
        let host = host(tmp.path());
        let ns = Namespace::from_bytes([1; 16]);
        let (mut v, _) = host.ensure(ns, b"user-1").unwrap();
        let birth = v.seal_birth().unwrap().seal;
        let s1 = seal(&mut v, 1);
        let layers = host.pool.layers(v.dataset()).list().unwrap();
        assert_eq!(
            layers,
            [(birth.lsn, birth.hash), (s1.lsn, s1.hash)],
            "a block-log Seal per Seal record"
        );

        let child = host.fork(&v, s1, b"child-1").unwrap();
        let info = host.pool.info(child.dataset()).unwrap().unwrap();
        assert_eq!(
            (info.origin_seal(), info.parent),
            (Some((v.dataset().clone(), s1.lsn)), Some(s1.hash))
        );
        drop(child);

        let id = v.id();
        drop(v);
        let (mut v, _) = host.open(id).unwrap(); // the lineage and layer checks pass on the block log
        assert_eq!(v.last_seal(), Some(s1));

        // A Vessel rollback goes back to the last Seal's blocks.
        write0(&host.pool, v.dataset(), 7);
        assert_eq!(v.rollback().unwrap(), Some(s1));
        assert_eq!(
            block0(&host.pool, v.dataset()),
            0,
            "the write after the last Seal is gone"
        );
    }

    #[test]
    fn a_vessel_and_its_fork_are_reborn_on_another_block_log_node() {
        use crate::pack::Packs;
        use crate::ship::LocalStore;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("store")).unwrap();
        let coord = Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap());
        let node = |n: u64| Host {
            coord: coord.clone(),
            pool: pool(),
            root: ds("tank/vessels"),
            state_dir: tmp.path().join(format!("node-{n}")),
            warden: WardenId::new(n),
        };
        let (a, b) = (node(1), node(2));
        let packs = |h: &Host<TestPool>, id| {
            Packs::new(
                LocalStore::new(tmp.path().join("store")),
                h.pool.sender(),
                "vessels",
                id,
            )
            .unwrap()
        };
        let ns = Namespace::from_bytes([3; 16]);

        // Node A: a Vessel with two published Seals, and a fork of the first.
        let (mut v, _) = a.ensure(ns, b"user").unwrap();
        let pa = packs(&a, v.id());
        let birth = v.seal_birth().unwrap().seal;
        v.publish_seal(
            &pa,
            &a.pool.snapshot(v.dataset(), birth.lsn).unwrap().unwrap(),
            None,
        )
        .unwrap();
        write0(&a.pool, v.dataset(), 1);
        let s1 = seal(&mut v, 1);
        v.publish_seal(
            &pa,
            &a.pool.snapshot(v.dataset(), s1.lsn).unwrap().unwrap(),
            None,
        )
        .unwrap();
        write0(&a.pool, v.dataset(), 2);
        let s2 = seal(&mut v, 2);
        v.publish_seal(
            &pa,
            &a.pool.snapshot(v.dataset(), s2.lsn).unwrap().unwrap(),
            None,
        )
        .unwrap();

        let mut child = a.fork(&v, s1, b"child").unwrap();
        let pc = packs(&a, child.id());
        let cb = child.seal_birth().unwrap().seal;
        let origin = a.pool.snapshot(v.dataset(), s1.lsn).unwrap().unwrap();
        child
            .publish_seal(
                &pc,
                &a.pool.snapshot(child.dataset(), cb.lsn).unwrap().unwrap(),
                Some(&origin),
            )
            .unwrap();
        write0(&a.pool, child.dataset(), 7);
        let c1 = seal(&mut child, 1);
        child
            .publish_seal(
                &pc,
                &a.pool.snapshot(child.dataset(), c1.lsn).unwrap().unwrap(),
                None,
            )
            .unwrap();

        // Node B: rebirth from the packs alone.
        let (w, r) = b.rebirth(v.id(), &packs(&b, v.id())).unwrap();
        assert_eq!(r.received, vec![birth.lsn, s1.lsn, s2.lsn]);
        assert_eq!(w.last_seal(), Some(s2));
        assert_eq!(
            block0(&b.pool, w.dataset()),
            2,
            "the state of the last Seal"
        );
        assert_eq!(
            b.pool.layers(w.dataset()).list().unwrap(),
            a.pool.layers(v.dataset()).list().unwrap()
        );

        let (wc, rc) = b.rebirth(child.id(), &packs(&b, child.id())).unwrap();
        assert_eq!(rc.received, vec![cb.lsn, c1.lsn]);
        assert_eq!(block0(&b.pool, wc.dataset()), 7);
        let info = b.pool.info(wc.dataset()).unwrap().unwrap();
        assert_eq!(
            (info.origin_seal(), info.parent),
            (Some((w.dataset().clone(), s1.lsn)), Some(s1.hash))
        );
    }
}
