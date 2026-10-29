//! Where a node keeps its Vessels: ZFS or the block log, chosen per node
//! by the configuration (`"storage"`).
//!
//! [`Storage`] implements [`Pool`], [`StorageLayers`] implements
//! [`Layers`] and [`StorageSend`] implements [`Sender`], each by passing
//! the call to the one the node uses.  The daemon holds a `Storage`, so
//! nothing above it knows which one it is.
//!
//! The types both engines speak in -- [`Dataset`], [`Snapshot`],
//! [`DatasetInfo`], [`CloneBase`] and the Seal snapshot naming -- live
//! here, so neither engine depends on the other's module.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::PathBuf;

use taso_core::envelope::{HashVal, Lsn};

use crate::blk::{BlkLayers, BlkPool, BlkSend};
use crate::chronicle::{LayerError, Layers, ZfsLayers};
use crate::ship::{ByteStream, Sender, ZfsSend};
use crate::vessel::{Pool, SealView};
use crate::zfs::{Cli, Zfs};

/// A node's storage.
#[derive(Clone)]
pub enum Storage {
    /// ZFS: a Vessel is a dataset, a Seal a snapshot.
    Zfs(Zfs<Cli>),
    /// The block log: a Vessel is a named branch, a Seal a block-log Seal.
    Blk(BlkPool),
}

/// The Seal layers of one dataset, in either storage.
pub enum StorageLayers {
    /// ZFS snapshots.
    Zfs(ZfsLayers<Cli>),
    /// Block-log Seals.
    Blk(BlkLayers),
}

/// The send streams of either storage.
pub enum StorageSend {
    /// `zfs send`.
    Zfs(ZfsSend),
    /// `taso-blkd export`.
    Blk(BlkSend),
}

impl Storage {
    /// Which storage this is, for logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Zfs(_) => "zfs",
            Self::Blk(_) => "blk",
        }
    }

    /// The [`Sender`] for this storage's Seals.
    pub fn sender(&self) -> StorageSend {
        match self {
            Self::Zfs(_) => StorageSend::Zfs(ZfsSend::default()),
            Self::Blk(p) => StorageSend::Blk(p.sender()),
        }
    }

    /// The Seal layer of `dataset` at `lsn`, in the shape the publisher
    /// wants; `None` if there is none.
    pub fn snapshot(&self, dataset: &Dataset, lsn: Lsn) -> Result<Option<Snapshot>, LayerError> {
        match self {
            Self::Zfs(z) => Ok(z.get(dataset, lsn)?),
            Self::Blk(p) => p.snapshot(dataset, lsn),
        }
    }

    /// Mount `dataset` if it is not (a reborn one is received unmounted).
    pub fn ensure_mounted(&self, dataset: &Dataset) -> Result<(), LayerError> {
        match self {
            Self::Zfs(z) => Ok(z.ensure_mounted(dataset)?),
            Self::Blk(p) => p.ensure_mounted(dataset).map(|_| ()),
        }
    }
}

/// What the start-up scan of uid slots reads from a pool
/// ([`crate::daemon::held_on`]).
pub trait Holdings {
    /// The datasets directly under `root`.
    fn children(&self, root: &Dataset) -> Result<Vec<Dataset>, LayerError>;
    /// The uids owning files in `dataset`.
    fn owner_uids(&self, dataset: &Dataset) -> Result<BTreeSet<u32>, LayerError>;
    /// The Seal snapshot `dataset` is a clone of, if any (P4 file 5h: a
    /// Template-born Vessel's dataset, before its Lineage is written, is
    /// a clone of its layer).
    fn origin(&self, dataset: &Dataset) -> Result<Option<(Dataset, Lsn)>, LayerError>;
}

impl<R: crate::zfs::Runner> Holdings for Zfs<R> {
    fn children(&self, root: &Dataset) -> Result<Vec<Dataset>, LayerError> {
        Ok(Zfs::children(self, root)?)
    }
    fn owner_uids(&self, dataset: &Dataset) -> Result<BTreeSet<u32>, LayerError> {
        Ok(Zfs::owner_uids(self, dataset)?)
    }
    fn origin(&self, dataset: &Dataset) -> Result<Option<(Dataset, Lsn)>, LayerError> {
        Ok(self.dataset_info(dataset)?.and_then(|i| i.origin_seal()))
    }
}

impl Holdings for Storage {
    fn children(&self, root: &Dataset) -> Result<Vec<Dataset>, LayerError> {
        match self {
            Self::Zfs(z) => Holdings::children(z, root),
            Self::Blk(p) => p.children(root),
        }
    }
    fn owner_uids(&self, dataset: &Dataset) -> Result<BTreeSet<u32>, LayerError> {
        match self {
            Self::Zfs(z) => Holdings::owner_uids(z, dataset),
            Self::Blk(p) => p.owner_uids(dataset),
        }
    }
    fn origin(&self, dataset: &Dataset) -> Result<Option<(Dataset, Lsn)>, LayerError> {
        Ok(Pool::info(self, dataset)?.and_then(|i| i.origin_seal()))
    }
}

impl Pool for Storage {
    type Layers = StorageLayers;

    fn create(&self, dataset: &Dataset) -> Result<DatasetInfo, LayerError> {
        match self {
            Self::Zfs(z) => Pool::create(z, dataset),
            Self::Blk(p) => p.create(dataset),
        }
    }

    fn clone(
        &self,
        source: &Dataset,
        seal: Lsn,
        seal_hash: HashVal,
        target: &Dataset,
    ) -> Result<DatasetInfo, LayerError> {
        match self {
            Self::Zfs(z) => Pool::clone(z, source, seal, seal_hash, target),
            Self::Blk(p) => Pool::clone(p, source, seal, seal_hash, target),
        }
    }

    fn info(&self, dataset: &Dataset) -> Result<Option<DatasetInfo>, LayerError> {
        match self {
            Self::Zfs(z) => Pool::info(z, dataset),
            Self::Blk(p) => p.info(dataset),
        }
    }

    fn layers(&self, dataset: &Dataset) -> StorageLayers {
        match self {
            Self::Zfs(z) => StorageLayers::Zfs(Pool::layers(z, dataset)),
            Self::Blk(p) => StorageLayers::Blk(p.layers(dataset)),
        }
    }

    fn receive(
        &self,
        dataset: &Dataset,
        from: Option<(Lsn, HashVal)>,
        to: (Lsn, HashVal),
        stream: &mut dyn io::Read,
    ) -> Result<u64, LayerError> {
        match self {
            Self::Zfs(z) => Pool::receive(z, dataset, from, to, stream),
            Self::Blk(p) => p.receive(dataset, from, to, stream),
        }
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
        match self {
            Self::Zfs(z) => Pool::adopt(z, dataset, base, to, child, child_seal, sender),
            Self::Blk(p) => p.adopt(dataset, base, to, child, child_seal, sender),
        }
    }

    fn receive_clone(
        &self,
        dataset: &Dataset,
        base: &CloneBase,
        to: (Lsn, HashVal),
        stream: &mut dyn io::Read,
    ) -> Result<u64, LayerError> {
        match self {
            Self::Zfs(z) => Pool::receive_clone(z, dataset, base, to, stream),
            Self::Blk(p) => p.receive_clone(dataset, base, to, stream),
        }
    }

    fn seal_view(&self, dataset: &Dataset, lsn: Lsn) -> Result<SealView, LayerError> {
        match self {
            Self::Zfs(z) => Pool::seal_view(z, dataset, lsn),
            Self::Blk(p) => p.seal_view(dataset, lsn),
        }
    }

    fn guid(&self, dataset: &Dataset) -> Result<Option<u64>, LayerError> {
        match self {
            Self::Zfs(z) => Pool::guid(z, dataset),
            Self::Blk(p) => p.guid(dataset),
        }
    }

    fn destroy(&self, dataset: &Dataset, guid: u64) -> Result<bool, LayerError> {
        match self {
            Self::Zfs(z) => Pool::destroy(z, dataset, guid),
            Self::Blk(p) => Pool::destroy(p, dataset, guid),
        }
    }
}

impl Layers for StorageLayers {
    fn snapshot(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
        match self {
            Self::Zfs(l) => l.snapshot(lsn, hash),
            Self::Blk(l) => l.snapshot(lsn, hash),
        }
    }
    fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError> {
        match self {
            Self::Zfs(l) => l.list(),
            Self::Blk(l) => l.list(),
        }
    }
    fn destroy(&mut self, lsn: Lsn) -> Result<(), LayerError> {
        match self {
            Self::Zfs(l) => l.destroy(lsn),
            Self::Blk(l) => l.destroy(lsn),
        }
    }
    fn destroy_orphan(&mut self, lsn: Lsn) -> Result<(), LayerError> {
        match self {
            Self::Zfs(l) => l.destroy_orphan(lsn),
            Self::Blk(l) => l.destroy_orphan(lsn),
        }
    }
    fn rollback(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
        match self {
            Self::Zfs(l) => l.rollback(lsn, hash),
            Self::Blk(l) => l.rollback(lsn, hash),
        }
    }
    fn discarded_blocks(&self) -> Option<u64> {
        match self {
            Self::Zfs(l) => l.discarded_blocks(),
            Self::Blk(l) => l.discarded_blocks(),
        }
    }
}

impl Sender for StorageSend {
    fn send(&self, dataset: &Dataset, from: Option<&str>, to: Lsn) -> io::Result<ByteStream> {
        match self {
            Self::Zfs(s) => s.send(dataset, from, to),
            Self::Blk(s) => s.send(dataset, from, to),
        }
    }
}

// ── Shared types ───────────────────────────────────────────────────

/// Prefix of every snapshot name Taso makes.
pub const SNAP_PREFIX: &str = "taso-seal-";

/// Digits in the lsn part of a snapshot name (`u64::MAX` has 20).
const LSN_DIGITS: usize = 20;

/// ZFS limits a full name to 255 bytes (`ZFS_MAX_DATASET_NAME_LEN` − 1);
/// the block log keeps the same bound so names mean the same on both.
const MAX_FULL_NAME: usize = 255;

/// Longest dataset name that still leaves room for `@taso-seal-<20 digits>`.
pub const MAX_DATASET_NAME: usize = MAX_FULL_NAME - 1 - SNAP_PREFIX.len() - LSN_DIGITS;

// ── Names ──────────────────────────────────────────────────────────

/// A dataset name rejected before anything ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidName {
    /// The name given.
    pub name: String,
    /// What is wrong with it.
    pub why: &'static str,
}

impl fmt::Display for InvalidName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid dataset name {:?}: {}", self.name, self.why)
    }
}

impl std::error::Error for InvalidName {}

/// A validated dataset name, e.g. `tasotest/vessel`: the name a Vessel's
/// storage goes by on either engine (a ZFS dataset, a block-log branch).
///
/// Components are separated by `/` and may contain only ASCII letters,
/// digits and `_ - . :`.  The pool (first component) starts with a
/// letter.  The name is short enough that every Seal snapshot of it fits
/// ZFS's 255-byte limit.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Dataset(String);

impl Dataset {
    /// Validate a dataset name.
    pub fn new(name: &str) -> Result<Self, InvalidName> {
        let bad = |why| {
            Err(InvalidName {
                name: name.to_string(),
                why,
            })
        };
        if name.is_empty() {
            return bad("empty");
        }
        if name.len() > MAX_DATASET_NAME {
            return bad("too long for a Seal snapshot name");
        }
        if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
            return bad("pool name must start with a letter");
        }
        for component in name.split('/') {
            if component.is_empty() {
                return bad("empty component (leading, trailing or double '/')");
            }
            if component == "." || component == ".." {
                return bad("'.' and '..' are not valid components");
            }
            if !component
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
            {
                return bad("only ASCII letters, digits and _ - . : are allowed");
            }
        }
        Ok(Self(name.to_string()))
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The pool: the first component.
    pub fn pool(&self) -> &str {
        self.0.split('/').next().unwrap_or(&self.0)
    }

    /// The full snapshot name for the Seal at `seal`.
    pub fn seal_snapshot(&self, seal: Lsn) -> String {
        format!("{}@{}", self.0, snap_name(seal))
    }
}

impl fmt::Display for Dataset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The snapshot part of a Seal's name: `taso-seal-` + lsn as 20 digits.
pub fn snap_name(seal: Lsn) -> String {
    format!("{SNAP_PREFIX}{:0width$}", seal.get(), width = LSN_DIGITS)
}

/// The Seal lsn in a snapshot part, if it is a name Taso made.
pub(crate) fn parse_snap_name(snap: &str) -> Option<Lsn> {
    let digits = snap.strip_prefix(SNAP_PREFIX)?;
    if digits.len() != LSN_DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().map(Lsn::new)
}

// ── Snapshot ───────────────────────────────────────────────────────

/// A Seal layer as the engine reports it: a ZFS snapshot, or a block-log
/// Seal described in the same terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The dataset it belongs to.
    pub dataset: Dataset,
    /// The Seal record's lsn, from the name.
    pub seal: Lsn,
    /// The engine's stable id for it (ZFS's guid; the block log derives
    /// one from the Seal); the same on every node it was received on.
    pub guid: u64,
    /// The `taso:seal` property, or `None` if it is unset (made by hand).
    pub seal_hash: Option<HashVal>,
}

impl Snapshot {
    /// The full name, `<dataset>@taso-seal-<lsn>`.
    pub fn name(&self) -> String {
        self.dataset.seal_snapshot(self.seal)
    }
}

/// A dataset as the engine reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatasetInfo {
    /// The dataset.
    pub dataset: Dataset,
    /// Where it is mounted; `None` for `none`, `legacy` or `-`.
    pub mountpoint: Option<PathBuf>,
    /// The snapshot it was cloned from (full name), if it is a clone.
    pub origin: Option<String>,
    /// The `taso:parent` property: the Seal record it was forked from.
    pub parent: Option<HashVal>,
}

impl DatasetInfo {
    /// The origin as a Taso Seal snapshot, `(dataset, seal lsn)`, if it is
    /// one.
    pub fn origin_seal(&self) -> Option<(Dataset, Lsn)> {
        let (ds, snap) = self.origin.as_deref()?.split_once('@')?;
        Some((Dataset::new(ds).ok()?, parse_snap_name(snap)?))
    }
}

/// The parent Seal snapshot a cloned Vessel's first stream is incremental
/// from, as the receiving side expects to find it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloneBase {
    /// The dataset holding the parent's Seal snapshot on this node.
    pub dataset: Dataset,
    /// The parent Seal's lsn.
    pub seal: Lsn,
    /// The parent Seal record's hash.
    pub hash: HashVal,
    /// The snapshot's guid (the same on every node it was received on).
    pub guid: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_dataset_names() {
        for name in ["tasotest", "tasotest/vessel", "pool/a-b_c.d:e/f9"] {
            assert!(Dataset::new(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn invalid_dataset_names() {
        for name in [
            "",
            "/pool",
            "pool/",
            "pool//a",
            "pool@snap",
            "pool/a b",
            "1pool",
            "pool/./a",
            "pool/../a",
            "pool/ä",
            "pool#bm",
        ] {
            assert!(
                matches!(Dataset::new(name), Err(InvalidName { .. })),
                "{name:?} should be invalid",
            );
        }
    }

    #[test]
    fn longest_dataset_still_fits() {
        let longest = format!("p{}", "a".repeat(MAX_DATASET_NAME - 1));
        let d = Dataset::new(&longest).unwrap();
        assert_eq!(d.seal_snapshot(Lsn::new(u64::MAX)).len(), MAX_FULL_NAME);
        let too_long = format!("{longest}a");
        assert!(Dataset::new(&too_long).is_err());
    }

    #[test]
    fn snapshot_names_sort_in_seal_order() {
        assert_eq!(snap_name(Lsn::new(1)), "taso-seal-00000000000000000001");
        assert_eq!(
            snap_name(Lsn::new(u64::MAX)),
            "taso-seal-18446744073709551615"
        );
        let lsns = [1u64, 2, 9, 10, 99, 100, 12345, u64::MAX];
        let names: Vec<String> = lsns.iter().map(|&l| snap_name(Lsn::new(l))).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        for &l in &lsns {
            assert_eq!(parse_snap_name(&snap_name(Lsn::new(l))), Some(Lsn::new(l)));
        }
    }

    #[test]
    fn foreign_snapshot_names_are_not_seals() {
        for snap in [
            "manual",
            "taso-seal-1",
            "taso-seal-0000000000000000000x",
            "zfs-auto-snap_hourly",
        ] {
            assert_eq!(parse_snap_name(snap), None, "{snap}");
        }
    }
}
