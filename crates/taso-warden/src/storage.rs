//! Where a node keeps its Vessels: ZFS or the block log, chosen per node
//! by the configuration (`"storage"`).
//!
//! [`Storage`] implements [`Pool`], [`StorageLayers`] implements
//! [`Layers`] and [`StorageSend`] implements [`Sender`], each by passing
//! the call to the one the node uses.  The daemon holds a `Storage`, so
//! nothing above it knows which one it is.

use std::collections::BTreeSet;
use std::io;

use taso_core::envelope::{HashVal, Lsn};

use crate::blk::{BlkLayers, BlkPool, BlkSend};
use crate::chronicle::{LayerError, Layers, ZfsLayers};
use crate::ship::{ByteStream, Sender, ZfsSend};
use crate::vessel::{Pool, SealView};
use crate::zfs::{Cli, CloneBase, Dataset, DatasetInfo, Snapshot, Zfs};

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
}

impl<R: crate::zfs::Runner> Holdings for Zfs<R> {
    fn children(&self, root: &Dataset) -> Result<Vec<Dataset>, LayerError> {
        Ok(Zfs::children(self, root)?)
    }
    fn owner_uids(&self, dataset: &Dataset) -> Result<BTreeSet<u32>, LayerError> {
        Ok(Zfs::owner_uids(self, dataset)?)
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
    fn rollback(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
        match self {
            Self::Zfs(l) => l.rollback(lsn, hash),
            Self::Blk(l) => l.rollback(lsn, hash),
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
