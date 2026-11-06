//! The names and shapes a node's storage speaks in -- [`Dataset`],
//! [`Snapshot`], [`DatasetInfo`], [`CloneBase`] and the Seal snapshot
//! naming -- and what the start-up scan of uid slots reads
//! ([`Holdings`]).  The storage itself is the block log ([`crate::blk`]):
//! the daemon holds its pool, layers and sender directly.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use taso_core::envelope::{HashVal, Lsn};

use crate::blk::{BlkPool, Blkd, Mounts};
use crate::chronicle::LayerError;
use crate::vessel::Pool;

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

impl<D: Blkd + 'static, M: Mounts + 'static> Holdings for BlkPool<D, M> {
    fn children(&self, root: &Dataset) -> Result<Vec<Dataset>, LayerError> {
        BlkPool::children(self, root)
    }
    fn owner_uids(&self, dataset: &Dataset) -> Result<BTreeSet<u32>, LayerError> {
        BlkPool::owner_uids(self, dataset)
    }
    fn origin(&self, dataset: &Dataset) -> Result<Option<(Dataset, Lsn)>, LayerError> {
        Ok(Pool::info(self, dataset)?.and_then(|i| i.origin_seal()))
    }
}

// ── Shared types ───────────────────────────────────────────────────

/// Prefix of every snapshot name Taso makes.
pub const SNAP_PREFIX: &str = "taso-seal-";

/// Digits in the lsn part of a snapshot name (`u64::MAX` has 20).
const LSN_DIGITS: usize = 20;

/// A full Seal name is at most 255 bytes: the bound Taso's names were
/// made under, kept so every name ever made stays valid.
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
/// storage goes by (a block-log branch).
///
/// Components are separated by `/` and may contain only ASCII letters,
/// digits and `_ - . :`.  The pool (first component) starts with a
/// letter.  The name is short enough that every Seal name of it fits the
/// 255-byte bound.
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

/// A Seal layer as the block log reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The dataset it belongs to.
    pub dataset: Dataset,
    /// The Seal record's lsn, from the name.
    pub seal: Lsn,
    /// Its stable id (the block log derives one from the Seal); the same
    /// on every node it was received on.
    pub guid: u64,
    /// The Seal record hash the layer is bound to, or `None` if unbound.
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
    /// Where it is mounted; `None` if it is not.
    pub mountpoint: Option<PathBuf>,
    /// The snapshot it was cloned from (full name), if it is a clone.
    pub origin: Option<String>,
    /// The Seal record it was forked from (its parent), if a fork.
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
            "auto-snap_hourly",
        ] {
            assert_eq!(parse_snap_name(snap), None, "{snap}");
        }
    }
}
