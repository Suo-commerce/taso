//! ZFS driver: a Seal is a snapshot (v1.0 §1 P1, §9.5).
//!
//! A Vessel is a ZFS dataset.  Sealing it takes a snapshot named after the
//! Seal record's lsn, `<dataset>@taso-seal-<lsn as 20 digits>`, so name
//! order is Seal order.  The snapshot also carries the user property
//! `taso:seal=<Seal record hash, hex>`, set atomically by
//! `zfs snapshot -o`, which binds it to exactly one Chronicle record.
//!
//! The driver calls the `zfs` command with machine-readable output
//! (`-H -p`).  It does not link `libzfs`: that would need `unsafe` FFI and
//! buys nothing at Phase 1's scale.  Every command goes through a
//! [`Runner`], so argument building and output parsing are unit-tested
//! without ZFS; the tests marked `#[ignore]` need a real pool.
//!
//! Snapshots Taso did not make are ignored, never parsed as Seals.  Taking
//! a Seal that already exists is an error ([`ZfsError::AlreadyExists`]),
//! never an overwrite.
//!
//! A Vessel is a dataset.  [`Zfs::create`] makes an empty one;
//! [`Zfs::clone`] is fork: a new dataset from a Seal snapshot, carrying
//! `taso:parent=<Seal record hash>` from birth, set in the same command.
//! The clone is refused unless the snapshot is bound to exactly the Seal
//! the caller names.  ZFS keeps a snapshot alive while a clone of it
//! exists, so purge (later) must account for clones.

use std::fmt;
use std::path::PathBuf;
use std::process::Command;

use taso_core::envelope::{HashVal, Lsn};

/// User property binding a snapshot to its Seal record.
pub const SEAL_PROPERTY: &str = "taso:seal";

/// User property binding a forked dataset to the Seal it was cloned from.
pub const PARENT_PROPERTY: &str = "taso:parent";

/// Prefix of every snapshot name Taso makes.
pub const SNAP_PREFIX: &str = "taso-seal-";

/// Digits in the lsn part of a snapshot name (`u64::MAX` has 20).
const LSN_DIGITS: usize = 20;

/// ZFS limits a full name to 255 bytes (`ZFS_MAX_DATASET_NAME_LEN` − 1).
const MAX_FULL_NAME: usize = 255;

/// Longest dataset name that still leaves room for `@taso-seal-<20 digits>`.
pub const MAX_DATASET_NAME: usize = MAX_FULL_NAME - 1 - SNAP_PREFIX.len() - LSN_DIGITS;

/// Columns requested from `zfs list`, in order.
const LIST_COLUMNS: &str = "name,createtxg,guid,taso:seal";

/// Columns requested by [`Zfs::dataset_info`], in order.
const INFO_COLUMNS: &str = "name,mountpoint,origin,taso:parent";

// ── Errors ─────────────────────────────────────────────────────────

/// Why a ZFS operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZfsError {
    /// A dataset name was rejected before any command ran.
    InvalidName {
        /// The name given.
        name: String,
        /// What is wrong with it.
        why: &'static str,
    },
    /// The `zfs` command could not be started.
    Spawn(String),
    /// The command exited non-zero.
    Exit {
        /// The arguments it was given.
        args: Vec<String>,
        /// Its exit code, if it exited normally.
        code: Option<i32>,
        /// What it printed on stderr.
        stderr: String,
    },
    /// A snapshot for this Seal, or a dataset, already exists.
    AlreadyExists(String),
    /// The Seal snapshot to clone from does not exist.
    NotFound(String),
    /// The snapshot exists but is not bound to the Seal the caller named
    /// (its `taso:seal` is another hash, or unset).
    SealMismatch(String),
    /// A line of `zfs list` output could not be read.
    Parse {
        /// The line.
        line: String,
        /// What is wrong with it.
        why: &'static str,
    },
}

impl fmt::Display for ZfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName { name, why } => write!(f, "invalid dataset name {name:?}: {why}"),
            Self::Spawn(e) => write!(f, "could not run zfs: {e}"),
            Self::Exit { args, code, stderr } => write!(
                f,
                "zfs {} failed ({}): {}",
                args.join(" "),
                code.map_or("signal".to_string(), |c| format!("exit {c}")),
                stderr.trim(),
            ),
            Self::AlreadyExists(name) => write!(f, "{name} already exists"),
            Self::NotFound(name) => write!(f, "{name} does not exist"),
            Self::SealMismatch(name) => {
                write!(f, "{name} is not bound to the requested Seal")
            }
            Self::Parse { line, why } => write!(f, "cannot parse zfs output {line:?}: {why}"),
        }
    }
}

impl std::error::Error for ZfsError {}

// ── Names ──────────────────────────────────────────────────────────

/// A validated ZFS dataset name, e.g. `tasotest/vessel`.
///
/// Components are separated by `/` and may contain only ASCII letters,
/// digits and `_ - . :`.  The pool (first component) starts with a
/// letter.  The name is short enough that every Seal snapshot of it fits
/// ZFS's 255-byte limit.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Dataset(String);

impl Dataset {
    /// Validate a dataset name.
    pub fn new(name: &str) -> Result<Self, ZfsError> {
        let bad = |why| Err(ZfsError::InvalidName { name: name.to_string(), why });
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
fn parse_snap_name(snap: &str) -> Option<Lsn> {
    let digits = snap.strip_prefix(SNAP_PREFIX)?;
    if digits.len() != LSN_DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().map(Lsn::new)
}

/// Parse 64 lowercase or uppercase hex digits into a hash.
fn parse_hash(s: &str) -> Option<HashVal> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(HashVal::from_bytes(out))
}

// ── Snapshot ───────────────────────────────────────────────────────

/// A Seal snapshot as ZFS reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The dataset it belongs to.
    pub dataset: Dataset,
    /// The Seal record's lsn, from the name.
    pub seal: Lsn,
    /// The transaction group it was created in.
    pub createtxg: u64,
    /// ZFS's unique id for it.
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

/// A dataset as ZFS reports it.
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

/// Parse the single `zfs list` line of [`Zfs::dataset_info`].
fn parse_info_line(dataset: &Dataset, line: &str) -> Result<DatasetInfo, ZfsError> {
    let bad = |why| ZfsError::Parse { line: line.to_string(), why };
    let fields: Vec<&str> = line.split('\t').collect();
    let [name, mountpoint, origin, prop] = fields[..] else {
        return Err(bad("expected 4 tab-separated fields"));
    };
    if name != dataset.as_str() {
        return Err(bad("not the requested dataset"));
    }
    let mountpoint = mountpoint.starts_with('/').then(|| PathBuf::from(mountpoint));
    let origin = match origin {
        "-" | "" => None,
        o if o.contains('@') => Some(o.to_string()),
        _ => return Err(bad("origin is not a snapshot name")),
    };
    let parent = match prop {
        "-" => None,
        hex => Some(parse_hash(hex).ok_or_else(|| bad("taso:parent is not a 64-digit hex hash"))?),
    };
    Ok(DatasetInfo { dataset: dataset.clone(), mountpoint, origin, parent })
}

/// Parse one tab-separated `zfs list` line.  `Ok(None)` for snapshots
/// Taso did not make, or of another dataset.
fn parse_line(dataset: &Dataset, line: &str) -> Result<Option<Snapshot>, ZfsError> {
    let bad = |why| ZfsError::Parse { line: line.to_string(), why };
    let fields: Vec<&str> = line.split('\t').collect();
    let [name, txg, guid, prop] = fields[..] else {
        return Err(bad("expected 4 tab-separated fields"));
    };
    let Some((ds, snap)) = name.split_once('@') else {
        return Err(bad("not a snapshot name"));
    };
    if ds != dataset.as_str() {
        return Ok(None);
    }
    let Some(seal) = parse_snap_name(snap) else {
        return Ok(None);
    };
    let createtxg = txg.parse().map_err(|_| bad("createtxg is not a u64"))?;
    let guid = guid.parse().map_err(|_| bad("guid is not a u64"))?;
    let seal_hash = match prop {
        "-" => None,
        hex => Some(parse_hash(hex).ok_or_else(|| bad("taso:seal is not a 64-digit hex hash"))?),
    };
    Ok(Some(Snapshot { dataset: dataset.clone(), seal, createtxg, guid, seal_hash }))
}

// ── Runner ─────────────────────────────────────────────────────────

/// What a finished command returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    /// True if it exited with status 0.
    pub success: bool,
    /// Its exit code, if it exited normally.
    pub code: Option<i32>,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

/// Runs `zfs` with the given arguments.
pub trait Runner {
    /// Run once and return what it printed.
    fn run(&self, args: &[String]) -> Result<Output, ZfsError>;
}

/// The real `zfs` command.
#[derive(Clone, Debug)]
pub struct Cli {
    program: PathBuf,
}

impl Default for Cli {
    fn default() -> Self {
        Self { program: PathBuf::from("zfs") }
    }
}

impl Cli {
    /// Use a `zfs` binary at a specific path.
    pub fn at(program: impl Into<PathBuf>) -> Self {
        Self { program: program.into() }
    }
}

impl Runner for Cli {
    fn run(&self, args: &[String]) -> Result<Output, ZfsError> {
        let out = Command::new(&self.program)
            .args(args)
            .output()
            .map_err(|e| ZfsError::Spawn(format!("{}: {e}", self.program.display())))?;
        Ok(Output {
            success: out.status.success(),
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

// ── Zfs ────────────────────────────────────────────────────────────

/// The ZFS driver.
#[derive(Clone, Debug, Default)]
pub struct Zfs<R: Runner = Cli> {
    runner: R,
}

impl Zfs<Cli> {
    /// The driver over the `zfs` on `PATH`.
    pub fn cli() -> Self {
        Self { runner: Cli::default() }
    }
}

impl<R: Runner> Zfs<R> {
    /// The driver over any runner.
    pub fn with_runner(runner: R) -> Self {
        Self { runner }
    }

    /// Run, turning a non-zero exit into [`ZfsError::Exit`].
    fn run(&self, args: Vec<String>) -> Result<String, ZfsError> {
        let out = self.runner.run(&args)?;
        if out.success {
            Ok(out.stdout)
        } else {
            Err(ZfsError::Exit { args, code: out.code, stderr: out.stderr })
        }
    }

    /// Take the snapshot for the Seal at `seal` whose record hash is
    /// `seal_hash`, and return it as ZFS reports it.
    ///
    /// The property is set in the same command, so a snapshot is never
    /// visible without its binding.  An existing snapshot for this Seal is
    /// [`ZfsError::AlreadyExists`].
    pub fn snapshot(
        &self,
        dataset: &Dataset,
        seal: Lsn,
        seal_hash: HashVal,
    ) -> Result<Snapshot, ZfsError> {
        let name = dataset.seal_snapshot(seal);
        let args = vec![
            "snapshot".to_string(),
            "-o".to_string(),
            format!("{SEAL_PROPERTY}={seal_hash}"),
            name.clone(),
        ];
        match self.run(args) {
            Ok(_) => {}
            Err(ZfsError::Exit { stderr, .. }) if stderr.contains("dataset already exists") => {
                return Err(ZfsError::AlreadyExists(name));
            }
            Err(e) => return Err(e),
        }
        self.get(dataset, seal)?.ok_or(ZfsError::Parse {
            line: name,
            why: "snapshot was created but zfs list does not show it",
        })
    }

    /// The snapshot for the Seal at `seal`, if it exists.
    pub fn get(&self, dataset: &Dataset, seal: Lsn) -> Result<Option<Snapshot>, ZfsError> {
        let name = dataset.seal_snapshot(seal);
        match self.run(list_args(&name, false)) {
            Ok(stdout) => Ok(parse_list(dataset, &stdout)?.into_iter().next()),
            Err(ZfsError::Exit { stderr, .. }) if stderr.contains("does not exist") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Every Seal snapshot of `dataset`, in Seal order.  Snapshots Taso
    /// did not make are left out.
    pub fn list(&self, dataset: &Dataset) -> Result<Vec<Snapshot>, ZfsError> {
        let stdout = self.run(list_args(dataset.as_str(), true))?;
        let mut snaps = parse_list(dataset, &stdout)?;
        snaps.sort_by_key(|s| s.seal);
        Ok(snaps)
    }

    /// Create an empty dataset (the root of a lineage, or a test).  An
    /// existing dataset is [`ZfsError::AlreadyExists`].
    pub fn create(&self, dataset: &Dataset) -> Result<DatasetInfo, ZfsError> {
        match self.run(vec!["create".to_string(), dataset.to_string()]) {
            Ok(_) => {}
            Err(ZfsError::Exit { stderr, .. }) if stderr.contains("dataset already exists") => {
                return Err(ZfsError::AlreadyExists(dataset.to_string()));
            }
            Err(e) => return Err(e),
        }
        self.created(dataset)
    }

    /// Fork: clone the Seal snapshot `source@taso-seal-<seal>` into
    /// `target`, setting `taso:parent=<seal_hash>` in the same command.
    ///
    /// Refused before anything is created if the snapshot does not exist
    /// ([`ZfsError::NotFound`]) or is not bound to `seal_hash`
    /// ([`ZfsError::SealMismatch`]).  An existing `target` is
    /// [`ZfsError::AlreadyExists`].
    pub fn clone(
        &self,
        source: &Dataset,
        seal: Lsn,
        seal_hash: HashVal,
        target: &Dataset,
    ) -> Result<DatasetInfo, ZfsError> {
        let origin = source.seal_snapshot(seal);
        let snap = self.get(source, seal)?.ok_or_else(|| ZfsError::NotFound(origin.clone()))?;
        if snap.seal_hash != Some(seal_hash) {
            return Err(ZfsError::SealMismatch(origin));
        }
        let args = vec![
            "clone".to_string(),
            "-o".to_string(),
            format!("{PARENT_PROPERTY}={seal_hash}"),
            origin,
            target.to_string(),
        ];
        match self.run(args) {
            Ok(_) => {}
            Err(ZfsError::Exit { stderr, .. }) if stderr.contains("dataset already exists") => {
                return Err(ZfsError::AlreadyExists(target.to_string()));
            }
            Err(e) => return Err(e),
        }
        self.created(target)
    }

    /// What ZFS reports for `dataset`, or `None` if it does not exist.
    pub fn dataset_info(&self, dataset: &Dataset) -> Result<Option<DatasetInfo>, ZfsError> {
        let args: Vec<String> = ["list", "-H", "-p", "-t", "filesystem", "-o", INFO_COLUMNS]
            .iter()
            .map(|s| s.to_string())
            .chain([dataset.to_string()])
            .collect();
        match self.run(args) {
            Ok(stdout) => {
                let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
                let line = lines.next().ok_or(ZfsError::Parse {
                    line: String::new(),
                    why: "zfs list printed nothing for an existing dataset",
                })?;
                parse_info_line(dataset, line).map(Some)
            }
            Err(ZfsError::Exit { stderr, .. }) if stderr.contains("does not exist") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Info for a dataset that was just created.
    fn created(&self, dataset: &Dataset) -> Result<DatasetInfo, ZfsError> {
        self.dataset_info(dataset)?.ok_or(ZfsError::Parse {
            line: dataset.to_string(),
            why: "dataset was created but zfs list does not show it",
        })
    }

    /// Destroy one Seal snapshot.  For test cleanup only: purge rules
    /// (what may be destroyed, and when) come with the sanction loop.
    pub fn destroy(&self, snapshot: &Snapshot) -> Result<(), ZfsError> {
        self.run(vec!["destroy".to_string(), snapshot.name()]).map(|_| ())
    }
}

/// `zfs list` arguments for one snapshot, or for every snapshot of a
/// dataset (`children`).
fn list_args(target: &str, children: bool) -> Vec<String> {
    let mut args: Vec<String> = ["list", "-H", "-p", "-t", "snapshot", "-o", LIST_COLUMNS]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if children {
        args.extend(["-d".to_string(), "1".to_string()]);
    }
    args.push(target.to_string());
    args
}

fn parse_list(dataset: &Dataset, stdout: &str) -> Result<Vec<Snapshot>, ZfsError> {
    let mut snaps = Vec::new();
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        if let Some(s) = parse_line(dataset, line)? {
            snaps.push(s);
        }
    }
    Ok(snaps)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// A runner that records every call and replays canned outputs.
    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<Vec<String>>>,
        replies: RefCell<VecDeque<Output>>,
    }

    impl Fake {
        fn reply(self, success: bool, stdout: &str, stderr: &str) -> Self {
            self.replies.borrow_mut().push_back(Output {
                success,
                code: Some(if success { 0 } else { 1 }),
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
            });
            self
        }
    }

    impl Runner for Fake {
        fn run(&self, args: &[String]) -> Result<Output, ZfsError> {
            self.calls.borrow_mut().push(args.to_vec());
            self.replies.borrow_mut().pop_front().ok_or(ZfsError::Spawn("no reply queued".into()))
        }
    }

    fn ds() -> Dataset {
        Dataset::new("tasotest/vessel").unwrap()
    }

    fn hash(b: u8) -> HashVal {
        HashVal::from_bytes([b; 32])
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // ── Names ──────────────────────────────────────────────────────

    #[test]
    fn valid_dataset_names() {
        for name in ["tasotest", "tasotest/vessel", "pool/a-b_c.d:e/f9"] {
            assert!(Dataset::new(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn invalid_dataset_names() {
        for name in [
            "", "/pool", "pool/", "pool//a", "pool@snap", "pool/a b", "1pool", "pool/./a",
            "pool/../a", "pool/ä", "pool#bm",
        ] {
            assert!(
                matches!(Dataset::new(name), Err(ZfsError::InvalidName { .. })),
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
        assert_eq!(snap_name(Lsn::new(u64::MAX)), "taso-seal-18446744073709551615");
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
        for snap in ["manual", "taso-seal-1", "taso-seal-0000000000000000000x", "zfs-auto-snap_hourly"] {
            assert_eq!(parse_snap_name(snap), None, "{snap}");
        }
    }

    #[test]
    fn hash_hex_round_trips() {
        let h = HashVal::from_bytes(core::array::from_fn(|i| i as u8 * 7));
        assert_eq!(parse_hash(&h.to_string()), Some(h));
        assert_eq!(parse_hash(&h.to_string().to_uppercase()), Some(h));
        assert_eq!(parse_hash("abc123"), None);
        assert_eq!(parse_hash(&"g".repeat(64)), None);
    }

    // ── Commands ───────────────────────────────────────────────────

    #[test]
    fn snapshot_builds_exact_arguments() {
        let name = "tasotest/vessel@taso-seal-00000000000000000007";
        let line = format!("{name}\t845\t17214216927645466380\t{}\n", hash(1));
        let zfs = Zfs::with_runner(Fake::default().reply(true, "", "").reply(true, &line, ""));
        let snap = zfs.snapshot(&ds(), Lsn::new(7), hash(1)).unwrap();

        let calls = zfs.runner.calls.borrow();
        assert_eq!(
            calls[0],
            strs(&["snapshot", "-o", &format!("taso:seal={}", hash(1)), name]),
        );
        assert_eq!(
            calls[1],
            strs(&["list", "-H", "-p", "-t", "snapshot", "-o", "name,createtxg,guid,taso:seal", name]),
        );
        assert_eq!(snap.seal, Lsn::new(7));
        assert_eq!(snap.createtxg, 845);
        assert_eq!(snap.guid, 17214216927645466380, "guid exceeds i64; must be u64");
        assert_eq!(snap.seal_hash, Some(hash(1)));
        assert_eq!(snap.name(), name);
    }

    #[test]
    fn duplicate_seal_is_already_exists() {
        // The exact stderr seen on the test node (OpenZFS 2.4.1).
        let stderr = "cannot create snapshot 'tasotest/vessel@taso-seal-00000000000000000001': \
                      dataset already exists\n";
        let zfs = Zfs::with_runner(Fake::default().reply(false, "", stderr));
        assert_eq!(
            zfs.snapshot(&ds(), Lsn::new(1), hash(1)),
            Err(ZfsError::AlreadyExists("tasotest/vessel@taso-seal-00000000000000000001".into())),
        );
        assert_eq!(zfs.runner.calls.borrow().len(), 1, "no list after a refused snapshot");
    }

    #[test]
    fn other_failures_keep_stderr() {
        let zfs = Zfs::with_runner(Fake::default().reply(false, "", "permission denied\n"));
        let Err(ZfsError::Exit { stderr, code, args }) = zfs.snapshot(&ds(), Lsn::new(1), hash(1))
        else {
            panic!("expected Exit")
        };
        assert_eq!(stderr, "permission denied\n");
        assert_eq!(code, Some(1));
        assert_eq!(args[0], "snapshot");
    }

    #[test]
    fn list_parses_sorts_and_skips_foreign_snapshots() {
        let out = format!(
            "tasotest/vessel@taso-seal-00000000000000000010\t900\t2\t{h}\n\
             tasotest/vessel@manual\t850\t3\t-\n\
             tasotest/vessel@taso-seal-00000000000000000002\t845\t17214216927645466380\t{h}\n\
             tasotest/vessel@taso-seal-00000000000000000005\t870\t4\t-\n",
            h = hash(9),
        );
        let zfs = Zfs::with_runner(Fake::default().reply(true, &out, ""));
        let snaps = zfs.list(&ds()).unwrap();

        assert_eq!(
            zfs.runner.calls.borrow()[0],
            strs(&[
                "list", "-H", "-p", "-t", "snapshot", "-o", "name,createtxg,guid,taso:seal",
                "-d", "1", "tasotest/vessel",
            ]),
        );
        let seals: Vec<u64> = snaps.iter().map(|s| s.seal.get()).collect();
        assert_eq!(seals, vec![2, 5, 10]);
        assert_eq!(snaps[1].seal_hash, None, "unset property is '-'");
        assert_eq!(snaps[0].guid, 17214216927645466380);
    }

    #[test]
    fn list_of_no_snapshots_is_empty() {
        let zfs = Zfs::with_runner(Fake::default().reply(true, "", "no datasets available\n"));
        assert_eq!(zfs.list(&ds()).unwrap(), vec![]);
    }

    #[test]
    fn malformed_list_lines_are_errors() {
        for line in [
            "tasotest/vessel@taso-seal-00000000000000000001\t845\t1",
            "tasotest/vessel@taso-seal-00000000000000000001\tx\t1\t-",
            "tasotest/vessel@taso-seal-00000000000000000001\t845\t-1\t-",
            "tasotest/vessel@taso-seal-00000000000000000001\t845\t1\tabc123",
            "tasotest/vessel\t845\t1\t-",
        ] {
            let zfs = Zfs::with_runner(Fake::default().reply(true, line, ""));
            assert!(
                matches!(zfs.list(&ds()), Err(ZfsError::Parse { .. })),
                "{line:?} should not parse",
            );
        }
    }

    #[test]
    fn get_missing_snapshot_is_none() {
        let stderr = "cannot open 'tasotest/vessel@taso-seal-00000000000000000003': \
                      dataset does not exist\n";
        let zfs = Zfs::with_runner(Fake::default().reply(false, "", stderr));
        assert_eq!(zfs.get(&ds(), Lsn::new(3)), Ok(None));
    }

    #[test]
    fn destroy_names_exactly_one_snapshot() {
        let zfs = Zfs::with_runner(Fake::default().reply(true, "", ""));
        let snap = Snapshot { dataset: ds(), seal: Lsn::new(4), createtxg: 1, guid: 1, seal_hash: None };
        zfs.destroy(&snap).unwrap();
        assert_eq!(
            zfs.runner.calls.borrow()[0],
            strs(&["destroy", "tasotest/vessel@taso-seal-00000000000000000004"]),
        );
    }

    #[test]
    fn missing_binary_is_spawn_error() {
        let zfs = Zfs::with_runner(Cli::at("/nonexistent/zfs"));
        assert!(matches!(zfs.list(&ds()), Err(ZfsError::Spawn(_))));
    }

    // ── Datasets ───────────────────────────────────────────────────

    fn info_line(name: &str, mount: &str, origin: &str, parent: &str) -> String {
        format!("{name}\t{mount}\t{origin}\t{parent}\n")
    }

    const LIST_FS: [&str; 7] = ["list", "-H", "-p", "-t", "filesystem", "-o", "name,mountpoint,origin,taso:parent"];

    #[test]
    fn create_builds_exact_arguments() {
        let line = info_line("tasotest/vessel", "/tasotest/vessel", "-", "-");
        let zfs = Zfs::with_runner(Fake::default().reply(true, "", "").reply(true, &line, ""));
        let info = zfs.create(&ds()).unwrap();
        let calls = zfs.runner.calls.borrow();
        assert_eq!(calls[0], strs(&["create", "tasotest/vessel"]));
        let mut list = strs(&LIST_FS);
        list.push("tasotest/vessel".into());
        assert_eq!(calls[1], list);
        assert_eq!(info.mountpoint, Some(PathBuf::from("/tasotest/vessel")));
        assert_eq!((info.origin, info.parent), (None, None));
    }

    #[test]
    fn create_existing_is_already_exists() {
        let stderr = "cannot create 'tasotest/vessel': dataset already exists\n";
        let zfs = Zfs::with_runner(Fake::default().reply(false, "", stderr));
        assert_eq!(zfs.create(&ds()), Err(ZfsError::AlreadyExists("tasotest/vessel".into())));
    }

    fn fork_target() -> Dataset {
        Dataset::new("tasotest/fork").unwrap()
    }

    fn seal_line(lsn: Lsn, prop: &str) -> String {
        format!("{}\t845\t1\t{prop}\n", ds().seal_snapshot(lsn))
    }

    #[test]
    fn clone_builds_exact_arguments() {
        let origin = ds().seal_snapshot(Lsn::new(7));
        let info = info_line("tasotest/fork", "/tasotest/fork", &origin, &hash(3).to_string());
        let zfs = Zfs::with_runner(
            Fake::default()
                .reply(true, &seal_line(Lsn::new(7), &hash(3).to_string()), "")
                .reply(true, "", "")
                .reply(true, &info, ""),
        );
        let got = zfs.clone(&ds(), Lsn::new(7), hash(3), &fork_target()).unwrap();
        let calls = zfs.runner.calls.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0][0], "list", "the binding is checked first");
        assert_eq!(
            calls[1],
            strs(&["clone", "-o", &format!("taso:parent={}", hash(3)), &origin, "tasotest/fork"]),
        );
        assert_eq!(got.parent, Some(hash(3)));
        assert_eq!(got.origin.as_deref(), Some(origin.as_str()));
        assert_eq!(got.origin_seal(), Some((ds(), Lsn::new(7))));
    }

    #[test]
    fn clone_refuses_wrong_or_unbound_seal_before_cloning() {
        for prop in [hash(4).to_string(), "-".to_string()] {
            let zfs = Zfs::with_runner(Fake::default().reply(true, &seal_line(Lsn::new(7), &prop), ""));
            assert_eq!(
                zfs.clone(&ds(), Lsn::new(7), hash(3), &fork_target()),
                Err(ZfsError::SealMismatch(ds().seal_snapshot(Lsn::new(7)))),
            );
            assert_eq!(zfs.runner.calls.borrow().len(), 1, "no clone was attempted");
        }
    }

    #[test]
    fn clone_from_missing_seal_is_not_found() {
        let stderr = "cannot open 'tasotest/vessel@taso-seal-00000000000000000007': \
                      dataset does not exist\n";
        let zfs = Zfs::with_runner(Fake::default().reply(false, "", stderr));
        assert_eq!(
            zfs.clone(&ds(), Lsn::new(7), hash(3), &fork_target()),
            Err(ZfsError::NotFound(ds().seal_snapshot(Lsn::new(7)))),
        );
        assert_eq!(zfs.runner.calls.borrow().len(), 1);
    }

    #[test]
    fn clone_onto_existing_target_is_already_exists() {
        let stderr = "cannot create 'tasotest/fork': dataset already exists\n";
        let zfs = Zfs::with_runner(
            Fake::default()
                .reply(true, &seal_line(Lsn::new(7), &hash(3).to_string()), "")
                .reply(false, "", stderr),
        );
        assert_eq!(
            zfs.clone(&ds(), Lsn::new(7), hash(3), &fork_target()),
            Err(ZfsError::AlreadyExists("tasotest/fork".into())),
        );
    }

    #[test]
    fn dataset_info_parses_and_reports_missing() {
        for (mount, want) in [("/m/x", Some(PathBuf::from("/m/x"))), ("none", None), ("legacy", None), ("-", None)] {
            let zfs = Zfs::with_runner(
                Fake::default().reply(true, &info_line("tasotest/vessel", mount, "-", "-"), ""),
            );
            assert_eq!(zfs.dataset_info(&ds()).unwrap().unwrap().mountpoint, want, "{mount}");
        }
        let stderr = "cannot open 'tasotest/vessel': dataset does not exist\n";
        let zfs = Zfs::with_runner(Fake::default().reply(false, "", stderr));
        assert_eq!(zfs.dataset_info(&ds()), Ok(None));
    }

    #[test]
    fn dataset_info_origin_that_is_not_a_seal() {
        let zfs = Zfs::with_runner(Fake::default().reply(
            true,
            &info_line("tasotest/vessel", "/x", "tasotest/other@manual", "-"),
            "",
        ));
        let info = zfs.dataset_info(&ds()).unwrap().unwrap();
        assert_eq!(info.origin.as_deref(), Some("tasotest/other@manual"));
        assert_eq!(info.origin_seal(), None);
    }

    #[test]
    fn malformed_info_lines_are_errors() {
        for line in [
            "tasotest/vessel\t/x\t-",
            "tasotest/other\t/x\t-\t-",
            "tasotest/vessel\t/x\tnot-a-snapshot\t-",
            "tasotest/vessel\t/x\t-\tabc123",
        ] {
            let zfs = Zfs::with_runner(Fake::default().reply(true, line, ""));
            assert!(
                matches!(zfs.dataset_info(&ds()), Err(ZfsError::Parse { .. })),
                "{line:?} should not parse",
            );
        }
    }

    // ── On-node tests: need a real pool ────────────────────────────
    //
    //   TASO_ZFS_DATASET=tasotest/vessel cargo test -p taso-warden -- --ignored --nocapture
    //
    // Each test works in its own child dataset, destroyed afterwards, so
    // the tests can run in parallel and leave nothing behind.

    mod node {
        use super::*;
        use std::time::Instant;

        /// A child dataset of `$TASO_ZFS_DATASET`, destroyed on drop.
        struct Scratch {
            ds: Dataset,
            mountpoint: PathBuf,
        }

        fn zfs_cmd(args: &[&str]) -> String {
            let out = Command::new("zfs").args(args).output().expect("run zfs");
            assert!(
                out.status.success(),
                "zfs {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr),
            );
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        impl Scratch {
            fn new(test: &str) -> Self {
                let base = std::env::var("TASO_ZFS_DATASET")
                    .expect("set TASO_ZFS_DATASET to a dataset these tests may use");
                let name = format!("{base}/t-{test}-{}", std::process::id());
                let ds = Dataset::new(&name).unwrap();
                zfs_cmd(&["create", &name]);
                let mountpoint =
                    PathBuf::from(zfs_cmd(&["get", "-H", "-o", "value", "mountpoint", &name]).trim());
                Self { ds, mountpoint }
            }
        }

        impl Drop for Scratch {
            fn drop(&mut self) {
                // -R: also the clones made from its snapshots.
                let _ = Command::new("zfs").args(["destroy", "-R", self.ds.as_str()]).status();
            }
        }

        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn snapshot_and_list_round_trip() {
            let s = Scratch::new("roundtrip");
            let zfs = Zfs::cli();
            let a = zfs.snapshot(&s.ds, Lsn::new(3), hash(3)).unwrap();
            let b = zfs.snapshot(&s.ds, Lsn::new(12), hash(12)).unwrap();
            // A snapshot Taso did not make is ignored.
            zfs_cmd(&["snapshot", &format!("{}@manual", s.ds)]);

            assert_eq!(a.seal_hash, Some(hash(3)));
            assert_ne!(a.guid, b.guid);
            assert!(a.createtxg <= b.createtxg);
            assert_eq!(zfs.list(&s.ds).unwrap(), vec![a.clone(), b]);
            assert_eq!(zfs.get(&s.ds, Lsn::new(3)).unwrap(), Some(a));
            assert_eq!(zfs.get(&s.ds, Lsn::new(4)).unwrap(), None);
        }

        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn duplicate_seal_refused() {
            let s = Scratch::new("duplicate");
            let zfs = Zfs::cli();
            let first = zfs.snapshot(&s.ds, Lsn::new(1), hash(1)).unwrap();
            assert_eq!(
                zfs.snapshot(&s.ds, Lsn::new(1), hash(2)),
                Err(ZfsError::AlreadyExists(first.name())),
            );
            // The original binding is untouched.
            assert_eq!(zfs.get(&s.ds, Lsn::new(1)).unwrap(), Some(first));
        }

        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn snapshot_keeps_old_bytes() {
            let s = Scratch::new("bytes");
            let zfs = Zfs::cli();
            let file = s.mountpoint.join("note.txt");
            std::fs::write(&file, b"version one").unwrap();
            let snap = zfs.snapshot(&s.ds, Lsn::new(1), hash(1)).unwrap();
            std::fs::write(&file, b"version two").unwrap();

            let frozen = s.mountpoint.join(".zfs/snapshot").join(snap_name(snap.seal)).join("note.txt");
            assert_eq!(std::fs::read(&file).unwrap(), b"version two");
            assert_eq!(std::fs::read(&frozen).unwrap(), b"version one");
        }

        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn snapshot_timing() {
            let s = Scratch::new("timing");
            let zfs = Zfs::cli();
            let file = s.mountpoint.join("turn.txt");
            let mut ms: Vec<f64> = Vec::new();
            for i in 1..=100u64 {
                std::fs::write(&file, format!("turn {i}")).unwrap();
                let t = Instant::now();
                zfs.snapshot(&s.ds, Lsn::new(i), hash(i as u8)).unwrap();
                ms.push(t.elapsed().as_secs_f64() * 1000.0);
            }
            assert_eq!(zfs.list(&s.ds).unwrap().len(), 100);
            ms.sort_by(f64::total_cmp);
            let pct = |p: f64| ms[((ms.len() as f64 * p).ceil() as usize).saturating_sub(1)];
            // Information, not a gate: includes the follow-up `zfs list`.
            println!(
                "snapshot+get over 100 Seals: p50 {:.1} ms, p95 {:.1} ms, max {:.1} ms",
                pct(0.50),
                pct(0.95),
                ms[ms.len() - 1],
            );
        }

        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn create_seal_clone_round_trip() {
            let s = Scratch::new("fork");
            let zfs = Zfs::cli();
            let src = Dataset::new(&format!("{}/src", s.ds)).unwrap();
            let fork = Dataset::new(&format!("{}/fork", s.ds)).unwrap();

            let info = zfs.create(&src).unwrap();
            assert_eq!(zfs.create(&src), Err(ZfsError::AlreadyExists(src.to_string())));
            let mount = info.mountpoint.expect("created dataset is mounted");
            std::fs::write(mount.join("state.txt"), b"at the seal").unwrap();
            zfs.snapshot(&src, Lsn::new(4), hash(4)).unwrap();
            std::fs::write(mount.join("state.txt"), b"after the seal").unwrap();

            // Wrong hash and missing Seal are refused, and nothing is made.
            assert!(matches!(zfs.clone(&src, Lsn::new(4), hash(5), &fork), Err(ZfsError::SealMismatch(_))));
            assert!(matches!(zfs.clone(&src, Lsn::new(9), hash(4), &fork), Err(ZfsError::NotFound(_))));
            assert_eq!(zfs.dataset_info(&fork).unwrap(), None);

            let forked = zfs.clone(&src, Lsn::new(4), hash(4), &fork).unwrap();
            assert_eq!(forked.parent, Some(hash(4)));
            assert_eq!(forked.origin_seal(), Some((src.clone(), Lsn::new(4))));
            let fmount = forked.mountpoint.clone().expect("clone is mounted");
            assert_eq!(std::fs::read(fmount.join("state.txt")).unwrap(), b"at the seal");
            assert_eq!(std::fs::read(mount.join("state.txt")).unwrap(), b"after the seal");
            assert!(matches!(
                zfs.clone(&src, Lsn::new(4), hash(4), &fork),
                Err(ZfsError::AlreadyExists(_))
            ));
            println!("forked: {forked:?}");
        }
    }
}
