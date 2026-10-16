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
//!
//! # Receive (rebirth)
//!
//! [`Zfs::receive`] applies a shipped send stream on another node and
//! binds the snapshot it creates to its Seal record.  A plain `zfs send`
//! does not carry `taso:seal`, so the binding comes from the caller (the
//! stream's `.meta`) and is set right after the receive.  Everything that
//! can be checked is checked before `zfs receive` runs: a full stream only
//! into a dataset that does not exist, an incremental only onto the
//! dataset's last Seal snapshot, bound to the base the caller names.  It
//! never passes `-F` (that would roll back or destroy the target) or `-s`
//! (a failed receive leaves nothing behind).
//!
//! A stream is verified as it is read and fails *at the end* if it is not
//! what its metadata says.  By then `zfs` would have every byte, so the
//! input is passed through [`HoldBack`]: the last byte is released only
//! once the input has ended cleanly.  A stream that fails at the end never
//! reaches `zfs` complete, and ZFS discards the partial receive.
//!
//! Receive is idempotent: if the Seal snapshot already exists it is bound
//! (if unbound) and returned, so a crash between receive and bind resumes.
//!
//! A Vessel forked from a Seal (a Template, usually) or born by succession
//! is a clone of its parent's Seal snapshot, so its first stream is
//! incremental from that snapshot, in another dataset.
//! [`Zfs::receive_clone`] receives it as a clone of the local copy of the
//! parent's snapshot (`zfs receive -o origin=`), which must be bound to the
//! parent Seal and have the guid the stream was made from: rebirth then
//! moves only what the Vessel changed, not the Template.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use taso_core::envelope::{HashVal, Lsn};

use crate::snapbatch::SnapBatch;

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
pub(crate) const LIST_COLUMNS: &str = "name,createtxg,guid,taso:seal";

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
    /// An incremental stream's base is not the dataset's last Seal
    /// snapshot (a later one exists).
    NotLatest(String),
    /// The input being received failed to read (for a shipped stream: it
    /// is not what its metadata says).  Nothing was received.
    Input(String),
    /// A batched snapshot's channel program reported an errno for it
    /// (1000 + errno: the binding failed and the snapshot was destroyed).
    Channel {
        /// The snapshot.
        name: String,
        /// The errno.
        errno: i64,
    },
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
            Self::NotLatest(name) => write!(f, "{name} is not the dataset's last Seal snapshot"),
            Self::Input(e) => write!(f, "the stream being received could not be read: {e}"),
            Self::Channel { name, errno } => write!(f, "zfs program could not snapshot {name}: errno {errno}"),
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

/// [`parse_line`] for the batch.
pub(crate) fn parse_line_for(dataset: &Dataset, line: &str) -> Result<Option<Snapshot>, ZfsError> {
    parse_line(dataset, line)
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

    /// Run once with `input` on stdin.  If reading `input` fails, the
    /// command is killed and the result is [`ZfsError::Input`], whatever
    /// the command did.
    fn run_input(&self, args: &[String], input: &mut dyn Read) -> Result<Output, ZfsError>;
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

    fn run_input(&self, args: &[String], input: &mut dyn Read) -> Result<Output, ZfsError> {
        let spawn_err = |e: io::Error| ZfsError::Spawn(format!("{}: {e}", self.program.display()));
        let mut child = Command::new(&self.program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(spawn_err)?;
        // Drain both outputs while we write, so a chatty command cannot
        // block on a full pipe.
        let drain = |r: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut v = Vec::new();
                if let Some(mut r) = r {
                    let _ = r.read_to_end(&mut v);
                }
                v
            })
        };
        let out_t = drain(child.stdout.take().map(|r| Box::new(r) as Box<dyn Read + Send>));
        let err_t = drain(child.stderr.take().map(|r| Box::new(r) as Box<dyn Read + Send>));

        let mut stdin = child.stdin.take();
        let mut read_error = None;
        let mut buf = vec![0u8; 128 * 1024];
        while let Some(w) = stdin.as_mut() {
            let n = match input.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    read_error = Some(e);
                    break;
                }
            };
            if w.write_all(&buf[..n]).is_err() {
                // The command stopped reading (it failed or exited);
                // its exit status and stderr say why.
                break;
            }
        }
        if read_error.is_some() {
            // Kill before closing stdin, so it never sees an end of input.
            let _ = child.kill();
        }
        drop(stdin);
        let status = child.wait().map_err(spawn_err)?;
        let stdout = out_t.join().unwrap_or_default();
        let stderr = err_t.join().unwrap_or_default();
        if let Some(e) = read_error {
            return Err(ZfsError::Input(e.to_string()));
        }
        Ok(Output {
            success: status.success(),
            code: status.code(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}

/// A reader that keeps the last byte of its input back until the input
/// has ended cleanly.
///
/// If the inner reader fails — for a verified stream, at the very end,
/// when its hash does not match — the held byte is never released, so
/// whoever reads this never sees the complete input.  `zfs receive`
/// commits only on the stream's final record; a stream one byte short is
/// discarded.
pub struct HoldBack<R> {
    inner: R,
    held: Option<u8>,
}

impl<R: Read> HoldBack<R> {
    /// Wrap `inner`.
    pub fn new(inner: R) -> Self {
        Self { inner, held: None }
    }
}

impl<R: Read> Read for HoldBack<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let n = self.inner.read(buf)?;
            if n == 0 {
                // A clean end: now the held byte may go.
                return Ok(match self.held.take() {
                    Some(b) => {
                        buf[0] = b;
                        1
                    }
                    None => 0,
                });
            }
            // Emit the held byte and all new bytes but the last, which is
            // held in turn.
            let last = buf[n - 1];
            match self.held.replace(last) {
                Some(prev) => {
                    buf.copy_within(0..n - 1, 1);
                    buf[0] = prev;
                    return Ok(n);
                }
                None if n > 1 => return Ok(n - 1),
                None => continue,
            }
        }
    }
}

// ── Zfs ────────────────────────────────────────────────────────────

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

/// The ZFS driver.
///
/// Clones share a batch queue if the driver is [`Zfs::batched`].
#[derive(Clone, Debug, Default)]
pub struct Zfs<R: Runner = Cli> {
    runner: R,
    batch: Option<std::sync::Arc<SnapBatch>>,
}

impl Zfs<Cli> {
    /// The driver over the `zfs` on `PATH`.
    pub fn cli() -> Self {
        Self { runner: Cli::default(), batch: None }
    }
}

impl<R: Runner> Zfs<R> {
    /// The driver over any runner.
    pub fn with_runner(runner: R) -> Self {
        Self { runner, batch: None }
    }

    /// This driver, with Seal snapshots batched: concurrent
    /// [`Zfs::snapshot`] calls of this driver and its clones share one
    /// channel program and one transaction group per pool
    /// ([`crate::snapbatch`]).  Needs `zfs program` (OpenZFS 2.0+, root).
    pub fn batched(mut self) -> Self {
        self.batch = Some(std::sync::Arc::default());
        self
    }

    /// The batch queue, if batched.
    #[cfg(test)]
    pub(crate) fn batch(&self) -> Option<&SnapBatch> {
        self.batch.as_deref()
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
        if let Some(batch) = &self.batch {
            return batch.snapshot(&self.runner, dataset, seal, seal_hash);
        }
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

    /// Mount `dataset` if it is not mounted (a received one is not:
    /// `zfs receive -u`).  Mounting a mounted dataset is not an error.
    pub fn ensure_mounted(&self, dataset: &Dataset) -> Result<(), ZfsError> {
        match self.run(vec!["mount".to_string(), dataset.to_string()]) {
            Ok(_) => Ok(()),
            Err(ZfsError::Exit { stderr, .. }) if stderr.contains("already mounted") => Ok(()),
            Err(e) => Err(e),
        }
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

    /// Receive a send stream into `dataset` and bind the Seal snapshot it
    /// creates, `@taso-seal-<to lsn>`, to `to`'s record hash.  Returns that
    /// snapshot as ZFS reports it.
    ///
    /// `from` is the Seal the stream is incremental from (`None` for a full
    /// stream).  Refused before anything is received:
    /// - a full stream into an existing dataset ([`ZfsError::AlreadyExists`]);
    /// - an incremental into a missing dataset, or onto a base snapshot that
    ///   is missing ([`ZfsError::NotFound`]), not bound to `from`'s hash
    ///   ([`ZfsError::SealMismatch`]), or not the dataset's last Seal
    ///   snapshot ([`ZfsError::NotLatest`]).
    ///
    /// If `@taso-seal-<to>` already exists, nothing is received: it is
    /// bound if unbound and returned; bound to another hash, it is
    /// [`ZfsError::SealMismatch`].  `stream` is read through [`HoldBack`];
    /// if it fails to read, nothing is received ([`ZfsError::Input`]).
    /// The dataset is left unmounted (`-u`).
    pub fn receive(
        &self,
        dataset: &Dataset,
        from: Option<(Lsn, HashVal)>,
        to: (Lsn, HashVal),
        stream: &mut dyn Read,
    ) -> Result<Snapshot, ZfsError> {
        if let Some(existing) = self.get(dataset, to.0)? {
            return self.bind(existing, to.1);
        }
        let info = self.dataset_info(dataset)?;
        match (from, info) {
            (None, Some(_)) => return Err(ZfsError::AlreadyExists(dataset.to_string())),
            (None, None) => {}
            (Some(_), None) => return Err(ZfsError::NotFound(dataset.to_string())),
            (Some((base_lsn, base_hash)), Some(_)) => {
                let snaps = self.list(dataset)?;
                let base_name = dataset.seal_snapshot(base_lsn);
                let base = snaps
                    .iter()
                    .find(|s| s.seal == base_lsn)
                    .ok_or_else(|| ZfsError::NotFound(base_name.clone()))?;
                if base.seal_hash != Some(base_hash) {
                    return Err(ZfsError::SealMismatch(base_name));
                }
                if snaps.last().map(|s| s.seal) != Some(base_lsn) {
                    return Err(ZfsError::NotLatest(base_name));
                }
            }
        }
        let args = vec!["receive".to_string(), "-u".to_string(), dataset.to_string()];
        let out = self.runner.run_input(&args, &mut HoldBack::new(stream))?;
        if !out.success {
            return Err(ZfsError::Exit { args, code: out.code, stderr: out.stderr });
        }
        let snap = self.get(dataset, to.0)?.ok_or(ZfsError::Parse {
            line: dataset.seal_snapshot(to.0),
            why: "the received stream did not create the expected Seal snapshot",
        })?;
        self.bind(snap, to.1)
    }

    /// Receive the first stream of a cloned Vessel: incremental from the
    /// parent's Seal snapshot `base`, into `dataset` as a clone of it, and
    /// bind the Seal snapshot it creates to `to`.  The dataset also gets
    /// `taso:parent=<base hash>`, as a fork made here would.
    ///
    /// Refused before anything is received if `base` is missing
    /// ([`ZfsError::NotFound`]), is bound to another Seal or has another
    /// guid ([`ZfsError::SealMismatch`]), or `dataset` exists
    /// ([`ZfsError::AlreadyExists`]).  ZFS itself also refuses a stream
    /// that was not made from `base`.  If `@taso-seal-<to>` already exists
    /// on a clone of `base`, nothing is received and it is bound if needed.
    pub fn receive_clone(
        &self,
        dataset: &Dataset,
        base: &CloneBase,
        to: (Lsn, HashVal),
        stream: &mut dyn Read,
    ) -> Result<Snapshot, ZfsError> {
        let base_name = base.dataset.seal_snapshot(base.seal);
        if let Some(existing) = self.get(dataset, to.0)? {
            self.check_clone_of(dataset, &base_name, base.hash)?;
            return self.bind(existing, to.1);
        }
        let snap = self.get(&base.dataset, base.seal)?.ok_or_else(|| ZfsError::NotFound(base_name.clone()))?;
        if snap.seal_hash != Some(base.hash) || snap.guid != base.guid {
            return Err(ZfsError::SealMismatch(base_name));
        }
        if self.dataset_info(dataset)?.is_some() {
            return Err(ZfsError::AlreadyExists(dataset.to_string()));
        }
        let args = vec![
            "receive".to_string(),
            "-u".to_string(),
            "-o".to_string(),
            format!("origin={base_name}"),
            "-o".to_string(),
            format!("{PARENT_PROPERTY}={}", base.hash),
            dataset.to_string(),
        ];
        let out = self.runner.run_input(&args, &mut HoldBack::new(stream))?;
        if !out.success {
            return Err(ZfsError::Exit { args, code: out.code, stderr: out.stderr });
        }
        self.check_clone_of(dataset, &base_name, base.hash)?;
        let snap = self.get(dataset, to.0)?.ok_or(ZfsError::Parse {
            line: dataset.seal_snapshot(to.0),
            why: "the received stream did not create the expected Seal snapshot",
        })?;
        self.bind(snap, to.1)
    }

    /// `dataset` is a clone of `origin` and carries `taso:parent=<hash>`.
    fn check_clone_of(&self, dataset: &Dataset, origin: &str, hash: HashVal) -> Result<(), ZfsError> {
        let info = self.dataset_info(dataset)?.ok_or_else(|| ZfsError::NotFound(dataset.to_string()))?;
        if info.origin.as_deref() != Some(origin) || info.parent != Some(hash) {
            return Err(ZfsError::SealMismatch(dataset.to_string()));
        }
        Ok(())
    }

    /// Bind an existing Seal snapshot to `hash` unless it already is;
    /// bound to another hash is [`ZfsError::SealMismatch`].
    fn bind(&self, snap: Snapshot, hash: HashVal) -> Result<Snapshot, ZfsError> {
        match snap.seal_hash {
            Some(h) if h == hash => return Ok(snap),
            Some(_) => return Err(ZfsError::SealMismatch(snap.name())),
            None => {}
        }
        self.run(vec!["set".to_string(), format!("{SEAL_PROPERTY}={hash}"), snap.name()])?;
        let bound = self.get(&snap.dataset, snap.seal)?;
        match bound {
            Some(b) if b.seal_hash == Some(hash) => Ok(b),
            _ => Err(ZfsError::Parse { line: snap.name(), why: "taso:seal was set but zfs list does not show it" }),
        }
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
        /// What each `run_input` call read, even if reading then failed.
        inputs: RefCell<Vec<Vec<u8>>>,
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
        fn run_input(&self, args: &[String], input: &mut dyn Read) -> Result<Output, ZfsError> {
            self.calls.borrow_mut().push(args.to_vec());
            let mut got = Vec::new();
            let r = input.read_to_end(&mut got);
            self.inputs.borrow_mut().push(got);
            r.map_err(|e| ZfsError::Input(e.to_string()))?;
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
    fn ensure_mounted_mounts_and_accepts_mounted() {
        let zfs = Zfs::with_runner(
            Fake::default()
                .reply(true, "", "")
                .reply(false, "", "cannot mount 'tasotest/vessel': filesystem already mounted\n")
                .reply(false, "", "cannot mount 'tasotest/vessel': no such pool\n"),
        );
        zfs.ensure_mounted(&ds()).unwrap();
        zfs.ensure_mounted(&ds()).unwrap();
        assert!(matches!(zfs.ensure_mounted(&ds()), Err(ZfsError::Exit { .. })));
        assert_eq!(zfs.runner.calls.borrow()[0], strs(&["mount", "tasotest/vessel"]));
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

    // ── HoldBack ───────────────────────────────────────────────────

    /// Yields `data`, `chunk` bytes at a time, then ends cleanly or fails.
    struct Source {
        data: io::Cursor<Vec<u8>>,
        chunk: usize,
        fail_at_end: bool,
    }

    impl Read for Source {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.chunk);
            let got = self.data.read(&mut buf[..n])?;
            if got == 0 && self.fail_at_end {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "stream does not match its metadata"));
            }
            Ok(got)
        }
    }

    fn source(data: &[u8], chunk: usize, fail_at_end: bool) -> Source {
        Source { data: io::Cursor::new(data.to_vec()), chunk, fail_at_end }
    }

    /// Read everything `r` gives, in reads of `buf` bytes; the bytes read
    /// and whether it ended cleanly.
    fn drain(r: &mut dyn Read, buf: usize) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let mut b = vec![0u8; buf];
        loop {
            match r.read(&mut b) {
                Ok(0) => return (out, true),
                Ok(n) => out.extend_from_slice(&b[..n]),
                Err(_) => return (out, false),
            }
        }
    }

    #[test]
    fn hold_back_passes_a_clean_input_exactly() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        for chunk in [1, 2, 7, 1000, 5000] {
            for buf in [1, 2, 3, 64, 4096] {
                let (got, clean) = drain(&mut HoldBack::new(source(&data, chunk, false)), buf);
                assert!(clean);
                assert_eq!(got, data, "chunk {chunk} buf {buf}");
            }
        }
        let (got, clean) = drain(&mut HoldBack::new(source(&[], 4, false)), 8);
        assert!(clean && got.is_empty());
    }

    #[test]
    fn hold_back_never_releases_the_last_byte_of_a_failing_input() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        for chunk in [1, 2, 7, 1000, 5000] {
            for buf in [1, 2, 3, 64, 4096] {
                let (got, clean) = drain(&mut HoldBack::new(source(&data, chunk, true)), buf);
                assert!(!clean);
                assert_eq!(got, data[..data.len() - 1], "chunk {chunk} buf {buf}");
            }
        }
    }

    // ── Receive ────────────────────────────────────────────────────

    const MISSING: &str = "dataset does not exist\n";

    fn recv_args() -> Vec<String> {
        strs(&["receive", "-u", "tasotest/vessel"])
    }

    fn set_args(lsn: Lsn, h: HashVal) -> Vec<String> {
        strs(&["set", &format!("taso:seal={h}"), &ds().seal_snapshot(lsn)])
    }

    fn ds_info() -> String {
        info_line("tasotest/vessel", "/tasotest/vessel", "-", "-")
    }

    #[test]
    fn receive_full_builds_exact_arguments_and_binds() {
        let zfs = Zfs::with_runner(
            Fake::default()
                .reply(false, "", MISSING) // get @1: not yet
                .reply(false, "", MISSING) // dataset_info: no dataset
                .reply(true, "", "") // receive
                .reply(true, &seal_line(Lsn::new(1), "-"), "") // get: unbound
                .reply(true, "", "") // set
                .reply(true, &seal_line(Lsn::new(1), &hash(1).to_string()), ""),
        );
        let snap = zfs.receive(&ds(), None, (Lsn::new(1), hash(1)), &mut &b"STREAM"[..]).unwrap();
        assert_eq!((snap.seal, snap.seal_hash), (Lsn::new(1), Some(hash(1))));
        let calls = zfs.runner.calls.borrow();
        assert_eq!(calls.len(), 6);
        assert_eq!(calls[2], recv_args());
        assert_eq!(calls[4], set_args(Lsn::new(1), hash(1)));
        assert_eq!(zfs.runner.inputs.borrow()[0], b"STREAM");
    }

    #[test]
    fn receive_incremental_checks_the_base_then_binds() {
        let base = seal_line(Lsn::new(3), &hash(3).to_string());
        let zfs = Zfs::with_runner(
            Fake::default()
                .reply(false, "", MISSING) // get @7: not yet
                .reply(true, &ds_info(), "")
                .reply(true, &base, "") // list: base is last and bound
                .reply(true, "", "") // receive
                .reply(true, &seal_line(Lsn::new(7), "-"), "")
                .reply(true, "", "")
                .reply(true, &seal_line(Lsn::new(7), &hash(7).to_string()), ""),
        );
        let snap = zfs
            .receive(&ds(), Some((Lsn::new(3), hash(3))), (Lsn::new(7), hash(7)), &mut &b"INC"[..])
            .unwrap();
        assert_eq!(snap.seal_hash, Some(hash(7)));
        let calls = zfs.runner.calls.borrow();
        assert_eq!(calls[3], recv_args());
        assert_eq!(calls[5], set_args(Lsn::new(7), hash(7)));
    }

    /// Every refusal happens before `zfs receive`, and the stream is not
    /// read.
    #[test]
    fn receive_refusals_come_before_any_receive() {
        let base_name = ds().seal_snapshot(Lsn::new(3));
        let base = |prop: &str| seal_line(Lsn::new(3), prop);
        type Case = (Fake, Option<(Lsn, HashVal)>, ZfsError);
        let cases: Vec<Case> = vec![
            // A full stream into an existing dataset.
            (
                Fake::default().reply(false, "", MISSING).reply(true, &ds_info(), ""),
                None,
                ZfsError::AlreadyExists("tasotest/vessel".into()),
            ),
            // An incremental into a missing dataset.
            (
                Fake::default().reply(false, "", MISSING).reply(false, "", MISSING),
                Some((Lsn::new(3), hash(3))),
                ZfsError::NotFound("tasotest/vessel".into()),
            ),
            // The base is missing.
            (
                Fake::default().reply(false, "", MISSING).reply(true, &ds_info(), "").reply(true, "", ""),
                Some((Lsn::new(3), hash(3))),
                ZfsError::NotFound(base_name.clone()),
            ),
            // The base is bound to another Seal, or unbound.
            (
                Fake::default()
                    .reply(false, "", MISSING)
                    .reply(true, &ds_info(), "")
                    .reply(true, &base(&hash(4).to_string()), ""),
                Some((Lsn::new(3), hash(3))),
                ZfsError::SealMismatch(base_name.clone()),
            ),
            (
                Fake::default().reply(false, "", MISSING).reply(true, &ds_info(), "").reply(true, &base("-"), ""),
                Some((Lsn::new(3), hash(3))),
                ZfsError::SealMismatch(base_name.clone()),
            ),
            // A later Seal exists on the target.
            (
                Fake::default()
                    .reply(false, "", MISSING)
                    .reply(true, &ds_info(), "")
                    .reply(true, &format!("{}{}", base(&hash(3).to_string()), seal_line(Lsn::new(5), &hash(5).to_string())), ""),
                Some((Lsn::new(3), hash(3))),
                ZfsError::NotLatest(base_name.clone()),
            ),
        ];
        for (fake, from, want) in cases {
            let zfs = Zfs::with_runner(fake);
            assert_eq!(zfs.receive(&ds(), from, (Lsn::new(7), hash(7)), &mut &b"X"[..]), Err(want.clone()));
            assert!(
                zfs.runner.calls.borrow().iter().all(|c| c[0] != "receive"),
                "no receive for {want:?}"
            );
            assert!(zfs.runner.inputs.borrow().is_empty());
        }
    }

    /// The Seal snapshot already exists: nothing is received.
    #[test]
    fn receive_is_idempotent() {
        // Already bound to this Seal.
        let zfs = Zfs::with_runner(Fake::default().reply(true, &seal_line(Lsn::new(7), &hash(7).to_string()), ""));
        let s = zfs.receive(&ds(), None, (Lsn::new(7), hash(7)), &mut io::empty()).unwrap();
        assert_eq!(s.seal_hash, Some(hash(7)));
        assert_eq!(zfs.runner.calls.borrow().len(), 1);
        // Received but unbound (a crash before the bind): bound now.
        let zfs = Zfs::with_runner(
            Fake::default()
                .reply(true, &seal_line(Lsn::new(7), "-"), "")
                .reply(true, "", "")
                .reply(true, &seal_line(Lsn::new(7), &hash(7).to_string()), ""),
        );
        let s = zfs.receive(&ds(), Some((Lsn::new(3), hash(3))), (Lsn::new(7), hash(7)), &mut io::empty()).unwrap();
        assert_eq!(s.seal_hash, Some(hash(7)));
        assert_eq!(zfs.runner.calls.borrow()[1], set_args(Lsn::new(7), hash(7)));
        // Bound to another Seal.
        let zfs = Zfs::with_runner(Fake::default().reply(true, &seal_line(Lsn::new(7), &hash(8).to_string()), ""));
        assert_eq!(
            zfs.receive(&ds(), None, (Lsn::new(7), hash(7)), &mut io::empty()),
            Err(ZfsError::SealMismatch(ds().seal_snapshot(Lsn::new(7)))),
        );
        assert_eq!(zfs.runner.calls.borrow().len(), 1);
    }

    /// An input that fails at the end: `zfs` never gets its last byte,
    /// the result is `Input`, and nothing is bound.
    #[test]
    fn receive_of_a_failing_stream_is_input_error() {
        let zfs = Zfs::with_runner(Fake::default().reply(false, "", MISSING).reply(false, "", MISSING));
        let mut bad = source(b"0123456789", 3, true);
        assert!(matches!(zfs.receive(&ds(), None, (Lsn::new(1), hash(1)), &mut bad), Err(ZfsError::Input(_))));
        assert_eq!(zfs.runner.inputs.borrow()[0], b"012345678");
        assert_eq!(zfs.runner.calls.borrow().len(), 3, "no get or set after the failed receive");
    }

    #[test]
    fn receive_failure_and_missing_snapshot_are_reported() {
        let zfs = Zfs::with_runner(
            Fake::default().reply(false, "", MISSING).reply(false, "", MISSING).reply(false, "", "cannot receive: invalid stream\n"),
        );
        assert!(matches!(
            zfs.receive(&ds(), None, (Lsn::new(1), hash(1)), &mut &b"X"[..]),
            Err(ZfsError::Exit { .. })
        ));
        // A stream for another Seal: receive succeeds, the snapshot is not there.
        let zfs = Zfs::with_runner(
            Fake::default().reply(false, "", MISSING).reply(false, "", MISSING).reply(true, "", "").reply(false, "", MISSING),
        );
        assert!(matches!(
            zfs.receive(&ds(), None, (Lsn::new(1), hash(1)), &mut &b"X"[..]),
            Err(ZfsError::Parse { .. })
        ));
    }

    #[test]
    fn cli_run_input_feeds_stdin_and_reports_read_errors() {
        // `cat` stands in for zfs: what goes in comes out.
        let cat = Cli::at("cat");
        let out = cat.run_input(&[], &mut &b"hello"[..]).unwrap();
        assert!(out.success);
        assert_eq!(out.stdout, "hello");
        let mut bad = source(b"abc", 1, true);
        assert!(matches!(cat.run_input(&[], &mut bad), Err(ZfsError::Input(_))));
        // A command that exits without reading: its own status is reported.
        let f = Cli::at("false");
        let big = vec![0u8; 4 << 20];
        let out = f.run_input(&[], &mut &big[..]).unwrap();
        assert!(!out.success);
    }

    // ── Receive as a clone ─────────────────────────────────────────

    fn tpl() -> Dataset {
        Dataset::new("tasotest/tpl").unwrap()
    }

    fn base() -> CloneBase {
        CloneBase { dataset: tpl(), seal: Lsn::new(5), hash: hash(5), guid: 42 }
    }

    fn tpl_line(prop: &str, guid: u64) -> String {
        format!("{}\t9\t{guid}\t{prop}\n", tpl().seal_snapshot(Lsn::new(5)))
    }

    fn clone_info(origin: &str, parent: &str) -> String {
        info_line("tasotest/vessel", "-", origin, parent)
    }

    #[test]
    fn receive_clone_builds_exact_arguments_and_checks_the_result() {
        let origin = tpl().seal_snapshot(Lsn::new(5));
        let zfs = Zfs::with_runner(
            Fake::default()
                .reply(false, "", MISSING) // get vessel@2: not yet
                .reply(true, &tpl_line(&hash(5).to_string(), 42), "") // the base, bound, right guid
                .reply(false, "", MISSING) // dataset_info: no vessel yet
                .reply(true, "", "") // receive
                .reply(true, &clone_info(&origin, &hash(5).to_string()), "") // a clone of the base
                .reply(true, &seal_line(Lsn::new(2), "-"), "")
                .reply(true, "", "") // set
                .reply(true, &seal_line(Lsn::new(2), &hash(2).to_string()), ""),
        );
        let s = zfs.receive_clone(&ds(), &base(), (Lsn::new(2), hash(2)), &mut &b"INC"[..]).unwrap();
        assert_eq!(s.seal_hash, Some(hash(2)));
        let calls = zfs.runner.calls.borrow();
        assert_eq!(
            calls[3],
            strs(&[
                "receive",
                "-u",
                "-o",
                &format!("origin={origin}"),
                "-o",
                &format!("taso:parent={}", hash(5)),
                "tasotest/vessel",
            ]),
        );
        assert_eq!(calls[6], set_args(Lsn::new(2), hash(2)));
        assert_eq!(zfs.runner.inputs.borrow()[0], b"INC");
    }

    #[test]
    fn receive_clone_refusals_come_before_any_receive() {
        let cases: Vec<(Fake, ZfsError)> = vec![
            // No base on this node.
            (
                Fake::default().reply(false, "", MISSING).reply(false, "", MISSING),
                ZfsError::NotFound(tpl().seal_snapshot(Lsn::new(5))),
            ),
            // The base is bound to another Seal, unbound, or another snapshot (guid).
            (
                Fake::default().reply(false, "", MISSING).reply(true, &tpl_line(&hash(6).to_string(), 42), ""),
                ZfsError::SealMismatch(tpl().seal_snapshot(Lsn::new(5))),
            ),
            (
                Fake::default().reply(false, "", MISSING).reply(true, &tpl_line("-", 42), ""),
                ZfsError::SealMismatch(tpl().seal_snapshot(Lsn::new(5))),
            ),
            (
                Fake::default().reply(false, "", MISSING).reply(true, &tpl_line(&hash(5).to_string(), 43), ""),
                ZfsError::SealMismatch(tpl().seal_snapshot(Lsn::new(5))),
            ),
            // The target exists already.
            (
                Fake::default()
                    .reply(false, "", MISSING)
                    .reply(true, &tpl_line(&hash(5).to_string(), 42), "")
                    .reply(true, &ds_info(), ""),
                ZfsError::AlreadyExists("tasotest/vessel".into()),
            ),
        ];
        for (fake, want) in cases {
            let zfs = Zfs::with_runner(fake);
            assert_eq!(zfs.receive_clone(&ds(), &base(), (Lsn::new(2), hash(2)), &mut &b"X"[..]), Err(want.clone()));
            assert!(zfs.runner.calls.borrow().iter().all(|c| c[0] != "receive"), "no receive for {want:?}");
            assert!(zfs.runner.inputs.borrow().is_empty());
        }
    }

    /// Received, but not a clone of the base (or without the parent
    /// binding): refused, nothing bound.
    #[test]
    fn receive_clone_checks_what_was_made() {
        let origin = tpl().seal_snapshot(Lsn::new(5));
        for info in [clone_info("-", "-"), clone_info("tasotest/other@taso-seal-00000000000000000005", &hash(5).to_string()), clone_info(&origin, "-")] {
            let zfs = Zfs::with_runner(
                Fake::default()
                    .reply(false, "", MISSING)
                    .reply(true, &tpl_line(&hash(5).to_string(), 42), "")
                    .reply(false, "", MISSING)
                    .reply(true, "", "")
                    .reply(true, &info, ""),
            );
            assert_eq!(
                zfs.receive_clone(&ds(), &base(), (Lsn::new(2), hash(2)), &mut &b"X"[..]),
                Err(ZfsError::SealMismatch("tasotest/vessel".into())),
            );
            assert!(zfs.runner.calls.borrow().iter().all(|c| c[0] != "set"));
        }
    }

    #[test]
    fn receive_clone_is_idempotent() {
        let origin = tpl().seal_snapshot(Lsn::new(5));
        let zfs = Zfs::with_runner(
            Fake::default()
                .reply(true, &seal_line(Lsn::new(2), &hash(2).to_string()), "")
                .reply(true, &clone_info(&origin, &hash(5).to_string()), ""),
        );
        let s = zfs.receive_clone(&ds(), &base(), (Lsn::new(2), hash(2)), &mut io::empty()).unwrap();
        assert_eq!(s.seal_hash, Some(hash(2)));
        assert_eq!(zfs.runner.calls.borrow().len(), 2);
        // Already there, but on a dataset that is not a clone of this base.
        let zfs = Zfs::with_runner(
            Fake::default()
                .reply(true, &seal_line(Lsn::new(2), &hash(2).to_string()), "")
                .reply(true, &clone_info("-", "-"), ""),
        );
        assert!(matches!(
            zfs.receive_clone(&ds(), &base(), (Lsn::new(2), hash(2)), &mut io::empty()),
            Err(ZfsError::SealMismatch(_))
        ));
    }

    #[test]
    fn receive_clone_of_a_failing_stream_is_input_error() {
        let zfs = Zfs::with_runner(
            Fake::default()
                .reply(false, "", MISSING)
                .reply(true, &tpl_line(&hash(5).to_string(), 42), "")
                .reply(false, "", MISSING),
        );
        let mut bad = source(b"0123456789", 4, true);
        assert!(matches!(
            zfs.receive_clone(&ds(), &base(), (Lsn::new(2), hash(2)), &mut bad),
            Err(ZfsError::Input(_))
        ));
        assert_eq!(zfs.runner.inputs.borrow()[0], b"012345678");
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

        /// Batched snapshots on a real pool: the channel program runs, every
        /// snapshot is bound in the same program, the plain driver sees
        /// exactly what the batch reported, a duplicate is refused without
        /// touching the binding, and a batched Seal can be forked.
        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn batched_snapshots_on_zfs() {
            let s = Scratch::new("batched");
            let plain = Zfs::cli();
            let batched = Zfs::cli().batched();
            let vessels: Vec<Dataset> = (0..8)
                .map(|i| {
                    let d = Dataset::new(&format!("{}/v{i}", s.ds)).unwrap();
                    plain.create(&d).unwrap();
                    d
                })
                .collect();
            let start = std::sync::Barrier::new(vessels.len());
            let got: Vec<Vec<Snapshot>> = std::thread::scope(|scope| {
                let handles: Vec<_> = vessels
                    .iter()
                    .enumerate()
                    .map(|(i, d)| {
                        let (zfs, start) = (Clone::clone(&batched), &start);
                        scope.spawn(move || {
                            start.wait();
                            (1..=5u64)
                                .map(|l| zfs.snapshot(d, Lsn::new(l), hash((i as u8) * 10 + l as u8)).unwrap())
                                .collect()
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            for (i, (d, snaps)) in vessels.iter().zip(&got).enumerate() {
                assert_eq!(&plain.list(d).unwrap(), snaps, "the plain driver sees what the batch reported");
                for (l, snap) in (1..=5u64).zip(snaps) {
                    assert_eq!(snap.seal_hash, Some(hash((i as u8) * 10 + l as u8)));
                    let prop = zfs_cmd(&["get", "-H", "-o", "value", SEAL_PROPERTY, &snap.name()]);
                    assert_eq!(prop.trim(), hash((i as u8) * 10 + l as u8).to_string());
                }
            }
            // Snapshots of different Vessels shared transaction groups.
            let txgs: std::collections::BTreeSet<u64> = got.iter().flatten().map(|s| s.createtxg).collect();
            println!("{} batched snapshots in {} txgs", got.len() * 5, txgs.len());
            assert!(txgs.len() < got.len() * 5, "no two snapshots shared a txg");

            let first = got[0][0].clone();
            assert_eq!(
                batched.snapshot(&vessels[0], Lsn::new(1), hash(99)),
                Err(ZfsError::AlreadyExists(first.name())),
            );
            assert_eq!(plain.get(&vessels[0], Lsn::new(1)).unwrap(), Some(first.clone()));
            let fork = Dataset::new(&format!("{}/fork", s.ds)).unwrap();
            plain.clone(&vessels[0], Lsn::new(1), first.seal_hash.unwrap(), &fork).unwrap();
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

        /// `zfs send` into memory (the streams here are a few KB).
        fn send(ds: &Dataset, from: Option<Lsn>, to: Lsn) -> Vec<u8> {
            let mut cmd = Command::new("zfs");
            cmd.arg("send");
            if let Some(f) = from {
                cmd.arg("-i").arg(format!("@{}", snap_name(f)));
            }
            let out = cmd.arg(ds.seal_snapshot(to)).output().expect("run zfs send");
            assert!(out.status.success(), "zfs send: {}", String::from_utf8_lossy(&out.stderr));
            out.stdout
        }

        /// Receive on another dataset, as rebirth will: refusals first,
        /// a stream that fails at its very end leaves nothing, the good
        /// streams arrive bound and byte-identical, and a crash between
        /// receive and bind resumes.
        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn receive_binds_and_refuses_on_zfs() {
            let s = Scratch::new("recv");
            let zfs = Zfs::cli();
            let src = Dataset::new(&format!("{}/src", s.ds)).unwrap();
            let dst = Dataset::new(&format!("{}/dst", s.ds)).unwrap();
            let other = Dataset::new(&format!("{}/other", s.ds)).unwrap();

            let mount = zfs.create(&src).unwrap().mountpoint.unwrap();
            std::fs::write(mount.join("f"), b"one").unwrap();
            zfs.snapshot(&src, Lsn::new(1), hash(1)).unwrap();
            std::fs::write(mount.join("f"), b"two").unwrap();
            zfs.snapshot(&src, Lsn::new(2), hash(2)).unwrap();
            let full = send(&src, None, Lsn::new(1));
            let inc = send(&src, Some(Lsn::new(1)), Lsn::new(2));
            println!("full {} bytes, incremental {} bytes", full.len(), inc.len());

            // A full stream that fails after its last byte: nothing received.
            let mut bad = source(&full, 4096, true);
            assert!(matches!(zfs.receive(&dst, None, (Lsn::new(1), hash(1)), &mut bad), Err(ZfsError::Input(_))));
            assert_eq!(zfs.dataset_info(&dst).unwrap(), None, "a failed full receive leaves no dataset");

            // The same stream, clean.
            let s1 = zfs.receive(&dst, None, (Lsn::new(1), hash(1)), &mut &full[..]).unwrap();
            assert_eq!(s1.seal_hash, Some(hash(1)));

            // Refused before receiving: wrong base, full onto an existing dataset.
            assert!(matches!(
                zfs.receive(&dst, Some((Lsn::new(1), hash(9))), (Lsn::new(2), hash(2)), &mut &inc[..]),
                Err(ZfsError::SealMismatch(_))
            ));
            zfs.create(&other).unwrap();
            assert!(matches!(
                zfs.receive(&other, None, (Lsn::new(1), hash(1)), &mut &full[..]),
                Err(ZfsError::AlreadyExists(_))
            ));

            // An incremental that fails at its end: the target is unchanged.
            let mut bad = source(&inc, 1024, true);
            assert!(matches!(
                zfs.receive(&dst, Some((Lsn::new(1), hash(1))), (Lsn::new(2), hash(2)), &mut bad),
                Err(ZfsError::Input(_))
            ));
            assert_eq!(zfs.list(&dst).unwrap(), vec![s1.clone()]);

            // Clean incremental.
            let s2 = zfs.receive(&dst, Some((Lsn::new(1), hash(1))), (Lsn::new(2), hash(2)), &mut &inc[..]).unwrap();
            assert_eq!(s2.seal_hash, Some(hash(2)));
            assert_eq!(zfs.list(&dst).unwrap(), vec![s1.clone(), s2.clone()]);

            // An incremental onto a base that is no longer the last Seal.
            assert!(matches!(
                zfs.receive(&dst, Some((Lsn::new(1), hash(1))), (Lsn::new(3), hash(3)), &mut io::empty()),
                Err(ZfsError::NotLatest(_))
            ));

            // Again: nothing received, the stream is not even read.
            assert_eq!(zfs.receive(&dst, Some((Lsn::new(1), hash(1))), (Lsn::new(2), hash(2)), &mut io::empty()), Ok(s2.clone()));

            // A crash between receive and bind: the binding is missing,
            // and the next receive restores it without receiving.
            zfs_cmd(&["inherit", SEAL_PROPERTY, &dst.seal_snapshot(Lsn::new(2))]);
            assert_eq!(zfs.get(&dst, Lsn::new(2)).unwrap().unwrap().seal_hash, None);
            let again = zfs.receive(&dst, Some((Lsn::new(1), hash(1))), (Lsn::new(2), hash(2)), &mut io::empty()).unwrap();
            assert_eq!(again.seal_hash, Some(hash(2)));
            assert_eq!(again.guid, s2.guid);

            // The contents arrived; the dataset was left unmounted.
            let mounted = zfs_cmd(&["get", "-H", "-o", "value", "mounted", dst.as_str()]);
            assert_eq!(mounted.trim(), "no");
            zfs_cmd(&["mount", dst.as_str()]);
            let dmount = PathBuf::from(zfs_cmd(&["get", "-H", "-o", "value", "mountpoint", dst.as_str()]).trim());
            assert_eq!(std::fs::read(dmount.join("f")).unwrap(), b"two");
            let first = dmount.join(".zfs/snapshot").join(snap_name(Lsn::new(1))).join("f");
            assert_eq!(std::fs::read(first).unwrap(), b"one");
        }

        /// The Template-based rebirth path.  A Vessel forked from a
        /// Template Seal is shipped as an incremental from that Seal; on
        /// "node B" (another place in the pool) the Template arrives first,
        /// keeping its guid, and the Vessel's stream is received on top as a
        /// clone.  Only what the Vessel changed travels.
        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn receive_clone_from_a_template_on_zfs() {
            let s = Scratch::new("rclone");
            let zfs = Zfs::cli();
            let tpl = Dataset::new(&format!("{}/tpl", s.ds)).unwrap();
            let vessel = Dataset::new(&format!("{}/v", s.ds)).unwrap();
            let tpl_b = Dataset::new(&format!("{}/b-tpl", s.ds)).unwrap();
            let vessel_b = Dataset::new(&format!("{}/b-v", s.ds)).unwrap();

            // Node A: a Template with a big file, sealed; a Vessel forked from it.
            let tmount = zfs.create(&tpl).unwrap().mountpoint.unwrap();
            std::fs::write(tmount.join("base.bin"), vec![7u8; 1 << 20]).unwrap();
            std::fs::write(tmount.join("note"), b"template").unwrap();
            let t5 = zfs.snapshot(&tpl, Lsn::new(5), hash(5)).unwrap();
            let vmount = zfs.clone(&tpl, Lsn::new(5), hash(5), &vessel).unwrap().mountpoint.unwrap();
            std::fs::write(vmount.join("note"), b"vessel change").unwrap();
            zfs.snapshot(&vessel, Lsn::new(2), hash(2)).unwrap();
            let full_tpl = send(&tpl, None, Lsn::new(5));
            // The Vessel's first stream, incremental from the Template Seal.
            let out = Command::new("zfs")
                .args(["send", "-i", &tpl.seal_snapshot(Lsn::new(5)), &vessel.seal_snapshot(Lsn::new(2))])
                .output()
                .unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            let inc = out.stdout;
            println!("template full {} bytes, vessel incremental from template {} bytes", full_tpl.len(), inc.len());
            assert!(inc.len() < full_tpl.len() / 10, "the Template's bytes do not travel with the Vessel");

            // Node B: the Template arrives first, with its guid.
            let tb = zfs.receive(&tpl_b, None, (Lsn::new(5), hash(5)), &mut &full_tpl[..]).unwrap();
            assert_eq!(tb.guid, t5.guid, "guids survive send and receive");
            let base = CloneBase { dataset: tpl_b.clone(), seal: Lsn::new(5), hash: hash(5), guid: tb.guid };

            // Refused before receiving: wrong Seal hash, wrong guid, no such base.
            assert!(matches!(
                zfs.receive_clone(&vessel_b, &CloneBase { hash: hash(9), ..base.clone() }, (Lsn::new(2), hash(2)), &mut &inc[..]),
                Err(ZfsError::SealMismatch(_))
            ));
            assert!(matches!(
                zfs.receive_clone(&vessel_b, &CloneBase { guid: tb.guid ^ 1, ..base.clone() }, (Lsn::new(2), hash(2)), &mut &inc[..]),
                Err(ZfsError::SealMismatch(_))
            ));
            assert!(matches!(
                zfs.receive_clone(&vessel_b, &CloneBase { seal: Lsn::new(6), ..base.clone() }, (Lsn::new(2), hash(2)), &mut &inc[..]),
                Err(ZfsError::NotFound(_))
            ));
            // A stream that fails at its very end: nothing is made.
            let mut bad = source(&inc, 4096, true);
            assert!(matches!(zfs.receive_clone(&vessel_b, &base, (Lsn::new(2), hash(2)), &mut bad), Err(ZfsError::Input(_))));
            assert_eq!(zfs.dataset_info(&vessel_b).unwrap(), None);

            // The real thing.
            let got = zfs.receive_clone(&vessel_b, &base, (Lsn::new(2), hash(2)), &mut &inc[..]).unwrap();
            assert_eq!(got.seal_hash, Some(hash(2)));
            let info = zfs.dataset_info(&vessel_b).unwrap().unwrap();
            assert_eq!(info.origin_seal(), Some((tpl_b.clone(), Lsn::new(5))));
            assert_eq!(info.parent, Some(hash(5)));
            // Again: nothing received.
            assert_eq!(zfs.receive_clone(&vessel_b, &base, (Lsn::new(2), hash(2)), &mut io::empty()).unwrap().guid, got.guid);

            zfs_cmd(&["mount", vessel_b.as_str()]);
            let bmount = PathBuf::from(zfs_cmd(&["get", "-H", "-o", "value", "mountpoint", vessel_b.as_str()]).trim());
            assert_eq!(std::fs::read(bmount.join("note")).unwrap(), b"vessel change");
            assert_eq!(std::fs::read(bmount.join("base.bin")).unwrap(), vec![7u8; 1 << 20]);
        }
    }
}
