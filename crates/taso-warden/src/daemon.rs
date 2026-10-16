//! The Warden daemon: one node's Vessels, end to end (v1.0 §1 P1, §3).
//!
//! `taso-wardend <config.json>` reads a [`Config`] and runs every Vessel
//! it lists, one thread each, until their agents exit.
//!
//! # One Vessel
//!
//! 1. **Find it** ([`decide`]): born from the void if the coordinator does
//!    not know it; opened if this node has its state; reborn from the
//!    store if not ([`crate::rebirth`]).  A Vessel held by another Warden
//!    is taken over only if its entry says `"takeover": true`: taking
//!    over fences the other Warden, so it is the operator's call, never
//!    the daemon's.
//! 2. **Publish what is not yet published**: the last Seal, if a crash
//!    came between taking and publishing it.
//! 3. **Effects**: the engine is opened (and reconciles) with the pack
//!    publisher: no effect is sent before its authorization is shipped.
//!    No adapters are registered yet (P3), so effect requests are refused.
//! 4. **Field socket** at `<run_dir>/v-<id>/field.sock`, owned by the
//!    Vessel's mapped root so the agent can connect.
//! 5. **runc**: a stale container of the same id (left by a killed
//!    daemon) is deleted, then the agent runs in the foreground on its
//!    own thread.
//! 6. **Serve** the socket until the agent exits.  Every Seal is published
//!    right after it is taken ([`SealPublisher`]): ship the `fs` section
//!    and the log, advance the shipped anchor.  A failed publish is
//!    counted and logged; the Seal stands and the next one catches up.
//!
//! # Stopping
//!
//! There is no shutdown protocol.  The Warden is built to be killed: every
//! step is durable before it is answered, and recovery finishes or drops
//! what was in flight.  SIGTERM and SIGKILL are both a crash.  (The agent's
//! container outlives a killed daemon until the next start deletes it; it
//! can no longer record anything.)
//!
//! # Not yet
//!
//! - A coordinator on another node: `remote` is a Unix socket, so across
//!   nodes it is forwarded (e.g. `ssh -L local.sock:remote.sock`).

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use taso_core::envelope::ChronicleId;
use taso_core::record::{vessel_id, Namespace, Verdict};
use taso_field::adapter::Registry;

use crate::chronicle::{Recovery, ZfsLayers};
use crate::coordinator::{Coord, CoordError};
use taso_core::model::WardenId;
use crate::effects::Effects;
use crate::field::{serve, AfterSeal, FieldSocket, Session};
use crate::pack::{PackPublisher, Packs};
use crate::quiesce::Watch;
use crate::rebirth::Reborn;
use crate::runtime::{prepare_work_dir, write_bundle, Runc, RuncCli, VesselSpec};
use crate::segment::Position;
use crate::s3::{S3Config, S3Store};
use crate::ship::{LocalStore, SharedStore, ZfsSend};
use crate::vessel::{Ensured, Host, Vessel, VesselError};
use crate::zfs::{Cli, Dataset, Snapshot, Zfs};

// ── Config ──────────────────────────────────────────────────────────

/// Where the coordinator is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoordConf {
    /// In this process, in a redb file; also served on `serve` if given
    /// (for Wardens on other nodes).
    Local {
        /// The redb file.
        path: PathBuf,
        /// A Unix socket to serve it on.
        serve: Option<PathBuf>,
    },
    /// Behind a Unix socket ([`crate::coordsrv`]).
    Remote {
        /// The socket.
        socket: PathBuf,
    },
}

/// Where packs are kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreConf {
    /// A local directory (one node, or a test).
    Local(PathBuf),
    /// An S3 bucket: Garage.  The secret is read from a file at start, so
    /// it is never in the config.
    S3 {
        /// `http://host:port`.
        endpoint: String,
        /// Signature region (`garage` by default).
        region: String,
        /// The bucket.
        bucket: String,
        /// The access key id.
        access_key_id: String,
        /// A file holding the secret key (mode 0600 is the operator's job).
        secret_key_file: PathBuf,
    },
}

impl StoreConf {
    /// Open the store.
    pub fn open(&self) -> std::io::Result<SharedStore> {
        Ok(match self {
            Self::Local(dir) => Arc::new(LocalStore::new(dir)),
            Self::S3 { endpoint, region, bucket, access_key_id, secret_key_file } => {
                let secret = std::fs::read_to_string(secret_key_file)
                    .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", secret_key_file.display())))?;
                Arc::new(S3Store::new(
                    S3Config {
                        endpoint: endpoint.clone(),
                        region: region.clone(),
                        bucket: bucket.clone(),
                        access_key_id: access_key_id.clone(),
                        secret_key: secret.trim().to_string(),
                    },
                    Duration::from_secs(30),
                )?)
            }
        })
    }
}

/// How Vessels run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConf {
    /// The image's root filesystem (read-only).
    pub rootfs: PathBuf,
    /// First host uid/gid of the Vessels' range.
    pub host_uid_base: u32,
    /// The Landlock shim inside the rootfs, if used.
    pub landlock_shim: Option<String>,
    /// The agent's command line.
    pub args: Vec<String>,
    /// Extra environment, `KEY=value`.
    pub env: Vec<String>,
    /// Memory limit in bytes.
    pub memory_bytes: Option<u64>,
    /// Maximum number of processes.
    pub pids: Option<u64>,
}

/// One Vessel to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VesselConf {
    /// Its namespace.
    pub namespace: Namespace,
    /// Its subject (the id is derived from both).
    pub subject: String,
    /// Take it over if another Warden holds it.
    pub takeover: bool,
}

impl VesselConf {
    /// The Vessel's id.
    pub fn id(&self) -> ChronicleId {
        vessel_id(self.namespace, self.subject.as_bytes())
    }
}

/// The daemon's configuration (JSON).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// This Warden.
    pub warden: WardenId,
    /// The coordinator.
    pub coordinator: CoordConf,
    /// Parent dataset of every Vessel dataset.
    pub root: Dataset,
    /// Parent of every Vessel's Warden state (outside `root`).
    pub state_dir: PathBuf,
    /// Batch Seal snapshots ([`crate::snapbatch`]).
    pub batched_snapshots: bool,
    /// Where packs are kept: a directory (`"store": "/path"`) or Garage
    /// (`"store": {"s3": {...}}`).
    pub store: StoreConf,
    /// Key prefix in the store.
    pub prefix: String,
    /// Sockets, bundles and runc state.
    pub run_dir: PathBuf,
    /// How Vessels run.
    pub runtime: RuntimeConf,
    /// Databases (paths in the dataset) whose quiescence is checked at
    /// each Seal.
    pub quiescence: Vec<String>,
    /// The Vessels to run.
    pub vessels: Vec<VesselConf>,
}

/// A bad configuration: where and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "config: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

fn bad(why: impl Into<String>) -> ConfigError {
    ConfigError(why.into())
}

fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value, ConfigError> {
    v.get(key).ok_or_else(|| bad(format!("missing {key:?}")))
}

fn string(v: &Value, key: &str) -> Result<String, ConfigError> {
    field(v, key)?.as_str().map(str::to_string).ok_or_else(|| bad(format!("{key:?} must be a string")))
}

fn abs_path(v: &Value, key: &str) -> Result<PathBuf, ConfigError> {
    let p = PathBuf::from(string(v, key)?);
    if !p.is_absolute() {
        return Err(bad(format!("{key:?} must be an absolute path")));
    }
    Ok(p)
}

fn opt_u64(v: &Value, key: &str) -> Result<Option<u64>, ConfigError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(x) => x.as_u64().map(Some).ok_or_else(|| bad(format!("{key:?} must be a non-negative integer"))),
    }
}

fn strings(v: &Value, key: &str) -> Result<Vec<String>, ConfigError> {
    match v.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| x.as_str().map(str::to_string).ok_or_else(|| bad(format!("{key:?} must be strings"))))
            .collect(),
        Some(_) => Err(bad(format!("{key:?} must be an array of strings"))),
    }
}

fn bool_or(v: &Value, key: &str, default: bool) -> Result<bool, ConfigError> {
    match v.get(key) {
        None => Ok(default),
        Some(x) => x.as_bool().ok_or_else(|| bad(format!("{key:?} must be true or false"))),
    }
}

/// A namespace: 32 hex digits.
fn namespace(s: &str) -> Result<Namespace, ConfigError> {
    let err = || bad(format!("namespace {s:?} must be 32 hex digits"));
    if s.len() != 32 {
        return Err(err());
    }
    let mut b = [0u8; 16];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(2 * i..2 * i + 2).ok_or_else(err)?, 16).map_err(|_| err())?;
    }
    Ok(Namespace::from_bytes(b))
}

impl Config {
    /// Parse and check a configuration.
    pub fn parse(json: &str) -> Result<Self, ConfigError> {
        let v: Value = serde_json::from_str(json).map_err(|e| bad(format!("not JSON: {e}")))?;
        let warden = field(&v, "warden")?.as_u64().filter(|w| *w > 0).ok_or_else(|| bad("\"warden\" must be a positive integer"))?;
        let c = field(&v, "coordinator")?;
        let coordinator = match (c.get("local"), c.get("remote")) {
            (Some(_), None) => CoordConf::Local {
                path: abs_path(c, "local")?,
                serve: if c.get("serve").is_some() { Some(abs_path(c, "serve")?) } else { None },
            },
            (None, Some(_)) => CoordConf::Remote { socket: abs_path(c, "remote")? },
            _ => return Err(bad("\"coordinator\" needs exactly one of \"local\" or \"remote\"")),
        };
        let root = Dataset::new(&string(&v, "root")?).map_err(|e| bad(e.to_string()))?;
        let r = field(&v, "runtime")?;
        let runtime = RuntimeConf {
            rootfs: abs_path(r, "rootfs")?,
            host_uid_base: u32::try_from(field(r, "host_uid_base")?.as_u64().ok_or_else(|| bad("\"host_uid_base\" must be an integer"))?)
                .map_err(|_| bad("\"host_uid_base\" is too large"))?,
            landlock_shim: match r.get("landlock_shim") {
                None | Some(Value::Null) => None,
                Some(_) => Some(abs_path(r, "landlock_shim")?.to_string_lossy().into_owned()),
            },
            args: strings(r, "args")?,
            env: strings(r, "env")?,
            memory_bytes: opt_u64(r, "memory_bytes")?,
            pids: opt_u64(r, "pids")?,
        };
        if runtime.args.is_empty() {
            return Err(bad("\"runtime.args\" must name the agent"));
        }
        let vessels = match field(&v, "vessels")? {
            Value::Array(a) => a
                .iter()
                .map(|x| {
                    Ok(VesselConf {
                        namespace: namespace(&string(x, "namespace")?)?,
                        subject: string(x, "subject")?,
                        takeover: bool_or(x, "takeover", false)?,
                    })
                })
                .collect::<Result<Vec<_>, ConfigError>>()?,
            _ => return Err(bad("\"vessels\" must be an array")),
        };
        let mut ids = std::collections::BTreeSet::new();
        for vc in &vessels {
            if !ids.insert(*vc.id().as_bytes()) {
                return Err(bad(format!("vessel {:?} is listed twice", vc.subject)));
            }
        }
        let quiescence = strings(&v, "quiescence")?;
        if let Some(q) = quiescence.iter().find(|q| Path::new(q).is_absolute() || q.split('/').any(|c| c == "..")) {
            return Err(bad(format!("quiescence path {q:?} must be relative to the dataset, without \"..\"")));
        }
        Ok(Self {
            warden: WardenId::new(warden),
            coordinator,
            root,
            state_dir: abs_path(&v, "state_dir")?,
            batched_snapshots: bool_or(&v, "batched_snapshots", true)?,
            store: match field(&v, "store")? {
                Value::String(_) => StoreConf::Local(abs_path(&v, "store")?),
                Value::Object(o) if o.contains_key("s3") => {
                    let s = &o["s3"];
                    StoreConf::S3 {
                        endpoint: string(s, "endpoint")?,
                        region: s.get("region").and_then(Value::as_str).unwrap_or("garage").to_string(),
                        bucket: string(s, "bucket")?,
                        access_key_id: string(s, "access_key_id")?,
                        secret_key_file: abs_path(s, "secret_key_file")?,
                    }
                }
                _ => return Err(bad("\"store\" must be a directory or {\"s3\": {...}}")),
            },
            prefix: v.get("prefix").and_then(Value::as_str).unwrap_or("vessels").to_string(),
            run_dir: abs_path(&v, "run_dir")?,
            runtime,
            quiescence,
            vessels,
        })
    }
}

// ── Deciding how a Vessel starts ────────────────────────────────────

/// How a Vessel starts on this node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Start {
    /// Unknown to the coordinator (or its birth was interrupted): born
    /// here from the void.
    Birth,
    /// This node has its state: opened (a new epoch fences any other
    /// incarnation).
    Open,
    /// This node has no state: rebuilt from the store.
    Rebirth,
    /// Held by another Warden and not ours to take.
    Refuse(String),
}

/// What the coordinator says about a Vessel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Known {
    /// Not registered.
    No,
    /// Registered, no record yet: an interrupted birth.
    Unborn,
    /// Registered and held by this Warden.
    Held(WardenId),
}

/// How the Vessel starts (see the module docs).
pub fn decide(known: Known, local_state: bool, me: WardenId, takeover: bool) -> Start {
    match known {
        Known::No | Known::Unborn => Start::Birth,
        Known::Held(holder) if holder != me && !takeover => Start::Refuse(format!(
            "held by Warden {}; set \"takeover\": true to fence it and take the Vessel over",
            holder.get()
        )),
        Known::Held(_) if local_state => Start::Open,
        Known::Held(_) => Start::Rebirth,
    }
}

/// The verdict of the first Seal after an open: `Unverified`, naming
/// what was lost, if recovery dropped anything (v0.4 §8.5).
pub fn verdict_after_open(r: &Recovery) -> Verdict {
    let mut lost = Vec::new();
    if r.segment.unaccepted_frames > 0 {
        lost.push(format!("{} unaccepted records dropped", r.segment.unaccepted_frames));
    }
    if r.segment.invalid_bytes > 0 {
        lost.push(format!("a torn tail of {} bytes cut", r.segment.invalid_bytes));
    }
    if let Some((kept, resumes)) = r.gap {
        lost.push(format!("records {}..{} lost in a takeover", kept.lsn.get() + 1, resumes.lsn.get()));
    }
    if !r.missing_layers.is_empty() {
        lost.push(format!("{} Seals without their layer", r.missing_layers.len()));
    }
    if lost.is_empty() {
        Verdict::Clean
    } else {
        Verdict::Unverified(format!("recovered: {}", lost.join(", ")))
    }
}

/// The verdict of the first Seal after a rebirth.
pub fn verdict_after_rebirth(r: &Reborn) -> Verdict {
    let mut lost = Vec::new();
    if let Some((kept, resumes)) = r.gap {
        lost.push(format!("records {}..{} were never shipped", kept.lsn.get() + 1, resumes.lsn.get()));
    }
    if !r.missing_layers.is_empty() {
        lost.push(format!("{} Seals without their layer", r.missing_layers.len()));
    }
    if lost.is_empty() {
        Verdict::Clean
    } else {
        Verdict::Unverified(format!("reborn: {}", lost.join(", ")))
    }
}

/// The runc container id of a Vessel.
pub fn container_id(id: ChronicleId) -> String {
    let hex: String = id.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    format!("taso-{hex}")
}

fn id_hex(id: ChronicleId) -> String {
    id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

// ── Publishing Seals ────────────────────────────────────────────────

/// Publishes each Seal as it is taken: finds its snapshot (one `zfs get`,
/// never the whole list) and runs [`Vessel::publish_seal`].
pub struct SealPublisher {
    zfs: Zfs<Cli>,
    packs: Packs<SharedStore, ZfsSend>,
    /// The parent's Seal snapshot, for a Vessel forked from one whose
    /// first `fs` section is not shipped yet: that section is incremental
    /// from it.  Cleared once a section is shipped (later Seals are
    /// incremental from the last named one, and `origin` is refused).
    origin: Option<Snapshot>,
    /// Seals published.
    pub published: u64,
}

impl SealPublisher {
    /// Publish `seal` of `vessel`.
    pub fn publish(&mut self, vessel: &mut Vessel<ZfsLayers<Cli>>, seal: Position) -> Result<(), String> {
        let snap = self
            .zfs
            .get(vessel.dataset(), seal.lsn)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("Seal {} has no snapshot", seal.lsn.get()))?;
        vessel.publish_seal(&self.packs, &snap, self.origin.as_ref()).map_err(|e| e.to_string())?;
        self.origin = None;
        Ok(())
    }
}

impl AfterSeal<ZfsLayers<Cli>> for SealPublisher {
    fn after_seal(&mut self, vessel: &mut Vessel<ZfsLayers<Cli>>, seal: Position) -> Result<(), String> {
        self.publish(vessel, seal)?;
        self.published += 1;
        Ok(())
    }
}

/// Whether the log already names a shipped `fs` section.
fn has_fs_shipped(vessel: &Vessel<ZfsLayers<Cli>>) -> Result<bool, DaemonError> {
    let frames = vessel.chronicle().frames().map_err(|e| DaemonError::Io(format!("reading the log: {e}")))?;
    Ok(frames.iter().any(|f| {
        f.envelope.stream == taso_core::envelope::Stream::Ctl
            && matches!(taso_core::record::Payload::decode(&f.payload), Ok(taso_core::record::Payload::FsShipped(_)))
    }))
}

// ── Running a Vessel ────────────────────────────────────────────────

/// What became of one Vessel.
#[derive(Debug)]
pub struct Report {
    /// Its subject.
    pub subject: String,
    /// How it started.
    pub start: Start,
    /// Field connections served.
    pub connections: u64,
    /// Seals published.
    pub published: u64,
    /// Publishes that failed (the Seal stood).
    pub publish_failures: u64,
    /// Whether the agent exited successfully, and its stderr.
    pub agent: Option<(bool, String)>,
}

/// Why a Vessel could not run.
#[derive(Debug)]
pub enum DaemonError {
    /// The Vessel layer refused or failed.
    Vessel(VesselError),
    /// The coordinator failed.
    Coord(CoordError),
    /// The file system, the socket or runc failed.
    Io(String),
    /// Held by another Warden.
    Refused(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vessel(e) => write!(f, "{e}"),
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Refused(e) => write!(f, "refused: {e}"),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<VesselError> for DaemonError {
    fn from(e: VesselError) -> Self {
        Self::Vessel(e)
    }
}

fn io(what: &str) -> impl Fn(std::io::Error) -> DaemonError + '_ {
    move |e| DaemonError::Io(format!("{what}: {e}"))
}

/// Everything a node's Vessels share.
pub struct Node {
    /// The configuration.
    pub config: Config,
    /// The coordinator.
    pub coord: Arc<dyn Coord>,
    /// The ZFS driver (batched or not; clones share the batch).
    pub zfs: Zfs<Cli>,
    /// The store (opened from `config.store`).
    pub store: SharedStore,
}

impl Node {
    /// A node: opens the store.
    pub fn new(config: Config, coord: Arc<dyn Coord>, zfs: Zfs<Cli>) -> std::io::Result<Self> {
        let store = config.store.open()?;
        Ok(Self { config, coord, zfs, store })
    }

    fn host(&self) -> Host<Zfs<Cli>> {
        Host {
            coord: self.coord.clone(),
            pool: Clone::clone(&self.zfs),
            root: self.config.root.clone(),
            state_dir: self.config.state_dir.clone(),
            warden: self.config.warden,
        }
    }

    fn packs(&self, id: ChronicleId) -> Result<Packs<SharedStore, ZfsSend>, DaemonError> {
        Packs::new(self.store.clone(), ZfsSend::default(), &self.config.prefix, id).map_err(io("packs"))
    }

    fn log(&self, vc: &VesselConf, msg: impl fmt::Display) {
        eprintln!("taso-wardend[{}] {}: {msg}", self.config.warden.get(), vc.subject);
    }

    /// Find, open or rebirth the Vessel (steps 1–2).
    fn start(&self, vc: &VesselConf) -> Result<(Vessel<ZfsLayers<Cli>>, Start, Verdict), DaemonError> {
        let host = self.host();
        let id = vc.id();
        let known = match self.coord.ownership(id) {
            Ok(o) => match self.coord.head(id).map_err(DaemonError::Coord)? {
                h if h.lsn.get() == 0 => Known::Unborn,
                _ => Known::Held(o.holder),
            },
            Err(CoordError::UnknownChronicle(_)) => Known::No,
            Err(e) => return Err(DaemonError::Coord(e)),
        };
        let local = host.dir_for(id).exists();
        let start = decide(known, local, self.config.warden, vc.takeover);
        let (vessel, verdict) = match &start {
            Start::Refuse(why) => return Err(DaemonError::Refused(why.clone())),
            Start::Birth | Start::Open => {
                let (v, how) = host.ensure(vc.namespace, vc.subject.as_bytes())?;
                let verdict = match &how {
                    Ensured::Opened(r) => verdict_after_open(r),
                    Ensured::Born | Ensured::BirthFinished => Verdict::Clean,
                };
                self.log(vc, format_args!("{how:?}"));
                (v, verdict)
            }
            Start::Rebirth => {
                let (v, reborn) = host.rebirth(id, &self.packs(id)?)?;
                self.log(vc, &reborn);
                let verdict = verdict_after_rebirth(&reborn);
                (v, verdict)
            }
        };
        Ok((vessel, start, verdict))
    }

    /// The parent's Seal snapshot, for a forked Vessel with no `fs`
    /// section shipped yet.
    fn origin(&self, vessel: &Vessel<ZfsLayers<Cli>>) -> Result<Option<Snapshot>, DaemonError> {
        if has_fs_shipped(vessel)? {
            return Ok(None);
        }
        let info = self.zfs.dataset_info(vessel.dataset()).map_err(|e| DaemonError::Io(e.to_string()))?;
        match info.and_then(|i| i.origin_seal()) {
            None => Ok(None),
            Some((ds, lsn)) => self.zfs.get(&ds, lsn).map_err(|e| DaemonError::Io(e.to_string())),
        }
    }

    /// Run one Vessel until its agent exits (see the module docs).
    pub fn run_vessel(&self, vc: &VesselConf) -> Result<Report, DaemonError> {
        let (mut vessel, start, mut verdict) = self.start(vc)?;
        let id = vc.id();
        self.log(vc, format_args!("dataset {}", vessel.dataset()));
        let mut publisher =
            SealPublisher { zfs: Clone::clone(&self.zfs), packs: self.packs(id)?, origin: self.origin(&vessel)?, published: 0 };
        // A crash between taking a Seal and publishing it: publish now.
        if let Some(seal) = vessel.last_seal() {
            if let Err(e) = publisher.publish(&mut vessel, seal) {
                self.log(vc, format_args!("publishing the last Seal (lsn {}) failed: {e}", seal.lsn.get()));
            }
        }
        let effects_publisher = PackPublisher::new(self.packs(id)?, self.coord.clone(), self.config.warden);
        let (mut effects, reconciled) = Effects::open(Registry::new(), Box::new(effects_publisher), &mut vessel)?;
        self.log(vc, format_args!("effects reconciled: {reconciled:?}"));

        // A reborn dataset was received unmounted.
        self.zfs.ensure_mounted(vessel.dataset()).map_err(|e| DaemonError::Io(format!("mount: {e}")))?;
        let mount = self
            .zfs
            .dataset_info(vessel.dataset())
            .map_err(|e| DaemonError::Io(e.to_string()))?
            .and_then(|i| i.mountpoint)
            .ok_or_else(|| DaemonError::Io(format!("{} is not mounted", vessel.dataset())))?;
        let rt = &self.config.runtime;
        prepare_work_dir(&mount, rt.host_uid_base).map_err(io("preparing the dataset"))?;

        let dir = self.config.run_dir.join(format!("v-{}", id_hex(id)));
        std::fs::create_dir_all(&dir).map_err(io("run dir"))?;
        let socket = FieldSocket::bind(dir.join("field.sock")).map_err(io("field socket"))?;
        std::os::unix::fs::chown(socket.path(), Some(rt.host_uid_base), Some(rt.host_uid_base))
            .map_err(io("field socket owner"))?;

        let spec = VesselSpec {
            id: container_id(id),
            rootfs: rt.rootfs.clone(),
            work: mount.clone(),
            socket: socket.path().to_path_buf(),
            host_uid_base: rt.host_uid_base,
            args: rt.args.clone(),
            env: rt.env.clone(),
            landlock_shim: rt.landlock_shim.clone(),
            memory_bytes: rt.memory_bytes,
            pids: rt.pids,
        };
        let bundle = write_bundle(&dir.join("bundle"), &spec).map_err(|e| DaemonError::Io(format!("bundle: {e:?}")))?;
        let bundle_dir = bundle.parent().map(Path::to_path_buf).unwrap_or(dir.join("bundle"));
        let runc = Runc::new(RuncCli::new(self.config.run_dir.join("runc")));
        if runc.state(&spec.id).map_err(io("runc state"))?.is_some() {
            self.log(vc, "deleting a stale container");
            runc.delete(&spec.id).map_err(io("runc delete"))?;
        }

        let exited = Arc::new(AtomicBool::new(false));
        let agent = {
            let (exited, id) = (exited.clone(), spec.id.clone());
            let runc = Runc::new(RuncCli::new(self.config.run_dir.join("runc")));
            std::thread::spawn(move || {
                let r = runc.run(&bundle_dir, &id);
                let _ = runc.delete(&id);
                exited.store(true, Ordering::SeqCst);
                r
            })
        };

        let mut connections = 0;
        let mut failures = 0;
        let stop = || exited.load(Ordering::SeqCst);
        while let Some(mut stream) = socket.accept_until(&stop, Duration::from_millis(20)).map_err(io("accept"))? {
            connections += 1;
            let watch = if self.config.quiescence.is_empty() {
                None
            } else {
                let dbs: Vec<&str> = self.config.quiescence.iter().map(String::as_str).collect();
                Some(Watch::new(&mount, &dbs).map_err(io("quiescence watch"))?)
            };
            let mut session = Session::new(&mut vessel, verdict.clone())?.with_effects(&mut effects).with_after_seal(&mut publisher);
            if let Some(w) = watch {
                session = session.with_watch(w);
            }
            let before = session.last_sealed_turn();
            let ended = serve(&mut stream, &mut session);
            if session.last_sealed_turn() != before {
                verdict = Verdict::Clean;
            }
            let (f, last) = session.after_seal_failures();
            if f > 0 {
                failures += f;
                self.log(vc, format_args!("{f} Seal publishes failed, last: {}", last.unwrap_or("?")));
            }
            self.log(vc, format_args!("connection ended: {ended:?}"));
        }
        let agent = agent.join().map_err(|_| DaemonError::Io("the runc thread panicked".into()))?.ok();
        if let Some((ok, err)) = &agent {
            self.log(vc, format_args!("agent exited {}{}", if *ok { "ok" } else { "with failure: " }, if *ok { "" } else { err.trim() }));
        }
        Ok(Report { subject: vc.subject.clone(), start, connections, published: publisher.published, publish_failures: failures, agent })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{
        "warden": 1,
        "coordinator": { "local": "/var/lib/taso/coord.redb", "serve": "/run/taso/coord.sock" },
        "root": "tank/vessel",
        "state_dir": "/var/lib/taso/state",
        "store": "/srv/taso/store",
        "run_dir": "/run/taso",
        "runtime": {
            "rootfs": "/srv/taso/rootfs",
            "host_uid_base": 200000,
            "landlock_shim": "/usr/lib/taso/landlock",
            "args": ["/usr/bin/agent", "--serve"],
            "memory_bytes": 268435456,
            "pids": 64
        },
        "quiescence": ["state.db"],
        "vessels": [
            { "namespace": "01010101010101010101010101010101", "subject": "a" },
            { "namespace": "01010101010101010101010101010101", "subject": "b", "takeover": true }
        ]
    }"#;

    #[test]
    fn a_good_config_parses() {
        let c = Config::parse(GOOD).unwrap();
        assert_eq!(c.warden, WardenId::new(1));
        assert_eq!(
            c.coordinator,
            CoordConf::Local { path: "/var/lib/taso/coord.redb".into(), serve: Some("/run/taso/coord.sock".into()) }
        );
        assert!(c.batched_snapshots, "batched by default");
        assert_eq!(c.prefix, "vessels");
        assert_eq!(c.runtime.landlock_shim.as_deref(), Some("/usr/lib/taso/landlock"));
        assert_eq!((c.runtime.memory_bytes, c.runtime.pids), (Some(256 << 20), Some(64)));
        assert_eq!(c.vessels.len(), 2);
        assert_eq!(c.vessels[0].namespace, Namespace::from_bytes([1; 16]));
        assert!(!c.vessels[0].takeover && c.vessels[1].takeover);
        assert_eq!(c.quiescence, vec!["state.db".to_string()]);
        assert_eq!(c.store, StoreConf::Local("/srv/taso/store".into()));
        let s3 = with(|v| {
            v["store"] = serde_json::json!({ "s3": {
                "endpoint": "http://10.0.0.2:3900", "bucket": "taso",
                "access_key_id": "GK1", "secret_key_file": "/etc/taso/s3.secret" } })
        })
        .unwrap();
        assert_eq!(
            s3.store,
            StoreConf::S3 {
                endpoint: "http://10.0.0.2:3900".into(),
                region: "garage".into(),
                bucket: "taso".into(),
                access_key_id: "GK1".into(),
                secret_key_file: "/etc/taso/s3.secret".into(),
            }
        );
    }

    #[test]
    fn stores_open_and_secrets_come_from_their_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(StoreConf::Local(dir.path().into()).open().is_ok());
        let s3 = |file: PathBuf| StoreConf::S3 {
            endpoint: "http://127.0.0.1:1".into(),
            region: "garage".into(),
            bucket: "taso".into(),
            access_key_id: "GK1".into(),
            secret_key_file: file,
        };
        assert!(s3(dir.path().join("missing")).open().is_err(), "no secret file, no store");
        std::fs::write(dir.path().join("secret"), "s3cr3t\n").unwrap();
        assert!(s3(dir.path().join("secret")).open().is_ok());
    }

    fn with(edit: impl FnOnce(&mut Value)) -> Result<Config, ConfigError> {
        let mut v: Value = serde_json::from_str(GOOD).unwrap();
        edit(&mut v);
        Config::parse(&v.to_string())
    }

    #[test]
    fn bad_configs_are_refused() {
        type Edit = Box<dyn FnOnce(&mut Value)>;
        let cases: Vec<(&str, Edit)> = vec![
            ("warden 0", Box::new(|v| v["warden"] = 0.into())),
            ("both coordinators", Box::new(|v| v["coordinator"]["remote"] = "/x.sock".into())),
            ("no coordinator", Box::new(|v| v["coordinator"] = serde_json::json!({}))),
            ("relative store", Box::new(|v| v["store"] = "store".into())),
            ("s3 without bucket", Box::new(|v| v["store"] = serde_json::json!({"s3": {"endpoint": "http://x:1", "access_key_id": "a", "secret_key_file": "/s"}}))),
            ("s3 relative secret", Box::new(|v| v["store"] = serde_json::json!({"s3": {"endpoint": "http://x:1", "bucket": "b", "access_key_id": "a", "secret_key_file": "s"}}))),
            ("store number", Box::new(|v| v["store"] = 3.into())),
            ("bad dataset", Box::new(|v| v["root"] = "tank//v".into())),
            ("no agent", Box::new(|v| v["runtime"]["args"] = serde_json::json!([]))),
            ("short namespace", Box::new(|v| v["vessels"][0]["namespace"] = "0101".into())),
            ("non-hex namespace", Box::new(|v| v["vessels"][0]["namespace"] = "zz".repeat(16).into())),
            ("a vessel twice", Box::new(|v| v["vessels"][1]["subject"] = "a".into())),
            ("absolute db", Box::new(|v| v["quiescence"] = serde_json::json!(["/etc/passwd"]))),
            ("db outside", Box::new(|v| v["quiescence"] = serde_json::json!(["../x.db"]))),
            ("takeover not bool", Box::new(|v| v["vessels"][0]["takeover"] = "yes".into())),
            ("huge uid base", Box::new(|v| v["runtime"]["host_uid_base"] = (u64::from(u32::MAX) + 1).into())),
        ];
        for (name, edit) in cases {
            assert!(with(edit).is_err(), "{name} was accepted");
        }
        assert!(Config::parse("not json").is_err());
        let remote = with(|v| v["coordinator"] = serde_json::json!({ "remote": "/run/taso/coord.sock" })).unwrap();
        assert_eq!(remote.coordinator, CoordConf::Remote { socket: "/run/taso/coord.sock".into() });
    }

    #[test]
    fn how_a_vessel_starts() {
        let (me, other) = (WardenId::new(1), WardenId::new(2));
        for local in [false, true] {
            for takeover in [false, true] {
                assert_eq!(decide(Known::No, local, me, takeover), Start::Birth);
                assert_eq!(decide(Known::Unborn, local, me, takeover), Start::Birth);
            }
        }
        assert_eq!(decide(Known::Held(me), true, me, false), Start::Open);
        assert_eq!(decide(Known::Held(me), false, me, false), Start::Rebirth, "ours, local state lost");
        assert!(matches!(decide(Known::Held(other), true, me, false), Start::Refuse(_)));
        assert!(matches!(decide(Known::Held(other), false, me, false), Start::Refuse(_)));
        assert_eq!(decide(Known::Held(other), true, me, true), Start::Open);
        assert_eq!(decide(Known::Held(other), false, me, true), Start::Rebirth);
    }

    fn pos(n: u64) -> Position {
        Position { lsn: taso_core::envelope::Lsn::new(n), hash: taso_core::envelope::HashVal::from_bytes([n as u8; 32]) }
    }

    #[test]
    fn verdicts_name_what_was_lost() {
        let clean = Recovery {
            epoch: taso_core::envelope::Epoch::FIRST,
            head: taso_core::envelope::ChronicleHead {
                lsn: taso_core::envelope::Lsn::new(5),
                hash: taso_core::envelope::HashVal::GENESIS,
                epoch: taso_core::envelope::Epoch::FIRST,
            },
            segment: crate::segment::Recovery { unaccepted_frames: 0, invalid_bytes: 0 },
            orphan_layers: vec![taso_core::envelope::Lsn::new(4)],
            last_seal: None,
            missing_layers: vec![],
            gap: None,
        };
        assert_eq!(verdict_after_open(&clean), Verdict::Clean, "an orphan layer loses nothing accepted");
        let mut lossy = clean.clone();
        lossy.segment = crate::segment::Recovery { unaccepted_frames: 2, invalid_bytes: 7 };
        lossy.gap = Some((pos(3), pos(6)));
        lossy.missing_layers = vec![pos(4)];
        let Verdict::Unverified(why) = verdict_after_open(&lossy) else { panic!() };
        for part in ["2 unaccepted", "7 bytes", "records 4..6", "1 Seals without"] {
            assert!(why.contains(part), "{why:?} lacks {part:?}");
        }

        let reborn = Reborn {
            epoch: taso_core::envelope::Epoch::new(3),
            anchor: pos(9),
            gap: None,
            received: vec![],
            dataset_at: None,
            missing_layers: vec![],
        };
        assert_eq!(verdict_after_rebirth(&reborn), Verdict::Clean);
        let lossy = Reborn { gap: Some((pos(9), pos(12))), missing_layers: vec![pos(11)], ..reborn };
        let Verdict::Unverified(why) = verdict_after_rebirth(&lossy) else { panic!() };
        assert!(why.contains("records 10..12") && why.contains("1 Seals without"), "{why}");
    }

    #[test]
    fn container_ids_are_per_vessel_and_valid() {
        let a = container_id(ChronicleId::from_bytes([0xab; 16]));
        assert_eq!(a, format!("taso-{}", "ab".repeat(16)));
        assert_ne!(a, container_id(ChronicleId::from_bytes([0xac; 16])));
    }
}
