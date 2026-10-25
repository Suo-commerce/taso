//! The Warden daemon: one node's Vessels, end to end (v1.0 §1 P1, §3).
//!
//! `taso-wardend <config.json>` reads a [`Config`] and runs every Vessel
//! it lists, one thread each, until their agents exit.
//!
//! # Where Vessels come from
//!
//! The config's `"source"` ([`SourceConf`]): its own `"vessels"` list
//! (`static`, the default), or the Vessel resources of a Kubernetes
//! cluster that name this node (`kubernetes`, [`KubeSourceConf`]).  A
//! cluster is not trusted: what a Vessel resource may ask for is bounded by
//! this node's config (which Kubernetes namespaces map to which tenant,
//! where rootfs directories may be, memory and process maxima, whether
//! Landlock may be turned off), and anything outside it is refused, never
//! clamped.  Every source goes through the same guard
//! ([`crate::source::Guard`]).
//!
//! A Vessel may carry its own runtime ([`VesselRuntime`]: rootfs, command
//! line, environment, Landlock, limits, quiescence); what it leaves out is
//! the node's `"runtime"`.  It is resolved ([`VesselConf::effective`])
//! before anything else in a start, so a Vessel whose runtime is incomplete
//! is refused before the coordinator hears of it.
//!
//! # Starting
//!
//! First, [`Node::new`] refuses a host with SELinux enabled
//! ([`refuse_selinux`], P4 spec rev. 12 D32): SELinux labels every file
//! with an xattr, in permissive mode too, and a manifest refuses every
//! entry that has one, so nothing on such a host could become a Template.
//! Supported hosts are Linux without SELinux (Ubuntu, Debian).
//!
//! Then, before any Vessel, it claims the run directory
//! ([`claim_run_dir`]: one daemon per `run_dir`, held until it exits) and
//! then sweeps its runc root ([`sweep_stale`]).  Holding the lock proves
//! that every container in that root was left by a dead incarnation of
//! this daemon, whichever Vessel it ran, including one since reborn on
//! another node.  If any of them cannot be removed the daemon does not
//! start: an old agent may still be writing into its dataset.
//!
//! # One Vessel
//!
//! 1. **Find it** ([`decide`]): born from the void if the coordinator does
//!    not know it; opened if this node has its state; reborn from the
//!    store if not ([`crate::rebirth`]).  A Vessel held by another Warden
//!    is taken over only if its entry names that ownership,
//!    `"takeover": {"holder": <warden>, "epoch": <n>}` (read from
//!    `taso-logcheck` or from the refusal line): taking over fences the
//!    other Warden, so it is the operator's call, never the daemon's, and
//!    it is one call — once the ownership moved, the instruction no
//!    longer matches and refuses itself, so a daemon restarted with it
//!    left in cannot fence anyone again (fencing review F2).  An entry
//!    naming this Warden as the holder is spent and ignored.  A takeover
//!    for a Vessel nobody holds (the coordinator does not know it, or its
//!    birth never finished) is refused, not turned into a birth: the
//!    operator expected an existing Vessel, and starting an empty one
//!    there would hide a wrong coordinator or a wrong node (decided
//!    2026-10-21).  Without the takeover it is born as usual.
//! 2. **Settle the state** ([`settle`]).  A Vessel with no Seal takes its
//!    birth Seal (turn 0, [`Vessel::seal_birth`]) before anything else:
//!    every Vessel has a Seal before its agent first runs.  Then the
//!    dataset is rolled back to the last Seal ([`Vessel::rollback`]), so
//!    a restart on this node starts from exactly what a rebirth elsewhere
//!    would: what a crashed turn wrote after its last Seal is discarded.
//!    This is safe only because nothing is writing: the startup sweep
//!    removed every old container, and on ZFS an open file does not stop
//!    a rollback (measured 2026-10-17).  If the last Seal's layer is
//!    missing, the rollback goes to the newest Seal that has one and a
//!    warning says so.  A failed rollback stops the start.
//! 3. **Publish what is not yet published**: the last Seal, if a crash
//!    came between taking and publishing it (the birth Seal on a new
//!    Vessel: shipped and anchored, so it is reborn elsewhere even if it
//!    dies before turn 1).
//! 4. **Effects**: the engine is opened (and reconciles) with the pack
//!    publisher: no effect is sent before its authorization is shipped.
//!    Taso never sends; the sender's contract is in `docs/relay.md`.
//!    A promotion whose files are not adopted yet is finished here too
//!    (C7): the child's increment from the fork Seal becomes this Vessel's
//!    adoption Seal before the agent runs ([`Host::adopt_files`]), so the
//!    agent starts on the child's files and continues its turns.  A
//!    promotion asked for over the Field ends the run for that.
//! 5. **Field socket** at `<run_dir>/v-<id>/field.sock`, owned by the
//!    Vessel's mapped root so the agent can connect.  Each Vessel has its
//!    own host uid/gid range ([`VesselConf::uid_slot`]); the dataset's
//!    top directory and the socket belong to it.
//! 6. **runc**: a stale container of the same id is deleted (a backstop;
//!    the startup sweep already removed it), then the agent runs in the
//!    foreground on its own thread.
//! 7. **Serve** both sockets until the agent exits: the agent's, and the
//!    sender's at `<run_dir>/senders/<id>.sock` (the Warden's own, mode
//!    0600, never mounted into the Vessel: only a sender lists released
//!    effects and reports outcomes; [`crate::field::Socket`]).  Every Seal is published
//!    right after it is taken ([`SealPublisher`]): ship the `fs` section
//!    and the log, advance the shipped anchor.  A failed publish is
//!    counted and logged; the Seal stands and the next one catches up.
//!
//! # Stopping
//!
//! There is no shutdown protocol.  The Warden is built to be killed: every
//! step is durable before it is answered, and recovery finishes or drops
//! what was in flight.  SIGTERM and SIGKILL are both a crash.  (The agent's
//! container outlives a killed daemon until the next start sweeps it; it
//! can no longer record anything or reach the network.)
//!
//! One Vessel can be stopped on its own ([`Stop`], [`Node::run_vessel_until`]):
//! its container is killed, which is a crash of that agent only; the next
//! start rolls the state back to the last Seal.  Each Vessel says whether its
//! agent is started again after it exits ([`Restart`], `"restart"`).
//!
//! # Not yet
//!
//! - Successions from a config entry (forks are: [`ForkConf`], and forks
//!   asked for over the Field: [`ForksConf`]).
//! - A fork is reborn only where its parent's Seal is (decided
//!   2026-10-23, option c): on its parent's node, on a node its parent was
//!   reborn on, or where the parent's Seal is kept as a Template.  The
//!   supervisor starts a parent listed with its fork first, so a node that
//!   takes both over rebirths the parent, then the child; anywhere else
//!   the child's rebirth is refused before anything changes, naming the
//!   missing Seal.  Fetching the parent's sections to rebirth a fork alone
//!   (option a) is for when children must outlive their parent's node.
//! - Children asked for over the Field are run by the Warden that made
//!   them; a new Warden does not list them again.  What happens to them
//!   then is the prime agent's call: their datasets, logs and slots stay,
//!   so it can still promote one (a promotion reads the log, it does not
//!   need the child running), or ask for new forks in its remaining
//!   slots.  A child cut short by the restart stays at its last Seal and
//!   keeps its slot.
//!
//! - A coordinator on another node: `remote` is a Unix socket, so across
//!   nodes it is forwarded (e.g. `ssh -L local.sock:remote.sock`).

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use taso_core::envelope::{ChronicleId, Epoch, Lsn};
use taso_core::record::{vessel_id, Namespace, TurnId, Verdict};

use crate::chronicle::Layers;
use crate::chronicle::{Claim, LayerError, Recovery};
use crate::coordinator::{Coord, CoordError};
use crate::effects::{Effects, Mode};
use crate::field::{serve_vessel, AfterSeal, Branches, FieldSocket, Session};
use crate::pack::{PackPublisher, Packs};
use crate::quiesce::Watch;
use crate::rebirth::Reborn;
use crate::runtime::{
    work_dir_range, write_bundle, Runc, RuncCli, RuncRunner, Swept, VesselSpec, ID_RANGE,
};
use crate::s3::{S3Config, S3Store};
use crate::segment::Position;
use crate::ship::{LocalStore, SharedStore};
use crate::source::{Held, Requested};
use crate::storage::{Holdings, Storage, StorageLayers, StorageSend};
use crate::template::{TemplateError, TemplateLayers};
use crate::vessel::{
    Ensured, Host, Pool, ReadLog, SealAt, TemplateBirth, Vessel, VesselError, BIRTH_TURN,
};
use crate::zfs::{Dataset, Snapshot};
use taso_core::contract::{ContractRecord, NominatedBy, PathClass, StorageKind, TemplateRef};
use taso_core::coordlog::Submitted;
use taso_core::model::WardenId;
use taso_core::record::{Origin, TemplateAsked};
use taso_field::protocol::{NominateResult, PromoteResult};

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
        /// For an `https://` endpoint: trust only this CA (PEM).
        ca_file: Option<PathBuf>,
    },
}

impl StoreConf {
    /// The `"store"` field of `v`: a directory, or `{"s3": {endpoint,
    /// bucket, access_key_id, secret_key_file, region?, ca_file?}}`.  The
    /// Warden's config and `taso-coordd --store-config` read it the same
    /// way.
    pub fn parse_in(v: &Value) -> Result<Self, ConfigError> {
        Ok(match field(v, "store")? {
            Value::String(_) => StoreConf::Local(abs_path(v, "store")?),
            Value::Object(o) if o.contains_key("s3") => {
                let s = &o["s3"];
                StoreConf::S3 {
                    endpoint: string(s, "endpoint")?,
                    region: s
                        .get("region")
                        .and_then(Value::as_str)
                        .unwrap_or("garage")
                        .to_string(),
                    bucket: string(s, "bucket")?,
                    access_key_id: string(s, "access_key_id")?,
                    secret_key_file: abs_path(s, "secret_key_file")?,
                    ca_file: if s.get("ca_file").is_some() {
                        Some(abs_path(s, "ca_file")?)
                    } else {
                        None
                    },
                }
            }
            _ => return Err(bad("\"store\" must be a directory or {\"s3\": {...}}")),
        })
    }

    /// Open the store.
    pub fn open(&self) -> std::io::Result<SharedStore> {
        Ok(match self {
            Self::Local(dir) => Arc::new(LocalStore::new(dir)),
            Self::S3 {
                endpoint,
                region,
                bucket,
                access_key_id,
                secret_key_file,
                ca_file,
            } => {
                let secret = std::fs::read_to_string(secret_key_file).map_err(|e| {
                    std::io::Error::new(e.kind(), format!("{}: {e}", secret_key_file.display()))
                })?;
                Arc::new(S3Store::new(
                    S3Config {
                        endpoint: endpoint.clone(),
                        region: region.clone(),
                        bucket: bucket.clone(),
                        access_key_id: access_key_id.clone(),
                        secret_key: secret.trim().to_string(),
                        ca_file: ca_file.clone(),
                    },
                    Duration::from_secs(30),
                )?)
            }
        })
    }
}

/// How Vessels run on this node: the defaults for what a Vessel's own
/// [`VesselRuntime`] leaves out, and the node-wide settings (the uid base,
/// the Landlock shim).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConf {
    /// The image's root filesystem (read-only), if Vessels share one.
    pub rootfs: Option<PathBuf>,
    /// First host uid/gid of the node's Vessel ranges: the Vessel in
    /// slot `n` maps its uids 0..65536 to `host_uid_base + n·65536`
    /// ([`VesselConf::uid_slot`]).
    pub host_uid_base: u32,
    /// The Template uid range's slot (P4 spec rev. 17 §5.6, D53): a
    /// Template's layer is owned by `host_uid_base + template_slot·65536`,
    /// the same on every node of a cluster.  Required for Template births;
    /// no Vessel and no fork slot may use it.
    pub template_slot: Option<u32>,
    /// The Landlock shim inside the rootfs, if used.
    pub landlock_shim: Option<String>,
    /// The agent's command line (may be empty if every Vessel names its own).
    pub args: Vec<String>,
    /// Extra environment, `KEY=value`.
    pub env: Vec<String>,
    /// Memory limit in bytes.
    pub memory_bytes: Option<u64>,
    /// Maximum number of processes.
    pub pids: Option<u64>,
}

/// A Vessel's own runtime: each field it sets replaces the node's
/// ([`RuntimeConf`], and the config's `"quiescence"`); each it leaves out
/// (`None`) is the node's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VesselRuntime {
    /// Its root filesystem (read-only), an absolute path on the node.
    pub rootfs: Option<PathBuf>,
    /// Its agent's command line (not empty).
    pub args: Option<Vec<String>>,
    /// Its agent's environment, `NAME=value`.
    pub env: Option<Vec<String>>,
    /// Run the agent through the node's Landlock shim (`true`) or not
    /// (`false`).  `true` on a node without a shim is an error, not a
    /// silent run without it.
    pub landlock: Option<bool>,
    /// Memory limit in bytes (at least 1).
    pub memory_bytes: Option<u64>,
    /// Maximum number of processes (at least 1).
    pub pids: Option<u64>,
    /// Databases whose quiescence is checked at each Seal.
    pub quiescence: Option<Vec<String>>,
}

/// What a Vessel runs with: its own runtime over the node's, resolved and
/// checked ([`VesselConf::effective`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effective {
    /// The root filesystem.
    pub rootfs: PathBuf,
    /// The agent's command line (not empty).
    pub args: Vec<String>,
    /// The agent's environment.
    pub env: Vec<String>,
    /// The Landlock shim inside the rootfs, if used.
    pub landlock_shim: Option<String>,
    /// Memory limit in bytes.
    pub memory_bytes: Option<u64>,
    /// Maximum number of processes.
    pub pids: Option<u64>,
    /// Databases whose quiescence is checked at each Seal.
    pub quiescence: Vec<String>,
}

/// Check an environment: each entry `NAME=value`, the name a C identifier,
/// no NUL anywhere.
pub fn check_env(env: &[String]) -> Result<(), String> {
    for e in env {
        let name = e
            .split_once('=')
            .map(|(n, _)| n)
            .ok_or_else(|| format!("env {e:?} must be NAME=value"))?;
        let mut chars = name.chars();
        let first_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if !first_ok || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!("env {e:?}: {name:?} is not a valid variable name"));
        }
        if e.contains('\0') {
            return Err(format!("env {name:?} contains a NUL byte"));
        }
    }
    Ok(())
}

/// Check quiescence paths: relative to the dataset, not empty, no `..`.
pub fn check_quiescence(dbs: &[String]) -> Result<(), String> {
    match dbs.iter().find(|q| {
        q.is_empty()
            || q.contains('\0')
            || Path::new(q).is_absolute()
            || q.split('/').any(|c| c == "..")
    }) {
        Some(q) => Err(format!(
            "quiescence path {q:?} must be relative to the dataset, without \"..\""
        )),
        None => Ok(()),
    }
}

/// The ownership a takeover replaces: what the operator read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeOver {
    /// The Warden to fence.
    pub holder: WardenId,
    /// Its epoch.
    pub epoch: Epoch,
}

impl TakeOver {
    /// `{"holder": <warden>, "epoch": <n>}`.
    fn parse(v: &Value) -> Result<Self, ConfigError> {
        let Value::Object(_) = v else {
            return Err(bad("\"takeover\" must be {\"holder\": <warden>, \"epoch\": <n>}: the ownership to replace, as read (true/false is no longer accepted)"));
        };
        only_keys(v, "takeover", &["holder", "epoch"])?;
        let n = |k: &str| {
            field(v, k)?
                .as_u64()
                .filter(|n| *n > 0)
                .ok_or_else(|| bad(format!("\"takeover.{k}\" must be a positive integer")))
        };
        Ok(Self {
            holder: WardenId::new(n("holder")?),
            epoch: Epoch::new(n("epoch")?),
        })
    }
}

/// One Vessel to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VesselConf {
    /// Its namespace.
    pub namespace: Namespace,
    /// Its subject (the id is derived from both).
    pub subject: String,
    /// Take it over from exactly this ownership, if another Warden holds
    /// it (none: never).
    pub takeover: Option<TakeOver>,
    /// Its host uid/gid range: slot `n` is
    /// `host_uid_base + n·65536 ..+65536`.  No two Vessels on a node share
    /// one, so one Vessel's processes cannot touch another's files or
    /// signal its processes.  A Vessel born from the void owns its
    /// dataset's files with host ids in this range and `zfs send` keeps
    /// them, so it keeps its slot on every node it runs on.  A fork in
    /// another slot runs over its lineage's files through an idmapped mount
    /// (F6): its files stay in that range, and its slot is this entry's.
    pub uid_slot: u32,
    /// What to do when its agent exits ([`Restart`]); `never` by default.
    pub restart: Restart,
    /// Its own runtime, over the node's; `None` runs it with the node's.
    /// (Boxed: most Vessels have none, and a `VesselConf` is moved a lot.)
    pub runtime: Option<Box<VesselRuntime>>,
    /// Forked from another Vessel on this node instead of born from the
    /// void ([`ForkConf`]); `None`: a birth.
    pub fork: Option<ForkConf>,
    /// Its verifier requirement (D57, `"verifier"`); `None`: it cannot
    /// nominate.  (Boxed, as `runtime`.)
    pub verifier: Option<Box<VerifierConf>>,
    /// Its Seal nominated at each start (`"candidate"`); needs `verifier`.
    /// (Boxed, as `runtime`.)
    pub candidate: Option<Box<CandidateConf>>,
    /// Born from a Template (P4 §5.5, D50: `"template": "<name>@<version>"`
    /// or `"<template_id>"`) instead of the void; `None`: not.  Excludes
    /// `fork`.  A Vessel that exists already must have been born from this
    /// Template, asked by this name.  (Boxed, as `runtime`.)
    pub template: Option<Box<TemplateRef>>,
    /// Whether its effects are released or held ([`EffectsConf`],
    /// `"effects": "dispatch" | "hold"`); `None`: by origin (P3 D4: a
    /// fork holds, a Vessel born from the void or by succession
    /// dispatches).  A config entry may say otherwise; an agent never can.
    pub effects: Option<EffectsConf>,
    /// Promote a fork at start time, before the agent runs
    /// ([`PromoteConf`], `"promote": {"child": "<subject>", "seal":
    /// "last"}`).  The child must be a fork of this Vessel, on this node.
    /// Used by the no-trace gate (P3 file 10).
    pub promote: Option<PromoteConf>,
    /// Forks its agent may ask for over the Field ([`ForksConf`],
    /// `"forks": {"slots": [<uid slot>, ...]}`); `None`: none.  (Boxed,
    /// as `runtime`.)
    pub forks: Option<Box<ForksConf>>,
}

/// The forks a Vessel's agent may ask for over the Field (P3 D1: a
/// request, never an authority).  Each request takes the first slot of
/// `slots` that no child of this Vessel has taken yet, so the list is
/// also the quota: one child per slot, a slot never given twice.  The
/// child is an entry the Warden makes ([`ForksConf::child`]): named
/// `<subject>-fork-<slot>`, forked from the Seal asked for (refused
/// until that Seal is shipped: [`Host::shipped_seal`]), in this
/// Vessel's namespace and runtime, effects always held, never restarted,
/// and with no forks of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForksConf {
    /// The uid slots its children may take, in order.
    pub slots: Vec<u32>,
}

impl ForksConf {
    /// The name of `parent`'s child in `slot`.
    pub fn child_name(parent: &str, slot: u32) -> String {
        format!("{parent}-fork-{slot}")
    }

    /// The entry of `parent`'s child in `slot`, forked from its Seal at
    /// `seal`.
    pub fn child(parent: &VesselConf, slot: u32, seal: Lsn) -> VesselConf {
        VesselConf {
            candidate: None,
            verifier: None,
            template: None,
            namespace: parent.namespace,
            subject: Self::child_name(&parent.subject, slot),
            takeover: None,
            uid_slot: slot,
            restart: Restart::Never,
            runtime: parent.runtime.clone(),
            fork: Some(ForkConf {
                parent: parent.subject.clone(),
                seal: SealAt::At(seal),
            }),
            effects: Some(EffectsConf::Hold),
            promote: None,
            forks: None,
        }
    }
}

/// What a Vessel's entry says about its effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectsConf {
    /// Released: a sender may act on them (`"dispatch"`).
    Dispatch,
    /// Held as proposals until a parent promotes (`"hold"`).
    Hold,
}

impl EffectsConf {
    /// The engine's mode for `origin`, with this entry's say if any.
    pub fn mode(this: Option<Self>, origin: &taso_core::record::Origin) -> Mode {
        match this {
            Some(EffectsConf::Dispatch) => Mode::Dispatch,
            Some(EffectsConf::Hold) => Mode::Hold,
            None => Mode::of(origin),
        }
    }
}

/// A Vessel forked from another on this node (fencing review F6 step 3c,
/// decision D1 of 2026-10-21; config: `"fork": {"parent": "<subject>",
/// "seal": "last" | <lsn>}`, `seal` defaulting to `"last"`).
///
/// Its first start forks it from the parent's accepted Seal, read from the
/// parent's local log without opening or claiming the parent
/// ([`Host::fork_from_log`]): a running parent is not disturbed.  The child
/// is in the parent's namespace (the entry's `namespace`, which names the
/// parent too), runs in its own `uid_slot`, and over the parent's files
/// through an idmapped `/work` when its slot is another
/// ([`crate::runtime::work_dir_range`]).  After that it opens like any
/// Vessel; an entry that names another parent than its Chronicle's
/// Lineage record is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkConf {
    /// The parent's subject (same namespace).
    pub parent: String,
    /// Which of its accepted Seals.
    pub seal: SealAt,
}

/// Promote a fork at start time, before the agent runs
/// (`"promote": {"child": "<subject>", "seal": "last" | <lsn>}`).
/// The child (same namespace) must be a fork of this Vessel, on this
/// node, with a sealed log.  The promotion is recorded and its
/// proposals adopted before the Field socket opens, so the agent's
/// first `Open` sees the released effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromoteConf {
    /// The child's subject (same namespace as this Vessel).
    pub child: String,
    /// Which of the child's accepted Seals to promote.
    pub seal: SealAt,
}

/// When a long-running Warden starts a Vessel's agent again after it
/// exited (`"restart"` in the config).  A Vessel stopped on purpose (removed
/// from the Warden's source) is never restarted, whatever this says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Restart {
    /// Run once (`"never"`): today's behaviour, and the default.
    #[default]
    Never,
    /// Again only if the agent failed, or never started (`"on-failure"`).
    OnFailure,
    /// Again whenever it exits (`"always"`).
    Always,
}

impl Restart {
    /// Whether to run again after a run that did not stop on purpose.
    /// `agent_ok` is `Some(true)` if the agent exited successfully,
    /// `Some(false)` if it failed, `None` if it never ran (the start
    /// failed, or the container could not be started).
    pub fn again(self, agent_ok: Option<bool>) -> bool {
        match self {
            Self::Never => false,
            Self::OnFailure => agent_ok != Some(true),
            Self::Always => true,
        }
    }
}

/// Asks a running Vessel to stop ([`Node::run_vessel_until`]).  Clones share
/// one request.  Stopping kills the agent's container: the turn in progress
/// was never sealed, and the next start rolls the state back to the last
/// Seal, so a stop is as safe as a crash and no more.
#[derive(Clone, Debug, Default)]
pub struct Stop(Arc<AtomicBool>);

impl Stop {
    /// A stop not yet requested.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request the stop.  Idempotent.
    pub fn request(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether a stop was requested.
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl RuntimeConf {
    /// The first host uid of the Template range, if a `template_slot` is
    /// set and its range fits in a u32.
    pub fn template_base(&self) -> Option<u32> {
        let base = self
            .template_slot?
            .checked_mul(ID_RANGE)?
            .checked_add(self.host_uid_base)?;
        base.checked_add(ID_RANGE - 1)?;
        Some(base)
    }
}

impl VesselConf {
    /// The Vessel's id.
    pub fn id(&self) -> ChronicleId {
        vessel_id(self.namespace, self.subject.as_bytes())
    }

    /// The first host uid/gid of its range, if the range fits in a u32.
    pub fn host_uid(&self, rt: &RuntimeConf) -> Option<u32> {
        let base = self
            .uid_slot
            .checked_mul(ID_RANGE)?
            .checked_add(rt.host_uid_base)?;
        base.checked_add(ID_RANGE - 1)?;
        Some(base)
    }

    /// What it runs with: its own runtime over the node's `rt` and the
    /// config's `quiescence`, checked.  An error says what is missing or
    /// wrong; the Vessel is not started.
    pub fn effective(&self, rt: &RuntimeConf, quiescence: &[String]) -> Result<Effective, String> {
        let own = self.runtime.as_deref().cloned().unwrap_or_default();
        let rootfs = own
            .rootfs
            .or_else(|| rt.rootfs.clone())
            .ok_or("no rootfs: neither the Vessel nor the node's runtime names one")?;
        if !rootfs.is_absolute() || rootfs.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(format!(
                "rootfs {} must be an absolute path",
                rootfs.display()
            ));
        }
        let args = own.args.unwrap_or_else(|| rt.args.clone());
        if args.is_empty() {
            return Err("no agent: neither the Vessel nor the node's runtime has args".into());
        }
        if args.iter().any(|a| a.contains('\0')) {
            return Err("args contain a NUL byte".into());
        }
        let env = own.env.unwrap_or_else(|| rt.env.clone());
        check_env(&env)?;
        let landlock_shim = match own.landlock {
            None => rt.landlock_shim.clone(),
            Some(false) => None,
            Some(true) => Some(
                rt.landlock_shim
                    .clone()
                    .ok_or("Landlock asked for, but the node has no runtime.landlock_shim")?,
            ),
        };
        let memory_bytes = own.memory_bytes.or(rt.memory_bytes);
        let pids = own.pids.or(rt.pids);
        if memory_bytes == Some(0) || pids == Some(0) {
            return Err("memory_bytes and pids must be at least 1".into());
        }
        let quiescence = own.quiescence.unwrap_or_else(|| quiescence.to_vec());
        check_quiescence(&quiescence)?;
        Ok(Effective {
            rootfs,
            args,
            env,
            landlock_shim,
            memory_bytes,
            pids,
            quiescence,
        })
    }
}

/// Where a node's Vessels come from (`"source"`; see the module docs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SourceConf {
    /// The config's own `"vessels"` list (`"static"`, the default).
    #[default]
    Static,
    /// Vessel resources in a Kubernetes cluster (`{"kubernetes": {...}}`).
    Kubernetes(KubeSourceConf),
}

/// How to reach the Kubernetes API, if not from inside a pod.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KubeApiConf {
    /// `https://host:port` (never plain http: the token goes with every
    /// request).
    pub url: String,
    /// A file holding the bearer token (re-read on every request).
    pub token_file: PathBuf,
    /// Trust only this CA (PEM), if given.
    pub ca_file: Option<PathBuf>,
}

/// What a Kubernetes cluster may ask of this node.  Every bound is checked
/// per Vessel resource, which is refused if it asks for more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KubeSourceConf {
    /// This node's name: only Vessels whose `spec.node` is it are run here.
    pub node: String,
    /// The Kubernetes namespaces Vessels are taken from, each with the one
    /// Taso tenant its Vessels must name (decision D1).  No tenant belongs to
    /// two namespaces, so one namespace's users can never name another's
    /// Vessels.  Vessels in any other namespace are refused.
    pub tenants: std::collections::BTreeMap<String, Namespace>,
    /// Every Vessel's `spec.rootfs.path` must resolve to a directory inside
    /// this one (D2).
    pub rootfs_dir: PathBuf,
    /// The most memory a Vessel may ask for, in bytes.
    pub max_memory_bytes: u64,
    /// The most processes a Vessel may ask for.
    pub max_pids: u64,
    /// Whether a Vessel may ask to run without Landlock (`false`: refused).
    pub allow_without_landlock: bool,
    /// The API server; `None` is the in-cluster service account.
    pub api: Option<KubeApiConf>,
}

/// A Kubernetes namespace name (an RFC 1123 label: lowercase letters,
/// digits and `-`, at most 63, starting and ending with a letter or digit).
pub fn valid_kube_namespace(s: &str) -> bool {
    s.len() <= 63 && !s.contains('.') && crate::kube::valid_name(s)
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
    /// Batch Seal snapshots ([`crate::snapbatch`]; ZFS only).
    pub batched_snapshots: bool,
    /// Where the Vessels live: `"zfs"` (the default) or
    /// `{"blk": {"socket": ..., "mounts": ..., "spool": ...}}`.
    pub storage: StorageConf,
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
    /// Where the Vessels come from.
    pub source: SourceConf,
    /// The Vessels to run (a static source; empty for any other).
    pub vessels: Vec<VesselConf>,
    /// Nominations on this node (P4 §3.1, D58): `"sanction": {"classmap":
    /// "<path>", "allowed_exclude": [<class>, ...]}`; `None`: this node
    /// nominates nothing.
    pub sanction: Option<SanctionNodeConf>,
}

/// The node's `"sanction"` (D58).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanctionNodeConf {
    /// The classification map's file, read when the node starts.
    pub classmap: PathBuf,
    /// The classes a nomination may drop (default `[Scratch]`).
    pub allowed_exclude: std::collections::BTreeSet<PathClass>,
}

/// A Vessel's `"verifier"` (D57): its verifier requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierConf {
    /// The verifier Template, `name@version` or a `template_id` (D50).
    pub template: TemplateRef,
    /// The verifier config's file: its bytes are the `vconf` object.
    pub config: PathBuf,
    /// The requirement's version, set by the operator.
    pub version: u32,
}

/// A Vessel's `"candidate"`: its Seal nominated at start (§3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateConf {
    /// Which Seal.
    pub seal: SealAt,
    /// The classes dropped.
    pub exclude: std::collections::BTreeSet<PathClass>,
}

/// Where a node's Vessels live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageConf {
    /// ZFS datasets under `root`.
    Zfs,
    /// The block log served by `taso-blkd`.
    Blk {
        /// The daemon's control socket.
        socket: PathBuf,
        /// Datasets are mounted under it (`<mounts>/<dataset>`).
        mounts: PathBuf,
        /// Where shipped streams pass through files (shared with the
        /// daemon, on this host).
        spool: PathBuf,
    },
}

impl StorageConf {
    /// The storage this configuration names (`batched`: ZFS Seal batching).
    pub fn open(&self, batched: bool) -> crate::storage::Storage {
        match self {
            Self::Zfs => {
                let z = crate::zfs::Zfs::cli();
                crate::storage::Storage::Zfs(if batched { z.batched() } else { z })
            }
            Self::Blk {
                socket,
                mounts,
                spool,
            } => crate::storage::Storage::Blk(crate::blk::BlkPool::new(socket, mounts, spool)),
        }
    }
}

fn storage_conf(v: &Value) -> Result<StorageConf, ConfigError> {
    match v.get("storage") {
        None => Ok(StorageConf::Zfs),
        Some(Value::String(s)) if s == "zfs" => Ok(StorageConf::Zfs),
        Some(o @ Value::Object(m)) if m.contains_key("blk") => {
            only_keys(o, "storage", &["blk"])?;
            let b = &m["blk"];
            only_keys(b, "storage.blk", &["socket", "mounts", "spool"])?;
            let mounts = abs_path(b, "mounts")?;
            if mounts == Path::new("/") {
                return Err(bad("\"storage.blk.mounts\" must not be /"));
            }
            Ok(StorageConf::Blk {
                socket: abs_path(b, "socket")?,
                mounts,
                spool: abs_path(b, "spool")?,
            })
        }
        Some(_) => Err(bad(
            "\"storage\" must be \"zfs\" or {\"blk\": {\"socket\", \"mounts\", \"spool\"}}",
        )),
    }
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
    field(v, key)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| bad(format!("{key:?} must be a string")))
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
        Some(x) => x
            .as_u64()
            .map(Some)
            .ok_or_else(|| bad(format!("{key:?} must be a non-negative integer"))),
    }
}

fn strings(v: &Value, key: &str) -> Result<Vec<String>, ConfigError> {
    match v.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| bad(format!("{key:?} must be strings")))
            })
            .collect(),
        Some(_) => Err(bad(format!("{key:?} must be an array of strings"))),
    }
}

fn bool_or(v: &Value, key: &str, default: bool) -> Result<bool, ConfigError> {
    match v.get(key) {
        None => Ok(default),
        Some(x) => x
            .as_bool()
            .ok_or_else(|| bad(format!("{key:?} must be true or false"))),
    }
}

/// Refuse keys of `v` not in `keys`: in objects where a misspelt key
/// would quietly loosen a bound.
fn only_keys(v: &Value, what: &str, keys: &[&str]) -> Result<(), ConfigError> {
    let o = v
        .as_object()
        .ok_or_else(|| bad(format!("{what:?} must be an object")))?;
    match o.keys().find(|k| !keys.contains(&k.as_str())) {
        Some(k) => Err(bad(format!("{what:?}: unknown key {k:?}"))),
        None => Ok(()),
    }
}

/// An optional integer of at least 1.
fn opt_positive(v: &Value, key: &str) -> Result<Option<u64>, ConfigError> {
    match opt_u64(v, key)? {
        Some(0) => Err(bad(format!("{key:?} must be at least 1"))),
        n => Ok(n),
    }
}

/// An optional array of strings (`None` if absent).
fn opt_strings(v: &Value, key: &str) -> Result<Option<Vec<String>>, ConfigError> {
    if v.get(key).is_none() {
        return Ok(None);
    }
    strings(v, key).map(Some)
}

/// A list of class names (D58): each one a map assigns, at most once.
fn classes(v: &Value, what: &str) -> Result<std::collections::BTreeSet<PathClass>, ConfigError> {
    let Some(a) = v.as_array() else {
        return Err(bad(format!("{what:?} must be an array of class names")));
    };
    let mut out = std::collections::BTreeSet::new();
    for x in a {
        let name = x
            .as_str()
            .ok_or_else(|| bad(format!("{what:?}: every class must be a string")))?;
        let c = crate::nominate::class_named(name)
            .ok_or_else(|| bad(format!("{what:?}: {name:?} is not a class")))?;
        if !out.insert(c) {
            return Err(bad(format!("{what:?}: {name:?} is listed twice")));
        }
    }
    Ok(out)
}

/// The node's `"sanction"` ([`SanctionNodeConf`]).
fn sanction_conf(v: &Value) -> Result<SanctionNodeConf, ConfigError> {
    only_keys(v, "sanction", &["classmap", "allowed_exclude"])?;
    Ok(SanctionNodeConf {
        classmap: abs_path(v, "classmap")?,
        allowed_exclude: match v.get("allowed_exclude") {
            None => [PathClass::Scratch].into(),
            Some(a) => classes(a, "sanction.allowed_exclude")?,
        },
    })
}

/// A Vessel's `"verifier"` ([`VerifierConf`]).
fn verifier_conf(v: &Value) -> Result<VerifierConf, ConfigError> {
    only_keys(v, "verifier", &["template", "config", "version"])?;
    Ok(VerifierConf {
        template: TemplateRef::parse(&string(v, "template")?)
            .map_err(|e| bad(format!("\"verifier.template\": {e}")))?,
        config: abs_path(v, "config")?,
        version: u32::try_from(
            field(v, "version")?
                .as_u64()
                .ok_or_else(|| bad("\"verifier.version\" must be an integer"))?,
        )
        .map_err(|_| bad("\"verifier.version\" is too large"))?,
    })
}

/// A Vessel's `"candidate"` ([`CandidateConf`]).
fn candidate_conf(v: &Value) -> Result<CandidateConf, ConfigError> {
    only_keys(v, "candidate", &["seal", "exclude"])?;
    let seal = match v.get("seal") {
        None => SealAt::Last,
        Some(Value::String(s)) if s == "last" => SealAt::Last,
        Some(n) => SealAt::At(Lsn::new(n.as_u64().filter(|n| *n > 0).ok_or_else(
            || bad("\"candidate.seal\" must be \"last\" or a positive lsn"),
        )?)),
    };
    Ok(CandidateConf {
        seal,
        exclude: match v.get("exclude") {
            None => std::collections::BTreeSet::new(),
            Some(a) => classes(a, "candidate.exclude")?,
        },
    })
}

/// A Vessel's `"fork"` ([`ForkConf`]).  Unknown keys are refused: a
/// misspelt `seal` must not quietly fork from the newest Seal.
fn fork_conf(f: &Value) -> Result<ForkConf, ConfigError> {
    only_keys(f, "fork", &["parent", "seal"])?;
    let parent = string(f, "parent")?;
    if parent.is_empty() {
        return Err(bad("\"fork\": \"parent\" must not be empty"));
    }
    let seal = match f.get("seal") {
        None => SealAt::Last,
        Some(Value::String(s)) if s == "last" => SealAt::Last,
        Some(Value::Number(n)) => match n.as_u64() {
            Some(l) if l >= 1 => SealAt::At(Lsn::new(l)),
            _ => {
                return Err(bad(
                    "\"fork\": \"seal\" must be \"last\" or an lsn of at least 1",
                ))
            }
        },
        Some(_) => {
            return Err(bad(
                "\"fork\": \"seal\" must be \"last\" or an lsn of at least 1",
            ))
        }
    };
    Ok(ForkConf { parent, seal })
}

/// A Vessel's `"promote"` ([`PromoteConf`]).  Unknown keys are refused.
fn forks_conf(f: &Value) -> Result<ForksConf, ConfigError> {
    only_keys(f, "forks", &["slots"])?;
    let Some(a) = field(f, "slots")?.as_array() else {
        return Err(bad("\"forks\": \"slots\" must be an array of uid slots"));
    };
    if a.is_empty() {
        return Err(bad(
            "\"forks\": \"slots\" is empty (leave \"forks\" out for no forks)",
        ));
    }
    let mut slots = Vec::new();
    for x in a {
        let s = x
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| bad("\"forks\": every slot must be an integer that fits a uid slot"))?;
        if slots.contains(&s) {
            return Err(bad(format!("\"forks\": slot {s} is listed twice")));
        }
        slots.push(s);
    }
    Ok(ForksConf { slots })
}

fn promote_conf(p: &Value) -> Result<PromoteConf, ConfigError> {
    only_keys(p, "promote", &["child", "seal"])?;
    let child = string(p, "child")?;
    if child.is_empty() {
        return Err(bad("\"promote\": \"child\" must not be empty"));
    }
    let seal = match p.get("seal") {
        None => SealAt::Last,
        Some(Value::String(s)) if s == "last" => SealAt::Last,
        Some(Value::Number(n)) => match n.as_u64() {
            Some(l) if l >= 1 => SealAt::At(Lsn::new(l)),
            _ => {
                return Err(bad(
                    "\"promote\": \"seal\" must be \"last\" or an lsn of at least 1",
                ))
            }
        },
        Some(_) => {
            return Err(bad(
                "\"promote\": \"seal\" must be \"last\" or an lsn of at least 1",
            ))
        }
    };
    Ok(PromoteConf { child, seal })
}

/// A Vessel's own `"runtime"` in a static config.
fn vessel_runtime(r: &Value) -> Result<VesselRuntime, ConfigError> {
    only_keys(
        r,
        "runtime",
        &[
            "rootfs",
            "args",
            "env",
            "landlock",
            "memory_bytes",
            "pids",
            "quiescence",
        ],
    )?;
    Ok(VesselRuntime {
        rootfs: if r.get("rootfs").is_some() {
            Some(abs_path(r, "rootfs")?)
        } else {
            None
        },
        args: opt_strings(r, "args")?,
        env: opt_strings(r, "env")?,
        landlock: match r.get("landlock") {
            None => None,
            Some(x) => Some(
                x.as_bool()
                    .ok_or_else(|| bad("\"landlock\" must be true or false"))?,
            ),
        },
        memory_bytes: opt_positive(r, "memory_bytes")?,
        pids: opt_positive(r, "pids")?,
        quiescence: opt_strings(r, "quiescence")?,
    })
}

/// The `"kubernetes"` source.
fn kube_source(k: &Value, rt: &RuntimeConf) -> Result<KubeSourceConf, ConfigError> {
    only_keys(
        k,
        "kubernetes",
        &[
            "node",
            "tenants",
            "rootfs_dir",
            "max_memory_bytes",
            "max_pids",
            "allow_without_landlock",
            "api",
        ],
    )?;
    let node = string(k, "node")?;
    if !crate::kube::valid_name(&node) {
        return Err(bad(format!(
            "kubernetes.node {node:?} is not a valid node name"
        )));
    }
    let mut tenants = std::collections::BTreeMap::new();
    let mut owner: std::collections::BTreeMap<[u8; 16], String> = std::collections::BTreeMap::new();
    match field(k, "tenants")? {
        Value::Object(o) if !o.is_empty() => {
            for (ns, t) in o {
                if !valid_kube_namespace(ns) {
                    return Err(bad(format!(
                        "kubernetes.tenants: {ns:?} is not a valid namespace name"
                    )));
                }
                let t = t.as_str().ok_or_else(|| {
                    bad(format!("kubernetes.tenants.{ns}: must be 32 hex digits"))
                })?;
                let tenant = namespace(t)?;
                if let Some(other) = owner.insert(*tenant.as_bytes(), ns.clone()) {
                    return Err(bad(format!("kubernetes.tenants: {other:?} and {ns:?} map to the same tenant (one namespace per tenant)")));
                }
                tenants.insert(ns.clone(), tenant);
            }
        }
        _ => {
            return Err(bad(
                "kubernetes.tenants must map at least one namespace to its tenant",
            ))
        }
    }
    let max = |key: &str| -> Result<u64, ConfigError> {
        opt_positive(k, key)?.ok_or_else(|| {
            bad(format!(
                "kubernetes.{key} is required (no unbounded agents from a cluster)"
            ))
        })
    };
    let (max_memory_bytes, max_pids) = (max("max_memory_bytes")?, max("max_pids")?);
    if rt.memory_bytes.is_some_and(|m| m > max_memory_bytes)
        || rt.pids.is_some_and(|p| p > max_pids)
    {
        return Err(bad(
            "the node's runtime memory_bytes/pids are above kubernetes.max_memory_bytes/max_pids",
        ));
    }
    let allow_without_landlock = bool_or(k, "allow_without_landlock", false)?;
    if rt.landlock_shim.is_none() && !allow_without_landlock {
        return Err(bad(
            "kubernetes needs runtime.landlock_shim (or allow_without_landlock: true)",
        ));
    }
    let api = match k.get("api") {
        None => None,
        Some(a) => {
            only_keys(a, "api", &["url", "token_file", "ca_file"])?;
            let url = string(a, "url")?;
            if !url.starts_with("https://") {
                return Err(bad(
                    "kubernetes.api.url must be https:// (the token goes with every request)",
                ));
            }
            Some(KubeApiConf {
                url,
                token_file: abs_path(a, "token_file")?,
                ca_file: if a.get("ca_file").is_some() {
                    Some(abs_path(a, "ca_file")?)
                } else {
                    None
                },
            })
        }
    };
    Ok(KubeSourceConf {
        node,
        tenants,
        rootfs_dir: abs_path(k, "rootfs_dir")?,
        max_memory_bytes,
        max_pids,
        allow_without_landlock,
        api,
    })
}

/// A namespace: 32 hex digits.
fn namespace(s: &str) -> Result<Namespace, ConfigError> {
    let err = || bad(format!("namespace {s:?} must be 32 hex digits"));
    if s.len() != 32 {
        return Err(err());
    }
    let mut b = [0u8; 16];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(s.get(2 * i..2 * i + 2).ok_or_else(err)?, 16).map_err(|_| err())?;
    }
    Ok(Namespace::from_bytes(b))
}

impl Config {
    /// Parse and check a configuration.
    pub fn parse(json: &str) -> Result<Self, ConfigError> {
        let v: Value = serde_json::from_str(json).map_err(|e| bad(format!("not JSON: {e}")))?;
        let warden = field(&v, "warden")?
            .as_u64()
            .filter(|w| *w > 0)
            .ok_or_else(|| bad("\"warden\" must be a positive integer"))?;
        let c = field(&v, "coordinator")?;
        let coordinator = match (c.get("local"), c.get("remote")) {
            (Some(_), None) => CoordConf::Local {
                path: abs_path(c, "local")?,
                serve: if c.get("serve").is_some() {
                    Some(abs_path(c, "serve")?)
                } else {
                    None
                },
            },
            (None, Some(_)) => CoordConf::Remote {
                socket: abs_path(c, "remote")?,
            },
            _ => {
                return Err(bad(
                    "\"coordinator\" needs exactly one of \"local\" or \"remote\"",
                ))
            }
        };
        let root = Dataset::new(&string(&v, "root")?).map_err(|e| bad(e.to_string()))?;
        let r = field(&v, "runtime")?;
        let runtime = RuntimeConf {
            rootfs: if r.get("rootfs").is_some() {
                Some(abs_path(r, "rootfs")?)
            } else {
                None
            },
            host_uid_base: u32::try_from(
                field(r, "host_uid_base")?
                    .as_u64()
                    .ok_or_else(|| bad("\"host_uid_base\" must be an integer"))?,
            )
            .map_err(|_| bad("\"host_uid_base\" is too large"))?,
            template_slot: match opt_u64(r, "template_slot")? {
                None => None,
                Some(n) => {
                    Some(u32::try_from(n).map_err(|_| bad("\"template_slot\" is too large"))?)
                }
            },
            landlock_shim: match r.get("landlock_shim") {
                None | Some(Value::Null) => None,
                Some(_) => Some(abs_path(r, "landlock_shim")?.to_string_lossy().into_owned()),
            },
            args: strings(r, "args")?,
            env: strings(r, "env")?,
            memory_bytes: opt_u64(r, "memory_bytes")?,
            pids: opt_u64(r, "pids")?,
        };
        check_env(&runtime.env).map_err(|e| bad(format!("runtime: {e}")))?;
        let source = match v.get("source") {
            None => SourceConf::Static,
            Some(Value::String(s)) if s == "static" => SourceConf::Static,
            Some(s @ Value::Object(o)) if o.contains_key("kubernetes") => {
                only_keys(s, "source", &["kubernetes"])?;
                SourceConf::Kubernetes(kube_source(&o["kubernetes"], &runtime)?)
            }
            Some(_) => {
                return Err(bad(
                    "\"source\" must be \"static\" or {\"kubernetes\": {...}}",
                ))
            }
        };
        let vessels = match (v.get("vessels"), &source) {
            (None, SourceConf::Kubernetes(_)) => Vec::new(),
            (Some(Value::Array(a)), SourceConf::Kubernetes(_)) if a.is_empty() => Vec::new(),
            (Some(_), SourceConf::Kubernetes(_)) => {
                return Err(bad("\"vessels\" and a kubernetes source exclude each other: the cluster lists the Vessels"))
            }
            (None, SourceConf::Static) => return Err(bad("missing \"vessels\"")),
            (Some(Value::Array(a)), SourceConf::Static) => a
                .iter()
                .map(|x| {
                    Ok(VesselConf {
                        namespace: namespace(&string(x, "namespace")?)?,
                        subject: string(x, "subject")?,
                        takeover: match x.get("takeover") {
                            None | Some(Value::Null) => None,
                            Some(t) => Some(TakeOver::parse(t)?),
                        },
                        uid_slot: u32::try_from(
                            field(x, "uid_slot")?.as_u64().ok_or_else(|| bad("\"uid_slot\" must be an integer"))?,
                        )
                        .map_err(|_| bad("\"uid_slot\" is too large"))?,
                        restart: match x.get("restart") {
                            None => Restart::Never,
                            Some(r) => match r.as_str() {
                                Some("never") => Restart::Never,
                                Some("on-failure") => Restart::OnFailure,
                                Some("always") => Restart::Always,
                                _ => return Err(bad("\"restart\" must be \"never\", \"on-failure\" or \"always\"")),
                            },
                        },
                        runtime: match x.get("runtime") {
                            None => None,
                            Some(r) => Some(Box::new(vessel_runtime(r)?)),
                        },
                        fork: match x.get("fork") {
                            None | Some(Value::Null) => None,
                            Some(f) => Some(fork_conf(f)?),
                        },
                        verifier: match x.get("verifier") {
                            None | Some(Value::Null) => None,
                            Some(f) => Some(Box::new(verifier_conf(f)?)),
                        },
                        candidate: match x.get("candidate") {
                            None | Some(Value::Null) => None,
                            Some(f) => Some(Box::new(candidate_conf(f)?)),
                        },
                        template: match x.get("template") {
                            None | Some(Value::Null) => None,
                            Some(Value::String(t)) => Some(Box::new(
                                TemplateRef::parse(t).map_err(|e| bad(format!("\"template\": {e}")))?,
                            )),
                            Some(_) => return Err(bad("\"template\" must be \"<name>@<version>\" or a template_id (32 hex digits)")),
                        },
                        effects: match x.get("effects") {
                            None | Some(Value::Null) => None,
                            Some(e) => match e.as_str() {
                                Some("dispatch") => Some(EffectsConf::Dispatch),
                                Some("hold") => Some(EffectsConf::Hold),
                                _ => return Err(bad("\"effects\" must be \"dispatch\" or \"hold\"")),
                            },
                        },
                        promote: match x.get("promote") {
                            None | Some(Value::Null) => None,
                            Some(p) => Some(promote_conf(p)?),
                        },
                        forks: match x.get("forks") {
                            None | Some(Value::Null) => None,
                            Some(f) => Some(Box::new(forks_conf(f)?)),
                        },
                    })
                })
                .collect::<Result<Vec<_>, ConfigError>>()?,
            (Some(_), SourceConf::Static) => return Err(bad("\"vessels\" must be an array")),
        };
        let quiescence = strings(&v, "quiescence")?;
        check_quiescence(&quiescence).map_err(bad)?;
        let mut ids = std::collections::BTreeSet::new();
        let mut slots = std::collections::BTreeMap::new();
        // The Template range is reserved (D53): named here first, no
        // Vessel or fork slot may be it.
        if let Some(t) = runtime.template_slot {
            if runtime.template_base().is_none() {
                return Err(bad(format!(
                    "runtime: template_slot {t} does not fit above host_uid_base"
                )));
            }
            slots.insert(t, "the Template range (runtime.template_slot)".to_string());
        }
        for vc in &vessels {
            if !ids.insert(*vc.id().as_bytes()) {
                return Err(bad(format!("vessel {:?} is listed twice", vc.subject)));
            }
            if vc.host_uid(&runtime).is_none() {
                return Err(bad(format!(
                    "vessel {:?}: uid_slot {} does not fit above host_uid_base",
                    vc.subject, vc.uid_slot
                )));
            }
            if let Some(other) = slots.insert(vc.uid_slot, vc.subject.clone()) {
                return Err(bad(format!(
                    "vessels {other:?} and {:?} share uid_slot {}",
                    vc.subject, vc.uid_slot
                )));
            }
            vc.effective(&runtime, &quiescence)
                .map_err(|e| bad(format!("vessel {:?}: {e}", vc.subject)))?;
            if vc.candidate.is_some() && (vc.verifier.is_none() || v.get("sanction").is_none()) {
                return Err(bad(format!(
                    "vessel {:?}: a \"candidate\" needs its \"verifier\" and the node's \"sanction\"",
                    vc.subject
                )));
            }
            if vc.template.is_some() && vc.fork.is_some() {
                return Err(bad(format!(
                    "vessel {:?}: \"template\" and \"fork\" exclude each other",
                    vc.subject
                )));
            }
            if vc.template.is_some() && runtime.template_slot.is_none() {
                return Err(bad(format!(
                    "vessel {:?}: a Template birth needs runtime.template_slot",
                    vc.subject
                )));
            }
            if vc.fork.as_ref().is_some_and(|f| f.parent == vc.subject) {
                return Err(bad(format!(
                    "vessel {:?} cannot be forked from itself",
                    vc.subject
                )));
            }
        }
        // A fork slot is given to one child only, and never to a listed
        // Vessel: every slot named anywhere is named once.
        for vc in &vessels {
            for &s in vc.forks.iter().flat_map(|f| &f.slots) {
                let child = VesselConf {
                    uid_slot: s,
                    ..ForksConf::child(vc, s, Lsn::new(1))
                };
                if child.host_uid(&runtime).is_none() {
                    return Err(bad(format!(
                        "vessel {:?}: fork slot {s} does not fit above host_uid_base",
                        vc.subject
                    )));
                }
                if let Some(other) = slots.insert(s, vc.subject.clone()) {
                    return Err(bad(format!(
                        "vessel {:?}: fork slot {s} is also {other:?}'s",
                        vc.subject
                    )));
                }
                if !ids.insert(*child.id().as_bytes()) {
                    return Err(bad(format!(
                        "vessel {:?}: its fork {:?} is listed as a vessel too",
                        vc.subject, child.subject
                    )));
                }
            }
        }
        Ok(Self {
            warden: WardenId::new(warden),
            coordinator,
            root,
            state_dir: abs_path(&v, "state_dir")?,
            batched_snapshots: bool_or(&v, "batched_snapshots", true)?,
            storage: storage_conf(&v)?,
            store: StoreConf::parse_in(&v)?,
            prefix: v
                .get("prefix")
                .and_then(Value::as_str)
                .unwrap_or("vessels")
                .to_string(),
            run_dir: abs_path(&v, "run_dir")?,
            runtime,
            quiescence,
            source,
            sanction: match v.get("sanction") {
                None | Some(Value::Null) => None,
                Some(s) => {
                    let c = sanction_conf(s)?;
                    for vc in &vessels {
                        if let Some(k) = &vc.candidate {
                            if !k.exclude.is_subset(&c.allowed_exclude) {
                                return Err(bad(format!(
                                    "vessel {:?}: \"candidate.exclude\" is not within \"sanction.allowed_exclude\"",
                                    vc.subject
                                )));
                            }
                        }
                    }
                    Some(c)
                }
            },
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
    /// Registered and held by a Warden at an epoch.
    Held(WardenId, Epoch),
}

/// How the Vessel starts (see the module docs).  A takeover must name
/// the ownership read, exactly; one that names this Warden is spent; one
/// for a Vessel nobody holds is refused.
pub fn decide(known: Known, local_state: bool, me: WardenId, takeover: Option<TakeOver>) -> Start {
    match known {
        Known::No | Known::Unborn => match takeover {
            None => Start::Birth,
            Some(t) => Start::Refuse(format!(
                "takeover names Warden {} at epoch {}, but nobody holds the Vessel ({}): nothing to take over, nothing started; without \"takeover\" it is born here",
                t.holder.get(),
                t.epoch.get(),
                if known == Known::No {
                    "the coordinator does not know it"
                } else {
                    "its birth never finished"
                }
            )),
        },
        Known::Held(holder, epoch) if holder != me => match takeover {
            None => Start::Refuse(format!(
                "held by Warden {} at epoch {}; to fence it and take the Vessel over, set \"takeover\": {{\"holder\": {}, \"epoch\": {}}}",
                holder.get(),
                epoch.get(),
                holder.get(),
                epoch.get()
            )),
            Some(t) if (t.holder, t.epoch) != (holder, epoch) => Start::Refuse(format!(
                "takeover names Warden {} at epoch {}, but Warden {} holds the Vessel at epoch {}: not what was read, nothing fenced",
                t.holder.get(),
                t.epoch.get(),
                holder.get(),
                epoch.get()
            )),
            Some(_) if local_state => Start::Open,
            Some(_) => Start::Rebirth,
        },
        Known::Held(..) if local_state => Start::Open,
        Known::Held(..) => Start::Rebirth,
    }
}

/// The verdict of the first Seal after an open: `Unverified`, naming
/// what was lost, if recovery dropped anything (v0.4 §8.5).
pub fn verdict_after_open(r: &Recovery) -> Verdict {
    let mut lost = Vec::new();
    if r.segment.unaccepted_frames > 0 {
        lost.push(format!(
            "{} unaccepted records dropped",
            r.segment.unaccepted_frames
        ));
    }
    if r.segment.invalid_bytes > 0 {
        lost.push(format!(
            "a torn tail of {} bytes cut",
            r.segment.invalid_bytes
        ));
    }
    if let Some((kept, resumes)) = r.gap {
        lost.push(format!(
            "records {}..{} lost in a takeover",
            kept.lsn.get() + 1,
            resumes.lsn.get()
        ));
    }
    if !r.missing_layers.is_empty() {
        lost.push(format!(
            "{} Seals without their layer",
            r.missing_layers.len()
        ));
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
        lost.push(format!(
            "records {}..{} were never shipped",
            kept.lsn.get() + 1,
            resumes.lsn.get()
        ));
    }
    if !r.missing_layers.is_empty() {
        lost.push(format!(
            "{} Seals without their layer",
            r.missing_layers.len()
        ));
    }
    if lost.is_empty() {
        Verdict::Clean
    } else {
        Verdict::Unverified(format!("reborn: {}", lost.join(", ")))
    }
}

/// The runc container id of a Vessel run by `warden`.  The Warden is in
/// it because runc derives the container's cgroup from the id: a
/// Vessel's old container (its Warden frozen or cut off, the agent still
/// alive) must not share a cgroup with the one its new holder starts.  On
/// one machine they would collide; across machines it says who ran it.
/// The Vessel part comes first, so the hostname (the id's first 12
/// characters) stays the same across holders.
pub fn container_id(id: ChronicleId, warden: WardenId) -> String {
    let hex: String = id.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    format!("taso-{hex}-w{}", warden.get())
}

fn id_hex(id: ChronicleId) -> String {
    id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

// ── Publishing Seals ────────────────────────────────────────────────

/// Publishes each Seal as it is taken: finds its layer (one lookup, never
/// the whole list) and runs [`Vessel::publish_seal`].
pub struct SealPublisher {
    storage: Storage,
    packs: Packs<SharedStore, StorageSend>,
    /// The parent's Seal snapshot, for a Vessel forked from one whose
    /// first `fs` section is not shipped yet: that section is incremental
    /// from it.  Cleared once a section is shipped (later Seals are
    /// incremental from the last named one, and `origin` is refused).
    origin: Option<Snapshot>,
    /// Seals published.
    pub published: u64,
    /// Segment files pruned after a publish.
    pub pruned: u64,
    /// Prunes that failed (the publish stood; the files stay for the next).
    pub prune_failures: u64,
    /// The last prune failure.
    pub prune_error: Option<String>,
}

/// Closed segment files kept on local disk after a prune: the newest
/// ones, for readers that start near the head.
pub const KEEP_CLOSED: usize = 2;

impl SealPublisher {
    /// Publish `seal` of `vessel`.  `Ok(true)` if this call shipped it,
    /// `Ok(false)` if an earlier one had (a retry: only the log and the
    /// anchor were brought up to date).
    pub fn publish(
        &mut self,
        vessel: &mut Vessel<StorageLayers>,
        seal: Position,
    ) -> Result<bool, String> {
        let snap = self
            .storage
            .snapshot(vessel.dataset(), seal.lsn)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("Seal {} has no snapshot", seal.lsn.get()))?;
        let published = vessel
            .publish_seal(&self.packs, &snap, self.origin.as_ref())
            .map_err(|e| e.to_string())?;
        self.origin = None;
        Ok(published.record.is_some())
    }
}

impl AfterSeal<StorageLayers> for SealPublisher {
    fn after_seal(
        &mut self,
        vessel: &mut Vessel<StorageLayers>,
        seal: Position,
    ) -> Result<(), String> {
        self.publish(vessel, seal)?;
        self.published += 1;
        // What is shipped need not stay on local disk.  A failed prune
        // leaves the files in place; the next publish tries again.
        match vessel.prune(KEEP_CLOSED) {
            Ok(p) => self.pruned += p.removed.len() as u64,
            Err(e) => {
                self.prune_failures += 1;
                self.prune_error = Some(e.to_string());
            }
        }
        Ok(())
    }
}

/// Whether the log already names a shipped `fs` section.
/// A Vessel's Fork and Promote requests on this node ([`ForksConf`]).
struct NodeBranches<'n> {
    node: &'n Node,
    vc: &'n VesselConf,
    /// Requested once a promotion is done: the run ends, and the files are
    /// adopted at the next start (C7).
    promoted: &'n Stop,
}

/// A Vessel's Nominate requests on this node (§3.1).
struct NodeNominations<'n> {
    node: &'n Node,
    vc: &'n VesselConf,
}

impl crate::field::Nominations<StorageLayers> for NodeNominations<'_> {
    fn nominate(
        &mut self,
        vessel: &mut Vessel<StorageLayers>,
        seal: Option<u64>,
        exclude: &[String],
    ) -> NominateResult {
        let mut ex = std::collections::BTreeSet::new();
        for name in exclude {
            match crate::nominate::class_named(name) {
                Some(c) if ex.insert(c) => {}
                Some(_) => {
                    return NominateResult::Refused {
                        reason: format!("{name:?} is listed twice"),
                    }
                }
                None => {
                    return NominateResult::Refused {
                        reason: format!("{name:?} is not a class"),
                    }
                }
            }
        }
        self.node
            .nominate(self.vc, vessel, seal.map(Lsn::new), ex, NominatedBy::Agent)
    }
}

/// How long an agent that asked for a promotion has to exit by itself
/// before its container is killed (C7).
const PROMOTED_GRACE: Duration = Duration::from_secs(2);

impl Branches<StorageLayers> for NodeBranches<'_> {
    fn fork(
        &mut self,
        vessel: &Vessel<StorageLayers>,
        at: SealAt,
    ) -> Result<(String, u64), String> {
        let Some(forks) = &self.vc.forks else {
            return Err(format!(
                "{:?} may not fork: its entry gives no uid slots for forks",
                self.vc.subject
            ));
        };
        let host = self.node.host();
        // The first slot no child has taken: not asked for in this
        // Warden's life, no Vessel of that name on this node, and no
        // files of anyone's owned by its range.
        let slot = forks.slots.iter().copied().find(|&slot| {
            let id = vessel_id(
                self.vc.namespace,
                ForksConf::child_name(&self.vc.subject, slot).as_bytes(),
            );
            !self.node.requested.contains(id.as_bytes())
                && !host.dir_for(id).exists()
                && !self.node.held.iter().any(|h| h.slots.contains(&slot))
        });
        let Some(slot) = slot else {
            return Err(format!(
                "no fork slot left: all {} of {:?}'s are taken",
                forks.slots.len(),
                self.vc.subject
            ));
        };
        let name = ForksConf::child_name(&self.vc.subject, slot);
        // Only from a shipped Seal (C3): a child of a Seal only this node
        // holds could be reborn nowhere once the node is lost.  "last" is
        // fixed here to the Seal checked.
        let seal = host
            .shipped_seal(vessel.id(), at)
            .map_err(|e| format!("fork of {:?} at {at:?}: {e}", self.vc.subject))?;
        let child = host
            .fork_from_log(vessel.id(), SealAt::At(seal.lsn), name.as_bytes())
            .map_err(|e| format!("fork of {:?} at {at:?}: {e}", self.vc.subject))?;
        let seal = child
            .lineage()
            .origin
            .parent()
            .map(|p| p.seal)
            .ok_or_else(|| format!("the fork {name:?} has no parent in its Lineage"))?;
        drop(child);
        self.node
            .requested
            .add(ForksConf::child(self.vc, slot, seal));
        self.node.log(
            self.vc,
            format_args!(
                "forked {name:?} (uid slot {slot}) at Seal lsn {} on its agent's request",
                seal.get()
            ),
        );
        Ok((name, seal.get()))
    }

    fn child_log(
        &mut self,
        vessel: &Vessel<StorageLayers>,
        child: &str,
    ) -> Result<ReadLog, String> {
        let id = vessel_id(vessel.namespace(), child.as_bytes());
        self.node
            .host()
            .read_log_of(id)
            .map_err(|e| format!("the log of {child:?} cannot be read here: {e}"))
    }

    fn promoted(&mut self, child: &str, result: &PromoteResult) {
        match result {
            PromoteResult::Promoted { seal, adopted } => {
                self.node.log(
                    self.vc,
                    format_args!(
                        "promoted {child:?} at Seal lsn {seal} on its agent's request: {} effect(s) adopted; its files at the next start",
                        adopted.len()
                    ),
                );
                self.promoted.request();
            }
            PromoteResult::Refused { reason } => self.node.log(
                self.vc,
                format_args!("promotion of {child:?} refused: {reason}"),
            ),
        }
    }
}

fn has_fs_shipped(vessel: &Vessel<StorageLayers>) -> Result<bool, DaemonError> {
    let frames = vessel
        .chronicle()
        .frames()
        .map_err(|e| DaemonError::Io(format!("reading the log: {e}")))?;
    let summary = crate::summary::Summary::of(&frames).map_err(|(lsn, e)| {
        DaemonError::Io(format!("reading the log at lsn {}: {e}", lsn.get()))
    })?;
    Ok(summary.fs_shipped.is_some())
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
    /// Segment files pruned.
    pub pruned: u64,
    /// Prunes that failed, and the last reason.
    pub prune_failures: (u64, Option<String>),
    /// Whether the agent exited successfully, and its stderr.
    pub agent: Option<(bool, String)>,
    /// What settling the state did before the agent ran.
    pub settled: Settled,
    /// The run ended because a stop was requested ([`Stop`]): the agent
    /// was killed, or never started.
    pub stopped: bool,
}

/// What [`settle`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settled {
    /// The birth Seal, if this start took it.
    pub birth: Option<Position>,
    /// The Seal the state was rolled back to, if any had a layer.
    pub rolled_back_to: Option<Position>,
    /// The last Seal in the log.
    pub last_seal: Option<Position>,
}

impl Settled {
    /// The state is older than the last Seal: its layer was missing, so
    /// the rollback went to an earlier one (or to none).
    pub fn behind(&self) -> bool {
        self.rolled_back_to != self.last_seal
    }
}

/// Put a Vessel's state at a Seal before its agent runs (step 2 in the
/// module docs): the birth Seal if it has none, then a rollback to the
/// last Seal.  `NotPristine` (no Seal, but records after Lineage) is an
/// error: there is no level to put the state at.
pub fn settle<L: Layers>(vessel: &mut Vessel<L>) -> Result<Settled, VesselError> {
    settle_at(vessel, BIRTH_TURN)
}

/// [`settle`] with the birth Seal (if one is taken) at `birth_turn`: a
/// fork's or succession's parent's turn ([`Host::birth_turn`]), so its agent
/// continues the parent's count.
pub fn settle_at<L: Layers>(
    vessel: &mut Vessel<L>,
    birth_turn: TurnId,
) -> Result<Settled, VesselError> {
    let birth = match vessel.last_seal() {
        None => Some(vessel.seal_birth_at(birth_turn)?.seal),
        Some(_) => None,
    };
    let rolled_back_to = vessel.rollback()?;
    Ok(Settled {
        birth,
        rolled_back_to,
        last_seal: vessel.last_seal(),
    })
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
    /// Its runtime is incomplete or wrong ([`VesselConf::effective`]).
    Runtime(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vessel(e) => write!(f, "{e}"),
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Refused(e) => write!(f, "refused: {e}"),
            Self::Runtime(e) => write!(f, "runtime: {e}"),
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

/// The lock file in a run directory.
pub const RUN_LOCK: &str = "daemon.lock";

/// A claimed run directory: the lock is held until this is dropped (or
/// the process exits, however it exits).
#[derive(Debug)]
pub struct RunDirLock {
    _file: File,
    path: PathBuf,
}

impl RunDirLock {
    /// The lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Where the kernel shows SELinux: this file exists exactly when SELinux
/// is enabled, enforcing or permissive (relative to the sysfs root).
pub const SELINUX_ENFORCE: &str = "fs/selinux/enforce";

/// Refuse to start on a host with SELinux enabled (P4 spec rev. 12 D32).
/// `sys` is the sysfs root, `/sys` on a real host.  A host whose sysfs
/// cannot be read is refused too: not knowing is not "no SELinux".
pub fn refuse_selinux(sys: &Path) -> io::Result<()> {
    let enforce = sys.join(SELINUX_ENFORCE);
    match std::fs::symlink_metadata(&enforce) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "SELinux is enabled ({} exists): unsupported host; Taso runs on Linux \
                 without SELinux (e.g. Ubuntu, Debian), because SELinux labels every \
                 file and a manifest refuses labelled entries (P4 spec D32)",
                enforce.display()
            ),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Absent: no SELinux, provided sysfs itself is there.
            std::fs::metadata(sys.join("fs")).map(|_| ()).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "cannot tell whether SELinux is enabled ({}: {e})",
                        sys.display()
                    ),
                )
            })
        }
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!(
                "cannot tell whether SELinux is enabled ({}: {e})",
                enforce.display()
            ),
        )),
    }
}

/// Claim `run_dir` for this daemon: create it, then take an exclusive
/// `flock` on [`RUN_LOCK`] without waiting.  Two daemons on one run
/// directory would share a runc root and sweep each other's agents, so a
/// held lock is a refusal (`WouldBlock`), not something to wait out.  The
/// kernel releases it when the holder dies, so a restart after a crash is
/// never refused by its own dead predecessor.
pub fn claim_run_dir(run_dir: &Path) -> io::Result<RunDirLock> {
    std::fs::create_dir_all(run_dir)?;
    let path = run_dir.join(RUN_LOCK);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)?;
    // A lock just released can still be held for a moment by a process
    // another thread is spawning (a child between fork and exec holds a
    // copy of every open file): retry briefly, as the Chronicle's own
    // directory lock does, before calling it another daemon's.
    let start = std::time::Instant::now();
    let mut pause = Duration::from_millis(1);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(RunDirLock { _file: file, path }),
            Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < RUN_LOCK_WAIT => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(20));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "{} is held by another taso-wardend (one daemon per run_dir)",
                        path.display()
                    ),
                ))
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(e),
        }
    }
}

/// How long [`claim_run_dir`] retries a held lock before refusing.
const RUN_LOCK_WAIT: Duration = Duration::from_millis(500);

/// Remove every container in a claimed run directory's runc root
/// ([`Runc::sweep`]).  Any container that could not be removed is an
/// error naming it: its agent may still be writing into its dataset, so
/// the daemon must not start Vessels beside it.
pub fn sweep_stale<R: RuncRunner>(runc: &Runc<R>) -> io::Result<Swept> {
    let swept = runc.sweep()?;
    if swept.failed.is_empty() {
        return Ok(swept);
    }
    let failed: Vec<String> = swept
        .failed
        .iter()
        .map(|(id, why)| format!("{id} ({})", why.trim()))
        .collect();
    Err(io::Error::other(format!(
        "stale containers could not be removed: {}",
        failed.join(", ")
    )))
}

/// What the node's pool holds of each Vessel under `root`, for
/// [`crate::source::Guard::seeded`]: for every `v-<id>` dataset, the uid
/// slots whose ranges own files in it (`zfs userspace`, mounted or not;
/// on the block log, a walk of the mounted file system), and its parent
/// from the Lineage record of its local Chronicle under `state_dir`
/// ([`crate::vessel::lineage_in`]; F6: a fork's files are its lineage's).
/// A log that cannot be read gives a warning and no parent: that can only
/// keep the Vessel apart from a lineage (blocked, never let in).
/// Root (uid 0) owns a fresh dataset's top directory and counts for no
/// slot.  Also returns warnings: datasets that are not a Vessel's, and uids
/// in no slot's range (they count for none).  Any failure to read the pool
/// is an error: without it, a slot could be given to a second Vessel.
pub fn held_on<H: Holdings>(
    pool: &H,
    root: &Dataset,
    host_uid_base: u32,
    template_slot: Option<u32>,
    state_dir: &Path,
) -> Result<(Vec<Held>, Vec<String>), LayerError> {
    let mut held = Vec::new();
    let mut warnings = Vec::new();
    for ds in pool.children(root)? {
        let name = ds.as_str().rsplit('/').next().unwrap_or_default();
        // A Template's layer or build (P4 §5.6): no Vessel's, its range
        // the reserved Template range.
        if name.starts_with("t-") || name.starts_with("tb-") {
            continue;
        }
        let Some(key) = name.strip_prefix("v-").and_then(key_of_hex) else {
            warnings.push(format!("{ds} is not a Vessel dataset (v-<id>): ignored"));
            continue;
        };
        let hex = name.strip_prefix("v-").unwrap_or_default();
        let (parent, from_template) = match crate::vessel::lineage_in(&state_dir.join(hex)) {
            Ok(Some(l)) => (
                l.origin.parent().map(|p| *p.chronicle.as_bytes()),
                matches!(l.origin, Origin::Template { .. }),
            ),
            // No Lineage yet: a birth stopped after its clone.  A clone of
            // a Template's layer (`<root>/t-<hex>`) is a Template birth.
            Ok(None) => (None, is_layer_clone(pool, root, &ds)?),
            Err(e) => {
                warnings.push(format!(
                    "{ds}: its local Chronicle's Lineage cannot be read ({e}): taken as no parent"
                ));
                (None, false)
            }
        };
        let mut slots = std::collections::BTreeSet::new();
        for uid in pool.owner_uids(&ds)? {
            if uid == 0 {
                continue;
            }
            match uid.checked_sub(host_uid_base) {
                // A Template-born Vessel's files are the Template range's
                // (D53), shared by every Vessel born from a Template: they
                // count for no slot.  Anyone else's count as any slot's.
                Some(off) if from_template && Some(off / ID_RANGE) == template_slot => {}
                Some(off) => {
                    slots.insert(off / ID_RANGE);
                }
                None => warnings.push(format!(
                    "{ds} has files of uid {uid}, below host_uid_base {host_uid_base}: in no slot"
                )),
            }
        }
        held.push(Held { key, slots, parent });
    }
    Ok((held, warnings))
}

/// Whether `ds` is a clone of a Template's layer under `root`, a
/// dataset named `t-<32 hex>` (P4 §5.6).
fn is_layer_clone<H: Holdings>(pool: &H, root: &Dataset, ds: &Dataset) -> Result<bool, LayerError> {
    Ok(pool.origin(ds)?.is_some_and(|(o, _)| {
        o.as_str()
            .strip_prefix(root.as_str())
            .and_then(|rest| rest.strip_prefix("/t-"))
            .is_some_and(|h| key_of_hex(h).is_some())
    }))
}

/// The disk range a fork may inherit, from its top directory's owner
/// `(uid, gid)`: a whole slot's range above `host_uid_base`, the same for
/// both; anything else (root's 0:0 for a fresh one, a stray or half owner)
/// is no range, and [`work_dir_range`] then decides as for a birth.
fn inherited_range((uid, gid): (u32, u32), host_uid_base: u32) -> Option<u32> {
    let aligned = uid
        .checked_sub(host_uid_base)
        .is_some_and(|off| off % ID_RANGE == 0);
    (uid == gid && uid != 0 && aligned).then_some(uid)
}

/// A Vessel key from 32 lowercase hex digits.
fn key_of_hex(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let mut k = [0u8; 16];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(k)
}

/// Everything a node's Vessels share.
pub struct Node {
    /// The configuration.
    pub config: Config,
    /// The coordinator.
    pub coord: Arc<dyn Coord>,
    /// Where the Vessels live: ZFS (batched or not; clones share the
    /// batch) or the block log.
    pub storage: Storage,
    /// The store (opened from `config.store`).
    pub store: SharedStore,
    /// The run directory, held for the node's lifetime.
    run_lock: RunDirLock,
    /// What the pool held of each Vessel when the node started ([`held_on`]).
    held: Vec<Held>,
    /// The children its Vessels' agents asked for over the Field: the
    /// daemon runs them next to its source's entries
    /// ([`crate::source::WithRequested`]).
    requested: Requested,
    /// Vessels whose run got past its start in this Warden's life (their
    /// datasets settled here): a fork of one may start (C6).
    started: std::sync::Mutex<std::collections::BTreeSet<[u8; 16]>>,
    /// Template layers on this node (P4 §5.6), if `runtime.template_slot`
    /// is set.
    layers: Option<TemplateLayers<Storage, StorageSend>>,
    /// A failpoint of a Template birth to stop at ([`BIRTH_FAILPOINTS`];
    /// tests on a node, `TASO_FAILPOINT`).
    failpoint: Option<&'static str>,
    /// Nominations on this node (P4 §3.1), if `"sanction"` is set.
    nominator: Option<crate::nominate::Nominator>,
}

/// The failpoints of a Template birth (P4 spec rev. 17 §10.2, file 5): the
/// layer's, then the Vessel's.  [`Node::with_failpoint`] stops a birth at
/// one of them.
pub const BIRTH_FAILPOINTS: [&str; 7] = [
    "layer.after_build_put",
    "layer.before_shipped_accept",
    "layer.after_shipped_accept",
    "layer.after_receive",
    "birth.after_clone",
    "birth.after_lineage_append",
    "birth.before_accept",
];

impl Node {
    /// A node: refuses a host with SELinux ([`refuse_selinux`]), claims
    /// the run directory, sweeps containers a dead
    /// incarnation left in its runc root (see "Starting" in the module
    /// docs), then opens the store.  Each error says which step failed.
    pub fn new(config: Config, coord: Arc<dyn Coord>, storage: Storage) -> std::io::Result<Self> {
        let ctx = |what: &'static str| {
            move |e: io::Error| io::Error::new(e.kind(), format!("{what}: {e}"))
        };
        refuse_selinux(Path::new("/sys")).map_err(ctx("checking the host"))?;
        let run_lock = claim_run_dir(&config.run_dir).map_err(ctx("claiming the run directory"))?;
        let swept = sweep_stale(&Runc::new(RuncCli::new(config.run_dir.join("runc"))))
            .map_err(ctx("sweeping stale containers"))?;
        for id in &swept.deleted {
            eprintln!(
                "taso-wardend[{}]: deleted stale container {id}",
                config.warden.get()
            );
        }
        // After the sweep: nothing writes into a dataset now.
        let (held, warnings) = held_on(
            &storage,
            &config.root,
            config.runtime.host_uid_base,
            config.runtime.template_slot,
            &config.state_dir,
        )
        .map_err(|e| {
            io::Error::other(format!("reading the uid slots of the pool's Vessels: {e}"))
        })?;
        for w in &warnings {
            eprintln!("taso-wardend[{}]: {w}", config.warden.get());
        }
        let store = config.store.open().map_err(ctx("opening the store"))?;
        let layers = config
            .runtime
            .template_base()
            .map(|template_base| TemplateLayers {
                pool: Clone::clone(&storage),
                sender: storage.sender(),
                storage: match config.storage {
                    StorageConf::Zfs => StorageKind::Zfs,
                    StorageConf::Blk { .. } => StorageKind::Blk,
                },
                store: store.clone(),
                prefix: config.prefix.clone(),
                coord: coord.clone(),
                warden: config.warden,
                state_dir: config.state_dir.clone(),
                root: config.root.clone(),
                template_base,
                limits: crate::classify::Limits::default(),
                reserved: crate::classify::Reserved::defaults(),
                failpoint: crate::template::no_failpoints(),
                lock: std::sync::Mutex::new(()),
            });
        let nominator = match &config.sanction {
            None => None,
            Some(sc) => {
                let bytes = std::fs::read(&sc.classmap).map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!(
                            "reading the classification map {}: {e}",
                            sc.classmap.display()
                        ),
                    )
                })?;
                let mut conf = crate::nominate::SanctionConf::new(bytes).map_err(|e| {
                    io::Error::other(format!(
                        "the classification map {}: {e}",
                        sc.classmap.display()
                    ))
                })?;
                conf.allowed_exclude = sc.allowed_exclude.clone();
                Some(crate::nominate::Nominator::new(
                    store.clone(),
                    config.prefix.clone(),
                    coord.clone(),
                    config.warden,
                    config.runtime.host_uid_base,
                    config.state_dir.join("nominate-tmp"),
                    conf,
                ))
            }
        };
        Ok(Self {
            config,
            coord,
            storage,
            store,
            run_lock,
            held,
            requested: Requested::new(),
            started: Default::default(),
            layers,
            failpoint: None,
            nominator,
        })
    }

    /// Stop every Template birth at `name`, one of [`BIRTH_FAILPOINTS`]
    /// (tests on a node); `None`: never.  Refused for any other name.
    pub fn with_failpoint(mut self, name: Option<&str>) -> Result<Self, String> {
        let Some(name) = name else {
            self.failpoint = None;
            return Ok(self);
        };
        let at = BIRTH_FAILPOINTS
            .iter()
            .chain(crate::nominate::FAILPOINTS.iter())
            .copied()
            .find(|p| *p == name)
            .ok_or_else(|| {
                format!(
                    "{name:?} is not a failpoint of a Template birth or a nomination ({}, {})",
                    BIRTH_FAILPOINTS.join(", "),
                    crate::nominate::FAILPOINTS.join(", ")
                )
            })?;
        if let Some(n) = self.nominator.as_mut() {
            n.failpoint = Box::new(move |p| {
                if p == at {
                    Err(crate::nominate::NominateError::Failpoint(p))
                } else {
                    Ok(())
                }
            });
        }
        if let Some(l) = self.layers.as_mut() {
            l.failpoint = Box::new(move |p| {
                if p == at {
                    Err(TemplateError::Failpoint(p))
                } else {
                    Ok(())
                }
            });
        }
        self.failpoint = Some(at);
        Ok(self)
    }

    /// Stop at the Vessel's failpoint, if this is it.
    fn birth_failpoint(&self, p: &'static str) -> Result<(), VesselError> {
        if self.failpoint == Some(p) {
            Err(VesselError::Failpoint(p))
        } else {
            Ok(())
        }
    }

    /// The Template `t` names, and the name it was asked by (§5.5): a
    /// `name@version` resolved through its accepted `TemplateNamed`.
    fn resolve_template(
        &self,
        t: &TemplateRef,
    ) -> Result<(ChronicleId, Option<TemplateAsked>), DaemonError> {
        match t {
            TemplateRef::Id(id) => Ok((*id, None)),
            TemplateRef::Named { name, version } => {
                let logical = t.logical_id().expect("a name has a logical id");
                match self
                    .coord
                    .query_logical(logical)
                    .map_err(DaemonError::Coord)?
                {
                    Some((_, Submitted::Contract(ContractRecord::TemplateNamed(n)))) => Ok((
                        n.template_id,
                        Some(TemplateAsked {
                            name: name.clone(),
                            version: *version,
                        }),
                    )),
                    None => Err(DaemonError::Refused(format!(
                        "no Template is named {name}@{version}"
                    ))),
                    Some(_) => Err(DaemonError::Refused(format!(
                        "{name}@{version}: the log holds another record for that name"
                    ))),
                }
            }
        }
    }

    /// Nominate `vessel`'s Seal for `vc` (§3.1): the answer for the
    /// agent, or why this Vessel cannot nominate.
    fn nominate(
        &self,
        vc: &VesselConf,
        vessel: &mut Vessel<StorageLayers>,
        seal: Option<Lsn>,
        exclude: std::collections::BTreeSet<PathClass>,
        by: NominatedBy,
    ) -> NominateResult {
        let (Some(n), Some(vf)) = (self.nominator.as_ref(), vc.verifier.as_deref()) else {
            return NominateResult::NoVerifier;
        };
        let retry = |why: String| NominateResult::Retry { why };
        let verifier = match self.resolve_template(&vf.template) {
            Ok((t, _)) => t,
            Err(e) => return retry(format!("the verifier Template: {e}")),
        };
        let vconf = match std::fs::read(&vf.config) {
            Ok(b) => b,
            Err(e) => return retry(format!("reading {}: {e}", vf.config.display())),
        };
        let ask = crate::nominate::Ask {
            seal,
            exclude,
            verifier,
            vconf,
            version: vf.version,
            by,
        };
        let packs = match self.packs(vessel.id()) {
            Ok(p) => p,
            Err(e) => return retry(format!("packs: {e}")),
        };
        let ds = vessel.dataset().clone();
        let view = |lsn: Lsn| Pool::seal_view(&self.storage, &ds, lsn);
        let hex = |h: taso_core::envelope::HashVal| h.to_string();
        let answer = match n.nominate(vessel, &packs, &ask, &view) {
            Ok(crate::nominate::Answer::Nominated(c)) => {
                NominateResult::Nominated { candidate: hex(c) }
            }
            Ok(crate::nominate::Answer::Pending(c)) => {
                NominateResult::Pending { candidate: hex(c) }
            }
            Ok(crate::nominate::Answer::Refused(r)) => NominateResult::Refused {
                reason: format!("{r:?}"),
            },
            Ok(crate::nominate::Answer::Retry(why)) => retry(why),
            Err(e) => retry(format!("nothing accepted: {e}")),
        };
        self.log(vc, format_args!("nomination ({by:?}): {answer:?}"));
        answer
    }

    /// Birth `vc` from its Template (§5.6): resolve it, receive its layer
    /// (building it first if no node has), then [`Host::born_from_template`].
    fn template_birth(
        &self,
        vc: &VesselConf,
        t: &TemplateRef,
    ) -> Result<Vessel<StorageLayers>, DaemonError> {
        let layers = self.layers.as_ref().ok_or_else(|| {
            DaemonError::Refused("a Template birth needs runtime.template_slot".into())
        })?;
        let (template_id, asked) = self.resolve_template(t)?;
        let layer = layers.ensure(template_id).map_err(|e| {
            DaemonError::Refused(format!(
                "the layer of Template {}: {e}",
                id_hex(template_id)
            ))
        })?;
        for n in &layer.notes {
            self.log(vc, n);
        }
        let birth = TemplateBirth {
            template_id,
            layer_key: layer.layer_key,
            asked,
        };
        let v = self
            .host()
            .born_from_template(
                vc.namespace,
                vc.subject.as_bytes(),
                &birth,
                &self.packs(vc.id())?,
                &|p| self.birth_failpoint(p),
            )
            .map_err(|e| {
                DaemonError::Refused(format!("birth from Template {}: {e}", id_hex(template_id)))
            })?;
        self.log(
            vc,
            format_args!(
                "Born from Template {}{} (layer {})",
                id_hex(template_id),
                birth
                    .asked
                    .as_ref()
                    .map(|a| format!(", asked as {}@{}", a.name, a.version))
                    .unwrap_or_default(),
                birth.layer_key
            ),
        );
        Ok(v)
    }

    /// Whether a run of the Vessel `key` got past its start in this
    /// Warden's life ([`crate::supervisor::RunVessel::started`]).
    pub fn has_started(&self, key: &[u8; 16]) -> bool {
        self.started
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(key)
    }

    /// The children asked for over the Field (see [`ForksConf`]).
    pub fn requested(&self) -> &Requested {
        &self.requested
    }

    /// What the pool held of each Vessel when the node started: the seed of
    /// a guard ([`crate::source::Guard::seeded`]).
    pub fn held(&self) -> &[Held] {
        &self.held
    }

    /// The run directory's lock file.
    pub fn run_lock(&self) -> &Path {
        self.run_lock.path()
    }

    fn host(&self) -> Host<Storage> {
        Host {
            coord: self.coord.clone(),
            pool: Clone::clone(&self.storage),
            root: self.config.root.clone(),
            state_dir: self.config.state_dir.clone(),
            warden: self.config.warden,
        }
    }

    fn packs(&self, id: ChronicleId) -> Result<Packs<SharedStore, StorageSend>, DaemonError> {
        Packs::new(
            self.store.clone(),
            self.storage.sender(),
            &self.config.prefix,
            id,
        )
        .map_err(io("packs"))
    }

    fn log(&self, vc: &VesselConf, msg: impl fmt::Display) {
        eprintln!(
            "taso-wardend[{}] {}: {msg}",
            self.config.warden.get(),
            vc.subject
        );
    }

    /// Find, open or rebirth the Vessel (step 1).
    fn start(
        &self,
        vc: &VesselConf,
    ) -> Result<(Vessel<StorageLayers>, Start, Verdict), DaemonError> {
        let host = self.host();
        let id = vc.id();
        // What was read is what may be claimed (fencing review F1): a
        // takeover claims the ownership the config names, which `decide`
        // has checked against the read; one stale by the time it acts is
        // refused by the coordinator instead of taking the Vessel back
        // from whoever took it over in between.
        let known = match self.coord.ownership(id) {
            Ok(o) => match self.coord.head(id).map_err(DaemonError::Coord)? {
                h if h.lsn.get() == 0 => Known::Unborn,
                _ => Known::Held(o.holder, o.epoch),
            },
            Err(CoordError::UnknownChronicle(_)) => Known::No,
            Err(e) => return Err(DaemonError::Coord(e)),
        };
        let claim = match (known, vc.takeover) {
            (Known::Held(holder, _), Some(t)) if holder != self.config.warden => Claim::TakeOver {
                from: t.holder,
                epoch: t.epoch,
            },
            _ => Claim::Mine,
        };
        let local = host.dir_for(id).exists();
        let start = decide(known, local, self.config.warden, vc.takeover);
        let (vessel, verdict) = match &start {
            Start::Refuse(why) => return Err(DaemonError::Refused(why.clone())),
            Start::Birth if vc.fork.is_some() => {
                let f = vc.fork.as_ref().expect("matched");
                let parent = vessel_id(vc.namespace, f.parent.as_bytes());
                let v = host
                    .fork_from_log(parent, f.seal, vc.subject.as_bytes())
                    .map_err(|e| {
                        DaemonError::Refused(format!(
                            "fork from {:?} ({:?}): {e}",
                            f.parent, f.seal
                        ))
                    })?;
                let at = v
                    .lineage()
                    .origin
                    .parent()
                    .map(|p| p.seal.get())
                    .unwrap_or(0);
                self.log(
                    vc,
                    format_args!("Forked from {:?} at Seal lsn {at}", f.parent),
                );
                (v, Verdict::Clean)
            }
            Start::Birth if vc.template.is_some() => {
                let t = vc.template.as_ref().expect("matched");
                (self.template_birth(vc, t)?, Verdict::Clean)
            }
            Start::Birth | Start::Open => {
                let (v, how) = host.ensure_as(vc.namespace, vc.subject.as_bytes(), claim)?;
                let verdict = match &how {
                    Ensured::Opened(r) => verdict_after_open(r),
                    Ensured::Born | Ensured::BirthFinished => Verdict::Clean,
                };
                self.log(vc, format_args!("{how:?}"));
                (v, verdict)
            }
            Start::Rebirth => {
                // A Template-born Vessel: its layer received here first
                // (§5.6), the one settled for this node's storage kind.
                let layer = |t: ChronicleId, key: taso_core::envelope::HashVal| {
                    let layers = self.layers.as_ref().ok_or_else(|| {
                        VesselError::LocalState(
                            "a Template-born Vessel is reborn over its layer: runtime.template_slot is not set".into(),
                        )
                    })?;
                    let l = layers.ensure(t).map_err(|e| {
                        VesselError::LocalState(format!("the layer of Template {}: {e}", id_hex(t)))
                    })?;
                    for n in &l.notes {
                        self.log(vc, n);
                    }
                    if l.layer_key != key {
                        return Err(VesselError::LocalState(format!(
                            "its Lineage names layer {key} of Template {}, but this node's storage kind has layer {}: a Vessel is not reborn across storage kinds",
                            id_hex(t),
                            l.layer_key
                        )));
                    }
                    Ok(())
                };
                let (v, reborn) = host
                    .rebirth_with(id, &self.packs(id)?, claim, &layer)
                    .map_err(|e| match e {
                        // Forks are node-bound (2026-10-23, option c).
                        VesselError::ParentMissing(p) => DaemonError::Refused(format!(
                            "a fork is reborn only where its parent's Seal is: the Seal at lsn {} of its parent {} is not on this node; rebirth the parent here first (a parent listed with it is started first), or keep its Seal here as a Template",
                            p.seal.get(),
                            id_hex(p.chronicle)
                        )),
                        e => DaemonError::Vessel(e),
                    })?;
                self.log(vc, &reborn);
                let verdict = verdict_after_rebirth(&reborn);
                (v, verdict)
            }
        };
        // An entry that says it is a fork must agree with the Chronicle: one
        // that names another parent (or a Vessel born from the void) is a
        // wrong entry, not a reason to run it.
        if let Some(f) = &vc.fork {
            let want = vessel_id(vc.namespace, f.parent.as_bytes());
            if vessel.lineage().origin.parent().map(|p| p.chronicle) != Some(want) {
                return Err(DaemonError::Refused(format!(
                    "the entry forks it from {:?}, but its Lineage record says otherwise",
                    f.parent
                )));
            }
        }
        // Likewise an entry that names a Template: the Lineage must name
        // that Template, asked by that name (D50).
        if let Some(t) = &vc.template {
            let agrees = match (&vessel.lineage().origin, &**t) {
                (Origin::Template { template_id, .. }, TemplateRef::Id(id)) => template_id == id,
                (Origin::Template { asked: Some(a), .. }, TemplateRef::Named { name, version }) => {
                    a.name == *name && a.version == *version
                }
                _ => false,
            };
            if !agrees {
                return Err(DaemonError::Refused(format!(
                    "the entry names Template {t:?}, but its Lineage record says otherwise"
                )));
            }
        }
        // A Template-born Vessel runs only once its Birth is accepted
        // (§5.6): an interrupted birth is finished here, on any start.
        if matches!(vessel.lineage().origin, Origin::Template { .. }) {
            let mut vessel = vessel;
            self.host()
                .finish_birth(&mut vessel, &self.packs(id)?, &|p| self.birth_failpoint(p))
                .map_err(|e| DaemonError::Refused(format!("finishing its Birth: {e}")))?;
            return Ok((vessel, start, verdict));
        }
        Ok((vessel, start, verdict))
    }

    /// The parent's Seal snapshot, for a forked Vessel with no `fs`
    /// section shipped yet.
    fn origin(&self, vessel: &Vessel<StorageLayers>) -> Result<Option<Snapshot>, DaemonError> {
        if has_fs_shipped(vessel)? {
            return Ok(None);
        }
        let info = Pool::info(&self.storage, vessel.dataset())
            .map_err(|e| DaemonError::Io(e.to_string()))?;
        match info.and_then(|i| i.origin_seal()) {
            None => Ok(None),
            Some((ds, lsn)) => self
                .storage
                .snapshot(&ds, lsn)
                .map_err(|e| DaemonError::Io(e.to_string())),
        }
    }

    /// Run one Vessel until its agent exits (see the module docs).
    pub fn run_vessel(&self, vc: &VesselConf) -> Result<Report, DaemonError> {
        self.run_vessel_until(vc, &Stop::new())
    }

    /// Run one Vessel until its agent exits or `stop` is requested.  A stop
    /// before the agent starts returns without starting it; a stop while it
    /// runs kills its container (right away, also in the middle of a Field
    /// session), and the run ends as on an agent exit, with
    /// [`Report::stopped`] set.
    ///
    /// A promotion the agent asks for over the Field ends the run (its
    /// files are adopted before it runs again, C7 Q1): the Vessel is started
    /// again at once, within this run and whatever its restart policy, and
    /// the agent comes back on the child's files.
    pub fn run_vessel_until(&self, vc: &VesselConf, stop: &Stop) -> Result<Report, DaemonError> {
        loop {
            let promoted = Stop::new();
            let report = self.run_once(vc, stop, &promoted)?;
            if promoted.requested() && !stop.requested() {
                self.log(
                    vc,
                    "promoted on its agent's request: starting it again to adopt the child's files",
                );
                continue;
            }
            return Ok(report);
        }
    }

    fn run_once(
        &self,
        vc: &VesselConf,
        stop: &Stop,
        promoted: &Stop,
    ) -> Result<Report, DaemonError> {
        // Before anything touches the coordinator or the dataset.
        let rt = vc
            .effective(&self.config.runtime, &self.config.quiescence)
            .map_err(DaemonError::Runtime)?;
        let (mut vessel, start, verdict) = self.start(vc)?;
        let id = vc.id();
        self.log(vc, format_args!("dataset {}", vessel.dataset()));
        let birth_turn = match vessel.last_seal() {
            None => self.host().birth_turn(&vessel)?,
            Some(_) => BIRTH_TURN,
        };
        let settled = settle_at(&mut vessel, birth_turn)?;
        // Its dataset is settled here: a fork of it may start (C6).
        self.started
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(*id.as_bytes());
        if let Some(b) = settled.birth {
            self.log(
                vc,
                format_args!(
                    "birth Seal at lsn {} (turn {})",
                    b.lsn.get(),
                    birth_turn.get()
                ),
            );
        }
        match settled.rolled_back_to {
            Some(s) => self.log(
                vc,
                format_args!("state rolled back to the Seal at lsn {}", s.lsn.get()),
            ),
            None => self.log(vc, "no Seal layer here: state not rolled back"),
        }
        if settled.behind() {
            self.log(
                vc,
                format_args!(
                    "WARNING: the last Seal (lsn {}) has no layer here; the state is older than the turn the agent resumes after",
                    settled.last_seal.map_or(0, |s| s.lsn.get())
                ),
            );
        }
        let mut publisher = SealPublisher {
            storage: Clone::clone(&self.storage),
            packs: self.packs(id)?,
            origin: self.origin(&vessel)?,
            published: 0,
            pruned: 0,
            prune_failures: 0,
            prune_error: None,
        };
        // A crash between taking a Seal and publishing it, or the birth
        // Seal just taken: publish now.  Counted only if this shipped it (a
        // Seal published before the restart is not published again).
        if let Some(seal) = vessel.last_seal() {
            match publisher.publish(&mut vessel, seal) {
                Ok(true) => publisher.published += 1,
                Ok(false) => {}
                Err(e) => self.log(
                    vc,
                    format_args!(
                        "publishing the last Seal (lsn {}) failed: {e}",
                        seal.lsn.get()
                    ),
                ),
            }
        }
        // The entry's Candidate (§3.1), nominated at each start; the same
        // request answers from the log (D61).
        if let Some(c) = vc.candidate.as_deref() {
            let seal = match c.seal {
                SealAt::Last => None,
                SealAt::At(l) => Some(l),
            };
            self.nominate(
                vc,
                &mut vessel,
                seal,
                c.exclude.clone(),
                NominatedBy::Config,
            );
        }
        let effects_publisher =
            PackPublisher::new(self.packs(id)?, self.coord.clone(), self.config.warden);
        // Who may release effects: the entry's say, else by origin (a
        // fork holds).
        let mode = EffectsConf::mode(vc.effects, &vessel.lineage().origin);
        let (mut effects, reconciled) =
            Effects::open(mode, Box::new(effects_publisher), &mut vessel)?;
        self.log(
            vc,
            format_args!("effects ({mode:?}) reconciled: {reconciled:?}"),
        );
        // A promotion recorded but not adopted (the Warden died in
        // between): finished before the agent runs, from the child's log
        // on this node.  Without that log the Vessel does not start: it
        // would run with the futures it chose not yet released.
        if let Some(p) = effects.pending_promotion() {
            let child = self.host().read_log_of(p.child).map_err(|e| {
                DaemonError::Refused(format!(
                    "a promotion of {} at its Seal lsn {} is recorded but not adopted, and its log cannot be read here: {e}",
                    id_hex(p.child),
                    p.seal.get()
                ))
            })?;
            let adopted = match effects.finish_promotion(&mut vessel, &child) {
                Ok(a) => a,
                // Done; listed once a ship succeeds.
                Err(crate::effects::PromoteError::AdoptionNotShipped {
                    adopted, error, ..
                }) => {
                    self.log(
                        vc,
                        format_args!("the adoption is recorded but not shipped yet ({error}): not listed until it is"),
                    );
                    adopted
                }
                Err(e) => {
                    return Err(DaemonError::Refused(format!(
                        "finishing the promotion of {} at its Seal lsn {}: {e:?}",
                        id_hex(p.child),
                        p.seal.get()
                    )))
                }
            };
            self.log(
                vc,
                format_args!(
                    "finished the promotion of {} at its Seal lsn {}: {} effect(s) adopted",
                    id_hex(p.child),
                    p.seal.get(),
                    adopted.len()
                ),
            );
        }
        // A config-driven promotion: the child is a fork of this Vessel,
        // on this node, whose agent has already run and sealed.  Used by
        // the no-trace gate (P3 file 10).
        //
        // Skipped when the child was already promoted (a previous start
        // with the same config completed the promotion, or crash recovery
        // above finished it).  Checked by looking for a Promotion record
        // naming this child in the Ctl stream.
        if let Some(pc) = &vc.promote {
            let child_id = taso_core::record::vessel_id(vc.namespace, pc.child.as_bytes());
            let frames = vessel
                .chronicle()
                .frames()
                .map_err(|e| DaemonError::Io(format!("reading frames for promotion check: {e}")))?;
            let already = frames.iter().any(|f| {
                matches!(
                    taso_core::record::Payload::decode(&f.payload),
                    Ok(taso_core::record::Payload::Promotion(p)) if p.child == child_id
                )
            });
            if already {
                self.log(
                    vc,
                    format_args!("promote: {} already promoted, skipping", pc.child),
                );
            } else {
                let child = self.host().read_log_of(child_id).map_err(|e| {
                    DaemonError::Refused(format!(
                        "promote: the child {:?} ({})'s log cannot be read here: {e}",
                        pc.child,
                        id_hex(child_id)
                    ))
                })?;
                let (record, adopted) = match effects.promote(&mut vessel, &child, pc.seal) {
                    Ok(r) => r,
                    // Done; listed once a ship succeeds.
                    Err(crate::effects::PromoteError::AdoptionNotShipped {
                        promotion,
                        adopted,
                        error,
                    }) => {
                        self.log(
                            vc,
                            format_args!("the adoption is recorded but not shipped yet ({error}): not listed until it is"),
                        );
                        (promotion, adopted)
                    }
                    Err(e) => {
                        return Err(DaemonError::Refused(format!(
                            "promote: {} at {:?}: {e:?}",
                            pc.child, pc.seal
                        )))
                    }
                };
                self.log(
                    vc,
                    format_args!(
                        "promoted {} at Seal lsn {}: {} effect(s) adopted",
                        id_hex(record.child),
                        record.seal.get(),
                        adopted.len()
                    ),
                );
            }
        }

        // The promoted child's files (C7): the adoption Seal, before the
        // agent runs, from the child's log on this node (forks are
        // node-bound), then published at once.
        if let Some(p) = vessel.adoption_pending()? {
            let refused = |e: VesselError| {
                DaemonError::Refused(format!(
                    "adopting the files of {} promoted at its Seal lsn {}: {e}",
                    id_hex(p.child),
                    p.seal.get()
                ))
            };
            let child = self.host().read_log_of(p.child).map_err(refused)?;
            let seal = self
                .host()
                .adopt_files(&mut vessel, &p, &child, &self.storage.sender())
                .map_err(refused)?;
            self.log(
                vc,
                format_args!(
                    "adopted the files of {} at its Seal lsn {}: the adoption Seal at lsn {}",
                    id_hex(p.child),
                    p.seal.get(),
                    seal.lsn.get()
                ),
            );
            match publisher.publish(&mut vessel, seal) {
                Ok(true) => publisher.published += 1,
                Ok(false) => {}
                Err(e) => self.log(
                    vc,
                    format_args!(
                        "publishing the adoption Seal (lsn {}) failed: {e}",
                        seal.lsn.get()
                    ),
                ),
            }
        }

        // A reborn (or adopting) dataset was received unmounted.
        self.storage
            .ensure_mounted(vessel.dataset())
            .map_err(|e| DaemonError::Io(format!("mount: {e}")))?;
        let mount = Pool::info(&self.storage, vessel.dataset())
            .map_err(|e| DaemonError::Io(e.to_string()))?
            .and_then(|i| i.mountpoint)
            .ok_or_else(|| DaemonError::Io(format!("{} is not mounted", vessel.dataset())))?;
        let uid = vc
            .host_uid(&self.config.runtime)
            .ok_or_else(|| DaemonError::Io(format!("uid_slot {} does not fit", vc.uid_slot)))?;
        // The range its files are owned by on disk (F6): its own, or for a
        // fork or succession its lineage's, which the top directory has
        // carried since it was first prepared; the mount is then idmapped.
        // Which lineage a range may belong to on this node is the source
        // guard's to check (`held_on`, `Guard::seeded`).
        let inherited = match vessel.lineage().origin.parent() {
            // Born from a Template: the Template range (D53), which the
            // layer's top directory carries.
            None if matches!(vessel.lineage().origin, Origin::Template { .. }) => {
                Some(self.config.runtime.template_base().ok_or_else(|| {
                    DaemonError::Refused(
                        "a Template-born Vessel runs over the Template range: runtime.template_slot is not set".into(),
                    )
                })?)
            }
            None => None,
            Some(_) => {
                use std::os::unix::fs::MetadataExt;
                let m = std::fs::symlink_metadata(&mount).map_err(io("reading the dataset"))?;
                inherited_range((m.uid(), m.gid()), self.config.runtime.host_uid_base)
            }
        };
        let disk = work_dir_range(&mount, uid, inherited).map_err(io("preparing the dataset"))?;
        if disk != uid {
            self.log(
                vc,
                format_args!("its files are its lineage's range ({disk}): /work is idmapped"),
            );
        }

        let dir = self.config.run_dir.join(format!("v-{}", id_hex(id)));
        std::fs::create_dir_all(&dir).map_err(io("run dir"))?;
        let socket = FieldSocket::bind(dir.join("field.sock")).map_err(io("field socket"))?;
        std::os::unix::fs::chown(socket.path(), Some(uid), Some(uid))
            .map_err(io("field socket owner"))?;
        // The sender socket (C5): the Warden's own, never mounted into the
        // Vessel; one per Vessel, so its path says whose.
        let senders = self.config.run_dir.join("senders");
        std::fs::create_dir_all(&senders).map_err(io("sender socket dir"))?;
        std::fs::set_permissions(
            &senders,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .map_err(io("sender socket dir"))?;
        let sender = FieldSocket::bind(senders.join(format!("{}.sock", id_hex(id))))
            .map_err(io("sender socket"))?;
        self.log(
            vc,
            format_args!("sender socket {}", sender.path().display()),
        );

        let spec = VesselSpec {
            id: container_id(id, self.config.warden),
            rootfs: rt.rootfs.clone(),
            work: mount.clone(),
            socket: socket.path().to_path_buf(),
            host_uid_base: uid,
            disk_uid_base: Some(disk),
            args: rt.args.clone(),
            env: rt.env.clone(),
            landlock_shim: rt.landlock_shim.clone(),
            memory_bytes: rt.memory_bytes,
            pids: rt.pids,
        };
        let bundle = write_bundle(&dir.join("bundle"), &spec)
            .map_err(|e| DaemonError::Io(format!("bundle: {e:?}")))?;
        let bundle_dir = bundle
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or(dir.join("bundle"));
        let runc = Runc::new(RuncCli::new(self.config.run_dir.join("runc")));
        if runc.state(&spec.id).map_err(io("runc state"))?.is_some() {
            self.log(vc, "deleting a stale container");
            runc.delete(&spec.id).map_err(io("runc delete"))?;
        }

        if stop.requested() {
            self.log(vc, "stopped before the agent started");
            return Ok(Report {
                subject: vc.subject.clone(),
                start,
                connections: 0,
                published: publisher.published,
                publish_failures: 0,
                pruned: publisher.pruned,
                prune_failures: (publisher.prune_failures, publisher.prune_error.clone()),
                agent: None,
                settled,
                stopped: true,
            });
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

        // A stop kills the container from here, whatever the Field loop is
        // doing; the agent's connection then closes and the loop ends as on
        // an exit.  It keeps trying until the agent is gone (a kill can fail
        // while the container is still being created).
        // A promotion asked for over the Field ends the run too, after a
        // grace for the agent to exit by itself (C7).
        let stopper = {
            let (stop, promoted, exited, id) = (
                stop.clone(),
                promoted.clone(),
                exited.clone(),
                spec.id.clone(),
            );
            let runc = Runc::new(RuncCli::new(self.config.run_dir.join("runc")));
            std::thread::spawn(move || {
                let mut killed = false;
                let mut since: Option<std::time::Instant> = None;
                while !exited.load(Ordering::SeqCst) {
                    if promoted.requested() {
                        since.get_or_insert_with(std::time::Instant::now);
                    }
                    let grace_over = since.is_some_and(|t| t.elapsed() >= PROMOTED_GRACE);
                    if stop.requested() || grace_over {
                        killed |= runc.kill(&id).is_ok();
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                stop.requested() || (killed && !promoted.requested())
            })
        };

        // Both sockets, every connection on its own thread, every request
        // handled here, one at a time (C5).
        let mut connections = 0;
        let stop = || exited.load(Ordering::SeqCst);
        let watch = if rt.quiescence.is_empty() {
            None
        } else {
            let dbs: Vec<&str> = rt.quiescence.iter().map(String::as_str).collect();
            Some(Watch::new(&mount, &dbs).map_err(io("quiescence watch"))?)
        };
        let mut branches = NodeBranches {
            node: self,
            vc,
            promoted,
        };
        let mut nominations = NodeNominations { node: self, vc };
        let mut session = Session::new(&mut vessel, verdict)?
            .with_effects(&mut effects)
            .with_after_seal(&mut publisher)
            .with_branches(&mut branches)
            .with_nominations(&mut nominations);
        if let Some(w) = watch {
            session = session.with_watch(w);
        }
        serve_vessel(
            &mut session,
            &socket,
            &sender,
            &stop,
            Duration::from_millis(20),
            &mut |c| {
                connections += 1;
                self.log(
                    vc,
                    format_args!("{:?} connection ended: {:?}", c.socket, c.ended),
                );
            },
        )
        .map_err(io("serving the sockets"))?;
        let (failures, last) = session.after_seal_failures();
        if failures > 0 {
            self.log(
                vc,
                format_args!(
                    "{failures} Seal publishes failed, last: {}",
                    last.unwrap_or("?")
                ),
            );
        }
        drop(session);
        let agent = agent
            .join()
            .map_err(|_| DaemonError::Io("the runc thread panicked".into()))?
            .ok();
        if let Some((ok, err)) = &agent {
            self.log(
                vc,
                format_args!(
                    "agent exited {}{}",
                    if *ok { "ok" } else { "with failure: " },
                    if *ok { "" } else { err.trim() }
                ),
            );
        }
        let stopped = stopper
            .join()
            .map_err(|_| DaemonError::Io("the stop thread panicked".into()))?;
        if stopped {
            self.log(vc, "stopped on request: the agent's container was killed");
        }
        Ok(Report {
            subject: vc.subject.clone(),
            start,
            connections,
            published: publisher.published,
            publish_failures: failures,
            pruned: publisher.pruned,
            prune_failures: (publisher.prune_failures, publisher.prune_error.clone()),
            agent,
            settled,
            stopped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zfs::{Runner, Zfs, ZfsError};

    // ── Settling the state ──────────────────────────────────────────

    use crate::vessel::tests::{env as vessel_env, ns};
    use crate::vessel::Pool;
    use taso_core::envelope::{Lsn, Stream};
    use taso_core::record::{Payload, StreamCut, TurnId};

    fn turn<L: Layers>(v: &mut Vessel<L>, t: u64) -> Position {
        v.seal(
            StreamCut::EMPTY,
            Verdict::Clean,
            Lsn::new(0),
            TurnId::new(t),
        )
        .unwrap()
        .seal
    }

    /// A new Vessel: the birth Seal, then the state is at it.  Settling
    /// again takes no second birth Seal.
    #[test]
    fn a_new_vessel_settles_at_its_birth_seal() {
        let e = vessel_env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let s = settle(&mut v).unwrap();
        let b = s.birth.expect("a birth Seal");
        assert_eq!(b.lsn, Lsn::new(2));
        assert_eq!((s.rolled_back_to, s.last_seal), (Some(b), Some(b)));
        assert!(!s.behind());
        let again = settle(&mut v).unwrap();
        assert_eq!(
            again,
            Settled {
                birth: None,
                rolled_back_to: Some(b),
                last_seal: Some(b)
            }
        );
    }

    /// A Vessel with turns: no birth Seal, the state goes back to the last
    /// Seal, whatever was recorded after it.
    #[test]
    fn a_running_vessel_settles_at_its_last_seal() {
        let e = vessel_env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        settle(&mut v).unwrap();
        turn(&mut v, 1);
        let s2 = turn(&mut v, 2);
        v.append(Stream::Transcript, Payload::Raw(vec![3])).unwrap(); // turn 3, cut short
        let s = settle(&mut v).unwrap();
        assert_eq!(
            s,
            Settled {
                birth: None,
                rolled_back_to: Some(s2),
                last_seal: Some(s2)
            }
        );
    }

    /// No Seal but records after Lineage: no birth Seal over unsealed work.
    #[test]
    fn unsealed_work_without_a_seal_is_refused() {
        let e = vessel_env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        v.append(Stream::Transcript, Payload::Raw(vec![1])).unwrap();
        assert!(matches!(settle(&mut v), Err(VesselError::NotPristine(_))));
        assert_eq!(v.last_seal(), None);
    }

    /// The last Seal's layer gone: the state goes to the Seal before it,
    /// and `behind` says so.
    #[test]
    fn a_missing_last_layer_settles_behind() {
        let e = vessel_env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let b = settle(&mut v).unwrap().birth.unwrap();
        let s1 = turn(&mut v, 1);
        drop(v);
        e.host
            .pool
            .layers(&e.host.dataset_for(vessel_id(ns(1), b"u")))
            .destroy(s1.lsn)
            .unwrap();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let s = settle(&mut v).unwrap();
        assert_eq!(
            s,
            Settled {
                birth: None,
                rolled_back_to: Some(b),
                last_seal: Some(s1)
            }
        );
        assert!(s.behind());
    }

    #[test]
    fn behind_is_only_when_a_seal_exists_and_differs() {
        let p = |n| Position {
            lsn: Lsn::new(n),
            hash: taso_core::envelope::HashVal::from_bytes([n as u8; 32]),
        };
        assert!(!Settled::default().behind());
        assert!(!Settled {
            birth: None,
            rolled_back_to: Some(p(3)),
            last_seal: Some(p(3))
        }
        .behind());
        assert!(Settled {
            birth: None,
            rolled_back_to: Some(p(2)),
            last_seal: Some(p(3))
        }
        .behind());
        assert!(Settled {
            birth: None,
            rolled_back_to: None,
            last_seal: Some(p(3))
        }
        .behind());
    }

    // ── Starting: the host (D32) ────────────────────────────────────

    #[test]
    fn a_host_with_selinux_is_refused() {
        let sys = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(sys.path().join("fs")).unwrap();
        refuse_selinux(sys.path()).expect("no SELinux: starts");
        std::fs::create_dir_all(sys.path().join("fs/selinux")).unwrap();
        refuse_selinux(sys.path()).expect("selinuxfs directory alone: not enabled");
        std::fs::write(sys.path().join(SELINUX_ENFORCE), b"0").unwrap();
        let e = refuse_selinux(sys.path()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported, "permissive (0) too");
        assert!(e.to_string().contains("SELinux is enabled"), "{e}");
        let gone = sys.path().join("nothing");
        assert!(
            refuse_selinux(&gone).is_err(),
            "no sysfs: cannot tell, refused"
        );
    }

    #[test]
    fn this_host_passes_the_selinux_check() {
        // The tests run on a supported host (taso-test, CI); if this
        // fails, every Node::new test fails for the same reason.
        refuse_selinux(Path::new("/sys")).unwrap();
    }

    // ── Starting: run directory and sweep ───────────────────────────

    #[test]
    fn a_run_dir_is_claimed_once_and_released_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path().join("run/taso");
        let first = claim_run_dir(&run).unwrap();
        assert_eq!(first.path(), run.join(RUN_LOCK));
        let e = claim_run_dir(&run).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        assert!(
            e.to_string().contains("held by another taso-wardend"),
            "{e}"
        );
        // Still refused while the first is held; free once it is dropped.
        assert!(claim_run_dir(&run).is_err());
        drop(first);
        let again = claim_run_dir(&run).unwrap();
        // Another run directory is independent.
        let _other = claim_run_dir(&tmp.path().join("run/other")).unwrap();
        drop(again);
    }

    /// A run directory released while another thread spawns processes may
    /// still be held for a moment by a child between fork and exec;
    /// claiming it again must not be refused for that (found on taso-test
    /// 2026-10-23: the node tests run in parallel, spawning runc and zfs,
    /// and a second Node of one test was refused its own run directory).
    #[test]
    fn a_run_dir_released_while_processes_spawn_is_claimed_again() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        let tmp = tempfile::tempdir().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let spawned = Arc::new(AtomicU64::new(0));
        let spawner = {
            let (stop, spawned) = (stop.clone(), spawned.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = std::process::Command::new("true").status();
                    spawned.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        let (mut claims, mut refused) = (0u64, 0u64);
        let t = std::time::Instant::now();
        while spawned.load(Ordering::Relaxed) < 300 && t.elapsed() < Duration::from_secs(10) {
            match claim_run_dir(tmp.path()) {
                Ok(lock) => drop(lock),
                Err(_) => refused += 1,
            }
            claims += 1;
        }
        stop.store(true, Ordering::Relaxed);
        spawner.join().unwrap();
        assert!(spawned.load(Ordering::Relaxed) >= 300);
        assert_eq!(refused, 0, "{refused} of {claims} claims refused");
    }

    #[test]
    fn a_held_lock_is_not_stolen_by_a_leftover_file() {
        // The lock file stays after its holder exits; only the flock counts.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(RUN_LOCK), b"left by a dead daemon").unwrap();
        let held = claim_run_dir(tmp.path()).unwrap();
        assert!(claim_run_dir(tmp.path()).is_err());
        drop(held);
    }

    #[test]
    fn a_node_claims_its_run_dir_before_anything_else() {
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path().join("run");
        let store = tmp.path().join("store");
        let mut v: Value = serde_json::from_str(GOOD).unwrap();
        v["run_dir"] = run.to_string_lossy().into();
        v["store"] = store.to_string_lossy().into();
        let config = Config::parse(&v.to_string()).unwrap();
        let coord: Arc<dyn Coord> =
            Arc::new(crate::coordinator::Coordinator::open(tmp.path().join("c.redb")).unwrap());
        let _held = claim_run_dir(&run).unwrap();
        let e = Node::new(config, coord, Storage::Zfs(Zfs::cli()))
            .err()
            .expect("a held run directory is refused");
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        assert!(
            e.to_string().starts_with("claiming the run directory: "),
            "{e}"
        );
        // Refused before the sweep (no runc root) and before the store.
        assert!(!run.join("runc").exists());
        assert!(!store.exists());
    }

    struct Scripted(
        std::cell::RefCell<Vec<(bool, String, String)>>,
        std::cell::RefCell<Vec<Vec<String>>>,
    );
    impl RuncRunner for Scripted {
        fn run(&self, args: &[String]) -> io::Result<(bool, String, String)> {
            self.1.borrow_mut().push(args.to_vec());
            Ok(self.0.borrow_mut().remove(0))
        }
    }
    fn scripted(replies: &[(bool, &str, &str)]) -> Runc<Scripted> {
        Runc::new(Scripted(
            std::cell::RefCell::new(
                replies
                    .iter()
                    .map(|(a, b, c)| (*a, b.to_string(), c.to_string()))
                    .collect(),
            ),
            Default::default(),
        ))
    }

    #[test]
    fn sweep_stale_removes_everything_or_refuses_naming_what_stayed() {
        let clean = scripted(&[
            (true, r#"[{"id":"taso-a","status":"running"}]"#, ""),
            (true, "", ""),
        ]);
        assert_eq!(
            sweep_stale(&clean).unwrap().deleted,
            vec!["taso-a".to_string()]
        );

        let empty = scripted(&[(true, "null", "")]);
        assert_eq!(sweep_stale(&empty).unwrap(), Swept::default());

        let stuck = scripted(&[
            (
                true,
                r#"[{"id":"taso-a","status":"running"},{"id":"taso-b","status":"running"}]"#,
                "",
            ),
            (false, "", "unable to kill: device busy\n"),
            (true, "", ""),
        ]);
        let e = sweep_stale(&stuck).unwrap_err().to_string();
        assert!(
            e.contains("taso-a (runc delete --force taso-a: unable to kill: device busy)"),
            "{e}"
        );
        assert!(!e.contains("taso-b"), "{e}");

        let unreadable = scripted(&[(false, "", "permission denied")]);
        assert!(sweep_stale(&unreadable)
            .unwrap_err()
            .to_string()
            .contains("permission denied"));
    }

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
            { "namespace": "01010101010101010101010101010101", "subject": "a", "uid_slot": 0 },
            { "namespace": "01010101010101010101010101010101", "subject": "b", "takeover": {"holder": 2, "epoch": 5}, "uid_slot": 7 }
        ]
    }"#;

    /// P4 file 6c (D57, D58): the node's `"sanction"`, a Vessel's
    /// `"verifier"` and `"candidate"`, and what each needs.
    #[test]
    fn sanction_verifier_and_candidate_entries() {
        let with = |f: &dyn Fn(&mut Value)| {
            let mut v: Value = serde_json::from_str(GOOD).unwrap();
            f(&mut v);
            Config::parse(&v.to_string())
        };
        let full = |v: &mut Value| {
            v["sanction"] = serde_json::json!({"classmap": "/etc/taso/map.toml"});
            v["vessels"][0]["verifier"] = serde_json::json!({"template": "checks@2", "config": "/etc/taso/v.toml", "version": 3});
            v["vessels"][0]["candidate"] =
                serde_json::json!({"seal": "last", "exclude": ["Scratch"]});
        };
        let c = with(&full).unwrap();
        let s = c.sanction.unwrap();
        assert_eq!(s.classmap, PathBuf::from("/etc/taso/map.toml"));
        assert_eq!(
            s.allowed_exclude,
            [PathClass::Scratch].into(),
            "the default"
        );
        let vf = c.vessels[0].verifier.as_deref().unwrap();
        assert_eq!(
            vf.template,
            TemplateRef::Named {
                name: "checks".into(),
                version: 2
            }
        );
        assert_eq!(
            (vf.config.as_path(), vf.version),
            (Path::new("/etc/taso/v.toml"), 3)
        );
        let k = c.vessels[0].candidate.as_deref().unwrap();
        assert_eq!(
            (k.seal, k.exclude.clone()),
            (SealAt::Last, [PathClass::Scratch].into())
        );
        // A Seal by lsn, nothing dropped.
        let c = with(&|v| {
            full(v);
            v["vessels"][0]["candidate"] = serde_json::json!({"seal": 7});
        })
        .unwrap();
        let k = c.vessels[0].candidate.as_deref().unwrap();
        assert_eq!((k.seal, k.exclude.len()), (SealAt::At(Lsn::new(7)), 0));
        let refused = |f: &dyn Fn(&mut Value), says: &str| {
            let e = with(f).unwrap_err().0;
            assert!(e.contains(says), "{says}: {e}");
        };
        refused(
            &|v| {
                full(v);
                v["vessels"][0].as_object_mut().unwrap().remove("verifier");
            },
            "needs its \"verifier\"",
        );
        refused(
            &|v| {
                full(v);
                v.as_object_mut().unwrap().remove("sanction");
            },
            "the node's \"sanction\"",
        );
        refused(
            &|v| {
                full(v);
                v["vessels"][0]["candidate"]["exclude"] = serde_json::json!(["Source"]);
            },
            "not within",
        );
        refused(
            &|v| {
                full(v);
                v["sanction"]["allowed_exclude"] = serde_json::json!(["Scratch", "Scratch"]);
            },
            "listed twice",
        );
        refused(
            &|v| {
                full(v);
                v["sanction"]["allowed_exclude"] = serde_json::json!(["Structural"]);
            },
            "is not a class",
        );
        refused(
            &|v| {
                full(v);
                v["vessels"][0]["verifier"]["template"] = "checks".into();
            },
            "verifier.template",
        );
        refused(
            &|v| {
                full(v);
                v["vessels"][0]["candidate"]["seal"] = 0.into();
            },
            "positive lsn",
        );
        refused(
            &|v| {
                full(v);
                v["sanction"]["extra"] = 1.into();
            },
            "sanction",
        );
    }

    /// P4 file 5f: `runtime.template_slot` is reserved and a Vessel's
    /// `"template"` names an exact Template (D50, D53).
    #[test]
    fn template_slot_and_template_entries() {
        let with = |f: &dyn Fn(&mut Value)| {
            let mut v: Value = serde_json::from_str(GOOD).unwrap();
            f(&mut v);
            Config::parse(&v.to_string())
        };
        let c = with(&|v| {
            v["runtime"]["template_slot"] = 9.into();
            v["vessels"][0]["template"] = "acme-base@3".into();
            v["vessels"][1]["template"] = "ab".repeat(16).into();
        })
        .unwrap();
        assert_eq!(c.runtime.template_slot, Some(9));
        assert_eq!(c.runtime.template_base(), Some(200_000 + 9 * ID_RANGE));
        assert_eq!(
            c.vessels[0].template.as_deref(),
            Some(&TemplateRef::Named {
                name: "acme-base".into(),
                version: 3
            })
        );
        assert_eq!(
            c.vessels[1].template.as_deref(),
            Some(&TemplateRef::Id(ChronicleId::from_bytes([0xab; 16])))
        );
        // Not set: no Template range, and no Template birth.
        assert_eq!(with(&|_| {}).unwrap().runtime.template_base(), None);
        let refused = |f: &dyn Fn(&mut Value), says: &str| {
            let e = with(f).unwrap_err().0;
            assert!(e.contains(says), "{e}");
        };
        refused(
            &|v| v["vessels"][0]["template"] = "acme-base@3".into(),
            "needs runtime.template_slot",
        );
        refused(
            &|v| {
                v["runtime"]["template_slot"] = 9.into();
                v["vessels"][0]["template"] = "acme-base".into();
            },
            "\"template\"",
        );
        refused(
            &|v| {
                v["runtime"]["template_slot"] = 9.into();
                v["vessels"][0]["template"] = 3.into();
            },
            "\"template\" must be",
        );
        refused(
            &|v| {
                v["runtime"]["template_slot"] = 9.into();
                v["vessels"][1]["template"] = "acme-base@3".into();
                v["vessels"][1]["fork"] = serde_json::json!({"parent": "a"});
            },
            "exclude each other",
        );
        // The Template range is no Vessel's and no fork's.
        refused(
            &|v| v["runtime"]["template_slot"] = 7.into(),
            "share uid_slot 7",
        );
        refused(
            &|v| {
                v["runtime"]["template_slot"] = 9.into();
                v["vessels"][0]["forks"] = serde_json::json!({"slots": [9]});
            },
            "fork slot 9 is also",
        );
        refused(
            &|v| v["runtime"]["template_slot"] = u64::from(u32::MAX).into(),
            "does not fit",
        );
    }

    /// A Template-born Vessel's files are the Template range's: they
    /// count for no slot in the guard's seed; another Vessel's files there
    /// count as usual; a layer's dataset is no Vessel's and no warning.
    #[test]
    fn held_on_counts_a_template_born_vessels_template_files_for_no_slot() {
        use crate::template::LAYER_LSN;
        let e = vessel_env();
        let t = ChronicleId::from_bytes([0x77; 16]);
        let key = taso_core::envelope::HashVal::from_bytes([0x1A; 32]);
        let layer = e.host.layer_dataset(t);
        e.host.pool.put_snapshot(layer.as_str(), LAYER_LSN, key);
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("store")).unwrap();
        let store: SharedStore = Arc::new(LocalStore::new(dir.path().join("store")));
        let tb = vessel_id(ns(1), b"tb");
        let packs = Packs::new(store, Storage::Zfs(Zfs::cli()).sender(), "p", tb).unwrap();
        let birth = TemplateBirth {
            template_id: t,
            layer_key: key,
            asked: None,
        };
        // Stopped before its Birth: its local log has the Lineage.
        let r = e
            .host
            .born_from_template(ns(1), b"tb", &birth, &packs, &|p| {
                if p == "birth.before_accept" {
                    Err(VesselError::Failpoint(p))
                } else {
                    Ok(())
                }
            });
        assert!(matches!(r, Err(VesselError::Failpoint(_))), "{:?}", r.err());
        let (void, _) = e.host.ensure(ns(1), b"void").unwrap();
        let void = void.id();
        let state = e.host.dir_for(tb).parent().unwrap().to_path_buf();
        let tbase = 200_000 + 9 * ID_RANGE;
        let pool = HoldTable(vec![
            (layer.clone(), vec![tbase]),
            (e.host.dataset_for(tb), vec![0, tbase, tbase + 5]),
            (e.host.dataset_for(void), vec![tbase]),
        ]);
        let root = Dataset::new("tank/vessels").unwrap();
        let (held, warnings) = held_on(&pool, &root, 200_000, Some(9), &state).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(held.len(), 2, "the layer is no Vessel's");
        let by = |k: ChronicleId| held.iter().find(|h| h.key == *k.as_bytes()).unwrap();
        assert_eq!(by(tb).slots, [].into());
        assert_eq!(by(tb).parent, None);
        assert_eq!(by(void).slots, [9].into(), "not born from a Template");
        // Without a Template range, those files are slot 9's like any.
        let (held, _) = held_on(&pool, &root, 200_000, None, &state).unwrap();
        let tbh = held.iter().find(|h| h.key == *tb.as_bytes()).unwrap();
        assert_eq!(tbh.slots, [9].into());
    }

    /// P4 file 5h (found on taso-test): a birth stopped after its clone
    /// leaves a dataset of the Template range and no Lineage yet.  Its
    /// files count for no slot, as a Template-born Vessel's, because the
    /// dataset is a clone of a layer under the root; a dataset with no
    /// Lineage that is not such a clone counts as before.
    #[test]
    fn held_on_counts_a_clone_of_a_layer_without_lineage_as_template_born() {
        let state = tempfile::tempdir().unwrap();
        let root = Dataset::new("t/v").unwrap();
        let tbase = 200_000 + 9 * ID_RANGE;
        let (a, b) = ("aa".repeat(16), "bb".repeat(16));
        let va = Dataset::new(&format!("t/v/v-{a}")).unwrap();
        let vb = Dataset::new(&format!("t/v/v-{b}")).unwrap();
        let layer = Dataset::new(&format!("t/v/t-{}", "77".repeat(16))).unwrap();
        let elsewhere = Dataset::new(&format!("t/w/t-{}", "77".repeat(16))).unwrap();
        let pool = |origin_of_b: Dataset| {
            CloneTable(
                HoldTable(vec![
                    (va.clone(), vec![0, tbase]),
                    (vb.clone(), vec![0, tbase]),
                ]),
                vec![
                    (va.clone(), (layer.clone(), Lsn::new(1))),
                    (vb.clone(), (origin_of_b, Lsn::new(1))),
                ],
            )
        };
        let (held, warnings) =
            held_on(&pool(elsewhere), &root, 200_000, Some(9), state.path()).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        let by = |k: &str| {
            held.iter()
                .find(|h| h.key == key_of_hex(k).unwrap())
                .unwrap()
        };
        assert_eq!(by(&a).slots, [].into(), "a clone of a layer under the root");
        assert_eq!(by(&b).slots, [9].into(), "a clone of something else");
        // Without a Template range, those files are slot 9's like any.
        let (held, _) = held_on(&pool(layer.clone()), &root, 200_000, None, state.path()).unwrap();
        assert!(held.iter().all(|h| h.slots == [9].into()));
        let layer = Dataset::new(&format!("t/v/t-{}", "77".repeat(16))).unwrap();
        // The guard then admits that Vessel's entry in its own slot (12),
        // where before it was "fixed" to slot 9 and refused.
        let mut vc = Config::parse(GOOD).unwrap().vessels[0].clone();
        vc.uid_slot = 12;
        let id_hex: String = vc
            .id()
            .as_bytes()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        let leftover = Dataset::new(&format!("t/v/v-{id_hex}")).unwrap();
        let pool = CloneTable(
            HoldTable(vec![(leftover.clone(), vec![0, tbase])]),
            vec![(leftover, (layer, Lsn::new(1)))],
        );
        let (held, _) = held_on(&pool, &root, 200_000, Some(9), state.path()).unwrap();
        assert_eq!(held[0].slots, [].into());
        let rt = RuntimeConf {
            template_slot: Some(9),
            ..Config::parse(GOOD).unwrap().runtime
        };
        let admitted = crate::source::Guard::seeded(rt, held).admit(vec![vc]);
        assert!(admitted.refused.is_empty(), "{:?}", admitted.refused);
    }

    /// The failpoints a node may stop a Template birth at are §10.2's.
    #[test]
    fn birth_failpoints_are_the_specs() {
        assert_eq!(
            BIRTH_FAILPOINTS,
            [
                "layer.after_build_put",
                "layer.before_shipped_accept",
                "layer.after_shipped_accept",
                "layer.after_receive",
                "birth.after_clone",
                "birth.after_lineage_append",
                "birth.before_accept",
            ]
        );
    }

    #[test]
    fn storage_is_zfs_or_the_block_log() {
        let with = |storage: Value| {
            let mut v: Value = serde_json::from_str(GOOD).unwrap();
            v["storage"] = storage;
            Config::parse(&v.to_string())
        };
        assert_eq!(
            with(serde_json::json!("zfs")).unwrap().storage,
            StorageConf::Zfs
        );
        let blk = serde_json::json!({"blk": {"socket": "/run/taso-blk.sock", "mounts": "/srv/taso", "spool": "/var/lib/taso-blk/spool"}});
        assert_eq!(
            with(blk).unwrap().storage,
            StorageConf::Blk {
                socket: "/run/taso-blk.sock".into(),
                mounts: "/srv/taso".into(),
                spool: "/var/lib/taso-blk/spool".into()
            }
        );
        for bad in [
            serde_json::json!("btrfs"),
            serde_json::json!({"blk": {"socket": "/s", "mounts": "/", "spool": "/p"}}),
            serde_json::json!({"blk": {"socket": "s", "mounts": "/m", "spool": "/p"}}),
            serde_json::json!({"blk": {"socket": "/s", "mounts": "/m"}}),
            serde_json::json!({"blk": {"socket": "/s", "mounts": "/m", "spool": "/p", "extra": 1}}),
            serde_json::json!({"blk": {}, "zfs": {}}),
        ] {
            assert!(with(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_good_config_parses() {
        let c = Config::parse(GOOD).unwrap();
        assert_eq!(c.warden, WardenId::new(1));
        assert_eq!(
            c.coordinator,
            CoordConf::Local {
                path: "/var/lib/taso/coord.redb".into(),
                serve: Some("/run/taso/coord.sock".into())
            }
        );
        assert!(c.batched_snapshots, "batched by default");
        assert_eq!(c.storage, StorageConf::Zfs, "ZFS by default");
        assert_eq!(c.prefix, "vessels");
        assert_eq!(
            c.runtime.landlock_shim.as_deref(),
            Some("/usr/lib/taso/landlock")
        );
        assert_eq!(
            (c.runtime.memory_bytes, c.runtime.pids),
            (Some(256 << 20), Some(64))
        );
        assert_eq!(c.vessels.len(), 2);
        assert_eq!(c.vessels[0].namespace, Namespace::from_bytes([1; 16]));
        assert_eq!(c.vessels[0].takeover, None);
        assert_eq!(
            c.vessels[1].takeover,
            Some(TakeOver {
                holder: WardenId::new(2),
                epoch: Epoch::new(5)
            })
        );
        let uids: Vec<_> = c.vessels.iter().map(|v| v.host_uid(&c.runtime)).collect();
        assert_eq!(
            uids,
            vec![Some(200_000), Some(200_000 + 7 * 65_536)],
            "one 65536-id range per slot"
        );
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
                ca_file: None,
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
            ca_file: None,
        };
        assert!(
            s3(dir.path().join("missing")).open().is_err(),
            "no secret file, no store"
        );
        std::fs::write(dir.path().join("secret"), "s3cr3t\n").unwrap();
        assert!(s3(dir.path().join("secret")).open().is_ok());
    }

    fn with(edit: impl FnOnce(&mut Value)) -> Result<Config, ConfigError> {
        let mut v: Value = serde_json::from_str(GOOD).unwrap();
        edit(&mut v);
        Config::parse(&v.to_string())
    }

    // ── fork entries (F6 step 3c) ────────────────────────────────────

    #[test]
    fn a_fork_entry_is_parsed_and_defaults_to_the_last_seal() {
        let c = Config::parse(GOOD).unwrap();
        assert!(
            c.vessels.iter().all(|v| v.fork.is_none()),
            "no \"fork\": a birth"
        );
        for (fork, want) in [
            (serde_json::json!({"parent": "a"}), SealAt::Last),
            (
                serde_json::json!({"parent": "a", "seal": "last"}),
                SealAt::Last,
            ),
            (
                serde_json::json!({"parent": "a", "seal": 7}),
                SealAt::At(Lsn::new(7)),
            ),
        ] {
            let c = with(|v| v["vessels"][1]["fork"] = fork.clone()).unwrap();
            assert_eq!(
                c.vessels[1].fork,
                Some(ForkConf {
                    parent: "a".into(),
                    seal: want
                }),
                "{fork}"
            );
        }
        // null is no fork, as for "takeover".
        let c = with(|v| v["vessels"][1]["fork"] = Value::Null).unwrap();
        assert_eq!(c.vessels[1].fork, None);
    }

    /// `"effects"` says whether a Vessel releases or holds; absent (or
    /// null) it is by origin: a fork holds, a birth dispatches.
    #[test]
    fn an_effects_entry_is_parsed_and_defaults_by_origin() {
        use taso_core::record::{Origin, ParentSeal};
        let c = Config::parse(GOOD).unwrap();
        assert!(c.vessels.iter().all(|v| v.effects.is_none()));
        for (text, want) in [
            ("dispatch", EffectsConf::Dispatch),
            ("hold", EffectsConf::Hold),
        ] {
            let c = with(|v| v["vessels"][1]["effects"] = text.into()).unwrap();
            assert_eq!(c.vessels[1].effects, Some(want), "{text}");
        }
        let c = with(|v| v["vessels"][1]["effects"] = Value::Null).unwrap();
        assert_eq!(c.vessels[1].effects, None);
        for bad in [
            serde_json::json!("send"),
            serde_json::json!(true),
            serde_json::json!({}),
        ] {
            let e = with(|v| v["vessels"][1]["effects"] = bad.clone()).unwrap_err();
            assert!(e.0.contains("\"dispatch\" or \"hold\""), "{bad}: {e}");
        }

        let fork = Origin::Fork {
            parent: ParentSeal {
                chronicle: ChronicleId::from_bytes([1; 16]),
                seal: Lsn::new(1),
                seal_hash: taso_core::envelope::HashVal::GENESIS,
            },
        };
        assert_eq!(EffectsConf::mode(None, &Origin::Void), Mode::Dispatch);
        assert_eq!(EffectsConf::mode(None, &fork), Mode::Hold);
        assert_eq!(
            EffectsConf::mode(Some(EffectsConf::Dispatch), &fork),
            Mode::Dispatch,
            "a fork meant to be its own agent"
        );
        assert_eq!(
            EffectsConf::mode(Some(EffectsConf::Hold), &Origin::Void),
            Mode::Hold,
            "a birth that only proposes"
        );
    }

    #[test]
    fn bad_fork_entries_are_refused() {
        for (fork, says) in [
            (serde_json::json!("a"), "must be an object"),
            (serde_json::json!({"seal": "last"}), "missing \"parent\""),
            (serde_json::json!({"parent": ""}), "must not be empty"),
            (serde_json::json!({"parent": 1}), "must be a string"),
            (serde_json::json!({"parent": "a", "seal": 0}), "at least 1"),
            (
                serde_json::json!({"parent": "a", "seal": "first"}),
                "\"last\" or an lsn",
            ),
            (
                serde_json::json!({"parent": "a", "seal": -3}),
                "\"last\" or an lsn",
            ),
            (
                serde_json::json!({"parent": "a", "sael": 3}),
                "unknown key \"sael\"",
            ),
            (
                serde_json::json!({"parent": "b"}),
                "cannot be forked from itself",
            ),
        ] {
            let e = with(|v| v["vessels"][1]["fork"] = fork.clone()).unwrap_err();
            assert!(e.0.contains(says), "{fork}: {}", e.0);
        }
    }

    // ── forks asked for over the Field (P3 file 11, D1) ──────────────

    /// `"forks": {"slots": [...]}` gives the agent's forks their slots, in
    /// order; absent or null: none.  A child's entry is the Warden's own:
    /// named after the slot, forked from the Seal asked for, held, never
    /// restarted, no forks of its own, the parent's namespace and runtime.
    #[test]
    fn a_forks_entry_is_parsed_and_makes_held_children() {
        let c = Config::parse(GOOD).unwrap();
        assert!(c.vessels.iter().all(|v| v.forks.is_none()));
        let c = with(|v| v["vessels"][1]["forks"] = Value::Null).unwrap();
        assert_eq!(c.vessels[1].forks, None);
        let c = with(|v| v["vessels"][0]["forks"] = serde_json::json!({"slots": [9, 8]})).unwrap();
        assert_eq!(
            c.vessels[0].forks,
            Some(Box::new(ForksConf { slots: vec![9, 8] }))
        );

        let parent = &c.vessels[0];
        let child = ForksConf::child(parent, 9, Lsn::new(4));
        assert_eq!(
            child,
            VesselConf {
                candidate: None,
                verifier: None,
                template: None,
                namespace: parent.namespace,
                subject: "a-fork-9".into(),
                takeover: None,
                uid_slot: 9,
                restart: Restart::Never,
                runtime: parent.runtime.clone(),
                fork: Some(ForkConf {
                    parent: "a".into(),
                    seal: SealAt::At(Lsn::new(4)),
                }),
                effects: Some(EffectsConf::Hold),
                promote: None,
                forks: None,
            }
        );
        // Held whatever its origin says.
        assert_eq!(
            EffectsConf::mode(child.effects, &taso_core::record::Origin::Void),
            Mode::Hold
        );
    }

    /// Every slot is named once in a config (a Vessel's, or one fork
    /// slot), fits the node, and a child's name is not a listed Vessel.
    #[test]
    fn bad_forks_entries_are_refused() {
        for (vessel, forks, says) in [
            (0, serde_json::json!([9]), "must be an object"),
            (0, serde_json::json!({}), "missing \"slots\""),
            (0, serde_json::json!({"slots": []}), "is empty"),
            (0, serde_json::json!({"slots": 9}), "must be an array"),
            (0, serde_json::json!({"slots": [-1]}), "must be an integer"),
            (0, serde_json::json!({"slots": ["9"]}), "must be an integer"),
            (0, serde_json::json!({"slots": [9, 9]}), "listed twice"),
            (
                0,
                serde_json::json!({"slots": [9], "max": 1}),
                "unknown key \"max\"",
            ),
            (0, serde_json::json!({"slots": [70000]}), "does not fit"),
            (0, serde_json::json!({"slots": [7]}), "also \"b\"'s"),
            (0, serde_json::json!({"slots": [0]}), "also \"a\"'s"),
        ] {
            let e = with(|v| v["vessels"][vessel]["forks"] = forks.clone()).unwrap_err();
            assert!(e.0.contains(says), "{forks}: {}", e.0);
        }
        // Two Vessels' forks sharing a slot.
        let e = with(|v| {
            v["vessels"][0]["forks"] = serde_json::json!({"slots": [9]});
            v["vessels"][1]["forks"] = serde_json::json!({"slots": [10, 9]});
        })
        .unwrap_err();
        assert!(e.0.contains("fork slot 9 is also \"a\"'s"), "{}", e.0);
        // A listed Vessel named like a child.
        let e = with(|v| {
            v["vessels"][0]["forks"] = serde_json::json!({"slots": [9]});
            v["vessels"][1]["subject"] = "a-fork-9".into();
        })
        .unwrap_err();
        assert!(e.0.contains("is listed as a vessel too"), "{}", e.0);
    }

    #[test]
    fn a_fork_inherits_only_a_whole_slots_range() {
        let base = 200_000;
        for (owner, want) in [
            ((base + ID_RANGE, base + ID_RANGE), Some(base + ID_RANGE)),
            ((base, base), Some(base)),
            (
                (base + 3 * ID_RANGE, base + 3 * ID_RANGE),
                Some(base + 3 * ID_RANGE),
            ),
            ((0, 0), None),                                 // fresh: becomes its own
            ((base + ID_RANGE, 0), None),                   // half
            ((base + ID_RANGE, base + 2 * ID_RANGE), None), // mixed
            ((base + ID_RANGE + 1000, base + ID_RANGE + 1000), None), // not a range's root
            ((1000, 1000), None),                           // below the base
        ] {
            assert_eq!(inherited_range(owner, base), want, "{owner:?}");
        }
    }

    #[test]
    fn restart_is_parsed_and_defaults_to_never() {
        let c = Config::parse(GOOD).unwrap();
        assert!(
            c.vessels.iter().all(|v| v.restart == Restart::Never),
            "no \"restart\": never"
        );
        for (text, want) in [
            ("never", Restart::Never),
            ("on-failure", Restart::OnFailure),
            ("always", Restart::Always),
        ] {
            let c = with(|v| v["vessels"][0]["restart"] = text.into()).unwrap();
            assert_eq!(c.vessels[0].restart, want, "{text}");
        }
        for bad in [
            serde_json::json!("sometimes"),
            serde_json::json!(true),
            serde_json::json!("Always"),
        ] {
            let e = with(|v| v["vessels"][0]["restart"] = bad.clone()).unwrap_err();
            assert!(e.to_string().contains("\"restart\" must be"), "{bad}: {e}");
        }
    }

    #[test]
    fn restart_policies() {
        use Restart::*;
        //                     exited ok      failed         never ran
        let table = [
            (Never, [false, false, false]),
            (OnFailure, [false, true, true]),
            (Always, [true, true, true]),
        ];
        for (policy, want) in table {
            let got = [
                policy.again(Some(true)),
                policy.again(Some(false)),
                policy.again(None),
            ];
            assert_eq!(got, want, "{policy:?}");
        }
    }

    #[test]
    fn a_stop_is_shared_by_its_clones() {
        let s = Stop::new();
        let c = s.clone();
        assert!(!s.requested() && !c.requested());
        c.request();
        assert!(s.requested() && c.requested());
        c.request();
        assert!(s.requested(), "idempotent");
        assert!(!Stop::new().requested(), "a new one is independent");
    }

    #[test]
    fn bad_configs_are_refused() {
        type Edit = Box<dyn FnOnce(&mut Value)>;
        let cases: Vec<(&str, Edit)> = vec![
            ("warden 0", Box::new(|v| v["warden"] = 0.into())),
            (
                "both coordinators",
                Box::new(|v| v["coordinator"]["remote"] = "/x.sock".into()),
            ),
            (
                "no coordinator",
                Box::new(|v| v["coordinator"] = serde_json::json!({})),
            ),
            ("relative store", Box::new(|v| v["store"] = "store".into())),
            (
                "s3 without bucket",
                Box::new(
                    |v| v["store"] = serde_json::json!({"s3": {"endpoint": "http://x:1", "access_key_id": "a", "secret_key_file": "/s"}}),
                ),
            ),
            (
                "s3 relative secret",
                Box::new(
                    |v| v["store"] = serde_json::json!({"s3": {"endpoint": "http://x:1", "bucket": "b", "access_key_id": "a", "secret_key_file": "s"}}),
                ),
            ),
            ("store number", Box::new(|v| v["store"] = 3.into())),
            ("bad dataset", Box::new(|v| v["root"] = "tank//v".into())),
            (
                "no agent",
                Box::new(|v| v["runtime"]["args"] = serde_json::json!([])),
            ),
            (
                "short namespace",
                Box::new(|v| v["vessels"][0]["namespace"] = "0101".into()),
            ),
            (
                "non-hex namespace",
                Box::new(|v| v["vessels"][0]["namespace"] = "zz".repeat(16).into()),
            ),
            (
                "a vessel twice",
                Box::new(|v| v["vessels"][1]["subject"] = "a".into()),
            ),
            (
                "absolute db",
                Box::new(|v| v["quiescence"] = serde_json::json!(["/etc/passwd"])),
            ),
            (
                "db outside",
                Box::new(|v| v["quiescence"] = serde_json::json!(["../x.db"])),
            ),
            (
                "takeover a bool",
                Box::new(|v| v["vessels"][0]["takeover"] = true.into()),
            ),
            (
                "takeover false",
                Box::new(|v| v["vessels"][0]["takeover"] = false.into()),
            ),
            (
                "takeover without epoch",
                Box::new(|v| v["vessels"][0]["takeover"] = serde_json::json!({"holder": 2})),
            ),
            (
                "takeover epoch 0",
                Box::new(|v| {
                    v["vessels"][0]["takeover"] = serde_json::json!({"holder": 2, "epoch": 0})
                }),
            ),
            (
                "takeover extra key",
                Box::new(|v| {
                    v["vessels"][0]["takeover"] =
                        serde_json::json!({"holder": 2, "epoch": 1, "from": 3})
                }),
            ),
            (
                "huge uid base",
                Box::new(|v| v["runtime"]["host_uid_base"] = (u64::from(u32::MAX) + 1).into()),
            ),
            (
                "no uid slot",
                Box::new(|v| {
                    v["vessels"][0].as_object_mut().unwrap().remove("uid_slot");
                }),
            ),
            (
                "uid slot not a number",
                Box::new(|v| v["vessels"][0]["uid_slot"] = "1".into()),
            ),
            (
                "uid slot shared",
                Box::new(|v| v["vessels"][1]["uid_slot"] = 0.into()),
            ),
            (
                "uid slot huge",
                Box::new(|v| v["vessels"][1]["uid_slot"] = (u64::from(u32::MAX) + 1).into()),
            ),
            // 200000 + 65535·65536 overflows a u32; so does the end of the
            // last range that would start below u32::MAX.
            (
                "uid slot past u32",
                Box::new(|v| v["vessels"][1]["uid_slot"] = 65_535.into()),
            ),
            (
                "range end past u32",
                Box::new(|v| {
                    v["runtime"]["host_uid_base"] = (u64::from(u32::MAX) - 65_536).into();
                    v["vessels"][1]["uid_slot"] = 1.into();
                }),
            ),
        ];
        for (name, edit) in cases {
            assert!(with(edit).is_err(), "{name} was accepted");
        }
        assert!(Config::parse("not json").is_err());
        let remote =
            with(|v| v["coordinator"] = serde_json::json!({ "remote": "/run/taso/coord.sock" }))
                .unwrap();
        assert_eq!(
            remote.coordinator,
            CoordConf::Remote {
                socket: "/run/taso/coord.sock".into()
            }
        );
    }

    // ── Per-Vessel runtime ──────────────────────────────────────────

    fn effective_of(c: &Config, i: usize) -> Result<Effective, String> {
        c.vessels[i].effective(&c.runtime, &c.quiescence)
    }

    #[test]
    fn a_vessel_without_its_own_runtime_runs_with_the_nodes() {
        let c = Config::parse(GOOD).unwrap();
        assert_eq!(c.source, SourceConf::Static, "static by default");
        assert_eq!(c.vessels[0].runtime, None);
        let e = effective_of(&c, 0).unwrap();
        assert_eq!(
            e,
            Effective {
                rootfs: "/srv/taso/rootfs".into(),
                args: vec!["/usr/bin/agent".into(), "--serve".into()],
                env: vec![],
                landlock_shim: Some("/usr/lib/taso/landlock".into()),
                memory_bytes: Some(256 << 20),
                pids: Some(64),
                quiescence: vec!["state.db".into()],
            }
        );
    }

    #[test]
    fn a_vessels_own_runtime_replaces_each_field_it_sets() {
        let c = with(|v| {
            v["vessels"][0]["runtime"] = serde_json::json!({
                "rootfs": "/srv/taso/images/a", "args": ["/bin/a"], "env": ["X=1"],
                "landlock": false, "memory_bytes": 1024, "pids": 3, "quiescence": []
            });
            v["vessels"][1]["runtime"] = serde_json::json!({ "pids": 9 });
        })
        .unwrap();
        let a = effective_of(&c, 0).unwrap();
        assert_eq!(
            a,
            Effective {
                rootfs: "/srv/taso/images/a".into(),
                args: vec!["/bin/a".into()],
                env: vec!["X=1".into()],
                landlock_shim: None,
                memory_bytes: Some(1024),
                pids: Some(3),
                quiescence: vec![],
            }
        );
        let b = effective_of(&c, 1).unwrap();
        assert_eq!(b.pids, Some(9));
        assert_eq!(
            (b.rootfs.as_path(), b.memory_bytes),
            (Path::new("/srv/taso/rootfs"), Some(256 << 20)),
            "the rest is the node's"
        );
        assert_eq!(b.landlock_shim.as_deref(), Some("/usr/lib/taso/landlock"));
    }

    #[test]
    fn landlock_asked_for_on_a_node_without_a_shim_is_refused() {
        let mut rt = Config::parse(GOOD).unwrap().runtime;
        rt.landlock_shim = None;
        let vc = |landlock| VesselConf {
            candidate: None,
            verifier: None,
            template: None,
            fork: None,
            namespace: Namespace::from_bytes([1; 16]),
            subject: "a".into(),
            takeover: None,
            uid_slot: 0,
            restart: Restart::Never,
            runtime: Some(Box::new(VesselRuntime {
                landlock,
                ..Default::default()
            })),
            effects: None,
            promote: None,
            forks: None,
        };
        let e = vc(Some(true)).effective(&rt, &[]).unwrap_err();
        assert!(e.contains("no runtime.landlock_shim"), "{e}");
        // Checked here too, not only by the parser: other sources build a
        // VesselRuntime themselves.
        for own in [
            VesselRuntime {
                memory_bytes: Some(0),
                ..Default::default()
            },
            VesselRuntime {
                pids: Some(0),
                ..Default::default()
            },
        ] {
            let e = VesselConf {
                fork: None,
                effects: None,
                runtime: Some(Box::new(own)),
                ..vc(None)
            }
            .effective(&rt, &[])
            .unwrap_err();
            assert!(e.contains("at least 1"), "{e}");
        }
        assert_eq!(vc(None).effective(&rt, &[]).unwrap().landlock_shim, None);
        assert_eq!(
            vc(Some(false)).effective(&rt, &[]).unwrap().landlock_shim,
            None
        );
    }

    #[test]
    fn a_node_without_rootfs_or_args_needs_them_from_every_vessel() {
        let bare = |v: &mut Value| {
            let r = v["runtime"].as_object_mut().unwrap();
            r.remove("rootfs");
            r.remove("args");
        };
        let e = with(bare).unwrap_err().to_string();
        assert!(e.contains("vessel \"a\"") && e.contains("no rootfs"), "{e}");
        let only_rootfs = with(|v| {
            bare(v);
            for i in 0..2 {
                v["vessels"][i]["runtime"] = serde_json::json!({ "rootfs": "/r" });
            }
        })
        .unwrap_err()
        .to_string();
        assert!(only_rootfs.contains("no agent"), "{only_rootfs}");
        let c = with(|v| {
            bare(v);
            for i in 0..2 {
                v["vessels"][i]["runtime"] = serde_json::json!({ "rootfs": "/r", "args": ["/a"] });
            }
        })
        .unwrap();
        assert_eq!(c.runtime.rootfs, None);
        assert!(effective_of(&c, 1).is_ok());
    }

    #[test]
    fn bad_vessel_runtimes_are_refused() {
        let cases: Vec<(&str, Value)> = vec![
            (
                "relative rootfs",
                serde_json::json!({ "rootfs": "images/a" }),
            ),
            ("empty args", serde_json::json!({ "args": [] })),
            ("args not strings", serde_json::json!({ "args": [1] })),
            ("NUL in args", serde_json::json!({ "args": ["/a\0b"] })),
            ("env without =", serde_json::json!({ "env": ["X"] })),
            ("env bad name", serde_json::json!({ "env": ["1X=1"] })),
            ("env empty name", serde_json::json!({ "env": ["=1"] })),
            ("env dash", serde_json::json!({ "env": ["A-B=1"] })),
            ("NUL in env", serde_json::json!({ "env": ["X=a\0"] })),
            ("landlock not bool", serde_json::json!({ "landlock": "no" })),
            ("zero memory", serde_json::json!({ "memory_bytes": 0 })),
            ("zero pids", serde_json::json!({ "pids": 0 })),
            ("negative pids", serde_json::json!({ "pids": -1 })),
            (
                "absolute db",
                serde_json::json!({ "quiescence": ["/etc/passwd"] }),
            ),
            (
                "db outside",
                serde_json::json!({ "quiescence": ["a/../../x"] }),
            ),
            ("empty db", serde_json::json!({ "quiescence": [""] })),
            ("misspelt key", serde_json::json!({ "memory_byte": 1 })),
            ("not an object", serde_json::json!(["/r"])),
        ];
        for (name, rt) in cases {
            assert!(
                with(|v| v["vessels"][0]["runtime"] = rt.clone()).is_err(),
                "{name} was accepted"
            );
        }
        assert!(
            with(|v| v["runtime"]["env"] = serde_json::json!(["bad name=1"])).is_err(),
            "the node's env is checked too"
        );
        assert!(
            with(|v| v["runtime"]["env"] = serde_json::json!(["OK_1=a=b"])).is_ok(),
            "= in the value is fine"
        );
    }

    // ── The Kubernetes source ───────────────────────────────────────

    const TENANT_A: &str = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
    const TENANT_B: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

    fn kube(edit: impl FnOnce(&mut Value)) -> Result<Config, ConfigError> {
        with(|v| {
            v.as_object_mut().unwrap().remove("vessels");
            v["source"] = serde_json::json!({ "kubernetes": {
                "node": "worker-3",
                "tenants": { "team-a": TENANT_A, "team-b": TENANT_B },
                "rootfs_dir": "/srv/taso/rootfs",
                "max_memory_bytes": 1u64 << 30,
                "max_pids": 512
            } });
            edit(v);
        })
    }

    #[test]
    fn a_kubernetes_source_parses_with_safe_defaults() {
        let c = kube(|_| {}).unwrap();
        let SourceConf::Kubernetes(k) = &c.source else {
            panic!("{:?}", c.source)
        };
        assert_eq!(k.node, "worker-3");
        assert_eq!(k.tenants.len(), 2);
        assert_eq!(k.tenants["team-a"], Namespace::from_bytes([0x0a; 16]));
        assert_eq!(k.tenants["team-b"], Namespace::from_bytes([0x0b; 16]));
        assert_eq!(k.rootfs_dir, PathBuf::from("/srv/taso/rootfs"));
        assert_eq!((k.max_memory_bytes, k.max_pids), (1 << 30, 512));
        assert!(
            !k.allow_without_landlock,
            "Landlock stays on unless the node allows otherwise"
        );
        assert_eq!(k.api, None, "in-cluster by default");
        assert!(c.vessels.is_empty());

        let c = kube(|v| {
            v["vessels"] = serde_json::json!([]);
            v["source"]["kubernetes"]["allow_without_landlock"] = true.into();
            v["source"]["kubernetes"]["api"] =
                serde_json::json!({ "url": "https://127.0.0.1:16443", "token_file": "/t", "ca_file": "/ca.crt" });
        })
        .unwrap();
        let SourceConf::Kubernetes(k) = &c.source else {
            panic!()
        };
        assert!(k.allow_without_landlock);
        assert_eq!(
            k.api,
            Some(KubeApiConf {
                url: "https://127.0.0.1:16443".into(),
                token_file: "/t".into(),
                ca_file: Some("/ca.crt".into())
            })
        );
        assert!(with(|v| v["source"] = "static".into()).is_ok());
    }

    #[test]
    fn bad_kubernetes_sources_are_refused() {
        type Edit = Box<dyn FnOnce(&mut Value)>;
        let k = |f: fn(&mut Value)| -> Edit {
            Box::new(move |v: &mut Value| f(&mut v["source"]["kubernetes"]))
        };
        let cases: Vec<(&str, &str, Edit)> = vec![
            (
                "vessels too",
                "exclude each other",
                Box::new(|v| {
                    v["vessels"] = serde_json::json!([{ "namespace": TENANT_A, "subject": "a", "uid_slot": 0 }])
                }),
            ),
            (
                "one tenant, two namespaces",
                "same tenant",
                k(|k| k["tenants"]["team-c"] = TENANT_A.into()),
            ),
            (
                "no tenants",
                "at least one",
                k(|k| k["tenants"] = serde_json::json!({})),
            ),
            (
                "tenants not a map",
                "at least one",
                k(|k| k["tenants"] = serde_json::json!([TENANT_A])),
            ),
            (
                "bad tenant",
                "32 hex",
                k(|k| k["tenants"]["team-a"] = "0a".into()),
            ),
            (
                "tenant not a string",
                "32 hex",
                k(|k| k["tenants"]["team-a"] = 1.into()),
            ),
            (
                "namespace upper case",
                "namespace name",
                k(|k| k["tenants"]["Team-A"] = TENANT_A.into()),
            ),
            (
                "namespace with a dot",
                "namespace name",
                k(|k| k["tenants"]["team.c"] = "0c".repeat(16).into()),
            ),
            (
                "namespace too long",
                "namespace name",
                k(|k| k["tenants"]["n".repeat(64)] = "0c".repeat(16).into()),
            ),
            (
                "no node",
                "missing \"node\"",
                k(|k| {
                    k.as_object_mut().unwrap().remove("node");
                }),
            ),
            (
                "bad node",
                "node name",
                k(|k| k["node"] = "worker/3".into()),
            ),
            (
                "relative rootfs_dir",
                "absolute",
                k(|k| k["rootfs_dir"] = "rootfs".into()),
            ),
            (
                "no memory max",
                "max_memory_bytes is required",
                k(|k| {
                    k.as_object_mut().unwrap().remove("max_memory_bytes");
                }),
            ),
            (
                "no pids max",
                "max_pids is required",
                k(|k| {
                    k.as_object_mut().unwrap().remove("max_pids");
                }),
            ),
            (
                "zero pids max",
                "at least 1",
                k(|k| k["max_pids"] = 0.into()),
            ),
            (
                "node default above max",
                "above",
                k(|k| k["max_pids"] = 63.into()),
            ),
            (
                "plain http",
                "https://",
                k(|k| {
                    k["api"] =
                        serde_json::json!({ "url": "http://10.0.0.1:6443", "token_file": "/t" })
                }),
            ),
            (
                "relative token",
                "absolute",
                k(|k| k["api"] = serde_json::json!({ "url": "https://h:1", "token_file": "t" })),
            ),
            (
                "misspelt key",
                "unknown key",
                k(|k| k["allow_without_landlok"] = true.into()),
            ),
            (
                "misspelt api key",
                "unknown key",
                k(|k| {
                    k["api"] =
                        serde_json::json!({ "url": "https://h:1", "token_file": "/t", "ca": "/c" })
                }),
            ),
            (
                "landlock not bool",
                "true or false",
                k(|k| k["allow_without_landlock"] = "yes".into()),
            ),
            (
                "no shim",
                "landlock_shim",
                Box::new(|v| {
                    v["runtime"]
                        .as_object_mut()
                        .unwrap()
                        .remove("landlock_shim");
                }),
            ),
            (
                "other source",
                "\"source\" must be",
                Box::new(|v| v["source"] = "etcd".into()),
            ),
            (
                "extra source key",
                "unknown key",
                Box::new(|v| v["source"]["static"] = true.into()),
            ),
        ];
        for (name, want, edit) in cases {
            match kube(edit) {
                Ok(_) => panic!("{name} was accepted"),
                Err(e) => assert!(
                    e.to_string().contains(want),
                    "{name}: {e} (wanted {want:?})"
                ),
            }
        }
        // Without a shim, a node that allows it may still take a cluster's Vessels.
        assert!(kube(|v| {
            v["runtime"]
                .as_object_mut()
                .unwrap()
                .remove("landlock_shim");
            v["source"]["kubernetes"]["allow_without_landlock"] = true.into();
        })
        .is_ok());
        // A static config still needs its list.
        assert!(with(|v| {
            v.as_object_mut().unwrap().remove("vessels");
        })
        .unwrap_err()
        .to_string()
        .contains("missing \"vessels\""));
    }

    #[test]
    fn kubernetes_namespace_names() {
        for ok in ["a", "team-a", "a1", "1a", &"n".repeat(63)] {
            assert!(valid_kube_namespace(ok), "{ok}");
        }
        for no in ["", "-a", "a-", "A", "a.b", "a_b", &"n".repeat(64), "a b"] {
            assert!(!valid_kube_namespace(no), "{no}");
        }
    }

    /// A zfs runner answering `list` and `userspace` from a table.
    struct ZfsTable(BTreeMap<String, String>);
    impl Runner for ZfsTable {
        fn run(&self, args: &[String]) -> Result<crate::zfs::Output, ZfsError> {
            let key = format!("{} {}", args[0], args.last().unwrap());
            let out = |stdout: &str| crate::zfs::Output {
                success: true,
                code: Some(0),
                stdout: stdout.into(),
                stderr: String::new(),
            };
            self.0
                .get(&key)
                .map(|s| out(s))
                .ok_or_else(|| ZfsError::Spawn(format!("unexpected: {key}")))
        }
        fn run_input(
            &self,
            _: &[String],
            _: &mut dyn std::io::Read,
        ) -> Result<crate::zfs::Output, ZfsError> {
            unreachable!()
        }
    }
    use std::collections::BTreeMap;

    #[test]
    fn the_pool_says_which_slots_own_each_vessels_files() {
        let (a, b, c) = ("aa".repeat(16), "bb".repeat(16), "cc".repeat(16));
        let pool = ZfsTable(
            [
                (
                    "list t/v".to_string(),
                    format!("t/v\nt/v/v-{a}\nt/v/v-{b}\nt/v/v-{c}\nt/v/scratch\nt/v/v-XYZ\n"),
                ),
                (format!("userspace t/v/v-{a}"), "0\n265536\n265537\n".into()),
                // No local Lineage for any: each is asked whether it is a
                // clone of a Template's layer (it is not).
                (
                    format!("list t/v/v-{a}"),
                    format!("t/v/v-{a}\t/t/v/v-{a}\t-\t-\n"),
                ),
                (
                    format!("list t/v/v-{b}"),
                    format!("t/v/v-{b}\t/t/v/v-{b}\t-\t-\n"),
                ),
                (
                    format!("list t/v/v-{c}"),
                    format!("t/v/v-{c}\t/t/v/v-{c}\t-\t-\n"),
                ),
                (format!("userspace t/v/v-{b}"), "0\n".into()),
                (
                    format!("userspace t/v/v-{c}"),
                    "331072\n265536\n1000\n".into(),
                ),
            ]
            .into(),
        );
        let no_state = tempfile::tempdir().unwrap();
        let (held, warnings) = held_on(
            &Zfs::with_runner(pool),
            &Dataset::new("t/v").unwrap(),
            200_000,
            None,
            no_state.path(),
        )
        .unwrap();
        assert!(
            held.iter().all(|h| h.parent.is_none()),
            "no local logs: no parents"
        );
        let got: Vec<(u8, Vec<u32>)> = held
            .iter()
            .map(|h| (h.key[0], h.slots.iter().copied().collect()))
            .collect();
        assert_eq!(
            got,
            vec![(0xaa, vec![1]), (0xbb, vec![]), (0xcc, vec![1, 2])]
        );
        assert_eq!(warnings.len(), 3, "{warnings:?}");
        assert!(warnings
            .iter()
            .any(|w| w.contains("scratch is not a Vessel")));
        assert!(warnings.iter().any(|w| w.contains("v-XYZ is not a Vessel")));
        assert!(warnings
            .iter()
            .any(|w| w.contains("uid 1000, below host_uid_base")));
        // A pool that cannot be read is an error, never "nothing held".
        let broken = ZfsTable([("list t/v".to_string(), format!("t/v\nt/v/v-{a}\n"))].into());
        assert!(held_on(
            &Zfs::with_runner(broken),
            &Dataset::new("t/v").unwrap(),
            200_000,
            None,
            no_state.path(),
        )
        .is_err());
    }

    /// Holdings from a table: datasets and the uids owning files in each.
    struct HoldTable(Vec<(Dataset, Vec<u32>)>);
    impl Holdings for HoldTable {
        fn children(&self, _: &Dataset) -> Result<Vec<Dataset>, LayerError> {
            Ok(self.0.iter().map(|(d, _)| d.clone()).collect())
        }
        fn owner_uids(&self, ds: &Dataset) -> Result<std::collections::BTreeSet<u32>, LayerError> {
            Ok(self
                .0
                .iter()
                .find(|(d, _)| d == ds)
                .map(|(_, u)| u.iter().copied().collect())
                .unwrap_or_default())
        }
        fn origin(&self, _: &Dataset) -> Result<Option<(Dataset, Lsn)>, LayerError> {
            Ok(None)
        }
    }

    /// A [`HoldTable`] whose datasets may be clones.
    struct CloneTable(HoldTable, Vec<(Dataset, (Dataset, Lsn))>);
    impl Holdings for CloneTable {
        fn children(&self, r: &Dataset) -> Result<Vec<Dataset>, LayerError> {
            self.0.children(r)
        }
        fn owner_uids(&self, ds: &Dataset) -> Result<std::collections::BTreeSet<u32>, LayerError> {
            self.0.owner_uids(ds)
        }
        fn origin(&self, ds: &Dataset) -> Result<Option<(Dataset, Lsn)>, LayerError> {
            Ok(self.1.iter().find(|(d, _)| d == ds).map(|(_, o)| o.clone()))
        }
    }

    /// F6 step 3b: the parent edge a fork's local Chronicle names reaches
    /// the guard's seed; a void birth has none; a log that cannot be read
    /// is a warning and no parent (it can only block, never let in).
    #[test]
    fn held_on_reads_each_forks_parent_from_its_local_chronicle() {
        let e = vessel_env();
        let (mut p, _) = e.host.ensure(ns(1), b"parent").unwrap();
        let s = p.seal_birth().unwrap().seal;
        let c = e.host.fork(&p, s, b"child").unwrap();
        let (pid, cid) = (p.id(), c.id());
        drop(c);
        drop(p);
        let state = e.host.dir_for(pid).parent().unwrap().to_path_buf();
        let range1 = 200_000 + ID_RANGE;
        let pool = HoldTable(vec![
            (e.host.dataset_for(pid), vec![0, range1]),
            (e.host.dataset_for(cid), vec![range1, range1 + 1000]),
        ]);
        let root = Dataset::new("tank/vessels").unwrap();
        let (held, warnings) = held_on(&pool, &root, 200_000, None, &state).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        let by = |k: ChronicleId| held.iter().find(|h| h.key == *k.as_bytes()).unwrap();
        assert_eq!(by(pid).parent, None);
        assert_eq!(by(cid).parent, Some(*pid.as_bytes()));
        assert_eq!(by(cid).slots, [1].into());

        // A local log that cannot be read: a warning, no parent.
        let cdir = e.host.dir_for(cid);
        for f in std::fs::read_dir(&cdir).unwrap() {
            let f = f.unwrap().path();
            if f.is_file() {
                std::fs::write(&f, b"not a segment").unwrap();
            }
        }
        let (held, warnings) = held_on(&pool, &root, 200_000, None, &state).unwrap();
        let child = held.iter().find(|h| h.key == *cid.as_bytes()).unwrap();
        if child.parent.is_some() {
            panic!("an unreadable log must not name a parent");
        }
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("Lineage cannot be read")),
            "{warnings:?}"
        );
    }

    #[test]
    fn vessel_keys_from_hex() {
        assert_eq!(key_of_hex(&"0a".repeat(16)), Some([0x0a; 16]));
        for bad in [
            "0A".repeat(16),
            "0a".repeat(15),
            "0a".repeat(17),
            "zz".repeat(16),
            String::new(),
        ] {
            assert_eq!(key_of_hex(&bad), None, "{bad}");
        }
        // The name the Vessel layer gives a dataset parses back to its id.
        let id = vessel_id(Namespace::from_bytes([7; 16]), b"s");
        assert_eq!(key_of_hex(&id_hex(id)), Some(*id.as_bytes()));
    }

    #[test]
    fn how_a_vessel_starts() {
        let (me, other) = (WardenId::new(1), WardenId::new(2));
        let (e3, e4) = (Epoch::new(3), Epoch::new(4));
        let exact = Some(TakeOver {
            holder: other,
            epoch: e3,
        });
        let stale = Some(TakeOver {
            holder: other,
            epoch: e4,
        });
        let wrong = Some(TakeOver {
            holder: WardenId::new(9),
            epoch: e3,
        });
        let spent = Some(TakeOver {
            holder: me,
            epoch: e3,
        });
        // Nobody holds it: born, unless a takeover expected a holder
        // (decided 2026-10-21: refused, never an empty Vessel instead).
        for local in [false, true] {
            assert_eq!(decide(Known::No, local, me, None), Start::Birth);
            assert_eq!(decide(Known::Unborn, local, me, None), Start::Birth);
            for takeover in [exact, stale, wrong, spent] {
                for (known, why_part) in [
                    (Known::No, "the coordinator does not know it"),
                    (Known::Unborn, "its birth never finished"),
                ] {
                    let Start::Refuse(why) = decide(known, local, me, takeover) else {
                        panic!("{known:?} {takeover:?}")
                    };
                    assert!(
                        why.contains("nobody holds the Vessel") && why.contains(why_part),
                        "{why}"
                    );
                }
            }
        }
        // Mine: any takeover entry is spent or irrelevant.
        for takeover in [None, exact, stale, spent] {
            assert_eq!(decide(Known::Held(me, e3), true, me, takeover), Start::Open);
            assert_eq!(
                decide(Known::Held(me, e3), false, me, takeover),
                Start::Rebirth,
                "ours, local state lost"
            );
        }
        // Another Warden's: only a takeover naming exactly what was read.
        for takeover in [None, stale, wrong, spent] {
            for local in [false, true] {
                let Start::Refuse(why) = decide(Known::Held(other, e3), local, me, takeover) else {
                    panic!("{takeover:?}")
                };
                assert!(why.contains("epoch 3") && why.contains("Warden 2"), "{why}");
                if takeover.is_some() {
                    assert!(why.contains("nothing fenced"), "{why}");
                }
            }
        }
        assert_eq!(decide(Known::Held(other, e3), true, me, exact), Start::Open);
        assert_eq!(
            decide(Known::Held(other, e3), false, me, exact),
            Start::Rebirth
        );
    }

    fn pos(n: u64) -> Position {
        Position {
            lsn: taso_core::envelope::Lsn::new(n),
            hash: taso_core::envelope::HashVal::from_bytes([n as u8; 32]),
        }
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
            segment: crate::segment::Recovery {
                unaccepted_frames: 0,
                invalid_bytes: 0,
            },
            orphan_layers: vec![taso_core::envelope::Lsn::new(4)],
            last_seal: None,
            missing_layers: vec![],
            gap: None,
        };
        assert_eq!(
            verdict_after_open(&clean),
            Verdict::Clean,
            "an orphan layer loses nothing accepted"
        );
        let mut lossy = clean.clone();
        lossy.segment = crate::segment::Recovery {
            unaccepted_frames: 2,
            invalid_bytes: 7,
        };
        lossy.gap = Some((pos(3), pos(6)));
        lossy.missing_layers = vec![pos(4)];
        let Verdict::Unverified(why) = verdict_after_open(&lossy) else {
            panic!()
        };
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
        let lossy = Reborn {
            gap: Some((pos(9), pos(12))),
            missing_layers: vec![pos(11)],
            ..reborn
        };
        let Verdict::Unverified(why) = verdict_after_rebirth(&lossy) else {
            panic!()
        };
        assert!(
            why.contains("records 10..12") && why.contains("1 Seals without"),
            "{why}"
        );
    }

    #[test]
    fn container_ids_are_per_vessel_and_warden() {
        let (v, w) = (ChronicleId::from_bytes([0xab; 16]), WardenId::new(1));
        let a = container_id(v, w);
        assert_eq!(a, format!("taso-{}-w1", "ab".repeat(16)));
        assert_ne!(a, container_id(ChronicleId::from_bytes([0xac; 16]), w));
        let b = container_id(v, WardenId::new(2));
        assert_ne!(
            a, b,
            "a new holder never reuses the old holder's container (cgroup)"
        );
        assert_eq!(a[..12], b[..12], "the hostname part is the Vessel's");
        assert!(a.len() <= 128 && a.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'));
    }
}
