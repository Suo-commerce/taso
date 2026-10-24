//! Template genesis (P4 spec rev. 14 §7; D17, D38–D48; file 4b).
//!
//! A genesis makes a Template from a tree nobody verified: a Vessel's Seal,
//! or a host directory under `--best-effort`.  It runs on a node, with that
//! node's storage, store, coordinator and Warden id, and every step is
//! ordered so that running it again with the same inputs finishes it, on
//! this node or another one (§7 step 8):
//!
//! 1. **Export** (§7 steps 1–2, D38, D44).  The source is walked with the
//!    classification map and its slot base (a directory: 0; a Seal: its top
//!    directory's owner, D44) and written as the **source artifact**; the
//!    artifact and the map are put, any existing object read back and
//!    verified first (§0.4).  This gives `genesis_id` (§9), which is also
//!    the Template's id.  Nothing local is needed after this step.
//! 2. **Lookup and claim** (§7 step 3, D42).  The log is asked by logical
//!    id what is already accepted, and accepted steps are skipped.  The
//!    genesis Chronicle (id `genesis_id`, no Lineage record, D46) is
//!    claimed with authority `Genesis`; if someone else holds it, it is
//!    taken over: with `GenesisStarted` once that is accepted, else with
//!    `Genesis` while nothing of it is accepted.  The local log lives in
//!    `<state_dir>/genesis/<id hex>`, rebuilt from the shipped packs when
//!    this node does not have it.
//! 3. **`GenesisStarted`** is accepted: holds on the source artifact and
//!    the map; `peer` is this process's uid and pid (D46).
//! 4. **Judge** (§7 step 4).  The source artifact's manifest, read from the
//!    store, is the input manifest and is put.  Refused, in this order: a
//!    stopped walk (`IncompleteWalk`); unsupported entries
//!    (`ReservedMismatch` if one of them is a reserved entry, else
//!    `Unsupported`); `Secret`; `Unknown`; `Hook` without a waiver.  A
//!    refusal is `GenesisRefused { reason, input_manifest_key }`, and no
//!    scratch was made.
//! 5. **Materialise.**  The output manifest is the input manifest (nothing
//!    is excluded, §4.1).  The scratch `<root>/genesis-<id hex>` is made
//!    fresh (one left by an interrupted run is destroyed by guid first and
//!    reported), the source artifact is restored into it from the store
//!    with slot base 0 (D43), its layer is taken at a synthetic lsn 1, and
//!    the sealed view is walked and compared entry for entry (§4.1.7).  A
//!    restore that fails as it runs is an error (the next run starts on a
//!    fresh scratch); a completed restore whose walk differs is
//!    `GenesisRefused { MaterialisationMismatch }` (D45).
//! 6. **Artifact** (§7 step 5).  The sealed view is exported with the
//!    output manifest and put; with nothing excluded it is the source
//!    artifact's bytes again, the same object.
//! 7. **Publish** (§7 step 6).  `TemplateReady { born_from: Genesis }`.
//! 8. **Cleanup** (§7 step 7, D45).  After `TemplateReady`, or after a
//!    `GenesisRefused` once a scratch existed: the record
//!    `GenesisCleanedUp { scratch_guid }` is written to the local log
//!    first, then the scratch is destroyed by that guid, then the record is
//!    accepted, so a run interrupted between the two still names the guid.
//!
//! # Submitting a record
//!
//! Every record goes the same way ([`Run::submit`]): the logical id is
//! asked first (accepted → done, whatever the digest); the record is
//! appended to the local log once (a frame with the same logical id from
//! an earlier run is reused, so the earlier run's `peer` stands); the log
//! is shipped and the anchor advanced; then announce and accept with the
//! head `query { chronicle }` reports.  `HeadMoved` cancels and resubmits;
//! `NotReadable` retries the same submission; `Conflict` reads the accepted
//! record and returns it for the caller to compare.
//!
//! # Failpoints (§10.2)
//!
//! [`Genesis::failpoint`] is called at each of `genesis.after_source_put`,
//! `before_started_accept`, `after_started_accept`, `after_materialise`,
//! `after_artifact_put`, `before_ready_accept`, `after_ready_accept` and
//! `before_cleanup`; an `Err` stops the run there as if the process had
//! died.  The command (file 4c) exits when `TASO_FAILPOINT` names the
//! point.
//!
//! # Resume by id (D48)
//!
//! [`Genesis::resume`] finishes a genesis from its id alone, once its
//! `GenesisStarted` is accepted: the source key, the map's key, the waiver
//! and the authority come from that record, the source artifact and the
//! map from the store, so the source need not exist any more.  Before
//! `GenesisStarted` is accepted the log does not name the source, and the
//! answer is [`GenesisError::NothingToResume`].  Every later record carries
//! the accepted `GenesisStarted`'s authority, whoever runs it.
//!
//! # Lsn 1 (D47)
//!
//! The first accepted record is `GenesisStarted`.  A holder lost after
//! appending its `GenesisStarted` and before shipping it takes lsn 1 with
//! it; the next holder continues after a Gap record and its own
//! `GenesisStarted` is the first accepted one.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 14, BLAKE3
//! `0d964e34a75a6c46cd3fcac21c752f863b1a6b431f325e1600e6a00cf1d30ba5`.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use taso_core::contract::{
    genesis_id, logical_id, submission_id, BornFrom, Consistency, ContractRecord, GenesisCleanedUp,
    GenesisRefused, GenesisStarted, LogicalKey, ObjectKind, PathClass, Peer, TemplateReady,
    WalkRefusal, TRANSFORM_VERSION,
};
use taso_core::coordlog::{Answer, ClaimAuthority, ClaimError, Final, Head, Submitted, Transient};
use taso_core::envelope::{ChronicleId, HashVal, Lsn, Stream};
use taso_core::model::WardenId;
use taso_core::record::{Authority, Payload};

use crate::artifact::{self, ArtifactError};
use crate::chronicle::{restore_log, Chronicle, ChronicleError, LayerError, Layers};
use crate::classify::{self, Classmap, Limits, Manifest, MapError, Owner, Reserved, Unsupported};
use crate::coordinator::{Coord, CoordError};
use crate::coordstore::object_key_path;
use crate::pack::{name_bounds, PackError, Packs};
use crate::segment::Position;
use crate::ship::{ByteStream, Sender, SharedStore};
use crate::vessel::Pool;
use crate::zfs::Dataset;

/// Domain of the synthetic Seal hash the scratch's layer is bound to.
pub const SCRATCH_DOMAIN: &str = "taso.genesis.scratch.v1";

/// The width of a uid slot (D44: a Seal's base is a whole slot above
/// `host_uid_base`).
const SLOT: u32 = classify::SLOT_WIDTH;

/// How often a `NotReadable` accept is retried before the run gives up
/// (the pack was put before the accept, so it is normally readable at
/// once; a store that lags gets a few tries).
const NOT_READABLE_TRIES: u32 = 5;

/// How many times a record is resubmitted after `HeadMoved` before the run
/// gives up (only this run writes the Chronicle, so the head moves only if
/// another Warden took it over).
const HEAD_MOVED_TRIES: u64 = 3;

// ── Inputs and outputs ──────────────────────────────────────────────

/// Where the tree comes from (§7 step 1, D40).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A Vessel's Seal, `<dataset>@<lsn>`: `consistency: Immutable`.
    Seal {
        /// The Vessel's dataset.
        dataset: Dataset,
        /// The Seal's lsn.
        lsn: Lsn,
    },
    /// A host directory, read as it is; only with
    /// [`Request::best_effort`] (`consistency: BestEffort`).
    Dir(PathBuf),
}

/// One genesis, as the command asks for it.
#[derive(Clone, Debug)]
pub struct Request {
    /// The tree.
    pub source: Source,
    /// The classification map's bytes, as given (D28).
    pub classmap: Vec<u8>,
    /// Who, and why (`--actor`, `--reason`).
    pub authority: Authority,
    /// `--hook-waiver <reason>`.
    pub hook_waiver: Option<String>,
    /// `--best-effort`: a directory source is allowed.
    pub best_effort: bool,
    /// This process (D46): it talks to no socket, so it names itself.
    pub peer: Peer,
}

/// How a genesis ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `TemplateReady` is accepted.
    Ready {
        /// The Template (= `genesis_id`).
        template_id: ChronicleId,
        /// Its layer: the artifact, by key.
        layer: HashVal,
        /// Its output manifest.
        output_manifest_key: HashVal,
    },
    /// `GenesisRefused` is accepted.
    Refused {
        /// The operation.
        genesis_id: ChronicleId,
        /// Why.
        reason: WalkRefusal,
        /// The input manifest, for diagnosis (D41).
        input_manifest_key: Option<HashVal>,
    },
}

/// What a run did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The operation (and the Template's id).
    pub genesis_id: ChronicleId,
    /// The source artifact's key.
    pub source_key: HashVal,
    /// The result, from accepted records.
    pub outcome: Outcome,
    /// Whether `GenesisCleanedUp` is accepted (always, unless the genesis
    /// was refused before a scratch existed).
    pub cleaned: bool,
    /// Things the operator is told: a takeover, a leftover scratch
    /// destroyed, an earlier run's record that stands.
    pub notes: Vec<String>,
}

/// Why a run stopped.  Every one leaves something the next run with the
/// same inputs finishes.
#[derive(Debug)]
pub enum GenesisError {
    /// A directory source without `--best-effort` (§7 step 1).
    SourceNotImmutable,
    /// A Seal whose top directory's owner is not a whole slot at or above
    /// `host_uid_base` with uid = gid (D44): its base cannot be told.
    SourceBase {
        /// The owner uid.
        uid: u32,
        /// The owner gid.
        gid: u32,
    },
    /// The classification map is refused (D28).
    Classmap(MapError),
    /// The source or the scratch could not be walked.
    Walk(io::Error),
    /// Writing or restoring an artifact failed.
    Artifact(ArtifactError),
    /// The store failed.
    Store(io::Error),
    /// An object in the store does not hash to its key: a store-integrity
    /// fault (§0.4); nothing more is done.
    Integrity(String),
    /// The pool failed.
    Pool(LayerError),
    /// A new dataset has no mountpoint to restore into.
    NoMountpoint(Dataset),
    /// The coordinator failed or refused.
    Coord(CoordError),
    /// The local log failed.
    Chronicle(ChronicleError),
    /// The packs failed.
    Pack(PackError),
    /// A submission can never be accepted, and not because another record
    /// stands for its logical id.
    Refused {
        /// The record kind.
        record: &'static str,
        /// The coordinator's reason.
        reason: Final,
    },
    /// A submission stayed transiently refused past the retries.
    NotAccepted {
        /// The record kind.
        record: &'static str,
        /// The last answer.
        last: Transient,
    },
    /// An accepted record does not agree with what this run derived
    /// (§5.3 step 5.3: compared, never assumed).
    Inconsistent(String),
    /// A failpoint stopped the run.
    Failpoint(&'static str),
    /// `--resume` of a genesis whose `GenesisStarted` is not accepted: the
    /// log does not name its source (D48).
    NothingToResume(ChronicleId),
}

impl fmt::Display for GenesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceNotImmutable => {
                f.write_str("a directory source needs --best-effort (SourceNotImmutable)")
            }
            Self::SourceBase { uid, gid } => write!(
                f,
                "the Seal's top directory is owned by {uid}:{gid}, not a whole slot above \
                 host_uid_base with uid = gid: its slot base cannot be told"
            ),
            Self::Classmap(e) => write!(f, "{e}"),
            Self::Walk(e) => write!(f, "walk: {e}"),
            Self::Artifact(e) => write!(f, "artifact: {e}"),
            Self::Store(e) => write!(f, "store: {e}"),
            Self::Integrity(p) => write!(f, "store integrity: {p} does not hash to its key"),
            Self::Pool(e) => write!(f, "pool: {e}"),
            Self::NoMountpoint(d) => write!(f, "{d} has no mountpoint"),
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Chronicle(e) => write!(f, "log: {e}"),
            Self::Pack(e) => write!(f, "packs: {e}"),
            Self::Refused { record, reason } => write!(f, "{record} refused: {reason:?}"),
            Self::NotAccepted { record, last } => {
                write!(f, "{record} not accepted: {last:?}")
            }
            Self::Inconsistent(why) => write!(f, "inconsistent: {why}"),
            Self::Failpoint(p) => write!(f, "failpoint {p}"),
            Self::NothingToResume(id) => write!(
                f,
                "nothing to resume: no GenesisStarted is accepted for {}; run it with its source",
                hex(id.as_bytes())
            ),
        }
    }
}

impl std::error::Error for GenesisError {}

impl From<CoordError> for GenesisError {
    fn from(e: CoordError) -> Self {
        Self::Coord(e)
    }
}

impl From<ChronicleError> for GenesisError {
    fn from(e: ChronicleError) -> Self {
        Self::Chronicle(e)
    }
}

impl From<PackError> for GenesisError {
    fn from(e: PackError) -> Self {
        Self::Pack(e)
    }
}

impl From<ArtifactError> for GenesisError {
    fn from(e: ArtifactError) -> Self {
        Self::Artifact(e)
    }
}

/// Called at each failpoint; an `Err` stops the run there.
pub type Failpoint = Box<dyn Fn(&'static str) -> Result<(), GenesisError> + Send + Sync>;

/// No failpoint stops anything.
pub fn no_failpoints() -> Failpoint {
    Box::new(|_| Ok(()))
}

// ── The genesis ─────────────────────────────────────────────────────

/// What a node runs a genesis with: its Warden's configuration (D40).
pub struct Genesis<P: Pool> {
    /// The node's storage.
    pub pool: P,
    /// The store.
    pub store: SharedStore,
    /// Key prefix in the store.
    pub prefix: String,
    /// The coordinator.
    pub coord: Arc<dyn Coord>,
    /// This node's Warden id.
    pub warden: WardenId,
    /// The Warden's state directory; the local log is under `genesis/`.
    pub state_dir: PathBuf,
    /// The parent dataset of every Vessel; the scratch is made under it.
    pub root: Dataset,
    /// `runtime.host_uid_base` (D44).
    pub host_uid_base: u32,
    /// `manifest.*` (§11.1).
    pub limits: Limits,
    /// `fs.reserved` (§11.1).
    pub reserved: Vec<Reserved>,
    /// The failpoint hook (§10.2).
    pub failpoint: Failpoint,
}

/// The fields of `GenesisStarted` a run derives before the log is asked.
struct Exported {
    source_key: HashVal,
    classmap_key: HashVal,
    consistency: Consistency,
}

/// What the steps after the export start from: a run's request, or an
/// accepted `GenesisStarted` (D48).
struct Inputs {
    exported: Exported,
    hook_waiver: Option<String>,
    authority: Authority,
    peer: Peer,
    /// The map, if this run read it; else it is read from the store.
    map: Option<Classmap>,
}

impl<P: Pool> Genesis<P> {
    /// The scratch dataset of `id` (§7 step 4).
    pub fn scratch(&self, id: ChronicleId) -> Result<Dataset, GenesisError> {
        Dataset::new(&format!("{}/genesis-{}", self.root, hex(id.as_bytes())))
            .map_err(|e| GenesisError::Pool(Box::new(e)))
    }

    /// The local log's directory of `id`.
    pub fn log_dir(&self, id: ChronicleId) -> PathBuf {
        self.state_dir.join("genesis").join(hex(id.as_bytes()))
    }

    /// Run the genesis `req` to its end, or as far as it gets; running it
    /// again with the same inputs resumes it (§7 step 8).
    pub fn run(&self, req: &Request) -> Result<Report, GenesisError> {
        let map = Classmap::parse(&req.classmap).map_err(GenesisError::Classmap)?;
        let exported = self.export(req, &map)?;
        (self.failpoint)("genesis.after_source_put")?;
        let gid = genesis_id(
            exported.source_key,
            exported.classmap_key,
            TRANSFORM_VERSION,
            req.hook_waiver.as_deref(),
            &req.authority.actor,
        );
        let source_key = exported.source_key;
        let inputs = Inputs {
            exported,
            hook_waiver: req.hook_waiver.clone(),
            authority: req.authority.clone(),
            peer: req.peer,
            map: Some(map),
        };
        let mut notes = Vec::new();
        let (outcome, cleaned) = self.finish(gid, &inputs, &mut notes)?;
        Ok(Report {
            genesis_id: gid,
            source_key,
            outcome,
            cleaned,
            notes,
        })
    }

    /// Resume the genesis `gid` from the log and the store alone (D48): its
    /// `GenesisStarted` must be accepted.
    pub fn resume(&self, gid: ChronicleId) -> Result<Report, GenesisError> {
        let Some((_, Submitted::Contract(ContractRecord::GenesisStarted(g)))) = self
            .coord
            .query_logical(logical_id(&LogicalKey::Genesis(gid)))?
        else {
            return Err(GenesisError::NothingToResume(gid));
        };
        let inputs = Inputs {
            exported: Exported {
                source_key: g.source_key,
                classmap_key: g.classmap_key,
                consistency: g.consistency,
            },
            hook_waiver: g.hook_waiver.clone(),
            authority: g.authority.clone(),
            peer: g.peer,
            map: None,
        };
        let mut notes = vec![format!(
            "resumed by id; the genesis was started by {:?} ({:?})",
            g.authority.actor, g.authority.reason
        )];
        let (outcome, cleaned) = self.finish(gid, &inputs, &mut notes)?;
        Ok(Report {
            genesis_id: gid,
            source_key: g.source_key,
            outcome,
            cleaned,
            notes,
        })
    }

    // ── 1. Export ───────────────────────────────────────────────────

    /// Walk the source, write and put the source artifact and the map.
    fn export(&self, req: &Request, map: &Classmap) -> Result<Exported, GenesisError> {
        let (view, root, owner, consistency) = match &req.source {
            Source::Dir(path) => {
                if !req.best_effort {
                    return Err(GenesisError::SourceNotImmutable);
                }
                (
                    None,
                    path.clone(),
                    Owner {
                        uid_base: 0,
                        gid_base: 0,
                    },
                    Consistency::BestEffort,
                )
            }
            Source::Seal { dataset, lsn } => {
                let view = self
                    .pool
                    .seal_view(dataset, *lsn)
                    .map_err(GenesisError::Pool)?;
                let path = view.path().to_path_buf();
                let base = self.seal_base(&path)?;
                (
                    Some(view),
                    path,
                    Owner {
                        uid_base: base,
                        gid_base: base,
                    },
                    Consistency::Immutable,
                )
            }
        };
        let manifest = classify::walk(&root, map, owner, &self.limits, &self.reserved)
            .map_err(GenesisError::Walk)?;
        let source_key = self.put_artifact(&root, &manifest, "source")?;
        drop(view);
        self.put_content(ObjectKind::Classmap, map.key(), &mut &req.classmap[..])?;
        Ok(Exported {
            source_key,
            classmap_key: map.key(),
            consistency,
        })
    }

    /// A Seal's slot base (D44): its top directory's owner, uid = gid, a
    /// whole number of slots at or above `host_uid_base`; never 0.
    fn seal_base(&self, top: &Path) -> Result<u32, GenesisError> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(top).map_err(GenesisError::Walk)?;
        let (uid, gid) = (m.uid(), m.gid());
        let aligned = uid
            .checked_sub(self.host_uid_base)
            .is_some_and(|off| off % SLOT == 0);
        if uid == gid && uid != 0 && aligned {
            Ok(uid)
        } else {
            Err(GenesisError::SourceBase { uid, gid })
        }
    }

    /// Write the archive of the tree at `root` (described by `manifest`) to
    /// a temporary file, then put it under its key.
    fn put_artifact(
        &self,
        root: &Path,
        manifest: &Manifest,
        what: &str,
    ) -> Result<HashVal, GenesisError> {
        let tmp_dir = self.state_dir.join("genesis").join("tmp");
        std::fs::create_dir_all(&tmp_dir).map_err(GenesisError::Store)?;
        let tmp = tmp_dir.join(format!("{what}-{}.part", std::process::id()));
        let written = (|| -> Result<HashVal, GenesisError> {
            let mut f = File::create(&tmp).map_err(GenesisError::Store)?;
            let (key, _) = artifact::write(root, manifest, &mut f)?;
            f.sync_all().map_err(GenesisError::Store)?;
            drop(f);
            let mut f = File::open(&tmp).map_err(GenesisError::Store)?;
            self.put_content(ObjectKind::Artifact, key, &mut f)?;
            Ok(key)
        })();
        let _ = std::fs::remove_file(&tmp);
        written
    }

    /// Put a content object (§0.4, D35): if the key is there, its bytes
    /// are read back and checked against the key instead (a mismatch is an
    /// integrity fault); otherwise `data` is put.
    fn put_content(
        &self,
        kind: ObjectKind,
        key: HashVal,
        data: &mut dyn Read,
    ) -> Result<(), GenesisError> {
        let path = object_key_path(&self.prefix, kind, key).expect("a content kind");
        if let Some(mut r) = self.store.get(&path).map_err(GenesisError::Store)? {
            let mut h = blake3::Hasher::new_derive_key(kind.prefix());
            io::copy(&mut r, &mut h).map_err(GenesisError::Store)?;
            if h.finalize().as_bytes() != key.as_bytes() {
                return Err(GenesisError::Integrity(path));
            }
            return Ok(());
        }
        self.store.put(&path, data).map_err(GenesisError::Store)?;
        Ok(())
    }

    /// A content object from the store.
    fn get_content(&self, kind: ObjectKind, key: HashVal) -> Result<ByteStream, GenesisError> {
        let path = object_key_path(&self.prefix, kind, key).expect("a content kind");
        self.store
            .get(&path)
            .map_err(GenesisError::Store)?
            .ok_or_else(|| {
                GenesisError::Store(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{path} is not in the store"),
                ))
            })
    }

    // ── 2–8. From the log ───────────────────────────────────────────

    /// Every step after the export, from what the log has accepted.
    /// Returns the outcome and whether the cleanup is accepted.
    fn finish(
        &self,
        gid: ChronicleId,
        inputs: &Inputs,
        notes: &mut Vec<String>,
    ) -> Result<(Outcome, bool), GenesisError> {
        let exported = &inputs.exported;
        let accepted = |key: LogicalKey| -> Result<Option<ContractRecord>, GenesisError> {
            Ok(match self.coord.query_logical(logical_id(&key))? {
                Some((_, Submitted::Contract(r))) => Some(r),
                Some((_, other)) => {
                    return Err(GenesisError::Inconsistent(format!(
                        "the log holds {other:?} under a genesis logical id"
                    )))
                }
                None => None,
            })
        };
        let started = accepted(LogicalKey::Genesis(gid))?;
        let ready = accepted(LogicalKey::Template(gid))?;
        let refused = accepted(LogicalKey::GenesisRefused(gid))?;
        let cleaned = accepted(LogicalKey::GenesisCleaned(gid))?.is_some();

        let scratch = self.scratch(gid)?;
        // What is already decided, if anything.
        let decided = match (&ready, &refused) {
            (Some(ContractRecord::TemplateReady(t)), _) => Some((ready_outcome(t), true)),
            (_, Some(ContractRecord::GenesisRefused(r))) => Some((
                refused_outcome(r),
                r.reason == WalkRefusal::MaterialisationMismatch,
            )),
            (None, None) => None,
            _ => {
                return Err(GenesisError::Inconsistent(
                    "an accepted record of another kind under a genesis logical id".into(),
                ))
            }
        };
        if let Some((outcome, needs_cleanup)) = &decided {
            if cleaned || !needs_cleanup {
                return Ok((outcome.clone(), cleaned));
            }
        }

        let mut run = self.open(gid, started.is_some(), notes)?;

        if decided.is_none() {
            // 3. GenesisStarted.
            let started = match started {
                Some(ContractRecord::GenesisStarted(g)) => *g,
                Some(_) => unreachable!("the Genesis row holds GenesisStarted"),
                None => {
                    let g = GenesisStarted {
                        genesis_id: gid,
                        source_key: exported.source_key,
                        consistency: exported.consistency,
                        classmap_key: exported.classmap_key,
                        transform_version: TRANSFORM_VERSION,
                        hook_waiver: inputs.hook_waiver.clone(),
                        authority: inputs.authority.clone(),
                        peer: inputs.peer,
                    };
                    let got = run.submit(
                        ContractRecord::GenesisStarted(Box::new(g)),
                        Some("genesis.before_started_accept"),
                    )?;
                    let ContractRecord::GenesisStarted(a) = got else {
                        unreachable!("the Genesis row holds GenesisStarted")
                    };
                    (self.failpoint)("genesis.after_started_accept")?;
                    *a
                }
            };
            if started.source_key != exported.source_key
                || started.classmap_key != exported.classmap_key
            {
                return Err(GenesisError::Inconsistent(
                    "the accepted GenesisStarted names another source or map".into(),
                ));
            }
            if started.authority != inputs.authority {
                notes.push(format!(
                    "the genesis was started with reason {:?}; its records carry that one",
                    started.authority.reason
                ));
            }
            // 4.–7.
            let outcome = self.judge_and_publish(
                &mut run,
                gid,
                &started,
                inputs.map.as_ref(),
                &scratch,
                notes,
            )?;
            if let Outcome::Refused { reason, .. } = &outcome {
                if *reason != WalkRefusal::MaterialisationMismatch {
                    return Ok((outcome, false));
                }
            }
            // 8.
            self.cleanup(&mut run, gid, &scratch)?;
            return Ok((outcome, true));
        }

        // Decided, not yet cleaned up.
        let (outcome, _) = decided.expect("checked");
        self.cleanup(&mut run, gid, &scratch)?;
        Ok((outcome, true))
    }

    /// Claim the genesis Chronicle, or take it over (D42), and open its
    /// local log, rebuilt from the packs if this node does not have it.
    fn open(
        &self,
        gid: ChronicleId,
        started: bool,
        notes: &mut Vec<String>,
    ) -> Result<Run<'_, P>, GenesisError> {
        let dir = self.log_dir(gid);
        let mut took_over = false;
        match self
            .coord
            .claim_chronicle(gid, self.warden, ClaimAuthority::Genesis)
        {
            Ok(_) => {}
            Err(CoordError::AlreadyRegistered(_))
            | Err(CoordError::Claim(ClaimError::AlreadyClaimed { .. })) => {
                let own = self.coord.ownership(gid)?;
                if own.holder != self.warden {
                    let authority = if started {
                        ClaimAuthority::GenesisStarted
                    } else {
                        ClaimAuthority::Genesis
                    };
                    let (epoch, _) =
                        self.coord
                            .takeover_target(gid, self.warden, authority, own.epoch)?;
                    notes.push(format!(
                        "took the genesis over from warden {} (epoch {} → {}, authority {authority:?})",
                        own.holder.get(),
                        own.epoch.get(),
                        epoch.get()
                    ));
                    took_over = true;
                }
            }
            Err(e) => return Err(e.into()),
        }
        let packs = self.packs(gid)?;
        let anchor = self.coord.shipped(gid)?;
        if took_over && dir.exists() && !has_position(&dir, anchor)? {
            // This node's log is an older holder's and does not reach what
            // was shipped since: keep it aside, rebuild from the packs.
            let aside = dir.with_extension(format!("superseded-{}", std::process::id()));
            std::fs::rename(&dir, &aside).map_err(GenesisError::Store)?;
            notes.push(format!(
                "this node's log of the genesis was behind the shipped anchor; kept at {}",
                aside.display()
            ));
        }
        if !dir.exists() {
            let frames = if anchor.lsn > Lsn::new(0) {
                packs.chain(Some(anchor))?.frames
            } else {
                Vec::new()
            };
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent).map_err(GenesisError::Store)?;
            }
            restore_log(&dir, gid, &frames)?;
        }
        let (chronicle, recovery) =
            Chronicle::open_after_gap(&dir, self.coord.clone(), gid, self.warden, NoLayers)?;
        if let Some((kept, resumes)) = recovery.gap {
            notes.push(format!(
                "records {}..{} of the genesis log were lost with an earlier holder (Gap)",
                kept.lsn.get() + 1,
                resumes.lsn.get()
            ));
        }
        Ok(Run {
            g: self,
            chronicle,
            packs,
            attempt: 0,
        })
    }

    fn packs(&self, gid: ChronicleId) -> Result<Packs<SharedStore, NoSend>, GenesisError> {
        Packs::new(self.store.clone(), NoSend, &self.prefix, gid).map_err(GenesisError::Store)
    }

    /// The map `GenesisStarted` names, from the store (D48).
    fn stored_map(&self, key: HashVal) -> Result<Classmap, GenesisError> {
        let mut bytes = Vec::new();
        self.get_content(ObjectKind::Classmap, key)?
            .read_to_end(&mut bytes)
            .map_err(GenesisError::Store)?;
        let map = Classmap::parse(&bytes).map_err(GenesisError::Classmap)?;
        if map.key() != key {
            return Err(GenesisError::Integrity(
                object_key_path(&self.prefix, ObjectKind::Classmap, key).expect("a content kind"),
            ));
        }
        Ok(map)
    }

    /// Steps 4–7: judge, materialise, export, publish, from the accepted
    /// `GenesisStarted` `g`.
    fn judge_and_publish(
        &self,
        run: &mut Run<'_, P>,
        gid: ChronicleId,
        g: &GenesisStarted,
        map: Option<&Classmap>,
        scratch: &Dataset,
        notes: &mut Vec<String>,
    ) -> Result<Outcome, GenesisError> {
        // 4. Judge, from the source artifact in the store.
        let input = {
            let mut r = self.get_content(ObjectKind::Artifact, g.source_key)?;
            artifact::read_manifest(&mut r)?
        };
        let input_key = input.key();
        self.put_content(ObjectKind::Manifest, input_key, &mut &input.bytes()[..])?;
        if let Some(reason) = judge(&input, g.hook_waiver.is_some()) {
            return self.refuse(run, gid, reason, input_key);
        }
        let stored;
        let map = match map {
            Some(m) => m,
            None => {
                stored = self.stored_map(g.classmap_key)?;
                &stored
            }
        };

        // 5. Materialise.  Nothing is excluded: the output manifest is the
        //    input manifest, the same object.
        let output = input;
        let output_key = input_key;
        if let Some(old) = self.pool.guid(scratch).map_err(GenesisError::Pool)? {
            self.pool
                .destroy(scratch, old)
                .map_err(GenesisError::Pool)?;
            notes.push(format!(
                "destroyed the scratch {scratch} (guid {old}) an interrupted run left"
            ));
        }
        let info = self.pool.create(scratch).map_err(GenesisError::Pool)?;
        let mount = info
            .mountpoint
            .ok_or_else(|| GenesisError::NoMountpoint(scratch.clone()))?;
        {
            let mut r = self.get_content(ObjectKind::Artifact, g.source_key)?;
            artifact::restore(
                &mut r,
                &mount,
                Owner {
                    uid_base: 0,
                    gid_base: 0,
                },
                &self.reserved,
                Some(g.source_key),
            )?;
        }
        let seal = Lsn::new(1);
        let mut layers = self.pool.layers(scratch);
        layers
            .snapshot(seal, scratch_hash(gid))
            .map_err(GenesisError::Pool)?;
        let view = self
            .pool
            .seal_view(scratch, seal)
            .map_err(GenesisError::Pool)?;
        let walked = classify::walk(
            view.path(),
            map,
            Owner {
                uid_base: 0,
                gid_base: 0,
            },
            &self.limits,
            &self.reserved,
        )
        .map_err(GenesisError::Walk)?;
        (self.failpoint)("genesis.after_materialise")?;
        if !same_entries(&walked, &output) {
            drop(view);
            return self.refuse(run, gid, WalkRefusal::MaterialisationMismatch, input_key);
        }

        // 6. The artifact, from the sealed output.
        let layer = self.put_artifact(view.path(), &output, "output")?;
        drop(view);
        (self.failpoint)("genesis.after_artifact_put")?;

        // 7. Publish.
        let t = TemplateReady {
            template_id: gid,
            parent_template: None,
            born_from: BornFrom::Genesis { genesis_id: gid },
            layer,
            output_manifest_key: output_key,
            classmap_key: g.classmap_key,
            vconf_key: None,
            authority: g.authority.clone(),
        };
        let got = run.submit(
            ContractRecord::TemplateReady(Box::new(t.clone())),
            Some("genesis.before_ready_accept"),
        )?;
        let ContractRecord::TemplateReady(a) = &got else {
            unreachable!("the Template row holds TemplateReady")
        };
        if a.born_from != t.born_from || a.layer != t.layer {
            return Err(GenesisError::Inconsistent(format!(
                "the accepted TemplateReady has layer {:?}, this run made {:?}",
                a.layer, t.layer
            )));
        }
        if **a != t {
            notes.push("an earlier run's TemplateReady stands (same layer)".into());
        }
        (self.failpoint)("genesis.after_ready_accept")?;
        Ok(ready_outcome(a))
    }

    /// Accept `GenesisRefused` (§7 step 4, D41, D45).
    fn refuse(
        &self,
        run: &mut Run<'_, P>,
        gid: ChronicleId,
        reason: WalkRefusal,
        input_key: HashVal,
    ) -> Result<Outcome, GenesisError> {
        let got = run.submit(
            ContractRecord::GenesisRefused(GenesisRefused {
                genesis_id: gid,
                reason,
                input_manifest_key: Some(input_key),
            }),
            None,
        )?;
        let ContractRecord::GenesisRefused(r) = got else {
            unreachable!("the GenesisRefused row holds GenesisRefused")
        };
        Ok(refused_outcome(&r))
    }

    /// Step 8: write `GenesisCleanedUp` locally with the scratch's guid,
    /// destroy the scratch by that guid, accept the record.
    fn cleanup(
        &self,
        run: &mut Run<'_, P>,
        gid: ChronicleId,
        scratch: &Dataset,
    ) -> Result<(), GenesisError> {
        (self.failpoint)("genesis.before_cleanup")?;
        let guid = self.pool.guid(scratch).map_err(GenesisError::Pool)?;
        let rec = run.prepare(ContractRecord::GenesisCleanedUp(GenesisCleanedUp {
            genesis_id: gid,
            scratch_guid: guid,
        }))?;
        // The guid the log will carry: this run's, or an earlier run's that
        // wrote the record and may have destroyed the scratch already.
        let ContractRecord::GenesisCleanedUp(c) = &rec else {
            unreachable!("prepared as GenesisCleanedUp")
        };
        if let Some(g) = c.scratch_guid {
            match self.pool.guid(scratch).map_err(GenesisError::Pool)? {
                Some(now) if now == g => {
                    self.pool.destroy(scratch, g).map_err(GenesisError::Pool)?;
                }
                Some(now) => {
                    return Err(GenesisError::Inconsistent(format!(
                        "{scratch} is guid {now}, the cleanup record names {g}"
                    )))
                }
                None => {}
            }
        }
        run.submit(rec, None)?;
        Ok(())
    }
}

/// The refusal, if any, of an input manifest (§7 step 4), in the order
/// the module docs give.
pub fn judge(m: &Manifest, hook_waived: bool) -> Option<WalkRefusal> {
    if !m.complete() {
        return Some(WalkRefusal::IncompleteWalk);
    }
    if !m.unsupported.is_empty() {
        return Some(
            if m.unsupported
                .iter()
                .any(|(_, u)| *u == Unsupported::ReservedMismatch)
            {
                WalkRefusal::ReservedMismatch
            } else {
                WalkRefusal::Unsupported
            },
        );
    }
    let c = m.counts();
    if c.secret > 0 {
        return Some(WalkRefusal::SecretPaths);
    }
    if c.unknown > 0 {
        return Some(WalkRefusal::UnknownPaths);
    }
    if c.hook > 0 && !hook_waived {
        return Some(WalkRefusal::HookNotWaived);
    }
    debug_assert!(m.entries.iter().all(|e| e.class != PathClass::Structural));
    None
}

/// §4.1.7: the output walk equals the output manifest entry for entry
/// (reserved entries are verified by the walk itself, not listed).
fn same_entries(walked: &Manifest, output: &Manifest) -> bool {
    walked.complete() && walked.unsupported.is_empty() && walked.entries == output.entries
}

/// The synthetic Seal hash of the scratch's layer.
pub fn scratch_hash(gid: ChronicleId) -> HashVal {
    HashVal::from_bytes(blake3::derive_key(SCRATCH_DOMAIN, gid.as_bytes()))
}

fn ready_outcome(t: &TemplateReady) -> Outcome {
    Outcome::Ready {
        template_id: t.template_id,
        layer: t.layer,
        output_manifest_key: t.output_manifest_key,
    }
}

fn refused_outcome(r: &GenesisRefused) -> Outcome {
    Outcome::Refused {
        genesis_id: r.genesis_id,
        reason: r.reason,
        input_manifest_key: r.input_manifest_key,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether the local log at `dir` holds `pos` (genesis always).
fn has_position(dir: &Path, pos: Position) -> Result<bool, GenesisError> {
    if pos.lsn == Lsn::new(0) {
        return Ok(true);
    }
    let frames = crate::chronicle::read_log(dir)?;
    Ok(frames
        .iter()
        .any(|f| f.envelope.lsn == pos.lsn && f.envelope.hash == pos.hash))
}

// ── One open genesis Chronicle ──────────────────────────────────────

/// The genesis Chronicle, open under this run's epoch.
struct Run<'a, P: Pool> {
    g: &'a Genesis<P>,
    chronicle: Chronicle<NoLayers>,
    packs: Packs<SharedStore, NoSend>,
    /// Submissions made under this epoch (`attempt_no`, §9).
    attempt: u64,
}

impl<P: Pool> Run<'_, P> {
    /// Append `rec` to the local log unless a frame with its logical id is
    /// there already (an earlier run's); returns the record the log holds.
    fn prepare(&mut self, rec: ContractRecord) -> Result<ContractRecord, GenesisError> {
        let logical = rec.logical_id();
        for f in self.chronicle.frames().map_err(ChronicleError::from)? {
            if f.envelope.stream != Stream::Ctl {
                continue;
            }
            if let Ok(Payload::Contract(r)) = Payload::decode(&f.payload) {
                if r.logical_id() == logical {
                    return Ok(*r);
                }
            }
        }
        self.chronicle
            .append(Stream::Ctl, Payload::Contract(Box::new(rec.clone())))?;
        Ok(rec)
    }

    /// The local lsn of the frame carrying `digest`.
    fn lsn_of(&self, digest: HashVal) -> Result<Lsn, GenesisError> {
        for f in self.chronicle.frames().map_err(ChronicleError::from)? {
            if let Ok(Payload::Contract(r)) = Payload::decode(&f.payload) {
                if r.digest() == digest {
                    return Ok(f.envelope.lsn);
                }
            }
        }
        Err(GenesisError::Inconsistent(
            "a prepared record is not in the local log".into(),
        ))
    }

    /// Ship the log to its tail and advance the anchor; the name of a log
    /// pack carrying `lsn`.
    fn ship(&mut self, lsn: Lsn) -> Result<String, GenesisError> {
        let tail = self.chronicle.tail();
        self.packs.ship_log(&self.chronicle.segments(), tail)?;
        self.g.coord.advance_shipped(
            self.g.warden,
            self.chronicle.id(),
            self.chronicle.epoch(),
            tail,
        )?;
        self.packs
            .pack_names()?
            .into_iter()
            .find(|n| {
                name_bounds(n)
                    .is_some_and(|(end, base, fs)| fs.is_none() && base < lsn && lsn <= end)
            })
            .ok_or_else(|| {
                GenesisError::Inconsistent(format!("no shipped pack carries lsn {}", lsn.get()))
            })
    }

    /// Submit `rec` (see the module docs): the record accepted for its
    /// logical id, this one or another.  `failpoint` is called just before
    /// the first accept.
    fn submit(
        &mut self,
        rec: ContractRecord,
        failpoint: Option<&'static str>,
    ) -> Result<ContractRecord, GenesisError> {
        let what = kind(&rec);
        let logical = rec.logical_id();
        if let Some(r) = self.accepted(logical)? {
            return Ok(r);
        }
        let rec = self.prepare(rec)?;
        let digest = rec.digest();
        let lsn = self.lsn_of(digest)?;
        let pack = self.ship(lsn)?;
        let (id, epoch) = (self.chronicle.id(), self.chronicle.epoch());
        let coord = &self.g.coord;
        let mut failpoint = failpoint;
        for _ in 0..HEAD_MOVED_TRIES {
            let sub = submission_id(logical, digest, epoch, self.attempt);
            self.attempt += 1;
            if let Err(a) = coord.announce(self.g.warden, id, epoch, sub, logical, digest)? {
                return self.final_answer(what, logical, a);
            }
            if let Some(p) = failpoint.take() {
                (self.g.failpoint)(p)?;
            }
            let mut tries = 0;
            loop {
                let head = coord.query_chronicle(id)?.map_or(Head::EMPTY, |v| v.head);
                let answer = coord.accept(
                    self.g.warden,
                    id,
                    epoch,
                    sub,
                    head,
                    pack.clone(),
                    Submitted::Contract(rec.clone()),
                )?;
                match answer {
                    Answer::Accepted { .. } | Answer::AlreadyAccepted { .. } => {
                        return self.accepted(logical)?.ok_or_else(|| {
                            GenesisError::Inconsistent(format!(
                                "{what} answered accepted, but the log does not have it"
                            ))
                        });
                    }
                    Answer::Refused(Transient::NotReadable) if tries + 1 < NOT_READABLE_TRIES => {
                        tries += 1;
                        std::thread::sleep(std::time::Duration::from_millis(200 << tries));
                    }
                    Answer::Refused(Transient::HeadMoved { .. }) => {
                        coord.cancel(self.g.warden, id, epoch, sub)?;
                        break;
                    }
                    Answer::Refused(last) => {
                        let _ = coord.cancel(self.g.warden, id, epoch, sub);
                        return Err(GenesisError::NotAccepted { record: what, last });
                    }
                    Answer::FinalRefused(_) => {
                        return self.final_answer(what, logical, answer);
                    }
                }
            }
        }
        Err(GenesisError::NotAccepted {
            record: what,
            last: Transient::HeadMoved {
                head: coord.query_chronicle(id)?.map_or(Head::EMPTY, |v| v.head),
            },
        })
    }

    /// A final answer: a `Conflict` returns the accepted record; anything
    /// else stops the run.
    fn final_answer(
        &self,
        what: &'static str,
        logical: HashVal,
        a: Answer,
    ) -> Result<ContractRecord, GenesisError> {
        match a {
            Answer::FinalRefused(Final::Conflict) => self.accepted(logical)?.ok_or_else(|| {
                GenesisError::Inconsistent(format!("{what}: Conflict, but nothing is accepted"))
            }),
            Answer::Accepted { .. } | Answer::AlreadyAccepted { .. } => self
                .accepted(logical)?
                .ok_or_else(|| GenesisError::Inconsistent(format!("{what}: not in the log"))),
            Answer::FinalRefused(reason) => Err(GenesisError::Refused {
                record: what,
                reason,
            }),
            Answer::Refused(last) => Err(GenesisError::NotAccepted { record: what, last }),
        }
    }

    fn accepted(&self, logical: HashVal) -> Result<Option<ContractRecord>, GenesisError> {
        Ok(match self.g.coord.query_logical(logical)? {
            Some((_, Submitted::Contract(r))) => Some(r),
            Some(_) => {
                return Err(GenesisError::Inconsistent(
                    "a Birth under a genesis logical id".into(),
                ))
            }
            None => None,
        })
    }
}

fn kind(r: &ContractRecord) -> &'static str {
    match r {
        ContractRecord::GenesisStarted(_) => "GenesisStarted",
        ContractRecord::GenesisRefused(_) => "GenesisRefused",
        ContractRecord::TemplateReady(_) => "TemplateReady",
        ContractRecord::GenesisCleanedUp(_) => "GenesisCleanedUp",
        _ => "record",
    }
}

// ── Plumbing ────────────────────────────────────────────────────────

/// The genesis Chronicle has no Seals: its layers are none.
struct NoLayers;

impl Layers for NoLayers {
    fn snapshot(&mut self, lsn: Lsn, _: HashVal) -> Result<(), LayerError> {
        Err(format!("a genesis Chronicle has no Seal layers (lsn {})", lsn.get()).into())
    }
    fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError> {
        Ok(Vec::new())
    }
    fn destroy(&mut self, _: Lsn) -> Result<(), LayerError> {
        Ok(())
    }
}

/// Genesis ships logs only: no `fs` stream is ever produced.
struct NoSend;

impl Sender for NoSend {
    fn send(&self, _: &Dataset, _: Option<&str>, _: Lsn) -> io::Result<ByteStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a genesis ships no fs stream",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    use crate::chronicle::read_log;
    use crate::coordinator::{Coordinator, LogConfig};
    use crate::coordstore::CoordStore;
    use crate::ship::{LocalStore, ObjectStore, Sender};
    use crate::vessel::SealView;
    use crate::zfs::{CloneBase, DatasetInfo};

    const PREFIX: &str = "taso";
    const BASE: u32 = 200_000;

    // ── A directory-backed pool ─────────────────────────────────────
    //
    // A dataset is a directory; a Seal layer is a `cp -a` copy of it with
    // its hash beside it; a Seal view is that copy; a guid is a counter.
    // `mangle` adds a stray file to every genesis scratch layer, so the
    // walk of the sealed output differs from its manifest (D45).

    #[derive(Default)]
    struct DirState {
        guids: BTreeMap<String, u64>,
        next: u64,
        destroyed: Vec<(String, u64)>,
    }

    #[derive(Clone)]
    struct DirPool {
        root: PathBuf,
        state: Arc<Mutex<DirState>>,
        mangle: bool,
    }

    impl DirPool {
        fn new(root: &Path) -> Self {
            Self {
                root: root.to_path_buf(),
                state: Arc::default(),
                mangle: false,
            }
        }
        fn data(&self, d: &Dataset) -> PathBuf {
            self.root.join("data").join(d.as_str())
        }
        fn snaps(&self, d: &Dataset) -> PathBuf {
            self.root.join("snap").join(d.as_str())
        }
        /// Make a dataset by hand (a Vessel's), with a guid.
        fn make(&self, d: &Dataset) -> PathBuf {
            Pool::create(self, d).unwrap();
            self.data(d)
        }
    }

    struct DirLayers {
        data: PathBuf,
        snaps: PathBuf,
        mangle: bool,
    }

    impl Layers for DirLayers {
        fn snapshot(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
            std::fs::create_dir_all(&self.snaps)?;
            let to = self.snaps.join(lsn.get().to_string());
            if to.exists() {
                return Err("layer exists".into());
            }
            let ok = std::process::Command::new("cp")
                .arg("-a")
                .arg(&self.data)
                .arg(&to)
                .status()?
                .success();
            if !ok {
                return Err("cp -a failed".into());
            }
            std::fs::write(to.with_extension("hash"), hash.as_bytes())?;
            if self.mangle {
                std::fs::write(to.join("stray"), b"not in the manifest")?;
            }
            Ok(())
        }
        fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError> {
            let mut out = Vec::new();
            let Ok(rd) = std::fs::read_dir(&self.snaps) else {
                return Ok(out);
            };
            for e in rd {
                let p = e?.path();
                if p.extension().is_some() {
                    continue;
                }
                let lsn: u64 = p.file_name().unwrap().to_str().unwrap().parse()?;
                let h: [u8; 32] = std::fs::read(p.with_extension("hash"))?
                    .try_into()
                    .map_err(|_| "bad hash")?;
                out.push((Lsn::new(lsn), HashVal::from_bytes(h)));
            }
            out.sort_by_key(|(l, _)| *l);
            Ok(out)
        }
        fn destroy(&mut self, lsn: Lsn) -> Result<(), LayerError> {
            let p = self.snaps.join(lsn.get().to_string());
            let _ = std::fs::remove_dir_all(&p);
            let _ = std::fs::remove_file(p.with_extension("hash"));
            Ok(())
        }
    }

    fn unsupported<T>() -> Result<T, LayerError> {
        Err("not in the test pool".into())
    }

    impl Pool for DirPool {
        type Layers = DirLayers;
        fn create(&self, d: &Dataset) -> Result<DatasetInfo, LayerError> {
            let p = self.data(d);
            if p.exists() {
                return Err(format!("{d} exists").into());
            }
            std::fs::create_dir_all(&p)?;
            let mut s = self.state.lock().unwrap();
            s.next += 1;
            let g = 1000 + s.next;
            s.guids.insert(d.as_str().into(), g);
            Ok(DatasetInfo {
                dataset: d.clone(),
                mountpoint: Some(p),
                origin: None,
                parent: None,
            })
        }
        fn clone(
            &self,
            _: &Dataset,
            _: Lsn,
            _: HashVal,
            _: &Dataset,
        ) -> Result<DatasetInfo, LayerError> {
            unsupported()
        }
        fn info(&self, d: &Dataset) -> Result<Option<DatasetInfo>, LayerError> {
            let p = self.data(d);
            Ok(p.exists().then(|| DatasetInfo {
                dataset: d.clone(),
                mountpoint: Some(p),
                origin: None,
                parent: None,
            }))
        }
        fn layers(&self, d: &Dataset) -> DirLayers {
            DirLayers {
                data: self.data(d),
                snaps: self.snaps(d),
                mangle: self.mangle && d.as_str().contains("/genesis-"),
            }
        }
        fn receive(
            &self,
            _: &Dataset,
            _: Option<(Lsn, HashVal)>,
            _: (Lsn, HashVal),
            _: &mut dyn Read,
        ) -> Result<u64, LayerError> {
            unsupported()
        }
        fn adopt(
            &self,
            _: &Dataset,
            _: (Lsn, HashVal),
            _: (Lsn, HashVal),
            _: &Dataset,
            _: Lsn,
            _: &dyn Sender,
        ) -> Result<u64, LayerError> {
            unsupported()
        }
        fn receive_clone(
            &self,
            _: &Dataset,
            _: &CloneBase,
            _: (Lsn, HashVal),
            _: &mut dyn Read,
        ) -> Result<u64, LayerError> {
            unsupported()
        }
        fn seal_view(&self, d: &Dataset, lsn: Lsn) -> Result<SealView, LayerError> {
            let p = self.snaps(d).join(lsn.get().to_string());
            if !p.exists() {
                return Err(format!("no layer {d}@{}", lsn.get()).into());
            }
            Ok(SealView::new(p, None))
        }
        fn guid(&self, d: &Dataset) -> Result<Option<u64>, LayerError> {
            Ok(self.state.lock().unwrap().guids.get(d.as_str()).copied())
        }
        fn destroy(&self, d: &Dataset, guid: u64) -> Result<bool, LayerError> {
            let mut s = self.state.lock().unwrap();
            match s.guids.get(d.as_str()) {
                None => return Ok(false),
                Some(&g) if g != guid => return Err(format!("{d} is {g}, not {guid}").into()),
                Some(_) => {}
            }
            s.guids.remove(d.as_str());
            s.destroyed.push((d.as_str().into(), guid));
            std::fs::remove_dir_all(self.data(d))?;
            let _ = std::fs::remove_dir_all(self.snaps(d));
            Ok(true)
        }
    }

    // ── A cluster: one coordinator and store, nodes beside it ───────

    struct Cluster {
        dir: tempfile::TempDir,
        store: SharedStore,
        coord: Arc<Coordinator>,
    }

    impl Cluster {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("store")).unwrap();
            let store: SharedStore = Arc::new(LocalStore::new(dir.path().join("store")));
            let coord = Arc::new(
                Coordinator::open_with(
                    dir.path().join("coord.redb"),
                    LogConfig {
                        store: Arc::new(CoordStore::new(store.clone(), PREFIX)),
                        ..LogConfig::default()
                    },
                )
                .unwrap(),
            );
            Self { dir, store, coord }
        }

        /// Node `n`: Warden `n`, its own pool and state directory.
        fn node(&self, n: u64) -> Genesis<DirPool> {
            let at = self.dir.path().join(format!("node{n}"));
            std::fs::create_dir_all(at.join("pool")).unwrap();
            Genesis {
                pool: DirPool::new(&at.join("pool")),
                store: self.store.clone(),
                prefix: PREFIX.into(),
                coord: self.coord.clone(),
                warden: WardenId::new(n),
                state_dir: at.join("state"),
                root: Dataset::new("tank/taso").unwrap(),
                host_uid_base: BASE,
                limits: Limits::default(),
                reserved: Reserved::defaults(),
                failpoint: no_failpoints(),
            }
        }

        /// Lose node `n`: its pool and its state directory are gone.
        fn lose(&self, n: u64) {
            std::fs::remove_dir_all(self.dir.path().join(format!("node{n}"))).unwrap();
        }

        fn src(&self) -> PathBuf {
            self.dir.path().join("src")
        }
    }

    // ── Trees ───────────────────────────────────────────────────────

    const MAP: &str = r#"
version = 1
[[rule]]
glob = "**"
class = "Source"
[[rule]]
glob = "etc/"
class = "Config"
[[rule]]
glob = "hooks/"
class = "Hook"
[[rule]]
glob = "**/*.key"
class = "Secret"
[[rule]]
glob = "odd/"
class = "Source"
[[rule]]
glob = "odd/"
class = "Scratch"
"#;

    const T: SystemTime = SystemTime::UNIX_EPOCH;

    fn at(secs: u64) -> SystemTime {
        T + Duration::from_secs(secs)
    }

    fn file(root: &Path, rel: &str, body: &[u8], owner: u32) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        std::os::unix::fs::chown(&p, Some(owner), Some(owner)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(at(1_700_000_000))
            .unwrap();
    }

    /// Fix every directory's owner and mtime, deepest first (a file
    /// written into a directory moves its mtime).
    fn settle(root: &Path, owner: u32) {
        let mut dirs = vec![root.to_path_buf()];
        let mut i = 0;
        while i < dirs.len() {
            for e in std::fs::read_dir(&dirs[i]).unwrap() {
                let e = e.unwrap();
                if e.file_type().unwrap().is_dir() {
                    dirs.push(e.path());
                }
            }
            i += 1;
        }
        for d in dirs.iter().rev() {
            std::os::unix::fs::chown(d, Some(owner), Some(owner)).unwrap();
            File::open(d)
                .unwrap()
                .set_modified(at(1_600_000_000))
                .unwrap();
        }
    }

    /// A tree the map classifies completely: sources and config.
    fn good_tree(root: &Path, owner: u32) {
        file(root, "app/main.py", b"print('hello')\n", owner);
        file(root, "app/lib/util.py", b"X = 1\n", owner);
        file(root, "etc/app.toml", b"debug = false\n", owner);
        std::os::unix::fs::symlink("app/main.py", root.join("main")).unwrap();
        std::os::unix::fs::lchown(root.join("main"), Some(owner), Some(owner)).unwrap();
        let t = rustix::fs::Timespec {
            tv_sec: 1_650_000_000,
            tv_nsec: 0,
        };
        rustix::fs::utimensat(
            rustix::fs::CWD,
            root.join("main"),
            &rustix::fs::Timestamps {
                last_access: t,
                last_modification: t,
            },
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
        settle(root, owner);
    }

    fn request(source: Source) -> Request {
        Request {
            source,
            classmap: MAP.as_bytes().to_vec(),
            authority: Authority {
                actor: "jarmo".into(),
                reason: "T(0)".into(),
            },
            hook_waiver: None,
            best_effort: true,
            peer: Peer { uid: 0, pid: 4242 },
        }
    }

    fn dir_request(c: &Cluster) -> Request {
        request(Source::Dir(c.src()))
    }

    fn fail_at(name: &'static str) -> Failpoint {
        Box::new(move |p| {
            if p == name {
                Err(GenesisError::Failpoint(p))
            } else {
                Ok(())
            }
        })
    }

    // ── Reading the result back ─────────────────────────────────────

    fn accepted(c: &Cluster, key: LogicalKey) -> Option<ContractRecord> {
        match c.coord.query_logical(logical_id(&key)).unwrap() {
            Some((_, Submitted::Contract(r))) => Some(r),
            None => None,
            other => panic!("{other:?}"),
        }
    }

    /// The genesis Chronicle's accepted records, in log order.
    fn records(c: &Cluster, gid: ChronicleId) -> Vec<&'static str> {
        let v = c.coord.query_chronicle(gid).unwrap().unwrap();
        let mut out = Vec::new();
        for (key, name) in [
            (LogicalKey::Genesis(gid), "GenesisStarted"),
            (LogicalKey::GenesisRefused(gid), "GenesisRefused"),
            (LogicalKey::Template(gid), "TemplateReady"),
            (LogicalKey::GenesisCleaned(gid), "GenesisCleanedUp"),
        ] {
            if let Some((pos, _)) = c.coord.query_logical(logical_id(&key)).unwrap() {
                assert!(v.accepted.contains(&pos));
                out.push((pos, name));
            }
        }
        out.sort();
        assert_eq!(out.len(), v.accepted.len(), "no other record in it");
        out.into_iter().map(|(_, n)| n).collect()
    }

    /// The shipped chain of the genesis Chronicle: lsn 1 is GenesisStarted,
    /// and no Lineage record anywhere (D46).
    fn check_chain(c: &Cluster, gid: ChronicleId) {
        let packs = Packs::new(c.store.clone(), NoSend, PREFIX, gid).unwrap();
        let chain = packs.chain(Some(c.coord.shipped(gid).unwrap())).unwrap();
        let kinds: Vec<Payload> = chain
            .frames
            .iter()
            .map(|f| Payload::decode(&f.payload).unwrap())
            .collect();
        assert!(matches!(
            kinds.first(),
            Some(Payload::Contract(r)) if matches!(**r, ContractRecord::GenesisStarted(_))
        ));
        assert!(!kinds.iter().any(|p| matches!(p, Payload::Lineage(_))));
    }

    fn ready(r: &Report) -> (ChronicleId, HashVal) {
        match r.outcome {
            Outcome::Ready {
                template_id, layer, ..
            } => (template_id, layer),
            ref o => panic!("not ready: {o:?}"),
        }
    }

    // ── The happy path ──────────────────────────────────────────────

    #[test]
    fn a_directory_becomes_a_template_and_the_scratch_is_cleaned_up() {
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        let g = c.node(1);
        let r = g.run(&dir_request(&c)).unwrap();
        let (tid, layer) = ready(&r);
        assert_eq!(tid, r.genesis_id);
        // Nothing excluded: the layer is the source artifact's bytes again.
        assert_eq!(layer, r.source_key);
        assert!(r.cleaned);
        assert!(r.notes.is_empty(), "{:?}", r.notes);
        assert_eq!(
            records(&c, tid),
            ["GenesisStarted", "TemplateReady", "GenesisCleanedUp"]
        );
        check_chain(&c, tid);

        // The scratch was made, then destroyed by guid, and the record
        // names that guid.
        let s = g.pool.state.lock().unwrap();
        assert_eq!(s.destroyed.len(), 1);
        let (ds, guid) = &s.destroyed[0];
        assert_eq!(ds, g.scratch(tid).unwrap().as_str());
        let Some(ContractRecord::GenesisCleanedUp(cl)) =
            accepted(&c, LogicalKey::GenesisCleaned(tid))
        else {
            panic!()
        };
        assert_eq!(cl.scratch_guid, Some(*guid));

        // The Template's definition, and its holds: layer, manifest, map.
        let Some(ContractRecord::TemplateReady(t)) = accepted(&c, LogicalKey::Template(tid)) else {
            panic!()
        };
        assert_eq!(t.born_from, BornFrom::Genesis { genesis_id: tid });
        assert_eq!((t.parent_template, t.vconf_key), (None, None));
        let holds = c.coord.query_chronicle(tid).unwrap().unwrap().holds;
        for k in [t.layer, t.output_manifest_key, t.classmap_key] {
            assert!(holds.contains(&taso_core::coordlog::ObjectId::content(k)));
        }
        // The output manifest describes the tree, slots from base 0.
        let m = {
            let mut r = g
                .get_content(ObjectKind::Manifest, t.output_manifest_key)
                .unwrap();
            let mut b = Vec::new();
            r.read_to_end(&mut b).unwrap();
            Manifest::decode(&b).unwrap()
        };
        let paths: Vec<&[u8]> = m.entries.iter().map(|e| &e.path[..]).collect();
        assert_eq!(
            paths,
            [
                &b"app"[..],
                b"app/lib",
                b"app/lib/util.py",
                b"app/main.py",
                b"etc",
                b"etc/app.toml",
                b"main"
            ]
        );
        assert!(m.entries.iter().all(|e| e.uid_slot == 0));

        // The same inputs again: nothing new, the same Template.
        drop(s);
        let again = g.run(&dir_request(&c)).unwrap();
        assert_eq!(again.outcome, r.outcome);
        assert_eq!(records(&c, tid).len(), 3);
    }

    #[test]
    fn a_directory_needs_best_effort_and_nothing_is_claimed() {
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        let mut req = dir_request(&c);
        req.best_effort = false;
        assert!(matches!(
            c.node(1).run(&req),
            Err(GenesisError::SourceNotImmutable)
        ));
        assert!(c.store.list(PREFIX).unwrap().is_empty(), "nothing put");
    }

    #[test]
    fn a_second_genesis_is_a_second_root() {
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        let a = c.node(1).run(&dir_request(&c)).unwrap();
        // The same tree from another actor, and another tree: each its
        // own Template, none with a parent.
        let mut by_other = dir_request(&c);
        by_other.authority.actor = "operator-2".into();
        let b = c.node(1).run(&by_other).unwrap();
        file(&c.src(), "app/new.py", b"Y = 2\n", 0);
        settle(&c.src(), 0);
        let d = c.node(1).run(&dir_request(&c)).unwrap();
        let ids = [ready(&a).0, ready(&b).0, ready(&d).0];
        assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
        assert_eq!(ready(&a).1, ready(&b).1, "the same bytes, one object");
        for id in ids {
            let Some(ContractRecord::TemplateReady(t)) = accepted(&c, LogicalKey::Template(id))
            else {
                panic!()
            };
            assert_eq!(t.parent_template, None);
        }
    }

    // ── Refusals ────────────────────────────────────────────────────

    fn refused(r: &Report) -> WalkRefusal {
        match r.outcome {
            Outcome::Refused {
                reason,
                input_manifest_key,
                ..
            } => {
                assert!(input_manifest_key.is_some());
                reason
            }
            ref o => panic!("not refused: {o:?}"),
        }
    }

    /// Run a genesis of `tree`; it must be refused for `want`, with no
    /// scratch ever made and no cleanup record.
    fn refuses(
        tree: impl FnOnce(&Path),
        adjust: impl FnOnce(&mut Genesis<DirPool>),
        want: WalkRefusal,
    ) {
        let c = Cluster::new();
        std::fs::create_dir_all(c.src()).unwrap();
        tree(&c.src());
        let mut g = c.node(1);
        adjust(&mut g);
        let r = g.run(&dir_request(&c)).unwrap();
        assert_eq!(refused(&r), want);
        assert!(!r.cleaned);
        assert_eq!(
            records(&c, r.genesis_id),
            ["GenesisStarted", "GenesisRefused"]
        );
        assert!(g.pool.state.lock().unwrap().guids.is_empty(), "no scratch");
        // The input manifest is in the store, for diagnosis.
        let Outcome::Refused {
            input_manifest_key: Some(k),
            ..
        } = r.outcome
        else {
            unreachable!()
        };
        assert!(g.get_content(ObjectKind::Manifest, k).is_ok());
        // Refused is final: running it again changes nothing.
        let again = g.run(&dir_request(&c)).unwrap();
        assert_eq!(again.outcome, r.outcome);
    }

    #[test]
    fn a_secret_path_is_refused() {
        refuses(
            |r| {
                good_tree(r, 0);
                file(r, "app/server.key", b"-----", 0);
                settle(r, 0);
            },
            |_| {},
            WalkRefusal::SecretPaths,
        );
    }

    #[test]
    fn an_unknown_path_is_refused() {
        refuses(
            |r| {
                good_tree(r, 0);
                file(r, "odd/x", b"?", 0);
                settle(r, 0);
            },
            |_| {},
            WalkRefusal::UnknownPaths,
        );
    }

    #[test]
    fn a_hook_without_a_waiver_is_refused_and_with_one_is_kept() {
        let tree = |r: &Path| {
            good_tree(r, 0);
            file(r, "hooks/pre-commit", b"#!/bin/sh\n", 0);
            settle(r, 0);
        };
        refuses(tree, |_| {}, WalkRefusal::HookNotWaived);
        let c = Cluster::new();
        tree(&c.src());
        let mut req = dir_request(&c);
        req.hook_waiver = Some("reviewed by hand".into());
        let r = c.node(1).run(&req).unwrap();
        ready(&r);
    }

    #[test]
    fn an_unsupported_entry_is_refused() {
        refuses(
            |r| {
                good_tree(r, 0);
                std::fs::hard_link(r.join("app/main.py"), r.join("app/again.py")).unwrap();
                settle(r, 0);
            },
            |_| {},
            WalkRefusal::Unsupported,
        );
    }

    #[test]
    fn a_reserved_entry_that_does_not_match_is_refused() {
        refuses(
            |r| {
                good_tree(r, 0);
                std::fs::create_dir(r.join("lost+found")).unwrap();
                std::fs::set_permissions(
                    r.join("lost+found"),
                    std::fs::Permissions::from_mode(0o755),
                )
                .unwrap();
                settle(r, 0);
            },
            |_| {},
            WalkRefusal::ReservedMismatch,
        );
    }

    #[test]
    fn a_walk_a_limit_stops_is_refused() {
        refuses(
            |r| good_tree(r, 0),
            |g| g.limits.max_entries = 2,
            WalkRefusal::IncompleteWalk,
        );
    }

    #[test]
    fn a_restore_whose_walk_differs_is_refused_and_its_scratch_cleaned_up() {
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        let mut g = c.node(1);
        g.pool.mangle = true;
        let r = g.run(&dir_request(&c)).unwrap();
        assert_eq!(refused(&r), WalkRefusal::MaterialisationMismatch);
        assert!(r.cleaned);
        assert_eq!(
            records(&c, r.genesis_id),
            ["GenesisStarted", "GenesisRefused", "GenesisCleanedUp"]
        );
        let s = g.pool.state.lock().unwrap();
        assert!(s.guids.is_empty());
        let Some(ContractRecord::GenesisCleanedUp(cl)) =
            accepted(&c, LogicalKey::GenesisCleaned(r.genesis_id))
        else {
            panic!()
        };
        assert_eq!(cl.scratch_guid, Some(s.destroyed[0].1));
        // Nothing was registered: no Template.
        assert!(accepted(&c, LogicalKey::Template(r.genesis_id)).is_none());
    }

    // ── A Vessel's Seal (D44) ───────────────────────────────────────

    #[test]
    fn a_seal_is_read_with_its_top_directorys_slot_base() {
        let c = Cluster::new();
        let g = c.node(1);
        let v = Dataset::new("tank/taso/v-0123").unwrap();
        let base = BASE + 3 * SLOT;
        let root = g.pool.make(&v);
        good_tree(&root, base);
        file(&root, "app/owned-by-slot-7", b"7", base + 7);
        settle(&root, base);
        g.pool
            .layers(&v)
            .snapshot(Lsn::new(5), HashVal::from_bytes([5; 32]))
            .unwrap();
        let req = request(Source::Seal {
            dataset: v.clone(),
            lsn: Lsn::new(5),
        });
        let r = g.run(&req).unwrap();
        ready(&r);
        let Some(ContractRecord::GenesisStarted(s)) =
            accepted(&c, LogicalKey::Genesis(r.genesis_id))
        else {
            panic!()
        };
        assert_eq!(s.consistency, Consistency::Immutable);
        let m = artifact::read_manifest(
            &mut g.get_content(ObjectKind::Artifact, r.source_key).unwrap(),
        )
        .unwrap();
        let slot = |p: &[u8]| m.entries.iter().find(|e| e.path == p).unwrap().uid_slot;
        assert_eq!((slot(b"app/main.py"), slot(b"app/owned-by-slot-7")), (0, 7));

        // The same tree from a directory at base 0 is the same artifact.
        let host = c.dir.path().join("host");
        good_tree(&host, 0);
        file(&host, "app/owned-by-slot-7", b"7", 7);
        settle(&host, 0);
        let d = c.node(1).run(&request(Source::Dir(host))).unwrap();
        assert_eq!(d.source_key, r.source_key);
        assert_eq!(d.genesis_id, r.genesis_id, "same source, map, actor");
    }

    #[test]
    fn a_seal_whose_base_cannot_be_told_is_refused() {
        let c = Cluster::new();
        let g = c.node(1);
        for (n, owner) in [
            (1u64, (0, 0)),
            (2, (BASE + SLOT, BASE + SLOT + 1)),
            (3, (BASE + 5, BASE + 5)),
            (4, (BASE - SLOT, BASE - SLOT)),
        ] {
            let v = Dataset::new(&format!("tank/taso/v-{n}")).unwrap();
            let root = g.pool.make(&v);
            good_tree(&root, owner.0);
            std::os::unix::fs::chown(&root, Some(owner.0), Some(owner.1)).unwrap();
            g.pool
                .layers(&v)
                .snapshot(Lsn::new(2), HashVal::from_bytes([2; 32]))
                .unwrap();
            let e = g
                .run(&request(Source::Seal {
                    dataset: v,
                    lsn: Lsn::new(2),
                }))
                .unwrap_err();
            assert!(
                matches!(e, GenesisError::SourceBase { uid, gid } if (uid, gid) == owner),
                "{owner:?}: {e}"
            );
        }
    }

    // ── Failpoints, takeover, lost nodes ────────────────────────────

    const FAILPOINTS: [&str; 8] = [
        "genesis.after_source_put",
        "genesis.before_started_accept",
        "genesis.after_started_accept",
        "genesis.after_materialise",
        "genesis.after_artifact_put",
        "genesis.before_ready_accept",
        "genesis.after_ready_accept",
        "genesis.before_cleanup",
    ];

    /// The id every run of the good tree gets (the trees are built with
    /// fixed times and owners, so every cluster's is the same).
    fn reference() -> (ChronicleId, HashVal) {
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        ready(&c.node(1).run(&dir_request(&c)).unwrap())
    }

    /// After the rerun: one TemplateReady with the reference's id, every
    /// record once, the chain's lsn 1 GenesisStarted, and no scratch left
    /// on `node`.
    fn finished(c: &Cluster, g: &Genesis<DirPool>, r: &Report, want: (ChronicleId, HashVal)) {
        assert_eq!(ready(r), want);
        assert!(r.cleaned);
        assert_eq!(
            records(c, want.0),
            ["GenesisStarted", "TemplateReady", "GenesisCleanedUp"]
        );
        check_chain(c, want.0);
        assert!(
            g.pool.state.lock().unwrap().guids.is_empty(),
            "scratch left"
        );
    }

    #[test]
    fn every_failpoint_resumes_on_the_same_node_with_the_same_template_id() {
        let want = reference();
        for fp in FAILPOINTS {
            let c = Cluster::new();
            good_tree(&c.src(), 0);
            let mut g = c.node(1);
            g.failpoint = fail_at(fp);
            match g.run(&dir_request(&c)) {
                Err(GenesisError::Failpoint(p)) => assert_eq!(p, fp),
                other => panic!("{fp}: {other:?}"),
            }
            g.failpoint = no_failpoints();
            let r = g
                .run(&dir_request(&c))
                .unwrap_or_else(|e| panic!("{fp}: {e}"));
            finished(&c, &g, &r, want);
            // A scratch left by an interrupted materialisation is
            // destroyed by guid before a fresh one, and reported.
            let left = matches!(
                fp,
                "genesis.after_materialise"
                    | "genesis.after_artifact_put"
                    | "genesis.before_ready_accept"
            );
            assert_eq!(
                r.notes
                    .iter()
                    .any(|n| n.contains("an interrupted run left")),
                left,
                "{fp}: {:?}",
                r.notes
            );
            // Two scratches destroyed if one was left, else one.
            assert_eq!(
                g.pool.state.lock().unwrap().destroyed.len(),
                1 + usize::from(left),
                "{fp}"
            );
        }
    }

    #[test]
    fn every_failpoint_resumes_on_another_node_after_the_first_is_lost() {
        let want = reference();
        for fp in FAILPOINTS {
            let c = Cluster::new();
            good_tree(&c.src(), 0);
            let mut a = c.node(1);
            a.failpoint = fail_at(fp);
            assert!(
                matches!(a.run(&dir_request(&c)), Err(GenesisError::Failpoint(_))),
                "{fp}"
            );
            drop(a);
            c.lose(1);
            let b = c.node(2);
            let r = b
                .run(&dir_request(&c))
                .unwrap_or_else(|e| panic!("{fp}: {e}"));
            finished(&c, &b, &r, want);
            // A claim was made before every failpoint but the first: the
            // other node takes it over.
            let took = r
                .notes
                .iter()
                .any(|n| n.starts_with("took the genesis over"));
            assert_eq!(
                took,
                fp != "genesis.after_source_put",
                "{fp}: {:?}",
                r.notes
            );
            // The cleanup names the scratch node 2 destroyed: node 1's was
            // lost with it.
            let Some(ContractRecord::GenesisCleanedUp(cl)) =
                accepted(&c, LogicalKey::GenesisCleaned(want.0))
            else {
                panic!()
            };
            let d = b.pool.state.lock().unwrap().destroyed.clone();
            match fp {
                "genesis.after_ready_accept" | "genesis.before_cleanup" => {
                    assert_eq!(cl.scratch_guid, None, "{fp}: no scratch on this node");
                    assert!(d.is_empty());
                }
                _ => assert_eq!(cl.scratch_guid, Some(d[0].1), "{fp}"),
            }
        }
    }

    #[test]
    fn a_genesis_claimed_and_lost_before_genesis_started_is_taken_over() {
        let want = reference();
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        // Node 1 claimed the id and was lost before anything was written.
        c.coord
            .claim_chronicle(want.0, WardenId::new(1), ClaimAuthority::Genesis)
            .unwrap();
        let b = c.node(2);
        let r = b.run(&dir_request(&c)).unwrap();
        finished(&c, &b, &r, want);
        assert!(
            r.notes.iter().any(|n| n.contains("authority Genesis")),
            "{:?}",
            r.notes
        );
        // Node 1, back, cannot write: its epoch is fenced.
        let own = c.coord.ownership(want.0).unwrap();
        assert_eq!(own.holder, WardenId::new(2));
    }

    #[test]
    fn a_takeover_after_genesis_started_uses_it_as_the_authority() {
        let want = reference();
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        let mut a = c.node(1);
        a.failpoint = fail_at("genesis.after_started_accept");
        assert!(a.run(&dir_request(&c)).is_err());
        // Node 1 is alive and still holds the claim; node 2 takes it over.
        let b = c.node(2);
        let r = b.run(&dir_request(&c)).unwrap();
        finished(&c, &b, &r, want);
        assert!(r
            .notes
            .iter()
            .any(|n| n.contains("authority GenesisStarted")));
        // Node 1's own run finds everything done and touches nothing.
        a.failpoint = no_failpoints();
        let back = a.run(&dir_request(&c)).unwrap();
        assert_eq!(back.outcome, r.outcome);
        assert_eq!(records(&c, want.0).len(), 3);
    }

    #[test]
    fn the_earlier_runs_genesis_started_is_reused_with_its_peer() {
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        let mut g = c.node(1);
        g.failpoint = fail_at("genesis.before_started_accept");
        assert!(g.run(&dir_request(&c)).is_err());
        g.failpoint = no_failpoints();
        let mut req = dir_request(&c);
        req.peer.pid = 9999;
        let r = g.run(&req).unwrap();
        let Some(ContractRecord::GenesisStarted(s)) =
            accepted(&c, LogicalKey::Genesis(r.genesis_id))
        else {
            panic!()
        };
        assert_eq!(s.peer.pid, 4242, "the record written first stands");
        let lsn1 = &read_log(&g.log_dir(r.genesis_id)).unwrap()[0];
        assert_eq!(lsn1.envelope.lsn, Lsn::new(1));
    }

    #[test]
    fn a_tampered_object_in_the_store_stops_the_run() {
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        let map = Classmap::parse(MAP.as_bytes()).unwrap();
        let path = object_key_path(PREFIX, ObjectKind::Classmap, map.key()).unwrap();
        c.store.put(&path, &mut &b"version = 1\n"[..]).unwrap();
        assert!(matches!(
            c.node(1).run(&dir_request(&c)),
            Err(GenesisError::Integrity(p)) if p == path
        ));
    }

    #[test]
    fn a_node_whose_log_is_behind_the_anchor_rebuilds_it_from_the_packs() {
        let want = reference();
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        // Node 1 stops after GenesisStarted; node 2 takes over and stops
        // with its TemplateReady shipped but not accepted.
        let mut a = c.node(1);
        a.failpoint = fail_at("genesis.after_started_accept");
        assert!(a.run(&dir_request(&c)).is_err());
        let mut b = c.node(2);
        b.failpoint = fail_at("genesis.before_ready_accept");
        assert!(b.run(&dir_request(&c)).is_err());
        // Node 1 takes it back: its own log ends at lsn 1, the anchor is
        // past it, so the log is kept aside and rebuilt; node 2's
        // TemplateReady is reused.
        a.failpoint = no_failpoints();
        let r = a.run(&dir_request(&c)).unwrap();
        assert_eq!(ready(&r), want);
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("behind the shipped anchor")),
            "{:?}",
            r.notes
        );
        assert_eq!(
            records(&c, want.0),
            ["GenesisStarted", "TemplateReady", "GenesisCleanedUp"]
        );
        check_chain(&c, want.0);
        let aside: Vec<_> = std::fs::read_dir(a.state_dir.join("genesis"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.contains(".superseded-"))
            .collect();
        assert_eq!(aside.len(), 1, "kept, not deleted");
    }

    /// D47: a node lost after appending its `GenesisStarted` (accepted by
    /// the append CAS) and before shipping it takes lsn 1 with it: the next
    /// holder continues after a Gap, and the accepted `GenesisStarted`, the
    /// first accepted record, is at lsn 3.
    #[test]
    fn a_genesis_started_lost_before_it_was_shipped_leaves_a_gap_at_lsn_1() {
        let want = reference();
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        let a = c.node(1);
        let req = dir_request(&c);
        let map = Classmap::parse(&req.classmap).unwrap();
        let ex = a.export(&req, &map).unwrap();
        {
            let mut notes = Vec::new();
            let mut run = a.open(want.0, false, &mut notes).unwrap();
            run.prepare(ContractRecord::GenesisStarted(Box::new(GenesisStarted {
                genesis_id: want.0,
                source_key: ex.source_key,
                consistency: ex.consistency,
                classmap_key: ex.classmap_key,
                transform_version: TRANSFORM_VERSION,
                hook_waiver: None,
                authority: req.authority.clone(),
                peer: req.peer,
            })))
            .unwrap();
        }
        drop(a);
        c.lose(1);
        let b = c.node(2);
        let r = b.run(&dir_request(&c)).unwrap();
        assert_eq!(ready(&r), want);
        assert!(r.notes.iter().any(|n| n.contains("(Gap)")), "{:?}", r.notes);
        let packs = Packs::new(c.store.clone(), NoSend, PREFIX, want.0).unwrap();
        let chain = packs.chain(Some(c.coord.shipped(want.0).unwrap())).unwrap();
        let first: Vec<(u64, bool)> = chain
            .frames
            .iter()
            .take(2)
            .map(|f| {
                (
                    f.envelope.lsn.get(),
                    matches!(Payload::decode(&f.payload), Ok(Payload::Gap(_))),
                )
            })
            .collect();
        assert_eq!(first, [(2, true), (3, false)]);
    }

    /// A Coord that loses the reply of the accept of one record kind: the
    /// accept happens, the caller sees the coordinator vanish.
    struct LoseReply {
        inner: Arc<Coordinator>,
        kind: &'static str,
        armed: std::sync::atomic::AtomicBool,
    }

    impl Coord for LoseReply {
        fn register(
            &self,
            c: ChronicleId,
            w: WardenId,
        ) -> Result<taso_core::envelope::ChronicleHead, CoordError> {
            self.inner.register(c, w)
        }
        fn append(
            &self,
            w: WardenId,
            e: &taso_core::envelope::Envelope,
        ) -> Result<taso_core::envelope::ChronicleHead, CoordError> {
            self.inner.append(w, e)
        }
        fn append_batch_with(
            &self,
            w: WardenId,
            e: &[taso_core::envelope::Envelope],
            x: &[Vec<u8>],
        ) -> Result<taso_core::envelope::ChronicleHead, CoordError> {
            self.inner.append_batch_with(w, e, x)
        }
        fn transfer_if(
            &self,
            c: ChronicleId,
            w: WardenId,
            x: (WardenId, taso_core::envelope::Epoch),
        ) -> Result<taso_core::envelope::Epoch, CoordError> {
            self.inner.transfer_if(c, w, x)
        }
        fn transfer(
            &self,
            c: ChronicleId,
            w: WardenId,
        ) -> Result<taso_core::envelope::Epoch, CoordError> {
            self.inner.transfer(c, w)
        }
        fn ownership(&self, c: ChronicleId) -> Result<taso_core::model::Ownership, CoordError> {
            self.inner.ownership(c)
        }
        fn head(&self, c: ChronicleId) -> Result<taso_core::envelope::ChronicleHead, CoordError> {
            self.inner.head(c)
        }
        fn advance_shipped(
            &self,
            w: WardenId,
            c: ChronicleId,
            e: taso_core::envelope::Epoch,
            to: Position,
        ) -> Result<Position, CoordError> {
            self.inner.advance_shipped(w, c, e, to)
        }
        fn shipped(&self, c: ChronicleId) -> Result<Position, CoordError> {
            self.inner.shipped(c)
        }
        fn claim_chronicle(
            &self,
            id: ChronicleId,
            w: WardenId,
            a: ClaimAuthority,
        ) -> Result<taso_core::envelope::Epoch, CoordError> {
            self.inner.claim_chronicle(id, w, a)
        }
        fn takeover_target(
            &self,
            id: ChronicleId,
            w: WardenId,
            a: ClaimAuthority,
            e: taso_core::envelope::Epoch,
        ) -> Result<(taso_core::envelope::Epoch, Head), CoordError> {
            self.inner.takeover_target(id, w, a, e)
        }
        fn announce(
            &self,
            w: WardenId,
            c: ChronicleId,
            e: taso_core::envelope::Epoch,
            s: HashVal,
            l: HashVal,
            d: HashVal,
        ) -> Result<Result<(), Answer>, CoordError> {
            self.inner.announce(w, c, e, s, l, d)
        }
        fn accept(
            &self,
            w: WardenId,
            c: ChronicleId,
            e: taso_core::envelope::Epoch,
            s: HashVal,
            h: Head,
            p: String,
            r: Submitted,
        ) -> Result<Answer, CoordError> {
            let lose = matches!(&r, Submitted::Contract(x) if kind(x) == self.kind)
                && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst);
            let a = self.inner.accept(w, c, e, s, h, p, r)?;
            if lose {
                return Err(CoordError::Unavailable(io::Error::other("reply lost")));
            }
            Ok(a)
        }
        fn cancel(
            &self,
            w: WardenId,
            c: ChronicleId,
            e: taso_core::envelope::Epoch,
            s: HashVal,
        ) -> Result<Answer, CoordError> {
            self.inner.cancel(w, c, e, s)
        }
        fn query_submission(
            &self,
            c: ChronicleId,
            s: HashVal,
        ) -> Result<taso_core::coordlog::SubmissionStatus, CoordError> {
            self.inner.query_submission(c, s)
        }
        fn query_logical(&self, l: HashVal) -> Result<Option<(u64, Submitted)>, CoordError> {
            self.inner.query_logical(l)
        }
        fn query_chronicle(
            &self,
            c: ChronicleId,
        ) -> Result<Option<taso_core::coordlog::ChronicleView>, CoordError> {
            self.inner.query_chronicle(c)
        }
        fn obligations(&self, c: ChronicleId) -> Result<Vec<u64>, CoordError> {
            self.inner.obligations(c)
        }
    }

    #[test]
    fn a_lost_accept_reply_is_found_by_logical_id_on_the_rerun() {
        let want = reference();
        for k in ["GenesisStarted", "TemplateReady", "GenesisCleanedUp"] {
            let c = Cluster::new();
            good_tree(&c.src(), 0);
            let mut g = c.node(1);
            g.coord = Arc::new(LoseReply {
                inner: c.coord.clone(),
                kind: k,
                armed: true.into(),
            });
            assert!(
                matches!(
                    g.run(&dir_request(&c)),
                    Err(GenesisError::Coord(CoordError::Unavailable(_)))
                ),
                "{k}"
            );
            // Rerun on the same node, and on another node after a loss.
            let r = g
                .run(&dir_request(&c))
                .unwrap_or_else(|e| panic!("{k}: {e}"));
            finished(&c, &g, &r, want);
        }
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        let mut a = c.node(1);
        a.coord = Arc::new(LoseReply {
            inner: c.coord.clone(),
            kind: "TemplateReady",
            armed: true.into(),
        });
        assert!(a.run(&dir_request(&c)).is_err());
        drop(a);
        c.lose(1);
        let b = c.node(2);
        let r = b.run(&dir_request(&c)).unwrap();
        finished(&c, &b, &r, want);
    }

    // ── Resume by id (D48) ──────────────────────────────────────────

    #[test]
    fn a_genesis_resumes_by_id_after_its_node_and_its_source_are_gone() {
        let want = reference();
        for fp in [
            "genesis.after_started_accept",
            "genesis.after_materialise",
            "genesis.after_artifact_put",
            "genesis.before_ready_accept",
            "genesis.after_ready_accept",
            "genesis.before_cleanup",
        ] {
            let c = Cluster::new();
            good_tree(&c.src(), 0);
            let mut a = c.node(1);
            a.failpoint = fail_at(fp);
            assert!(a.run(&dir_request(&c)).is_err(), "{fp}");
            drop(a);
            c.lose(1);
            std::fs::remove_dir_all(c.src()).unwrap();
            let b = c.node(2);
            let r = b.resume(want.0).unwrap_or_else(|e| panic!("{fp}: {e}"));
            finished(&c, &b, &r, want);
            assert_eq!(r.source_key, want.1, "{fp}");
            assert!(
                r.notes[0].starts_with("resumed by id"),
                "{fp}: {:?}",
                r.notes
            );
            // Every record carries the authority GenesisStarted was
            // accepted with.
            let Some(ContractRecord::TemplateReady(t)) = accepted(&c, LogicalKey::Template(want.0))
            else {
                panic!()
            };
            assert_eq!(t.authority, dir_request(&c).authority, "{fp}");
        }
    }

    #[test]
    fn a_refused_genesis_is_cleaned_up_by_id() {
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        let mut a = c.node(1);
        a.pool.mangle = true;
        a.failpoint = fail_at("genesis.before_cleanup");
        assert!(a.run(&dir_request(&c)).is_err());
        let Some((_, Submitted::Contract(ContractRecord::GenesisRefused(r)))) = c
            .coord
            .query_logical(logical_id(&LogicalKey::GenesisRefused(reference().0)))
            .unwrap()
        else {
            panic!("refused")
        };
        drop(a);
        c.lose(1);
        std::fs::remove_dir_all(c.src()).unwrap();
        let b = c.node(2);
        let rep = b.resume(r.genesis_id).unwrap();
        assert_eq!(refused(&rep), WalkRefusal::MaterialisationMismatch);
        assert!(rep.cleaned);
        assert_eq!(
            records(&c, r.genesis_id),
            ["GenesisStarted", "GenesisRefused", "GenesisCleanedUp"]
        );
    }

    #[test]
    fn resume_by_id_needs_an_accepted_genesis_started() {
        let want = reference();
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        // Nothing at all, then claimed and announced but not accepted.
        assert!(matches!(
            c.node(2).resume(want.0),
            Err(GenesisError::NothingToResume(id)) if id == want.0
        ));
        let mut a = c.node(1);
        a.failpoint = fail_at("genesis.before_started_accept");
        assert!(a.run(&dir_request(&c)).is_err());
        assert!(matches!(
            c.node(2).resume(want.0),
            Err(GenesisError::NothingToResume(_))
        ));
        // With its source, it finishes.
        let b = c.node(2);
        let r = b.run(&dir_request(&c)).unwrap();
        finished(&c, &b, &r, want);
    }

    #[test]
    fn later_records_carry_the_authority_genesis_started_was_accepted_with() {
        let c = Cluster::new();
        good_tree(&c.src(), 0);
        let mut g = c.node(1);
        g.failpoint = fail_at("genesis.after_started_accept");
        assert!(g.run(&dir_request(&c)).is_err());
        g.failpoint = no_failpoints();
        let mut req = dir_request(&c);
        req.authority.reason = "a different reason".into();
        let r = g.run(&req).unwrap();
        let (tid, _) = ready(&r);
        let Some(ContractRecord::TemplateReady(t)) = accepted(&c, LogicalKey::Template(tid)) else {
            panic!()
        };
        assert_eq!(t.authority.reason, "T(0)");
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("its records carry that one")),
            "{:?}",
            r.notes
        );
    }
}
