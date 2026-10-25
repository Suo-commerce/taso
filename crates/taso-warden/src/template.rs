//! A Template's layer on a node (P4 spec rev. 17 §5.6; D52, D53, D55;
//! file 5e).
//!
//! A Vessel born from a Template is a clone of the Template's **layer**:
//! the dataset `<root>/t-<template_id hex>`, whose Seal layer at lsn 1 is
//! bound to `layer_key`.  Its later Seals ship as increments on that layer,
//! so every node of a storage kind must hold the very same layer: one
//! storage stream, the `layer` object `layer_key`, accepted once per
//! Template and storage kind by `LayerShipped` (D52).
//!
//! [`TemplateLayers::ensure`] makes the layer present and checked on this
//! node, in an order that a retry of the same call finishes from any
//! crash:
//!
//! 1. **Accepted?**  If a `LayerShipped` for the Template and this storage
//!    kind is accepted, the layer is **settled**: receive it (step 3) and
//!    stop.
//! 2. **Build** (no `LayerShipped` yet).  A `LayerShipped` this node
//!    prepared earlier and never had accepted, or a layer it received and
//!    checked but never shipped, is reused if its object is in the store.
//!    Otherwise: the Template's artifact is restored into a
//!    fresh `<root>/tb-<hex>` at the Template range (D53), its top
//!    directory and a `lost+found` the filesystem made are given to the
//!    range (an artifact has no entry for its root), the tree is walked and
//!    checked equal to the output manifest, and sealed at lsn 1 with the
//!    build hash; its full stream is put as the `layer` object; the build
//!    dataset is destroyed by guid.  The builder then receives its own
//!    object (step 3), which gives it the layer's guid, and only then
//!    submits `LayerShipped` from its **Warden Chronicle** (D55).  If
//!    another node's layer was accepted first (`Conflict`), this node's
//!    received layer is destroyed by guid and the accepted one received.
//! 3. **Receive and check** (every node, the builder included).  A layer
//!    already bound to `layer_key` is used as it is once this node has
//!    checked it (a marker in `<state_dir>/layers/`); one bound otherwise
//!    is destroyed by guid.  The object is received as the Seal at lsn 1,
//!    bound to `layer_key`, verified against its key as it is read (a
//!    stream that fails as it is read leaves nothing); its guid must be
//!    the accepted one; its top directory must be owned by the Template
//!    range; its tree is walked and checked equal to the output manifest.
//!    Only then is it marked checked.
//!
//! A layer is bound to `layer_key` only by receiving the object with that
//! key, so no other bytes can stand where a Vessel's increments expect
//! these.
//!
//! # The Warden Chronicle (D55)
//!
//! Each Warden has one Chronicle of its own, id `"taso.warden.v1" ‖
//! warden_id` ([`warden_chronicle`]), claimed with authority `Vessel` and
//! reopened by it after a restart; it has no Lineage and carries
//! `LayerShipped`.  Its local log lives in `<state_dir>/warden/<id hex>`,
//! rebuilt from its packs if this node lost it.  A Warden that finds it
//! held by another Warden stops.
//!
//! The submit path (logical lookup, append once, ship, announce, accept)
//! is the one of [`crate::genesis`], kept here as its own copy for now;
//! the two are to be joined when P4 is simplified.
//!
//! # Failpoints (§10.2)
//!
//! `layer.after_build_put`, `layer.before_shipped_accept`,
//! `layer.after_shipped_accept`, `layer.after_receive`.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 17, BLAKE3
//! `097a3eb0375596aa60927260b971deeaf350b70c08067234ad2e656cb88ae369`.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use taso_core::canon::Canon;
use taso_core::contract::{
    logical_id, submission_id, ContractRecord, LayerShipped, LogicalKey, ObjectKind, StorageKind,
    TemplateReady,
};
use taso_core::coordlog::{Answer, ClaimAuthority, ClaimError, Final, Head, Submitted, Transient};
use taso_core::envelope::{ChronicleId, HashVal, Lsn, Stream};
use taso_core::model::WardenId;
use taso_core::record::Payload;

use crate::artifact::{self, ArtifactError};
use crate::chronicle::{restore_log, Chronicle, ChronicleError, LayerError, Layers};
use crate::classify::{self, Classmap, Limits, Manifest, MapError, Owner, Reserved};
use crate::coordinator::{Coord, CoordError};
use crate::coordstore::object_key_path;
use crate::pack::{name_bounds, PackError, Packs};
use crate::ship::{ByteStream, Sender, SharedStore};
use crate::vessel::Pool;
use crate::zfs::Dataset;

/// The lsn of a Template's layer Seal on every node.
pub const LAYER_LSN: Lsn = Lsn::new(1);

/// Domain of the build's provisional Seal hash (§9).
pub const BUILD_DOMAIN: &str = "taso.template.layer.build.v1";

/// Domain of a Warden Chronicle's id (D55).
pub const WARDEN_DOMAIN: &str = "taso.warden.v1";

/// How often a `NotReadable` accept is retried.
const NOT_READABLE_TRIES: u32 = 5;

/// How many times a record is resubmitted after `HeadMoved`.
const HEAD_MOVED_TRIES: u64 = 3;

/// A Warden's own Chronicle (D55): the first 16 bytes of
/// `"taso.warden.v1" ‖ warden_id`.
pub fn warden_chronicle(warden: WardenId) -> ChronicleId {
    let mut c = Canon::new();
    c.u64(warden.get());
    let h = blake3::derive_key(WARDEN_DOMAIN, c.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    ChronicleId::from_bytes(id)
}

/// The build's provisional Seal hash.
pub fn build_hash(template: ChronicleId) -> HashVal {
    HashVal::from_bytes(blake3::derive_key(BUILD_DOMAIN, template.as_bytes()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Errors ──────────────────────────────────────────────────────────

/// Why a layer could not be made present.  Each leaves something a retry
/// of the same call finishes.
#[derive(Debug)]
pub enum TemplateError {
    /// No `TemplateReady` is accepted for this id.
    NotATemplate(ChronicleId),
    /// The store failed.
    Store(io::Error),
    /// An object in the store does not hash to its key (§0.4).
    Integrity(String),
    /// The pool failed.
    Pool(LayerError),
    /// A new dataset has no mountpoint.
    NoMountpoint(Dataset),
    /// The classification map in the store is refused.
    Classmap(MapError),
    /// Walking a tree failed.
    Walk(io::Error),
    /// Restoring the artifact failed.
    Artifact(ArtifactError),
    /// The layer is not what it must be: its walk, its guid or its owner
    /// differs.  It was destroyed, unless it was already bound to the
    /// accepted key (then it is left, for an operator).
    Mismatch(String),
    /// The coordinator failed or refused.
    Coord(CoordError),
    /// The Warden Chronicle's local log failed.
    Chronicle(ChronicleError),
    /// The packs failed.
    Pack(PackError),
    /// This Warden's own Chronicle is held by another Warden: two nodes
    /// with one id.
    WardenHeldElsewhere {
        /// Who holds it.
        holder: WardenId,
    },
    /// A submission can never be accepted.
    Refused(Final),
    /// A submission stayed transiently refused past the retries.
    NotAccepted(Transient),
    /// What the log holds does not agree with what this node did.
    Inconsistent(String),
    /// A failpoint stopped the call.
    Failpoint(&'static str),
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotATemplate(t) => write!(f, "{} is not a ready Template", hex(t.as_bytes())),
            Self::Store(e) => write!(f, "store: {e}"),
            Self::Integrity(p) => write!(f, "store integrity: {p} does not hash to its key"),
            Self::Pool(e) => write!(f, "pool: {e}"),
            Self::NoMountpoint(d) => write!(f, "{d} has no mountpoint"),
            Self::Classmap(e) => write!(f, "{e}"),
            Self::Walk(e) => write!(f, "walk: {e}"),
            Self::Artifact(e) => write!(f, "artifact: {e}"),
            Self::Mismatch(why) => write!(f, "layer mismatch: {why}"),
            Self::Coord(e) => write!(f, "coordinator: {e}"),
            Self::Chronicle(e) => write!(f, "warden chronicle: {e}"),
            Self::Pack(e) => write!(f, "packs: {e}"),
            Self::WardenHeldElsewhere { holder } => write!(
                f,
                "this Warden's own Chronicle is held by warden {}: two nodes with one id",
                holder.get()
            ),
            Self::Refused(r) => write!(f, "LayerShipped refused: {r:?}"),
            Self::NotAccepted(t) => write!(f, "LayerShipped not accepted: {t:?}"),
            Self::Inconsistent(why) => write!(f, "inconsistent: {why}"),
            Self::Failpoint(p) => write!(f, "failpoint {p}"),
        }
    }
}

impl std::error::Error for TemplateError {}

impl From<CoordError> for TemplateError {
    fn from(e: CoordError) -> Self {
        Self::Coord(e)
    }
}

impl From<ChronicleError> for TemplateError {
    fn from(e: ChronicleError) -> Self {
        Self::Chronicle(e)
    }
}

impl From<PackError> for TemplateError {
    fn from(e: PackError) -> Self {
        Self::Pack(e)
    }
}

impl From<ArtifactError> for TemplateError {
    fn from(e: ArtifactError) -> Self {
        Self::Artifact(e)
    }
}

/// Called at each failpoint; an `Err` stops the call there.
pub type Failpoint = Box<dyn Fn(&'static str) -> Result<(), TemplateError> + Send + Sync>;

/// No failpoint stops anything.
pub fn no_failpoints() -> Failpoint {
    Box::new(|_| Ok(()))
}

// ── The layer ───────────────────────────────────────────────────────

/// A Template's layer, present and checked on this node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer {
    /// The Template.
    pub template_id: ChronicleId,
    /// `<root>/t-<template_id hex>`: Vessels clone its Seal at
    /// [`LAYER_LSN`], bound to `layer_key`.
    pub dataset: Dataset,
    /// The `layer` object, and the layer Seal's binding.
    pub layer_key: HashVal,
    /// The layer Seal's guid.
    pub guid: u64,
    /// For the operator: a build, a leftover destroyed, another node's
    /// layer taken.
    pub notes: Vec<String>,
}

/// What a node needs to make Template layers present (from its Warden
/// config).
pub struct TemplateLayers<P: Pool, X: Sender> {
    /// The node's storage.
    pub pool: P,
    /// Makes a Seal's full stream.
    pub sender: X,
    /// Which storage `pool` is.
    pub storage: StorageKind,
    /// The store.
    pub store: SharedStore,
    /// Key prefix in the store.
    pub prefix: String,
    /// The coordinator.
    pub coord: Arc<dyn Coord>,
    /// This Warden.
    pub warden: WardenId,
    /// The Warden's state directory.
    pub state_dir: PathBuf,
    /// The parent dataset of Vessels and layers.
    pub root: Dataset,
    /// The Template range's base: `host_uid_base + template_slot · 65536`
    /// (D53), the same on every node of the cluster.
    pub template_base: u32,
    /// `manifest.*`.
    pub limits: Limits,
    /// `fs.reserved`.
    pub reserved: Vec<Reserved>,
    /// The failpoint hook.
    pub failpoint: Failpoint,
    /// One `ensure` at a time on this node (the Warden Chronicle and the
    /// datasets are this node's).
    pub lock: Mutex<()>,
}

/// What the Template's own records say its layer must be.
struct Definition {
    ready: TemplateReady,
    map: Classmap,
    manifest: Manifest,
}

impl<P: Pool, X: Sender> TemplateLayers<P, X> {
    /// `<root>/t-<template_id hex>`.
    pub fn layer_dataset(&self, t: ChronicleId) -> Result<Dataset, TemplateError> {
        Dataset::new(&format!("{}/t-{}", self.root, hex(t.as_bytes())))
            .map_err(|e| TemplateError::Pool(Box::new(e)))
    }

    /// `<root>/tb-<template_id hex>`.
    pub fn build_dataset(&self, t: ChronicleId) -> Result<Dataset, TemplateError> {
        Dataset::new(&format!("{}/tb-{}", self.root, hex(t.as_bytes())))
            .map_err(|e| TemplateError::Pool(Box::new(e)))
    }

    fn marker(&self, key: HashVal) -> PathBuf {
        self.state_dir.join("layers").join(hex(key.as_bytes()))
    }

    /// Make the layer of Template `t` present and checked on this node.
    pub fn ensure(&self, t: ChronicleId) -> Result<Layer, TemplateError> {
        let _one = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let def = self.definition(t)?;
        let ds = self.layer_dataset(t)?;
        let mut notes = Vec::new();
        // At most twice round: a lost race leaves the accepted layer.
        for _ in 0..3 {
            if let Some(l) = self.accepted(t)? {
                let guid =
                    self.receive_checked(&ds, l.layer_key, Some(l.guid), &def, &mut notes)?;
                return Ok(Layer {
                    template_id: t,
                    dataset: ds,
                    layer_key: l.layer_key,
                    guid,
                    notes,
                });
            }
            let mut warden = self.open_warden(&mut notes)?;
            let logical = logical_id(&LogicalKey::Layer(t, self.storage));
            let mine = match (warden.prepared(logical)?, self.built_here(&ds)?) {
                (Some(ContractRecord::LayerShipped(p)), _) if self.has_object(p.layer_key)? => {
                    notes.push(format!(
                        "reusing the layer {} this node prepared earlier",
                        hex(p.layer_key.as_bytes())
                    ));
                    let guid =
                        self.receive_checked(&ds, p.layer_key, Some(p.guid), &def, &mut notes)?;
                    LayerShipped { guid, ..p }
                }
                (_, Some((key, guid))) => {
                    notes.push(format!(
                        "reusing the layer {} this node built and checked earlier",
                        hex(key.as_bytes())
                    ));
                    LayerShipped {
                        template_id: t,
                        storage: self.storage,
                        layer_key: key,
                        guid,
                    }
                }
                _ => {
                    let key = self.build(t, &def, &mut notes)?;
                    let guid = self.receive_checked(&ds, key, None, &def, &mut notes)?;
                    notes.push(format!("built the layer {}", hex(key.as_bytes())));
                    LayerShipped {
                        template_id: t,
                        storage: self.storage,
                        layer_key: key,
                        guid,
                    }
                }
            };
            (self.failpoint)("layer.before_shipped_accept")?;
            let got = warden.submit(ContractRecord::LayerShipped(mine))?;
            (self.failpoint)("layer.after_shipped_accept")?;
            let ContractRecord::LayerShipped(got) = got else {
                return Err(TemplateError::Inconsistent(
                    "the Layer row holds LayerShipped".into(),
                ));
            };
            if got == mine {
                return Ok(Layer {
                    template_id: t,
                    dataset: ds,
                    layer_key: got.layer_key,
                    guid: got.guid,
                    notes,
                });
            }
            // Another node's layer was accepted first: ours is destroyed
            // when the accepted one is received (next round).
            notes.push(format!(
                "another node's layer {} was shipped first; this node's {} is an orphan candidate",
                hex(got.layer_key.as_bytes()),
                hex(mine.layer_key.as_bytes())
            ));
        }
        Err(TemplateError::Inconsistent(
            "no LayerShipped settled after a lost race".into(),
        ))
    }

    // ── What the log says ───────────────────────────────────────────

    fn accepted_record(&self, key: LogicalKey) -> Result<Option<ContractRecord>, TemplateError> {
        Ok(match self.coord.query_logical(logical_id(&key))? {
            Some((_, Submitted::Contract(r))) => Some(r),
            Some(_) => {
                return Err(TemplateError::Inconsistent(
                    "a Birth under a Template logical id".into(),
                ))
            }
            None => None,
        })
    }

    fn accepted(&self, t: ChronicleId) -> Result<Option<LayerShipped>, TemplateError> {
        match self.accepted_record(LogicalKey::Layer(t, self.storage))? {
            Some(ContractRecord::LayerShipped(l)) => Ok(Some(l)),
            Some(_) => Err(TemplateError::Inconsistent(
                "the Layer row holds LayerShipped".into(),
            )),
            None => Ok(None),
        }
    }

    /// The Template's definition, its map and output manifest from the
    /// store, each checked against its key.
    fn definition(&self, t: ChronicleId) -> Result<Definition, TemplateError> {
        let ready = match self.accepted_record(LogicalKey::Template(t))? {
            Some(ContractRecord::TemplateReady(r)) => *r,
            _ => return Err(TemplateError::NotATemplate(t)),
        };
        let bytes = self.read_content(ObjectKind::Classmap, ready.classmap_key)?;
        let map = Classmap::parse(&bytes).map_err(TemplateError::Classmap)?;
        let bytes = self.read_content(ObjectKind::Manifest, ready.output_manifest_key)?;
        let manifest = Manifest::decode(&bytes).map_err(TemplateError::Classmap)?;
        if manifest.key() != ready.output_manifest_key {
            return Err(TemplateError::Integrity(
                self.path(ObjectKind::Manifest, ready.output_manifest_key),
            ));
        }
        Ok(Definition {
            ready,
            map,
            manifest,
        })
    }

    // ── The store ───────────────────────────────────────────────────

    fn path(&self, kind: ObjectKind, key: HashVal) -> String {
        object_key_path(&self.prefix, kind, key).expect("a content kind")
    }

    fn get(&self, kind: ObjectKind, key: HashVal) -> Result<ByteStream, TemplateError> {
        let path = self.path(kind, key);
        self.store
            .get(&path)
            .map_err(TemplateError::Store)?
            .ok_or_else(|| {
                TemplateError::Store(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{path} is not in the store"),
                ))
            })
    }

    /// A small content object, read whole and checked against its key.
    fn read_content(&self, kind: ObjectKind, key: HashVal) -> Result<Vec<u8>, TemplateError> {
        let mut b = Vec::new();
        self.get(kind, key)?
            .read_to_end(&mut b)
            .map_err(TemplateError::Store)?;
        if taso_core::contract::object_key(kind, &b) != key {
            return Err(TemplateError::Integrity(self.path(kind, key)));
        }
        Ok(b)
    }

    /// A layer this node received and checked earlier whose object is in
    /// the store (a build interrupted before it shipped): its key and guid.
    fn built_here(&self, ds: &Dataset) -> Result<Option<(HashVal, u64)>, TemplateError> {
        if self.pool.info(ds).map_err(TemplateError::Pool)?.is_none() {
            return Ok(None);
        }
        let bound = self.pool.layers(ds).list().map_err(TemplateError::Pool)?;
        let [(lsn, key)] = bound[..] else {
            return Ok(None);
        };
        if lsn != LAYER_LSN || !self.has_object(key)? {
            return Ok(None);
        }
        let Ok(g) = self
            .pool
            .receive(ds, None, (LAYER_LSN, key), &mut io::empty())
        else {
            return Ok(None);
        };
        let checked = std::fs::read_to_string(self.marker(key)).ok() == Some(g.to_string());
        Ok(checked.then_some((key, g)))
    }

    fn has_object(&self, key: HashVal) -> Result<bool, TemplateError> {
        self.store
            .exists(&self.path(ObjectKind::Layer, key))
            .map_err(TemplateError::Store)
    }

    /// Put a content object from a file (§0.4): an existing key is read
    /// back and verified instead.
    fn put_layer(&self, key: HashVal, file: &Path) -> Result<(), TemplateError> {
        let path = self.path(ObjectKind::Layer, key);
        if let Some(mut r) = self.store.get(&path).map_err(TemplateError::Store)? {
            let mut h = blake3::Hasher::new_derive_key(ObjectKind::Layer.prefix());
            io::copy(&mut r, &mut h).map_err(TemplateError::Store)?;
            if h.finalize().as_bytes() != key.as_bytes() {
                return Err(TemplateError::Integrity(path));
            }
            return Ok(());
        }
        let mut f = File::open(file).map_err(TemplateError::Store)?;
        self.store
            .put(&path, &mut f)
            .map_err(TemplateError::Store)?;
        Ok(())
    }

    // ── Build ───────────────────────────────────────────────────────

    /// Restore, check, seal, send, put, destroy the build: the new layer
    /// object's key.
    fn build(
        &self,
        t: ChronicleId,
        def: &Definition,
        notes: &mut Vec<String>,
    ) -> Result<HashVal, TemplateError> {
        let bd = self.build_dataset(t)?;
        if let Some(g) = self.pool.guid(&bd).map_err(TemplateError::Pool)? {
            self.pool.destroy(&bd, g).map_err(TemplateError::Pool)?;
            notes.push(format!(
                "destroyed the build {bd} (guid {g}) an interrupted run left"
            ));
        }
        let info = self.pool.create(&bd).map_err(TemplateError::Pool)?;
        let mount = info
            .mountpoint
            .ok_or_else(|| TemplateError::NoMountpoint(bd.clone()))?;
        let owner = Owner {
            uid_base: self.template_base,
            gid_base: self.template_base,
        };
        {
            let mut r = self.get(ObjectKind::Artifact, def.ready.layer)?;
            artifact::restore(&mut r, &mount, owner, &self.reserved, Some(def.ready.layer))?;
        }
        own_top(&mount, self.template_base).map_err(TemplateError::Walk)?;
        let walked = classify::walk(&mount, &def.map, owner, &self.limits, &self.reserved)
            .map_err(TemplateError::Walk)?;
        if !same_entries(&walked, &def.manifest) {
            let g = self.pool.guid(&bd).map_err(TemplateError::Pool)?;
            if let Some(g) = g {
                self.pool.destroy(&bd, g).map_err(TemplateError::Pool)?;
            }
            return Err(TemplateError::Mismatch(format!(
                "the restored build {bd} does not walk to the Template's output manifest"
            )));
        }
        self.pool
            .layers(&bd)
            .snapshot(LAYER_LSN, build_hash(t))
            .map_err(TemplateError::Pool)?;
        // The full stream, to a temporary file: its key, then the put.
        let tmp_dir = self.state_dir.join("layers").join("tmp");
        std::fs::create_dir_all(&tmp_dir).map_err(TemplateError::Store)?;
        let tmp = tmp_dir.join(format!("{}-{}.part", hex(t.as_bytes()), std::process::id()));
        let key = (|| -> Result<HashVal, TemplateError> {
            let mut stream = self
                .sender
                .send(&bd, None, LAYER_LSN)
                .map_err(TemplateError::Store)?;
            let mut f = File::create(&tmp).map_err(TemplateError::Store)?;
            let mut h = blake3::Hasher::new_derive_key(ObjectKind::Layer.prefix());
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let n = stream.read(&mut buf).map_err(TemplateError::Store)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
                f.write_all(&buf[..n]).map_err(TemplateError::Store)?;
            }
            f.sync_all().map_err(TemplateError::Store)?;
            let key = HashVal::from_bytes(*h.finalize().as_bytes());
            self.put_layer(key, &tmp)?;
            Ok(key)
        })();
        let _ = std::fs::remove_file(&tmp);
        let key = key?;
        (self.failpoint)("layer.after_build_put")?;
        if let Some(g) = self.pool.guid(&bd).map_err(TemplateError::Pool)? {
            self.pool.destroy(&bd, g).map_err(TemplateError::Pool)?;
        }
        Ok(key)
    }

    // ── Receive and check ───────────────────────────────────────────

    /// The layer bound to `key`, present and checked: its guid.  `want`
    /// is the accepted guid, if one is accepted.
    fn receive_checked(
        &self,
        ds: &Dataset,
        key: HashVal,
        want: Option<u64>,
        def: &Definition,
        notes: &mut Vec<String>,
    ) -> Result<u64, TemplateError> {
        let marker = self.marker(key);
        if self.pool.info(ds).map_err(TemplateError::Pool)?.is_some() {
            // Bound to this key already?  `receive` of a Seal that is
            // there binds and returns without reading.
            match self
                .pool
                .receive(ds, None, (LAYER_LSN, key), &mut io::empty())
            {
                Ok(g) => {
                    if want.is_some_and(|w| w != g) {
                        return Err(TemplateError::Mismatch(format!(
                            "{ds} is bound to the accepted layer with guid {g}, not {}; left for an operator",
                            want.unwrap_or_default()
                        )));
                    }
                    if std::fs::read_to_string(&marker).ok().as_deref() == Some(&g.to_string()) {
                        return Ok(g);
                    }
                    notes.push(format!("checking {ds}, received but not yet checked"));
                    self.check_or_destroy(ds, def)?;
                    self.mark(&marker, g)?;
                    return Ok(g);
                }
                Err(_) => {
                    let g = self.pool.guid(ds).map_err(TemplateError::Pool)?;
                    if let Some(g) = g {
                        self.pool.destroy(ds, g).map_err(TemplateError::Pool)?;
                        notes.push(format!(
                            "destroyed {ds} (guid {g}): bound to another layer than {}",
                            hex(key.as_bytes())
                        ));
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&marker);
        let mut r = Verifying {
            inner: self.get(ObjectKind::Layer, key)?,
            hasher: blake3::Hasher::new_derive_key(ObjectKind::Layer.prefix()),
            key,
            done: false,
        };
        let g = self
            .pool
            .receive(ds, None, (LAYER_LSN, key), &mut r)
            .map_err(|e| {
                if r.done && r.failed() {
                    TemplateError::Integrity(self.path(ObjectKind::Layer, key))
                } else {
                    TemplateError::Pool(e)
                }
            })?;
        (self.failpoint)("layer.after_receive")?;
        if want.is_some_and(|w| w != g) {
            self.destroy(ds)?;
            return Err(TemplateError::Mismatch(format!(
                "the received layer's guid is {g}, the accepted one {}",
                want.unwrap_or_default()
            )));
        }
        self.check_or_destroy(ds, def)?;
        self.mark(&marker, g)?;
        Ok(g)
    }

    fn mark(&self, marker: &Path, guid: u64) -> Result<(), TemplateError> {
        if let Some(d) = marker.parent() {
            std::fs::create_dir_all(d).map_err(TemplateError::Store)?;
        }
        std::fs::write(marker, guid.to_string()).map_err(TemplateError::Store)
    }

    fn destroy(&self, ds: &Dataset) -> Result<(), TemplateError> {
        if let Some(g) = self.pool.guid(ds).map_err(TemplateError::Pool)? {
            self.pool.destroy(ds, g).map_err(TemplateError::Pool)?;
        }
        Ok(())
    }

    /// The received layer's top directory is the Template range's and its
    /// tree walks to the output manifest; else it is destroyed.
    fn check_or_destroy(&self, ds: &Dataset, def: &Definition) -> Result<(), TemplateError> {
        let checked = (|| -> Result<(), TemplateError> {
            use std::os::unix::fs::MetadataExt;
            let view = self
                .pool
                .seal_view(ds, LAYER_LSN)
                .map_err(TemplateError::Pool)?;
            let m = std::fs::symlink_metadata(view.path()).map_err(TemplateError::Walk)?;
            if (m.uid(), m.gid()) != (self.template_base, self.template_base) {
                return Err(TemplateError::Mismatch(format!(
                    "{ds}'s top directory is owned by {}:{}, not this node's Template range {} \
                     (host_uid_base and template_slot must be the same on every node)",
                    m.uid(),
                    m.gid(),
                    self.template_base
                )));
            }
            let owner = Owner {
                uid_base: self.template_base,
                gid_base: self.template_base,
            };
            let walked = classify::walk(view.path(), &def.map, owner, &self.limits, &self.reserved)
                .map_err(TemplateError::Walk)?;
            if !same_entries(&walked, &def.manifest) {
                return Err(TemplateError::Mismatch(format!(
                    "{ds} does not walk to the Template's output manifest"
                )));
            }
            Ok(())
        })();
        if checked.is_err() {
            self.destroy(ds)?;
        }
        checked
    }

    // ── The Warden Chronicle ────────────────────────────────────────

    fn open_warden(&self, notes: &mut Vec<String>) -> Result<Warden<'_, P, X>, TemplateError> {
        let id = warden_chronicle(self.warden);
        match self
            .coord
            .claim_chronicle(id, self.warden, ClaimAuthority::Vessel)
        {
            Ok(_) => {}
            Err(CoordError::AlreadyRegistered(_))
            | Err(CoordError::Claim(ClaimError::AlreadyClaimed { .. })) => {
                let own = self.coord.ownership(id)?;
                if own.holder != self.warden {
                    return Err(TemplateError::WardenHeldElsewhere { holder: own.holder });
                }
            }
            Err(e) => return Err(e.into()),
        }
        let packs = Packs::new(self.store.clone(), NoSend, &self.prefix, id)
            .map_err(TemplateError::Store)?;
        let dir = self.state_dir.join("warden").join(hex(id.as_bytes()));
        if !dir.exists() {
            let anchor = self.coord.shipped(id)?;
            let frames = if anchor.lsn > Lsn::new(0) {
                packs.chain(Some(anchor))?.frames
            } else {
                Vec::new()
            };
            if let Some(p) = dir.parent() {
                std::fs::create_dir_all(p).map_err(TemplateError::Store)?;
            }
            restore_log(&dir, id, &frames)?;
            if !frames.is_empty() {
                notes.push("rebuilt this Warden's Chronicle from its packs".into());
            }
        }
        let (chronicle, _) =
            Chronicle::open_after_gap(&dir, self.coord.clone(), id, self.warden, NoLayers)?;
        Ok(Warden {
            t: self,
            chronicle,
            packs,
            attempt: 0,
        })
    }
}

/// §4.1.7: the walk equals the manifest entry for entry.
pub(crate) fn same_entries(walked: &Manifest, want: &Manifest) -> bool {
    walked.complete() && walked.unsupported.is_empty() && walked.entries == want.entries
}

/// What the manifest does not describe is given to the range, as the
/// runtime prepares a Vessel's dataset: the top directory (owner, mode
/// 0750; an artifact has no entry for its root) and a `lost+found` the
/// filesystem made `0:0` (file 4d).  The receive check requires the top
/// directory to be the range's.
pub(crate) fn own_top(dir: &Path, base: u32) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    std::os::unix::fs::chown(dir, Some(base), Some(base))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))?;
    let p = dir.join("lost+found");
    match std::fs::symlink_metadata(&p) {
        Ok(m) if m.file_type().is_dir() && m.uid() == 0 && m.gid() == 0 => {
            std::os::unix::fs::lchown(&p, Some(base), Some(base))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// A layer object as it is read, checked against its key at its end: a
/// mismatch fails the read, so the receive leaves nothing.
struct Verifying {
    inner: ByteStream,
    hasher: blake3::Hasher,
    key: HashVal,
    done: bool,
}

impl Verifying {
    fn failed(&self) -> bool {
        self.hasher.finalize().as_bytes() != self.key.as_bytes()
    }
}

impl Read for Verifying {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 {
            self.done = true;
            if self.failed() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the layer object does not hash to its key",
                ));
            }
            return Ok(0);
        }
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

// ── Submitting from the Warden Chronicle ────────────────────────────

struct Warden<'a, P: Pool, X: Sender> {
    t: &'a TemplateLayers<P, X>,
    chronicle: Chronicle<NoLayers>,
    packs: Packs<SharedStore, NoSend>,
    attempt: u64,
}

impl<P: Pool, X: Sender> Warden<'_, P, X> {
    /// A record with this logical id already in the local log.
    fn prepared(&self, logical: HashVal) -> Result<Option<ContractRecord>, TemplateError> {
        for f in self.chronicle.frames().map_err(ChronicleError::from)? {
            if f.envelope.stream != Stream::Ctl {
                continue;
            }
            if let Ok(Payload::Contract(r)) = Payload::decode(&f.payload) {
                if r.logical_id() == logical {
                    return Ok(Some(*r));
                }
            }
        }
        Ok(None)
    }

    fn lsn_of(&self, digest: HashVal) -> Result<Lsn, TemplateError> {
        for f in self.chronicle.frames().map_err(ChronicleError::from)? {
            if let Ok(Payload::Contract(r)) = Payload::decode(&f.payload) {
                if r.digest() == digest {
                    return Ok(f.envelope.lsn);
                }
            }
        }
        Err(TemplateError::Inconsistent(
            "a prepared record is not in the local log".into(),
        ))
    }

    fn accepted(&self, logical: HashVal) -> Result<Option<ContractRecord>, TemplateError> {
        Ok(match self.t.coord.query_logical(logical)? {
            Some((_, Submitted::Contract(r))) => Some(r),
            Some(_) => {
                return Err(TemplateError::Inconsistent(
                    "a Birth under a layer id".into(),
                ))
            }
            None => None,
        })
    }

    /// Submit `rec` (logical lookup, append once, ship, announce, accept):
    /// the record accepted for its logical id, this one or another.
    fn submit(&mut self, rec: ContractRecord) -> Result<ContractRecord, TemplateError> {
        let logical = rec.logical_id();
        if let Some(r) = self.accepted(logical)? {
            return Ok(r);
        }
        let rec = match self.prepared(logical)? {
            Some(p) if p == rec => p,
            Some(p) => {
                return Err(TemplateError::Inconsistent(format!(
                    "the Warden Chronicle already holds another {p:?} for this layer"
                )))
            }
            None => {
                self.chronicle
                    .append(Stream::Ctl, Payload::Contract(Box::new(rec.clone())))?;
                rec
            }
        };
        let digest = rec.digest();
        let lsn = self.lsn_of(digest)?;
        let tail = self.chronicle.tail();
        self.packs.ship_log(&self.chronicle.segments(), tail)?;
        self.t.coord.advance_shipped(
            self.t.warden,
            self.chronicle.id(),
            self.chronicle.epoch(),
            tail,
        )?;
        let pack = self
            .packs
            .pack_names()?
            .into_iter()
            .find(|n| {
                name_bounds(n)
                    .is_some_and(|(end, base, fs)| fs.is_none() && base < lsn && lsn <= end)
            })
            .ok_or_else(|| {
                TemplateError::Inconsistent(format!("no shipped pack carries lsn {}", lsn.get()))
            })?;
        let (id, epoch) = (self.chronicle.id(), self.chronicle.epoch());
        let coord = &self.t.coord;
        for _ in 0..HEAD_MOVED_TRIES {
            let sub = submission_id(logical, digest, epoch, self.attempt);
            self.attempt += 1;
            if let Err(a) = coord.announce(self.t.warden, id, epoch, sub, logical, digest)? {
                return self.final_answer(logical, a);
            }
            let mut tries = 0;
            loop {
                let head = coord.query_chronicle(id)?.map_or(Head::EMPTY, |v| v.head);
                let a = coord.accept(
                    self.t.warden,
                    id,
                    epoch,
                    sub,
                    head,
                    pack.clone(),
                    Submitted::Contract(rec.clone()),
                )?;
                match a {
                    Answer::Accepted { .. } | Answer::AlreadyAccepted { .. } => {
                        return self.accepted(logical)?.ok_or_else(|| {
                            TemplateError::Inconsistent("accepted, but not in the log".into())
                        });
                    }
                    Answer::Refused(Transient::NotReadable) if tries + 1 < NOT_READABLE_TRIES => {
                        tries += 1;
                        std::thread::sleep(std::time::Duration::from_millis(200 << tries));
                    }
                    Answer::Refused(Transient::HeadMoved { .. }) => {
                        coord.cancel(self.t.warden, id, epoch, sub)?;
                        break;
                    }
                    Answer::Refused(last) => {
                        let _ = coord.cancel(self.t.warden, id, epoch, sub);
                        return Err(TemplateError::NotAccepted(last));
                    }
                    Answer::FinalRefused(_) => return self.final_answer(logical, a),
                }
            }
        }
        Err(TemplateError::NotAccepted(Transient::HeadMoved {
            head: coord.query_chronicle(id)?.map_or(Head::EMPTY, |v| v.head),
        }))
    }

    fn final_answer(&self, logical: HashVal, a: Answer) -> Result<ContractRecord, TemplateError> {
        match a {
            Answer::FinalRefused(Final::Conflict)
            | Answer::Accepted { .. }
            | Answer::AlreadyAccepted { .. } => self.accepted(logical)?.ok_or_else(|| {
                TemplateError::Inconsistent(
                    "answered accepted or Conflict, nothing accepted".into(),
                )
            }),
            Answer::FinalRefused(r) => Err(TemplateError::Refused(r)),
            Answer::Refused(t) => Err(TemplateError::NotAccepted(t)),
        }
    }
}

/// The Warden Chronicle has no Seals.
struct NoLayers;

impl Layers for NoLayers {
    fn snapshot(&mut self, lsn: Lsn, _: HashVal) -> Result<(), LayerError> {
        Err(format!("a Warden Chronicle has no Seal layers (lsn {})", lsn.get()).into())
    }
    fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError> {
        Ok(Vec::new())
    }
    fn destroy(&mut self, _: Lsn) -> Result<(), LayerError> {
        Ok(())
    }
}

/// The Warden Chronicle ships logs only.
struct NoSend;

impl Sender for NoSend {
    fn send(&self, _: &Dataset, _: Option<&str>, _: Lsn) -> io::Result<ByteStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a Warden Chronicle ships no fs stream",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, SystemTime};

    use taso_core::contract::Peer;
    use taso_core::coordlog::ObjectId;
    use taso_core::record::Authority;

    use crate::coordinator::{Coordinator, LogConfig};
    use crate::coordstore::CoordStore;
    use crate::genesis::{self, Genesis, Outcome, Request, Source};
    use crate::ship::{LocalStore, ObjectStore};
    use crate::vessel::SealView;
    use crate::zfs::{CloneBase, DatasetInfo};

    const PREFIX: &str = "taso";
    const BASE: u32 = 200_000;
    const SLOT: u32 = 65_536;
    /// Slot 9 of every node is the Template range in these tests.
    const TBASE: u32 = BASE + 9 * SLOT;

    // ── A directory-backed pool that sends and receives ─────────────
    //
    // A dataset is a directory; a Seal layer a `cp -a` copy with its hash
    // beside it; a stream a `tar` of a Seal's copy (owners and times
    // kept); a received Seal's guid derived from its binding, as the block
    // log's.

    #[derive(Default)]
    struct DirState {
        guids: BTreeMap<String, u64>,
        next: u64,
        destroyed: Vec<String>,
        created: Vec<String>,
        /// Clones: dataset → (origin snapshot, the Seal's hash).
        clones: BTreeMap<String, (String, HashVal)>,
    }

    #[derive(Clone)]
    struct DirPool {
        root: PathBuf,
        state: Arc<Mutex<DirState>>,
    }

    impl DirPool {
        fn data(&self, d: &Dataset) -> PathBuf {
            self.root.join("data").join(d.as_str())
        }
        fn snaps(&self, d: &Dataset) -> PathBuf {
            self.root.join("snap").join(d.as_str())
        }
        fn new_dataset(&self, d: &Dataset) -> Result<PathBuf, LayerError> {
            let p = self.data(d);
            if p.exists() {
                return Err(format!("{d} exists").into());
            }
            std::fs::create_dir_all(&p)?;
            let mut s = self.state.lock().unwrap();
            s.next += 1;
            let g = 1000 + s.next;
            s.guids.insert(d.as_str().into(), g);
            s.created.push(d.as_str().into());
            Ok(p)
        }
    }

    struct DirLayers {
        data: PathBuf,
        snaps: PathBuf,
    }

    fn copy_tree(from: &Path, to: &Path) -> Result<(), LayerError> {
        let ok = Command::new("cp")
            .arg("-a")
            .arg(from)
            .arg(to)
            .status()?
            .success();
        if ok {
            Ok(())
        } else {
            Err("cp -a failed".into())
        }
    }

    impl Layers for DirLayers {
        fn snapshot(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
            std::fs::create_dir_all(&self.snaps)?;
            let to = self.snaps.join(lsn.get().to_string());
            if to.exists() {
                return Err("layer exists".into());
            }
            copy_tree(&self.data, &to)?;
            std::fs::write(to.with_extension("hash"), hash.as_bytes())?;
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
            let p = self.new_dataset(d)?;
            Ok(DatasetInfo {
                dataset: d.clone(),
                mountpoint: Some(p),
                origin: None,
                parent: None,
            })
        }
        /// A copy of the bound Seal's files (P4 file 5f: a Vessel born
        /// from a layer).
        fn clone(
            &self,
            source: &Dataset,
            seal: Lsn,
            seal_hash: HashVal,
            target: &Dataset,
        ) -> Result<DatasetInfo, LayerError> {
            let bound = self.layers(source).list()?;
            if !bound.contains(&(seal, seal_hash)) {
                return Err(format!("no Seal {source}@{} with that hash", seal.get()).into());
            }
            let p = self.new_dataset(target)?;
            let from = self.snaps(source).join(seal.get().to_string());
            let ok = Command::new("cp")
                .arg("-a")
                .arg(from.join("."))
                .arg(&p)
                .status()?
                .success();
            if !ok {
                return Err("cp -a failed".into());
            }
            self.state.lock().unwrap().clones.insert(
                target.as_str().into(),
                (source.seal_snapshot(seal), seal_hash),
            );
            Ok(self.info(target)?.expect("made"))
        }
        fn info(&self, d: &Dataset) -> Result<Option<DatasetInfo>, LayerError> {
            let p = self.data(d);
            let clone = self.state.lock().unwrap().clones.get(d.as_str()).cloned();
            Ok(p.exists().then(|| DatasetInfo {
                dataset: d.clone(),
                mountpoint: Some(p),
                origin: clone.as_ref().map(|c| c.0.clone()),
                parent: clone.map(|c| c.1),
            }))
        }
        fn layers(&self, d: &Dataset) -> DirLayers {
            DirLayers {
                data: self.data(d),
                snaps: self.snaps(d),
            }
        }
        fn receive(
            &self,
            d: &Dataset,
            from: Option<(Lsn, HashVal)>,
            to: (Lsn, HashVal),
            stream: &mut dyn Read,
        ) -> Result<u64, LayerError> {
            assert!(from.is_none(), "the test pool receives full streams only");
            if self.data(d).exists() {
                let bound = self.layers(d).list()?.into_iter().find(|(l, _)| *l == to.0);
                return match bound {
                    Some((_, h)) if h == to.1 => Ok(crate::blk::guid(to.0, to.1)),
                    Some(_) => Err("bound to another record".into()),
                    None => Err(format!("{d} exists without its Seal").into()),
                };
            }
            // Read the whole stream first: a stream that fails as it is
            // read leaves nothing.
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes)?;
            let p = self.new_dataset(d)?;
            let mut child = Command::new("tar")
                .args(["-x", "-p", "--numeric-owner", "-f", "-", "-C"])
                .arg(&p)
                .stdin(Stdio::piped())
                .spawn()?;
            child.stdin.take().unwrap().write_all(&bytes)?;
            if !child.wait()?.success() {
                return Err("tar -x failed".into());
            }
            self.layers(d).snapshot(to.0, to.1)?;
            Ok(crate::blk::guid(to.0, to.1))
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
            s.destroyed.push(d.as_str().into());
            std::fs::remove_dir_all(self.data(d))?;
            let _ = std::fs::remove_dir_all(self.snaps(d));
            Ok(true)
        }
    }

    /// A Seal's full stream: `tar` of its copy, sorted by name.
    /// The pool's root, and a label written into every stream's tar volume
    /// header (ignored on extract): each node's builds differ by it, as two
    /// real builds' streams do (ZFS guids and txgs; ext4 allocation).
    struct DirSend(PathBuf, String);

    impl Sender for DirSend {
        fn send(&self, d: &Dataset, from: Option<&str>, to: Lsn) -> io::Result<ByteStream> {
            assert!(from.is_none());
            let dir = self
                .0
                .join("snap")
                .join(d.as_str())
                .join(to.get().to_string());
            let out = Command::new("tar")
                .args(["-c", "--sort=name", "--numeric-owner", "-V"])
                .arg(&self.1)
                .args(["-f", "-", "-C"])
                .arg(&dir)
                .arg(".")
                .output()?;
            if !out.status.success() {
                return Err(io::Error::other("tar -c failed"));
            }
            Ok(Box::new(Cursor::new(out.stdout)))
        }
    }

    // ── A cluster with one Template ─────────────────────────────────

    struct Cluster {
        dir: tempfile::TempDir,
        store: SharedStore,
        coord: Arc<Coordinator>,
        t0: ChronicleId,
    }

    const MAP: &str = "version = 1\n[[rule]]\nglob = \"**\"\nclass = \"Source\"\n";

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
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
            // T(0), by a genesis from a small host tree on node 0.
            let src = dir.path().join("src");
            std::fs::create_dir_all(src.join("app")).unwrap();
            for (f, body) in [("app/main.py", "print(1)\n"), ("README", "t0\n")] {
                std::fs::write(src.join(f), body).unwrap();
                std::fs::set_permissions(src.join(f), std::fs::Permissions::from_mode(0o644))
                    .unwrap();
                File::options()
                    .write(true)
                    .open(src.join(f))
                    .unwrap()
                    .set_modified(at(1_700_000_000))
                    .unwrap();
            }
            for d in [src.join("app"), src.clone()] {
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
                File::open(&d)
                    .unwrap()
                    .set_modified(at(1_600_000_000))
                    .unwrap();
            }
            let n0 = dir.path().join("node0");
            let g = Genesis {
                pool: DirPool {
                    root: n0.join("pool"),
                    state: Arc::default(),
                },
                store: store.clone(),
                prefix: PREFIX.into(),
                coord: coord.clone(),
                warden: WardenId::new(100),
                state_dir: n0.join("state"),
                root: Dataset::new("tank/taso").unwrap(),
                host_uid_base: BASE,
                limits: Limits::default(),
                reserved: Reserved::defaults(),
                failpoint: genesis::no_failpoints(),
            };
            let r = g
                .run(&Request {
                    source: Source::Dir(src),
                    classmap: MAP.as_bytes().to_vec(),
                    authority: Authority {
                        actor: "jarmo".into(),
                        reason: "T(0)".into(),
                    },
                    hook_waiver: None,
                    best_effort: true,
                    peer: Peer { uid: 0, pid: 1 },
                })
                .unwrap();
            let Outcome::Ready { template_id, .. } = r.outcome else {
                panic!("{:?}", r.outcome)
            };
            Self {
                dir,
                store,
                coord,
                t0: template_id,
            }
        }

        fn node(&self, n: u64, storage: StorageKind) -> TemplateLayers<DirPool, DirSend> {
            let at = self.dir.path().join(format!("node{n}"));
            TemplateLayers {
                pool: DirPool {
                    root: at.join("pool"),
                    state: Arc::default(),
                },
                sender: DirSend(at.join("pool"), format!("node{n}")),
                storage,
                store: self.store.clone(),
                prefix: PREFIX.into(),
                coord: self.coord.clone(),
                warden: WardenId::new(n),
                state_dir: at.join("state"),
                root: Dataset::new("tank/taso").unwrap(),
                template_base: TBASE,
                limits: Limits::default(),
                reserved: Reserved::defaults(),
                failpoint: no_failpoints(),
                lock: Mutex::new(()),
            }
        }

        fn lose(&self, n: u64) {
            std::fs::remove_dir_all(self.dir.path().join(format!("node{n}"))).unwrap();
        }

        fn shipped(&self, storage: StorageKind) -> Option<LayerShipped> {
            match self
                .coord
                .query_logical(logical_id(&LogicalKey::Layer(self.t0, storage)))
                .unwrap()
            {
                Some((_, Submitted::Contract(ContractRecord::LayerShipped(l)))) => Some(l),
                None => None,
                other => panic!("{other:?}"),
            }
        }
    }

    fn fail_at(name: &'static str) -> Failpoint {
        Box::new(move |p| {
            if p == name {
                Err(TemplateError::Failpoint(p))
            } else {
                Ok(())
            }
        })
    }

    /// The layer on `node` is the accepted one, checked, its files owned by
    /// the Template range.
    fn present(c: &Cluster, node: &TemplateLayers<DirPool, DirSend>, l: &Layer) {
        use std::os::unix::fs::MetadataExt;
        let s = c.shipped(node.storage).expect("a LayerShipped is accepted");
        assert_eq!((l.layer_key, l.guid), (s.layer_key, s.guid));
        assert_eq!(l.dataset, node.layer_dataset(c.t0).unwrap());
        let bound = node.pool.layers(&l.dataset).list().unwrap();
        assert_eq!(bound, vec![(LAYER_LSN, s.layer_key)]);
        let view = node.pool.seal_view(&l.dataset, LAYER_LSN).unwrap();
        let m = std::fs::metadata(view.path().join("app/main.py")).unwrap();
        assert_eq!((m.uid(), m.gid()), (TBASE, TBASE));
        assert!(node.marker(s.layer_key).exists(), "marked checked");
        assert!(
            node.pool
                .info(&node.build_dataset(c.t0).unwrap())
                .unwrap()
                .is_none(),
            "no build left"
        );
    }

    // ── Tests ───────────────────────────────────────────────────────

    #[test]
    fn the_first_node_builds_and_every_node_receives_the_same_layer() {
        let c = Cluster::new();
        let n1 = c.node(1, StorageKind::Blk);
        let l1 = n1.ensure(c.t0).unwrap();
        present(&c, &n1, &l1);
        assert!(
            l1.notes.iter().any(|n| n.starts_with("built the layer")),
            "{:?}",
            l1.notes
        );
        // Held by the Template.
        assert!(c
            .coord
            .query_chronicle(c.t0)
            .unwrap()
            .unwrap()
            .holds
            .contains(&ObjectId::content(l1.layer_key)));
        // Shipped from node 1's own Chronicle.
        let wc = c
            .coord
            .query_chronicle(warden_chronicle(WardenId::new(1)))
            .unwrap()
            .unwrap();
        assert_eq!(wc.accepted.len(), 1);

        // Node 2 builds nothing: it receives the same stream.
        let n2 = c.node(2, StorageKind::Blk);
        let l2 = n2.ensure(c.t0).unwrap();
        present(&c, &n2, &l2);
        assert_eq!((l2.layer_key, l2.guid), (l1.layer_key, l1.guid));
        assert!(l2.notes.is_empty(), "{:?}", l2.notes);
        assert!(!n2
            .pool
            .state
            .lock()
            .unwrap()
            .created
            .iter()
            .any(|d| d.contains("/tb-")));

        // Again on node 2: present and checked, nothing done.
        let again = n2.ensure(c.t0).unwrap();
        assert_eq!(again, l2);
        assert_eq!(n2.pool.state.lock().unwrap().created.len(), 1);

        // The other storage kind has its own LayerShipped.  (The test
        // pool's streams are alike for both kinds, so here it is the same
        // object; real storages' streams differ.)
        let z = c.node(3, StorageKind::Zfs).ensure(c.t0).unwrap();
        assert_eq!(c.shipped(StorageKind::Zfs).unwrap().layer_key, z.layer_key);
        let wc3 = c
            .coord
            .query_chronicle(warden_chronicle(WardenId::new(3)))
            .unwrap()
            .unwrap();
        assert_eq!(wc3.accepted.len(), 1, "node 3 shipped the ZFS layer");
    }

    #[test]
    fn not_a_template_is_refused() {
        let c = Cluster::new();
        let n1 = c.node(1, StorageKind::Blk);
        let v = ChronicleId::from_bytes([0x0A; 16]);
        assert!(matches!(n1.ensure(v), Err(TemplateError::NotATemplate(t)) if t == v));
    }

    #[test]
    fn a_layer_received_but_not_checked_is_checked_and_a_bad_one_destroyed() {
        let c = Cluster::new();
        c.node(1, StorageKind::Blk).ensure(c.t0).unwrap();
        // Node 2 stops right after its receive.
        let mut n2 = c.node(2, StorageKind::Blk);
        n2.failpoint = fail_at("layer.after_receive");
        assert!(matches!(n2.ensure(c.t0), Err(TemplateError::Failpoint(_))));
        n2.failpoint = no_failpoints();
        let l = n2.ensure(c.t0).unwrap();
        assert!(
            l.notes.iter().any(|n| n.contains("not yet checked")),
            "{:?}",
            l.notes
        );
        present(&c, &n2, &l);
        // A layer tampered with after its receive fails its check and is
        // destroyed; the next call receives it afresh.
        std::fs::remove_file(n2.marker(l.layer_key)).unwrap();
        let view = n2.pool.seal_view(&l.dataset, LAYER_LSN).unwrap();
        std::fs::write(view.path().join("README"), "tampered\n").unwrap();
        assert!(matches!(n2.ensure(c.t0), Err(TemplateError::Mismatch(_))));
        assert!(n2.pool.info(&l.dataset).unwrap().is_none(), "destroyed");
        let l = n2.ensure(c.t0).unwrap();
        present(&c, &n2, &l);
    }

    #[test]
    fn every_failpoint_resumes_with_one_layer_shipped() {
        for fp in [
            "layer.after_build_put",
            "layer.before_shipped_accept",
            "layer.after_shipped_accept",
            "layer.after_receive",
        ] {
            let c = Cluster::new();
            let mut n1 = c.node(1, StorageKind::Blk);
            n1.failpoint = fail_at(fp);
            assert!(
                matches!(n1.ensure(c.t0), Err(TemplateError::Failpoint(p)) if p == fp),
                "{fp}"
            );
            n1.failpoint = no_failpoints();
            let l = n1.ensure(c.t0).unwrap_or_else(|e| panic!("{fp}: {e}"));
            present(&c, &n1, &l);
            let wc = c
                .coord
                .query_chronicle(warden_chronicle(WardenId::new(1)))
                .unwrap()
                .unwrap();
            assert_eq!(wc.accepted.len(), 1, "{fp}: one LayerShipped");
            // A layer built and checked but not shipped is reused, not
            // rebuilt.
            if fp == "layer.before_shipped_accept" {
                assert!(
                    l.notes.iter().any(|n| n.contains("checked earlier")),
                    "{fp}: {:?}",
                    l.notes
                );
                let builds = n1
                    .pool
                    .state
                    .lock()
                    .unwrap()
                    .created
                    .iter()
                    .filter(|d| d.contains("/tb-"))
                    .count();
                assert_eq!(builds, 1, "{fp}: built once");
            }
            // The same failpoints on a node lost there: another node
            // finishes, from the store and the log.
            let c = Cluster::new();
            let mut n1 = c.node(1, StorageKind::Blk);
            n1.failpoint = fail_at(fp);
            assert!(n1.ensure(c.t0).is_err());
            drop(n1);
            c.lose(1);
            let n2 = c.node(2, StorageKind::Blk);
            let l = n2
                .ensure(c.t0)
                .unwrap_or_else(|e| panic!("{fp} on node 2: {e}"));
            present(&c, &n2, &l);
        }
    }

    #[test]
    fn two_builders_race_and_the_loser_takes_the_accepted_layer() {
        let c = Arc::new(Cluster::new());
        // Node 1 builds and receives its own layer; just before it ships,
        // node 2 builds and ships its own (a different stream).
        let mut n1 = c.node(1, StorageKind::Blk);
        let c2 = c.clone();
        n1.failpoint = Box::new(move |p| {
            if p == "layer.before_shipped_accept" && c2.shipped(StorageKind::Blk).is_none() {
                c2.node(2, StorageKind::Blk)
                    .ensure(c2.t0)
                    .map_err(|e| TemplateError::Inconsistent(e.to_string()))?;
            }
            Ok(())
        });
        let l1 = n1.ensure(c.t0).unwrap();
        let won = c.shipped(StorageKind::Blk).unwrap();
        // Node 1's submission answered Conflict: it took node 2's layer,
        // destroying its own, and said so.
        assert_eq!(l1.layer_key, won.layer_key);
        assert!(
            l1.notes.iter().any(|n| n.contains("was shipped first")),
            "{:?}",
            l1.notes
        );
        assert!(
            l1.notes
                .iter()
                .any(|n| n.contains("bound to another layer")),
            "{:?}",
            l1.notes
        );
        present(&c, &n1, &l1);
        let accepted = |w: u64| {
            c.coord
                .query_chronicle(warden_chronicle(WardenId::new(w)))
                .unwrap()
                .unwrap()
                .accepted
                .len()
        };
        assert_eq!(
            (accepted(1), accepted(2)),
            (0, 1),
            "one LayerShipped, node 2's"
        );
        // Node 1's own object is an orphan candidate: held by nothing.
        let mine = l1
            .notes
            .iter()
            .find_map(|n| n.split("this node's ").nth(1))
            .and_then(|r| r.split(' ').next())
            .unwrap()
            .to_string();
        assert_ne!(mine, hex(won.layer_key.as_bytes()));
    }

    #[test]
    fn a_lost_race_with_a_different_stream_destroys_the_losers_layer() {
        let c = Cluster::new();
        // Node 1 built, received and checked its own layer, then stopped
        // before shipping it.
        let mut n1 = c.node(1, StorageKind::Blk);
        n1.failpoint = fail_at("layer.before_shipped_accept");
        assert!(n1.ensure(c.t0).is_err());
        let mine = n1.layer_dataset(c.t0).unwrap();
        let my_key = n1.pool.layers(&mine).list().unwrap()[0].1;
        // Node 2 ships its own, a different stream.
        let won = c.node(2, StorageKind::Blk).ensure(c.t0).unwrap();
        assert_ne!(won.layer_key, my_key);
        // Node 1 again: the accepted layer is settled; its own is destroyed
        // by guid and the accepted one received.
        n1.failpoint = no_failpoints();
        let l = n1.ensure(c.t0).unwrap();
        assert_eq!(l.layer_key, won.layer_key);
        assert!(
            l.notes.iter().any(|n| n.contains("bound to another layer")),
            "{:?}",
            l.notes
        );
        present(&c, &n1, &l);
    }

    #[test]
    fn a_tampered_layer_object_is_never_received() {
        let c = Cluster::new();
        let l1 = c.node(1, StorageKind::Blk).ensure(c.t0).unwrap();
        let path = object_key_path(PREFIX, ObjectKind::Layer, l1.layer_key).unwrap();
        let mut bytes = Vec::new();
        c.store
            .get(&path)
            .unwrap()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        c.store.put(&path, &mut &bytes[..]).unwrap();
        let n2 = c.node(2, StorageKind::Blk);
        assert!(matches!(n2.ensure(c.t0), Err(TemplateError::Integrity(p)) if p == path));
        assert!(
            n2.pool
                .info(&n2.layer_dataset(c.t0).unwrap())
                .unwrap()
                .is_none(),
            "nothing left"
        );
    }

    #[test]
    fn a_node_with_another_template_range_refuses_the_layer() {
        let c = Cluster::new();
        c.node(1, StorageKind::Blk).ensure(c.t0).unwrap();
        let mut n2 = c.node(2, StorageKind::Blk);
        n2.template_base = TBASE + SLOT;
        let e = n2.ensure(c.t0).unwrap_err();
        assert!(
            matches!(&e, TemplateError::Mismatch(w) if w.contains("Template range")),
            "{e}"
        );
        assert!(
            n2.pool
                .info(&n2.layer_dataset(c.t0).unwrap())
                .unwrap()
                .is_none(),
            "destroyed"
        );
    }

    #[test]
    fn the_warden_chronicle_survives_its_node_and_is_one_wardens() {
        let c = Cluster::new();
        let mut n1 = c.node(1, StorageKind::Blk);
        n1.failpoint = fail_at("layer.after_shipped_accept");
        assert!(n1.ensure(c.t0).is_err());
        drop(n1);
        c.lose(1);
        // Node 1 again, on a fresh disk: its Chronicle is rebuilt from the
        // packs; the accepted layer is received.
        let n1 = c.node(1, StorageKind::Blk);
        let l = n1.ensure(c.t0).unwrap();
        present(&c, &n1, &l);
        // Another Warden holding warden 5's Chronicle stops warden 5.
        c.coord
            .claim_chronicle(
                warden_chronicle(WardenId::new(5)),
                WardenId::new(6),
                ClaimAuthority::Vessel,
            )
            .unwrap();
        let n5 = c.node(5, StorageKind::Zfs);
        assert!(matches!(
            n5.ensure(c.t0),
            Err(TemplateError::WardenHeldElsewhere { holder }) if holder == WardenId::new(6)
        ));
    }

    #[test]
    fn warden_chronicle_ids_are_pinned_and_distinct() {
        assert_ne!(
            warden_chronicle(WardenId::new(1)),
            warden_chronicle(WardenId::new(2))
        );
        let mut b = [0u8; 32];
        b[..16].copy_from_slice(warden_chronicle(WardenId::new(1)).as_bytes());
        assert_eq!(
            HashVal::from_bytes(b).to_string(),
            "cccc13deaa40ef3ac092018c1391102800000000000000000000000000000000"
        );
    }

    // ── Vessels born from the layer (P4 file 5f) ────────────────────

    use crate::vessel::{Host, TemplateBirth, VesselError};
    use taso_core::record::{vessel_id, LineageRecord, Namespace, Origin, TemplateAsked};

    fn host(c: &Cluster, node: &TemplateLayers<DirPool, DirSend>) -> Host<DirPool> {
        Host {
            coord: c.coord.clone(),
            pool: Clone::clone(&node.pool),
            root: node.root.clone(),
            state_dir: node.state_dir.clone(),
            warden: node.warden,
        }
    }

    fn vpacks(
        c: &Cluster,
        node: &TemplateLayers<DirPool, DirSend>,
        id: ChronicleId,
    ) -> Packs<SharedStore, DirSend> {
        Packs::new(
            c.store.clone(),
            DirSend(node.state_dir.join("unused"), String::new()),
            PREFIX,
            id,
        )
        .unwrap()
    }

    fn vfail(name: &'static str) -> impl Fn(&'static str) -> Result<(), VesselError> {
        move |p| {
            if p == name {
                Err(VesselError::Failpoint(p))
            } else {
                Ok(())
            }
        }
    }

    fn nofail(_: &'static str) -> Result<(), VesselError> {
        Ok(())
    }

    const NS: Namespace = Namespace::from_bytes([7; 16]);

    fn birth_of(l: &Layer, asked: Option<TemplateAsked>) -> TemplateBirth {
        TemplateBirth {
            template_id: l.template_id,
            layer_key: l.layer_key,
            asked,
        }
    }

    /// The Birth accepted for `id`, if any.
    fn accepted_birth(c: &Cluster, id: ChronicleId, lineage: &LineageRecord) -> Option<Submitted> {
        let b = Submitted::Birth {
            chronicle: id,
            lineage: lineage.clone(),
        };
        crate::submit::accepted(c.coord.as_ref(), b.logical_id()).unwrap()
    }

    #[test]
    fn ten_vessels_are_born_from_one_layer() {
        use std::os::unix::fs::MetadataExt;
        let c = Cluster::new();
        let n1 = c.node(1, StorageKind::Zfs);
        let l = n1.ensure(c.t0).unwrap();
        let h = host(&c, &n1);
        let birth = birth_of(&l, None);
        for i in 0..10 {
            let subject = format!("v{i}");
            let id = vessel_id(NS, subject.as_bytes());
            let v = h
                .born_from_template(
                    NS,
                    subject.as_bytes(),
                    &birth,
                    &vpacks(&c, &n1, id),
                    &nofail,
                )
                .unwrap();
            assert_eq!(
                v.lineage().origin,
                Origin::Template {
                    template_id: c.t0,
                    layer_key: l.layer_key,
                    asked: None
                }
            );
            assert_eq!(v.lineage().ledger_pos, Lsn::new(0));
            assert!(h.birth_accepted(&v).unwrap());
            assert_eq!(
                accepted_birth(&c, id, v.lineage()).map(|r| r.digest()),
                Some(
                    Submitted::Birth {
                        chronicle: id,
                        lineage: v.lineage().clone()
                    }
                    .digest()
                )
            );
            // The layer's files, in the Template range, on the Vessel's
            // own dataset.
            let info = h.pool.info(v.dataset()).unwrap().unwrap();
            assert_eq!(info.parent, Some(l.layer_key));
            assert_eq!(info.origin_seal(), Some((l.dataset.clone(), LAYER_LSN)));
            let m = std::fs::metadata(info.mountpoint.unwrap().join("app/main.py")).unwrap();
            assert_eq!((m.uid(), m.gid()), (TBASE, TBASE));
            assert_eq!(v.tail().lsn, Lsn::new(1), "the Lineage only");
            assert!(
                c.coord.shipped(id).unwrap().lsn >= Lsn::new(1),
                "shipped first"
            );
        }
        // The Birth holds the layer object for each Vessel.
        assert!(c
            .coord
            .query_chronicle(vessel_id(NS, b"v3"))
            .unwrap()
            .unwrap()
            .holds
            .contains(&ObjectId::content(l.layer_key)));
        // Again: opened, nothing appended, nothing accepted twice.
        let id = vessel_id(NS, b"v0");
        let v = h
            .born_from_template(NS, b"v0", &birth, &vpacks(&c, &n1, id), &nofail)
            .unwrap();
        assert_eq!(v.tail().lsn, Lsn::new(1));
        // Opened by id, it is a Template-born Vessel with its Birth.
        drop(v);
        let (v, _) = h.open(id).unwrap();
        assert!(h.birth_accepted(&v).unwrap());
        // Asked by another name: refused, never re-born.
        drop(v);
        let other = birth_of(
            &l,
            Some(TemplateAsked {
                name: "acme".into(),
                version: 1,
            }),
        );
        assert!(matches!(
            h.born_from_template(NS, b"v0", &other, &vpacks(&c, &n1, id), &nofail),
            Err(VesselError::TemplateMismatch)
        ));
    }

    #[test]
    fn an_interrupted_birth_is_finished_and_never_runs_before_its_birth() {
        let c = Cluster::new();
        let n1 = c.node(1, StorageKind::Blk);
        let l = n1.ensure(c.t0).unwrap();
        let h = host(&c, &n1);
        let birth = birth_of(&l, None);
        for (i, at) in [
            "birth.after_clone",
            "birth.after_lineage_append",
            "birth.before_accept",
        ]
        .into_iter()
        .enumerate()
        {
            let subject = format!("f{i}");
            let id = vessel_id(NS, subject.as_bytes());
            let packs = vpacks(&c, &n1, id);
            let e = h
                .born_from_template(NS, subject.as_bytes(), &birth, &packs, &vfail(at))
                .err()
                .expect("stopped");
            assert!(
                matches!(e, VesselError::Failpoint(p) if p == at),
                "{at}: {e}"
            );
            let lineage = LineageRecord {
                origin: Origin::Template {
                    template_id: c.t0,
                    layer_key: l.layer_key,
                    asked: None,
                },
                namespace: NS,
                ledger_pos: Lsn::new(0),
            };
            assert!(
                accepted_birth(&c, id, &lineage).is_none(),
                "{at}: no Birth yet"
            );
            if at != "birth.after_clone" {
                // An open finds the Lineage without its Birth: not to run.
                let (v, _) = h.open(id).unwrap();
                assert!(!h.birth_accepted(&v).unwrap(), "{at}");
            }
            // The same call finishes it.
            let v = h
                .born_from_template(NS, subject.as_bytes(), &birth, &packs, &nofail)
                .unwrap();
            assert_eq!(v.lineage(), &lineage);
            assert_eq!(v.tail().lsn, Lsn::new(1), "{at}: one Lineage");
            assert!(h.birth_accepted(&v).unwrap(), "{at}");
        }
        // An open finishes a Birth too.
        let id = vessel_id(NS, b"g");
        let packs = vpacks(&c, &n1, id);
        h.born_from_template(NS, b"g", &birth, &packs, &vfail("birth.before_accept"))
            .err()
            .expect("stopped");
        let (mut v, _) = h.open(id).unwrap();
        h.finish_birth(&mut v, &packs, &nofail).unwrap();
        assert!(h.birth_accepted(&v).unwrap());
    }

    #[test]
    fn a_birth_needs_a_settled_layer_and_an_asked_name_that_names_it() {
        let c = Cluster::new();
        let n1 = c.node(1, StorageKind::Zfs);
        let l = n1.ensure(c.t0).unwrap();
        let h = host(&c, &n1);
        // A name that names nothing: the Birth row refuses it.
        let id = vessel_id(NS, b"n");
        let asked = birth_of(
            &l,
            Some(TemplateAsked {
                name: "acme".into(),
                version: 1,
            }),
        );
        let e = h
            .born_from_template(NS, b"n", &asked, &vpacks(&c, &n1, id), &nofail)
            .err()
            .expect("refused");
        assert!(
            matches!(
                e,
                VesselError::Birth(crate::submit::SubmitError::Refused(Final::Predicate(_)))
            ),
            "{e}"
        );
        // A layer key that is not the settled one: the clone refuses it
        // (no such bound Seal here), before anything is registered.
        let id = vessel_id(NS, b"k");
        let stray = TemplateBirth {
            template_id: c.t0,
            layer_key: HashVal::from_bytes([0x5A; 32]),
            asked: None,
        };
        assert!(matches!(
            h.born_from_template(NS, b"k", &stray, &vpacks(&c, &n1, id), &nofail),
            Err(VesselError::Pool(_))
        ));
    }

    // ── Verification attempts (P4 file 7b) ──────────────────────────

    use crate::attempt::{self, AttemptError, AttemptRun, Attempts};
    use crate::nominate::{Answer, Ask, Nominator, SanctionConf};
    use taso_core::contract::{NominatedBy, Outcome as VOutcome, PathClass};
    use taso_core::record::{StreamCut, TurnId, Verdict};

    impl Cluster {
        /// Another Template, by a genesis of `src` on node 0.
        fn template_from(&self, src: &Path) -> ChronicleId {
            let n0 = self.dir.path().join("node0");
            let g = Genesis {
                pool: DirPool {
                    root: n0.join("pool"),
                    state: Arc::default(),
                },
                store: self.store.clone(),
                prefix: PREFIX.into(),
                coord: self.coord.clone(),
                warden: WardenId::new(100),
                state_dir: n0.join("state"),
                root: Dataset::new("tank/taso").unwrap(),
                host_uid_base: BASE,
                limits: Limits::default(),
                reserved: Reserved::defaults(),
                failpoint: genesis::no_failpoints(),
            };
            let r = g
                .run(&Request {
                    source: Source::Dir(src.to_path_buf()),
                    classmap: MAP.as_bytes().to_vec(),
                    authority: Authority {
                        actor: "jarmo".into(),
                        reason: "a verifier".into(),
                    },
                    hook_waiver: None,
                    best_effort: true,
                    peer: Peer { uid: 0, pid: 1 },
                })
                .unwrap();
            let Outcome::Ready { template_id, .. } = r.outcome else {
                panic!("{:?}", r.outcome)
            };
            template_id
        }
    }

    struct Bytes;
    impl Sender for Bytes {
        fn send(&self, d: &Dataset, from: Option<&str>, to: Lsn) -> io::Result<ByteStream> {
            Ok(Box::new(Cursor::new(
                format!("{d} {from:?} {}", to.get()).into_bytes(),
            )))
        }
    }

    type FV = crate::vessel::Vessel<<crate::vessel::tests::FakePool as Pool>::Layers>;

    /// A Vessel (fake pool) with one shipped Seal, nominated with `verifier`
    /// as its verifier Template and `vconf`: its accepted Candidate.
    fn nominated(
        c: &Cluster,
        subject: &[u8],
        verifier: ChronicleId,
        vconf: &[u8],
    ) -> (
        Host<crate::vessel::tests::FakePool>,
        FV,
        Packs<SharedStore, Bytes>,
        taso_core::contract::Candidate,
    ) {
        nominated_with(c, subject, verifier, vconf, MAP)
    }

    /// [`nominated`] classifying with `map`.
    fn nominated_with(
        c: &Cluster,
        subject: &[u8],
        verifier: ChronicleId,
        vconf: &[u8],
        map: &str,
    ) -> (
        Host<crate::vessel::tests::FakePool>,
        FV,
        Packs<SharedStore, Bytes>,
        taso_core::contract::Candidate,
    ) {
        let host = Host {
            coord: c.coord.clone(),
            pool: crate::vessel::tests::FakePool::default(),
            root: Dataset::new("tank/vessels").unwrap(),
            state_dir: c.dir.path().join(format!("vstate-{}", hex(subject))),
            warden: WardenId::new(1),
        };
        let (mut v, _) = host.ensure(NS, subject).unwrap();
        let packs = Packs::new(c.store.clone(), Bytes, PREFIX, v.id()).unwrap();
        v.append(Stream::Fs, Payload::Raw(vec![1; 8])).unwrap();
        let s = v
            .seal(
                StreamCut::EMPTY,
                Verdict::Clean,
                Lsn::new(0),
                TurnId::new(1),
            )
            .unwrap()
            .seal;
        let snap = crate::zfs::Snapshot {
            dataset: v.dataset().clone(),
            seal: s.lsn,
            createtxg: 1,
            guid: crate::vessel::tests::fake_guid(s.lsn),
            seal_hash: Some(s.hash),
        };
        v.publish_seal(&packs, &snap, None).unwrap();
        // The Seal's files: one source file, owned by the Vessel's slot 1.
        let tree = c.dir.path().join(format!("seal-{}", hex(subject)));
        std::fs::create_dir_all(tree.join("app")).unwrap();
        std::fs::write(tree.join("app/main.py"), "print(1)\n").unwrap();
        let st = Command::new("chown")
            .args(["-hR", &format!("{0}:{0}", BASE + SLOT)])
            .arg(&tree)
            .status()
            .unwrap();
        assert!(st.success());
        // Whole-second times: the test pool's tar streams keep no more.
        let st = Command::new("sh")
            .arg("-c")
            .arg("find \"$0\" -mindepth 1 ! -type d -exec touch -h -d @1700000000 {} + && find \"$0\" -depth -type d -exec touch -d @1600000000 {} +")
            .arg(&tree)
            .status()
            .unwrap();
        assert!(st.success());
        let mut conf = SanctionConf::new(map.as_bytes().to_vec()).unwrap();
        conf.min_interval = Duration::ZERO;
        let n = Nominator::new(
            c.store.clone(),
            PREFIX,
            c.coord.clone(),
            WardenId::new(1),
            BASE,
            c.dir.path().join("ntmp"),
            conf,
        );
        let ask = Ask {
            seal: None,
            exclude: [PathClass::Scratch].into(),
            verifier,
            vconf: vconf.to_vec(),
            version: 1,
            by: NominatedBy::Agent,
        };
        let t = tree.clone();
        let a = n
            .nominate(&mut v, &packs, &ask, &move |_| {
                Ok(SealView::new(t.clone(), None))
            })
            .unwrap();
        let Answer::Nominated(cid) = a else {
            panic!("{a:?}")
        };
        let cand = match c
            .coord
            .query_logical(logical_id(&LogicalKey::Candidate(cid)))
            .unwrap()
        {
            Some((_, Submitted::Contract(ContractRecord::Candidate(k)))) => *k,
            other => panic!("{other:?}"),
        };
        (host, v, packs, cand)
    }

    fn attempts(c: &Cluster) -> Attempts {
        Attempts {
            coord: c.coord.clone(),
            warden: WardenId::new(1),
            failpoint: attempt::no_failpoints(),
        }
    }

    const VCONF: &[u8] = b"version = 1\nentry = [\"/bin/sh\", \"-c\", \"exit 0\"]\n";

    #[test]
    fn an_attempt_holds_the_verifier_layer_and_the_artifact_until_it_finishes() {
        let c = Cluster::new();
        let (_h, mut v, packs, cand) = nominated(&c, b"a", c.t0, VCONF);
        let at = attempts(&c);
        assert_eq!(at.to_attempt(&v).unwrap(), vec![cand.clone()]);
        let st = at.start(&mut v, &packs, &cand).unwrap();
        assert_eq!(st.started_at, Lsn::new(v.tail().lsn.get() - 1));
        let holds = c.coord.query_chronicle(v.id()).unwrap().unwrap().holds;
        let layer = match c
            .coord
            .query_logical(logical_id(&LogicalKey::Template(c.t0)))
            .unwrap()
        {
            Some((_, Submitted::Contract(ContractRecord::TemplateReady(t)))) => t.layer,
            other => panic!("{other:?}"),
        };
        assert!(holds.contains(&ObjectId::content(layer)));
        assert_eq!(at.open(&v).unwrap(), vec![st]);
        assert!(at.to_attempt(&v).unwrap().is_empty());
        // One attempt at a time.
        assert!(matches!(
            at.start(&mut v, &packs, &cand),
            Err(AttemptError::Submit(_))
        ));
        let f = at
            .finish(
                &mut v,
                &packs,
                &st,
                VOutcome::Exit { code: 0 },
                b"ok\n".to_vec(),
            )
            .unwrap();
        assert!(f.is_consistent_with(&st));
        assert!(at.open(&v).unwrap().is_empty());
        assert_eq!(at.finished(&v).unwrap(), vec![st]);
        // A finished Candidate is not attempted again by itself.
        assert!(at.to_attempt(&v).unwrap().is_empty());
    }

    /// D88: a Candidate whose attempts all ended `Interrupted` is attempted
    /// again, fewer than three times; one that ended otherwise is not.
    #[test]
    fn an_interrupted_attempt_is_run_again_up_to_three_times() {
        let c = Cluster::new();
        let (_h, mut v, packs, cand) = nominated(&c, b"a", c.t0, VCONF);
        let at = attempts(&c);
        for n in 1..=crate::attempt::MAX_INTERRUPTED {
            let st = at.start(&mut v, &packs, &cand).unwrap();
            assert!(at.to_attempt(&v).unwrap().is_empty(), "open: {n}");
            at.finish(&mut v, &packs, &st, VOutcome::Interrupted, Vec::new())
                .unwrap();
            let want = if n < crate::attempt::MAX_INTERRUPTED {
                vec![cand.clone()]
            } else {
                vec![]
            };
            assert_eq!(at.to_attempt(&v).unwrap(), want, "after {n} interrupted");
        }
        // A result about the files ends it: no rerun.
        let (_h, mut v, packs, cand) = nominated(&c, b"b", c.t0, VCONF);
        let st = at.start(&mut v, &packs, &cand).unwrap();
        at.finish(&mut v, &packs, &st, VOutcome::Interrupted, Vec::new())
            .unwrap();
        let st = at.start(&mut v, &packs, &cand).unwrap();
        at.finish(&mut v, &packs, &st, VOutcome::Exit { code: 1 }, Vec::new())
            .unwrap();
        assert!(at.to_attempt(&v).unwrap().is_empty());
    }

    #[test]
    fn a_start_stopped_before_its_accept_leaves_the_candidate_to_attempt() {
        let c = Cluster::new();
        let (_h, mut v, packs, cand) = nominated(&c, b"a", c.t0, VCONF);
        let mut at = attempts(&c);
        at.failpoint = Arc::new(|p| p == "verify.before_started_accept");
        assert!(matches!(
            at.start(&mut v, &packs, &cand),
            Err(AttemptError::Failpoint("verify.before_started_accept"))
        ));
        at.failpoint = attempt::no_failpoints();
        assert_eq!(at.to_attempt(&v).unwrap(), vec![cand.clone()]);
        assert!(at.open(&v).unwrap().is_empty());
        at.start(&mut v, &packs, &cand).unwrap();
        assert!(at.to_attempt(&v).unwrap().is_empty());
    }

    #[test]
    fn an_open_attempt_is_interrupted_by_the_next_owner_and_the_old_one_cannot_finish() {
        let c = Cluster::new();
        let (h, mut v1, packs, cand) = nominated(&c, b"a", c.t0, VCONF);
        let at = attempts(&c);
        let st = at.start(&mut v1, &packs, &cand).unwrap();
        let at2 = Attempts {
            coord: c.coord.clone(),
            warden: WardenId::new(2),
            failpoint: attempt::no_failpoints(),
        };
        // Another node takes the Vessel over (a fence) from what is shipped.
        let h2 = Host {
            coord: c.coord.clone(),
            pool: crate::vessel::tests::FakePool::default(),
            root: h.root.clone(),
            state_dir: c.dir.path().join("vstate-node2"),
            warden: WardenId::new(2),
        };
        let (mut v2, _) = h2.rebirth(v1.id(), &packs).unwrap();
        let closed = at2.interrupt_open(&mut v2, &packs).unwrap();
        assert_eq!(closed, vec![st]);
        assert!(at2.open(&v2).unwrap().is_empty());
        let f = match c
            .coord
            .query_logical(logical_id(&LogicalKey::AttemptFinished(st.attempt_id)))
            .unwrap()
        {
            Some((_, Submitted::Contract(ContractRecord::VerificationFinished(f)))) => f,
            other => panic!("{other:?}"),
        };
        assert_eq!((f.outcome, f.output.len()), (VOutcome::Interrupted, 0));
        // The old holder's late result: fenced.
        assert!(at
            .finish(&mut v1, &packs, &st, VOutcome::Exit { code: 0 }, Vec::new())
            .is_err());
        // Nothing more to interrupt.
        assert!(at2.interrupt_open(&mut v2, &packs).unwrap().is_empty());
    }

    #[test]
    fn a_start_naming_no_ready_template_is_refused() {
        let c = Cluster::new();
        let nobody = ChronicleId::from_bytes([0x42; 16]);
        let (_h, mut v, packs, cand) = nominated(&c, b"a", nobody, VCONF);
        let e = attempts(&c).start(&mut v, &packs, &cand).unwrap_err();
        assert!(
            matches!(
                &e,
                AttemptError::Submit(crate::submit::SubmitError::Refused(Final::Predicate(_)))
            ),
            "{e}"
        );
    }

    fn run_with<'a>(
        c: &'a Cluster,
        node: &'a TemplateLayers<DirPool, DirSend>,
        limits: &'a Limits,
        reserved: &'a [Reserved],
    ) -> AttemptRun<'a, DirPool, DirSend> {
        AttemptRun {
            pool: &node.pool,
            layers: node,
            store: &c.store,
            prefix: PREFIX,
            root: &node.root,
            run_dir: Box::leak(Box::new(c.dir.path().join("run"))),
            limits: crate::verify::VerifierLimits::default(),
            walk_limits: limits,
            reserved,
            failpoint: attempt::no_failpoints(),
        }
    }

    #[test]
    fn what_keeps_an_attempt_from_starting_ends_it_launch_failed() {
        let c = Cluster::new();
        let node = c.node(1, StorageKind::Zfs);
        let (limits, reserved) = (Limits::default(), Reserved::defaults());
        let run = run_with(&c, &node, &limits, &reserved);
        // A vconf that is not one.
        let (_h, mut v, packs, cand) = nominated(&c, b"a", c.t0, b"entry = [\"/bin/true\"]\n");
        let st = attempts(&c).start(&mut v, &packs, &cand).unwrap();
        let (o, out) = run.run(&st, &cand).unwrap();
        assert_eq!(o, VOutcome::LaunchFailed);
        assert!(String::from_utf8(out).unwrap().contains("version"));
        // T(0) has no mount targets (it is no verifier image).
        let (_h, mut v, packs, cand) = nominated(&c, b"b", c.t0, VCONF);
        let st = attempts(&c).start(&mut v, &packs, &cand).unwrap();
        let (o, out) = run.run(&st, &cand).unwrap();
        assert_eq!(o, VOutcome::LaunchFailed);
        assert!(
            String::from_utf8(out).unwrap().contains("no /proc"),
            "launch failed for another reason"
        );
        // No /candidate dataset was made for it.
        assert!(!attempt::destroy_candidate(&node.pool, &node.root, st.attempt_id).unwrap());
    }

    /// A verifier image: the host's `sh` and `cat` with their libraries,
    /// and the mount targets.
    fn verifier_tree(at: &Path) {
        for d in ["proc", "dev", "sys", "tmp", "candidate", "bin"] {
            std::fs::create_dir_all(at.join(d)).unwrap();
        }
        for b in ["sh", "cat"] {
            let host = Command::new("sh")
                .arg("-c")
                .arg(format!("command -v {b}"))
                .output()
                .unwrap();
            let host = PathBuf::from(String::from_utf8(host.stdout).unwrap().trim());
            let host = std::fs::canonicalize(host).unwrap();
            std::fs::copy(&host, at.join("bin").join(b)).unwrap();
            let libs = Command::new("ldd").arg(&host).output().unwrap();
            for l in String::from_utf8_lossy(&libs.stdout).split_whitespace() {
                if l.starts_with('/') {
                    let dest = at.join(l.trim_start_matches('/'));
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    std::fs::copy(l, &dest).unwrap();
                }
            }
        }
        let st = Command::new("chown")
            .args(["-hR", "0:0"])
            .arg(at)
            .status()
            .unwrap();
        assert!(st.success());
        // Whole-second times: the test pool's tar streams keep no more.
        let st = Command::new("sh")
            .arg("-c")
            .arg("find \"$0\" -mindepth 1 ! -type d -exec touch -h -d @1700000000 {} + && find \"$0\" -depth -type d -exec touch -d @1600000000 {} +")
            .arg(at)
            .status()
            .unwrap();
        assert!(st.success());
    }

    /// The whole attempt, in a real container (as root, with runc and
    /// user namespaces): the verifier reads `/candidate`, cannot write it,
    /// and its exit status and output are the attempt's; `/candidate` is a
    /// dataset destroyed once the attempt is finished.
    #[test]
    #[ignore = "needs root, runc and user namespaces"]
    fn a_verifier_reads_the_candidate_and_its_exit_is_the_outcome() {
        let c = Cluster::new();
        let vt = c.dir.path().join("verifier");
        verifier_tree(&vt);
        let verifier = c.template_from(&vt);
        let node = c.node(1, StorageKind::Zfs);
        let (limits, reserved) = (Limits::default(), Reserved::defaults());
        let run = run_with(&c, &node, &limits, &reserved);
        let script = b"version = 1\nentry = [\"/bin/sh\", \"-c\", \"cat /candidate/app/main.py; if echo x > /candidate/x 2>/dev/null; then exit 9; fi; exit 3\"]\n";
        let (_h, mut v, packs, cand) = nominated(&c, b"a", verifier, script);
        let at = attempts(&c);
        let st = at.start(&mut v, &packs, &cand).unwrap();
        let (o, out) = run.run(&st, &cand).unwrap();
        assert_eq!(
            o,
            VOutcome::Exit { code: 3 },
            "{}",
            String::from_utf8_lossy(&out)
        );
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("print(1)\n"), "{text}");
        assert!(text.contains("Read-only file system"), "{text}");
        at.finish(&mut v, &packs, &st, o, out).unwrap();
        assert!(attempt::destroy_candidate(&node.pool, &node.root, st.attempt_id).unwrap());
    }

    // ── Verdicts (P4 file 8a) ───────────────────────────────────────

    use crate::verdict::{self, RetryReason, VerdictAnswer, VerdictError, Verdicts};
    use taso_core::contract::{
        template_id as template_id_of, Decision, Refusal, VerdictRequest, VerificationFinished,
    };

    const PEER: Peer = Peer { uid: 0, pid: 4242 };

    fn verdicts(c: &Cluster) -> Verdicts {
        Verdicts {
            coord: c.coord.clone(),
            warden: WardenId::new(1),
            failpoint: attempt::no_failpoints(),
        }
    }

    /// A request by `PEER` for `cand`, naming `f`'s attempt and result.
    fn request(
        cand: &taso_core::contract::Candidate,
        f: &VerificationFinished,
        decision: Decision,
    ) -> VerdictRequest {
        let mut r = VerdictRequest {
            request_id: HashVal::from_bytes([0; 32]),
            candidate_id: cand.candidate_id,
            facts_hash: cand.facts_hash,
            artifact_key: cand.artifact_key,
            requirement: cand.requirement,
            exclude: cand.exclude.clone(),
            attempt_id: f.attempt_id,
            result_digest: f.result_digest,
            decision,
            authority: Authority {
                actor: "jarmo".into(),
                reason: "reviewed".into(),
            },
            policy_digest: None,
        };
        r.request_id = taso_core::contract::request_id(
            PEER.uid,
            taso_core::contract::OpKind::Verdict,
            &r.body(),
        );
        r
    }

    /// One finished attempt of `cand` ending `o`.
    fn attempted(
        c: &Cluster,
        v: &mut FV,
        packs: &Packs<SharedStore, Bytes>,
        cand: &taso_core::contract::Candidate,
        o: VOutcome,
    ) -> VerificationFinished {
        let at = attempts(c);
        let st = at.start(v, packs, cand).unwrap();
        at.finish(v, packs, &st, o, b"out\n".to_vec()).unwrap()
    }

    fn sanction_of(c: &Cluster, cid: HashVal) -> Option<taso_core::contract::SanctionCommitted> {
        match c
            .coord
            .query_logical(logical_id(&LogicalKey::Sanction(cid)))
            .unwrap()
        {
            Some((_, Submitted::Contract(ContractRecord::SanctionCommitted(s)))) => Some(s),
            None => None,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_sanction_of_a_passed_attempt_commits_once() {
        let c = Cluster::new();
        let (_h, mut v, packs, cand) = nominated(&c, b"a", c.t0, VCONF);
        let vd = verdicts(&c);
        let cid = cand.candidate_id;
        // Nothing to decide before an attempt has finished (D73).
        let frames = v.chronicle().frames().unwrap();
        assert!(verdict::pending(c.coord.as_ref(), &frames)
            .unwrap()
            .is_empty());
        let f = attempted(&c, &mut v, &packs, &cand, VOutcome::Exit { code: 0 });
        let frames = v.chronicle().frames().unwrap();
        let p = verdict::pending(c.coord.as_ref(), &frames).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].candidate, cand);
        assert_eq!(p[0].attempts[0].1, f);
        let r = request(&cand, &f, Decision::Sanction);
        let verdict_id = logical_id(&LogicalKey::Verdict(r.request_id));
        let a = vd.handle(&mut v, &packs, &r, PEER).unwrap();
        let tid = template_id_of(cid, verdict_id);
        assert_eq!(a, VerdictAnswer::Committed { template_id: tid });
        let s = sanction_of(&c, cid).unwrap();
        assert!(s.is_consistent());
        assert_eq!(
            (s.template_id, s.attempt_id, s.result_digest, s.verdict),
            (tid, f.attempt_id, f.result_digest, verdict_id)
        );
        assert_eq!(s.parent_template, None, "a Vessel born from the void");
        assert_eq!(
            (
                s.artifact_key,
                s.output_manifest_key,
                s.classmap_key,
                s.vconf_key
            ),
            (
                cand.artifact_key,
                cand.output_manifest_key,
                cand.classmap_key,
                cand.requirement.vconf_key
            )
        );
        // The same request again, and any other: the commit answers.
        let tail = v.tail().lsn;
        assert_eq!(vd.handle(&mut v, &packs, &r, PEER).unwrap(), a);
        let hold = request(&cand, &f, Decision::Hold);
        assert_eq!(vd.handle(&mut v, &packs, &hold, PEER).unwrap(), a);
        assert_eq!(v.tail().lsn, tail, "nothing more recorded");
        let frames = v.chronicle().frames().unwrap();
        assert!(verdict::pending(c.coord.as_ref(), &frames)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn step_one_records_the_permanent_refusals() {
        let c = Cluster::new();
        let (_h, mut v, packs, cand) = nominated(&c, b"a", c.t0, VCONF);
        let vd = verdicts(&c);
        let f = attempted(&c, &mut v, &packs, &cand, VOutcome::Exit { code: 3 });
        // A request whose id is not its peer's: nothing recorded.
        let r = request(&cand, &f, Decision::Sanction);
        let tail = v.tail().lsn;
        assert!(matches!(
            vd.handle(&mut v, &packs, &r, Peer { uid: 7, pid: 1 }),
            Err(VerdictError::BadRequestId)
        ));
        assert_eq!(v.tail().lsn, tail);
        // A failed attempt is not sanctioned, for good.
        assert_eq!(
            vd.handle(&mut v, &packs, &r, PEER).unwrap(),
            VerdictAnswer::Refused(Refusal::AttemptNotPassed)
        );
        let tail = v.tail().lsn;
        assert_eq!(
            vd.handle(&mut v, &packs, &r, PEER).unwrap(),
            VerdictAnswer::Refused(Refusal::AttemptNotPassed)
        );
        assert_eq!(v.tail().lsn, tail, "a retry answers from the log");
        match c
            .coord
            .query_logical(logical_id(&LogicalKey::Verdict(r.request_id)))
            .unwrap()
        {
            Some((_, Submitted::Contract(ContractRecord::Refused(x)))) => {
                assert_eq!(
                    (x.rule, x.peer, x.candidate_id),
                    (Refusal::AttemptNotPassed, PEER, cand.candidate_id)
                )
            }
            other => panic!("{other:?}"),
        }
        // Stale facts; a result that is not the attempt's.
        let mut stale = request(&cand, &f, Decision::Hold);
        stale.facts_hash = HashVal::from_bytes([9; 32]);
        stale.request_id = taso_core::contract::request_id(
            PEER.uid,
            taso_core::contract::OpKind::Verdict,
            &stale.body(),
        );
        assert_eq!(
            vd.handle(&mut v, &packs, &stale, PEER).unwrap(),
            VerdictAnswer::Refused(Refusal::StaleFacts)
        );
        let mut wrong = request(&cand, &f, Decision::Hold);
        wrong.result_digest = HashVal::from_bytes([8; 32]);
        wrong.request_id = taso_core::contract::request_id(
            PEER.uid,
            taso_core::contract::OpKind::Verdict,
            &wrong.body(),
        );
        assert_eq!(
            vd.handle(&mut v, &packs, &wrong, PEER).unwrap(),
            VerdictAnswer::Refused(Refusal::WrongAttempt)
        );
        // A Hold of the failed attempt is recorded; a Never closes.
        let hold = request(&cand, &f, Decision::Hold);
        assert_eq!(
            vd.handle(&mut v, &packs, &hold, PEER).unwrap(),
            VerdictAnswer::Held
        );
        let never = request(
            &cand,
            &f,
            Decision::Never {
                reason: "exits 3".into(),
            },
        );
        assert_eq!(
            vd.handle(&mut v, &packs, &never, PEER).unwrap(),
            VerdictAnswer::ClosedNever
        );
        assert_eq!(
            vd.handle(&mut v, &packs, &never, PEER).unwrap(),
            VerdictAnswer::ClosedNever
        );
        let frames = v.chronicle().frames().unwrap();
        assert!(verdict::pending(c.coord.as_ref(), &frames)
            .unwrap()
            .is_empty());
        // After the close: Closed, for any new request.
        let other = request(
            &cand,
            &f,
            Decision::Never {
                reason: "again".into(),
            },
        );
        assert_eq!(
            vd.handle(&mut v, &packs, &other, PEER).unwrap(),
            VerdictAnswer::Refused(Refusal::Closed)
        );
        assert!(sanction_of(&c, cand.candidate_id).is_none());
    }

    /// A hostile caller (a policy that sanctions anything): a Candidate
    /// with a secret in its input is never sanctioned, whatever it asks.
    #[test]
    fn a_sanction_against_the_hard_rules_is_refused_for_good() {
        let c = Cluster::new();
        let map = "version = 1\n[[rule]]\nglob = \"**\"\nclass = \"Source\"\n[[rule]]\nglob = \"app/main.py\"\nclass = \"Secret\"\n";
        let (_h, mut v, packs, cand) = nominated_with(&c, b"a", c.t0, VCONF, map);
        assert_eq!(cand.facts.input.secret, 1);
        let f = attempted(&c, &mut v, &packs, &cand, VOutcome::Exit { code: 0 });
        let r = request(&cand, &f, Decision::Sanction);
        let vd = verdicts(&c);
        assert_eq!(
            vd.handle(&mut v, &packs, &r, PEER).unwrap(),
            VerdictAnswer::Refused(Refusal::HardRules)
        );
        assert_eq!(
            vd.handle(&mut v, &packs, &r, PEER).unwrap(),
            VerdictAnswer::Refused(Refusal::HardRules),
            "again: the same, from the log"
        );
        assert!(sanction_of(&c, cand.candidate_id).is_none());
        // Never is still the caller's to say.
        let never = request(
            &cand,
            &f,
            Decision::Never {
                reason: "secret".into(),
            },
        );
        assert_eq!(
            vd.handle(&mut v, &packs, &never, PEER).unwrap(),
            VerdictAnswer::ClosedNever
        );
    }

    #[test]
    fn what_can_still_change_is_answered_and_a_retry_continues() {
        let c = Cluster::new();
        let (_h, mut v, packs, cand) = nominated(&c, b"a", c.t0, VCONF);
        let vd = verdicts(&c);
        let at = attempts(&c);
        let f1 = attempted(&c, &mut v, &packs, &cand, VOutcome::Exit { code: 0 });
        let st2 = at.start(&mut v, &packs, &cand).unwrap();
        let sanction = request(&cand, &f1, Decision::Sanction);
        assert!(matches!(
            vd.handle(&mut v, &packs, &sanction, PEER).unwrap(),
            VerdictAnswer::Retry(RetryReason::Rule(Refusal::OpenAttempt))
        ));
        let never = request(
            &cand,
            &f1,
            Decision::Never {
                reason: "no".into(),
            },
        );
        assert_eq!(
            vd.handle(&mut v, &packs, &never, PEER).unwrap(),
            VerdictAnswer::Retry(RetryReason::Rule(Refusal::OpenAttempt))
        );
        // The later attempt fails: the same request, sent again, is
        // answered from its recorded VerdictSubmitted.
        at.finish(&mut v, &packs, &st2, VOutcome::Exit { code: 1 }, Vec::new())
            .unwrap();
        let tail = v.tail().lsn;
        assert!(matches!(
            vd.handle(&mut v, &packs, &sanction, PEER).unwrap(),
            VerdictAnswer::Retry(RetryReason::Rule(Refusal::LaterAttemptFailed))
        ));
        assert_eq!(v.tail().lsn, tail, "nothing more recorded");
        // The Never, retried, now closes.
        assert_eq!(
            vd.handle(&mut v, &packs, &never, PEER).unwrap(),
            VerdictAnswer::ClosedNever
        );
        assert!(sanction_of(&c, cand.candidate_id).is_none());
        // The recorded Sanction, sent again after the close: final (D86).
        assert!(matches!(
            vd.handle(&mut v, &packs, &sanction, PEER).unwrap(),
            VerdictAnswer::Refused(Refusal::Closed)
        ));
    }

    #[test]
    fn a_verdict_stopped_at_a_failpoint_is_finished_by_sending_it_again() {
        for point in verdict::FAILPOINTS {
            let c = Cluster::new();
            let (_h, mut v, packs, cand) = nominated(&c, b"a", c.t0, VCONF);
            let f = attempted(&c, &mut v, &packs, &cand, VOutcome::Exit { code: 0 });
            let r = request(&cand, &f, Decision::Sanction);
            let mut vd = verdicts(&c);
            vd.failpoint = Arc::new(move |p| p == point);
            assert!(
                matches!(vd.handle(&mut v, &packs, &r, PEER), Err(VerdictError::Failpoint(p)) if p == point)
            );
            assert!(sanction_of(&c, cand.candidate_id).is_none());
            let vd = verdicts(&c);
            assert!(matches!(
                vd.handle(&mut v, &packs, &r, PEER).unwrap(),
                VerdictAnswer::Committed { .. }
            ));
        }
    }

    // ── Finishing a sanction (P4 file 9a) ───────────────────────────

    use crate::finish::{FinishError, Finisher};
    use taso_core::contract::BornFrom;

    fn finisher(c: &Cluster, warden: u64) -> Finisher {
        Finisher {
            coord: c.coord.clone(),
            store: c.store.clone(),
            prefix: PREFIX.into(),
            warden: WardenId::new(warden),
            state_dir: c.dir.path().join(format!("fstate{warden}")),
            claim_wait: Duration::ZERO,
            failpoint: attempt::no_failpoints(),
        }
    }

    /// A Vessel whose Candidate is committed: (host, vessel, packs, commit).
    fn committed(
        c: &Cluster,
        subject: &[u8],
    ) -> (
        Host<crate::vessel::tests::FakePool>,
        FV,
        Packs<SharedStore, Bytes>,
        taso_core::contract::SanctionCommitted,
    ) {
        let (h, mut v, packs, cand) = nominated(c, subject, c.t0, VCONF);
        let f = attempted(c, &mut v, &packs, &cand, VOutcome::Exit { code: 0 });
        let r = request(&cand, &f, Decision::Sanction);
        let a = verdicts(c).handle(&mut v, &packs, &r, PEER).unwrap();
        assert!(matches!(a, VerdictAnswer::Committed { .. }), "{a:?}");
        let s = sanction_of(c, cand.candidate_id).unwrap();
        (h, v, packs, s)
    }

    fn ready_of(c: &Cluster, t: ChronicleId) -> Option<TemplateReady> {
        match c
            .coord
            .query_logical(logical_id(&LogicalKey::Template(t)))
            .unwrap()
        {
            Some((_, Submitted::Contract(ContractRecord::TemplateReady(r)))) => Some(*r),
            None => None,
            other => panic!("{other:?}"),
        }
    }

    fn completed(c: &Cluster, t: ChronicleId) -> bool {
        c.coord
            .query_logical(logical_id(&LogicalKey::SanctionCompleted(t)))
            .unwrap()
            .is_some()
    }

    #[test]
    fn a_commit_finishes_into_a_template_a_node_builds() {
        let c = Cluster::new();
        let (_h, mut v, packs, s) = committed(&c, b"a");
        let fin = finisher(&c, 1);
        assert_eq!(fin.unfinished(&v).unwrap(), vec![s]);
        let done = fin.finish(&mut v, &packs, &s).unwrap();
        assert_eq!((done.template_id, done.notes.len()), (s.template_id, 0));
        let t = ready_of(&c, s.template_id).unwrap();
        assert_eq!(
            t.born_from,
            BornFrom::Sanction {
                source: v.id(),
                candidate_id: s.candidate_id,
                verdict: s.verdict
            }
        );
        assert_eq!(
            (
                t.layer,
                t.output_manifest_key,
                t.classmap_key,
                t.vconf_key,
                t.parent_template
            ),
            (
                s.artifact_key,
                s.output_manifest_key,
                s.classmap_key,
                Some(s.vconf_key),
                None
            )
        );
        assert_eq!(t.authority.actor, "jarmo", "the verdict's authority (D79)");
        assert!(completed(&c, s.template_id));
        assert!(fin.unfinished(&v).unwrap().is_empty());
        // Again: nothing more recorded.
        let tail = v.tail().lsn;
        fin.finish(&mut v, &packs, &s).unwrap();
        assert_eq!(v.tail().lsn, tail);
        // The Template's holds keep its definition; a node builds its layer.
        let node = c.node(1, StorageKind::Zfs);
        let l = node.ensure(s.template_id).unwrap();
        assert_eq!(l.template_id, s.template_id);
        match c
            .coord
            .query_logical(logical_id(&LogicalKey::Layer(
                s.template_id,
                StorageKind::Zfs,
            )))
            .unwrap()
        {
            Some((_, Submitted::Contract(ContractRecord::LayerShipped(x)))) => {
                assert_eq!((x.layer_key, x.guid), (l.layer_key, l.guid))
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn each_finish_failpoint_stops_and_a_rerun_finishes_once() {
        for point in &crate::finish::FAILPOINTS[1..] {
            let c = Cluster::new();
            let (_h, mut v, packs, s) = committed(&c, b"a");
            let mut fin = finisher(&c, 1);
            let p = *point;
            fin.failpoint = Arc::new(move |q| q == p);
            match fin.finish(&mut v, &packs, &s) {
                Err(FinishError::Failpoint(q)) => assert_eq!(q, p),
                other => panic!("{p}: {other:?}"),
            }
            let ready = ready_of(&c, s.template_id).is_some();
            let want_ready = matches!(
                p,
                "sanction.after_ready_accept" | "sanction.before_completed_accept"
            );
            assert_eq!(ready, want_ready, "{p}");
            assert!(!completed(&c, s.template_id), "{p}");
            assert_eq!(fin.unfinished(&v).unwrap(), vec![s], "{p}");
            let fin = finisher(&c, 1);
            fin.finish(&mut v, &packs, &s).unwrap();
            assert!(completed(&c, s.template_id), "{p}");
            assert!(fin.unfinished(&v).unwrap().is_empty(), "{p}");
        }
    }

    #[test]
    fn a_target_claimed_by_a_lost_node_is_taken_over_with_the_commits_authority() {
        let c = Cluster::new();
        let (h, mut v1, packs, s) = committed(&c, b"a");
        let mut f1 = finisher(&c, 1);
        f1.failpoint = Arc::new(|q| q == "sanction.after_target_put");
        assert!(matches!(
            f1.finish(&mut v1, &packs, &s),
            Err(FinishError::Failpoint("sanction.after_target_put"))
        ));
        // Node 1 is lost; node 2 takes the source over from what is
        // shipped, and finds the commit unfinished (step 6).
        let h2 = Host {
            coord: c.coord.clone(),
            pool: crate::vessel::tests::FakePool::default(),
            root: h.root.clone(),
            state_dir: c.dir.path().join("vstate-node2"),
            warden: WardenId::new(2),
        };
        let (mut v2, _) = h2.rebirth(v1.id(), &packs).unwrap();
        let f2 = finisher(&c, 2);
        assert_eq!(f2.unfinished(&v2).unwrap(), vec![s]);
        let done = f2.finish(&mut v2, &packs, &s).unwrap();
        assert!(
            done.notes
                .iter()
                .any(|n| n.contains("took Template") && n.contains("from Warden 1")),
            "{:?}",
            done.notes
        );
        assert!(ready_of(&c, s.template_id).is_some());
        assert!(completed(&c, s.template_id));
        let own = c.coord.ownership(s.template_id).unwrap();
        assert_eq!(own.holder, WardenId::new(2));
        // The lost node, back, finds it finished: nothing to do.
        let f1 = finisher(&c, 1);
        assert!(f1.unfinished(&v1).unwrap().is_empty());
        // A takeover needs the commit's authority: another is refused.
        assert!(c
            .coord
            .takeover_target(
                s.template_id,
                WardenId::new(3),
                taso_core::coordlog::ClaimAuthority::Sanction {
                    commit: HashVal::from_bytes([9; 32])
                },
                own.epoch
            )
            .is_err());
    }

    /// D87: Warden 1, fenced, carries on its finish after Warden 2 has
    /// published the Template; it learns that another Warden finished it
    /// and stops with no error.
    #[test]
    fn a_fenced_finisher_learns_that_another_warden_finished() {
        let c = Cluster::new();
        let (h, mut v1, packs, s) = committed(&c, b"a");
        let mut f1 = finisher(&c, 1);
        f1.failpoint = Arc::new(|q| q == "sanction.after_target_put");
        assert!(matches!(
            f1.finish(&mut v1, &packs, &s),
            Err(FinishError::Failpoint("sanction.after_target_put"))
        ));
        let h2 = Host {
            coord: c.coord.clone(),
            pool: crate::vessel::tests::FakePool::default(),
            root: h.root.clone(),
            state_dir: c.dir.path().join("vstate-node2"),
            warden: WardenId::new(2),
        };
        let (mut v2, _) = h2.rebirth(v1.id(), &packs).unwrap();
        // Warden 2 publishes the Template and stops before completing.
        let mut f2 = finisher(&c, 2);
        f2.failpoint = Arc::new(|q| q == "sanction.before_completed_accept");
        assert!(matches!(
            f2.finish(&mut v2, &packs, &s),
            Err(FinishError::Failpoint("sanction.before_completed_accept"))
        ));
        assert!(ready_of(&c, s.template_id).is_some());
        // Warden 1 carries on: fenced on the source, it is told.
        let done = finisher(&c, 1).finish(&mut v1, &packs, &s).unwrap();
        assert!(done.elsewhere, "{:?}", done.notes);
        assert!(!completed(&c, s.template_id));
        // Warden 2's next open completes it.
        let done = finisher(&c, 2).finish(&mut v2, &packs, &s).unwrap();
        assert!(!done.elsewhere);
        assert!(completed(&c, s.template_id));
    }

    // ── Purge (P4 file 11) ──────────────────────────────────────────

    use crate::purge::{PurgeError, Purged, Purger};
    use taso_core::contract::PurgeBlocker;

    fn purger(c: &Cluster) -> Purger {
        Purger {
            coord: c.coord.clone(),
            store: c.store.clone(),
            prefix: PREFIX.into(),
            warden: WardenId::new(1),
            failpoint: attempt::no_failpoints(),
        }
    }

    fn fs_pack_names(packs: &Packs<SharedStore, Bytes>) -> (Vec<String>, Vec<String>) {
        let names = packs.pack_names().unwrap();
        let (fs, log): (Vec<String>, Vec<String>) = names
            .into_iter()
            .partition(|n| crate::pack::name_bounds(n).is_some_and(|(_, _, f)| f.is_some()));
        (fs, log)
    }

    #[test]
    fn a_vessel_is_purged_to_log_only_packs_and_its_dataset_is_gone() {
        let c = Cluster::new();
        let (h, mut v, packs, _cand) = nominated(&c, b"a", c.t0, VCONF);
        let (fs_before, _) = fs_pack_names(&packs);
        assert_eq!(fs_before.len(), 1, "one shipped Seal with an fs section");
        assert!(h.pool.guid(v.dataset()).unwrap().is_some());
        let p = purger(&c);
        let out = p.purge(&h.pool, &mut v, &packs).unwrap();
        let Purged::Complete { items, attestation } = out.clone() else {
            panic!("{out:?}")
        };
        assert_eq!(items, 1);
        let view = c.coord.query_chronicle(v.id()).unwrap().unwrap();
        assert!(view.retired);
        let (fs_after, _) = fs_pack_names(&packs);
        assert!(fs_after.is_empty(), "{fs_after:?}");
        let replacement = taso_core::contract::replacement_name(&fs_before[0]).unwrap();
        assert!(packs.has_pack(&replacement).unwrap());
        // The history still reads and verifies, without the section.
        let anchor = c.coord.shipped(v.id()).unwrap();
        assert!(packs.chain(Some(anchor)).is_err(), "the section is gone");
        let purged: std::collections::BTreeSet<Lsn> = [v.last_seal().unwrap().lsn].into();
        let chain = packs.chain_after_purge(Some(anchor), &purged).unwrap();
        // The attestation is of the history before PurgeComplete.
        let end = chain
            .frames
            .iter()
            .position(|f| {
                matches!(
                    Payload::decode(&f.payload),
                    Ok(Payload::Contract(r)) if matches!(*r, ContractRecord::PurgeComplete(_))
                )
            })
            .unwrap();
        assert_eq!(
            crate::pack::frames_digest(&chain.frames[..end]),
            attestation
        );
        // Local state gone; the log stays.
        assert_eq!(h.pool.guid(v.dataset()).unwrap(), None);
        // Again: the same answer, nothing more recorded.
        let tail = v.tail().lsn;
        assert_eq!(p.purge(&h.pool, &mut v, &packs).unwrap(), out);
        assert_eq!(v.tail().lsn, tail);
    }

    #[test]
    fn what_blocks_a_purge_is_answered_and_nothing_recorded() {
        let c = Cluster::new();
        let (h, mut v, packs, cand) = nominated(&c, b"a", c.t0, VCONF);
        let p = purger(&c);
        let at = attempts(&c);
        // An open attempt.
        let st = at.start(&mut v, &packs, &cand).unwrap();
        let tail = v.tail().lsn;
        assert_eq!(
            p.purge(&h.pool, &mut v, &packs).unwrap(),
            Purged::Blocked(PurgeBlocker::OpenAttempt)
        );
        // D85: the Warden records nothing while a purge is blocked; explain
        // asks the coordinator what blocks it now.
        assert_eq!(v.tail().lsn, tail);
        let e = crate::explain::explain(
            c.coord.as_ref(),
            &c.store,
            PREFIX,
            crate::explain::Subject::Chronicle(v.id()),
        )
        .unwrap();
        assert_eq!(
            e.explain["purge"]["blocked_now"],
            serde_json::json!("OpenAttempt")
        );
        let f = at
            .finish(&mut v, &packs, &st, VOutcome::Exit { code: 0 }, Vec::new())
            .unwrap();
        // A retention pin.
        c.coord.set_retention_pin(v.id(), true).unwrap();
        assert_eq!(
            p.purge(&h.pool, &mut v, &packs).unwrap(),
            Purged::Blocked(PurgeBlocker::RetentionPin)
        );
        c.coord.set_retention_pin(v.id(), false).unwrap();
        // A committed sanction not finished.
        let r = request(&cand, &f, Decision::Sanction);
        assert!(matches!(
            verdicts(&c).handle(&mut v, &packs, &r, PEER).unwrap(),
            VerdictAnswer::Committed { .. }
        ));
        assert_eq!(
            p.purge(&h.pool, &mut v, &packs).unwrap(),
            Purged::Blocked(PurgeBlocker::OpenSanction {
                candidate_id: cand.candidate_id
            })
        );
        assert!(!c.coord.query_chronicle(v.id()).unwrap().unwrap().retired);
        // Once its Template is ready, nothing keeps it (the daemon keeps a
        // sanctioned Vessel by its own rule, D81).
        let s = sanction_of(&c, cand.candidate_id).unwrap();
        finisher(&c, 1).finish(&mut v, &packs, &s).unwrap();
        assert!(matches!(
            p.purge(&h.pool, &mut v, &packs).unwrap(),
            Purged::Complete { .. }
        ));
        // The Template is untouched: its layer still builds on a node.
        c.node(1, StorageKind::Zfs).ensure(s.template_id).unwrap();
    }

    #[test]
    fn each_purge_failpoint_stops_and_a_rerun_completes_once() {
        for point in crate::purge::FAILPOINTS {
            let c = Cluster::new();
            let (h, mut v, packs, _cand) = nominated(&c, b"a", c.t0, VCONF);
            let mut p = purger(&c);
            p.failpoint = Arc::new(move |q| q == point);
            match p.purge(&h.pool, &mut v, &packs) {
                Err(PurgeError::Failpoint(q)) => assert_eq!(q, point),
                other => panic!("{point}: {other:?}"),
            }
            let p = purger(&c);
            let out = p.purge(&h.pool, &mut v, &packs).unwrap();
            assert!(
                matches!(out, Purged::Complete { items: 1, .. }),
                "{point}: {out:?}"
            );
            let (fs_after, _) = fs_pack_names(&packs);
            assert!(fs_after.is_empty(), "{point}");
            assert_eq!(h.pool.guid(v.dataset()).unwrap(), None, "{point}");
        }
    }

    #[test]
    fn an_item_lost_after_the_commit_is_recorded_and_the_purge_is_damaged() {
        let c = Cluster::new();
        let (h, mut v, packs, _cand) = nominated(&c, b"a", c.t0, VCONF);
        let (fs, _) = fs_pack_names(&packs);
        let mut p = purger(&c);
        p.failpoint = Arc::new(|q| q == "purge.after_accept");
        assert!(matches!(
            p.purge(&h.pool, &mut v, &packs),
            Err(PurgeError::Failpoint("purge.after_accept"))
        ));
        // The original is lost from the store before anything replaced it.
        let key = format!("{PREFIX}/{}/pack/{}", hex(v.id().as_bytes()), fs[0]);
        assert!(c.store.delete(&key).unwrap());
        let out = purger(&c).purge(&h.pool, &mut v, &packs).unwrap();
        assert_eq!(
            out,
            Purged::Damaged {
                replaced: 0,
                lost: 1
            }
        );
        // Never fabricated: no replacement.
        let r = taso_core::contract::replacement_name(&fs[0]).unwrap();
        assert!(!packs.has_pack(&r).unwrap());
        assert!(c.coord.query_chronicle(v.id()).unwrap().unwrap().retired);
    }

    // ── explain (P4 file 12) ────────────────────────────────────────

    use crate::explain::{explain, Subject};
    use serde_json::{json, Value};

    fn explained(c: &Cluster, s: Subject) -> crate::explain::Explained {
        explain(c.coord.as_ref(), &c.store, PREFIX, s).unwrap()
    }

    #[test]
    fn explain_rebuilds_a_sanction_and_every_check_holds() {
        let c = Cluster::new();
        let (_h, mut v, packs, s) = committed(&c, b"a");
        // Committed, not finished: what it waits for.
        let e = explained(&c, Subject::Chronicle(v.id()));
        assert!(e.failed().is_empty(), "{:?}", e.failed());
        let cand = &e.explain["candidates"][0];
        assert_eq!(cand["candidate_id"], json!(s.candidate_id.to_string()));
        assert_eq!(cand["outcome"]["sanctioned"]["ready"], json!(false));
        assert!(cand["pending_reason"]
            .as_str()
            .unwrap()
            .contains("TemplateReady"));
        assert_eq!(cand["attempts"][0]["outcome"], json!("Exit { code: 0 }"));
        assert_eq!(cand["verdicts"][0]["decision"], json!("sanction"));
        assert_eq!(cand["verdicts"][0]["actor"], json!("jarmo"));
        assert_eq!(cand["verdicts"][0]["peer"]["pid"], json!(4242));
        finisher(&c, 1).finish(&mut v, &packs, &s).unwrap();
        let e = explained(&c, Subject::Chronicle(v.id()));
        assert!(e.failed().is_empty(), "{:?}", e.failed());
        let cand = &e.explain["candidates"][0];
        assert_eq!(cand["outcome"]["sanctioned"]["completed"], json!(true));
        assert_eq!(cand["pending_reason"], Value::Null);
        // Every kind of check was made.
        for kind in ["intact:", "carried:", "derived:", "content:"] {
            assert!(e.checks.iter().any(|k| k.what.starts_with(kind)), "{kind}");
        }
        // The Template: its definition and the trail it was born from.
        let t = explained(&c, Subject::Chronicle(s.template_id));
        assert!(t.failed().is_empty(), "{:?}", t.failed());
        assert_eq!(
            t.explain["born_from"]["sanction"]["trail"]["candidate_id"],
            json!(s.candidate_id.to_string())
        );
        // The Candidate alone.
        let k = explained(&c, Subject::Candidate(s.candidate_id));
        assert_eq!(k.explain["candidates"].as_array().unwrap().len(), 1);
        // T(0), a genesis: no track record.
        let g = explained(&c, Subject::Chronicle(c.t0));
        assert!(g.explain["born_from"]["genesis"]["note"]
            .as_str()
            .unwrap()
            .contains("no track record"));
    }

    #[test]
    fn explain_fails_its_checks_on_what_was_changed_after_acceptance() {
        let c = Cluster::new();
        let (_h, v, _packs, cand) = nominated(&c, b"a", c.t0, VCONF);
        assert!(explained(&c, Subject::Chronicle(v.id()))
            .failed()
            .is_empty());
        // A content object changed in the store.
        let path = crate::coordstore::object_key_path(
            PREFIX,
            ObjectKind::Manifest,
            cand.output_manifest_key,
        )
        .unwrap();
        c.store
            .put(&path, &mut Cursor::new(b"tampered".to_vec()))
            .unwrap();
        let e = explained(&c, Subject::Chronicle(v.id()));
        let failed: Vec<String> = e.failed().iter().map(|k| k.what.clone()).collect();
        // Nothing was excluded, so the input manifest is the output's: the
        // one object fails both checks that name it, and nothing else.
        assert_eq!(cand.input_manifest_key, cand.output_manifest_key);
        assert_eq!(failed.len(), 2, "{failed:?}");
        assert!(
            failed
                .iter()
                .all(|w| w.starts_with("content: ") && w.ends_with(&path)),
            "{failed:?}"
        );
        // A pack that carried a record, rewritten without it.
        let view = c.coord.query_chronicle(v.id()).unwrap().unwrap();
        let e0 = c
            .coord
            .query_entry(*view.accepted.last().unwrap())
            .unwrap()
            .unwrap();
        let key = format!("{PREFIX}/{}/pack/{}", hex(v.id().as_bytes()), e0.pack);
        c.store
            .put(&key, &mut Cursor::new(b"not a pack".to_vec()))
            .unwrap();
        let e = explained(&c, Subject::Chronicle(v.id()));
        assert!(
            e.failed().iter().any(|k| k.what.starts_with("carried:")),
            "{:?}",
            e.failed()
        );
        // The explanation is still given.
        assert_eq!(
            e.explain["candidates"][0]["candidate_id"],
            json!(cand.candidate_id.to_string())
        );
    }

    #[test]
    fn explain_tells_a_purge_and_a_never() {
        let c = Cluster::new();
        let (h, mut v, packs, cand) = nominated(&c, b"a", c.t0, VCONF);
        let f = attempted(&c, &mut v, &packs, &cand, VOutcome::Exit { code: 3 });
        let never = request(
            &cand,
            &f,
            Decision::Never {
                reason: "exits 3".into(),
            },
        );
        assert_eq!(
            verdicts(&c).handle(&mut v, &packs, &never, PEER).unwrap(),
            VerdictAnswer::ClosedNever
        );
        assert!(matches!(
            purger(&c).purge(&h.pool, &mut v, &packs).unwrap(),
            Purged::Complete { .. }
        ));
        let e = explained(&c, Subject::Chronicle(v.id()));
        assert!(e.failed().is_empty(), "{:?}", e.failed());
        assert_eq!(e.explain["retired"], json!(true));
        assert_eq!(
            e.explain["candidates"][0]["outcome"]["never"]["reason"],
            json!("exits 3")
        );
        assert_eq!(
            e.explain["purge"]["end"]["complete"]["items_replaced"],
            json!(1)
        );
        assert_eq!(e.explain["purge"]["replaced"], json!(1));
    }
}
