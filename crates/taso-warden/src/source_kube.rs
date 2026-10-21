//! Vessels from a Kubernetes cluster (K2; design:
//! claude/Taso_design_k2_2026-10-17.md).
//!
//! A [`KubeSource`] lists the `Vessel` resources whose `spec.node` is this
//! node (the API server filters by the field the CRD declares selectable)
//! and turns each into a [`VesselConf`] with its own runtime.  It is
//! level-triggered: every list is the whole set, and the supervisor acts on
//! the difference.  A list that fails, or an answer that is not a
//! `VesselList`, is an error ("unknown"): nothing is started or stopped.
//!
//! # Nothing in a resource is trusted
//!
//! Anyone allowed to create a Vessel in some namespace writes what this
//! Warden acts on as root.  The CRD's validation is the first fence; every
//! rule is checked again here, against the node's
//! [`KubeSourceConf`], and an item that breaks one is refused with its
//! reason (for its status), never repaired or clamped:
//!
//! - **Strict shape.**  Unknown keys in `spec` are refused (the API server
//!   prunes them, so only a broken server or a changed CRD sends them).
//! - **D1, tenancy.**  The resource's Kubernetes namespace must be mapped
//!   to a tenant on this node, and `spec.tenant` must be that tenant.  So
//!   Kubernetes RBAC on namespaces is the tenancy boundary: a user in one
//!   namespace can never name another tenant's Vessel.
//! - **D2, rootfs.**  `spec.rootfs.path` must resolve (symlinks followed)
//!   to a directory strictly inside the node's `rootfs_dir`; the resolved
//!   path is what runs.
//! - **D3, takeover.**  `spec.takeover` is refused until the conditional
//!   transfer exists (fencing review F1/F2).
//! - **Limits.**  Memory and pids at most the node's maxima; a Vessel that
//!   asks for none gets the node's runtime default, or else the maximum.
//! - **Landlock** may be turned off only if the node allows it.
//! - **One resource per Vessel.**  Two resources naming the same Vessel
//!   (tenant and subject) are both refused: neither may decide for it.
//!
//! What a resource leaves out is not taken from the node's static runtime
//! (args, env, quiescence are the resource's alone): a cluster user's agent
//! never inherits what the operator set for the node's own agents.
//!
//! **A bad edit hurts only itself.**  A resource that ran with a good spec
//! and is now refused keeps its last good spec (by its Kubernetes uid; the
//! CRD makes tenant, subject and uidSlot immutable, so it is the same
//! Vessel): editing a running Vessel into something invalid neither changes
//! nor stops it.  Deleting it (or marking it for deletion) stops it.
//!
//! Items for another node (if a server ignored the field selector) are
//! skipped, not refused: their status is not this Warden's to write.
//!
//! Every Vessel from a cluster restarts after it exits (`Always`, with the
//! supervisor's backoff): the resource says it should run.
//!
//! The uid-slot rules are the [`crate::source::Guard`]'s, as for any source.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use taso_core::record::Namespace;

use crate::daemon::{
    check_env, check_quiescence, valid_kube_namespace, KubeSourceConf, Restart, RuntimeConf,
    VesselConf, VesselRuntime,
};
use crate::kube::{valid_name, Kube, KubeError, Resource};
use crate::source::{SourceError, VesselKey, VesselSource};

/// The `Vessel` resource (`deploy/k8s/vessel-crd.yaml`).
pub const VESSELS: Resource = Resource {
    group: "taso.suocommerce.com",
    version: "v1alpha1",
    plural: "vessels",
};

/// How often the cluster is listed, at most.
pub const DEFAULT_TICK: Duration = Duration::from_secs(2);

/// Lists the Vessel resources of one node.
pub trait ListVessels: Send {
    /// The `VesselList` of the Vessels whose `spec.node` is `node`.
    fn list(&self, node: &str) -> Result<Value, KubeError>;
}

impl ListVessels for Kube {
    fn list(&self, node: &str) -> Result<Value, KubeError> {
        // `node` is a checked name ([`KubeSourceConf::node`]): no `,` or `=`
        // can widen the selector.
        if !valid_name(node) {
            return Err(KubeError::BadName(node.into()));
        }
        Kube::list(self, VESSELS, None, Some(&format!("spec.node={node}")))
    }
}

/// A Vessel resource, for its status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRef {
    /// Its Kubernetes namespace.
    pub namespace: String,
    /// Its name.
    pub name: String,
    /// Its uid (a deleted and recreated resource has a new one).
    pub uid: String,
    /// Its `metadata.generation`, for `status.observedGeneration`.
    pub generation: u64,
}

/// A resource this source did not take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KubeRefused {
    /// The resource, if its metadata could be read (else only logged).
    pub object: Option<ObjectRef>,
    /// Why.
    pub reason: String,
    /// It still runs with its last good spec.
    pub kept_previous: bool,
}

/// What the last good list said, for the status writer: which resource
/// each Vessel in the set came from, and what was refused.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    /// The resource behind each Vessel in the set.
    pub objects: BTreeMap<VesselKey, ObjectRef>,
    /// Refused resources.
    pub refused: Vec<KubeRefused>,
}

/// A [`View`] shared with the status writer.
pub type SharedView = Arc<Mutex<View>>;

/// The source (see the module docs).
pub struct KubeSource<L: ListVessels> {
    lister: L,
    conf: KubeSourceConf,
    runtime: RuntimeConf,
    tick: Duration,
    next_list: Option<Instant>,
    /// The set last answered.
    last: Option<Vec<VesselConf>>,
    /// The last good entry of each resource, by uid.
    last_good: BTreeMap<String, (VesselKey, VesselConf)>,
    view: SharedView,
}

impl<L: ListVessels> KubeSource<L> {
    /// A source listing with `lister` at most every `tick`, under the
    /// node's `conf` and `runtime`.
    pub fn new(lister: L, conf: KubeSourceConf, runtime: RuntimeConf, tick: Duration) -> Self {
        Self {
            lister,
            conf,
            runtime,
            tick,
            next_list: None,
            last: None,
            last_good: BTreeMap::new(),
            view: SharedView::default(),
        }
    }

    /// The view the status writer reads.
    pub fn view(&self) -> SharedView {
        self.view.clone()
    }

    /// Read a list into the set to run and its view (see the module docs).
    fn read(&mut self, list: &Value) -> Result<(Vec<VesselConf>, View), SourceError> {
        if list.get("kind").and_then(Value::as_str) != Some("VesselList") {
            return Err(SourceError(format!(
                "expected a VesselList, got kind {:?}",
                list.get("kind")
            )));
        }
        let items = list
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| SourceError("a VesselList without items".into()))?;

        let mut parsed: Vec<(ObjectRef, Result<VesselConf, String>)> = Vec::new();
        let mut refused = Vec::new();
        for item in items {
            let object = match object_ref(item) {
                Ok(o) => o,
                Err(reason) => {
                    refused.push(KubeRefused {
                        object: None,
                        reason,
                        kept_previous: false,
                    });
                    continue;
                }
            };
            if item
                .get("metadata")
                .and_then(|m| m.get("deletionTimestamp"))
                .is_some_and(|d| !d.is_null())
            {
                continue; // being deleted: stopped
            }
            if item
                .get("spec")
                .and_then(|s| s.get("node"))
                .and_then(Value::as_str)
                != Some(self.conf.node.as_str())
            {
                continue; // another node's (see the module docs)
            }
            let entry = self.vessel(&object, item);
            parsed.push((object, entry));
        }

        // One resource per Vessel.
        let mut count: BTreeMap<VesselKey, usize> = BTreeMap::new();
        for (_, e) in &parsed {
            if let Ok(vc) = e {
                *count.entry(*vc.id().as_bytes()).or_default() += 1;
            }
        }
        let mut set: BTreeMap<VesselKey, VesselConf> = BTreeMap::new();
        let mut objects = BTreeMap::new();
        let mut good = BTreeMap::new();
        for (object, entry) in parsed {
            let entry = entry.and_then(|vc| {
                let key = *vc.id().as_bytes();
                match count[&key] {
                    1 => Ok((key, vc)),
                    n => Err(format!(
                        "{n} Vessel resources name tenant and subject {:?}: none of them is run",
                        vc.subject
                    )),
                }
            });
            match entry {
                Ok((key, vc)) => {
                    good.insert(object.uid.clone(), (key, vc.clone()));
                    objects.insert(key, object);
                    set.insert(key, vc);
                }
                Err(reason) => {
                    // Its last good spec stays, unless another resource now
                    // has its Vessel.
                    let kept = match self.last_good.get(&object.uid) {
                        Some((key, vc)) if !set.contains_key(key) && !count.contains_key(key) => {
                            good.insert(object.uid.clone(), (*key, vc.clone()));
                            objects.insert(*key, object.clone());
                            set.insert(*key, vc.clone());
                            true
                        }
                        _ => false,
                    };
                    refused.push(KubeRefused {
                        object: Some(object),
                        reason,
                        kept_previous: kept,
                    });
                }
            }
        }
        self.last_good = good;
        Ok((set.into_values().collect(), View { objects, refused }))
    }

    /// One resource's entry, or why it is refused.
    fn vessel(&self, object: &ObjectRef, item: &Value) -> Result<VesselConf, String> {
        let spec = item
            .get("spec")
            .and_then(Value::as_object)
            .ok_or("no spec")?;
        known_keys(
            spec,
            "spec",
            &[
                "tenant",
                "subject",
                "uidSlot",
                "node",
                "takeover",
                "rootfs",
                "args",
                "env",
                "landlock",
                "resources",
                "quiescence",
            ],
        )?;

        // D1.
        let tenant = hex16(
            spec.get("tenant")
                .and_then(Value::as_str)
                .ok_or("spec.tenant must be a string")?,
        )?;
        let mine = self.conf.tenants.get(&object.namespace).ok_or_else(|| {
            format!(
                "namespace {:?} is not mapped to a tenant on node {}",
                object.namespace, self.conf.node
            )
        })?;
        if *mine != tenant {
            return Err(format!(
                "spec.tenant is not the tenant of namespace {:?}",
                object.namespace
            ));
        }
        let subject = spec
            .get("subject")
            .and_then(Value::as_str)
            .ok_or("spec.subject must be a string")?;
        if subject.is_empty() || subject.len() > 256 {
            return Err("spec.subject must be 1 to 256 bytes".into());
        }
        let uid_slot =
            spec.get("uidSlot")
                .and_then(Value::as_u64)
                .filter(|s| *s <= 65_000)
                .ok_or("spec.uidSlot must be an integer from 0 to 65000")? as u32;

        // D3.
        if spec.get("takeover").is_some_and(|t| !t.is_null()) {
            return Err("spec.takeover is refused: taking a Vessel over needs a conditional transfer (fencing review F1/F2), not built yet".into());
        }

        // D2.
        let rootfs = spec
            .get("rootfs")
            .and_then(Value::as_object)
            .ok_or("spec.rootfs must be an object")?;
        known_keys(rootfs, "spec.rootfs", &["path"])?;
        let path = rootfs
            .get("path")
            .and_then(Value::as_str)
            .ok_or("spec.rootfs.path must be a string")?;
        let rootfs = inside(&self.conf.rootfs_dir, Path::new(path))?;

        let args = strings(spec, "args")?.ok_or("spec.args is required")?;
        if args.is_empty() {
            return Err("spec.args must name the agent".into());
        }
        let env = strings(spec, "env")?.unwrap_or_default();
        check_env(&env).map_err(|e| format!("spec.{e}"))?;
        let quiescence = strings(spec, "quiescence")?.unwrap_or_default();
        check_quiescence(&quiescence).map_err(|e| format!("spec: {e}"))?;

        let landlock = match spec.get("landlock") {
            None | Some(Value::Null) => true,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err("spec.landlock must be true or false".into()),
        };
        if !landlock && !self.conf.allow_without_landlock {
            return Err("spec.landlock: false is refused on this node (it does not allow agents without Landlock)".into());
        }

        // Limits.
        let (mut memory, mut pids) = (None, None);
        if let Some(r) = spec.get("resources").filter(|r| !r.is_null()) {
            let r = r.as_object().ok_or("spec.resources must be an object")?;
            known_keys(r, "spec.resources", &["memory", "pids"])?;
            memory = r
                .get("memory")
                .filter(|m| !m.is_null())
                .map(memory_bytes)
                .transpose()?;
            pids = match r.get("pids").filter(|p| !p.is_null()) {
                None => None,
                Some(p) => Some(
                    p.as_u64()
                        .filter(|p| *p >= 1)
                        .ok_or("spec.resources.pids must be an integer of at least 1")?,
                ),
            };
        }
        let memory = memory
            .or(self.runtime.memory_bytes)
            .unwrap_or(self.conf.max_memory_bytes);
        let pids = pids.or(self.runtime.pids).unwrap_or(self.conf.max_pids);
        if memory == 0 || memory > self.conf.max_memory_bytes {
            return Err(format!(
                "spec.resources.memory: {memory} bytes; this node allows 1 to {}",
                self.conf.max_memory_bytes
            ));
        }
        if pids > self.conf.max_pids {
            return Err(format!(
                "spec.resources.pids: {pids}; this node allows at most {}",
                self.conf.max_pids
            ));
        }

        let vc = VesselConf {
            namespace: tenant,
            subject: subject.to_string(),
            takeover: None,
            uid_slot,
            restart: Restart::Always,
            runtime: Some(Box::new(VesselRuntime {
                rootfs: Some(rootfs),
                args: Some(args),
                env: Some(env),
                landlock: Some(landlock),
                memory_bytes: Some(memory),
                pids: Some(pids),
                quiescence: Some(quiescence),
            })),
        };
        // The daemon's own check, as for any Vessel (e.g. Landlock without a
        // shim).  It repeats some checks above; those come first so that the
        // reason names the resource's field.
        vc.effective(&self.runtime, &[])?;
        Ok(vc)
    }
}

impl<L: ListVessels> VesselSource for KubeSource<L> {
    fn poll(&mut self, wait: Duration) -> Result<Option<Vec<VesselConf>>, SourceError> {
        if let Some(next) = self.next_list {
            let now = Instant::now();
            if now < next {
                std::thread::sleep(wait.min(next - now));
                if Instant::now() < next {
                    return Ok(None);
                }
            }
        }
        self.next_list = Some(Instant::now() + self.tick);
        let list = self
            .lister
            .list(&self.conf.node)
            .map_err(|e| SourceError(e.to_string()))?;
        let (set, view) = self.read(&list)?;
        *self.view.lock().unwrap_or_else(|p| p.into_inner()) = view;
        if self.last.as_ref() == Some(&set) {
            return Ok(None);
        }
        self.last = Some(set.clone());
        Ok(Some(set))
    }

    fn is_finite(&self) -> bool {
        false
    }
}

// ── Reading a resource ──────────────────────────────────────────────

fn object_ref(item: &Value) -> Result<ObjectRef, String> {
    let m = item.get("metadata").ok_or("an item without metadata")?;
    let s = |k: &str| {
        m.get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("an item without metadata.{k}"))
    };
    let (namespace, name, uid) = (s("namespace")?, s("name")?, s("uid")?);
    if !valid_kube_namespace(namespace) || !valid_name(name) {
        return Err(format!(
            "an item named {namespace:?}/{name:?}: not valid Kubernetes names"
        ));
    }
    if uid.is_empty() {
        return Err(format!("{namespace}/{name}: an empty metadata.uid"));
    }
    let generation = m.get("generation").and_then(Value::as_u64).unwrap_or(0);
    Ok(ObjectRef {
        namespace: namespace.into(),
        name: name.into(),
        uid: uid.into(),
        generation,
    })
}

fn known_keys(o: &Map<String, Value>, what: &str, keys: &[&str]) -> Result<(), String> {
    match o.keys().find(|k| !keys.contains(&k.as_str())) {
        Some(k) => Err(format!("{what}: unknown field {k:?}")),
        None => Ok(()),
    }
}

fn strings(o: &Map<String, Value>, key: &str) -> Result<Option<Vec<String>>, String> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("spec.{key} must be strings"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(format!("spec.{key} must be an array of strings")),
    }
}

fn hex16(s: &str) -> Result<Namespace, String> {
    let err = || "spec.tenant must be 32 lowercase hex digits".to_string();
    if s.len() != 32
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(err());
    }
    let mut b = [0u8; 16];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| err())?;
    }
    Ok(Namespace::from_bytes(b))
}

/// D2: `path`, resolved, as a directory strictly inside `dir` (resolved).
pub fn inside(dir: &Path, path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!(
            "spec.rootfs.path {} must be absolute",
            path.display()
        ));
    }
    let base = dir
        .canonicalize()
        .map_err(|e| format!("the node's rootfs_dir {}: {e}", dir.display()))?;
    let real = path
        .canonicalize()
        .map_err(|e| format!("spec.rootfs.path {}: {e}", path.display()))?;
    if real == base || !real.starts_with(&base) {
        return Err(format!(
            "spec.rootfs.path {} is not inside this node's rootfs directory",
            path.display()
        ));
    }
    if !real.is_dir() {
        return Err(format!(
            "spec.rootfs.path {} is not a directory",
            path.display()
        ));
    }
    Ok(real)
}

/// A memory quantity in bytes: an integer, or a string of digits with an
/// optional fraction and one of the suffixes the CRD allows (`Ki Mi Gi Ti`,
/// `k M G T`).  It must come to a whole number of bytes.
pub fn memory_bytes(v: &Value) -> Result<u64, String> {
    let bad = || format!("spec.resources.memory {v}: not a quantity of whole bytes (e.g. 256Mi)");
    let s = match v {
        Value::Number(n) => return n.as_u64().ok_or_else(bad),
        Value::String(s) => s.as_str(),
        _ => return Err(bad()),
    };
    let digits_end = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num, suffix) = s.split_at(digits_end);
    let mult: u128 = match suffix {
        "" => 1,
        "k" => 1_000,
        "M" => 1_000_000,
        "G" => 1_000_000_000,
        "T" => 1_000_000_000_000,
        "Ki" => 1 << 10,
        "Mi" => 1 << 20,
        "Gi" => 1 << 30,
        "Ti" => 1 << 40,
        _ => return Err(bad()),
    };
    let (int, frac) = num.split_once('.').unwrap_or((num, ""));
    if int.is_empty()
        || num.ends_with('.')
        || frac.len() > 9
        || !int.bytes().chain(frac.bytes()).all(|c| c.is_ascii_digit())
        || int.len() > 20
    {
        return Err(bad());
    }
    let scale = 10u128.pow(frac.len() as u32);
    let whole: u128 = format!("{int}{frac}").parse().map_err(|_| bad())?;
    let total = whole.checked_mul(mult).ok_or_else(bad)?;
    if total % scale != 0 {
        return Err(bad());
    }
    u64::try_from(total / scale).map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TA: &str = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
    const TB: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

    struct Fixture {
        _dir: tempfile::TempDir,
        rootfs_dir: PathBuf,
        conf: KubeSourceConf,
        runtime: RuntimeConf,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let rootfs_dir = dir.path().join("rootfs");
        std::fs::create_dir_all(rootfs_dir.join("agent")).unwrap();
        std::fs::create_dir_all(dir.path().join("elsewhere")).unwrap();
        let conf = KubeSourceConf {
            node: "node-a".into(),
            tenants: [
                ("team-a".to_string(), hex16(TA).unwrap()),
                ("team-b".to_string(), hex16(TB).unwrap()),
            ]
            .into(),
            rootfs_dir: rootfs_dir.clone(),
            max_memory_bytes: 1 << 30,
            max_pids: 512,
            allow_without_landlock: false,
            api: None,
        };
        let runtime = RuntimeConf {
            rootfs: None,
            host_uid_base: 200_000,
            landlock_shim: Some("/usr/lib/taso/landlock".into()),
            args: vec![],
            env: vec!["NODE_SECRET=x".into()],
            memory_bytes: Some(256 << 20),
            pids: None,
        };
        Fixture {
            _dir: dir,
            rootfs_dir,
            conf,
            runtime,
        }
    }

    fn item(f: &Fixture, ns: &str, name: &str, uid: &str, spec: Value) -> Value {
        let mut s = json!({
            "tenant": if ns == "team-b" { TB } else { TA },
            "subject": name,
            "uidSlot": 1,
            "node": "node-a",
            "rootfs": { "path": f.rootfs_dir.join("agent") },
            "args": ["/usr/bin/agent"]
        });
        for (k, v) in spec.as_object().unwrap() {
            if v.is_null() {
                s.as_object_mut().unwrap().remove(k);
            } else {
                s[k] = v.clone();
            }
        }
        json!({ "metadata": { "namespace": ns, "name": name, "uid": uid, "generation": 3 }, "spec": s })
    }

    fn list(items: Vec<Value>) -> Value {
        json!({ "kind": "VesselList", "apiVersion": "taso.suocommerce.com/v1alpha1", "items": items })
    }

    /// A lister answering from a shared slot, counting calls.
    #[derive(Clone)]
    struct Fake(Arc<Mutex<Result<Value, String>>>, Arc<AtomicUsize>);
    impl Default for Fake {
        fn default() -> Self {
            Self(Arc::new(Mutex::new(Ok(list(vec![])))), Arc::default())
        }
    }
    impl Fake {
        fn set(&self, v: Value) {
            *self.0.lock().unwrap() = Ok(v);
        }
        fn fail(&self, why: &str) {
            *self.0.lock().unwrap() = Err(why.into());
        }
    }
    impl ListVessels for Fake {
        fn list(&self, node: &str) -> Result<Value, KubeError> {
            assert_eq!(node, "node-a");
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.lock().unwrap().clone().map_err(KubeError::Transport)
        }
    }

    fn source(f: &Fixture) -> (Fake, KubeSource<Fake>) {
        let fake = Fake::default();
        fake.set(list(vec![]));
        (
            fake.clone(),
            KubeSource::new(fake, f.conf.clone(), f.runtime.clone(), Duration::ZERO),
        )
    }

    fn one(f: &Fixture, spec: Value) -> Result<VesselConf, String> {
        let (fake, mut s) = source(f);
        fake.set(list(vec![item(f, "team-a", "v1", "u1", spec)]));
        let set = s.poll(Duration::ZERO).unwrap().unwrap();
        let view = s.view().lock().unwrap().clone();
        match (set.first(), view.refused.first()) {
            (Some(vc), None) => Ok(vc.clone()),
            (None, Some(r)) => Err(r.reason.clone()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_good_resource_becomes_a_vessel_with_its_own_runtime_only() {
        let f = fixture();
        let vc = one(&f, json!({ "env": ["A=1"], "quiescence": ["db.sqlite"], "resources": { "memory": "128Mi", "pids": 32 } })).unwrap();
        assert_eq!(vc.namespace, hex16(TA).unwrap());
        assert_eq!(
            (vc.subject.as_str(), vc.uid_slot, vc.takeover, vc.restart),
            ("v1", 1, None, Restart::Always)
        );
        let rt = *vc.runtime.clone().unwrap();
        assert_eq!(
            rt,
            VesselRuntime {
                rootfs: Some(f.rootfs_dir.join("agent").canonicalize().unwrap()),
                args: Some(vec!["/usr/bin/agent".into()]),
                env: Some(vec!["A=1".into()]),
                landlock: Some(true),
                memory_bytes: Some(128 << 20),
                pids: Some(32),
                quiescence: Some(vec!["db.sqlite".into()]),
            }
        );
        let e = vc.effective(&f.runtime, &["node.db".into()]).unwrap();
        assert_eq!(
            e.landlock_shim.as_deref(),
            Some("/usr/lib/taso/landlock"),
            "Landlock by default"
        );
        assert_eq!(
            e.env,
            vec!["A=1".to_string()],
            "the node's env is not inherited"
        );
        assert!(
            e.quiescence == vec!["db.sqlite".to_string()],
            "nor the node's quiescence"
        );

        // Without limits: the node's default, else its maximum.
        let vc = one(&f, json!({})).unwrap();
        let rt = vc.runtime.unwrap();
        assert_eq!((rt.memory_bytes, rt.pids), (Some(256 << 20), Some(512)));
        assert_eq!((rt.env, rt.quiescence), (Some(vec![]), Some(vec![])));
    }

    #[test]
    fn tenancy_follows_the_kubernetes_namespace() {
        let f = fixture();
        let e = one(&f, json!({ "tenant": TB })).unwrap_err();
        assert!(e.contains("not the tenant of namespace \"team-a\""), "{e}");
        let (fake, mut s) = source(&f);
        fake.set(list(vec![item(&f, "team-c", "v1", "u1", json!({}))]));
        assert_eq!(s.poll(Duration::ZERO).unwrap(), Some(vec![]));
        let r = s.view().lock().unwrap().refused.clone();
        assert!(r[0].reason.contains("\"team-c\" is not mapped"), "{r:?}");
        assert_eq!(r[0].object.as_ref().unwrap().name, "v1");
        // Each namespace with its own tenant is fine.
        fake.set(list(vec![
            item(&f, "team-a", "a", "u1", json!({})),
            item(&f, "team-b", "b", "u2", json!({ "uidSlot": 2 })),
        ]));
        assert_eq!(s.poll(Duration::ZERO).unwrap().unwrap().len(), 2);
    }

    #[test]
    fn rootfs_must_resolve_inside_the_nodes_directory() {
        let f = fixture();
        let base = f.rootfs_dir.clone();
        let outside = base.parent().unwrap().join("elsewhere");
        std::os::unix::fs::symlink(&outside, base.join("escape")).unwrap();
        std::os::unix::fs::symlink(base.join("agent"), base.join("alias")).unwrap();
        std::fs::write(base.join("file"), b"").unwrap();
        for (path, why) in [
            (outside.clone(), "not inside"),
            (base.clone(), "not inside"),
            (base.join("escape"), "not inside"),
            (base.join("agent/../../elsewhere"), "not inside"),
            (base.join("missing"), "No such file"),
            (base.join("file"), "not a directory"),
            (PathBuf::from("/"), "not inside"),
            (PathBuf::from("agent"), "must be absolute"),
        ] {
            let e = one(&f, json!({ "rootfs": { "path": path } })).unwrap_err();
            assert!(e.contains(why), "{}: {e}", path.display());
        }
        let vc = one(&f, json!({ "rootfs": { "path": base.join("alias") } })).unwrap();
        assert_eq!(
            vc.runtime.unwrap().rootfs,
            Some(base.join("agent").canonicalize().unwrap()),
            "the resolved path runs"
        );
    }

    #[test]
    fn takeover_is_refused_for_now() {
        let f = fixture();
        let e = one(&f, json!({ "takeover": { "holder": 2, "epoch": 5 } })).unwrap_err();
        assert!(e.contains("F1/F2"), "{e}");
    }

    #[test]
    fn limits_are_bounded_by_the_node_and_never_clamped() {
        let f = fixture();
        assert_eq!(
            one(&f, json!({ "resources": { "memory": "1Gi" } }))
                .unwrap()
                .runtime
                .unwrap()
                .memory_bytes,
            Some(1 << 30)
        );
        for (res, why) in [
            (json!({ "memory": "2Gi" }), "allows 1 to"),
            (json!({ "memory": 0 }), "allows 1 to"),
            (json!({ "memory": "1.5" }), "whole bytes"),
            (json!({ "memory": "1Ei" }), "whole bytes"),
            (json!({ "memory": -1 }), "whole bytes"),
            (json!({ "pids": 513 }), "at most 512"),
            (
                json!({ "pids": 0 }),
                "spec.resources.pids must be an integer of at least 1",
            ),
            (json!({ "cpu": 1 }), "unknown field"),
        ] {
            let e = one(&f, json!({ "resources": res })).unwrap_err();
            assert!(e.contains(why), "{res}: {e}");
        }
        let mut f2 = fixture();
        f2.runtime.memory_bytes = None;
        assert_eq!(
            one(&f2, json!({})).unwrap().runtime.unwrap().memory_bytes,
            Some(1 << 30),
            "no node default: the maximum"
        );
    }

    #[test]
    fn landlock_off_only_where_the_node_allows_it() {
        let mut f = fixture();
        assert!(one(&f, json!({ "landlock": false }))
            .unwrap_err()
            .contains("does not allow"));
        assert!(one(&f, json!({ "landlock": "no" }))
            .unwrap_err()
            .contains("true or false"));
        f.conf.allow_without_landlock = true;
        assert_eq!(
            one(&f, json!({ "landlock": false }))
                .unwrap()
                .runtime
                .unwrap()
                .landlock,
            Some(false)
        );
        // On, but the node has no shim: the daemon's own check refuses it.
        f.runtime.landlock_shim = None;
        assert!(one(&f, json!({})).unwrap_err().contains("landlock_shim"));
    }

    #[test]
    fn the_shape_is_strict() {
        let f = fixture();
        for (spec, why) in [
            (json!({ "restart": "never" }), "unknown field \"restart\""),
            (
                json!({ "rootfs": { "path": "/x", "image": "y" } }),
                "unknown field \"image\"",
            ),
            (json!({ "tenant": TA.to_uppercase() }), "lowercase hex"),
            (json!({ "tenant": "0a" }), "lowercase hex"),
            (json!({ "subject": "" }), "1 to 256"),
            (json!({ "subject": "s".repeat(257) }), "1 to 256"),
            (json!({ "subject": null }), "subject must be"),
            (json!({ "uidSlot": 65_001 }), "0 to 65000"),
            (json!({ "uidSlot": -1 }), "0 to 65000"),
            (json!({ "uidSlot": "1" }), "0 to 65000"),
            (json!({ "args": [] }), "name the agent"),
            (json!({ "args": null }), "args is required"),
            (json!({ "args": [1] }), "must be strings"),
            (
                json!({ "env": ["1=x"] }),
                "spec.env \"1=x\": \"1\" is not a valid variable name",
            ),
            (json!({ "env": "A=1" }), "array of strings"),
            (
                json!({ "quiescence": ["../x"] }),
                "spec: quiescence path \"../x\" must be relative",
            ),
            (json!({ "rootfs": "/x" }), "rootfs must be an object"),
            (json!({ "resources": 5 }), "resources must be an object"),
        ] {
            let e = one(&f, spec.clone()).unwrap_err();
            assert!(e.contains(why), "{spec}: {e}");
        }
    }

    #[test]
    fn items_are_skipped_or_reported_by_what_they_are() {
        let f = fixture();
        let (fake, mut s) = source(&f);
        let other_node = item(&f, "team-a", "x", "u9", json!({ "node": "node-b" }));
        let mut deleting = item(&f, "team-a", "d", "u8", json!({ "uidSlot": 4 }));
        deleting["metadata"]["deletionTimestamp"] = "2026-10-17T12:00:00Z".into();
        let nameless = json!({ "metadata": { "namespace": "team-a", "uid": "u7" }, "spec": {} });
        let bad_name =
            json!({ "metadata": { "namespace": "Team-A", "name": "x", "uid": "u6" }, "spec": {} });
        fake.set(list(vec![
            other_node,
            deleting,
            nameless,
            bad_name,
            item(&f, "team-a", "v1", "u1", json!({})),
        ]));
        let set = s.poll(Duration::ZERO).unwrap().unwrap();
        assert_eq!(
            set.iter().map(|v| v.subject.as_str()).collect::<Vec<_>>(),
            vec!["v1"]
        );
        let view = s.view().lock().unwrap().clone();
        assert_eq!(view.objects.len(), 1);
        assert_eq!(
            view.objects.values().next().unwrap(),
            &ObjectRef {
                namespace: "team-a".into(),
                name: "v1".into(),
                uid: "u1".into(),
                generation: 3
            }
        );
        assert_eq!(view.refused.len(), 2, "{view:?}");
        assert!(
            view.refused.iter().all(|r| r.object.is_none()),
            "unaddressable: logged, no status"
        );
    }

    #[test]
    fn two_resources_for_one_vessel_are_both_refused() {
        let f = fixture();
        let (fake, mut s) = source(&f);
        let a = item(&f, "team-a", "v1", "u1", json!({ "subject": "same" }));
        let b = item(
            &f,
            "team-a",
            "v2",
            "u2",
            json!({ "subject": "same", "uidSlot": 2 }),
        );
        fake.set(list(vec![a.clone(), b]));
        assert_eq!(s.poll(Duration::ZERO).unwrap(), Some(vec![]));
        let r = s.view().lock().unwrap().refused.clone();
        assert_eq!(r.len(), 2);
        assert!(r
            .iter()
            .all(|r| r.reason.contains("2 Vessel resources") && !r.kept_previous));

        // A running one is not kept when a second resource claims its Vessel:
        // neither decides.
        fake.set(list(vec![a.clone()]));
        assert_eq!(s.poll(Duration::ZERO).unwrap().unwrap().len(), 1);
        let b = item(
            &f,
            "team-a",
            "v2",
            "u2",
            json!({ "subject": "same", "uidSlot": 2 }),
        );
        fake.set(list(vec![a, b]));
        assert_eq!(s.poll(Duration::ZERO).unwrap(), Some(vec![]));
    }

    #[test]
    fn a_bad_edit_keeps_the_last_good_spec_and_deletion_stops() {
        let f = fixture();
        let (fake, mut s) = source(&f);
        fake.set(list(vec![item(&f, "team-a", "v1", "u1", json!({}))]));
        let first = s.poll(Duration::ZERO).unwrap().unwrap();
        // Edited past the node's limit: refused, but it runs on as it was.
        fake.set(list(vec![item(
            &f,
            "team-a",
            "v1",
            "u1",
            json!({ "resources": { "pids": 9999 } }),
        )]));
        assert_eq!(s.poll(Duration::ZERO).unwrap(), None, "unchanged set");
        let view = s.view().lock().unwrap().clone();
        assert!(view.refused[0].kept_previous && view.refused[0].reason.contains("at most 512"));
        assert_eq!(view.objects.len(), 1, "still addressed for its status");
        // Still refused on the next list: still kept.
        assert_eq!(s.poll(Duration::ZERO).unwrap(), None);
        // A good edit applies.
        fake.set(list(vec![item(
            &f,
            "team-a",
            "v1",
            "u1",
            json!({ "resources": { "pids": 8 } }),
        )]));
        let edited = s.poll(Duration::ZERO).unwrap().unwrap();
        assert_ne!(edited, first);
        assert_eq!(edited[0].runtime.as_ref().unwrap().pids, Some(8));
        // A new resource (new uid) with a bad spec has nothing to keep.
        fake.set(list(vec![item(
            &f,
            "team-a",
            "v1",
            "u2",
            json!({ "resources": { "pids": 9999 } }),
        )]));
        assert_eq!(s.poll(Duration::ZERO).unwrap(), Some(vec![]));
        assert!(!s.view().lock().unwrap().refused[0].kept_previous);
        // Deleted: stopped.
        fake.set(list(vec![item(&f, "team-a", "v1", "u3", json!({}))]));
        assert_eq!(s.poll(Duration::ZERO).unwrap().unwrap().len(), 1);
        fake.set(list(vec![]));
        assert_eq!(s.poll(Duration::ZERO).unwrap(), Some(vec![]));
    }

    #[test]
    fn a_failed_or_strange_list_is_unknown_not_empty() {
        let f = fixture();
        let (fake, mut s) = source(&f);
        fake.set(list(vec![item(&f, "team-a", "v1", "u1", json!({}))]));
        assert_eq!(s.poll(Duration::ZERO).unwrap().unwrap().len(), 1);
        fake.fail("connection refused");
        assert!(s
            .poll(Duration::ZERO)
            .unwrap_err()
            .to_string()
            .contains("connection refused"));
        for strange in [
            json!({ "kind": "Status", "items": [] }),
            json!({ "kind": "VesselList" }),
            json!([]),
            Value::Null,
        ] {
            fake.set(strange.clone());
            assert!(s.poll(Duration::ZERO).is_err(), "{strange}");
        }
        assert_eq!(
            s.view().lock().unwrap().objects.len(),
            1,
            "the view stays as the last good list left it"
        );
        // Back with the same set: nothing to change.
        fake.set(list(vec![item(&f, "team-a", "v1", "u1", json!({}))]));
        assert_eq!(s.poll(Duration::ZERO).unwrap(), None);
        // An empty list is an answer: stop everything.
        fake.set(list(vec![]));
        assert_eq!(s.poll(Duration::ZERO).unwrap(), Some(vec![]));
        assert!(!s.is_finite());
    }

    #[test]
    fn the_first_answer_is_always_given_and_lists_are_spaced_by_the_tick() {
        let f = fixture();
        let fake = Fake::default();
        fake.set(list(vec![]));
        let mut s = KubeSource::new(
            fake.clone(),
            f.conf.clone(),
            f.runtime.clone(),
            Duration::from_millis(300),
        );
        assert_eq!(
            s.poll(Duration::ZERO).unwrap(),
            Some(vec![]),
            "even an empty first answer"
        );
        assert_eq!(s.poll(Duration::from_millis(10)).unwrap(), None);
        assert_eq!(
            fake.1.load(Ordering::SeqCst),
            1,
            "not listed again before the tick"
        );
        let t = Instant::now();
        assert_eq!(s.poll(Duration::from_secs(5)).unwrap(), None);
        assert!(
            t.elapsed() >= Duration::from_millis(250),
            "waited for the tick"
        );
        assert_eq!(fake.1.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn memory_quantities() {
        let ok = [
            (json!(1024), 1024),
            (json!("1024"), 1024),
            (json!("256Mi"), 256 << 20),
            (json!("1Gi"), 1 << 30),
            (json!("0.5Gi"), 1 << 29),
            (json!("1.5k"), 1500),
            (json!("2M"), 2_000_000),
            (json!("3G"), 3_000_000_000),
            (json!("1T"), 1_000_000_000_000),
            (json!("1Ti"), 1 << 40),
            (json!("1Ki"), 1024),
        ];
        for (v, want) in ok {
            assert_eq!(memory_bytes(&v), Ok(want), "{v}");
        }
        for v in [
            json!("0.1"),
            json!("1.5"),
            json!("1m"),
            json!("1Ei"),
            json!("1e3"),
            json!("."),
            json!("1."),
            json!(".5Gi"),
            json!("1..5"),
            json!(""),
            json!("Mi"),
            json!("-1"),
            json!(" 1"),
            json!(1.5),
            json!(true),
            json!("99999999999999999999Ti"),
        ] {
            assert!(memory_bytes(&v).is_err(), "{v}");
        }
    }

    #[test]
    fn the_kube_lister_filters_by_a_checked_node_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("t"), "tok").unwrap();
        let k = Kube::new(
            &crate::kube::KubeConfig {
                api: "https://127.0.0.1:1".into(),
                token_file: dir.path().join("t"),
                ca_file: None,
            },
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(
            ListVessels::list(&k, "a,spec.node!=a"),
            Err(KubeError::BadName(_))
        ));
        assert!(
            matches!(
                ListVessels::list(&k, "node-a"),
                Err(KubeError::Transport(_))
            ),
            "a good name gets to the network"
        );
    }

    /// Against a real API server with the Vessel CRD.  Set TASO_KUBE_API,
    /// TASO_KUBE_TOKEN_FILE, TASO_KUBE_CA (optional) as for the kube client
    /// test, and:
    ///   TASO_KUBE_NODE         the node to list for
    ///   TASO_KUBE_ROOTFS_DIR   the node's rootfs directory
    ///   TASO_KUBE_TENANTS      namespace=tenant,... (32 hex digits each)
    ///   TASO_KUBE_RUN          ns/name,... expected to run
    ///   TASO_KUBE_REFUSED      ns/name=reason part,... expected refused
    /// Every other Vessel on the node must be neither.
    #[test]
    #[ignore = "needs a kube-apiserver: set TASO_KUBE_*"]
    fn against_a_real_api_server() {
        let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
        let cfg = crate::kube::KubeConfig {
            api: env("TASO_KUBE_API"),
            token_file: env("TASO_KUBE_TOKEN_FILE").into(),
            ca_file: std::env::var_os("TASO_KUBE_CA").map(Into::into),
        };
        let kube = Kube::new(&cfg, Duration::from_secs(10)).unwrap();
        let tenants = env("TASO_KUBE_TENANTS")
            .split(',')
            .map(|p| {
                let (ns, t) = p.split_once('=').unwrap();
                (ns.to_string(), hex16(t).unwrap())
            })
            .collect();
        let conf = KubeSourceConf {
            node: env("TASO_KUBE_NODE"),
            tenants,
            rootfs_dir: env("TASO_KUBE_ROOTFS_DIR").into(),
            max_memory_bytes: 1 << 30,
            max_pids: 512,
            allow_without_landlock: false,
            api: None,
        };
        let mut s = KubeSource::new(kube, conf, fixture().runtime, Duration::ZERO);
        let set = s.poll(Duration::ZERO).unwrap().expect("a first answer");
        let view = s.view().lock().unwrap().clone();
        let name = |o: &ObjectRef| format!("{}/{}", o.namespace, o.name);
        let mut run: Vec<String> = view.objects.values().map(name).collect();
        run.sort();
        let mut want_run: Vec<String> = env("TASO_KUBE_RUN")
            .split(',')
            .map(str::to_string)
            .collect();
        want_run.sort();
        assert_eq!(run, want_run, "{view:#?}");
        assert_eq!(set.len(), want_run.len());
        let want_refused: Vec<(String, String)> = env("TASO_KUBE_REFUSED")
            .split(',')
            .map(|p| {
                let (n, r) = p.split_once('=').unwrap();
                (n.to_string(), r.to_string())
            })
            .collect();
        assert_eq!(view.refused.len(), want_refused.len(), "{view:#?}");
        for (n, part) in want_refused {
            let r = view
                .refused
                .iter()
                .find(|r| r.object.as_ref().map(name).as_deref() == Some(n.as_str()))
                .unwrap_or_else(|| panic!("{n} not refused: {view:#?}"));
            assert!(r.reason.contains(&part), "{n}: {}", r.reason);
            eprintln!("refused {n}: {}", r.reason);
        }
        assert!(view
            .objects
            .values()
            .all(|o| o.generation >= 1 && !o.uid.is_empty()));
        assert_eq!(
            s.poll(Duration::ZERO).unwrap(),
            None,
            "unchanged on the next list"
        );
    }

    #[test]
    fn keys_are_known_or_refused() {
        let m: Map<String, Value> = serde_json::from_value(json!({ "a": 1, "b": 2 })).unwrap();
        assert!(known_keys(&m, "x", &["a", "b"]).is_ok());
        assert!(known_keys(&m, "x", &["a"]).unwrap_err().contains("\"b\""));
    }
}
