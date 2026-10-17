//! Vessel status in a Kubernetes cluster (K2; design:
//! claude/Taso_design_k2_2026-10-17.md).
//!
//! The supervisor's events become the `status` of the Vessel resources
//! they are about: `Running` when a run starts, `Exited` (how it started,
//! what settling did, how the agent ended, when it restarts), `Refused`
//! (by the source or the guard, with the reason), `Failed` (the start
//! failed).  A refusal by the source ([`crate::source_kube`]) is shown as
//! well, from its [`View`].
//!
//! # It never decides anything
//!
//! - **Best-effort, off the loop.**  [`StatusWriter::event`] only queues; a
//!   thread of its own writes.  A write that fails (API down, conflict) is
//!   tried again next round; it never blocks, slows or changes what runs.
//! - **Only resources of this node, as they are now.**  A status is written
//!   only to a resource in the source's latest [`View`], and each write is
//!   `get`, check, then patch *at the resourceVersion just read*
//!   ([`Kube::patch_status_at`]): if the resource is not the one the view
//!   names (deleted and recreated: another uid) or no longer on this node
//!   (moved: its new node's Warden writes its status), nothing is written;
//!   and if it changed between the read and the patch, the API server
//!   refuses the patch (409) and the next round tries again.
//! - **Only what changed** is written: the same status is not patched again.
//!
//! Not yet: `epoch`, `lastSeal` and `shippedAnchor` (the run's report does
//! not carry them yet); conditions.

use std::collections::BTreeMap;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{json, Value};
use taso_core::model::WardenId;

use crate::daemon::{DaemonError, Report};
use crate::kube::{Kube, KubeError};
use crate::source_kube::{ObjectRef, SharedView, View, VESSELS};
use crate::source::VesselKey;
use crate::supervisor::Event;

/// The longest message written to a status.
pub const MAX_MESSAGE: usize = 1024;

/// The calls the writer makes.
pub trait StatusApi: Send + 'static {
    /// The resource as it is now.
    fn get(&self, namespace: &str, name: &str) -> Result<Value, KubeError>;
    /// Merge `status` into its status if it is still at `resource_version`.
    fn patch(&self, namespace: &str, name: &str, resource_version: &str, status: &Value) -> Result<Value, KubeError>;
}

impl StatusApi for Kube {
    fn get(&self, namespace: &str, name: &str) -> Result<Value, KubeError> {
        Kube::get(self, VESSELS, namespace, name)
    }

    fn patch(&self, namespace: &str, name: &str, resource_version: &str, status: &Value) -> Result<Value, KubeError> {
        self.patch_status_at(VESSELS, namespace, name, Some(resource_version), status)
    }
}

/// The status an event calls for, as a merge patch of the fields this
/// writer owns (a `null` clears one), or `None` if it calls for none.
pub fn status_of(event: &Event<Result<Report, DaemonError>>, warden: WardenId) -> Option<(VesselKey, Value)> {
    let key = |vc: &crate::daemon::VesselConf| *vc.id().as_bytes();
    let again = |restart_in: &Option<Duration>| match restart_in {
        Some(d) => format!("; restarts in {}s", d.as_secs().max(1)),
        None => String::new(),
    };
    let holder = warden.get();
    Some(match event {
        Event::Started(vc) => (key(vc), json!({ "phase": "Running", "holder": holder, "message": "agent started" })),
        Event::Exited { vc, out: Ok(r), stopped, restart_in } => {
            let how = match (&r.agent, stopped) {
                (_, true) => "stopped on request".to_string(),
                (Some((true, _)), _) => "agent exited ok".to_string(),
                (Some((false, err)), _) => format!("agent failed: {}", err.trim()),
                (None, _) => "the agent never ran".to_string(),
            };
            let start = match r.start {
                crate::daemon::Start::Birth => json!("Birth"),
                crate::daemon::Start::Open => json!("Open"),
                crate::daemon::Start::Rebirth => json!("Rebirth"),
                crate::daemon::Start::Refuse(_) => Value::Null,
            };
            let lsn = |p: Option<crate::segment::Position>| p.map_or(Value::Null, |p| json!(p.lsn.get()));
            (
                key(vc),
                json!({
                    "phase": "Exited",
                    "holder": holder,
                    "start": start,
                    "settled": {
                        "birthSeal": lsn(r.settled.birth),
                        "rolledBackTo": lsn(r.settled.rolled_back_to),
                        "behind": r.settled.behind(),
                    },
                    "message": message(&format!("{how}{}", again(restart_in))),
                }),
            )
        }
        Event::Exited { vc, out: Err(e), restart_in, .. } => {
            let phase = if matches!(e, DaemonError::Refused(_)) { "Refused" } else { "Failed" };
            (key(vc), json!({ "phase": phase, "message": message(&format!("{e}{}", again(restart_in))) }))
        }
        Event::Panicked { vc, restart_in } => {
            (key(vc), json!({ "phase": "Failed", "message": message(&format!("the run panicked{}", again(restart_in))) }))
        }
        Event::Refused(r) if r.kept_previous => (r.key, json!({ "message": message(&format!("entry refused, running its last good one: {}", r.reason)) })),
        Event::Refused(r) => (r.key, json!({ "phase": "Refused", "message": message(&r.reason) })),
        Event::Stopping(_) | Event::SourceFailed(_) => return None,
    })
}

/// `s`, cut to [`MAX_MESSAGE`] bytes on a character boundary.
fn message(s: &str) -> String {
    if s.len() <= MAX_MESSAGE {
        return s.to_string();
    }
    let mut end = MAX_MESSAGE - 3;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// RFC 7386 merge of `patch` into `into`.
fn merge(into: &mut Value, patch: &Value) {
    match (into.as_object_mut(), patch.as_object()) {
        (Some(o), Some(p)) => {
            for (k, v) in p {
                if v.is_null() {
                    o.remove(k);
                } else {
                    merge(o.entry(k.clone()).or_insert(Value::Null), v);
                }
            }
        }
        _ => *into = patch.clone(),
    }
}

/// Writes statuses on its own thread (see the module docs).
pub struct StatusWriter {
    tx: Option<Sender<(VesselKey, Value)>>,
    warden: WardenId,
    thread: Option<JoinHandle<()>>,
}

impl StatusWriter {
    /// Start writing through `api` for the resources in `view` (the
    /// source's), on node `node`, a round every `tick`.
    pub fn spawn<A: StatusApi>(api: A, view: SharedView, node: String, warden: WardenId, tick: Duration) -> Self {
        let (tx, rx) = channel();
        let thread = std::thread::spawn(move || Writer { api, view, node, wanted: BTreeMap::new(), written: BTreeMap::new() }.run(rx, tick));
        Self { tx: Some(tx), warden, thread: Some(thread) }
    }

    /// Queue the status an event calls for.  Never blocks.
    pub fn event(&self, event: &Event<Result<Report, DaemonError>>) {
        if let (Some(tx), Some(update)) = (&self.tx, status_of(event, self.warden)) {
            let _ = tx.send(update);
        }
    }

    /// Write what is queued (one last round), then stop.
    pub fn finish(mut self) {
        self.tx.take();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for StatusWriter {
    fn drop(&mut self) {
        self.tx.take(); // the thread ends after its last round
    }
}

struct Writer<A: StatusApi> {
    api: A,
    view: SharedView,
    node: String,
    /// What events asked for, per resource uid (merged).
    wanted: BTreeMap<String, Value>,
    /// What was last written, per resource uid.
    written: BTreeMap<String, Value>,
}

impl<A: StatusApi> Writer<A> {
    fn run(mut self, rx: Receiver<(VesselKey, Value)>, tick: Duration) {
        loop {
            let mut updates = Vec::new();
            let open = match rx.recv_timeout(tick) {
                Ok(u) => {
                    updates.push(u);
                    true
                }
                Err(RecvTimeoutError::Timeout) => true,
                Err(RecvTimeoutError::Disconnected) => false,
            };
            updates.extend(rx.try_iter());
            let view = self.view.lock().unwrap_or_else(|p| p.into_inner()).clone();
            self.round(&view, updates);
            if !open {
                return;
            }
        }
    }

    /// One round: take `updates`, then write what differs from what was
    /// written, for the resources in `view`.
    fn round(&mut self, view: &View, updates: Vec<(VesselKey, Value)>) {
        for (key, patch) in updates {
            // Only for a Vessel the view has a resource for (else it is gone,
            // or no longer this node's).
            if let Some(o) = view.objects.get(&key) {
                merge(self.wanted.entry(o.uid.clone()).or_insert_with(|| json!({})), &patch);
            }
        }

        // The resources of this round and the status each should have.
        let mut targets: BTreeMap<String, (ObjectRef, Value)> = BTreeMap::new();
        for o in view.objects.values() {
            if let Some(w) = self.wanted.get(&o.uid) {
                targets.insert(o.uid.clone(), (o.clone(), w.clone()));
            }
        }
        for r in &view.refused {
            let Some(o) = &r.object else { continue };
            let base = self.wanted.get(&o.uid).cloned().unwrap_or_else(|| json!({}));
            let mut status = base;
            if r.kept_previous {
                merge(&mut status, &json!({ "message": message(&format!("spec refused, running its last good spec: {}", r.reason)) }));
            } else {
                merge(&mut status, &json!({ "phase": "Refused", "message": message(&r.reason) }));
            }
            targets.insert(o.uid.clone(), (o.clone(), status));
        }

        // Forget resources that are gone from the view.
        self.wanted.retain(|uid, _| targets.contains_key(uid) || view.objects.values().any(|o| &o.uid == uid));
        self.written.retain(|uid, _| targets.contains_key(uid));

        for (uid, (o, mut status)) in targets {
            status["observedGeneration"] = json!(o.generation);
            if self.written.get(&uid) == Some(&status) {
                continue;
            }
            match self.write(&o, &status) {
                Ok(()) => {
                    self.written.insert(uid, status);
                }
                Err(why) => eprintln!("taso-wardend: status of {}/{}: {why} (tried again next round)", o.namespace, o.name),
            }
        }
    }

    /// Read the resource, check it is the one meant and still this node's,
    /// and patch it at the version read.
    fn write(&self, o: &ObjectRef, status: &Value) -> Result<(), String> {
        let now = self.api.get(&o.namespace, &o.name).map_err(|e| e.to_string())?;
        let meta = &now["metadata"];
        if meta["uid"].as_str() != Some(o.uid.as_str()) {
            return Err("not written: the resource was replaced (another uid)".into());
        }
        if now["spec"]["node"].as_str() != Some(self.node.as_str()) {
            return Err(format!("not written: the resource is no longer on node {}", self.node));
        }
        let rv = meta["resourceVersion"].as_str().filter(|r| !r.is_empty()).ok_or("not written: no resourceVersion")?;
        self.api.patch(&o.namespace, &o.name, rv, status).map(|_| ()).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{Restart, Settled, Start, VesselConf};
    use crate::source::Refused;
    use crate::source_kube::KubeRefused;
    use std::sync::{Arc, Mutex};
    use taso_core::envelope::{HashVal, Lsn};
    use taso_core::record::Namespace;

    fn vc(subject: &str) -> VesselConf {
        VesselConf { namespace: Namespace::from_bytes([0x0a; 16]), subject: subject.into(), takeover: false, uid_slot: 1, restart: Restart::Always, runtime: None }
    }

    fn key(subject: &str) -> VesselKey {
        *vc(subject).id().as_bytes()
    }

    fn pos(n: u64) -> crate::segment::Position {
        crate::segment::Position { lsn: Lsn::new(n), hash: HashVal::from_bytes([n as u8; 32]) }
    }

    fn report(agent: Option<(bool, &str)>, stopped: bool) -> Report {
        Report {
            subject: "v1".into(),
            start: Start::Open,
            connections: 1,
            published: 2,
            publish_failures: 0,
            pruned: 0,
            prune_failures: (0, None),
            agent: agent.map(|(ok, e)| (ok, e.to_string())),
            settled: Settled { birth: None, rolled_back_to: Some(pos(4)), last_seal: Some(pos(5)) },
            stopped,
        }
    }

    const W: WardenId = WardenId::new(7);

    #[test]
    fn events_become_statuses() {
        let s = |e| status_of(&e, W).map(|(_, v)| v);
        assert_eq!(s(Event::Started(vc("v1"))), Some(json!({ "phase": "Running", "holder": 7, "message": "agent started" })));
        let exited = s(Event::Exited { vc: vc("v1"), out: Ok(report(Some((false, "boom\n")), false)), stopped: false, restart_in: Some(Duration::from_secs(4)) }).unwrap();
        assert_eq!(
            exited,
            json!({
                "phase": "Exited", "holder": 7, "start": "Open",
                "settled": { "birthSeal": null, "rolledBackTo": 4, "behind": true },
                "message": "agent failed: boom; restarts in 4s"
            })
        );
        let ok = s(Event::Exited { vc: vc("v1"), out: Ok(report(Some((true, "")), false)), stopped: false, restart_in: None }).unwrap();
        assert_eq!(ok["message"], "agent exited ok");
        let stopped = s(Event::Exited { vc: vc("v1"), out: Ok(report(Some((false, "killed")), true)), stopped: true, restart_in: None }).unwrap();
        assert_eq!(stopped["message"], "stopped on request");
        let never = s(Event::Exited { vc: vc("v1"), out: Ok(report(None, false)), stopped: false, restart_in: None }).unwrap();
        assert_eq!(never["message"], "the agent never ran");

        let refused = s(Event::Exited { vc: vc("v1"), out: Err(DaemonError::Refused("held by Warden 2".into())), stopped: false, restart_in: None }).unwrap();
        assert_eq!(refused, json!({ "phase": "Refused", "message": "refused: held by Warden 2" }));
        let failed = s(Event::Exited { vc: vc("v1"), out: Err(DaemonError::Io("mount: no".into())), stopped: false, restart_in: Some(Duration::from_millis(10)) }).unwrap();
        assert_eq!(failed, json!({ "phase": "Failed", "message": "mount: no; restarts in 1s" }));
        assert_eq!(s(Event::Panicked { vc: vc("v1"), restart_in: None }).unwrap()["phase"], "Failed");

        let r = |kept| Refused { subject: "v1".into(), key: key("v1"), reason: "uid_slot 1 is bound".into(), kept_previous: kept };
        assert_eq!(s(Event::Refused(r(false))), Some(json!({ "phase": "Refused", "message": "uid_slot 1 is bound" })));
        let kept = s(Event::Refused(r(true))).unwrap();
        assert!(kept.get("phase").is_none(), "a kept Vessel keeps its phase: {kept}");
        assert!(kept["message"].as_str().unwrap().contains("last good"));

        assert_eq!(s(Event::Stopping(vc("v1"))), None);
        assert_eq!(s(Event::SourceFailed(crate::source::SourceError("x".into()))), None);
        let (k, _) = status_of(&Event::Started(vc("v2")), W).unwrap();
        assert_eq!(k, key("v2"), "keyed by the Vessel");
    }

    #[test]
    fn messages_are_bounded_on_a_char_boundary() {
        assert_eq!(message("short"), "short");
        let long = "ä".repeat(MAX_MESSAGE);
        let m = message(&long);
        assert!(m.len() <= MAX_MESSAGE && m.ends_with("..."), "{}", m.len());
        assert_eq!(message(&"a".repeat(MAX_MESSAGE)).len(), MAX_MESSAGE);
    }

    #[test]
    fn merge_patch() {
        let mut v = json!({ "a": 1, "s": { "x": 1, "y": 2 } });
        merge(&mut v, &json!({ "a": null, "b": 2, "s": { "y": null, "z": 3 } }));
        assert_eq!(v, json!({ "b": 2, "s": { "x": 1, "z": 3 } }));
        merge(&mut v, &json!({ "s": 5 }));
        assert_eq!(v["s"], 5);
    }

    // ── The writer ──────────────────────────────────────────────────

    /// One resource on the fake API server.
    #[derive(Clone, Debug)]
    struct Obj {
        uid: String,
        node: String,
        rv: u64,
        status: Value,
    }

    /// A fake API server: objects by namespace/name, merge-patching with
    /// the resourceVersion precondition; can fail, or change an object
    /// between the get and the patch.
    #[derive(Clone, Default)]
    struct Fake {
        objs: Arc<Mutex<BTreeMap<String, Obj>>>,
        down: Arc<Mutex<bool>>,
        bump_after_get: Arc<Mutex<bool>>,
        no_rv: Arc<Mutex<bool>>,
        patches: Arc<Mutex<u32>>,
        gets: Arc<Mutex<u32>>,
    }

    impl Fake {
        fn put(&self, name: &str, uid: &str, node: &str) {
            self.objs.lock().unwrap().insert(format!("team-a/{name}"), Obj { uid: uid.into(), node: node.into(), rv: 1, status: json!({}) });
        }
        fn status(&self, name: &str) -> Value {
            self.objs.lock().unwrap()[&format!("team-a/{name}")].status.clone()
        }
        fn patches(&self) -> u32 {
            *self.patches.lock().unwrap()
        }
    }

    impl StatusApi for Fake {
        fn get(&self, ns: &str, name: &str) -> Result<Value, KubeError> {
            *self.gets.lock().unwrap() += 1;
            if *self.down.lock().unwrap() {
                return Err(KubeError::Transport("down".into()));
            }
            let mut objs = self.objs.lock().unwrap();
            let o = objs.get_mut(&format!("{ns}/{name}")).ok_or(KubeError::Status { code: 404, reason: "NotFound".into(), message: String::new() })?;
            let rv = if *self.no_rv.lock().unwrap() { String::new() } else { o.rv.to_string() };
            let v = json!({ "metadata": { "uid": o.uid, "resourceVersion": rv }, "spec": { "node": o.node }, "status": o.status });
            if *self.bump_after_get.lock().unwrap() {
                o.rv += 1; // someone else wrote in between
            }
            Ok(v)
        }
        fn patch(&self, ns: &str, name: &str, rv: &str, status: &Value) -> Result<Value, KubeError> {
            let mut objs = self.objs.lock().unwrap();
            let o = objs.get_mut(&format!("{ns}/{name}")).unwrap();
            // As the API server: an empty resourceVersion is no precondition.
            if !rv.is_empty() && o.rv.to_string() != rv {
                return Err(KubeError::Status { code: 409, reason: "Conflict".into(), message: "modified".into() });
            }
            merge(&mut o.status, status);
            o.rv += 1;
            *self.patches.lock().unwrap() += 1;
            Ok(Value::Null)
        }
    }

    fn obj(name: &str, uid: &str) -> ObjectRef {
        ObjectRef { namespace: "team-a".into(), name: name.into(), uid: uid.into(), generation: 2 }
    }

    fn view(objs: &[(&str, &str)], refused: Vec<KubeRefused>) -> View {
        View { objects: objs.iter().map(|(n, u)| (key(n), obj(n, u))).collect(), refused }
    }

    fn writer(fake: &Fake) -> Writer<Fake> {
        Writer { api: fake.clone(), view: SharedView::default(), node: "node-a".into(), wanted: BTreeMap::new(), written: BTreeMap::new() }
    }

    fn started(n: &str) -> (VesselKey, Value) {
        status_of(&Event::Started(vc(n)), W).unwrap()
    }

    #[test]
    fn statuses_are_written_once_with_the_generation() {
        let fake = Fake::default();
        fake.put("v1", "u1", "node-a");
        let mut w = writer(&fake);
        let v = view(&[("v1", "u1")], vec![]);
        w.round(&v, vec![started("v1")]);
        assert_eq!(fake.status("v1"), json!({ "phase": "Running", "holder": 7, "message": "agent started", "observedGeneration": 2 }));
        w.round(&v, vec![]);
        w.round(&v, vec![started("v1")]);
        assert_eq!(fake.patches(), 1, "the same status is not written again");
        let exited = status_of(&Event::Exited { vc: vc("v1"), out: Ok(report(Some((true, "")), false)), stopped: false, restart_in: None }, W).unwrap();
        w.round(&v, vec![exited]);
        assert_eq!(fake.status("v1")["phase"], "Exited");
        assert_eq!(fake.status("v1")["settled"]["rolledBackTo"], 4);
        assert_eq!(fake.patches(), 2);
    }

    #[test]
    fn only_resources_in_the_view_that_are_still_the_same_and_on_this_node() {
        let fake = Fake::default();
        fake.put("v1", "u1", "node-a");
        fake.put("moved", "u2", "node-b");
        fake.put("replaced", "u3-new", "node-a");
        let mut w = writer(&fake);
        let v = view(&[("v1", "u1"), ("moved", "u2"), ("replaced", "u3")], vec![]);
        // An event for a Vessel the view has no resource for: nothing.
        let gone = status_of(&Event::Panicked { vc: vc("gone"), restart_in: None }, W).unwrap();
        w.round(&v, vec![gone, started("v1"), started("moved"), started("replaced")]);
        assert_eq!(fake.status("v1")["phase"], "Running");
        assert_eq!(fake.status("moved"), json!({}), "another node's: not written");
        assert_eq!(fake.status("replaced"), json!({}), "another uid: not written");
        assert_eq!(fake.patches(), 1);
        // Gone from the view: forgotten, never written later.
        fake.put("replaced", "u3", "node-a");
        w.round(&view(&[("v1", "u1")], vec![]), vec![]);
        w.round(&view(&[("v1", "u1")], vec![]), vec![]);
        assert_eq!(fake.status("replaced"), json!({}));
        assert!(w.wanted.keys().all(|u| u == "u1"), "{:?}", w.wanted.keys());

        // Back in the view (say it moved away and back, and another Warden
        // wrote its status meanwhile): written again on its next event.
        w.round(&view(&[], vec![]), vec![]);
        fake.objs.lock().unwrap().get_mut("team-a/v1").unwrap().status = json!({ "phase": "Exited", "holder": 9 });
        w.round(&v, vec![started("v1")]);
        assert_eq!(fake.status("v1")["holder"], 7, "what was written before it left counts no more");
    }

    #[test]
    fn an_event_for_a_vessel_without_a_resource_writes_nothing() {
        let fake = Fake::default();
        fake.put("v1", "u1", "node-a");
        let mut w = writer(&fake);
        let gone = status_of(&Event::Panicked { vc: vc("gone"), restart_in: None }, W).unwrap();
        w.round(&view(&[("v1", "u1")], vec![]), vec![gone]);
        assert_eq!((fake.status("v1"), fake.patches()), (json!({}), 0));
    }

    #[test]
    fn no_resource_version_no_write() {
        let fake = Fake::default();
        fake.put("v1", "u1", "node-a");
        *fake.no_rv.lock().unwrap() = true;
        let mut w = writer(&fake);
        w.round(&view(&[("v1", "u1")], vec![]), vec![started("v1")]);
        assert_eq!((fake.status("v1"), fake.patches()), (json!({}), 0));
    }

    #[test]
    fn a_failed_or_conflicting_write_is_tried_again() {
        let fake = Fake::default();
        fake.put("v1", "u1", "node-a");
        let mut w = writer(&fake);
        let v = view(&[("v1", "u1")], vec![]);
        *fake.down.lock().unwrap() = true;
        w.round(&v, vec![started("v1")]);
        assert_eq!(fake.status("v1"), json!({}));
        *fake.down.lock().unwrap() = false;
        *fake.bump_after_get.lock().unwrap() = true;
        w.round(&v, vec![]);
        assert_eq!(fake.status("v1"), json!({}), "changed between get and patch: 409, nothing written");
        *fake.bump_after_get.lock().unwrap() = false;
        w.round(&v, vec![]);
        assert_eq!(fake.status("v1")["phase"], "Running", "written once it could be");
    }

    #[test]
    fn source_refusals_are_shown() {
        let fake = Fake::default();
        fake.put("bad", "u1", "node-a");
        fake.put("kept", "u2", "node-a");
        let mut w = writer(&fake);
        let refused = |n: &str, u: &str, kept| KubeRefused { object: Some(obj(n, u)), reason: format!("{n} is wrong"), kept_previous: kept };
        let v = view(&[("kept", "u2")], vec![refused("bad", "u1", false), refused("kept", "u2", true), KubeRefused { object: None, reason: "nameless".into(), kept_previous: false }]);
        w.round(&v, vec![started("kept")]);
        assert_eq!(fake.status("bad"), json!({ "phase": "Refused", "message": "bad is wrong", "observedGeneration": 2 }));
        let kept = fake.status("kept");
        assert_eq!(kept["phase"], "Running", "a kept Vessel keeps running and says so");
        assert!(kept["message"].as_str().unwrap().contains("last good spec: kept is wrong"), "{kept}");
        // Fixed: the refusal is gone, the event's status comes back.
        w.round(&view(&[("kept", "u2")], vec![]), vec![]);
        assert_eq!(fake.status("kept")["message"], "agent started");
    }

    #[test]
    fn the_thread_writes_queued_events_and_finishes() {
        let fake = Fake::default();
        fake.put("v1", "u1", "node-a");
        let shared = SharedView::default();
        *shared.lock().unwrap() = view(&[("v1", "u1")], vec![]);
        let sw = StatusWriter::spawn(fake.clone(), shared, "node-a".into(), W, Duration::from_secs(60));
        sw.event(&Event::Started(vc("v1")));
        sw.event(&Event::Stopping(vc("v1")));
        sw.finish();
        assert_eq!(fake.status("v1")["phase"], "Running");
        assert_eq!(fake.patches(), 1);
    }

    #[test]
    fn finishing_tries_a_failed_write_once_more() {
        let fake = Fake::default();
        fake.put("v1", "u1", "node-a");
        *fake.down.lock().unwrap() = true;
        let shared = SharedView::default();
        *shared.lock().unwrap() = view(&[("v1", "u1")], vec![]);
        let sw = StatusWriter::spawn(fake.clone(), shared, "node-a".into(), W, Duration::from_secs(60));
        sw.event(&Event::Started(vc("v1")));
        let t = std::time::Instant::now();
        while *fake.gets.lock().unwrap() == 0 {
            assert!(t.elapsed() < Duration::from_secs(10), "the first write was never tried");
            std::thread::sleep(Duration::from_millis(5));
        }
        *fake.down.lock().unwrap() = false;
        sw.finish();
        assert_eq!(fake.status("v1")["phase"], "Running");
    }

    /// Against a real API server (the kube client test's TASO_KUBE_API,
    /// TASO_KUBE_TOKEN_FILE, TASO_KUBE_CA) and TASO_KUBE_VESSEL=ns/name of
    /// a Vessel on TASO_KUBE_NODE whose status this test may write.
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
        let target = env("TASO_KUBE_VESSEL");
        let (ns, name) = target.split_once('/').unwrap();
        let now = StatusApi::get(&kube, ns, name).unwrap();
        let o = ObjectRef {
            namespace: ns.into(),
            name: name.into(),
            uid: now["metadata"]["uid"].as_str().unwrap().into(),
            generation: now["metadata"]["generation"].as_u64().unwrap(),
        };
        let k = key("real");
        let v = View { objects: [(k, o.clone())].into(), refused: vec![] };
        let mut w = Writer { api: kube, view: SharedView::default(), node: env("TASO_KUBE_NODE"), wanted: BTreeMap::new(), written: BTreeMap::new() };
        let exited = status_of(&Event::Exited { vc: vc("real"), out: Ok(report(Some((false, "boom")), false)), stopped: false, restart_in: Some(Duration::from_secs(2)) }, W).unwrap().1;
        w.round(&v, vec![(k, exited)]);
        let after = StatusApi::get(&w.api, ns, name).unwrap();
        assert_eq!(after["status"]["phase"], "Exited", "{after}");
        assert_eq!(after["status"]["settled"], json!({ "rolledBackTo": 4, "behind": true }), "null fields cleared");
        assert_eq!(after["status"]["observedGeneration"], o.generation);
        assert_eq!(after["status"]["message"], "agent failed: boom; restarts in 2s");
        // Another uid: nothing written.
        let other = View { objects: [(k, ObjectRef { uid: "not-it".into(), ..o })].into(), refused: vec![] };
        let mut w2 = Writer { wanted: BTreeMap::new(), written: BTreeMap::new(), ..w };
        w2.round(&other, vec![started("real")]);
        assert_eq!(StatusApi::get(&w2.api, ns, name).unwrap()["status"]["phase"], "Exited");
    }
}
