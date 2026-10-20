//! `taso-logcheck` and the gate's `logjudge.py` together, on real logs: a
//! takeover that loses records (Gap) and one that loses none.  The judge
//! must pass the honest logs and fail each way the evidence can be wrong.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use serde_json::Value;
use taso_core::envelope::{ChronicleId, HashVal, Lsn, Stream};
use taso_core::model::WardenId;
use taso_core::record::{Payload, StreamCut, TurnId, Verdict};
use taso_warden::chronicle::{restore_log, Chronicle, Claim, LayerError, Layers};
use taso_warden::coordinator::{Coord, Coordinator};
use taso_warden::coordsrv::Server;
use taso_warden::segment::Position;

const LOGCHECK: &str = env!("CARGO_BIN_EXE_taso-logcheck");
const A: WardenId = WardenId::new(1);
const B: WardenId = WardenId::new(2);

#[derive(Default)]
struct Mem(Vec<(Lsn, HashVal)>);
impl Layers for Mem {
    fn snapshot(&mut self, lsn: Lsn, hash: HashVal) -> Result<(), LayerError> {
        self.0.push((lsn, hash));
        Ok(())
    }
    fn list(&self) -> Result<Vec<(Lsn, HashVal)>, LayerError> {
        Ok(self.0.clone())
    }
    fn destroy(&mut self, lsn: Lsn) -> Result<(), LayerError> {
        self.0.retain(|(l, _)| *l != lsn);
        Ok(())
    }
}

fn hex(id: ChronicleId) -> String {
    id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

struct Env {
    tmp: tempfile::TempDir,
    coord: Arc<dyn Coord>,
    sock: PathBuf,
    _server: Server,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let coord: Arc<dyn Coord> = Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap());
    let sock = tmp.path().join("coord.sock");
    let server = Server::spawn(&sock, coord.clone()).unwrap();
    Env { tmp, coord, sock, _server: server }
}

/// A runs and ships up to `shipped` records out of `accepted`, then B takes
/// over from what was shipped and takes one Seal with `verdict`.
fn takeover(e: &Env, n: u8, shipped: u64, extra: u64, verdict: Verdict) -> ChronicleId {
    let id = ChronicleId::from_bytes([n; 16]);
    let (a_dir, b_dir) = (e.tmp.path().join("a").join(hex(id)), e.tmp.path().join("b").join(hex(id)));
    std::fs::create_dir_all(&a_dir).unwrap();
    let (mut a, _) = Chronicle::create(&a_dir, e.coord.clone(), id, A, Mem::default()).unwrap();
    a.append(Stream::Fs, Payload::Raw(vec![1])).unwrap();
    a.seal(StreamCut::EMPTY, Verdict::Clean, Lsn::new(0), TurnId::new(1)).unwrap();
    while a.tail().lsn.get() < shipped {
        a.append(Stream::Fs, Payload::Raw(vec![2])).unwrap();
    }
    let frames = a.frames().unwrap();
    let to = Position { lsn: Lsn::new(shipped), hash: frames[shipped as usize - 1].envelope.hash };
    e.coord.advance_shipped(A, id, a.epoch(), to).unwrap();
    for _ in 0..extra {
        a.append(Stream::Fs, Payload::Raw(vec![3])).unwrap(); // accepted, never shipped
    }
    std::fs::create_dir_all(b_dir.parent().unwrap()).unwrap();
    restore_log(&b_dir, id, &frames[..shipped as usize]).unwrap();
    let o = e.coord.ownership(id).unwrap();
    let claim = Claim::TakeOver { from: o.holder, epoch: o.epoch };
    let (mut b, _) = Chronicle::open_after_gap_as(&b_dir, e.coord.clone(), id, B, Mem::default(), claim).unwrap();
    b.append(Stream::Fs, Payload::Raw(vec![4])).unwrap();
    b.seal(StreamCut::EMPTY, verdict, Lsn::new(0), TurnId::new(2)).unwrap();
    id
}

fn logcheck(e: &Env, node: &str, id: ChronicleId) -> Value {
    let out = Command::new(LOGCHECK)
        .arg(&e.sock)
        .arg(e.tmp.path().join(node))
        .arg(hex(id))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}

fn judge(dir: &Path, a: &Value, b: &Value) -> Value {
    let (pa, pb) = (dir.join("a.json"), dir.join("b.json"));
    std::fs::write(&pa, a.to_string()).unwrap();
    std::fs::write(&pb, b.to_string()).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/gate-cloud/logjudge.py");
    let out = Command::new("python3").arg(script).arg(&pa).arg(&pb).output().expect("python3");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}

fn frames_mut(v: &mut Value) -> &mut Vec<Value> {
    v["frames"].as_array_mut().unwrap()
}

#[test]
fn a_takeover_that_loses_records_is_reported_and_judged() {
    let e = env();
    let id = takeover(&e, 1, 4, 2, Verdict::Unverified("reborn: records 5..6 were never shipped".into()));
    let (a, b) = (logcheck(&e, "a", id), logcheck(&e, "b", id));
    assert_eq!(b["ownership"]["sealed_prefix"]["lsn"], 6, "the head when B took over");
    let gap = b["frames"].as_array().unwrap().iter().find(|f| f["kind"] == "gap").unwrap().clone();
    assert_eq!((gap["kept"].clone(), gap["resumes"].clone(), gap["lsn"].clone()), (4.into(), 6.into(), 7.into()));
    let v = judge(e.tmp.path(), &a, &b);
    assert_eq!((v["ok"].clone(), v["lost"].clone()), (true.into(), 2.into()), "{v}");

    // Each way the evidence can be wrong fails.
    let fails = |a: &Value, b: &Value, what: &str| {
        let v = judge(e.tmp.path(), a, b);
        assert_eq!(v["ok"], false, "{what} passed: {v}");
    };
    let mut b2 = b.clone();
    for f in frames_mut(&mut b2) {
        if f["kind"] == "seal" && f["lsn"].as_u64() > Some(7) {
            f["verdict"] = "clean".into();
            f["reason"] = "".into();
        }
    }
    fails(&a, &b2, "a Clean first Seal after a gap");
    let mut b2 = b.clone();
    for f in frames_mut(&mut b2) {
        if f["kind"] == "seal" && f["lsn"].as_u64() > Some(7) {
            f["reason"] = "reborn: records 5..9 were never shipped".into();
        }
    }
    fails(&a, &b2, "a verdict naming another range");
    let mut b2 = b.clone();
    frames_mut(&mut b2).retain(|f| f["kind"] != "gap");
    fails(&a, &b2, "no Gap record");
    let mut b2 = b.clone();
    b2["ownership"]["sealed_prefix"]["hash"] = HashVal::GENESIS.to_string().into();
    fails(&a, &b2, "a Gap that does not name the coordinator's head");
    let mut a2 = a.clone();
    frames_mut(&mut a2).retain(|f| f["lsn"] != 5);
    fails(&a2, &b, "a lost record missing from A's log");
    let mut b2 = b.clone();
    let mut extra = gap.clone();
    extra["lsn"] = 5.into();
    frames_mut(&mut b2).push(extra);
    fails(&a, &b2, "two Gap records");
}

#[test]
fn a_takeover_that_loses_nothing_is_judged() {
    let e = env();
    let id = takeover(&e, 2, 4, 0, Verdict::Clean);
    let (a, b) = (logcheck(&e, "a", id), logcheck(&e, "b", id));
    assert!(b["frames"].as_array().unwrap().iter().all(|f| f["kind"] != "gap"));
    let v = judge(e.tmp.path(), &a, &b);
    assert_eq!((v["ok"].clone(), v["lost"].clone()), (true.into(), 0.into()), "{v}");

    let mut b2 = b.clone();
    for f in frames_mut(&mut b2) {
        if f["kind"] == "seal" && f["epoch"] == b["ownership"]["epoch"] {
            f["verdict"] = "unverified".into();
        }
    }
    let v = judge(e.tmp.path(), &a, &b2);
    assert_eq!(v["ok"], false, "an Unverified first Seal with nothing lost passed: {v}");
}
