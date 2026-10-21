//! The daemon end to end on one machine (needs root, runc and a ZFS pool:
//! set TASO_ZFS_DATASET).  Two "nodes" share the coordinator, the store
//! and the pool, each with its own root dataset and state directory:
//!
//! 1. node A: the Vessel is born and takes its birth Seal, the agent runs
//!    5 turns, each sealed and published (6 Seals published);
//! 2. node A again, after a stray file was left in the dataset (what a
//!    turn cut short by a crash leaves): opened, the state rolled back to
//!    the last Seal (the file is gone), the agent resumes after turn 5;
//! 3. node B, taking over: reborn from the store, the agent resumes after
//!    turn 10 with the database as of the last Seal;
//! 4. node A again, not taking over: refused.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use serde_json::{json, Value};
use taso_warden::coordinator::{Coord, Coordinator};
use taso_warden::daemon::{Config, DaemonError, Node, Report, Restart, Start, Stop, VesselConf};
use taso_warden::source::{Guard, SourceError, VesselSource};
use taso_warden::storage::Storage;
use taso_warden::supervisor::{Event, Supervisor, Timing};
use taso_warden::zfs::Zfs;

const SIM: &str = env!("CARGO_BIN_EXE_taso-sim");

fn rootfs(root: &Path) {
    let mut files = vec![(PathBuf::from(SIM), PathBuf::from("usr/bin/taso-sim"))];
    let ldd = Command::new("ldd").arg(SIM).output().unwrap();
    for tok in String::from_utf8_lossy(&ldd.stdout).split_whitespace() {
        if let Some(rel) = tok.strip_prefix('/') {
            files.push((PathBuf::from(tok), PathBuf::from(rel)));
        }
    }
    for d in ["proc", "dev", "sys", "tmp", "work", "run/taso"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("run/taso/field.sock"), b"").unwrap();
    for (src, dst) in files {
        let dst = root.join(dst);
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::copy(src, dst).unwrap();
    }
}

struct Cleanup(String);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new("zfs")
            .args(["destroy", "-R", &self.0])
            .status();
    }
}

/// `takeover`: the ownership to take over, `(holder, epoch)` as read from
/// the coordinator (F2: a takeover names what it replaces).
fn config(tmp: &Path, base: &str, node: &str, warden: u64, takeover: Option<(u64, u64)>) -> Config {
    config_with(
        tmp,
        base,
        node,
        warden,
        takeover,
        "sim-1",
        &["--turns", "5", "--txns", "2", "--rows", "3"],
    )
}

fn config_with(
    tmp: &Path,
    base: &str,
    node: &str,
    warden: u64,
    takeover: Option<(u64, u64)>,
    subject: &str,
    sim_args: &[&str],
) -> Config {
    let mut args = vec!["/usr/bin/taso-sim"];
    args.extend_from_slice(sim_args);
    let v = json!({
        "warden": warden,
        "coordinator": { "local": tmp.join("coord.redb") },
        "root": format!("{base}/{node}"),
        "state_dir": tmp.join(node).join("state"),
        "store": tmp.join("store"),
        "run_dir": tmp.join(node).join("run"),
        "runtime": {
            "rootfs": tmp.join("rootfs"),
            "host_uid_base": 200000,
            "args": args,
            "memory_bytes": 268435456,
            "pids": 64
        },
        "vessels": [{ "namespace": "07070707070707070707070707070707", "subject": subject,
                      "takeover": takeover.map(|(h, e)| json!({"holder": h, "epoch": e})), "uid_slot": 3 }]
    });
    Config::parse(&v.to_string()).unwrap()
}

fn mount(node: &Node) -> PathBuf {
    let id = node.config.vessels[0].id();
    let hex: String = id.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let ds = format!("{}/v-{hex}", node.config.root);
    let mount = Command::new("zfs")
        .args(["get", "-H", "-o", "value", "mountpoint", &ds])
        .output()
        .unwrap();
    PathBuf::from(String::from_utf8(mount.stdout).unwrap().trim())
}

fn stats(node: &Node) -> Value {
    let mount = mount(node);
    let mount = mount.to_str().unwrap();
    // The dataset belongs to this Vessel's own uid range (slot 3), on every node.
    let owner = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(mount.trim()).unwrap());
    assert_eq!(
        Some(owner),
        node.config.vessels[0].host_uid(&node.config.runtime)
    );
    assert_eq!(owner, 200_000 + 3 * 65_536);
    serde_json::from_str(
        &std::fs::read_to_string(Path::new(mount.trim()).join("sim-stats.json")).unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "needs root, runc and a ZFS pool: set TASO_ZFS_DATASET"]
fn born_reopened_reborn_elsewhere_and_refused() {
    let base = format!(
        "{}/daemon-{}",
        std::env::var("TASO_ZFS_DATASET").expect("set TASO_ZFS_DATASET"),
        std::process::id()
    );
    for ds in [base.clone(), format!("{base}/a"), format!("{base}/b")] {
        assert!(Command::new("zfs")
            .args(["create", &ds])
            .status()
            .unwrap()
            .success());
    }
    let _c = Cleanup(base.clone());
    let tmp = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    rootfs(&tmp.path().join("rootfs"));
    let coord: Arc<dyn Coord> = Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap());
    let node = |name: &str, warden: u64, takeover: Option<(u64, u64)>| {
        Node::new(
            config(tmp.path(), &base, name, warden, takeover),
            coord.clone(),
            Storage::Zfs(Zfs::cli().batched()),
        )
        .unwrap()
    };

    // 1. Born on A.
    let a = node("a", 1, None);
    let r = a.run_vessel(&a.config.vessels[0]).unwrap();
    // The agent's result first: a failed agent wrote no stats.
    assert!(r.agent.as_ref().unwrap().0, "agent failed: {:?}", r.agent);
    println!("A, first: {r:?}\n{}", stats(&a));
    assert_eq!(r.start, Start::Birth);
    let birth = r.settled.birth.expect("a birth Seal");
    assert_eq!(birth.lsn.get(), 2, "right after the Lineage record");
    assert_eq!(
        (r.settled.rolled_back_to, r.settled.last_seal),
        (Some(birth), Some(birth))
    );
    assert_eq!(
        (r.published, r.publish_failures, r.prune_failures.0),
        (6, 0, 0),
        "the birth Seal and 5 turns"
    );
    let s = stats(&a);
    assert_eq!(
        (
            s["turns"].clone(),
            s["sealed"].clone(),
            s["rows_in_db"].clone()
        ),
        (json!([1, 5]), json!(5), json!(30))
    );

    // 2. Reopened on A after a crashed turn left a file behind: the state
    //    is rolled back to the last Seal, then the agent resumes after turn 5.
    let stray = mount(&a).join("stray-from-a-crashed-turn");
    std::fs::write(&stray, b"written after the last Seal").unwrap();
    let r = a.run_vessel(&a.config.vessels[0]).unwrap();
    assert!(r.agent.as_ref().unwrap().0, "agent failed: {:?}", r.agent);
    println!("A, again: {r:?}\n{}", stats(&a));
    assert_eq!(r.start, Start::Open);
    assert!(
        !stray.exists(),
        "a file written after the last Seal is gone"
    );
    assert_eq!(r.settled.birth, None, "a birth Seal only once");
    assert!(
        r.settled.rolled_back_to.is_some_and(|s| s.lsn.get() > 2),
        "{:?}",
        r.settled
    );
    assert_eq!(r.settled.rolled_back_to, r.settled.last_seal);
    assert_eq!(
        (r.published, r.publish_failures),
        (5, 0),
        "the last Seal was already published: no extra"
    );
    let s = stats(&a);
    assert_eq!(
        (
            s["resumed_after"].clone(),
            s["turns"].clone(),
            s["rows_in_db"].clone()
        ),
        (json!(5), json!([6, 10]), json!(60))
    );

    // 3. Reborn on B: resumes after turn 10 with the database of turn 10.
    //    B's operator read who holds it and names exactly that.
    let o = coord.ownership(a.config.vessels[0].id()).unwrap();
    let b = node("b", 2, Some((o.holder.get(), o.epoch.get())));
    let r = b.run_vessel(&b.config.vessels[0]).unwrap();
    assert!(r.agent.as_ref().unwrap().0, "agent failed: {:?}", r.agent);
    println!("B, takeover: {r:?}\n{}", stats(&b));
    assert_eq!(r.start, Start::Rebirth);
    assert_eq!(r.settled.birth, None);
    assert!(r.settled.rolled_back_to.is_some());
    assert_eq!(
        r.settled.rolled_back_to, r.settled.last_seal,
        "a reborn dataset is at its last Seal"
    );
    let s = stats(&b);
    assert_eq!(
        (
            s["resumed_after"].clone(),
            s["turns"].clone(),
            s["rows_in_db"].clone()
        ),
        (json!(10), json!([11, 15]), json!(90))
    );
    assert_eq!(
        coord
            .ownership(a.config.vessels[0].id())
            .unwrap()
            .holder
            .get(),
        2
    );

    // 4. A may not take it back unasked.
    let e = a.run_vessel(&a.config.vessels[0]).unwrap_err();
    println!("A, after the takeover: {e}");
    assert!(e.to_string().contains("held by Warden 2"), "{e}");
}

// ── W1: the supervisor on a real node ─────────────────────────────────

/// A source the test drives: each pushed set is answered once.
#[derive(Clone, Default)]
struct Driven(Arc<std::sync::Mutex<std::collections::VecDeque<Vec<VesselConf>>>>);

impl VesselSource for Driven {
    fn poll(&mut self, wait: std::time::Duration) -> Result<Option<Vec<VesselConf>>, SourceError> {
        let next = self.0.lock().unwrap().pop_front();
        if next.is_none() {
            std::thread::sleep(wait);
        }
        Ok(next)
    }
    fn is_finite(&self) -> bool {
        false
    }
}

impl Driven {
    fn push(&self, set: Vec<VesselConf>) {
        self.0.lock().unwrap().push_back(set);
    }
}

/// What the test sees of one run.
#[derive(Debug)]
struct Seen {
    stopped: bool,
    agent_ok: Option<bool>,
    restarting: bool,
    /// sim-stats.json as the agent left it (only if it exited by itself).
    stats: Option<Value>,
}

fn taso_sim_processes() -> usize {
    let out = Command::new("pgrep")
        .args(["-f", "^/usr/bin/taso-sim --turns 20 --turn-sleep-ms"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).lines().count()
}

fn snapshots(dataset: &str) -> usize {
    let out = Command::new("zfs")
        .args(["list", "-H", "-t", "snapshot", "-o", "name", "-r", dataset])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).lines().count()
}

fn wait_until(what: &str, secs: u64, mut cond: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while !cond() {
        assert!(
            std::time::Instant::now() < end,
            "timed out after {secs} s waiting for {what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// W1 on real ZFS and runc, one node:
///
/// 1. a slow agent is stopped mid-run by removing its Vessel from the
///    source: its container is gone at once, the run reports `stopped`;
/// 2. listed again (restart never): it starts afresh, resumes right after
///    its last sealed turn and runs to the end; the database holds exactly
///    one row per turn up to the last — a turn committed but not sealed when
///    the agent was killed was rolled back, not kept and done twice;
/// 3. listed with restart always: every run that ends by itself is started
///    again and resumes after the turn the one before ended on; once
///    removed, a run going is stopped (one waiting out its backoff is
///    dropped) and it is never started again.
#[test]
#[ignore = "needs root, runc and a ZFS pool: set TASO_ZFS_DATASET"]
fn supervisor_stops_relists_and_restarts_on_a_real_node() {
    let base = format!(
        "{}/w1-{}",
        std::env::var("TASO_ZFS_DATASET").expect("set TASO_ZFS_DATASET"),
        std::process::id()
    );
    for ds in [base.clone(), format!("{base}/a")] {
        assert!(Command::new("zfs")
            .args(["create", &ds])
            .status()
            .unwrap()
            .success());
    }
    let _c = Cleanup(base.clone());
    let tmp = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    rootfs(&tmp.path().join("rootfs"));
    let coord: Arc<dyn Coord> = Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap());
    let sim = [
        "--turns",
        "20",
        "--turn-sleep-ms",
        "50",
        "--txns",
        "1",
        "--rows",
        "1",
    ];
    let node = Arc::new(
        Node::new(
            // Its own Vessel (and so its own runc container id and cgroup):
            // the tests of this file run in parallel, and one container id
            // in two of them is refused by runc ("cgroup is not empty").
            config_with(tmp.path(), &base, "a", 1, None, "sim-2", &sim),
            coord,
            Storage::Zfs(Zfs::cli().batched()),
        )
        .unwrap(),
    );
    let vessel = node.config.vessels[0].clone();
    let with = |restart: Restart| VesselConf {
        restart,
        ..vessel.clone()
    };
    let id = vessel.id();
    let hex: String = id.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let dataset = format!("{base}/a/v-{hex}");

    let source = Driven::default();
    let shutdown = Stop::new();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<Seen>::new()));
    let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sup = {
        let (node, mut source, shutdown, seen, starts) = (
            node.clone(),
            source.clone(),
            shutdown.clone(),
            seen.clone(),
            starts.clone(),
        );
        let timing = Timing {
            tick: std::time::Duration::from_millis(50),
            backoff_first: std::time::Duration::from_millis(200),
            backoff_max: std::time::Duration::from_secs(1),
            healthy: std::time::Duration::from_secs(600),
        };
        std::thread::spawn(move || {
            let guard = Guard::new(node.config.runtime.clone());
            let stats_of = |node: &Node| -> Option<Value> {
                std::fs::read_to_string(mount(node).join("sim-stats.json"))
                    .ok()
                    .and_then(|t| serde_json::from_str(&t).ok())
            };
            Supervisor::new(node.clone(), guard, timing).run(
                &mut source,
                &shutdown,
                |e: Event<Result<Report, DaemonError>>| match e {
                    Event::Started(_) => {
                        starts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Event::Exited {
                        out,
                        stopped,
                        restart_in,
                        ..
                    } => {
                        let r = out.expect("the run itself must not fail");
                        println!("run ended: stopped={stopped} restart_in={restart_in:?} {r:?}");
                        // Read before any next start rolls the state back.
                        let stats = if stopped { None } else { stats_of(&node) };
                        seen.lock().unwrap().push(Seen {
                            stopped: r.stopped,
                            agent_ok: r.agent.as_ref().map(|a| a.0),
                            restarting: restart_in.is_some(),
                            stats,
                        });
                    }
                    Event::Panicked { .. } => panic!("a run panicked"),
                    Event::Refused(r) => panic!("refused: {r:?}"),
                    Event::SourceFailed(e) => panic!("{e}"),
                    Event::Stopping(_) => {}
                },
            )
        })
    };
    let runs = || seen.lock().unwrap().len();

    // 1. Run, then remove mid-run: stopped at once.
    source.push(vec![with(Restart::Never)]);
    wait_until("3 sealed turns (birth Seal + 3 snapshots)", 60, || {
        snapshots(&dataset) >= 4
    });
    assert_eq!(taso_sim_processes(), 1, "the agent runs");
    let asked = std::time::Instant::now();
    source.push(vec![]);
    wait_until("the stopped run to end", 10, || runs() == 1);
    println!("stopped in {:?}", asked.elapsed());
    {
        let s = &seen.lock().unwrap()[0];
        assert!(s.stopped, "the run reports it was stopped: {s:?}");
        assert_ne!(
            s.agent_ok,
            Some(true),
            "a killed agent did not exit ok: {s:?}"
        );
    }
    assert_eq!(
        taso_sim_processes(),
        0,
        "no agent process outlives its stop"
    );

    // 2. Listed again: resumes after its last sealed turn, runs to the end,
    //    and the database holds exactly one row per turn.
    source.push(vec![with(Restart::Never)]);
    wait_until("the second run to end by itself", 120, || runs() == 2);
    let (resumed, last) = {
        let s = &seen.lock().unwrap()[1];
        assert!(
            !s.stopped && s.agent_ok == Some(true) && !s.restarting,
            "{s:?}"
        );
        let st = s.stats.as_ref().expect("stats of a finished run");
        let resumed = st["resumed_after"]
            .as_u64()
            .expect("it resumed after a sealed turn");
        let (first, last) = (
            st["turns"][0].as_u64().unwrap(),
            st["turns"][1].as_u64().unwrap(),
        );
        assert!(
            resumed >= 3,
            "at least the 3 turns sealed before the stop: {st}"
        );
        assert_eq!(
            first,
            resumed + 1,
            "resumes right after its last sealed turn: {st}"
        );
        assert_eq!(
            st["rows_in_db"].as_u64(),
            Some(last),
            "one row per turn, none twice and none lost: {st}"
        );
        (resumed, last)
    };
    println!("second run: resumed after {resumed}, ran to {last}");

    // 3. Restart always: runs that end by themselves start again and go on
    //    from where the one before ended; removal stops it for good.
    source.push(vec![]);
    std::thread::sleep(std::time::Duration::from_millis(300));
    source.push(vec![with(Restart::Always)]);
    wait_until("two more runs ending by themselves", 180, || runs() >= 4);
    source.push(vec![]);
    // Removed while a run is going (it is stopped) or while one waits out
    // its backoff (nothing runs, nothing starts again): either way, every
    // run started has ended.
    let all_ended = || runs() == starts.load(std::sync::atomic::Ordering::SeqCst);
    wait_until("every started run to end after the removal", 30, || {
        all_ended() && taso_sim_processes() == 0
    });
    let starts_at_removal = starts.load(std::sync::atomic::Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_millis(1500)); // past any backoff
    assert_eq!(
        starts.load(std::sync::atomic::Ordering::SeqCst),
        starts_at_removal,
        "never started again once removed"
    );
    assert_eq!(taso_sim_processes(), 0);
    {
        let seen = seen.lock().unwrap();
        let finished: Vec<&Value> = seen[2..]
            .iter()
            .filter(|s| !s.stopped)
            .map(|s| s.stats.as_ref().unwrap())
            .collect();
        assert!(finished.len() >= 2, "{seen:?}");
        let mut prev_last = last;
        for st in finished {
            assert_eq!(
                st["resumed_after"].as_u64(),
                Some(prev_last),
                "each run resumes where the one before ended: {st}"
            );
            prev_last = st["turns"][1].as_u64().unwrap();
            assert_eq!(st["rows_in_db"].as_u64(), Some(prev_last), "{st}");
        }
        assert!(
            seen[2..]
                .iter()
                .filter(|s| !s.stopped)
                .all(|s| s.restarting),
            "always: every run that ended by itself was restarted"
        );
    }

    shutdown.request();
    sup.join().unwrap();
    assert_eq!(taso_sim_processes(), 0);
}
