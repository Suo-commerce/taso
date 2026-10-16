//! The daemon end to end on one machine (needs root, runc and a ZFS pool:
//! set TASO_ZFS_DATASET).  Two "nodes" share the coordinator, the store
//! and the pool, each with its own root dataset and state directory:
//!
//! 1. node A: the Vessel is born, the agent runs 5 turns, each sealed and
//!    published;
//! 2. node A again: opened, the agent resumes after turn 5;
//! 3. node B, taking over: reborn from the store, the agent resumes after
//!    turn 10 with the database as of the last Seal;
//! 4. node A again, not taking over: refused.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use serde_json::{json, Value};
use taso_warden::coordinator::{Coord, Coordinator};
use taso_warden::daemon::{Config, Node, Start};
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
        let _ = Command::new("zfs").args(["destroy", "-R", &self.0]).status();
    }
}

fn config(tmp: &Path, base: &str, node: &str, warden: u64, takeover: bool) -> Config {
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
            "args": ["/usr/bin/taso-sim", "--turns", "5", "--txns", "2", "--rows", "3"],
            "memory_bytes": 268435456,
            "pids": 64
        },
        "vessels": [{ "namespace": "07070707070707070707070707070707", "subject": "sim-1", "takeover": takeover }]
    });
    Config::parse(&v.to_string()).unwrap()
}

fn stats(node: &Node) -> Value {
    let id = node.config.vessels[0].id();
    let hex: String = id.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let ds = format!("{}/v-{hex}", node.config.root);
    let mount = Command::new("zfs").args(["get", "-H", "-o", "value", "mountpoint", &ds]).output().unwrap();
    let mount = String::from_utf8(mount.stdout).unwrap();
    serde_json::from_str(&std::fs::read_to_string(Path::new(mount.trim()).join("sim-stats.json")).unwrap()).unwrap()
}

#[test]
#[ignore = "needs root, runc and a ZFS pool: set TASO_ZFS_DATASET"]
fn born_reopened_reborn_elsewhere_and_refused() {
    let base = format!("{}/daemon-{}", std::env::var("TASO_ZFS_DATASET").expect("set TASO_ZFS_DATASET"), std::process::id());
    for ds in [base.clone(), format!("{base}/a"), format!("{base}/b")] {
        assert!(Command::new("zfs").args(["create", &ds]).status().unwrap().success());
    }
    let _c = Cleanup(base.clone());
    let tmp = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    rootfs(&tmp.path().join("rootfs"));
    let coord: Arc<dyn Coord> = Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap());
    let node = |name: &str, warden: u64, takeover: bool| Node {
        config: config(tmp.path(), &base, name, warden, takeover),
        coord: coord.clone(),
        zfs: Zfs::cli().batched(),
    };

    // 1. Born on A.
    let a = node("a", 1, false);
    let r = a.run_vessel(&a.config.vessels[0]).unwrap();
    println!("A, first: {r:?}\n{}", stats(&a));
    assert_eq!(r.start, Start::Birth);
    assert!(r.agent.as_ref().unwrap().0, "agent failed: {:?}", r.agent);
    assert_eq!((r.published, r.publish_failures), (5, 0));
    let s = stats(&a);
    assert_eq!((s["turns"].clone(), s["sealed"].clone(), s["rows_in_db"].clone()), (json!([1, 5]), json!(5), json!(30)));

    // 2. Reopened on A: resumes after turn 5.
    let r = a.run_vessel(&a.config.vessels[0]).unwrap();
    println!("A, again: {r:?}\n{}", stats(&a));
    assert_eq!(r.start, Start::Open);
    assert_eq!((r.published, r.publish_failures), (5, 0), "the last Seal was already published: no extra");
    let s = stats(&a);
    assert_eq!((s["resumed_after"].clone(), s["turns"].clone(), s["rows_in_db"].clone()), (json!(5), json!([6, 10]), json!(60)));

    // 3. Reborn on B: resumes after turn 10 with the database of turn 10.
    let b = node("b", 2, true);
    let r = b.run_vessel(&b.config.vessels[0]).unwrap();
    println!("B, takeover: {r:?}\n{}", stats(&b));
    assert_eq!(r.start, Start::Rebirth);
    assert!(r.agent.as_ref().unwrap().0, "agent failed: {:?}", r.agent);
    let s = stats(&b);
    assert_eq!((s["resumed_after"].clone(), s["turns"].clone(), s["rows_in_db"].clone()), (json!(10), json!([11, 15]), json!(90)));
    assert_eq!(coord.ownership(a.config.vessels[0].id()).unwrap().holder.get(), 2);

    // 4. A may not take it back unasked.
    let e = a.run_vessel(&a.config.vessels[0]).unwrap_err();
    println!("A, after the takeover: {e}");
    assert!(e.to_string().contains("held by Warden 2"), "{e}");
}
