//! `BlkPool` on real devices: the Warden's Vessels on `taso-blkd`, ublk,
//! ext4 and real mounts (birth, Seal, forks, reopen, rollback), and
//! rebirth on a second node from shipped packs.  Needs root, ublk and two
//! running daemons (node A and node B), so it is ignored by default;
//! `scripts/blk-warden-test.sh` starts them on fresh logs and runs it:
//!
//! ```text
//! TASO_BLK_SOCKET=/run/a.sock TASO_BLK_SOCKET_B=/run/b.sock TASO_BLK_MOUNTS=/mnt/blk-warden \
//!   cargo test -p taso-warden --test blk_device -- --ignored --test-threads=1
//! ```
//!
//! The rebirth test ships its packs to a local directory, or to an S3
//! bucket when `TASO_BLK_S3_ENDPOINT` is set (with `TASO_BLK_S3_REGION`,
//! `TASO_BLK_S3_BUCKET`, `TASO_BLK_S3_ACCESS_KEY_ID` and
//! `TASO_BLK_S3_SECRET_KEY_FILE`): the Warden's own S3 client, under a
//! fresh prefix per run.
//!
//! Every mount it makes is unmounted when the test ends, also when it fails.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use taso_core::envelope::Lsn;
use taso_core::model::WardenId;
use taso_core::record::{Namespace, StreamCut, TurnId, Verdict};
use taso_warden::blk::BlkPool;
use taso_warden::chronicle::Layers;
use taso_warden::coordinator::Coordinator;
use taso_warden::daemon::StoreConf;
use taso_warden::pack::Packs;
use taso_warden::ship::SharedStore;
use taso_warden::vessel::{Host, Pool};
use taso_warden::zfs::Dataset;

/// The daemon's socket and the mount root, from the environment.
fn setup() -> (PathBuf, PathBuf) {
    let get = |k: &str| {
        std::env::var_os(k)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{k} is not set; see the file's header"))
    };
    let (socket, mounts) = (get("TASO_BLK_SOCKET"), get("TASO_BLK_MOUNTS"));
    assert!(
        mounts.is_absolute() && mounts != Path::new("/"),
        "TASO_BLK_MOUNTS must be an absolute directory other than /"
    );
    (socket, mounts)
}

/// Unmounts everything under the mount root when dropped.
struct Unmount(PathBuf);

impl Drop for Unmount {
    fn drop(&mut self) {
        let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
            return;
        };
        let root = self.0.to_string_lossy().to_string();
        let mut points: Vec<String> = info
            .lines()
            .filter_map(|l| l.split(' ').nth(4))
            .filter(|p| p.starts_with(&root))
            .map(str::to_string)
            .collect();
        points.sort_by_key(|p| std::cmp::Reverse(p.len())); // innermost first
        for p in points {
            let _ = Command::new("fsfreeze").arg("-u").arg(&p).output(); // never leave one frozen
            let _ = Command::new("umount").arg(&p).status();
        }
    }
}

fn seal<L: Layers>(
    v: &mut taso_warden::vessel::Vessel<L>,
    turn: u64,
) -> taso_warden::segment::Position {
    v.seal(
        StreamCut::EMPTY,
        Verdict::Clean,
        Lsn::new(0),
        TurnId::new(turn),
    )
    .unwrap()
    .seal
}

/// The mount options of the file system mounted at `dir` (super options
/// included), from /proc/self/mountinfo.
fn mount_options(dir: &std::path::Path) -> String {
    let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    for line in info.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f.get(4).map(std::path::Path::new) == Some(dir) {
            let sep = f.iter().position(|x| *x == "-").unwrap();
            return format!("{},{}", f[5], f.get(sep + 3).unwrap_or(&""));
        }
    }
    panic!("{} is not mounted", dir.display());
}

#[test]
#[ignore = "needs root, ublk and a running taso-blkd; run scripts/blk-warden-test.sh"]
fn vessels_on_real_devices() {
    let (socket, mounts) = setup();
    let _unmount = Unmount(mounts.clone());
    let state = tempfile::tempdir().unwrap();
    // A fresh root dataset per run, so runs never meet.
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let host = Host {
        coord: Arc::new(Coordinator::open(state.path().join("coord.redb")).unwrap()),
        pool: BlkPool::new(&socket, &mounts, state.path().join("spool")),
        root: Dataset::new(&format!("blk/run-{run}")).unwrap(),
        state_dir: state.path().join("state"),
        warden: WardenId::new(1),
    };
    let ns = Namespace::from_bytes([7; 16]);

    // Birth: a formatted, mounted dataset.
    let (mut v, _) = host.ensure(ns, b"user-1").unwrap();
    let mp = host
        .pool
        .info(v.dataset())
        .unwrap()
        .unwrap()
        .mountpoint
        .unwrap();
    assert!(mp.starts_with(&mounts));
    assert!(
        mount_options(&mp).split(',').any(|o| o == "discard"),
        "mounted -o discard: {}",
        mount_options(&mp)
    );
    let birth = v.seal_birth().unwrap().seal;

    // A file, then a Seal (ext4 frozen for it), then a change after it.
    std::fs::write(mp.join("note"), b"sealed").unwrap();
    let s1 = seal(&mut v, 1);
    std::fs::write(mp.join("note"), b"changed after the seal").unwrap();
    std::fs::write(mp.join("later"), b"only in the parent").unwrap();
    assert_eq!(
        host.pool.layers(v.dataset()).list().unwrap(),
        [(birth.lsn, birth.hash), (s1.lsn, s1.hash)]
    );

    // A fork of s1 sees exactly the sealed state.
    let child = host.fork(&v, s1, b"child-1").unwrap();
    let ci = host.pool.info(child.dataset()).unwrap().unwrap();
    assert_eq!(
        (ci.origin_seal(), ci.parent),
        (Some((v.dataset().clone(), s1.lsn)), Some(s1.hash))
    );
    let cmp = ci.mountpoint.unwrap();
    assert_eq!(std::fs::read(cmp.join("note")).unwrap(), b"sealed");
    assert!(
        !cmp.join("later").exists(),
        "a write after the Seal is not in the fork"
    );

    // The fork writes; the parent does not see it.
    std::fs::write(cmp.join("child-only"), b"x").unwrap();
    assert!(!mp.join("child-only").exists());
    assert_eq!(
        std::fs::read(mp.join("note")).unwrap(),
        b"changed after the seal"
    );

    // A second fork of the same Seal is independent of the first.
    let second = host.fork(&v, s1, b"child-2").unwrap();
    let smp = host
        .pool
        .info(second.dataset())
        .unwrap()
        .unwrap()
        .mountpoint
        .unwrap();
    assert_eq!(std::fs::read(smp.join("note")).unwrap(), b"sealed");
    assert!(!smp.join("child-only").exists());

    // Reopen the parent: lineage and layer checks pass on real layers.
    let id = v.id();
    drop((v, child, second));
    let (mut v, _) = host.open(id).unwrap();
    assert_eq!(v.last_seal(), Some(s1));
    let dev = host.pool.ensure_mounted(v.dataset()).unwrap();
    assert_eq!(
        host.pool.ensure_mounted(v.dataset()).unwrap(),
        dev,
        "mounted already: the same device"
    );

    // Rollback to the last Seal: unmount, reset, remount; the file is as
    // sealed again and the later one is gone.
    assert_eq!(v.rollback().unwrap(), Some(s1));
    assert_eq!(std::fs::read(mp.join("note")).unwrap(), b"sealed");
    assert!(!mp.join("later").exists());
    assert_eq!(
        host.pool.layers(v.dataset()).list().unwrap(),
        [(birth.lsn, birth.hash), (s1.lsn, s1.hash)]
    );
}

#[test]
#[ignore = "needs root, ublk and two running taso-blkd; run scripts/blk-warden-test.sh"]
fn rebirth_on_a_second_node_from_shipped_packs() {
    let (socket_a, mounts) = setup();
    let socket_b = std::env::var_os("TASO_BLK_SOCKET_B")
        .map(PathBuf::from)
        .expect("TASO_BLK_SOCKET_B is not set");
    let _unmount = Unmount(mounts.clone());
    let state = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(state.path().join("store")).unwrap();
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let coord = Arc::new(Coordinator::open(state.path().join("coord.redb")).unwrap());
    let node = |n: u64, socket: &Path| Host {
        coord: coord.clone(),
        pool: BlkPool::new(
            socket,
            mounts.join(format!("node-{n}")),
            state.path().join(format!("spool-{n}")),
        ),
        root: Dataset::new(&format!("blk/reb-{run}")).unwrap(),
        state_dir: state.path().join(format!("state-{n}")),
        warden: WardenId::new(n),
    };
    let (a, b) = (node(1, &socket_a), node(2, &socket_b));
    let store: SharedStore = match std::env::var("TASO_BLK_S3_ENDPOINT") {
        Ok(endpoint) => {
            let env = |k: &str| {
                std::env::var(k)
                    .unwrap_or_else(|_| panic!("{k} is not set (TASO_BLK_S3_ENDPOINT is)"))
            };
            eprintln!(
                "packs in S3: {endpoint}, bucket {}",
                env("TASO_BLK_S3_BUCKET")
            );
            StoreConf::S3 {
                endpoint,
                region: env("TASO_BLK_S3_REGION"),
                bucket: env("TASO_BLK_S3_BUCKET"),
                access_key_id: env("TASO_BLK_S3_ACCESS_KEY_ID"),
                secret_key_file: env("TASO_BLK_S3_SECRET_KEY_FILE").into(),
                ca_file: None,
            }
            .open()
            .unwrap()
        }
        Err(_) => StoreConf::Local(state.path().join("store")).open().unwrap(),
    };
    let prefix = format!("taso-test/reb-{run}");
    let packs =
        |h: &Host<BlkPool>, id| Packs::new(store.clone(), h.pool.sender(), &prefix, id).unwrap();
    let publish = |h: &Host<BlkPool>,
                   v: &mut taso_warden::vessel::Vessel<taso_warden::blk::BlkLayers>,
                   at: Lsn,
                   origin: Option<&taso_warden::zfs::Snapshot>| {
        let snap = h.pool.snapshot(v.dataset(), at).unwrap().unwrap();
        v.publish_seal(&packs(h, v.id()), &snap, origin).unwrap();
    };
    let ns = Namespace::from_bytes([9; 16]);

    // Node A: a Vessel writes, seals and ships; then writes what it never ships.
    let (mut v, _) = a.ensure(ns, b"user-1").unwrap();
    let mp = a
        .pool
        .info(v.dataset())
        .unwrap()
        .unwrap()
        .mountpoint
        .unwrap();
    let birth = v.seal_birth().unwrap().seal;
    publish(&a, &mut v, birth.lsn, None);
    std::fs::write(mp.join("note"), b"first").unwrap();
    let s1 = seal(&mut v, 1);
    publish(&a, &mut v, s1.lsn, None);
    std::fs::write(mp.join("note"), b"second").unwrap();
    std::fs::create_dir_all(mp.join("dir/deeper")).unwrap();
    std::fs::write(mp.join("dir/deeper/big"), vec![7u8; 3 << 20]).unwrap();
    let s2 = seal(&mut v, 2);
    publish(&a, &mut v, s2.lsn, None);
    std::fs::write(mp.join("unshipped"), b"lost with node A").unwrap();

    // A fork of s1 on node A, shipped incrementally from its parent Seal.
    let mut child = a.fork(&v, s1, b"child-1").unwrap();
    let cmp = a
        .pool
        .info(child.dataset())
        .unwrap()
        .unwrap()
        .mountpoint
        .unwrap();
    let cb = child.seal_birth().unwrap().seal;
    let origin = a.pool.snapshot(v.dataset(), s1.lsn).unwrap().unwrap();
    publish(&a, &mut child, cb.lsn, Some(&origin));
    std::fs::write(cmp.join("child-note"), b"from the fork").unwrap();
    let c1 = seal(&mut child, 1);
    publish(&a, &mut child, c1.lsn, None);

    // Node B: reborn from the packs alone, then mounted.
    let (w, r) = b.rebirth(v.id(), &packs(&b, v.id())).unwrap();
    assert_eq!(r.received, vec![birth.lsn, s1.lsn, s2.lsn]);
    b.pool.ensure_mounted(w.dataset()).unwrap();
    let wmp = b
        .pool
        .info(w.dataset())
        .unwrap()
        .unwrap()
        .mountpoint
        .unwrap();
    assert_eq!(
        std::fs::read(wmp.join("note")).unwrap(),
        b"second",
        "the state of the last shipped Seal"
    );
    assert_eq!(
        std::fs::read(wmp.join("dir/deeper/big")).unwrap(),
        vec![7u8; 3 << 20]
    );
    assert!(
        !wmp.join("unshipped").exists(),
        "nothing after the last shipped Seal"
    );

    let (wc, _) = b.rebirth(child.id(), &packs(&b, child.id())).unwrap();
    b.pool.ensure_mounted(wc.dataset()).unwrap();
    let wcmp = b
        .pool
        .info(wc.dataset())
        .unwrap()
        .unwrap()
        .mountpoint
        .unwrap();
    assert_eq!(
        std::fs::read(wcmp.join("note")).unwrap(),
        b"first",
        "the fork stands on s1"
    );
    assert_eq!(
        std::fs::read(wcmp.join("child-note")).unwrap(),
        b"from the fork"
    );
    assert!(!wcmp.join("dir").exists(), "nothing of the parent after s1");
    let info = b.pool.info(wc.dataset()).unwrap().unwrap();
    assert_eq!(
        (info.origin_seal(), info.parent),
        (Some((w.dataset().clone(), s1.lsn)), Some(s1.hash))
    );
}
