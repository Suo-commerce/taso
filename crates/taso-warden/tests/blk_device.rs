//! `BlkPool` on real devices: the Warden's Vessels on `taso-blkd`, ublk,
//! ext4 and real mounts.  Needs root, ublk and a running daemon, so it is
//! ignored by default; `scripts/blk-warden-test.sh` starts a daemon on a
//! fresh log and runs it:
//!
//! ```text
//! TASO_BLK_SOCKET=/run/x.sock TASO_BLK_MOUNTS=/mnt/blk-warden \
//!   cargo test -p taso-warden --test blk_device -- --ignored --test-threads=1
//! ```
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
use taso_warden::vessel::{Host, Pool};
use taso_warden::zfs::Dataset;

/// The daemon's socket and the mount root, from the environment.
fn setup() -> (PathBuf, PathBuf) {
    let get = |k: &str| std::env::var_os(k).map(PathBuf::from).unwrap_or_else(|| panic!("{k} is not set; see the file's header"));
    let (socket, mounts) = (get("TASO_BLK_SOCKET"), get("TASO_BLK_MOUNTS"));
    assert!(mounts.is_absolute() && mounts != Path::new("/"), "TASO_BLK_MOUNTS must be an absolute directory other than /");
    (socket, mounts)
}

/// Unmounts everything under the mount root when dropped.
struct Unmount(PathBuf);

impl Drop for Unmount {
    fn drop(&mut self) {
        let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else { return };
        let root = self.0.to_string_lossy().to_string();
        let mut points: Vec<String> =
            info.lines().filter_map(|l| l.split(' ').nth(4)).filter(|p| p.starts_with(&root)).map(str::to_string).collect();
        points.sort_by_key(|p| std::cmp::Reverse(p.len())); // innermost first
        for p in points {
            let _ = Command::new("fsfreeze").arg("-u").arg(&p).output(); // never leave one frozen
            let _ = Command::new("umount").arg(&p).status();
        }
    }
}

fn seal<L: Layers>(v: &mut taso_warden::vessel::Vessel<L>, turn: u64) -> taso_warden::segment::Position {
    v.seal(StreamCut::EMPTY, Verdict::Clean, Lsn::new(0), TurnId::new(turn)).unwrap().seal
}

#[test]
#[ignore = "needs root, ublk and a running taso-blkd; run scripts/blk-warden-test.sh"]
fn vessels_on_real_devices() {
    let (socket, mounts) = setup();
    let _unmount = Unmount(mounts.clone());
    let state = tempfile::tempdir().unwrap();
    // A fresh root dataset per run, so runs never meet.
    let run = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    let host = Host {
        coord: Arc::new(Coordinator::open(state.path().join("coord.redb")).unwrap()),
        pool: BlkPool::new(&socket, &mounts),
        root: Dataset::new(&format!("blk/run-{run}")).unwrap(),
        state_dir: state.path().join("state"),
        warden: WardenId::new(1),
    };
    let ns = Namespace::from_bytes([7; 16]);

    // Birth: a formatted, mounted dataset.
    let (mut v, _) = host.ensure(ns, b"user-1").unwrap();
    let mp = host.pool.info(v.dataset()).unwrap().unwrap().mountpoint.unwrap();
    assert!(mp.starts_with(&mounts));
    let birth = v.seal_birth().unwrap().seal;

    // A file, then a Seal (ext4 frozen for it), then a change after it.
    std::fs::write(mp.join("note"), b"sealed").unwrap();
    let s1 = seal(&mut v, 1);
    std::fs::write(mp.join("note"), b"changed after the seal").unwrap();
    std::fs::write(mp.join("later"), b"only in the parent").unwrap();
    assert_eq!(host.pool.layers(v.dataset()).list().unwrap(), [(birth.lsn, birth.hash), (s1.lsn, s1.hash)]);

    // A fork of s1 sees exactly the sealed state.
    let child = host.fork(&v, s1, b"child-1").unwrap();
    let ci = host.pool.info(child.dataset()).unwrap().unwrap();
    assert_eq!((ci.origin_seal(), ci.parent), (Some((v.dataset().clone(), s1.lsn)), Some(s1.hash)));
    let cmp = ci.mountpoint.unwrap();
    assert_eq!(std::fs::read(cmp.join("note")).unwrap(), b"sealed");
    assert!(!cmp.join("later").exists(), "a write after the Seal is not in the fork");

    // The fork writes; the parent does not see it.
    std::fs::write(cmp.join("child-only"), b"x").unwrap();
    assert!(!mp.join("child-only").exists());
    assert_eq!(std::fs::read(mp.join("note")).unwrap(), b"changed after the seal");

    // A second fork of the same Seal is independent of the first.
    let second = host.fork(&v, s1, b"child-2").unwrap();
    let smp = host.pool.info(second.dataset()).unwrap().unwrap().mountpoint.unwrap();
    assert_eq!(std::fs::read(smp.join("note")).unwrap(), b"sealed");
    assert!(!smp.join("child-only").exists());

    // Reopen the parent: lineage and layer checks pass on real layers.
    let id = v.id();
    drop((v, child, second));
    let (v, _) = host.open(id).unwrap();
    assert_eq!(v.last_seal(), Some(s1));
    let dev = host.pool.ensure_mounted(v.dataset()).unwrap();
    assert_eq!(host.pool.ensure_mounted(v.dataset()).unwrap(), dev, "mounted already: the same device");
}
