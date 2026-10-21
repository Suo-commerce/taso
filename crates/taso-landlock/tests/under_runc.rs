//! The shim inside a real Vessel under runc (needs runc and root): the
//! same agent runs twice, without and with the shim, and only the writes
//! outside `/work` and `/tmp` change from allowed to refused.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use taso_warden::runtime::{
    check_rootfs, prepare_work_dir, write_bundle, Runc, RuncCli, VesselSpec,
};

const SHIM: &str = env!("CARGO_BIN_EXE_taso-landlock");
const SHIM_IN_ROOTFS: &str = "/usr/lib/taso/landlock";

/// A root filesystem with `/bin/sh`, the shim, and their libraries.
fn tiny_rootfs(root: &Path) {
    let sh = std::fs::canonicalize("/bin/sh").unwrap();
    let mut files: Vec<(PathBuf, PathBuf)> = vec![
        (sh.clone(), PathBuf::from("bin/sh")),
        (PathBuf::from(SHIM), PathBuf::from(&SHIM_IN_ROOTFS[1..])),
    ];
    for bin in [sh.as_path(), Path::new(SHIM)] {
        let ldd = Command::new("ldd").arg(bin).output().unwrap();
        for tok in String::from_utf8_lossy(&ldd.stdout).split_whitespace() {
            if let Some(rel) = tok.strip_prefix('/') {
                files.push((PathBuf::from(tok), PathBuf::from(rel)));
            }
        }
    }
    for d in ["bin", "proc", "dev", "sys", "tmp", "work", "run/taso"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("run/taso/field.sock"), b"").unwrap();
    for (src, dst) in files {
        let dst = root.join(dst);
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::copy(src, dst).unwrap();
    }
}

const AGENT: &str = r#"
t() { if ( eval "$2" ) 2>/dev/null; then echo "$1 yes"; else echo "$1 no"; fi; }
{
t work      'echo hi > /work/x'
t tmp       'echo hi > /tmp/x'
t dev_null  'echo hi > /dev/null'
t dev_shm   'echo hi > /dev/shm/x'
t dev_new   'echo hi > /dev/newfile'
t proc_oom  'echo 500 > /proc/self/oom_score_adj'
} > /work/out
"#;

/// Run the agent in a fresh Vessel; its probe results.
fn run(shim: bool) -> String {
    let dir = tempfile::tempdir().unwrap();
    let rootfs = dir.path().join("rootfs");
    tiny_rootfs(&rootfs);
    assert_eq!(check_rootfs(&rootfs), Vec::<String>::new());
    let work = dir.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let base = 200_000;
    prepare_work_dir(&work, base).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let sock = dir.path().join("field.sock");
    let _listener = UnixListener::bind(&sock).unwrap();
    let spec = VesselSpec {
        id: format!("taso-ll-{}-{}", std::process::id(), u8::from(shim)),
        rootfs,
        work: work.clone(),
        socket: sock,
        host_uid_base: base,
        args: vec!["/bin/sh".into(), "-c".into(), AGENT.into()],
        env: vec![],
        landlock_shim: shim.then(|| SHIM_IN_ROOTFS.to_string()),
        memory_bytes: Some(256 << 20),
        pids: Some(64),
    };
    let bundle = dir.path().join("bundle");
    write_bundle(&bundle, &spec).unwrap();
    let runc = Runc::new(RuncCli::new(dir.path().join("runc-state")));
    let (ok, err) = runc.run(&bundle, &spec.id).unwrap();
    let _ = runc.delete(&spec.id);
    assert!(ok, "the Vessel failed: {err}");
    std::fs::read_to_string(work.join("out")).unwrap()
}

#[test]
#[ignore = "needs runc and root"]
fn the_shim_confines_writes_in_a_vessel() {
    let without = run(false);
    let with = run(true);
    println!("without the shim:\n{without}\nwith the shim:\n{with}");
    for want in ["work yes", "tmp yes", "dev_null yes"] {
        assert!(with.lines().any(|l| l == want), "{want:?} with the shim");
    }
    for blocked in ["dev_shm", "dev_new", "proc_oom"] {
        assert!(
            without.lines().any(|l| l == format!("{blocked} yes")),
            "{blocked}: allowed without the shim (control)"
        );
        assert!(
            with.lines().any(|l| l == format!("{blocked} no")),
            "{blocked}: refused with the shim"
        );
    }
}
