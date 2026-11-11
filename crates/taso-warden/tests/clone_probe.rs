//! Finding 2.8 (K1-1 (c)) on a real kernel: inside a Vessel under runc,
//! `clone` with any namespace flag is refused with `EPERM`, `clone3`
//! answers `ENOSYS`, and a fork and a thread still work.
//!
//! Needs runc and root:
//! `cargo test -p taso-warden --test clone_probe -- --ignored --test-threads=1`.
//! The test runs this same binary as the Vessel's agent (`probe`, which
//! does nothing unless `TASO_CLONE_PROBE` is set).  It is a test file of
//! its own because the probe calls `clone` directly, and the crate keeps
//! one `unsafe` exception (`blk.rs`).

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use taso_warden::runtime::{prepare_work_dir, write_bundle, Runc, RuncCli, VesselSpec};

/// `clone(flags | SIGCHLD)`: "made" (the child leaves at once) or the errno.
fn try_clone(flags: u64) -> String {
    // SAFETY: a raw clone with no new stack; the child is a copy of this
    // process and leaves at once with `_exit`.
    let pid = unsafe { libc::syscall(libc::SYS_clone, flags | libc::SIGCHLD as u64, 0, 0, 0, 0) };
    if pid == 0 {
        unsafe { libc::_exit(0) };
    }
    if pid < 0 {
        return format!("errno {}", errno());
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid as i32, &mut st, 0) };
    "made".into()
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// The Vessel's agent: writes what each call gave to `/work/clone`.
#[test]
#[ignore = "the agent of no_namespace_is_made_inside_a_vessel_under_runc"]
fn probe() {
    if std::env::var_os("TASO_CLONE_PROBE").is_none() {
        return;
    }
    let mut out = String::new();
    for (name, flag) in [
        ("NEWNS", libc::CLONE_NEWNS),
        ("NEWCGROUP", libc::CLONE_NEWCGROUP),
        ("NEWUTS", libc::CLONE_NEWUTS),
        ("NEWIPC", libc::CLONE_NEWIPC),
        ("NEWUSER", libc::CLONE_NEWUSER),
        ("NEWPID", libc::CLONE_NEWPID),
        ("NEWNET", libc::CLONE_NEWNET),
    ] {
        out += &format!("{name} {}\n", try_clone(flag as u64));
    }
    // A user and a network namespace at once, as Chromium's sandbox asks.
    let both = (libc::CLONE_NEWUSER | libc::CLONE_NEWNET) as u64;
    out += &format!("NEWUSER+NEWNET {}\n", try_clone(both));
    out += &format!("FORK {}\n", try_clone(0));
    // struct clone_args (88 bytes), all zero: a fork with no exit signal.
    let args = [0u64; 11];
    let r = unsafe { libc::syscall(libc::SYS_clone3, args.as_ptr(), 88usize) };
    if r == 0 {
        unsafe { libc::_exit(0) };
    }
    let clone3 = if r < 0 {
        format!("errno {}", errno())
    } else {
        "made".into()
    };
    out += &format!("CLONE3 {clone3}\n");
    out += &format!("THREAD {}\n", std::thread::spawn(|| 7).join().unwrap());
    std::fs::write("/work/clone", out).unwrap();
}

/// Copy `prog` and the libraries `ldd` names into `root` at their paths.
fn add_binary(root: &Path, prog: &Path) {
    let ldd = Command::new("ldd").arg(prog).output().unwrap();
    let libs: Vec<PathBuf> = String::from_utf8_lossy(&ldd.stdout)
        .split_whitespace()
        .filter(|t| t.starts_with('/'))
        .map(PathBuf::from)
        .collect();
    for f in std::iter::once(prog.to_path_buf()).chain(libs) {
        let dst = root.join(f.strip_prefix("/").unwrap());
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::copy(&f, &dst).unwrap();
    }
}

#[test]
#[ignore = "needs runc and root"]
fn no_namespace_is_made_inside_a_vessel_under_runc() {
    let dir = tempfile::tempdir().unwrap();
    let rootfs = dir.path().join("rootfs");
    for d in ["proc", "dev", "sys", "tmp", "work", "run/taso"] {
        std::fs::create_dir_all(rootfs.join(d)).unwrap();
    }
    std::fs::write(rootfs.join("run/taso/field.sock"), b"").unwrap();
    let me = std::env::current_exe().unwrap();
    add_binary(&rootfs, &me);
    let work = dir.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let base = 200_000;
    prepare_work_dir(&work, base).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let sock = dir.path().join("field.sock");
    let _listener = UnixListener::bind(&sock).unwrap();
    let spec = VesselSpec {
        id: format!("taso-clone-{}", std::process::id()),
        rootfs,
        work: work.clone(),
        socket: sock,
        host_uid_base: base,
        disk_uid_base: None,
        args: vec![
            me.to_str().unwrap().into(),
            "--exact".into(),
            "probe".into(),
            "--ignored".into(),
            "--test-threads=1".into(),
        ],
        env: vec!["TASO_CLONE_PROBE=1".into()],
        landlock_shim: None,
        memory_bytes: Some(256 << 20),
        pids: Some(64),
    };
    let bundle = dir.path().join("bundle");
    write_bundle(&bundle, &spec).unwrap();
    let runc = Runc::new(RuncCli::new(dir.path().join("runc-state")));
    let (ok, err) = runc.run(&bundle, &spec.id).unwrap();
    let _ = runc.delete(&spec.id);
    assert!(ok, "the probe failed: {err}");
    let got = std::fs::read_to_string(work.join("clone")).unwrap();
    println!("{got}");
    assert_eq!(
        got,
        "NEWNS errno 1\nNEWCGROUP errno 1\nNEWUTS errno 1\nNEWIPC errno 1\n\
         NEWUSER errno 1\nNEWPID errno 1\nNEWNET errno 1\nNEWUSER+NEWNET errno 1\nFORK made\n\
         CLONE3 errno 38\nTHREAD 7\n"
    );
}
