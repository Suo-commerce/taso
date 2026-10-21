//! The shim on this kernel, without a container: what the agent can and
//! cannot do once restricted.  Skipped (with a note) on a kernel without
//! Landlock.

use std::path::Path;
use std::process::{Command, Output};

const SHIM: &str = env!("CARGO_BIN_EXE_taso-landlock");

fn shim(args: &[&str], script: &str) -> Output {
    Command::new(SHIM)
        .args(args)
        .args(["--", "/bin/sh", "-c", script])
        .env("TEST_PID", std::process::id().to_string())
        .output()
        .unwrap()
}

fn landlock_here() -> bool {
    let out = shim(&["--write", "/tmp"], "true");
    if out.status.code() == Some(70) {
        eprintln!("skipped: no Landlock in this kernel");
        return false;
    }
    assert!(out.status.success(), "{out:?}");
    true
}

#[test]
fn writes_only_beneath_the_write_paths() {
    if !landlock_here() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (w, o) = (dir.path().join("w"), dir.path().join("o"));
    std::fs::create_dir_all(&w).unwrap();
    std::fs::create_dir_all(&o).unwrap();
    std::fs::write(o.join("existing"), b"keep\n").unwrap();
    std::fs::write(w.join("mine"), b"m").unwrap();
    let script = format!(
        r#"
        t() {{ if ( eval "$2" ) 2>/dev/null; then echo "$1 yes"; else echo "$1 no"; fi; }}
        t write_w      'echo hi > {w}/ok'
        t mkdir_w      'mkdir {w}/d && rmdir {w}/d'
        t write_other  'echo hi > {o}/x'
        t read_other   'read l < {o}/existing'
        t trunc_other  ': > {o}/existing'
        t move_out     'mv {w}/mine {o}/mine'
        t dev_null     'echo hi > /dev/null'
        t signal_out   'kill -0 $TEST_PID'
        "#,
        w = w.display(),
        o = o.display()
    );
    // Control: without the shim every probe succeeds, so a "no" below is
    // Landlock's doing.  (Run it on a copy: it moves and truncates.)
    std::fs::create_dir_all(dir.path().join("c/w")).unwrap();
    std::fs::create_dir_all(dir.path().join("c/o")).unwrap();
    std::fs::write(dir.path().join("c/o/existing"), b"keep\n").unwrap();
    std::fs::write(dir.path().join("c/w/mine"), b"m").unwrap();
    let control = Command::new("/bin/sh")
        .args([
            "-c",
            &script.replace(
                &dir.path().display().to_string(),
                &format!("{}/c", dir.path().display()),
            ),
        ])
        .env("TEST_PID", std::process::id().to_string())
        .output()
        .unwrap();
    let c = String::from_utf8_lossy(&control.stdout).into_owned();
    assert!(
        c.lines()
            .all(|l| l.trim().is_empty() || l.trim().ends_with(" yes")),
        "control:\n{c}"
    );

    let out = shim(&["--write", w.to_str().unwrap()], &script);
    let text = String::from_utf8_lossy(&out.stdout);
    println!("{text}{}", String::from_utf8_lossy(&out.stderr));
    for want in [
        "write_w yes",
        "mkdir_w yes",
        "write_other no",
        "trunc_other no",
        "read_other yes",
        "move_out no",
        "dev_null yes",
        "signal_out no",
    ] {
        assert!(
            text.lines().any(|l| l.trim() == want),
            "expected {want:?} in:\n{text}"
        );
    }
    assert_eq!(std::fs::read(o.join("existing")).unwrap(), b"keep\n");
    assert!(!o.join("x").exists() && !o.join("mine").exists());
}

#[test]
fn a_missing_write_path_runs_nothing() {
    if !landlock_here() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let out = shim(
        &["--write", "/does/not/exist"],
        &format!("touch {}", marker.display()),
    );
    assert_eq!(out.status.code(), Some(71), "{out:?}");
    assert!(!Path::new(&marker).exists());
}

#[test]
fn usage_errors_run_nothing() {
    let out = Command::new(SHIM).args(["--write"]).output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    let out = Command::new(SHIM)
        .args(["--write", "/tmp", "--", "/does/not/exist"])
        .output()
        .unwrap();
    // With Landlock: restricted, then exec fails (126).  Without: 70.
    assert!(matches!(out.status.code(), Some(126) | Some(70)), "{out:?}");
}
