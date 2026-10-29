//! E3-3c: a named pause inside one operation, for the crash harness.
//!
//! `hold(name)` does nothing unless the process was started with
//! `TASO_E3_HOLD=name`, and even then only once `<dir>/<name>.arm` exists:
//! the harness creates it just before the round's operation, so the reaches
//! before it (a Vessel's Birth Seal and its publish) pass straight through.
//! Armed, it writes `<dir>/<name>.held` (the pid) and waits, polling every
//! 10 ms for at most 60 s, for `<dir>/<name>.release`.
//! Under E3 the release never comes: the harness swaps the device and kills
//! the process while it waits.  `<dir>` is `TASO_E3_HOLD_DIR`, default
//! `/run/taso-e3`, on `/` and never on the device under test.
//! A hold pauses; it never fails the operation.  Off, the first call reads
//! the environment once; every call after is one load and one compare.
//! Named, each reach of that site also checks for the arm file.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static ARMED: OnceLock<Option<(String, PathBuf)>> = OnceLock::new();

/// Pause here if this process's hold is `name`.
pub fn hold(name: &str) {
    let armed = ARMED.get_or_init(|| {
        let name = std::env::var("TASO_E3_HOLD")
            .ok()
            .filter(|n| !n.is_empty())?;
        let dir = std::env::var_os("TASO_E3_HOLD_DIR")
            .map_or_else(|| PathBuf::from("/run/taso-e3"), PathBuf::from);
        Some((name, dir))
    });
    match armed {
        Some((want, dir)) if is_armed(name, want, dir) => wait(name, dir, Duration::from_secs(60)),
        _ => {}
    }
}

/// This process holds at `name`, and the harness has armed it.
fn is_armed(name: &str, want: &str, dir: &Path) -> bool {
    want == name && dir.join(format!("{name}.arm")).exists()
}

/// Write the marker, then wait for the release or the bound.  Best effort:
/// if the marker cannot be written the process still pauses, and the
/// harness reports "the hold was never reached".
fn wait(name: &str, dir: &Path, bound: Duration) {
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(
        dir.join(format!("{name}.held")),
        std::process::id().to_string(),
    );
    let release = dir.join(format!("{name}.release"));
    let until = Instant::now() + bound;
    while Instant::now() < until && !release.exists() {
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the system temp dir, one per test.
    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("taso-hold-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn arms_by_file() {
        let dir = scratch("arm");
        assert!(!is_armed("x", "x", &dir));
        std::fs::write(dir.join("x.arm"), "").unwrap();
        assert!(is_armed("x", "x", &dir));
        std::fs::write(dir.join("y.arm"), "").unwrap();
        assert!(!is_armed("y", "x", &dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn marks_and_releases() {
        let dir = scratch("release");
        std::fs::write(dir.join("x.release"), "").unwrap();
        let start = Instant::now();
        wait("x", &dir, Duration::from_secs(5));
        assert!(start.elapsed() < Duration::from_secs(1));
        let pid = std::fs::read_to_string(dir.join("x.held")).unwrap();
        assert_eq!(pid, std::process::id().to_string());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bounded_without_release() {
        let dir = scratch("bound");
        let start = Instant::now();
        wait("y", &dir, Duration::from_millis(50));
        assert!(start.elapsed() >= Duration::from_millis(50));
        assert!(dir.join("y.held").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
