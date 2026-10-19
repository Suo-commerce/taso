//! The client against the real `taso-blkd`: both sides of the protocol
//! agree.  Everything but `attach` (which needs ublk and root), including a
//! restart on the same log.

#![cfg(feature = "daemon")]

use std::path::Path;
use std::process::{Child, Command};
use std::{thread, time::Duration};

use taso_blk::client::{Client, ClientError, LayerKind};

/// A running daemon, killed and reaped if the test ends early.
struct Daemon(Child);

impl Daemon {
    /// Start the daemon on `log` and wait for its socket.
    fn start(log: &Path, sock: &Path) -> Self {
        Self::start_with(log, sock, &[])
    }

    /// The same, with more arguments.
    fn start_with(log: &Path, sock: &Path, args: &[&str]) -> Self {
        Self::spawn(
            Command::new(env!("CARGO_BIN_EXE_taso-blkd"))
                .arg(log)
                .arg(sock)
                .args(args),
            sock,
        )
    }

    /// Start the command and wait for `sock`.
    fn spawn(cmd: &mut Command, sock: &Path) -> Self {
        let d = Daemon(cmd.spawn().unwrap());
        for _ in 0..250 {
            if sock.exists() {
                return d;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("taso-blkd did not open its socket");
    }

    /// Wait for it to exit after `quit`; true if it exited cleanly.
    fn wait(mut self) -> bool {
        self.0.wait().unwrap().success()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Ok(None) = self.0.try_wait() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn the_client_and_the_daemon_agree() {
    let dir = tempfile::tempdir().unwrap();
    let (log, sock) = (dir.path().join("log"), dir.path().join("sock"));
    let d = Daemon::start(&log, &sock);
    let mut c = Client::connect(&sock).unwrap();

    let root = c.root().unwrap();
    let a = c.branch(root, Some("tank/taso/a")).unwrap();
    let records = c.stats().unwrap()["records"].clone();
    assert!(
        matches!(c.branch(root, Some("tank/taso/a")), Err(ClientError::Daemon(e)) if e.contains("taken"))
    );
    assert!(matches!(
        c.branch(root, Some("bad!name")),
        Err(ClientError::Daemon(_))
    ));
    assert!(matches!(
        c.branch(root, Some("tank taso")),
        Err(ClientError::BadArgument(_))
    ));
    assert_eq!(
        c.stats().unwrap()["records"],
        records,
        "refused names append nothing"
    );
    assert_eq!(c.find("tank/taso/a").unwrap(), Some(a));
    assert_eq!(c.find("nope").unwrap(), None);

    let tag: Vec<u8> = (0..64).collect();
    let s1 = c.seal(a, &tag).unwrap();
    let s2 = c.seal(a, b"").unwrap();
    assert!(matches!(c.seal(a, &[0; 65]), Err(ClientError::Daemon(_))));
    assert_eq!(c.seals(a).unwrap(), vec![(s1, tag.clone()), (s2, vec![])]);

    let i = c.info(s1).unwrap();
    assert_eq!(
        (i.kind, i.parent, i.tag, i.origin, i.dev),
        (
            LayerKind::Seal,
            Some(root),
            Some(tag.clone()),
            Some(a),
            None
        )
    );
    assert_eq!(c.info(s2).unwrap().tag, Some(vec![]));
    let i = c.info(a).unwrap();
    assert_eq!(
        (i.kind, i.parent, i.name.as_deref(), i.tag),
        (LayerKind::Branch, Some(s2), Some("tank/taso/a"), None)
    );

    // Export a Seal, import it into a fresh branch, seal: the same image,
    // so exporting the copy gives the same bytes.
    let (f1, f2) = (dir.path().join("s2.blks"), dir.path().join("copy.blks"));
    let n = c.export(s2, None, &f1).unwrap();
    assert!(
        matches!(c.export(s2, None, &f1), Err(ClientError::Daemon(_))),
        "never over an existing file"
    );
    assert!(matches!(
        c.export(s2, None, Path::new("relative.blks")),
        Err(ClientError::BadArgument(_))
    ));
    let copy = c.branch(root, Some("tank/taso/copy")).unwrap();
    assert_eq!(c.import(copy, &f1).unwrap(), n);
    let cs = c.seal(copy, b"").unwrap();
    c.export(cs, None, &f2).unwrap();
    assert_eq!(std::fs::read(&f1).unwrap(), std::fs::read(&f2).unwrap());
    let empty = c
        .export(s2, Some(s2), &dir.path().join("empty.blks"))
        .unwrap();
    assert_eq!(empty, 0, "nothing between a Seal and itself");
    assert_eq!(
        c.names().unwrap(),
        vec![
            ("tank/taso/a".to_string(), a),
            ("tank/taso/copy".to_string(), copy)
        ]
    );
    std::fs::write(dir.path().join("junk.blks"), b"junk").unwrap();
    let j = c.branch(root, Some("tank/taso/j")).unwrap();
    assert!(
        matches!(c.import(j, &dir.path().join("junk.blks")), Err(ClientError::Daemon(e)) if e.contains("bad import stream"))
    );
    c.drop_layer(j).unwrap();

    c.reset(a).unwrap(); // detached: allowed
    assert_eq!(
        c.info(a).unwrap().parent,
        Some(s2),
        "a reset branch keeps its place"
    );
    assert_eq!(c.seals(a).unwrap().len(), 2, "and its Seals");
    let b = c.branch(s1, Some("tank/taso/b")).unwrap();
    assert_eq!(
        c.seals(b).unwrap(),
        vec![],
        "a fork has no Seals of its own"
    );
    c.name(b, Some("tank/taso/b2")).unwrap();
    assert_eq!(c.find("tank/taso/b").unwrap(), None);
    c.name(b, None).unwrap();
    assert_eq!(c.info(b).unwrap().name, None);
    assert!(
        matches!(c.drop_layer(s1), Err(ClientError::Daemon(_))),
        "b stands on s1"
    );
    c.drop_layer(b).unwrap();
    c.drop_layer(s1).unwrap_err(); // a stands on s2, which stands on s1
    assert!(c.flush().unwrap() > 0);
    assert_eq!(c.stats().unwrap()["devices"], "0");
    assert!(c.checkpoint().unwrap() > 0);
    let k = c.compact().unwrap();
    let n = |key: &str| k[key].parse::<u64>().unwrap();
    assert!(
        n("after") <= n("before") && n("live") <= n("after"),
        "{k:?}"
    );
    assert_eq!(
        c.stats().unwrap()["garbage_bytes"],
        "0",
        "compacted: no garbage left"
    );
    assert_eq!(
        c.find("tank/taso/a").unwrap(),
        Some(a),
        "names survive a compaction"
    );
    c.quit().unwrap();
    assert!(d.wait());
    assert!(
        dir.path().join("log.ckpt").exists(),
        "quit leaves a checkpoint"
    );

    let d = Daemon::start(&log, &sock);
    let mut c = Client::connect(&sock).unwrap();
    assert_eq!(c.find("tank/taso/a").unwrap(), Some(a));
    assert_eq!(c.seals(a).unwrap(), vec![(s1, tag), (s2, vec![])]);
    assert!(
        matches!(c.info(b), Err(ClientError::Daemon(_))),
        "the dropped branch stays dropped"
    );
    c.quit().unwrap();
    assert!(d.wait());
}

/// An export stream of `n` blocks of `byte` from block 0 (the store's
/// stream format, written by hand).
fn stream(byte: u8, n: u32) -> Vec<u8> {
    let mut b = b"TASOBLKX".to_vec();
    b.push(1);
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&n.to_le_bytes());
    b.extend(std::iter::repeat_n(byte, n as usize * 4096));
    b.push(0);
    b.extend_from_slice(&u64::from(n).to_le_bytes());
    let h = blake3::hash(&b);
    b.extend_from_slice(h.as_bytes());
    b
}

#[test]
fn the_daemon_compacts_by_itself_and_keeps_what_is_live() {
    let dir = tempfile::tempdir().unwrap();
    let (log, sock) = (dir.path().join("log"), dir.path().join("sock"));
    let d = Daemon::start_with(
        &log,
        &sock,
        &["--compact-pct", "20", "--compact-min-mib", "0"],
    );
    let mut c = Client::connect(&sock).unwrap();
    let root = c.root().unwrap();
    let blocks = dir.path().join("in.blks");
    std::fs::write(&blocks, stream(0xab, 256)).unwrap();
    // Kept: a Seal of 256 blocks.  Garbage: the same again, reset away.
    let keep = c.branch(root, Some("tank/keep")).unwrap();
    c.import(keep, &blocks).unwrap();
    let sealed = c.seal(keep, b"").unwrap();
    let gone = c.branch(root, None).unwrap();
    c.import(gone, &blocks).unwrap();
    c.reset(gone).unwrap();
    c.flush().unwrap();
    assert_eq!(
        c.stats().unwrap()["garbage_bytes"],
        (256 * 4096).to_string()
    );
    // The upkeep thread looks every 5 s.
    let mut compacted = false;
    for _ in 0..60 {
        thread::sleep(Duration::from_millis(250));
        if c.stats().unwrap()["garbage_bytes"] == "0" {
            compacted = true;
            break;
        }
    }
    assert!(compacted, "no automatic compaction within 15 s");
    assert_eq!(&std::fs::read(&log).unwrap()[..8], b"TASOBLK3");
    let out = dir.path().join("out.blks");
    c.export(sealed, None, &out).unwrap();
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(&blocks).unwrap(),
        "the Seal's blocks, unchanged"
    );
    assert_eq!(c.find("tank/keep").unwrap(), Some(keep));
    c.quit().unwrap();
    assert!(d.wait());
    // And it starts again on the compacted log.
    let d = Daemon::start(&log, &sock);
    let mut c = Client::connect(&sock).unwrap();
    std::fs::remove_file(&out).unwrap();
    c.export(sealed, None, &out).unwrap();
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(&blocks).unwrap()
    );
    c.quit().unwrap();
    assert!(d.wait());
}

/// The daemon's log on a full disk: every write to it fails.  Logging must
/// never take the daemon down (on taso-test, 2026-10-18, a failed log write
/// panicked a device thread holding the store, and the daemon could not
/// quit).  /dev/full fails every write with ENOSPC.
#[test]
fn the_daemon_works_when_its_log_cannot_be_written() {
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (log, sock) = (dir.path().join("log"), dir.path().join("sock"));
    let d = Daemon::spawn(
        Command::new(env!("CARGO_BIN_EXE_taso-blkd"))
            .arg(&log)
            .arg(&sock)
            .stderr(full),
        &sock,
    );
    let mut c = Client::connect(&sock).unwrap();
    let root = c.root().unwrap();
    let a = c.branch(root, Some("tank/full")).unwrap();
    std::fs::write(dir.path().join("in.blks"), stream(0x5a, 8)).unwrap();
    c.import(a, &dir.path().join("in.blks")).unwrap();
    c.reset(a).unwrap();
    assert!(c.checkpoint().unwrap() > 0);
    c.compact().unwrap();
    c.quit().unwrap();
    assert!(
        d.wait(),
        "quit exits cleanly although nothing could be logged"
    );
}
