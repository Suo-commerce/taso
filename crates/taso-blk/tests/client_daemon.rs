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
        let d = Daemon(Command::new(env!("CARGO_BIN_EXE_taso-blkd")).arg(log).arg(sock).spawn().unwrap());
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
    assert!(matches!(c.branch(root, Some("tank/taso/a")), Err(ClientError::Daemon(e)) if e.contains("taken")));
    assert!(matches!(c.branch(root, Some("bad!name")), Err(ClientError::Daemon(_))));
    assert!(matches!(c.branch(root, Some("tank taso")), Err(ClientError::BadArgument(_))));
    assert_eq!(c.stats().unwrap()["records"], records, "refused names append nothing");
    assert_eq!(c.find("tank/taso/a").unwrap(), Some(a));
    assert_eq!(c.find("nope").unwrap(), None);

    let tag: Vec<u8> = (0..64).collect();
    let s1 = c.seal(a, &tag).unwrap();
    let s2 = c.seal(a, b"").unwrap();
    assert!(matches!(c.seal(a, &[0; 65]), Err(ClientError::Daemon(_))));
    assert_eq!(c.seals(a).unwrap(), vec![(s1, tag.clone()), (s2, vec![])]);

    let i = c.info(s1).unwrap();
    assert_eq!((i.kind, i.parent, i.tag, i.origin, i.dev), (LayerKind::Seal, Some(root), Some(tag.clone()), Some(a), None));
    assert_eq!(c.info(s2).unwrap().tag, Some(vec![]));
    let i = c.info(a).unwrap();
    assert_eq!((i.kind, i.parent, i.name.as_deref(), i.tag), (LayerKind::Branch, Some(s2), Some("tank/taso/a"), None));

    // Export a Seal, import it into a fresh branch, seal: the same image,
    // so exporting the copy gives the same bytes.
    let (f1, f2) = (dir.path().join("s2.blks"), dir.path().join("copy.blks"));
    let n = c.export(s2, None, &f1).unwrap();
    assert!(matches!(c.export(s2, None, &f1), Err(ClientError::Daemon(_))), "never over an existing file");
    assert!(matches!(c.export(s2, None, Path::new("relative.blks")), Err(ClientError::BadArgument(_))));
    let copy = c.branch(root, Some("tank/taso/copy")).unwrap();
    assert_eq!(c.import(copy, &f1).unwrap(), n);
    let cs = c.seal(copy, b"").unwrap();
    c.export(cs, None, &f2).unwrap();
    assert_eq!(std::fs::read(&f1).unwrap(), std::fs::read(&f2).unwrap());
    let empty = c.export(s2, Some(s2), &dir.path().join("empty.blks")).unwrap();
    assert_eq!(empty, 0, "nothing between a Seal and itself");
    assert_eq!(
        c.names().unwrap(),
        vec![("tank/taso/a".to_string(), a), ("tank/taso/copy".to_string(), copy)]
    );
    std::fs::write(dir.path().join("junk.blks"), b"junk").unwrap();
    let j = c.branch(root, Some("tank/taso/j")).unwrap();
    assert!(matches!(c.import(j, &dir.path().join("junk.blks")), Err(ClientError::Daemon(e)) if e.contains("bad import stream")));
    c.drop_layer(j).unwrap();

    c.reset(a).unwrap(); // detached: allowed
    assert_eq!(c.info(a).unwrap().parent, Some(s2), "a reset branch keeps its place");
    assert_eq!(c.seals(a).unwrap().len(), 2, "and its Seals");
    let b = c.branch(s1, Some("tank/taso/b")).unwrap();
    assert_eq!(c.seals(b).unwrap(), vec![], "a fork has no Seals of its own");
    c.name(b, Some("tank/taso/b2")).unwrap();
    assert_eq!(c.find("tank/taso/b").unwrap(), None);
    c.name(b, None).unwrap();
    assert_eq!(c.info(b).unwrap().name, None);
    assert!(matches!(c.drop_layer(s1), Err(ClientError::Daemon(_))), "b stands on s1");
    c.drop_layer(b).unwrap();
    c.drop_layer(s1).unwrap_err(); // a stands on s2, which stands on s1
    assert!(c.flush().unwrap() > 0);
    assert_eq!(c.stats().unwrap()["devices"], "0");
    assert!(c.checkpoint().unwrap() > 0);
    c.quit().unwrap();
    assert!(d.wait());
    assert!(dir.path().join("log.ckpt").exists(), "quit leaves a checkpoint");

    let d = Daemon::start(&log, &sock);
    let mut c = Client::connect(&sock).unwrap();
    assert_eq!(c.find("tank/taso/a").unwrap(), Some(a));
    assert_eq!(c.seals(a).unwrap(), vec![(s1, tag), (s2, vec![])]);
    assert!(matches!(c.info(b), Err(ClientError::Daemon(_))), "the dropped branch stays dropped");
    c.quit().unwrap();
    assert!(d.wait());
}
