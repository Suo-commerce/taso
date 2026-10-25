//! The decider socket (P4 spec rev. 22 §5.1, D72, D78; file 8b).
//!
//! A Unix socket, mode 0600 in a 0700 directory; the socket is the
//! authentication in P4 (D1a): each connection's uid and pid are read
//! with `SO_PEERCRED` and are the `peer` of what it asks. Frames are the
//! Field's, each body at most `max_frame_bytes`; at most
//! `max_connections` connections at once (one more is answered `Error`
//! and closed). Messages: [`taso_core::decider`].
//!
//! A connection says `Hello { version: 1 }` first, once. A malformed or
//! out-of-order request, an unknown version, or a `Verdict` whose
//! `request_id` is not the one its peer's uid, `op_kind = Verdict` and its
//! body derive, is answered `Error` and the connection is closed: nothing
//! is recorded. What a [`Decide`] cannot do (it failed) is answered
//! `Error` and the connection stays open.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 22, BLAKE3
//! `f3a54561505ebef478c43426273d79c789ec60dc74d0ff9c74ae0455720bde46`.

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use taso_core::contract::{Peer, VerdictRequest};
use taso_core::decider::{PendingItem, Reply, Request, VerdictAnswer, VERSION};
use taso_core::frame::{self, FrameError};

/// The decider socket's settings (`decider.*`, §11.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeciderConf {
    /// The socket; its directory is made 0700.
    pub socket: PathBuf,
    /// The largest body accepted.
    pub max_frame_bytes: u32,
    /// Connections at once.
    pub max_connections: usize,
}

impl DeciderConf {
    /// The defaults under `run_dir`: `<run_dir>/decide/decide.sock`, 1 MiB,
    /// 8 connections.
    pub fn defaults(run_dir: &Path) -> Self {
        Self {
            socket: run_dir.join("decide").join("decide.sock"),
            max_frame_bytes: 1 << 20,
            max_connections: 8,
        }
    }
}

/// What the socket asks of the Warden.
pub trait Decide: Send + Sync {
    /// The pending Candidates (D73).
    fn pending(&self) -> Result<Vec<PendingItem>, String>;
    /// A verdict from `peer`, whose `request_id` has been checked (D74).
    fn verdict(&self, request: &VerdictRequest, peer: Peer) -> Result<VerdictAnswer, String>;
}

/// The serving socket.  Dropping it stops it.
pub struct DeciderServer {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    conns: Arc<Mutex<HashMap<u64, UnixStream>>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    accept: Option<JoinHandle<()>>,
}

const ACCEPT_POLL: Duration = Duration::from_millis(10);

impl DeciderServer {
    /// Make the socket's directory (0700), bind the socket (0600) and
    /// serve `d` on it, one thread per connection.  A stale socket file
    /// is replaced; one another server answers on is refused.
    pub fn spawn(conf: &DeciderConf, d: Arc<dyn Decide>) -> io::Result<Self> {
        let path = conf.socket.clone();
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "socket has no directory")
            })?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_socket() => {
                if UnixStream::connect(&path).is_ok() {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!("{} is served by a live Warden", path.display()),
                    ));
                }
                std::fs::remove_file(&path)?;
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener: UnixListener = crate::coordsrv::bind_private(&path, None)?;
        listener.set_nonblocking(true)?;
        let (max_frame, max_conns) = (conf.max_frame_bytes, conf.max_connections);
        let stop = Arc::new(AtomicBool::new(false));
        let conns: Arc<Mutex<HashMap<u64, UnixStream>>> = Arc::default();
        let workers: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let accept = {
            let (stop, conns, workers) = (stop.clone(), conns.clone(), workers.clone());
            std::thread::spawn(move || {
                let mut next = 0u64;
                while !stop.load(Ordering::SeqCst) {
                    let mut stream = match listener.accept() {
                        Ok((s, _)) => s,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(ACCEPT_POLL);
                            continue;
                        }
                        Err(_) => continue,
                    };
                    if stream.set_nonblocking(false).is_err() {
                        continue;
                    }
                    // A peer that cannot be read is a dropped connection.
                    let Ok(cred) = rustix::net::sockopt::socket_peercred(&stream) else {
                        continue;
                    };
                    let peer = Peer {
                        uid: cred.uid.as_raw(),
                        pid: cred.pid.as_raw_nonzero().get() as u32,
                    };
                    if lock(&conns).len() >= max_conns {
                        let _ = send(
                            &mut stream,
                            &Reply::Error {
                                message: format!(
                                    "{max_conns} connections are open: try again later"
                                ),
                            },
                        );
                        continue;
                    }
                    let Ok(handle) = stream.try_clone() else {
                        continue;
                    };
                    let id = next;
                    next += 1;
                    lock(&conns).insert(id, handle);
                    let (d, conns_w) = (d.clone(), conns.clone());
                    let w = std::thread::spawn(move || {
                        serve_conn(d.as_ref(), stream, peer, max_frame);
                        lock(&conns_w).remove(&id);
                    });
                    let mut ws = lock(&workers);
                    ws.retain(|w| !w.is_finished());
                    ws.push(w);
                }
            })
        };
        Ok(Self {
            path,
            stop,
            conns,
            workers,
            accept: Some(accept),
        })
    }

    /// The socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stop accepting, close every connection, wait for every thread, and
    /// remove the socket.  A verdict being handled finishes first; its
    /// reply may be lost (the same request sent again answers it).
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        let Some(accept) = self.accept.take() else {
            return;
        };
        self.stop.store(true, Ordering::SeqCst);
        let _ = accept.join();
        for (_, c) in lock(&self.conns).drain() {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
        let ws: Vec<_> = lock(&self.workers).drain(..).collect();
        for w in ws {
            let _ = w.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for DeciderServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn send(s: &mut UnixStream, r: &Reply) -> Result<(), FrameError> {
    frame::write_frame(s, &r.encode())
}

/// Serve one connection until it closes, breaks or errs.
fn serve_conn(d: &dyn Decide, mut s: UnixStream, peer: Peer, max_frame: u32) {
    let mut hello = false;
    loop {
        let body = match frame::read_frame_max(&mut s, max_frame) {
            Ok(Some(b)) => b,
            Ok(None) => return,
            Err(FrameError::TooLarge(n)) => {
                let _ = send(
                    &mut s,
                    &Reply::Error {
                        message: format!("a frame of {n} bytes is over {max_frame}"),
                    },
                );
                return;
            }
            Err(_) => return,
        };
        let (reply, close) = match Request::decode(&body) {
            Err(e) => (err(format!("malformed request: {e:?}")), true),
            Ok(Request::Hello { version }) if !hello && version == VERSION => {
                hello = true;
                (Reply::Hello { version: VERSION }, false)
            }
            Ok(Request::Hello { version }) if !hello => (
                err(format!(
                    "version {version} is not spoken here: {VERSION} is"
                )),
                true,
            ),
            Ok(_) if !hello => (err("Hello comes first"), true),
            Ok(Request::Hello { .. }) => (err("Hello comes once"), true),
            Ok(Request::Pending) => match d.pending() {
                Ok(items) => (Reply::Pending { items }, false),
                Err(e) => (err(e), false),
            },
            Ok(Request::Verdict { request }) if !request.id_matches(peer) => (
                err(format!(
                    "request_id {} is not this request's from uid {}",
                    request.request_id, peer.uid
                )),
                true,
            ),
            Ok(Request::Verdict { request }) => match d.verdict(&request, peer) {
                Ok(answer) => (Reply::Verdict { answer }, false),
                Err(e) => (err(e), false),
            },
        };
        if send(&mut s, &reply).is_err() || close {
            return;
        }
    }
}

fn err(message: impl Into<String>) -> Reply {
    Reply::Error {
        message: message.into(),
    }
}

/// A client of the decider socket (the `taso-decide` command, tests).
pub struct DeciderClient {
    s: UnixStream,
}

impl DeciderClient {
    /// Connect to `path` and say Hello.
    pub fn connect(path: &Path) -> io::Result<Self> {
        let mut c = Self {
            s: UnixStream::connect(path)?,
        };
        match c.call(&Request::Hello { version: VERSION })? {
            Reply::Hello { version } if version == VERSION => Ok(c),
            other => Err(io::Error::other(format!("Hello answered {other:?}"))),
        }
    }

    /// Send `req`, read the reply.
    pub fn call(&mut self, req: &Request) -> io::Result<Reply> {
        frame::write_frame(&mut self.s, &req.encode()).map_err(frame_io)?;
        let body = frame::read_frame(&mut self.s)
            .map_err(frame_io)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        Reply::decode(&body).map_err(|e| io::Error::other(format!("malformed reply: {e:?}")))
    }
}

fn frame_io(e: FrameError) -> io::Error {
    match e {
        FrameError::Io(e) => e,
        e => io::Error::other(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use taso_core::contract::{request_id, Decision, OpKind, Refusal};
    use taso_core::envelope::HashVal;

    #[derive(Default)]
    struct Fake {
        seen: Mutex<Vec<(VerdictRequest, Peer)>>,
    }

    impl Decide for Fake {
        fn pending(&self) -> Result<Vec<PendingItem>, String> {
            Err("no Vessels here".into())
        }
        fn verdict(&self, r: &VerdictRequest, peer: Peer) -> Result<VerdictAnswer, String> {
            lock(&self.seen).push((r.clone(), peer));
            Ok(VerdictAnswer::Retry(taso_core::decider::RetryReason::Rule(
                Refusal::OpenAttempt,
            )))
        }
    }

    fn request(uid: u32) -> VerdictRequest {
        let mut r = VerdictRequest {
            request_id: HashVal::from_bytes([0; 32]),
            candidate_id: HashVal::from_bytes([1; 32]),
            facts_hash: HashVal::from_bytes([2; 32]),
            artifact_key: HashVal::from_bytes([3; 32]),
            requirement: taso_core::contract::VerifierRequirement {
                template: taso_core::envelope::ChronicleId::from_bytes([4; 16]),
                vconf_key: HashVal::from_bytes([5; 32]),
                version: 1,
            },
            exclude: Default::default(),
            attempt_id: HashVal::from_bytes([6; 32]),
            result_digest: HashVal::from_bytes([7; 32]),
            decision: Decision::Hold,
            authority: taso_core::record::Authority {
                actor: "jarmo".into(),
                reason: "test".into(),
            },
            policy_digest: None,
        };
        r.request_id = request_id(uid, OpKind::Verdict, &r.body());
        r
    }

    fn me() -> u32 {
        rustix::process::getuid().as_raw()
    }

    fn server(dir: &Path, max_conns: usize) -> (DeciderServer, Arc<Fake>, DeciderConf) {
        let conf = DeciderConf {
            socket: dir.join("d").join("decide.sock"),
            max_frame_bytes: 4096,
            max_connections: max_conns,
        };
        let fake = Arc::new(Fake::default());
        (
            DeciderServer::spawn(&conf, fake.clone()).unwrap(),
            fake,
            conf,
        )
    }

    #[test]
    fn the_socket_is_private_and_the_peer_is_the_connections() {
        let dir = tempfile::tempdir().unwrap();
        let (srv, fake, conf) = server(dir.path(), 8);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(conf.socket.parent().unwrap()), 0o700);
        assert_eq!(mode(&conf.socket), 0o600);
        let mut c = DeciderClient::connect(&conf.socket).unwrap();
        assert!(matches!(
            c.call(&Request::Pending).unwrap(),
            Reply::Error { message } if message == "no Vessels here"
        ));
        let r = request(me());
        assert_eq!(
            c.call(&Request::Verdict {
                request: Box::new(r.clone())
            })
            .unwrap(),
            Reply::Verdict {
                answer: VerdictAnswer::Retry(taso_core::decider::RetryReason::Rule(
                    Refusal::OpenAttempt
                ))
            }
        );
        let seen = lock(&fake.seen).clone();
        assert_eq!(
            seen,
            vec![(
                r,
                Peer {
                    uid: me(),
                    pid: std::process::id()
                }
            )]
        );
        // A second server on a live socket is refused.
        assert!(DeciderServer::spawn(&conf, fake.clone()).is_err());
        srv.stop();
        assert!(!conf.socket.exists());
    }

    #[test]
    fn what_is_out_of_order_or_not_the_peers_is_an_error_and_closes() {
        let dir = tempfile::tempdir().unwrap();
        let (_srv, fake, conf) = server(dir.path(), 8);
        let raw = |req: &Request| -> (Reply, bool) {
            let mut s = UnixStream::connect(&conf.socket).unwrap();
            frame::write_frame(&mut s, &req.encode()).unwrap();
            let r = Reply::decode(&frame::read_frame(&mut s).unwrap().unwrap()).unwrap();
            // Closed after: the next read ends.
            let closed = frame::read_frame(&mut s).unwrap().is_none();
            (r, closed)
        };
        // Not Hello first; a version not spoken.
        assert!(matches!(
            raw(&Request::Pending),
            (Reply::Error { .. }, true)
        ));
        assert!(matches!(
            raw(&Request::Hello { version: 2 }),
            (Reply::Error { .. }, true)
        ));
        // Hello twice.
        let mut c = DeciderClient::connect(&conf.socket).unwrap();
        assert!(matches!(
            c.call(&Request::Hello { version: VERSION }).unwrap(),
            Reply::Error { .. }
        ));
        // A request id of another uid's.
        let mut c = DeciderClient::connect(&conf.socket).unwrap();
        let other = request(me() + 1);
        assert!(matches!(
            c.call(&Request::Verdict { request: Box::new(other) }).unwrap(),
            Reply::Error { message } if message.contains("is not this request's")
        ));
        assert!(lock(&fake.seen).is_empty(), "nothing reached the Warden");
        // Garbage, and a frame over the limit.
        let mut s = UnixStream::connect(&conf.socket).unwrap();
        frame::write_frame(&mut s, &[9, 9]).unwrap();
        let r = Reply::decode(&frame::read_frame(&mut s).unwrap().unwrap()).unwrap();
        assert!(matches!(r, Reply::Error { message } if message.starts_with("malformed")));
        let mut s = UnixStream::connect(&conf.socket).unwrap();
        s.write_all(&5000u32.to_be_bytes()).unwrap();
        let r = Reply::decode(&frame::read_frame(&mut s).unwrap().unwrap()).unwrap();
        assert!(matches!(r, Reply::Error { message } if message.contains("over 4096")));
    }

    #[test]
    fn one_connection_over_the_limit_is_answered_and_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (_srv, _fake, conf) = server(dir.path(), 1);
        let _a = DeciderClient::connect(&conf.socket).unwrap();
        let mut b = UnixStream::connect(&conf.socket).unwrap();
        let r = Reply::decode(&frame::read_frame(&mut b).unwrap().unwrap()).unwrap();
        assert!(matches!(r, Reply::Error { message } if message.contains("connections are open")));
        drop(_a);
        // Freed once the first one closes.
        let t = std::time::Instant::now();
        loop {
            if DeciderClient::connect(&conf.socket).is_ok() {
                break;
            }
            assert!(t.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
