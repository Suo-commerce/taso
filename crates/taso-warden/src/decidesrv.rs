//! The decider socket (P4 spec rev. 22 §5.1, D72, D78; file 8b).
//!
//! A Unix socket, mode 0600 in a 0700 directory; the socket is the
//! authentication in P4 (D1a): each connection's uid and pid are read
//! with `SO_PEERCRED` and are the `peer` of what it asks. Frames are the
//! Field's, each body at most `max_frame_bytes`; at most
//! `max_connections` connections at once (one more is answered `Error`
//! and closed). Messages: [`taso_core::decider`].
//!
//! A connection says `Hello { version }` first, once (version 2:
//! `Pending` in pages; a peer speaking another version is answered
//! `Error` and closed). A malformed or
//! out-of-order request, an unknown version, or a `Verdict` whose
//! `request_id` is not the one its peer's uid, `op_kind = Verdict` and its
//! body derive, is answered `Error` and the connection is closed: nothing
//! is recorded. What a [`Decide`] cannot do (it failed) is answered
//! `Error` and the connection stays open.
//!
//! `Pending { after }` is answered with one page (review fix N3b-a): the
//! node's pending Candidates, cut by [`taso_core::decider::page`].  Each
//! page asks the node again, so a Candidate decided between two pages is
//! simply not on the next one.
//!
//! `Proposals { vessel, after }` (version 3, 4a) is a read, answered with
//! one page of that Vessel's held proposals: nothing is recorded, nothing
//! is released.  A Vessel the node cannot answer for is an `Error` that
//! says so, never an empty page.  One proposal whose reply would pass the
//! frame limit cannot be sent: the connection closes, which is an
//! unavailable answer, not a wrong one.
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
use taso_core::decider::{PendingItem, ProposalItem, Reply, Request, VerdictAnswer, VERSION};
use taso_core::envelope::{ChronicleId, Lsn};
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
    /// Every held proposal of `vessel`, in any order, and its last Seal
    /// (4a).  A read: it records nothing.  A Vessel this node cannot
    /// answer for is an error, never an empty list.  A node that keeps no
    /// Vessels' logs answers as here.
    fn proposals(&self, vessel: ChronicleId) -> Result<(Vec<ProposalItem>, Option<Lsn>), String> {
        let _ = vessel;
        Err("this Warden lists no proposals".into())
    }
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
            Ok(Request::Pending { after }) => match d.pending() {
                Ok(all) => {
                    let (items, more) = taso_core::decider::page(all, after);
                    (Reply::Pending { items, more }, false)
                }
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
            Ok(Request::Proposals { vessel, after }) => match d.proposals(vessel) {
                Ok((all, last_seal)) => {
                    let (items, more) = taso_core::decider::proposal_page(all, after);
                    (
                        Reply::Proposals {
                            items,
                            more,
                            last_seal,
                        },
                        false,
                    )
                }
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

    /// Every pending Candidate, read page by page (review fix N3b-a):
    /// `Pending { after }` with the last id of each page until a page says
    /// no more.  A Warden whose pages do not move forward (an empty page,
    /// or one that does not start after `after`, while it says more) is an
    /// error, never a loop.
    pub fn pending_all(&mut self) -> Result<Vec<PendingItem>, String> {
        let mut all: Vec<PendingItem> = Vec::new();
        let mut after = None;
        loop {
            let (items, more) = match self
                .call(&Request::Pending { after })
                .map_err(|e| e.to_string())?
            {
                Reply::Pending { items, more } => (items, more),
                Reply::Error { message } => return Err(message),
                other => return Err(format!("unexpected reply {other:?}")),
            };
            let first = items.first().map(|i| *i.candidate.candidate_id.as_bytes());
            let forward = match (first, after) {
                (Some(f), Some(a)) => f > *a.as_bytes(),
                (Some(_), None) => true,
                (None, _) => !more,
            };
            if !forward {
                return Err("the Warden's Pending pages do not move forward".into());
            }
            after = items.last().map(|i| i.candidate.candidate_id).or(after);
            all.extend(items);
            if !more {
                return Ok(all);
            }
        }
    }

    /// Every held proposal of `vessel`, read page by page, and the last
    /// Seal the final page named.  Pages that do not move forward are an
    /// error, never a loop.  The Vessel may seal between two pages, so a
    /// caller that needs one consistent view reads again until two reads
    /// name the same Seal.
    pub fn proposals_all(
        &mut self,
        vessel: ChronicleId,
    ) -> Result<(Vec<ProposalItem>, Option<Lsn>), String> {
        let mut all: Vec<ProposalItem> = Vec::new();
        let mut after = None;
        loop {
            let (items, more, last_seal) = match self
                .call(&Request::Proposals { vessel, after })
                .map_err(|e| e.to_string())?
            {
                Reply::Proposals {
                    items,
                    more,
                    last_seal,
                } => (items, more, last_seal),
                Reply::Error { message } => return Err(message),
                other => return Err(format!("unexpected reply {other:?}")),
            };
            let forward = match (items.first().map(|i| i.intent.op.get()), after) {
                (Some(f), Some(a)) => f > a,
                (Some(_), None) => true,
                (None, _) => !more,
            };
            if !forward {
                return Err("the Warden's Proposals pages do not move forward".into());
            }
            after = items.last().map(|i| i.intent.op.get()).or(after);
            all.extend(items);
            if !more {
                return Ok((all, last_seal));
            }
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

    mod support {
        include!("../tests/support/pending.rs");
    }

    #[derive(Default)]
    struct Fake {
        seen: Mutex<Vec<(VerdictRequest, Peer)>>,
        /// What `pending` gives; `None`: it fails.
        items: Option<Vec<PendingItem>>,
        /// The one Vessel `proposals` knows, its held proposals and its
        /// last Seal; any other Vessel is unknown.
        held: Option<(ChronicleId, Vec<ProposalItem>, Option<Lsn>)>,
    }

    impl Decide for Fake {
        fn pending(&self) -> Result<Vec<PendingItem>, String> {
            self.items.clone().ok_or_else(|| "no Vessels here".into())
        }
        fn verdict(&self, r: &VerdictRequest, peer: Peer) -> Result<VerdictAnswer, String> {
            lock(&self.seen).push((r.clone(), peer));
            Ok(VerdictAnswer::Retry(taso_core::decider::RetryReason::Rule(
                Refusal::OpenAttempt,
            )))
        }
        fn proposals(
            &self,
            vessel: ChronicleId,
        ) -> Result<(Vec<ProposalItem>, Option<Lsn>), String> {
            match &self.held {
                Some((v, items, seal)) if *v == vessel => Ok((items.clone(), *seal)),
                _ => Err(format!("no Vessel {vessel:?} here")),
            }
        }
    }

    /// A Decide that says nothing of proposals: the trait's own answer.
    struct NoProposals;

    impl Decide for NoProposals {
        fn pending(&self) -> Result<Vec<PendingItem>, String> {
            Ok(Vec::new())
        }
        fn verdict(&self, _: &VerdictRequest, _: Peer) -> Result<VerdictAnswer, String> {
            Err("no verdicts here".into())
        }
    }

    fn proposal(op: u64) -> ProposalItem {
        use taso_core::record::{Consequence, Dispatch, IntentRecord, OpId, RetryPolicy};
        ProposalItem {
            lsn: Lsn::new(10 + op),
            intent: IntentRecord {
                op: OpId::new(op),
                provider: "mail".into(),
                request: format!("to: a{op}").into_bytes(),
                footprint: b"inbox:a".to_vec(),
                dispatch: Dispatch::Immediate,
                retry: RetryPolicy::UnsafeToRetry,
                consequence: Consequence::Irreversible,
                authority: Vec::new(),
                barrier: None,
            },
            sealed: op <= 100,
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
        server_with(dir, max_conns, Fake::default())
    }

    fn server_with(
        dir: &Path,
        max_conns: usize,
        fake: Fake,
    ) -> (DeciderServer, Arc<Fake>, DeciderConf) {
        let conf = DeciderConf {
            socket: dir.join("d").join("decide.sock"),
            max_frame_bytes: 4096,
            max_connections: max_conns,
        };
        let fake = Arc::new(fake);
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
            c.call(&Request::Pending { after: None }).unwrap(),
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
        // Not Hello first; a version not spoken (1, before pages).
        assert!(matches!(
            raw(&Request::Pending { after: None }),
            (Reply::Error { .. }, true)
        ));
        assert!(matches!(
            raw(&Request::Hello { version: 1 }),
            (Reply::Error { message }, true) if message.contains("version 1 is not spoken")
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

    /// Review fix N3b-a: 100 pending Candidates come in two pages, 64
    /// then 36, each once and in id order; the last says no more.
    #[test]
    fn pending_is_answered_page_by_page() {
        let dir = tempfile::tempdir().unwrap();
        let items: Vec<PendingItem> = (1..=100u8)
            .rev()
            .map(|n| support::item(n, support::clean(1), &[]))
            .collect();
        let (_srv, _fake, conf) = server_with(
            dir.path(),
            8,
            Fake {
                items: Some(items),
                ..Fake::default()
            },
        );
        let mut c = DeciderClient::connect(&conf.socket).unwrap();
        let (mut seen, mut after, mut pages) = (Vec::new(), None, Vec::new());
        loop {
            let Reply::Pending { items, more } = c.call(&Request::Pending { after }).unwrap()
            else {
                panic!()
            };
            pages.push(items.len());
            after = items.last().map(|i| i.candidate.candidate_id);
            seen.extend(items.iter().map(|i| i.candidate.candidate_id.as_bytes()[0]));
            if !more {
                break;
            }
        }
        assert_eq!(pages, [64, 36]);
        assert_eq!(seen, (1..=100u8).collect::<Vec<_>>());
        // The client's own reader gives the same, all of it.
        let all = c.pending_all().unwrap();
        assert_eq!(
            all.iter()
                .map(|i| i.candidate.candidate_id.as_bytes()[0])
                .collect::<Vec<_>>(),
            (1..=100u8).collect::<Vec<_>>()
        );
        // A node that fails: its error, as before.
        let dir2 = tempfile::tempdir().unwrap();
        let (_srv2, _f2, conf2) = server(dir2.path(), 8);
        let mut c2 = DeciderClient::connect(&conf2.socket).unwrap();
        assert_eq!(c2.pending_all().unwrap_err(), "no Vessels here");
    }

    /// 4a: a Vessel's held proposals are answered page by page, in op
    /// order, with the Seal that decided `sealed`; asking records nothing.
    #[test]
    fn proposals_are_answered_page_by_page_and_record_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let vessel = ChronicleId::from_bytes([5; 16]);
        let items: Vec<ProposalItem> = (1..=150u64).rev().map(proposal).collect();
        let (_srv, fake, conf) = server_with(
            dir.path(),
            8,
            Fake {
                held: Some((vessel, items, Some(Lsn::new(110)))),
                ..Fake::default()
            },
        );
        let mut c = DeciderClient::connect(&conf.socket).unwrap();
        let (mut seen, mut after, mut pages) = (Vec::new(), None, Vec::new());
        loop {
            let Reply::Proposals {
                items,
                more,
                last_seal,
            } = c.call(&Request::Proposals { vessel, after }).unwrap()
            else {
                panic!()
            };
            assert_eq!(last_seal, Some(Lsn::new(110)));
            pages.push(items.len());
            after = items.last().map(|i| i.intent.op.get());
            seen.extend(items.iter().map(|i| (i.intent.op.get(), i.sealed)));
            if !more {
                break;
            }
        }
        assert_eq!(pages, [64, 64, 22]);
        let want: Vec<(u64, bool)> = (1..=150).map(|op| (op, op <= 100)).collect();
        assert_eq!(seen, want, "each once, in op order, its flag kept");
        // The client's own reader gives the same, all of it.
        let (all, last_seal) = c.proposals_all(vessel).unwrap();
        assert_eq!(all.len(), 150);
        assert_eq!(all[0].intent.request, b"to: a1");
        assert_eq!(last_seal, Some(Lsn::new(110)));
        assert!(lock(&fake.seen).is_empty(), "a read: no verdict was made");
    }

    /// 4a, rule R: a Vessel the Warden cannot answer for is an error that
    /// says so, never an empty list, and the connection stays open; a
    /// Warden that lists no proposals at all says that.
    #[test]
    fn an_unknown_vessel_is_an_error_never_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let vessel = ChronicleId::from_bytes([5; 16]);
        let other = ChronicleId::from_bytes([6; 16]);
        let (_srv, _fake, conf) = server_with(
            dir.path(),
            8,
            Fake {
                held: Some((vessel, Vec::new(), None)),
                ..Fake::default()
            },
        );
        let mut c = DeciderClient::connect(&conf.socket).unwrap();
        let e = c.proposals_all(other).unwrap_err();
        assert!(e.contains("no Vessel"), "{e}");
        // The same connection still answers: a Vessel holding nothing is
        // an empty list, a different answer from the error above.
        assert_eq!(c.proposals_all(vessel).unwrap(), (Vec::new(), None));

        let dir2 = tempfile::tempdir().unwrap();
        let conf2 = DeciderConf {
            socket: dir2.path().join("d").join("decide.sock"),
            max_frame_bytes: 4096,
            max_connections: 8,
        };
        let _srv2 = DeciderServer::spawn(&conf2, Arc::new(NoProposals)).unwrap();
        let mut c2 = DeciderClient::connect(&conf2.socket).unwrap();
        let e = c2.proposals_all(vessel).unwrap_err();
        assert!(e.contains("lists no proposals"), "{e}");
    }

    /// 4a: Proposals before Hello is out of order, as any request is.
    #[test]
    fn proposals_before_hello_is_refused_and_closes() {
        let dir = tempfile::tempdir().unwrap();
        let (_srv, _fake, conf) = server(dir.path(), 8);
        let mut s = UnixStream::connect(&conf.socket).unwrap();
        let q = Request::Proposals {
            vessel: ChronicleId::from_bytes([5; 16]),
            after: None,
        };
        frame::write_frame(&mut s, &q.encode()).unwrap();
        let body = frame::read_frame(&mut s).unwrap().unwrap();
        assert!(matches!(Reply::decode(&body).unwrap(), Reply::Error { .. }));
        assert!(frame::read_frame(&mut s).unwrap().is_none(), "closed");
    }
}
