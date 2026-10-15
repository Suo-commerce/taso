//! The Warden side of the Field: one Vessel's socket (v1.0 §3, v0.4 §7.1).
//!
//! [`Session`] is the request handler, free of I/O so it can be tested on
//! its own; [`serve`] runs it over any byte stream; [`FieldSocket`] binds
//! the per-Vessel Unix socket and serves one connection at a time (the
//! Vessel's Chronicle has one writer).
//!
//! # Rules
//!
//! - **Hello first.**  Anything before a `Hello` with this crate's
//!   [`VERSION`], or a second `Hello`, is refused with `BadHello`.
//! - **Transcript** entries become `Transcript` records, durable (segment
//!   fsync + CAS) before `Recorded` is sent.
//! - **TurnEnd** seals when the harness reports the turn quiescent, and
//!   not otherwise.  Turns must increase.  In Phase 1 file changes live in
//!   the dataset, not in records, so the Warden cannot tell an unchanged
//!   turn from a changed one cheaply; it seals every quiescent turn (a
//!   snapshot is metadata-only).  The Seal's cut records the highest
//!   `Transcript` lsn and its `ledger_pos` the highest `Effect` lsn.
//!   Trusting the harness's quiescence flag is Phase 1's contract; the
//!   `-wal` check that verifies it is a separate step.
//! - **Effect** requests are refused before dispatch with "no adapter":
//!   adapters come next, and an effect with no adapter is refused, never
//!   guessed at (v0.4 §7.1).
//! - A malformed body is answered with `Malformed` and the connection
//!   continues (the frame boundary is intact); a broken frame or a socket
//!   error ends the connection.
//!
//! Isolation of the socket itself (its own namespace per Vessel, mode
//! 0600) belongs to the runtime; [`FieldSocket::bind`] sets the mode.

use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use taso_core::envelope::{Lsn, Stream};
use taso_core::record::{Payload, StreamCut, TurnId, Verdict};
use taso_field::protocol::{
    recv_request, send_reply, EffectResult, ErrorCode, ProtocolError, Reply, Request, VERSION,
};

use crate::chronicle::{ChronicleError, Layers};
use crate::vessel::{Vessel, VesselError};

// ── Session ─────────────────────────────────────────────────────────

/// One conversation with a Vessel's harness.
pub struct Session<'v, L: Layers> {
    vessel: &'v mut Vessel<L>,
    greeted: bool,
    last_sealed_turn: Option<u64>,
    /// Highest `Transcript` lsn so far (the Seal cut).
    transcript: Lsn,
    /// Highest `Effect` lsn so far (the Seal's `ledger_pos`).
    ledger: Lsn,
    /// Verdict for the next Seal; `Clean` after the first.
    next_verdict: Verdict,
}

impl<'v, L: Layers> Session<'v, L> {
    /// Start a session on `vessel`.  `first_verdict` is the verdict of the
    /// first Seal this session takes: `Clean` normally, `Unverified` with
    /// a reason after a recovery dropped records (v0.4 §8.5).
    pub fn new(vessel: &'v mut Vessel<L>, first_verdict: Verdict) -> Result<Self, VesselError> {
        let frames = vessel
            .chronicle()
            .segment()
            .frames()
            .map_err(|e| VesselError::Chronicle(ChronicleError::Segment(e)))?;
        let mut transcript = Lsn::new(0);
        let mut ledger = Lsn::new(0);
        let mut last_sealed_turn = None;
        for f in &frames {
            match f.envelope.stream {
                Stream::Transcript => transcript = f.envelope.lsn,
                Stream::Effect => ledger = f.envelope.lsn,
                Stream::Ctl if Some(f.envelope.lsn) == vessel.last_seal().map(|s| s.lsn) => {
                    let p = Payload::decode(&f.payload)
                        .map_err(|error| VesselError::Decode { lsn: f.envelope.lsn, error })?;
                    if let Payload::Seal(s) = p {
                        last_sealed_turn = Some(s.turn.get());
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            vessel,
            greeted: false,
            last_sealed_turn,
            transcript,
            ledger,
            next_verdict: first_verdict,
        })
    }

    /// The last turn sealed, if any.
    pub fn last_sealed_turn(&self) -> Option<u64> {
        self.last_sealed_turn
    }

    /// Answer one request.
    pub fn handle(&mut self, req: Request) -> Reply {
        match (self.greeted, req) {
            (false, Request::Hello { version }) if version == VERSION => {
                self.greeted = true;
                Reply::Hello { version: VERSION, last_sealed_turn: self.last_sealed_turn }
            }
            (false, Request::Hello { version }) => error(
                ErrorCode::BadHello,
                format!("protocol version {version} is not supported; this Warden speaks {VERSION}"),
            ),
            (false, _) => error(ErrorCode::BadHello, "the first request must be Hello".into()),
            (true, Request::Hello { .. }) => error(ErrorCode::BadHello, "already greeted".into()),
            (true, Request::Transcript { entry }) => {
                match self.vessel.append(Stream::Transcript, Payload::Raw(entry)) {
                    Ok(head) => {
                        self.transcript = head.lsn;
                        Reply::Recorded { lsn: head.lsn.get() }
                    }
                    Err(e) => vessel_error(e),
                }
            }
            (true, Request::Effect { call, provider, .. }) => Reply::Effect {
                call,
                result: EffectResult::Refused { reason: format!("no adapter for provider {provider:?}") },
            },
            (true, Request::TurnEnd { turn, quiescent }) => self.turn_end(turn, quiescent),
        }
    }

    fn turn_end(&mut self, turn: u64, quiescent: bool) -> Reply {
        if self.last_sealed_turn.is_some_and(|last| turn <= last) {
            return error(
                ErrorCode::Malformed,
                format!("turn {turn} is not after the last sealed turn"),
            );
        }
        if !quiescent {
            return Reply::TurnEnd { turn, sealed: None };
        }
        let cut = StreamCut { fs: Lsn::new(0), db: Lsn::new(0), transcript: self.transcript };
        let verdict = std::mem::replace(&mut self.next_verdict, Verdict::Clean);
        match self.vessel.seal(cut, verdict.clone(), self.ledger, TurnId::new(turn)) {
            Ok(sealed) => {
                self.last_sealed_turn = Some(turn);
                Reply::TurnEnd { turn, sealed: Some(sealed.seal.lsn.get()) }
            }
            Err(e) => {
                self.next_verdict = verdict;
                vessel_error(e)
            }
        }
    }
}

fn error(code: ErrorCode, message: String) -> Reply {
    Reply::Error { code, message }
}

fn vessel_error(e: VesselError) -> Reply {
    let code = match &e {
        VesselError::Closed { .. } => ErrorCode::Closed,
        VesselError::Chronicle(ChronicleError::Fenced | ChronicleError::Refused(_)) => ErrorCode::Fenced,
        _ => ErrorCode::Internal,
    };
    error(code, e.to_string())
}

// ── Serving ─────────────────────────────────────────────────────────

/// Why a connection ended.
#[derive(Debug)]
pub enum Ended {
    /// The harness closed the socket between frames.
    Closed,
    /// A broken frame or a socket error.
    Broken(ProtocolError),
}

/// Serve one connection until it ends.  Every request gets exactly one
/// reply; a malformed body gets `Malformed` and the connection continues.
pub fn serve<S: Read + Write, L: Layers>(stream: &mut S, session: &mut Session<'_, L>) -> Ended {
    loop {
        let reply = match recv_request(stream) {
            Ok(None) => return Ended::Closed,
            Ok(Some(req)) => session.handle(req),
            Err(ProtocolError::Malformed { at, why }) => {
                error(ErrorCode::Malformed, format!("byte {at}: {why}"))
            }
            Err(e) => return Ended::Broken(e),
        };
        if let Err(e) = send_reply(stream, &reply) {
            return Ended::Broken(e);
        }
    }
}

/// A Vessel's Field socket.
pub struct FieldSocket {
    path: PathBuf,
    listener: UnixListener,
}

impl FieldSocket {
    /// Bind the socket at `path`, mode 0600.  A stale socket left by a
    /// crashed Warden is replaced; any other file at `path` is an error.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_socket() => std::fs::remove_file(&path)?,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { path, listener })
    }

    /// The socket's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept one connection and serve it to the end with a fresh session.
    pub fn serve_one<L: Layers>(
        &self,
        vessel: &mut Vessel<L>,
        first_verdict: Verdict,
    ) -> io::Result<(Ended, Option<u64>)> {
        let (mut stream, _) = self.listener.accept()?;
        let mut session = Session::new(vessel, first_verdict)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let ended = serve(&mut stream, &mut session);
        Ok((ended, session.last_sealed_turn()))
    }
}

impl Drop for FieldSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vessel::tests::{env, ns};
    use std::os::unix::net::UnixStream;
    use taso_field::protocol::{recv_reply, send_request, write_frame};

    fn hello() -> Request {
        Request::Hello { version: VERSION }
    }

    fn is_error(r: &Reply, code: ErrorCode) -> bool {
        matches!(r, Reply::Error { code: c, .. } if *c == code)
    }

    #[test]
    fn hello_first_and_only_once() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        assert!(is_error(&s.handle(Request::Transcript { entry: vec![1] }), ErrorCode::BadHello));
        assert!(is_error(&s.handle(Request::Hello { version: VERSION + 1 }), ErrorCode::BadHello));
        assert_eq!(s.handle(hello()), Reply::Hello { version: VERSION, last_sealed_turn: None });
        assert!(is_error(&s.handle(hello()), ErrorCode::BadHello));
    }

    #[test]
    fn transcript_is_recorded_durably_and_turns_seal_when_quiescent() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        s.handle(hello());
        let Reply::Recorded { lsn } = s.handle(Request::Transcript { entry: b"user: hi".to_vec() }) else {
            panic!("not recorded")
        };
        assert_eq!(lsn, 2, "lsn 1 is the Lineage record");

        // Not quiescent: no Seal.
        assert_eq!(
            s.handle(Request::TurnEnd { turn: 1, quiescent: false }),
            Reply::TurnEnd { turn: 1, sealed: None }
        );
        // Quiescent: sealed right after the transcript entry.
        assert_eq!(
            s.handle(Request::TurnEnd { turn: 1, quiescent: true }),
            Reply::TurnEnd { turn: 1, sealed: Some(3) }
        );
        // Turns must increase.
        assert!(is_error(&s.handle(Request::TurnEnd { turn: 1, quiescent: true }), ErrorCode::Malformed));
        assert_eq!(s.last_sealed_turn(), Some(1));
        drop(s);

        // The Seal's cut and turn are in the record.
        let seal = v.last_seal().unwrap();
        let frames = v.chronicle().segment().frames().unwrap();
        let f = frames.iter().find(|f| f.envelope.lsn == seal.lsn).unwrap();
        let Payload::Seal(rec) = Payload::decode(&f.payload).unwrap() else { panic!() };
        assert_eq!(rec.cut.transcript, Lsn::new(2));
        assert_eq!(rec.turn, TurnId::new(1));
        assert_eq!(rec.verdict, Verdict::Clean);
    }

    #[test]
    fn a_resumed_session_reports_the_last_sealed_turn() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        s.handle(hello());
        s.handle(Request::TurnEnd { turn: 7, quiescent: true });
        drop(s);
        drop(v);
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        assert_eq!(s.handle(hello()), Reply::Hello { version: VERSION, last_sealed_turn: Some(7) });
        assert!(is_error(&s.handle(Request::TurnEnd { turn: 7, quiescent: true }), ErrorCode::Malformed));
    }

    #[test]
    fn first_seal_takes_the_given_verdict_then_clean() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut s = Session::new(&mut v, Verdict::Unverified("recovered: 1 group dropped".into())).unwrap();
        s.handle(hello());
        s.handle(Request::TurnEnd { turn: 1, quiescent: true });
        s.handle(Request::TurnEnd { turn: 2, quiescent: true });
        drop(s);
        let verdicts: Vec<Verdict> = v
            .chronicle()
            .segment()
            .frames()
            .unwrap()
            .iter()
            .filter_map(|f| match Payload::decode(&f.payload).unwrap() {
                Payload::Seal(s) => Some(s.verdict),
                _ => None,
            })
            .collect();
        assert_eq!(verdicts, vec![Verdict::Unverified("recovered: 1 group dropped".into()), Verdict::Clean]);
    }

    #[test]
    fn effects_are_refused_without_an_adapter_and_record_nothing() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let tail = v.tail();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        s.handle(hello());
        let r = s.handle(Request::Effect {
            call: 3,
            provider: "mail".into(),
            operation: "send".into(),
            args: b"{\"consequence\":\"none\"}".to_vec(),
        });
        assert!(matches!(r, Reply::Effect { call: 3, result: EffectResult::Refused { .. } }));
        drop(s);
        assert_eq!(v.tail(), tail);
    }

    #[test]
    fn a_closed_vessel_answers_closed() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        v.seal(StreamCut::EMPTY, Verdict::Clean, Lsn::new(0), TurnId::new(1)).unwrap();
        let auth = taso_core::record::Authority { actor: "op".into(), reason: "merge".into() };
        let mut old = e.host.succeed(v, ns(1), b"n", auth, false).unwrap().predecessor;
        let mut s = Session::new(&mut old, Verdict::Clean).unwrap();
        s.handle(hello());
        assert!(is_error(&s.handle(Request::Transcript { entry: vec![1] }), ErrorCode::Closed));
        assert!(is_error(&s.handle(Request::TurnEnd { turn: 2, quiescent: true }), ErrorCode::Closed));
    }

    // ── over a real socket ──────────────────────────────────────────

    #[test]
    fn serve_over_a_socket_pair_survives_malformed_bodies() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let (mut server, mut client) = UnixStream::pair().unwrap();
        let t = std::thread::spawn(move || {
            send_request(&mut client, &hello()).unwrap();
            let r1 = recv_reply(&mut client).unwrap().unwrap();
            write_frame(&mut client, &[42]).unwrap(); // not a request
            let r2 = recv_reply(&mut client).unwrap().unwrap();
            send_request(&mut client, &Request::Transcript { entry: b"x".to_vec() }).unwrap();
            let r3 = recv_reply(&mut client).unwrap().unwrap();
            (r1, r2, r3)
        });
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        let ended = serve(&mut server, &mut s);
        let (r1, r2, r3) = t.join().unwrap();
        assert!(matches!(ended, Ended::Closed));
        assert!(matches!(r1, Reply::Hello { .. }));
        assert!(is_error(&r2, ErrorCode::Malformed));
        assert!(matches!(r3, Reply::Recorded { .. }));
    }

    #[test]
    fn bind_sets_mode_replaces_stale_socket_and_refuses_other_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("field.sock");
        let sock = FieldSocket::bind(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Simulate a crash: leak the listener so the socket file stays.
        std::mem::forget(sock);
        let sock = FieldSocket::bind(&path).unwrap();
        drop(sock);
        assert!(!path.exists(), "removed on drop");

        std::fs::write(&path, b"not a socket").unwrap();
        assert!(FieldSocket::bind(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
    }

    #[test]
    fn serve_one_over_the_bound_socket() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sock = FieldSocket::bind(dir.path().join("field.sock")).unwrap();
        let path = sock.path().to_path_buf();
        let t = std::thread::spawn(move || {
            let mut c = UnixStream::connect(&path).unwrap();
            send_request(&mut c, &hello()).unwrap();
            recv_reply(&mut c).unwrap();
            send_request(&mut c, &Request::TurnEnd { turn: 1, quiescent: true }).unwrap();
            recv_reply(&mut c).unwrap().unwrap()
        });
        let (ended, last) = sock.serve_one(&mut v, Verdict::Clean).unwrap();
        let reply = t.join().unwrap();
        assert!(matches!(ended, Ended::Closed));
        assert_eq!(last, Some(1));
        assert!(matches!(reply, Reply::TurnEnd { turn: 1, sealed: Some(_) }));
        assert!(v.last_seal().is_some());
    }
}
