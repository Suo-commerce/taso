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
//!   not otherwise.  Turns start at 1 and must increase: turn 0 is the
//!   Warden's birth Seal ([`crate::vessel::Vessel::seal_birth`]), which
//!   `Hello` reports as no turn sealed.  In Phase 1 file changes live in
//!   the dataset, not in records, so the Warden cannot tell an unchanged
//!   turn from a changed one cheaply; it seals every quiescent turn (a
//!   snapshot is metadata-only).  The Seal's cut records the highest
//!   `Transcript` lsn and its `ledger_pos` the highest `Effect` lsn.
//!   Trusting the harness's quiescence flag is Phase 1's contract; the
//!   `-wal` check that verifies it is a separate step.
//! - **Effect** requests go through the effect engine
//!   ([`Session::with_effects`]): intent before dispatch, outcomes
//!   recorded, authority withheld while anything is unresolved.  Without
//!   an engine they are refused before dispatch — an effect with no
//!   adapter is refused, never guessed at (v0.4 §7.1).
//! - **Quiescence is verified** when a [`Watch`] is given
//!   ([`Session::with_watch`]): sampled at `TurnEnd`, sampled again once
//!   the layer is frozen; if a database moved in between, the layer is
//!   destroyed, no Seal exists, and the reply is `sealed: None`.
//! - **After each Seal** an [`AfterSeal`] hook runs, if one is given
//!   ([`Session::with_after_seal`]): the daemon publishes the Seal there
//!   (ships it and advances the shipped anchor).  It runs **after the
//!   TurnEnd reply is sent** and before the next request is handled
//!   ([`Session::after_reply`]), so the agent's turn pause is the Seal
//!   alone (decision 3, 2026-10-16).  Until it lands the Seal is not
//!   anchored: a crash in that window rebirths from the Seal before it,
//!   one turn more lost, never a wrong state; effects are unaffected (they
//!   publish before sending, always).  Its failure does not undo the Seal,
//!   which is accepted and stays; it is counted
//!   ([`Session::after_seal_failures`]) and the next Seal's publish ships
//!   from the last one that was named, so nothing is skipped for good.
//! - A malformed body is answered with `Malformed` and the connection
//!   continues (the frame boundary is intact); a broken frame or a socket
//!   error ends the connection.
//!
//! Isolation of the socket itself (its own namespace per Vessel, mode
//! 0600) belongs to the runtime; [`FieldSocket::bind`] sets the mode.

use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;
use std::path::{Path, PathBuf};

use taso_core::envelope::{Lsn, Stream};
use taso_core::record::{Payload, StreamCut, TurnId, Verdict};
use taso_field::protocol::{
    recv_request, send_reply, EffectResult, ErrorCode, ProtocolError, Reply, Request, VERSION,
};

use crate::chronicle::{ChronicleError, Layers};
use crate::effects::Effects;
use crate::quiesce::{verify, Watch};
use crate::segment::Position;
use crate::vessel::{Vessel, VesselError, BIRTH_TURN};
use taso_field::adapter::Call;

// ── Session ─────────────────────────────────────────────────────────

/// What runs after each Seal a session takes (the daemon: publish it).
pub trait AfterSeal<L: Layers> {
    /// `seal` was just accepted on `vessel`.  An error is reported, not
    /// fatal: the Seal stands.
    fn after_seal(&mut self, vessel: &mut Vessel<L>, seal: Position) -> Result<(), String>;
}

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
    /// The effect engine, if effects may be dispatched.
    effects: Option<&'v mut Effects>,
    /// The databases whose quiescence is verified at each Seal.
    watch: Option<Watch>,
    /// Runs after each Seal.
    after_seal: Option<&'v mut dyn AfterSeal<L>>,
    /// How many times it failed, and the last reason.
    after_seal_failures: u64,
    last_after_seal_error: Option<String>,
    /// A Seal taken whose hook has not run yet (it runs after the reply).
    pending_seal: Option<Position>,
}

impl<'v, L: Layers> Session<'v, L> {
    /// Start a session on `vessel`.  `first_verdict` is the verdict of the
    /// first Seal this session takes: `Clean` normally, `Unverified` with
    /// a reason after a recovery dropped records (v0.4 §8.5).
    pub fn new(vessel: &'v mut Vessel<L>, first_verdict: Verdict) -> Result<Self, VesselError> {
        let frames = vessel
            .chronicle()
            .frames()
            .map_err(|e| VesselError::Chronicle(ChronicleError::Segment(e)))?;
        // From the newest Checkpoint on: older segments may be gone.
        let summary = crate::summary::Summary::of(&frames).map_err(|(lsn, error)| VesselError::Decode { lsn, error })?;
        let (transcript, ledger) = (summary.transcript, summary.effect);
        let last_sealed_turn = summary.seal.map(|s| s.turn.get());
        Ok(Self {
            vessel,
            greeted: false,
            last_sealed_turn,
            transcript,
            ledger,
            next_verdict: first_verdict,
            effects: None,
            watch: None,
            after_seal: None,
            after_seal_failures: 0,
            last_after_seal_error: None,
            pending_seal: None,
        })
    }

    /// Dispatch effects through `effects` (reconciled when it was opened).
    pub fn with_effects(mut self, effects: &'v mut Effects) -> Self {
        self.effects = Some(effects);
        self
    }

    /// Verify quiescence of `watch`'s databases at every Seal.
    pub fn with_watch(mut self, watch: Watch) -> Self {
        self.watch = Some(watch);
        self
    }

    /// Run `hook` after each Seal.
    pub fn with_after_seal(mut self, hook: &'v mut dyn AfterSeal<L>) -> Self {
        self.after_seal = Some(hook);
        self
    }

    /// How many times the after-Seal hook failed, and the last reason.
    pub fn after_seal_failures(&self) -> (u64, Option<&str>) {
        (self.after_seal_failures, self.last_after_seal_error.as_deref())
    }

    /// The last turn sealed, if any, counting the birth Seal (turn 0,
    /// [`BIRTH_TURN`]).  `Hello` reports the birth Seal as no turn.
    pub fn last_sealed_turn(&self) -> Option<u64> {
        self.last_sealed_turn
    }

    /// Run the after-Seal hook for a Seal taken by the last request, if
    /// any.  [`serve`] calls it right after sending each reply; [`Session::handle`]
    /// calls it first, so a pending publish always runs before the next
    /// request is handled.
    pub fn after_reply(&mut self) {
        let Some(seal) = self.pending_seal.take() else { return };
        if let Some(hook) = self.after_seal.as_deref_mut() {
            if let Err(e) = hook.after_seal(self.vessel, seal) {
                self.after_seal_failures += 1;
                self.last_after_seal_error = Some(e);
            }
        }
    }

    /// Answer one request.
    pub fn handle(&mut self, req: Request) -> Reply {
        self.after_reply();
        match (self.greeted, req) {
            (false, Request::Hello { version }) if version == VERSION => {
                self.greeted = true;
                // The birth Seal is the Warden's, not a harness turn.
                let last = self.last_sealed_turn.filter(|&t| t != BIRTH_TURN.get());
                Reply::Hello { version: VERSION, last_sealed_turn: last }
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
            (true, Request::Effect { call, provider, operation, args }) => {
                let Some(fx) = self.effects.as_deref_mut() else {
                    return Reply::Effect {
                        call,
                        result: EffectResult::Refused {
                            reason: format!("no adapter for provider {provider:?}"),
                        },
                    };
                };
                let before = self.vessel.tail();
                match fx.dispatch(self.vessel, &provider, Call { operation, args }) {
                    Ok(result) => {
                        if self.vessel.tail() != before {
                            self.ledger = self.vessel.tail().lsn;
                        }
                        Reply::Effect { call, result }
                    }
                    Err(e) => vessel_error(e),
                }
            }
            (true, Request::TurnEnd { turn, quiescent }) => self.turn_end(turn, quiescent),
        }
    }

    fn turn_end(&mut self, turn: u64, quiescent: bool) -> Reply {
        if turn == BIRTH_TURN.get() {
            return error(ErrorCode::Malformed, format!("turn {turn} is the Warden's birth Seal; turns start at 1"));
        }
        if self.last_sealed_turn.is_some_and(|last| turn <= last) {
            return error(
                ErrorCode::Malformed,
                format!("turn {turn} is not after the last sealed turn"),
            );
        }
        if !quiescent {
            return Reply::TurnEnd { turn, sealed: None };
        }
        let before = match self.watch.as_ref().map(Watch::sample).transpose() {
            Ok(b) => b,
            Err(e) => return error(ErrorCode::Internal, format!("quiescence sample: {e}")),
        };
        let watch = &self.watch;
        let check = move || -> Result<(), String> {
            match (watch, before) {
                (Some(w), Some(b)) => {
                    let after = w.sample().map_err(|e| format!("quiescence sample: {e}"))?;
                    verify(&b, &after).map_err(|e| e.to_string())
                }
                _ => Ok(()),
            }
        };
        let cut = StreamCut { fs: Lsn::new(0), db: Lsn::new(0), transcript: self.transcript };
        let verdict = std::mem::replace(&mut self.next_verdict, Verdict::Clean);
        match self.vessel.seal_checked(cut, verdict.clone(), self.ledger, TurnId::new(turn), check) {
            Ok(sealed) => {
                self.last_sealed_turn = Some(turn);
                // Published after the reply: Session::after_reply.
                self.pending_seal = Some(sealed.seal);
                Reply::TurnEnd { turn, sealed: Some(sealed.seal.lsn.get()) }
            }
            Err(VesselError::Chronicle(ChronicleError::CheckFailed(_))) => {
                // Not actually quiescent: no Seal, try again next turn.
                self.next_verdict = verdict;
                Reply::TurnEnd { turn, sealed: None }
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
    let ended = loop {
        let reply = match recv_request(stream) {
            Ok(None) => break Ended::Closed,
            Ok(Some(req)) => session.handle(req),
            Err(ProtocolError::Malformed { at, why }) => {
                error(ErrorCode::Malformed, format!("byte {at}: {why}"))
            }
            Err(e) => break Ended::Broken(e),
        };
        if let Err(e) = send_reply(stream, &reply) {
            break Ended::Broken(e);
        }
        // The reply is on its way: now publish the Seal it announced.
        session.after_reply();
    };
    session.after_reply();
    ended
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
        let mut session = Session::new(vessel, first_verdict)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let ended = self.serve_session(&mut session)?;
        Ok((ended, session.last_sealed_turn()))
    }

    /// Accept one connection and serve it with a prepared session (with
    /// its effect engine and quiescence watch).
    pub fn serve_session<L: Layers>(&self, session: &mut Session<'_, L>) -> io::Result<Ended> {
        let (mut stream, _) = self.listener.accept()?;
        Ok(serve(&mut stream, session))
    }

    /// Wait for a connection, checking `stop` every `poll`.  `None` once
    /// `stop` says so with nobody connecting.  The connection is blocking.
    pub fn accept_until(&self, stop: &dyn Fn() -> bool, poll: Duration) -> io::Result<Option<UnixStream>> {
        self.listener.set_nonblocking(true)?;
        let got = loop {
            match self.listener.accept() {
                Ok((stream, _)) => break Ok(Some(stream)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if stop() {
                        break Ok(None);
                    }
                    std::thread::sleep(poll);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => break Err(e),
            }
        };
        self.listener.set_nonblocking(false)?;
        let stream = got?;
        if let Some(s) = &stream {
            s.set_nonblocking(false)?;
        }
        Ok(stream)
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
    use taso_field::adapter::{FakeProvider, Registry};
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
        let frames = v.chronicle().frames().unwrap();
        let f = frames.iter().find(|f| f.envelope.lsn == seal.lsn).unwrap();
        let Payload::Seal(rec) = Payload::decode(&f.payload).unwrap() else { panic!() };
        assert_eq!(rec.cut.transcript, Lsn::new(2));
        assert_eq!(rec.turn, TurnId::new(1));
        assert_eq!(rec.verdict, Verdict::Clean);
    }

    /// After the birth Seal (turn 0) the harness still hears "nothing
    /// sealed yet" and starts at turn 1; turn 0 is never the harness's.
    #[test]
    fn the_birth_seal_is_not_a_harness_turn() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let birth = v.seal_birth().unwrap().seal;
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        assert_eq!(s.last_sealed_turn(), Some(0), "the session knows the birth Seal");
        assert_eq!(s.handle(hello()), Reply::Hello { version: VERSION, last_sealed_turn: None });
        assert!(is_error(&s.handle(Request::TurnEnd { turn: 0, quiescent: true }), ErrorCode::Malformed));
        assert_eq!(
            s.handle(Request::TurnEnd { turn: 1, quiescent: true }),
            Reply::TurnEnd { turn: 1, sealed: Some(birth.lsn.get() + 1) }
        );
        drop(s);
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        assert_eq!(s.handle(hello()), Reply::Hello { version: VERSION, last_sealed_turn: Some(1) });
    }

    /// Turn 0 is refused even before any Seal: a harness Seal at turn 0
    /// would look like a birth Seal.
    #[test]
    fn turn_zero_is_refused_without_a_birth_seal_too() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        s.handle(hello());
        let r = s.handle(Request::TurnEnd { turn: 0, quiescent: true });
        assert!(is_error(&r, ErrorCode::Malformed), "{r:?}");
        assert_eq!(s.last_sealed_turn(), None);
        drop(s);
        assert_eq!(v.last_seal(), None, "nothing sealed");
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

    /// Records the Seals it was called for; fails when told to.
    struct Hook {
        seen: Vec<Position>,
        fail: bool,
    }

    impl<L: Layers> AfterSeal<L> for Hook {
        fn after_seal(&mut self, vessel: &mut Vessel<L>, seal: Position) -> Result<(), String> {
            assert_eq!(vessel.last_seal(), Some(seal), "called with the Seal just taken");
            self.seen.push(seal);
            if self.fail {
                Err("store down".into())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn the_hook_runs_after_each_seal_and_its_failure_does_not_undo_it() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut hook = Hook { seen: Vec::new(), fail: false };
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap().with_after_seal(&mut hook);
        s.handle(hello());
        assert_eq!(s.handle(Request::TurnEnd { turn: 1, quiescent: false }), Reply::TurnEnd { turn: 1, sealed: None });
        assert_eq!(s.handle(Request::TurnEnd { turn: 1, quiescent: true }), Reply::TurnEnd { turn: 1, sealed: Some(2) });
        assert_eq!(s.pending_seal.map(|p| p.lsn.get()), Some(2), "not yet: after the reply");
        s.after_reply();
        s.after_reply();
        assert_eq!(s.after_seal_failures(), (0, None));
        drop(s);
        assert_eq!(hook.seen.iter().map(|p| p.lsn.get()).collect::<Vec<_>>(), vec![2], "not for the unsealed turn");

        hook.fail = true;
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap().with_after_seal(&mut hook);
        s.handle(hello());
        assert_eq!(s.handle(Request::TurnEnd { turn: 2, quiescent: true }), Reply::TurnEnd { turn: 2, sealed: Some(3) });
        // The next request runs the pending hook first.
        s.handle(Request::Transcript { entry: b"next".to_vec() });
        assert_eq!(s.after_seal_failures(), (1, Some("store down")));
        drop(s);
        assert_eq!(v.last_seal().unwrap().lsn, Lsn::new(3), "the Seal stands");
    }

    /// Over a connection: the TurnEnd reply is written before the hook
    /// runs, and a hook still pending when the agent hangs up runs anyway.
    #[test]
    fn the_reply_goes_out_before_the_publish() {
        use std::cell::RefCell;
        use std::rc::Rc;
        /// Sealed TurnEnd replies already written.
        fn sealed_replies(out: &[u8]) -> usize {
            let mut r = out;
            let mut n = 0;
            while let Some(reply) = recv_reply(&mut r).unwrap() {
                n += usize::from(matches!(reply, Reply::TurnEnd { sealed: Some(_), .. }));
            }
            n
        }
        struct Duplex {
            input: std::io::Cursor<Vec<u8>>,
            output: Rc<RefCell<Vec<u8>>>,
            published: Rc<RefCell<usize>>,
        }
        impl Read for Duplex {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                // The Warden must not wait for the agent's next request
                // to publish a Seal it already announced.
                assert_eq!(
                    *self.published.borrow(),
                    sealed_replies(&self.output.borrow()),
                    "reading the next request with a Seal still unpublished"
                );
                self.input.read(b)
            }
        }
        impl Write for Duplex {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.output.borrow_mut().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        struct Watching(Rc<RefCell<Vec<u8>>>, Vec<usize>, Rc<RefCell<usize>>);
        impl<L: Layers> AfterSeal<L> for Watching {
            fn after_seal(&mut self, _: &mut Vessel<L>, _: Position) -> Result<(), String> {
                // How many replies the agent already has.
                let out = self.0.borrow().clone();
                let mut r = &out[..];
                let mut n = 0;
                while recv_reply(&mut r).unwrap().is_some() {
                    n += 1;
                }
                self.1.push(n);
                *self.2.borrow_mut() += 1;
                Ok(())
            }
        }
        let mut input = Vec::new();
        for req in [hello(), Request::TurnEnd { turn: 1, quiescent: true }, Request::TurnEnd { turn: 2, quiescent: true }] {
            taso_field::protocol::send_request(&mut input, &req).unwrap();
        }
        let output = Rc::new(RefCell::new(Vec::new()));
        let published = Rc::new(RefCell::new(0));
        let mut stream = Duplex { input: std::io::Cursor::new(input), output: output.clone(), published: published.clone() };
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut hook = Watching(output.clone(), Vec::new(), published.clone());
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap().with_after_seal(&mut hook);
        assert!(matches!(serve(&mut stream, &mut s), Ended::Closed));
        drop(s);
        assert_eq!(hook.1, vec![2, 3], "each publish ran after its TurnEnd reply was written");
    }

    #[test]
    fn accept_until_stops_and_accepts() {
        let dir = tempfile::tempdir().unwrap();
        let sock = FieldSocket::bind(dir.path().join("f.sock")).unwrap();
        let polls = std::cell::Cell::new(0);
        let none = sock
            .accept_until(&|| { polls.set(polls.get() + 1); polls.get() > 2 }, Duration::from_millis(1))
            .unwrap();
        assert!(none.is_none());
        assert_eq!(polls.get(), 3);
        let _client = UnixStream::connect(sock.path()).unwrap();
        let mut got = sock.accept_until(&|| false, Duration::from_millis(1)).unwrap().unwrap();
        // The connection serves a session as from serve_session.
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        let mut client = _client;
        taso_field::protocol::send_request(&mut client, &hello()).unwrap();
        drop(client.shutdown(std::net::Shutdown::Write));
        assert!(matches!(serve(&mut got, &mut s), Ended::Closed));
        assert_eq!(
            recv_reply(&mut client).unwrap(),
            Some(Reply::Hello { version: VERSION, last_sealed_turn: None })
        );
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
    fn effects_dispatch_through_the_engine() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut reg = Registry::new();
        reg.register(Box::new(FakeProvider::new("mail")));
        let (mut fx, _) = Effects::open(reg, Box::new(crate::effects::AlwaysPublish), &mut v).unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap().with_effects(&mut fx);
        s.handle(hello());
        let r = s.handle(Request::Effect {
            call: 1,
            provider: "mail".into(),
            operation: "send".into(),
            args: b"bob".to_vec(),
        });
        assert!(matches!(r, Reply::Effect { call: 1, result: EffectResult::Applied { .. } }));
        let r = s.handle(Request::Effect {
            call: 2,
            provider: "http".into(),
            operation: "get".into(),
            args: b"x".to_vec(),
        });
        assert!(matches!(r, Reply::Effect { call: 2, result: EffectResult::Refused { .. } }));
        // The Seal's ledger_pos covers the effect records.
        s.handle(Request::TurnEnd { turn: 1, quiescent: true });
        drop(s);
        let frames = v.chronicle().frames().unwrap();
        let last_effect = frames.iter().rfind(|f| f.envelope.stream == Stream::Effect).unwrap();
        let seal = frames.last().unwrap();
        let Payload::Seal(rec) = Payload::decode(&seal.payload).unwrap() else { panic!() };
        assert_eq!(rec.ledger_pos, last_effect.envelope.lsn);
    }

    #[test]
    fn a_turn_that_is_not_really_quiescent_is_not_sealed() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mount = tempfile::tempdir().unwrap();
        std::fs::write(mount.path().join("state.db-journal"), [0u8; 512]).unwrap();
        let watch = Watch::new(mount.path(), &["state.db"]).unwrap();
        let tail = v.tail();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap().with_watch(watch);
        s.handle(hello());
        // The harness says quiescent; the journal says otherwise.
        assert_eq!(
            s.handle(Request::TurnEnd { turn: 1, quiescent: true }),
            Reply::TurnEnd { turn: 1, sealed: None }
        );
        assert_eq!(s.last_sealed_turn(), None);
        // Once the transaction is done, the same turn seals.
        std::fs::remove_file(mount.path().join("state.db-journal")).unwrap();
        assert!(matches!(
            s.handle(Request::TurnEnd { turn: 1, quiescent: true }),
            Reply::TurnEnd { turn: 1, sealed: Some(_) }
        ));
        drop(s);
        assert_eq!(v.tail().lsn, tail.lsn.next(), "exactly one Seal record");
        assert_eq!(v.chronicle().layers().list().unwrap().len(), 1, "one layer");
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
