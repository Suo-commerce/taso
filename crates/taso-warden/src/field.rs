//! The Warden side of the Field: one Vessel's socket (v1.0 §3, v0.4 §7.1).
//!
//! [`Session`] is the request handler, free of I/O so it can be tested on
//! its own; [`serve`] runs it over any byte stream; [`FieldSocket`] binds
//! the per-Vessel Unix socket and serves one connection at a time (the
//! Vessel's Chronicle has one writer).
//!
//! # Rules
//!
//! - **Two sockets** (C5, review findings 2 and 4): the agent's, mounted
//!   into the Vessel, and the sender's, the Warden's own
//!   ([`Socket`]).  Only the sender lists (`Open`) and reports
//!   (`Outcome`); the agent declares and reads its effect's `Result`.  A
//!   request on the other socket is refused (`NotOnThisSocket`) and
//!   records nothing.  [`serve_vessel`] serves both at once, every
//!   connection on its own thread, every request handled by the one
//!   thread that owns the session.
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
//!   an engine they are refused before dispatch (v0.4 §7.1).  Taso
//!   never sends; the sender's contract is in `docs/relay.md`.
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
//! - **A failed publish is retried before an effect** (fencing review
//!   F4b).  The log is never shipped past a Seal whose `fs` section is not
//!   shipped (F4), so until that Seal is published every effect would be
//!   refused (`SealNotShipped`) — for the rest of the turn.  So an
//!   `Effect` request first runs the hook once more for that Seal; if it
//!   lands, the effect proceeds, and if not, the failure is counted and
//!   the effect is refused as before.  Once per request: no loop, no wait.
//!   A later Seal published replaces the retry (a named Seal covers every
//!   Seal before it).
//! - **Fork and Promote are requests, never authorities** (decision D1).
//!   The session hands them to the Warden's [`Branches`]
//!   ([`Session::with_branches`]), which keeps the mechanical limits:
//!   which slots a child may take (its quota), that a child always holds
//!   its effects, which Seal is proven.  A promotion goes through the
//!   effect engine ([`Effects::promote`]): refused if this Vessel sealed
//!   again since the fork (M7) or already promoted a child there.  Without
//!   `Branches` (or, for Promote, an engine) both are refused and nothing
//!   is recorded.
//! - A malformed body is answered with `Malformed` and the connection
//!   continues (the frame boundary is intact); a broken frame or a socket
//!   error ends the connection.
//!
//! Isolation of the socket itself (its own namespace per Vessel, mode
//! 0600) belongs to the runtime; [`FieldSocket::bind`] sets the mode.

use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use taso_core::envelope::{Lsn, Stream};
use taso_core::record::{OpId, Payload, StreamCut, TurnId, Verdict};
use taso_field::protocol::{
    recv_request, send_reply, EffectResult, ErrorCode, ForkResult, OpState, OpenEffect, Outcome,
    PromoteResult, ProtocolError, Reply, Request, VERSION,
};

use crate::chronicle::{ChronicleError, Layers};
use crate::effects::{Asked, Effects};
use crate::ledger::{Answer, Declared};
use crate::quiesce::{verify, Watch};
use crate::segment::Position;
use crate::vessel::{ReadLog, SealAt, Vessel, VesselError, BIRTH_TURN};

// ── Session ─────────────────────────────────────────────────────────

/// What runs after each Seal a session takes (the daemon: publish it).
pub trait AfterSeal<L: Layers> {
    /// `seal` was just accepted on `vessel`.  An error is reported, not
    /// fatal: the Seal stands.
    fn after_seal(&mut self, vessel: &mut Vessel<L>, seal: Position) -> Result<(), String>;
}

/// Which of a Vessel's two sockets a connection came in on (C5): the agent
/// socket, mounted into the Vessel, or the sender socket, the Warden's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socket {
    /// Hello, Effect, Transcript, TurnEnd, Fork, Promote, Result.
    Agent,
    /// Hello, Open, Outcome.
    Sender,
}

impl Socket {
    /// True if `req` may come in on this socket.
    pub fn allows(self, req: &Request) -> bool {
        match req {
            Request::Hello { .. } => true,
            Request::Open | Request::Outcome { .. } => self == Socket::Sender,
            Request::Effect { .. }
            | Request::Transcript { .. }
            | Request::TurnEnd { .. }
            | Request::Fork { .. }
            | Request::Promote { .. }
            | Request::Result { .. } => self == Socket::Agent,
        }
    }
}

/// One connection's own state; everything else is the Vessel's
/// ([`Session`]).
#[derive(Debug)]
pub struct Conn {
    socket: Socket,
    greeted: bool,
}

impl Conn {
    /// A new connection on `socket`.
    pub fn new(socket: Socket) -> Self {
        Self {
            socket,
            greeted: false,
        }
    }

    /// The socket it came in on.
    pub fn socket(&self) -> Socket {
        self.socket
    }
}

/// How a session's Fork and Promote requests reach the Warden (the
/// daemon: [`crate::daemon`]).  A refusal is a reason for the agent;
/// nothing is made.
pub trait Branches<L: Layers> {
    /// Fork a child of `vessel` from its accepted Seal `at`.  Returns the
    /// child's name and the Seal lsn it was forked from.
    fn fork(&mut self, vessel: &Vessel<L>, at: SealAt) -> Result<(String, u64), String>;

    /// The local log of `vessel`'s child `child` (by the name `fork`
    /// gave), read without claiming it.
    fn child_log(&mut self, vessel: &Vessel<L>, child: &str) -> Result<ReadLog, String>;

    /// A promotion of `child` was answered `result` (for the Warden's log).
    fn promoted(&mut self, _child: &str, _result: &PromoteResult) {}
}

/// One conversation with a Vessel's harness.
pub struct Session<'v, L: Layers> {
    vessel: &'v mut Vessel<L>,
    /// The connection [`Session::handle`] answers for (an agent's).
    agent: Conn,
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
    /// Forks and promotions, if this Vessel may ask for them.
    branches: Option<&'v mut dyn Branches<L>>,
    /// A promotion is done and its files are adopted at the next start
    /// (C7): until then this Vessel takes no Seal (it would move), and the
    /// agent may only record transcript and read results.
    adopting: bool,
    /// How many times it failed, and the last reason.
    after_seal_failures: u64,
    last_after_seal_error: Option<String>,
    /// A Seal taken whose hook has not run yet (it runs after the reply).
    pending_seal: Option<Position>,
    /// The newest Seal whose hook ran and failed: retried before the next
    /// effect (F4b).  Cleared when a hook succeeds.
    unpublished: Option<Position>,
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
        let summary = crate::summary::Summary::of(&frames)
            .map_err(|(lsn, error)| VesselError::Decode { lsn, error })?;
        let (transcript, ledger) = (summary.transcript, summary.effect);
        let last_sealed_turn = summary.seal.map(|s| s.turn.get());
        Ok(Self {
            vessel,
            agent: Conn::new(Socket::Agent),
            last_sealed_turn,
            transcript,
            ledger,
            next_verdict: first_verdict,
            effects: None,
            watch: None,
            after_seal: None,
            branches: None,
            adopting: false,
            after_seal_failures: 0,
            last_after_seal_error: None,
            pending_seal: None,
            unpublished: None,
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

    /// Hand Fork and Promote requests to `branches`.
    pub fn with_branches(mut self, branches: &'v mut dyn Branches<L>) -> Self {
        self.branches = Some(branches);
        self
    }

    /// How many times the after-Seal hook failed, and the last reason.
    pub fn after_seal_failures(&self) -> (u64, Option<&str>) {
        (
            self.after_seal_failures,
            self.last_after_seal_error.as_deref(),
        )
    }

    /// The last turn sealed, if any, counting the birth Seal (turn 0,
    /// [`BIRTH_TURN`], for a Vessel born from the void; a fork's or
    /// succession's birth Seal carries its parent's turn).  `Hello`
    /// reports a turn-0 birth Seal as no turn, and a fork's as its parent's
    /// last turn, so the agent continues the count.
    pub fn last_sealed_turn(&self) -> Option<u64> {
        self.last_sealed_turn
    }

    /// Run the after-Seal hook for a Seal taken by the last request, if
    /// any.  [`serve`] calls it right after sending each reply; [`Session::handle`]
    /// calls it first, so a pending publish always runs before the next
    /// request is handled.
    pub fn after_reply(&mut self) {
        let Some(seal) = self.pending_seal.take() else {
            return;
        };
        self.run_hook(seal);
    }

    /// Run the after-Seal hook for `seal`.  A success clears the retry
    /// (this Seal covers any earlier unpublished one); a failure is
    /// counted and leaves `seal` to be retried before the next effect.
    fn run_hook(&mut self, seal: Position) {
        let Some(hook) = self.after_seal.as_deref_mut() else {
            return;
        };
        match hook.after_seal(self.vessel, seal) {
            Ok(()) => self.unpublished = None,
            Err(e) => {
                self.after_seal_failures += 1;
                self.last_after_seal_error = Some(e);
                self.unpublished = Some(seal);
            }
        }
    }

    /// Answer one request from the agent's connection.
    pub fn handle(&mut self, req: Request) -> Reply {
        let mut conn = std::mem::replace(&mut self.agent, Conn::new(Socket::Agent));
        let reply = self.handle_as(&mut conn, req);
        self.agent = conn;
        reply
    }

    /// Answer one request from `conn`.  A request the connection's socket
    /// does not allow ([`Socket::allows`]) is refused (`NotOnThisSocket`)
    /// and records nothing.
    pub fn handle_as(&mut self, conn: &mut Conn, req: Request) -> Reply {
        self.after_reply();
        if conn.greeted && !conn.socket.allows(&req) {
            let other = match conn.socket {
                Socket::Agent => "the Warden's sender socket",
                Socket::Sender => "the agent's socket",
            };
            return error(
                ErrorCode::NotOnThisSocket,
                format!("{} belongs on {other}", request_name(&req)),
            );
        }
        if self.adopting
            && conn.greeted
            && matches!(
                req,
                Request::Effect { .. }
                    | Request::TurnEnd { .. }
                    | Request::Fork { .. }
                    | Request::Promote { .. }
            )
        {
            return error(
                ErrorCode::Closed,
                format!(
                    "{}: this vessel was promoted; it adopts its child's files at its next start, and the Warden starts its agent again on them",
                    request_name(&req)
                ),
            );
        }
        match (conn.greeted, req) {
            (false, Request::Hello { version }) if version == VERSION => {
                conn.greeted = true;
                // The birth Seal is the Warden's, not a harness turn.
                let last = self.last_sealed_turn.filter(|&t| t != BIRTH_TURN.get());
                Reply::Hello {
                    version: VERSION,
                    last_sealed_turn: last,
                }
            }
            (false, Request::Hello { version }) => error(
                ErrorCode::BadHello,
                format!(
                    "protocol version {version} is not supported; this Warden speaks {VERSION}"
                ),
            ),
            (false, _) => error(
                ErrorCode::BadHello,
                "the first request must be Hello".into(),
            ),
            (true, Request::Hello { .. }) => error(ErrorCode::BadHello, "already greeted".into()),
            (true, Request::Transcript { entry }) => {
                match self.vessel.append(Stream::Transcript, Payload::Raw(entry)) {
                    Ok(head) => {
                        self.transcript = head.lsn;
                        Reply::Recorded {
                            lsn: head.lsn.get(),
                        }
                    }
                    Err(e) => vessel_error(e),
                }
            }
            (
                true,
                Request::Effect {
                    call,
                    provider,
                    request,
                    footprint,
                    retry,
                    consequence,
                    authority,
                },
            ) => {
                if self.effects.is_none() {
                    return Reply::Effect {
                        call,
                        result: EffectResult::Refused {
                            reason: format!("no effect engine for provider {provider:?}"),
                        },
                    };
                }
                // F4b: the log cannot ship past an unpublished Seal, so
                // without this the effect would be refused until the next
                // Seal.  One more try; a failure is refused below as before.
                if let Some(seal) = self.unpublished {
                    self.run_hook(seal);
                }
                let Some(fx) = self.effects.as_deref_mut() else {
                    unreachable!("checked above")
                };
                let d = Declared {
                    provider,
                    request,
                    footprint,
                    dispatch: taso_core::record::Dispatch::Immediate,
                    retry,
                    consequence,
                    authority,
                };
                let before = self.vessel.tail();
                let asked = fx.ask(self.vessel, &d);
                if self.vessel.tail() != before {
                    self.ledger = self.vessel.tail().lsn;
                }
                match asked {
                    Ok(Asked::Released { op }) => Reply::Effect {
                        call,
                        result: EffectResult::Released { op: op.get() },
                    },
                    Ok(Asked::Held { op }) => Reply::Effect {
                        call,
                        result: EffectResult::Held { op: op.get() },
                    },
                    Ok(Asked::Refused { reason }) => Reply::Effect {
                        call,
                        result: EffectResult::Refused { reason },
                    },
                    Err(e) => vessel_error(e),
                }
            }
            (true, Request::Outcome { op, result }) => {
                let Some(fx) = self.effects.as_deref_mut() else {
                    return Reply::Outcome {
                        op,
                        refused: Some("no effect engine".into()),
                    };
                };
                let answer = match result {
                    Outcome::Applied { receipt } => Answer::Applied { receipt },
                    Outcome::NotApplied { reason } => Answer::NotApplied { reason },
                    Outcome::Unknown => Answer::Unknown,
                };
                let before = self.vessel.tail();
                let r = fx.report(self.vessel, OpId::new(op), &answer);
                if self.vessel.tail() != before {
                    self.ledger = self.vessel.tail().lsn;
                }
                match r {
                    Ok(()) => Reply::Outcome { op, refused: None },
                    Err(crate::effects::ReportError::NotReleased(_)) => Reply::Outcome {
                        op,
                        refused: Some(format!(
                            "op {op} is not a released, unsettled effect of this vessel"
                        )),
                    },
                    Err(crate::effects::ReportError::Vessel(e)) => vessel_error(e),
                }
            }
            (true, Request::Open) => {
                // Anything released but not yet shipped (an adoption whose
                // ship failed) gets one more try; until it lands it is not
                // listed.
                if let Some(fx) = self.effects.as_deref_mut() {
                    let _ = fx.ship_unlisted(self.vessel);
                }
                let Some(fx) = self.effects.as_deref_mut() else {
                    return Reply::Open {
                        effects: Vec::new(),
                    };
                };
                match fx.hand_out(self.vessel) {
                    Ok(released) => Reply::Open {
                        effects: released
                            .into_iter()
                            .map(|(r, before)| OpenEffect {
                                op: r.intent.op.get(),
                                provider: r.intent.provider,
                                request: r.intent.request,
                                retry: r.intent.retry,
                                consequence: r.intent.consequence,
                                authority: r.intent.authority,
                                // Reconciled unknown, or listed before
                                // (a sender that crashed, the Warden up).
                                unknown: before,
                            })
                            .collect(),
                    },
                    Err(e) => vessel_error(e),
                }
            }
            (true, Request::TurnEnd { turn, quiescent }) => self.turn_end(turn, quiescent),
            (true, Request::Fork { seal }) => Reply::Fork {
                result: self.fork(seal),
            },
            (true, Request::Result { op }) => self.result(op),
            (true, Request::Promote { child, seal }) => {
                let result = self.promote(&child, seal);
                if let Some(b) = self.branches.as_deref_mut() {
                    b.promoted(&child, &result);
                }
                Reply::Promote { child, result }
            }
        }
    }

    fn result(&mut self, op: u64) -> Reply {
        let Some(fx) = self.effects.as_deref() else {
            return Reply::Result {
                op,
                state: OpState::NotFound,
            };
        };
        let state = match fx.result(self.vessel, OpId::new(op)) {
            Ok(None) => OpState::NotFound,
            Ok(Some(crate::effects::OpRecord { state, evidence })) => {
                use taso_core::record::OutcomeState as S;
                let text = |e: Option<Vec<u8>>| {
                    e.map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_default()
                };
                match state {
                    Some(S::DispatchAuthorized) => OpState::Pending,
                    Some(S::Proposed) => OpState::Held,
                    Some(S::OutcomeUnknown) => OpState::Unknown,
                    Some(S::AcceptedUnknown) => OpState::AcceptedUnknown,
                    Some(S::ConfirmedApplied) => OpState::Applied {
                        receipt: evidence.unwrap_or_default(),
                    },
                    Some(S::ConfirmedNotApplied) => OpState::NotApplied {
                        reason: text(evidence),
                    },
                    // An intent never released: nothing could act on it.
                    Some(S::Prepared) | None => OpState::NotApplied {
                        reason: "never released".into(),
                    },
                }
            }
            Err(e) => return vessel_error(e),
        };
        Reply::Result { op, state }
    }

    fn fork(&mut self, seal: Option<u64>) -> ForkResult {
        let refused = |reason: String| ForkResult::Refused { reason };
        if self.branches.is_none() {
            return refused("this Warden makes no forks for this vessel".into());
        }
        // The Seal must be anchored to be proven; one whose publish failed
        // gets one more try first (as before an effect, F4b).
        if let Some(seal) = self.unpublished {
            self.run_hook(seal);
        }
        let Some(b) = self.branches.as_deref_mut() else {
            unreachable!("checked above")
        };
        match b.fork(self.vessel, at(seal)) {
            Ok((child, seal)) => ForkResult::Forked { child, seal },
            Err(reason) => refused(reason),
        }
    }

    fn promote(&mut self, child: &str, seal: Option<u64>) -> PromoteResult {
        let refused = |reason: String| PromoteResult::Refused { reason };
        if self.branches.is_none() || self.effects.is_none() {
            return refused("this Warden promotes no forks for this vessel".into());
        }
        // The Promotion is shipped before anything is adopted, and the log
        // cannot ship past an unpublished Seal: one more try first (F4b).
        if let Some(seal) = self.unpublished {
            self.run_hook(seal);
        }
        let (Some(b), Some(fx)) = (self.branches.as_deref_mut(), self.effects.as_deref_mut())
        else {
            return refused("this Warden promotes no forks for this vessel".into());
        };
        let log = match b.child_log(self.vessel, child) {
            Ok(l) => l,
            Err(reason) => return refused(reason),
        };
        let before = self.vessel.tail();
        let r = fx.promote(self.vessel, &log, at(seal));
        if self.vessel.tail() != before {
            self.ledger = self.vessel.tail().lsn;
        }
        match r {
            Ok((record, adopted)) => {
                self.adopting = true;
                PromoteResult::Promoted {
                    seal: record.seal.get(),
                    adopted: adopted.iter().map(|a| a.op.get()).collect(),
                }
            }
            // Done; Open lists the adopted ops once a ship succeeds (it
            // retries before each Open).
            Err(crate::effects::PromoteError::AdoptionNotShipped {
                promotion,
                adopted,
                ..
            }) => {
                self.adopting = true;
                PromoteResult::Promoted {
                    seal: promotion.seal.get(),
                    adopted: adopted.iter().map(|a| a.op.get()).collect(),
                }
            }
            Err(crate::effects::PromoteError::Vessel(e)) => refused(e.to_string()),
            Err(crate::effects::PromoteError::NotShipped(e)) => refused(format!(
                "the Promotion is recorded but the ledger could not be shipped ({e}); nothing is adopted until it is finished at this vessel's next start"
            )),
        }
    }

    fn turn_end(&mut self, turn: u64, quiescent: bool) -> Reply {
        if turn == BIRTH_TURN.get() {
            return error(
                ErrorCode::Malformed,
                format!("turn {turn} is the Warden's birth Seal; turns start at 1"),
            );
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
        let cut = StreamCut {
            fs: Lsn::new(0),
            db: Lsn::new(0),
            transcript: self.transcript,
        };
        let verdict = std::mem::replace(&mut self.next_verdict, Verdict::Clean);
        match self
            .vessel
            .seal_checked(cut, verdict.clone(), self.ledger, TurnId::new(turn), check)
        {
            Ok(sealed) => {
                self.last_sealed_turn = Some(turn);
                // Published after the reply: Session::after_reply.
                self.pending_seal = Some(sealed.seal);
                Reply::TurnEnd {
                    turn,
                    sealed: Some(sealed.seal.lsn.get()),
                }
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
        VesselError::Chronicle(ChronicleError::Fenced | ChronicleError::Refused(_)) => {
            ErrorCode::Fenced
        }
        _ => ErrorCode::Internal,
    };
    error(code, e.to_string())
}

/// A request's name, for refusals.
fn request_name(req: &Request) -> &'static str {
    match req {
        Request::Hello { .. } => "Hello",
        Request::Effect { .. } => "Effect",
        Request::Transcript { .. } => "Transcript",
        Request::TurnEnd { .. } => "TurnEnd",
        Request::Outcome { .. } => "Outcome",
        Request::Open => "Open",
        Request::Fork { .. } => "Fork",
        Request::Promote { .. } => "Promote",
        Request::Result { .. } => "Result",
    }
}

/// The wire's Seal choice: `None` is the newest.
fn at(seal: Option<u64>) -> SealAt {
    match seal {
        None => SealAt::Last,
        Some(l) => SealAt::At(Lsn::new(l)),
    }
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

/// What one connection of [`serve_vessel`] came to.
#[derive(Debug)]
pub struct ConnEnded {
    /// Which socket it came in on.
    pub socket: Socket,
    /// How it ended.
    pub ended: Ended,
}

enum Msg {
    Request {
        id: u64,
        req: Request,
        reply: std::sync::mpsc::Sender<Reply>,
    },
    End {
        id: u64,
        ended: Ended,
    },
}

/// Serve a Vessel's two sockets (C5) until `stop` says so and the agent's
/// connections have ended; then the sender's connections are closed.
///
/// Each connection has its own thread, which only reads and writes
/// frames; every request is handled here, by the one thread that owns
/// `session`, one at a time, so the Vessel's Chronicle keeps one writer.
/// Each reply is handed to its connection before the after-Seal hook
/// runs ([`Session::after_reply`]), as in [`serve`].  A malformed body is
/// answered by its connection's thread and the connection goes on.
/// `on_end` is told of every connection that ended.
pub fn serve_vessel<L: Layers>(
    session: &mut Session<'_, L>,
    agent: &FieldSocket,
    sender: &FieldSocket,
    stop: &dyn Fn() -> bool,
    tick: Duration,
    on_end: &mut dyn FnMut(ConnEnded),
) -> io::Result<()> {
    use std::collections::BTreeMap;
    use std::sync::mpsc;
    agent.listener.set_nonblocking(true)?;
    sender.listener.set_nonblocking(true)?;
    let (tx, rx) = mpsc::channel::<Msg>();
    std::thread::scope(|scope| -> io::Result<()> {
        let mut conns: BTreeMap<u64, (Conn, UnixStream)> = BTreeMap::new();
        let mut next_id = 0u64;
        let mut closing = false;
        let mut failed: Option<io::Error> = None;
        loop {
            // New connections, unless stopping (or accepting failed).
            if !stop() && failed.is_none() {
                for (listener, socket) in [(agent, Socket::Agent), (sender, Socket::Sender)] {
                    loop {
                        match listener.listener.accept() {
                            Ok((stream, _)) => {
                                stream.set_nonblocking(false)?;
                                let id = next_id;
                                next_id += 1;
                                conns.insert(id, (Conn::new(socket), stream.try_clone()?));
                                let tx = tx.clone();
                                scope.spawn(move || connection(id, stream, tx));
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(e) => {
                                // Every connection's thread must end before
                                // the scope can: close them all.
                                for (_, stream) in conns.values() {
                                    let _ = stream.shutdown(std::net::Shutdown::Both);
                                }
                                closing = true;
                                failed = Some(e);
                                break;
                            }
                        }
                    }
                }
            } else if !closing && !conns.values().any(|(c, _)| c.socket == Socket::Agent) {
                // The agent is done: close the senders' connections.
                closing = true;
                for (_, stream) in conns.values() {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
            }
            if closing && conns.is_empty() {
                return failed.map_or(Ok(()), Err);
            }
            match rx.recv_timeout(tick) {
                Ok(Msg::Request { id, req, reply }) => {
                    let Some((conn, _)) = conns.get_mut(&id) else {
                        continue;
                    };
                    let r = session.handle_as(conn, req);
                    let _ = reply.send(r);
                    // The reply is on its way: now publish the Seal it
                    // announced.
                    session.after_reply();
                }
                Ok(Msg::End { id, ended }) => {
                    if let Some((conn, _)) = conns.remove(&id) {
                        on_end(ConnEnded {
                            socket: conn.socket,
                            ended,
                        });
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => unreachable!("tx is held here"),
            }
        }
    })?;
    session.after_reply();
    Ok(())
}

/// One connection's thread: frames in, requests to the owner, replies out.
fn connection(id: u64, mut stream: UnixStream, tx: std::sync::mpsc::Sender<Msg>) {
    let ended = loop {
        let reply = match recv_request(&mut stream) {
            Ok(None) => break Ended::Closed,
            Ok(Some(req)) => {
                let (rtx, rrx) = std::sync::mpsc::channel();
                if tx
                    .send(Msg::Request {
                        id,
                        req,
                        reply: rtx,
                    })
                    .is_err()
                {
                    break Ended::Closed;
                }
                match rrx.recv() {
                    Ok(r) => r,
                    Err(_) => break Ended::Closed,
                }
            }
            Err(ProtocolError::Malformed { at, why }) => {
                error(ErrorCode::Malformed, format!("byte {at}: {why}"))
            }
            Err(e) => break Ended::Broken(e),
        };
        if let Err(e) = send_reply(&mut stream, &reply) {
            break Ended::Broken(e);
        }
    };
    let _ = tx.send(Msg::End { id, ended });
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
        let mut session =
            Session::new(vessel, first_verdict).map_err(|e| io::Error::other(e.to_string()))?;
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
    pub fn accept_until(
        &self,
        stop: &dyn Fn() -> bool,
        poll: Duration,
    ) -> io::Result<Option<UnixStream>> {
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
    use crate::effects::Mode;
    use crate::vessel::tests::{env, ns};
    use std::os::unix::net::UnixStream;
    use taso_field::protocol::{recv_reply, send_request, write_frame};

    fn hello() -> Request {
        Request::Hello { version: VERSION }
    }

    /// A greeted connection on the sender socket.
    fn sender() -> Conn {
        Conn {
            socket: Socket::Sender,
            greeted: true,
        }
    }

    fn is_error(r: &Reply, code: ErrorCode) -> bool {
        matches!(r, Reply::Error { code: c, .. } if *c == code)
    }

    #[test]
    fn hello_first_and_only_once() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        assert!(is_error(
            &s.handle(Request::Transcript { entry: vec![1] }),
            ErrorCode::BadHello
        ));
        assert!(is_error(
            &s.handle(Request::Hello {
                version: VERSION + 1
            }),
            ErrorCode::BadHello
        ));
        assert_eq!(
            s.handle(hello()),
            Reply::Hello {
                version: VERSION,
                last_sealed_turn: None
            }
        );
        assert!(is_error(&s.handle(hello()), ErrorCode::BadHello));
    }

    /// A fork whose birth Seal carries its parent's turn (5): Hello says
    /// the agent resumes after 5, and its next turn must be after it.
    #[test]
    fn a_fork_continues_its_parents_turns() {
        let e = env();
        let (mut p, _) = e.host.ensure(ns(1), b"parent").unwrap();
        let s = p
            .seal(
                taso_core::record::StreamCut::EMPTY,
                Verdict::Clean,
                taso_core::envelope::Lsn::new(0),
                taso_core::record::TurnId::new(5),
            )
            .unwrap()
            .seal;
        let mut c = e.host.fork(&p, s, b"child").unwrap();
        let t = e.host.birth_turn(&c).unwrap();
        c.seal_birth_at(t).unwrap();
        let mut session = Session::new(&mut c, Verdict::Clean).unwrap();
        assert_eq!(
            session.handle(hello()),
            Reply::Hello {
                version: VERSION,
                last_sealed_turn: Some(5)
            }
        );
        for turn in [1, 5] {
            assert!(
                is_error(
                    &session.handle(Request::TurnEnd {
                        turn,
                        quiescent: true
                    }),
                    ErrorCode::Malformed
                ),
                "turn {turn} is not after the parent's 5"
            );
        }
        assert!(matches!(
            session.handle(Request::TurnEnd {
                turn: 6,
                quiescent: true
            }),
            Reply::TurnEnd {
                turn: 6,
                sealed: Some(_)
            }
        ));
    }

    #[test]
    fn transcript_is_recorded_durably_and_turns_seal_when_quiescent() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        s.handle(hello());
        let Reply::Recorded { lsn } = s.handle(Request::Transcript {
            entry: b"user: hi".to_vec(),
        }) else {
            panic!("not recorded")
        };
        assert_eq!(lsn, 2, "lsn 1 is the Lineage record");

        // Not quiescent: no Seal.
        assert_eq!(
            s.handle(Request::TurnEnd {
                turn: 1,
                quiescent: false
            }),
            Reply::TurnEnd {
                turn: 1,
                sealed: None
            }
        );
        // Quiescent: sealed right after the transcript entry.
        assert_eq!(
            s.handle(Request::TurnEnd {
                turn: 1,
                quiescent: true
            }),
            Reply::TurnEnd {
                turn: 1,
                sealed: Some(3)
            }
        );
        // Turns must increase.
        assert!(is_error(
            &s.handle(Request::TurnEnd {
                turn: 1,
                quiescent: true
            }),
            ErrorCode::Malformed
        ));
        assert_eq!(s.last_sealed_turn(), Some(1));
        drop(s);

        // The Seal's cut and turn are in the record.
        let seal = v.last_seal().unwrap();
        let frames = v.chronicle().frames().unwrap();
        let f = frames.iter().find(|f| f.envelope.lsn == seal.lsn).unwrap();
        let Payload::Seal(rec) = Payload::decode(&f.payload).unwrap() else {
            panic!()
        };
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
        assert_eq!(
            s.last_sealed_turn(),
            Some(0),
            "the session knows the birth Seal"
        );
        assert_eq!(
            s.handle(hello()),
            Reply::Hello {
                version: VERSION,
                last_sealed_turn: None
            }
        );
        assert!(is_error(
            &s.handle(Request::TurnEnd {
                turn: 0,
                quiescent: true
            }),
            ErrorCode::Malformed
        ));
        assert_eq!(
            s.handle(Request::TurnEnd {
                turn: 1,
                quiescent: true
            }),
            Reply::TurnEnd {
                turn: 1,
                sealed: Some(birth.lsn.get() + 1)
            }
        );
        drop(s);
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        assert_eq!(
            s.handle(hello()),
            Reply::Hello {
                version: VERSION,
                last_sealed_turn: Some(1)
            }
        );
    }

    /// Turn 0 is refused even before any Seal: a harness Seal at turn 0
    /// would look like a birth Seal.
    #[test]
    fn turn_zero_is_refused_without_a_birth_seal_too() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        s.handle(hello());
        let r = s.handle(Request::TurnEnd {
            turn: 0,
            quiescent: true,
        });
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
        s.handle(Request::TurnEnd {
            turn: 7,
            quiescent: true,
        });
        drop(s);
        drop(v);
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        assert_eq!(
            s.handle(hello()),
            Reply::Hello {
                version: VERSION,
                last_sealed_turn: Some(7)
            }
        );
        assert!(is_error(
            &s.handle(Request::TurnEnd {
                turn: 7,
                quiescent: true
            }),
            ErrorCode::Malformed
        ));
    }

    #[test]
    fn first_seal_takes_the_given_verdict_then_clean() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut s = Session::new(
            &mut v,
            Verdict::Unverified("recovered: 1 group dropped".into()),
        )
        .unwrap();
        s.handle(hello());
        s.handle(Request::TurnEnd {
            turn: 1,
            quiescent: true,
        });
        s.handle(Request::TurnEnd {
            turn: 2,
            quiescent: true,
        });
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
        assert_eq!(
            verdicts,
            vec![
                Verdict::Unverified("recovered: 1 group dropped".into()),
                Verdict::Clean
            ]
        );
    }

    /// Records the Seals it was called for; fails when told to.
    struct Hook {
        seen: Vec<Position>,
        fail: bool,
    }

    impl<L: Layers> AfterSeal<L> for Hook {
        fn after_seal(&mut self, vessel: &mut Vessel<L>, seal: Position) -> Result<(), String> {
            assert_eq!(
                vessel.last_seal(),
                Some(seal),
                "called with the Seal just taken"
            );
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
        let mut hook = Hook {
            seen: Vec::new(),
            fail: false,
        };
        let mut s = Session::new(&mut v, Verdict::Clean)
            .unwrap()
            .with_after_seal(&mut hook);
        s.handle(hello());
        assert_eq!(
            s.handle(Request::TurnEnd {
                turn: 1,
                quiescent: false
            }),
            Reply::TurnEnd {
                turn: 1,
                sealed: None
            }
        );
        assert_eq!(
            s.handle(Request::TurnEnd {
                turn: 1,
                quiescent: true
            }),
            Reply::TurnEnd {
                turn: 1,
                sealed: Some(2)
            }
        );
        assert_eq!(
            s.pending_seal.map(|p| p.lsn.get()),
            Some(2),
            "not yet: after the reply"
        );
        s.after_reply();
        s.after_reply();
        assert_eq!(s.after_seal_failures(), (0, None));
        drop(s);
        assert_eq!(
            hook.seen.iter().map(|p| p.lsn.get()).collect::<Vec<_>>(),
            vec![2],
            "not for the unsealed turn"
        );

        hook.fail = true;
        let mut s = Session::new(&mut v, Verdict::Clean)
            .unwrap()
            .with_after_seal(&mut hook);
        s.handle(hello());
        assert_eq!(
            s.handle(Request::TurnEnd {
                turn: 2,
                quiescent: true
            }),
            Reply::TurnEnd {
                turn: 2,
                sealed: Some(3)
            }
        );
        // The next request runs the pending hook first.
        s.handle(Request::Transcript {
            entry: b"next".to_vec(),
        });
        assert_eq!(s.after_seal_failures(), (1, Some("store down")));
        drop(s);
        assert_eq!(v.last_seal().unwrap().lsn, Lsn::new(3), "the Seal stands");
    }

    /// F4b.  A publish that failed is retried before the next effect, and
    /// the effect goes out if the retry lands.  The publisher refuses
    /// while the Seal is unpublished, as `ship_log` does (F4).
    #[test]
    fn a_failed_publish_is_retried_before_an_effect() {
        use std::cell::Cell;
        use std::rc::Rc;
        /// Fails the first `fails` calls; marks the Seal published after.
        struct Flaky {
            seen: Vec<Position>,
            fails: u32,
            published: Rc<Cell<bool>>,
        }
        impl<L: Layers> AfterSeal<L> for Flaky {
            fn after_seal(&mut self, _: &mut Vessel<L>, seal: Position) -> Result<(), String> {
                self.seen.push(seal);
                if self.fails > 0 {
                    self.fails -= 1;
                    self.published.set(false);
                    return Err("store down".into());
                }
                self.published.set(true);
                Ok(())
            }
        }
        /// Refuses to ship the log while the Seal is unpublished.
        struct Strict(Rc<Cell<bool>>);
        impl crate::effects::Publish for Strict {
            fn publish(
                &mut self,
                _: taso_core::envelope::ChronicleId,
                _: taso_core::envelope::Epoch,
                _: &[&crate::segment::Segment],
                _: Position,
            ) -> Result<(), crate::effects::PublishError> {
                if self.0.get() {
                    Ok(())
                } else {
                    Err(crate::effects::PublishError(
                        "pack: Seal not shipped".into(),
                    ))
                }
            }
        }
        let mail = |call| declare(call, "mail", b"send bob");

        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let published = Rc::new(Cell::new(true));
        let (mut fx, _) =
            Effects::open(Mode::Dispatch, Box::new(Strict(published.clone())), &mut v).unwrap();
        // Two failures: the publish after the reply, and the first retry.
        let mut hook = Flaky {
            seen: Vec::new(),
            fails: 2,
            published: published.clone(),
        };
        let mut s = Session::new(&mut v, Verdict::Clean)
            .unwrap()
            .with_effects(&mut fx)
            .with_after_seal(&mut hook);
        s.handle(hello());
        let Reply::TurnEnd {
            sealed: Some(seal), ..
        } = s.handle(Request::TurnEnd {
            turn: 1,
            quiescent: true,
        })
        else {
            panic!("turn 1 not sealed")
        };
        s.after_reply();
        assert_eq!(s.after_seal_failures().0, 1);

        // Retry fails: the effect is refused, as before F4b.
        assert!(matches!(
            s.handle(mail(1)),
            Reply::Effect {
                result: EffectResult::Refused { .. },
                ..
            }
        ));
        assert_eq!(s.after_seal_failures().0, 2);
        // Retry lands: the effect is released, in the same turn.
        assert!(matches!(
            s.handle(mail(2)),
            Reply::Effect {
                result: EffectResult::Released { .. },
                ..
            }
        ));
        // Published: no more retries.
        s.handle(mail(3));
        assert_eq!(s.after_seal_failures().0, 2);
        drop(s);
        assert_eq!(
            hook.seen.iter().map(|p| p.lsn.get()).collect::<Vec<_>>(),
            vec![seal; 3],
            "the same Seal each time, retried once per effect until it landed"
        );
    }

    /// A later Seal published replaces the retry: an earlier Seal is never
    /// published after a newer one.
    #[test]
    fn a_later_seal_replaces_the_retry() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let (mut fx, _) = Effects::open(
            Mode::Dispatch,
            Box::new(crate::effects::AlwaysPublish),
            &mut v,
        )
        .unwrap();
        let mut hook = Hook {
            seen: Vec::new(),
            fail: true,
        };
        {
            let mut s = Session::new(&mut v, Verdict::Clean)
                .unwrap()
                .with_effects(&mut fx)
                .with_after_seal(&mut hook);
            s.handle(hello());
            s.handle(Request::TurnEnd {
                turn: 1,
                quiescent: true,
            });
            s.after_reply();
            assert!(s.unpublished.is_some(), "turn 1's Seal awaits a retry");
        }
        hook.fail = false;
        let mut s = Session::new(&mut v, Verdict::Clean)
            .unwrap()
            .with_effects(&mut fx)
            .with_after_seal(&mut hook);
        s.handle(hello());
        s.handle(Request::TurnEnd {
            turn: 2,
            quiescent: true,
        });
        s.after_reply();
        assert_eq!(s.unpublished, None);
        s.handle(declare(1, "mail", b"send bob"));
        drop(s);
        let seen: Vec<u64> = hook.seen.iter().map(|p| p.lsn.get()).collect();
        assert_eq!(seen.len(), 2, "turn 1 once (failed), turn 2 once: {seen:?}");
        assert!(seen[1] > seen[0], "never back to the older Seal: {seen:?}");
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
                n += usize::from(matches!(
                    reply,
                    Reply::TurnEnd {
                        sealed: Some(_),
                        ..
                    }
                ));
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
        for req in [
            hello(),
            Request::TurnEnd {
                turn: 1,
                quiescent: true,
            },
            Request::TurnEnd {
                turn: 2,
                quiescent: true,
            },
        ] {
            taso_field::protocol::send_request(&mut input, &req).unwrap();
        }
        let output = Rc::new(RefCell::new(Vec::new()));
        let published = Rc::new(RefCell::new(0));
        let mut stream = Duplex {
            input: std::io::Cursor::new(input),
            output: output.clone(),
            published: published.clone(),
        };
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mut hook = Watching(output.clone(), Vec::new(), published.clone());
        let mut s = Session::new(&mut v, Verdict::Clean)
            .unwrap()
            .with_after_seal(&mut hook);
        assert!(matches!(serve(&mut stream, &mut s), Ended::Closed));
        drop(s);
        assert_eq!(
            hook.1,
            vec![2, 3],
            "each publish ran after its TurnEnd reply was written"
        );
    }

    #[test]
    fn accept_until_stops_and_accepts() {
        let dir = tempfile::tempdir().unwrap();
        let sock = FieldSocket::bind(dir.path().join("f.sock")).unwrap();
        let polls = std::cell::Cell::new(0);
        let none = sock
            .accept_until(
                &|| {
                    polls.set(polls.get() + 1);
                    polls.get() > 2
                },
                Duration::from_millis(1),
            )
            .unwrap();
        assert!(none.is_none());
        assert_eq!(polls.get(), 3);
        let _client = UnixStream::connect(sock.path()).unwrap();
        let mut got = sock
            .accept_until(&|| false, Duration::from_millis(1))
            .unwrap()
            .unwrap();
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
            Some(Reply::Hello {
                version: VERSION,
                last_sealed_turn: None
            })
        );
    }

    /// A declared effect: an irreversible, deduplicated request.
    fn declare(call: u64, provider: &str, request: &[u8]) -> Request {
        Request::Effect {
            call,
            provider: provider.into(),
            request: request.to_vec(),
            footprint: Vec::new(),
            retry: taso_core::record::RetryPolicy::ProviderDeduplicated {
                key: request.to_vec(),
            },
            consequence: taso_core::record::Consequence::Irreversible,
            authority: b"user".to_vec(),
        }
    }

    #[test]
    fn effects_are_refused_without_an_engine_and_record_nothing() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let tail = v.tail();
        let mut s = Session::new(&mut v, Verdict::Clean).unwrap();
        s.handle(hello());
        let r = s.handle(declare(3, "mail", b"send bob"));
        assert!(matches!(
            r,
            Reply::Effect {
                call: 3,
                result: EffectResult::Refused { .. }
            }
        ));
        assert!(matches!(
            s.handle_as(
                &mut sender(),
                Request::Outcome {
                    op: 1,
                    result: Outcome::Unknown
                }
            ),
            Reply::Outcome {
                op: 1,
                refused: Some(_)
            }
        ));
        assert_eq!(
            s.handle_as(&mut sender(), Request::Open),
            Reply::Open {
                effects: Vec::new()
            }
        );
        drop(s);
        assert_eq!(v.tail(), tail);
    }

    /// A dispatcher over the Field: a declared effect is released, listed
    /// as open with its exact request bytes and key, reported by the
    /// sender and then gone from the list; a report on an op that is not
    /// open is refused and records nothing; the Seal's ledger_pos covers
    /// the effect records.
    #[test]
    fn effects_are_released_listed_and_reported_over_the_field() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let (mut fx, _) = Effects::open(
            Mode::Dispatch,
            Box::new(crate::effects::AlwaysPublish),
            &mut v,
        )
        .unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean)
            .unwrap()
            .with_effects(&mut fx);
        s.handle(hello());
        assert_eq!(
            s.handle(declare(1, "mail", b"send bob")),
            Reply::Effect {
                call: 1,
                result: EffectResult::Released { op: 1 }
            }
        );
        assert_eq!(
            s.handle_as(&mut sender(), Request::Open),
            Reply::Open {
                effects: vec![OpenEffect {
                    op: 1,
                    provider: "mail".into(),
                    request: b"send bob".to_vec(),
                    retry: taso_core::record::RetryPolicy::ProviderDeduplicated {
                        key: b"send bob".to_vec()
                    },
                    // As declared: the sender needs both to decide how to act.
                    consequence: taso_core::record::Consequence::Irreversible,
                    authority: b"user".to_vec(),
                    unknown: false,
                }]
            }
        );
        let tail = s.vessel.tail();
        assert!(matches!(
            s.handle_as(
                &mut sender(),
                Request::Outcome {
                    op: 7,
                    result: Outcome::Unknown
                }
            ),
            Reply::Outcome {
                op: 7,
                refused: Some(_)
            }
        ));
        assert_eq!(s.vessel.tail(), tail, "a refused report records nothing");
        assert_eq!(
            s.handle_as(
                &mut sender(),
                Request::Outcome {
                    op: 1,
                    result: Outcome::Applied {
                        receipt: b"ok".to_vec()
                    }
                }
            ),
            Reply::Outcome {
                op: 1,
                refused: None
            }
        );
        assert_eq!(
            s.handle_as(&mut sender(), Request::Open),
            Reply::Open {
                effects: Vec::new()
            }
        );
        // The Seal's ledger_pos covers the effect records.
        s.handle(Request::TurnEnd {
            turn: 1,
            quiescent: true,
        });
        drop(s);
        let frames = v.chronicle().frames().unwrap();
        let last_effect = frames
            .iter()
            .rfind(|f| f.envelope.stream == Stream::Effect)
            .unwrap();
        let seal = frames.last().unwrap();
        let Payload::Seal(rec) = Payload::decode(&seal.payload).unwrap() else {
            panic!()
        };
        assert_eq!(rec.ledger_pos, last_effect.envelope.lsn);
    }

    /// A holder over the Field: the same declaration is held, never
    /// listed as open, and a report on it is refused.
    #[test]
    fn a_holders_effects_are_held_over_the_field() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let (mut fx, _) =
            Effects::open(Mode::Hold, Box::new(crate::effects::AlwaysPublish), &mut v).unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean)
            .unwrap()
            .with_effects(&mut fx);
        s.handle(hello());
        assert_eq!(
            s.handle(declare(1, "pay", b"pay 10")),
            Reply::Effect {
                call: 1,
                result: EffectResult::Held { op: 1 }
            }
        );
        assert_eq!(
            s.handle_as(&mut sender(), Request::Open),
            Reply::Open {
                effects: Vec::new()
            }
        );
        assert!(matches!(
            s.handle_as(
                &mut sender(),
                Request::Outcome {
                    op: 1,
                    result: Outcome::Applied { receipt: vec![] }
                }
            ),
            Reply::Outcome {
                op: 1,
                refused: Some(_)
            }
        ));
    }

    /// The daemon's part, on the test host: a child per request, named
    /// `c1`, `c2`, …, kept open for the test to run; at most `quota`.
    struct FakeBranches<'h> {
        host: &'h crate::vessel::Host<crate::vessel::tests::FakePool>,
        quota: usize,
        children: Vec<Vessel<<crate::vessel::tests::FakePool as crate::vessel::Pool>::Layers>>,
        promoted: Vec<(String, PromoteResult)>,
    }

    impl Branches<<crate::vessel::tests::FakePool as crate::vessel::Pool>::Layers>
        for FakeBranches<'_>
    {
        fn fork(
            &mut self,
            vessel: &Vessel<<crate::vessel::tests::FakePool as crate::vessel::Pool>::Layers>,
            at: SealAt,
        ) -> Result<(String, u64), String> {
            if self.children.len() == self.quota {
                return Err("no fork slot left".into());
            }
            let name = format!("c{}", self.children.len() + 1);
            let c = self
                .host
                .fork_from_log(vessel.id(), at, name.as_bytes())
                .map_err(|e| e.to_string())?;
            let seal = c.lineage().origin.parent().unwrap().seal.get();
            self.children.push(c);
            Ok((name, seal))
        }

        fn child_log(
            &mut self,
            vessel: &Vessel<<crate::vessel::tests::FakePool as crate::vessel::Pool>::Layers>,
            child: &str,
        ) -> Result<ReadLog, String> {
            self.host
                .read_log_of(taso_core::record::vessel_id(
                    vessel.namespace(),
                    child.as_bytes(),
                ))
                .map_err(|e| e.to_string())
        }

        fn promoted(&mut self, child: &str, result: &PromoteResult) {
            self.promoted.push((child.into(), result.clone()));
        }
    }

    /// A child (always held) records `n` proposals and seals one turn.
    fn propose<L: Layers>(c: &mut Vessel<L>, n: u64) {
        let (mut fx, _) =
            Effects::open(Mode::Hold, Box::new(crate::effects::AlwaysPublish), c).unwrap();
        let mut s = Session::new(c, Verdict::Clean)
            .unwrap()
            .with_effects(&mut fx);
        let Reply::Hello {
            last_sealed_turn, ..
        } = s.handle(hello())
        else {
            panic!("no hello")
        };
        for k in 0..n {
            let req = format!("child-{k}").into_bytes();
            assert!(matches!(
                s.handle(declare(k, "pay", &req)),
                Reply::Effect {
                    result: EffectResult::Held { .. },
                    ..
                }
            ));
        }
        let turn = last_sealed_turn.unwrap_or(0) + 1;
        assert!(matches!(
            s.handle(Request::TurnEnd {
                turn,
                quiescent: true
            }),
            Reply::TurnEnd {
                sealed: Some(_),
                ..
            }
        ));
    }

    /// D1 over the Field: the agent asks, the Warden's `Branches` makes
    /// the child (its quota refuses the rest); a promotion adopts that
    /// child's held proposals as this Vessel's released effects, and a
    /// second promotion at the same fork point — the sibling — is refused
    /// with nothing adopted (C1: the unchosen future touched nothing).
    #[test]
    fn forks_and_promotions_are_asked_for_over_the_field() {
        let e = env();
        let (mut p, _) = e.host.ensure(ns(1), b"prime").unwrap();
        p.seal_birth().unwrap();
        let mut b = FakeBranches {
            host: &e.host,
            quota: 2,
            children: Vec::new(),
            promoted: Vec::new(),
        };
        let (mut fx, _) = Effects::open(
            Mode::Dispatch,
            Box::new(crate::effects::AlwaysPublish),
            &mut p,
        )
        .unwrap();
        let fork_seal = {
            let mut s = Session::new(&mut p, Verdict::Clean)
                .unwrap()
                .with_effects(&mut fx)
                .with_branches(&mut b);
            s.handle(hello());
            let Reply::TurnEnd {
                sealed: Some(seal), ..
            } = s.handle(Request::TurnEnd {
                turn: 1,
                quiescent: true,
            })
            else {
                panic!("turn 1 not sealed")
            };
            for want in ["c1", "c2"] {
                assert_eq!(
                    s.handle(Request::Fork { seal: None }),
                    Reply::Fork {
                        result: ForkResult::Forked {
                            child: want.into(),
                            seal
                        }
                    }
                );
            }
            // The quota is the Warden's, not the agent's.
            assert!(matches!(
                s.handle(Request::Fork { seal: None }),
                Reply::Fork {
                    result: ForkResult::Refused { .. }
                }
            ));
            seal
        };
        let mut children = std::mem::take(&mut b.children);
        propose(&mut children[0], 2);
        propose(&mut children[1], 1);
        let c1_seal = children[0].last_seal().unwrap().lsn.get();
        drop(children);

        let mut s = Session::new(&mut p, Verdict::Clean)
            .unwrap()
            .with_effects(&mut fx)
            .with_branches(&mut b);
        s.handle(hello());
        assert_eq!(
            s.handle_as(&mut sender(), Request::Open),
            Reply::Open { effects: vec![] }
        );
        let Reply::Promote {
            child,
            result: PromoteResult::Promoted { seal, adopted },
        } = s.handle(Request::Promote {
            child: "c1".into(),
            seal: None,
        })
        else {
            panic!("c1 not promoted")
        };
        assert_eq!((child.as_str(), seal, adopted.len()), ("c1", c1_seal, 2));
        let Reply::Open { effects } = s.handle_as(&mut sender(), Request::Open) else {
            panic!()
        };
        assert_eq!(effects.iter().map(|e| e.op).collect::<Vec<_>>(), adopted);
        assert!(effects
            .iter()
            .all(|e| e.request.starts_with(b"child-") && !e.unknown));
        // The sibling, c1 again, and a turn: the Vessel is promoted, its
        // files are adopted at the next start (C7), so nothing more is taken
        // until then; one choice per fork point holds below that too.
        for req in [
            Request::Promote {
                child: "c2".into(),
                seal: None,
            },
            Request::Promote {
                child: "c1".into(),
                seal: None,
            },
            Request::TurnEnd {
                turn: 9,
                quiescent: true,
            },
            Request::Fork { seal: None },
        ] {
            assert!(is_error(&s.handle(req), ErrorCode::Closed));
        }
        let Reply::Open { effects: after } = s.handle_as(&mut sender(), Request::Open) else {
            panic!()
        };
        let ops = |l: &[OpenEffect]| l.iter().map(|e| e.op).collect::<Vec<_>>();
        assert_eq!(
            ops(&after),
            ops(&effects),
            "nothing of the sibling's was adopted"
        );
        assert!(
            after.iter().all(|e| e.unknown),
            "listed before: may have been acted on"
        );
        // Results stay readable.
        assert!(matches!(
            s.handle(Request::Result { op: adopted[0] }),
            Reply::Result {
                state: OpState::Pending,
                ..
            }
        ));
        drop(s);
        assert_eq!(b.promoted.len(), 1);
        assert!(
            p.last_seal().unwrap().lsn.get() == fork_seal,
            "no Seal taken"
        );
        assert!(
            p.adoption_pending().unwrap().is_some(),
            "the files are still to come"
        );
    }

    /// A store that is down from the `from`-th ship on, until `up` is set.
    struct Down {
        calls: std::rc::Rc<std::cell::Cell<u32>>,
        from: u32,
        up: std::rc::Rc<std::cell::Cell<bool>>,
    }

    impl crate::effects::Publish for Down {
        fn publish(
            &mut self,
            _: taso_core::envelope::ChronicleId,
            _: taso_core::envelope::Epoch,
            _: &[&crate::segment::Segment],
            _: Position,
        ) -> Result<(), crate::effects::PublishError> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() >= self.from && !self.up.get() {
                return Err(crate::effects::PublishError("store unavailable".into()));
            }
            Ok(())
        }
    }

    /// The adoption's ship fails: the agent is told it is promoted (it
    /// is: recorded, never undone), but Open lists none of it until a ship
    /// succeeds; Open retries, and lists them once the store is back.
    #[test]
    fn an_adoption_not_yet_shipped_is_not_listed_until_it_is() {
        let e = env();
        let (mut p, _) = e.host.ensure(ns(1), b"prime").unwrap();
        p.seal_birth().unwrap();
        let mut b = FakeBranches {
            host: &e.host,
            quota: 1,
            children: Vec::new(),
            promoted: Vec::new(),
        };
        let up = std::rc::Rc::new(std::cell::Cell::new(false));
        // Ship 1: the Promotion; ship 2: the adoption (down from there).
        let (mut fx, _) = Effects::open(
            Mode::Dispatch,
            Box::new(Down {
                calls: Default::default(),
                from: 2,
                up: up.clone(),
            }),
            &mut p,
        )
        .unwrap();
        {
            let mut s = Session::new(&mut p, Verdict::Clean)
                .unwrap()
                .with_effects(&mut fx)
                .with_branches(&mut b);
            s.handle(hello());
            assert!(matches!(
                s.handle(Request::Fork { seal: None }),
                Reply::Fork {
                    result: ForkResult::Forked { .. }
                }
            ));
        }
        let mut children = std::mem::take(&mut b.children);
        propose(&mut children[0], 2);
        drop(children);

        let mut s = Session::new(&mut p, Verdict::Clean)
            .unwrap()
            .with_effects(&mut fx)
            .with_branches(&mut b);
        s.handle(hello());
        let Reply::Promote {
            result: PromoteResult::Promoted { adopted, .. },
            ..
        } = s.handle(Request::Promote {
            child: "c1".into(),
            seal: None,
        })
        else {
            panic!("not promoted")
        };
        assert_eq!(adopted.len(), 2);
        assert_eq!(
            s.handle_as(&mut sender(), Request::Open),
            Reply::Open { effects: vec![] }
        );
        up.set(true);
        let Reply::Open { effects } = s.handle_as(&mut sender(), Request::Open) else {
            panic!()
        };
        assert_eq!(effects.iter().map(|e| e.op).collect::<Vec<_>>(), adopted);
    }

    /// Review finding 3: a sender that crashed while the Warden stayed up
    /// left no `OutcomeUnknown`; the next listing tells whoever reads it
    /// that the op was handed out before — also on a new connection, the
    /// engine (not the session) remembers.  A new op is not marked.
    #[test]
    fn an_op_listed_before_is_listed_as_unknown() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        v.seal_birth().unwrap();
        let (mut fx, _) = Effects::open(
            Mode::Dispatch,
            Box::new(crate::effects::AlwaysPublish),
            &mut v,
        )
        .unwrap();
        let unknown = |r: Reply| match r {
            Reply::Open { effects } => effects
                .iter()
                .map(|e| (e.op, e.unknown))
                .collect::<Vec<_>>(),
            r => panic!("{r:?}"),
        };
        {
            let mut s = Session::new(&mut v, Verdict::Clean)
                .unwrap()
                .with_effects(&mut fx);
            s.handle(hello());
            s.handle(declare(1, "mail", b"send bob"));
            assert_eq!(
                unknown(s.handle_as(&mut sender(), Request::Open)),
                [(1, false)]
            );
            // The sender polls again, or crashed and a new one reads.
            assert_eq!(
                unknown(s.handle_as(&mut sender(), Request::Open)),
                [(1, true)]
            );
        }
        // A new connection (the sender restarted), the same engine.
        let mut s = Session::new(&mut v, Verdict::Clean)
            .unwrap()
            .with_effects(&mut fx);
        s.handle(hello());
        s.handle(declare(2, "mail", b"send eve"));
        assert_eq!(
            unknown(s.handle_as(&mut sender(), Request::Open)),
            [(1, true), (2, false)],
            "the old op is marked, the new one is not"
        );
    }

    /// Review finding 4 (C5): both sockets are served at once.  The agent
    /// and a sender are connected together; the agent declares, the sender
    /// lists and reports, the agent reads the result — all while both
    /// connections stay open.  Once the agent is gone and `stop` says so,
    /// the sender's connection is closed and serving returns.
    #[test]
    fn the_agent_and_a_sender_are_served_together() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        v.seal_birth().unwrap();
        let (mut fx, _) = Effects::open(
            Mode::Dispatch,
            Box::new(crate::effects::AlwaysPublish),
            &mut v,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let agent = FieldSocket::bind(dir.path().join("agent.sock")).unwrap();
        let sender = FieldSocket::bind(dir.path().join("sender.sock")).unwrap();
        let done = AtomicBool::new(false);
        let mut ends = Vec::new();
        std::thread::scope(|scope| {
            let (a, snd) = (agent.path().to_path_buf(), sender.path().to_path_buf());
            let done = &done;
            scope.spawn(move || {
                let ask = |c: &mut UnixStream, r: Request| {
                    send_request(c, &r).unwrap();
                    recv_reply(c).unwrap().unwrap()
                };
                let mut ag = UnixStream::connect(&a).unwrap();
                let mut se = UnixStream::connect(&snd).unwrap();
                assert!(matches!(ask(&mut ag, hello()), Reply::Hello { .. }));
                assert!(matches!(ask(&mut se, hello()), Reply::Hello { .. }));
                assert!(matches!(
                    ask(&mut ag, declare(1, "mail", b"send bob")),
                    Reply::Effect {
                        result: EffectResult::Released { op: 1 },
                        ..
                    }
                ));
                let Reply::Open { effects } = ask(&mut se, Request::Open) else {
                    panic!()
                };
                assert_eq!(effects.len(), 1);
                assert!(matches!(
                    ask(
                        &mut se,
                        Request::Outcome {
                            op: 1,
                            result: Outcome::Applied {
                                receipt: b"r1".to_vec()
                            }
                        }
                    ),
                    Reply::Outcome { refused: None, .. }
                ));
                assert_eq!(
                    ask(&mut ag, Request::Result { op: 1 }),
                    Reply::Result {
                        op: 1,
                        state: OpState::Applied {
                            receipt: b"r1".to_vec()
                        }
                    }
                );
                // The agent asks on the sender's behalf: refused.
                assert!(is_error(
                    &ask(&mut ag, Request::Open),
                    ErrorCode::NotOnThisSocket
                ));
                drop(ag);
                done.store(true, Ordering::SeqCst);
                // The Warden closes the sender's connection.
                assert!(recv_reply(&mut se).unwrap().is_none());
            });
            let mut session = Session::new(&mut v, Verdict::Clean)
                .unwrap()
                .with_effects(&mut fx);
            serve_vessel(
                &mut session,
                &agent,
                &sender,
                &|| done.load(Ordering::SeqCst),
                Duration::from_millis(5),
                &mut |c| ends.push(c.socket),
            )
            .unwrap();
        });
        ends.sort_by_key(|s| *s == Socket::Sender);
        assert_eq!(ends, [Socket::Agent, Socket::Sender]);
    }

    /// Review finding 2: who may write an outcome is a trust boundary.  The
    /// agent's socket refuses Open and Outcome, the sender's refuses
    /// everything an agent does; a refusal records nothing.  Both need
    /// Hello first.
    #[test]
    fn each_socket_takes_only_its_own_requests() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        v.seal_birth().unwrap();
        let (mut fx, _) = Effects::open(
            Mode::Dispatch,
            Box::new(crate::effects::AlwaysPublish),
            &mut v,
        )
        .unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean)
            .unwrap()
            .with_effects(&mut fx);
        s.handle(hello());
        assert!(matches!(
            s.handle(declare(1, "mail", b"send bob")),
            Reply::Effect {
                result: EffectResult::Released { op: 1 },
                ..
            }
        ));
        let tail = s.vessel.tail();
        // The agent may neither list nor report.
        for req in [
            Request::Open,
            Request::Outcome {
                op: 1,
                result: Outcome::Applied { receipt: vec![] },
            },
        ] {
            assert!(is_error(&s.handle(req), ErrorCode::NotOnThisSocket));
        }
        assert_eq!(s.vessel.tail(), tail, "nothing recorded");
        // The sender: Hello first, then only Open and Outcome.
        let mut snd = Conn::new(Socket::Sender);
        assert!(is_error(
            &s.handle_as(&mut snd, Request::Open),
            ErrorCode::BadHello
        ));
        assert!(matches!(
            s.handle_as(&mut snd, hello()),
            Reply::Hello { .. }
        ));
        for req in [
            declare(2, "mail", b"send eve"),
            Request::Transcript { entry: vec![1] },
            Request::TurnEnd {
                turn: 1,
                quiescent: true,
            },
            Request::Fork { seal: None },
            Request::Promote {
                child: "c".into(),
                seal: None,
            },
            Request::Result { op: 1 },
        ] {
            assert!(
                is_error(
                    &s.handle_as(&mut snd, req.clone()),
                    ErrorCode::NotOnThisSocket
                ),
                "{req:?}"
            );
        }
        assert_eq!(s.vessel.tail(), tail, "nothing recorded");
        assert!(matches!(
            s.handle_as(&mut snd, Request::Open),
            Reply::Open { effects } if effects.len() == 1
        ));
    }

    /// The agent reads what became of its own effect (C5), never writes
    /// it: pending until the sender reports, then applied with the receipt
    /// or not applied with the reason; held in a fork; not found for an op
    /// that is not its.  Reading marks nothing for the sender.
    #[test]
    fn the_agent_reads_its_effects_result() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        v.seal_birth().unwrap();
        let (mut fx, _) = Effects::open(
            Mode::Dispatch,
            Box::new(crate::effects::AlwaysPublish),
            &mut v,
        )
        .unwrap();
        let mut s = Session::new(&mut v, Verdict::Clean)
            .unwrap()
            .with_effects(&mut fx);
        s.handle(hello());
        s.handle(declare(1, "mail", b"send bob"));
        s.handle(declare(2, "mail", b"send eve"));
        let result = |s: &mut Session<'_, _>, op| match s.handle(Request::Result { op }) {
            Reply::Result { op: o, state } if o == op => state,
            r => panic!("{r:?}"),
        };
        assert_eq!(result(&mut s, 1), OpState::Pending);
        // Asking marks nothing: the sender's first listing is fresh.
        let Reply::Open { effects } = s.handle_as(&mut sender(), Request::Open) else {
            panic!()
        };
        assert!(effects.iter().all(|e| !e.unknown));
        let mut snd = sender();
        s.handle_as(
            &mut snd,
            Request::Outcome {
                op: 1,
                result: Outcome::Applied {
                    receipt: b"msg-1".to_vec(),
                },
            },
        );
        s.handle_as(
            &mut snd,
            Request::Outcome {
                op: 2,
                result: Outcome::NotApplied {
                    reason: "bounced".into(),
                },
            },
        );
        assert_eq!(
            result(&mut s, 1),
            OpState::Applied {
                receipt: b"msg-1".to_vec()
            }
        );
        assert_eq!(
            result(&mut s, 2),
            OpState::NotApplied {
                reason: "bounced".into()
            }
        );
        assert_eq!(result(&mut s, 99), OpState::NotFound);
        drop(s);

        // In a fork, a proposal is held.
        let (mut h, _) = e.host.ensure(ns(1), b"h").unwrap();
        h.seal_birth().unwrap();
        let (mut hfx, _) =
            Effects::open(Mode::Hold, Box::new(crate::effects::AlwaysPublish), &mut h).unwrap();
        let mut s = Session::new(&mut h, Verdict::Clean)
            .unwrap()
            .with_effects(&mut hfx);
        s.handle(hello());
        s.handle(declare(1, "mail", b"send bob"));
        assert_eq!(result(&mut s, 1), OpState::Held);
    }

    /// M7 over the Field (C8): a parent that sealed again since the fork
    /// has moved on; promoting the child is refused, names both Seals,
    /// and adopts and lists nothing.
    #[test]
    fn a_promotion_after_the_parent_moved_is_refused() {
        let e = env();
        let (mut p, _) = e.host.ensure(ns(1), b"prime").unwrap();
        p.seal_birth().unwrap();
        let mut b = FakeBranches {
            host: &e.host,
            quota: 1,
            children: Vec::new(),
            promoted: Vec::new(),
        };
        let (mut fx, _) = Effects::open(
            Mode::Dispatch,
            Box::new(crate::effects::AlwaysPublish),
            &mut p,
        )
        .unwrap();
        {
            let mut s = Session::new(&mut p, Verdict::Clean)
                .unwrap()
                .with_effects(&mut fx)
                .with_branches(&mut b);
            s.handle(hello());
            assert!(matches!(
                s.handle(Request::Fork { seal: None }),
                Reply::Fork {
                    result: ForkResult::Forked { .. }
                }
            ));
        }
        let mut children = std::mem::take(&mut b.children);
        propose(&mut children[0], 2);
        drop(children);

        let mut s = Session::new(&mut p, Verdict::Clean)
            .unwrap()
            .with_effects(&mut fx)
            .with_branches(&mut b);
        s.handle(hello());
        // The parent moves: one more sealed turn.
        assert!(matches!(
            s.handle(Request::TurnEnd {
                turn: 1,
                quiescent: true
            }),
            Reply::TurnEnd {
                sealed: Some(_),
                ..
            }
        ));
        let tail = s.vessel.tail();
        let Reply::Promote {
            result: PromoteResult::Refused { reason },
            ..
        } = s.handle(Request::Promote {
            child: "c1".into(),
            seal: None,
        })
        else {
            panic!("promoted after the parent moved")
        };
        assert!(reason.contains("sealed again"), "{reason}");
        assert_eq!(s.vessel.tail(), tail, "nothing recorded");
        assert_eq!(
            s.handle_as(&mut sender(), Request::Open),
            Reply::Open { effects: vec![] }
        );
    }

    /// Without the Warden's `Branches` (or, for Promote, an engine),
    /// Fork and Promote are refused and nothing is recorded.
    #[test]
    fn forks_and_promotions_without_branches_are_refused() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        v.seal_birth().unwrap();
        let (mut fx, _) = Effects::open(
            Mode::Dispatch,
            Box::new(crate::effects::AlwaysPublish),
            &mut v,
        )
        .unwrap();
        let mut b = FakeBranches {
            host: &e.host,
            quota: 1,
            children: Vec::new(),
            promoted: Vec::new(),
        };
        {
            let mut s = Session::new(&mut v, Verdict::Clean)
                .unwrap()
                .with_effects(&mut fx);
            assert!(is_error(
                &s.handle(Request::Fork { seal: None }),
                ErrorCode::BadHello
            ));
            s.handle(hello());
            let tail = s.vessel.tail();
            assert!(matches!(
                s.handle(Request::Fork { seal: None }),
                Reply::Fork {
                    result: ForkResult::Refused { .. }
                }
            ));
            assert!(matches!(
                s.handle(Request::Promote {
                    child: "c1".into(),
                    seal: None
                }),
                Reply::Promote {
                    result: PromoteResult::Refused { .. },
                    ..
                }
            ));
            assert_eq!(s.vessel.tail(), tail);
        }
        // Branches without an engine: Promote is refused before the child
        // is even looked at.
        let mut s = Session::new(&mut v, Verdict::Clean)
            .unwrap()
            .with_branches(&mut b);
        s.handle(hello());
        assert!(matches!(
            s.handle(Request::Promote {
                child: "c1".into(),
                seal: None
            }),
            Reply::Promote {
                result: PromoteResult::Refused { .. },
                ..
            }
        ));
        drop(s);
        assert!(b.promoted.len() == 1 && b.children.is_empty());
    }

    #[test]
    fn a_turn_that_is_not_really_quiescent_is_not_sealed() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        let mount = tempfile::tempdir().unwrap();
        std::fs::write(mount.path().join("state.db-journal"), [0u8; 512]).unwrap();
        let watch = Watch::new(mount.path(), &["state.db"]).unwrap();
        let tail = v.tail();
        let mut s = Session::new(&mut v, Verdict::Clean)
            .unwrap()
            .with_watch(watch);
        s.handle(hello());
        // The harness says quiescent; the journal says otherwise.
        assert_eq!(
            s.handle(Request::TurnEnd {
                turn: 1,
                quiescent: true
            }),
            Reply::TurnEnd {
                turn: 1,
                sealed: None
            }
        );
        assert_eq!(s.last_sealed_turn(), None);
        // Once the transaction is done, the same turn seals.
        std::fs::remove_file(mount.path().join("state.db-journal")).unwrap();
        assert!(matches!(
            s.handle(Request::TurnEnd {
                turn: 1,
                quiescent: true
            }),
            Reply::TurnEnd {
                turn: 1,
                sealed: Some(_)
            }
        ));
        drop(s);
        assert_eq!(v.tail().lsn, tail.lsn.next(), "exactly one Seal record");
        assert_eq!(v.chronicle().layers().list().unwrap().len(), 1, "one layer");
    }

    #[test]
    fn a_closed_vessel_answers_closed() {
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"u").unwrap();
        v.seal(
            StreamCut::EMPTY,
            Verdict::Clean,
            Lsn::new(0),
            TurnId::new(1),
        )
        .unwrap();
        let auth = taso_core::record::Authority {
            actor: "op".into(),
            reason: "merge".into(),
        };
        let mut old = e
            .host
            .succeed(v, ns(1), b"n", auth, false)
            .unwrap()
            .predecessor;
        let mut s = Session::new(&mut old, Verdict::Clean).unwrap();
        s.handle(hello());
        assert!(is_error(
            &s.handle(Request::Transcript { entry: vec![1] }),
            ErrorCode::Closed
        ));
        assert!(is_error(
            &s.handle(Request::TurnEnd {
                turn: 2,
                quiescent: true
            }),
            ErrorCode::Closed
        ));
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
            send_request(
                &mut client,
                &Request::Transcript {
                    entry: b"x".to_vec(),
                },
            )
            .unwrap();
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
            send_request(
                &mut c,
                &Request::TurnEnd {
                    turn: 1,
                    quiescent: true,
                },
            )
            .unwrap();
            recv_reply(&mut c).unwrap().unwrap()
        });
        let (ended, last) = sock.serve_one(&mut v, Verdict::Clean).unwrap();
        let reply = t.join().unwrap();
        assert!(matches!(ended, Ended::Closed));
        assert_eq!(last, Some(1));
        assert!(matches!(
            reply,
            Reply::TurnEnd {
                turn: 1,
                sealed: Some(_)
            }
        ));
        assert!(v.last_seal().is_some());
    }
}
