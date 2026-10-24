//! The effect engine of the reference runner: the outbox over the ledger
//! (v0.4 §7.2–7.4; P3, 2026-10-22).
//!
//! Taso never sends.  The record of every effect, and every rule about it
//! that is storage, lives in [`crate::ledger`]; this module is what one
//! Vessel's Field session and daemon drive: it answers an effect request
//! with *released*, *held* or *refused*, takes the sender's report of what
//! happened, and promotes a fork.  Whoever sends reads what was released
//! and reports back; `docs/relay.md` is that contract.
//!
//! # Asking ([`Effects::ask`])
//!
//! For one declared effect:
//!
//! 1. No effect authority (a released effect is unresolved) → refused.
//!    Nothing is recorded for a refusal.
//! 2. A Vessel that **dispatches** ([`Mode::Dispatch`]): the ledger
//!    releases it ([`Ledger::release`]: `Intent` and `DispatchAuthorized`,
//!    durable together), then ships the ledger
//!    ([`Ledger::ship_before_send`]).  If the ship fails, the release is
//!    withdrawn (`ConfirmedNotApplied`, "ledger not shipped") and the
//!    answer is refused: nothing a sender may act on exists only on this
//!    node.  Otherwise *released*: from here on a sender may act on it.
//! 3. A Vessel that **holds** ([`Mode::Hold`], a fork by default): the
//!    ledger records it as a proposal ([`Ledger::propose`]: `Intent` and
//!    `Proposed`, durable together) and answers *held*.  Nothing is ever
//!    released from this Chronicle; only its parent may adopt it.
//!
//! # Reporting ([`Effects::report`])
//!
//! The sender reports `Applied`, `NotApplied` or `Unknown` for a released
//! op; the ledger records it ([`Ledger::record`]).  An unknown outcome on
//! a barrier intent withdraws effect authority until an operator resolves
//! it ([`Effects::resolve`]).
//!
//! # Reopening ([`Effects::open`])
//!
//! Reconciliation lists; it settles nothing itself.  A released intent
//! with no terminal outcome is recorded `OutcomeUnknown` (that is the
//! truth after a crash: one of two worlds) and is an open obligation
//! until a sender reports or an operator resolves.  Held proposals are
//! not visited.  A Promotion whose adoption did not happen is reported
//! ([`Effects::pending_promotion`]) for the daemon to finish
//! ([`Effects::finish_promotion`]).
//!
//! # Promoting ([`Effects::promote`])
//!
//! [`Vessel::promote`] writes the Promotion (refused if the parent moved
//! or the child's Seal is not proven); the ledger is shipped; then every
//! proposal the Promotion names is adopted in **one** batch
//! ([`Ledger::adopt`]): all of them or none, so a crash leaves either the
//! Promotion without its adoption (finished on reopen) or the whole
//! adoption.  The adoption is shipped too before any of it is listed.  A
//! sibling that was not promoted has no Promotion and no adopted intent:
//! nothing of it was ever released.  The child's files follow as the
//! parent's next Seal, its adoption Seal ([`crate::vessel::Host::adopt_files`],
//! C7): the Promotion record is the commit for both.
//!
//! # Listing ([`Effects::released`]): only what is off the node
//!
//! A sender only ever sees a released effect whose record is shipped, so
//! whoever takes the Vessel over knows of everything a sender may have
//! acted on (review finding 1, 2026-10-23: an adoption listed before it
//! was shipped could be adopted again, as fresh, after a rebirth).  A
//! release is shipped before it is answered; an adoption is shipped after
//! it is recorded, and until that ship succeeds its ops are *unlisted*
//! ([`Effects::ship_unlisted`] retries); on reopen the released, unsettled
//! ops are listed once a ship covering them succeeds.  Unlisted ops are
//! recorded and stay so: a promotion is never undone, only its listing
//! waits.

use taso_core::envelope::Lsn;
use taso_core::record::{Authority, IntentRecord, OpId, Origin, OutcomeState, PromotionRecord};

use crate::chronicle::Layers;
use crate::ledger::{Answer, Authorized, Declared, Ledger};
use crate::segment::Position;
use crate::vessel::{ReadLog, SealAt, Vessel, VesselError};

pub use crate::ledger::{Publish, PublishError, Reconciled, Resolution, ResolveError};

#[cfg(test)]
pub(crate) use crate::ledger::AlwaysPublish;

/// Whether this Vessel may release effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Its effects are released: a sender may act on them.
    Dispatch,
    /// Its effects are held as proposals: only its parent may release
    /// them, by promotion.
    Hold,
}

impl Mode {
    /// The default by origin (D4): a fork holds, a Vessel born from the
    /// void or by succession dispatches.  A config entry may override
    /// it; an agent never can.
    pub fn of(origin: &Origin) -> Self {
        match origin {
            Origin::Fork { .. } => Mode::Hold,
            Origin::Void | Origin::Succession { .. } => Mode::Dispatch,
        }
    }
}

/// The answer to an effect request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Asked {
    /// Recorded and released: a sender may act on it.
    Released {
        /// Its op id, which the sender reports against.
        op: OpId,
    },
    /// Recorded and held: nothing may act on it until a parent promotes.
    Held {
        /// Its op id in this Chronicle.
        op: OpId,
    },
    /// Not recorded (or, after a failed ship, recorded as not applied).
    Refused {
        /// Why.
        reason: String,
    },
}

/// Why a sender's report was refused.
#[derive(Debug)]
pub enum ReportError {
    /// The op is not a released, unsettled effect of this Vessel.
    NotReleased(OpId),
    /// Recording it failed.
    Vessel(VesselError),
}

/// Why a promotion was refused or left unfinished.
#[derive(Debug)]
pub enum PromoteError {
    /// [`Vessel::promote`] refused it (not my fork, parent moved, Seal
    /// not proven) or recording failed; nothing was adopted.
    Vessel(VesselError),
    /// The Promotion is recorded but the ledger could not be shipped, so
    /// nothing was adopted yet.  Calling [`Effects::finish_promotion`]
    /// later finishes it.
    NotShipped(PublishError),
    /// Adopted and recorded (the promotion is done), but the adoption
    /// could not be shipped: its ops are not listed until a ship succeeds
    /// ([`Effects::ship_unlisted`]).
    AdoptionNotShipped {
        /// The Promotion, done.
        promotion: PromotionRecord,
        /// The adopted ops.
        adopted: Vec<Authorized>,
        /// Why the ship failed.
        error: PublishError,
    },
}

impl From<VesselError> for PromoteError {
    fn from(e: VesselError) -> Self {
        PromoteError::Vessel(e)
    }
}

/// What the local log says of one op ([`Effects::result`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpRecord {
    /// Its latest outcome state; `None`: an intent with no outcome yet.
    pub state: Option<OutcomeState>,
    /// That outcome's evidence (a receipt, a reason), if any.
    pub evidence: Option<Vec<u8>>,
}

/// A released, unsettled effect: what a sender reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Released {
    /// The intent, with the exact request bytes and the retry policy.
    pub intent: IntentRecord,
    /// `DispatchAuthorized` (never acted on, as far as the ledger knows)
    /// or `OutcomeUnknown` (acted on, outcome lost).
    pub state: OutcomeState,
}

/// The effect engine of one Vessel.
pub struct Effects {
    mode: Mode,
    ledger: Ledger,
    /// Released ops a sender may still report on, with their barrier:
    /// shipped, so listed.
    released: std::collections::BTreeMap<OpId, Option<taso_core::record::BarrierId>>,
    /// Released ops recorded but not yet known shipped: not listed until a
    /// ship succeeds.
    unlisted: std::collections::BTreeMap<OpId, Option<taso_core::record::BarrierId>>,
    /// Ops a listing ([`Effects::hand_out`]) has already given to a
    /// sender in this engine's life.  Not durable on purpose: after a
    /// Warden restart reconcile records them `OutcomeUnknown` anyway.
    handed_out: std::collections::BTreeSet<OpId>,
    pending: Option<PromotionRecord>,
}

impl Effects {
    /// Start the engine on an opened Vessel: reconcile its ledger (every
    /// released intent without a terminal outcome becomes an open
    /// obligation, recorded `OutcomeUnknown` if it was not already), then
    /// grant effect authority if nothing is open.  `publisher` ships the
    /// ledger before every release and promotion.
    pub fn open<L: Layers>(
        mode: Mode,
        publisher: Box<dyn Publish>,
        vessel: &mut Vessel<L>,
    ) -> Result<(Self, Reconciled), VesselError> {
        let (ledger, r) = Ledger::open(publisher, vessel, |l, v, i, s| l.mark_unknown(v, i.op, s))?;
        let summary = summary(vessel)?;
        let unlisted = summary
            .obligations()
            .filter(|e| unsettled(e.state))
            .map(|e| (e.intent.op, e.intent.barrier))
            .collect();
        let mut fx = Self {
            mode,
            ledger,
            released: Default::default(),
            unlisted,
            handed_out: Default::default(),
            pending: summary.promotion,
        };
        // Listed once a ship covers them (a failure leaves them unlisted
        // until one does: [`Effects::ship_unlisted`]).
        let _ = fx.ship_unlisted(vessel);
        Ok((fx, r))
    }

    /// Ship the ledger if any released op is unlisted, and list them.
    /// `Ok(false)`: nothing was unlisted.
    pub fn ship_unlisted<L: Layers>(&mut self, vessel: &Vessel<L>) -> Result<bool, PublishError> {
        if self.unlisted.is_empty() {
            return Ok(false);
        }
        self.ledger.ship(vessel)?;
        self.released.append(&mut self.unlisted);
        Ok(true)
    }

    /// Released ops not yet listed (their ship has not succeeded).
    pub fn unlisted(&self) -> Vec<OpId> {
        self.unlisted.keys().copied().collect()
    }

    /// Whether this Vessel releases or holds.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// True if effects may be released: no open obligation.
    pub fn authorized(&self) -> bool {
        self.ledger.authorized()
    }

    /// Open obligations.
    pub fn open_obligations(&self) -> Vec<OpId> {
        self.ledger.open_obligations()
    }

    /// A Promotion recorded whose adoption has not happened.
    pub fn pending_promotion(&self) -> Option<PromotionRecord> {
        self.pending
    }

    /// Answer one declared effect: released, held or refused.
    pub fn ask<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        d: &Declared,
    ) -> Result<Asked, VesselError> {
        if !self.ledger.authorized() {
            return Ok(Asked::Refused {
                reason: format!(
                    "no effect authority: {} unresolved effect(s)",
                    self.ledger.open_obligations().len()
                ),
            });
        }
        let _total = crate::timing::span("effect.total");
        match self.mode {
            Mode::Hold => {
                let a = self.ledger.propose(vessel, d)?;
                Ok(Asked::Held { op: a.op })
            }
            Mode::Dispatch => {
                let a = self.ledger.release(vessel, d)?;
                // The release goes off the node before anyone may act on it.
                match self.ledger.ship_before_send(vessel, &a)? {
                    Ok(()) => {
                        // The ship covered the whole log: anything
                        // unlisted is off the node too.
                        self.released.append(&mut self.unlisted);
                        self.released.insert(a.op, a.barrier);
                        Ok(Asked::Released { op: a.op })
                    }
                    Err(reason) => Ok(Asked::Refused { reason }),
                }
            }
        }
    }

    /// The released, unsettled effects whose records are shipped, in op
    /// order: what a sender reads and acts on.  Unlisted ones are not
    /// among them ([`Effects::ship_unlisted`]).
    pub fn released<L: Layers>(&self, vessel: &Vessel<L>) -> Result<Vec<Released>, VesselError> {
        Ok(summary(vessel)?
            .obligations()
            .filter(|e| unsettled(e.state) && self.released.contains_key(&e.intent.op))
            .map(|e| Released {
                intent: e.intent.clone(),
                state: e.state.expect("unsettled has a state"),
            })
            .collect())
    }

    /// What a sender reads ([`Effects::released`]), each with whether it
    /// may have been acted on already: `OutcomeUnknown` (reconciled after a
    /// restart), or handed out by an earlier listing of this engine — a
    /// sender that crashed while the Warden stayed up (review finding 3).
    /// Marks every listed op as handed out.
    pub fn hand_out<L: Layers>(
        &mut self,
        vessel: &Vessel<L>,
    ) -> Result<Vec<(Released, bool)>, VesselError> {
        let listed = self.released(vessel)?;
        Ok(listed
            .into_iter()
            .map(|r| {
                let before =
                    r.state == OutcomeState::OutcomeUnknown || !self.handed_out.insert(r.intent.op);
                (r, before)
            })
            .collect())
    }

    /// What became of `op`, as this Vessel's local log says: its latest
    /// outcome state and evidence (`None` state: an intent with no outcome
    /// yet), or `None` if the op is not in the local log (never declared
    /// here, or settled and pruned behind a Checkpoint).  Read-only: what
    /// an agent asks about its own effect (C5), never a listing.
    pub fn result<L: Layers>(
        &self,
        vessel: &Vessel<L>,
        op: OpId,
    ) -> Result<Option<OpRecord>, VesselError> {
        let frames = vessel
            .chronicle()
            .frames()
            .map_err(|e| VesselError::Chronicle(crate::chronicle::ChronicleError::Segment(e)))?;
        let mut found = None;
        for f in &frames {
            if f.envelope.stream != taso_core::envelope::Stream::Effect {
                continue;
            }
            let p = taso_core::record::Payload::decode(&f.payload).map_err(|error| {
                VesselError::Decode {
                    lsn: f.envelope.lsn,
                    error,
                }
            })?;
            match p {
                taso_core::record::Payload::Intent(i) if i.op == op => {
                    found = Some(OpRecord {
                        state: None,
                        evidence: None,
                    })
                }
                taso_core::record::Payload::Outcome(o) if o.op == op && found.is_some() => {
                    found = Some(OpRecord {
                        state: Some(o.state),
                        evidence: o.evidence,
                    })
                }
                _ => {}
            }
        }
        // A Checkpoint carries the ops still open: one of those whose
        // intent was pruned is still known, as open.
        if found.is_none() {
            let s = summary(vessel)?;
            if let Some(e) = s.open.get(&op) {
                found = Some(OpRecord {
                    state: e.state,
                    evidence: None,
                });
            }
        }
        Ok(found)
    }

    /// The sender's report on a released effect.  Refused for an op that
    /// is not released and unsettled.
    pub fn report<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        op: OpId,
        answer: &Answer,
    ) -> Result<(), ReportError> {
        let Some(&barrier) = self.released.get(&op) else {
            return Err(ReportError::NotReleased(op));
        };
        let _t = crate::timing::span("effect.outcome");
        self.ledger
            .record(vessel, op, barrier, answer)
            .map_err(ReportError::Vessel)?;
        if *answer != Answer::Unknown {
            self.released.remove(&op);
        }
        Ok(())
    }

    /// Operator resolution of an open effect: record what really happened.
    /// Refused without an actor and a reason, or for an effect that is not
    /// open.
    pub fn resolve<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        op: OpId,
        resolution: Resolution,
        authority: Authority,
    ) -> Result<(), ResolveError> {
        self.ledger.resolve(vessel, op, resolution, authority)?;
        self.released.remove(&op);
        self.unlisted.remove(&op);
        Ok(())
    }

    /// Promote a fork: record the Promotion ([`Vessel::promote`]), ship
    /// the ledger, adopt every proposal it names in one batch.  Returns
    /// the Promotion and the adopted ops.
    pub fn promote<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        child: &ReadLog,
        at: SealAt,
    ) -> Result<(PromotionRecord, Vec<Authorized>), PromoteError> {
        let _total = crate::timing::span("promote.total");
        let t = crate::timing::span("promote.record");
        let (record, _) = vessel.promote(child, at)?;
        drop(t);
        self.pending = Some(record);
        let adopted = self.finish_promotion(vessel, child)?;
        Ok((record, adopted))
    }

    /// Finish a promotion whose adoption did not happen (a crash after the
    /// Promotion was recorded, or a ship that failed): ship the ledger,
    /// then adopt the proposals the pending Promotion names, in one
    /// batch.  Nothing to do if no promotion is pending.  `child` is the
    /// log the Promotion names, read again.
    pub fn finish_promotion<L: Layers>(
        &mut self,
        vessel: &mut Vessel<L>,
        child: &ReadLog,
    ) -> Result<Vec<Authorized>, PromoteError> {
        let Some(p) = self.pending else {
            return Ok(Vec::new());
        };
        if child.chronicle != p.child {
            return Err(PromoteError::Vessel(VesselError::NotMyFork(
                child.chronicle,
            )));
        }
        // The Promotion goes off the node before anything is adopted from
        // it: an adoption only this node knew of could not be reconciled
        // by whoever takes the Vessel over.
        let t = crate::timing::span("promote.ship_promotion");
        self.ledger.ship(vessel).map_err(PromoteError::NotShipped)?;
        drop(t);
        let seal = Position {
            lsn: p.seal,
            hash: p.seal_hash,
        };
        // The Seal must still be the one promoted: proven again from the
        // child's log as it is now.
        let (proven, ledger_pos) = child.prove(SealAt::At(seal.lsn))?;
        if proven != seal || ledger_pos != p.ledger_pos {
            return Err(PromoteError::Vessel(VesselError::NotASeal(seal)));
        }
        let proposals: Vec<IntentRecord> = child
            .proposals(ledger_pos)?
            .into_iter()
            .map(|e| e.intent)
            .collect();
        let held = self.mode == Mode::Hold;
        let adopted = self
            .ledger
            .adopt(vessel, p.child, p.seal, &proposals, held)?;
        // Recorded: the promotion is done (the summary agrees).
        self.pending = None;
        if held {
            // Proposals again: nothing a sender sees, nothing to list.
            return Ok(adopted);
        }
        // Listed only once shipped: a rebirth must know of anything a
        // sender may act on.
        for a in &adopted {
            self.unlisted.insert(a.op, a.barrier);
        }
        let t = crate::timing::span("promote.ship_adoption");
        let shipped = self.ship_unlisted(vessel);
        drop(t);
        match shipped {
            Ok(_) => Ok(adopted),
            Err(error) => Err(PromoteError::AdoptionNotShipped {
                promotion: p,
                adopted,
                error,
            }),
        }
    }
}

fn unsettled(state: Option<OutcomeState>) -> bool {
    matches!(
        state,
        Some(OutcomeState::DispatchAuthorized | OutcomeState::OutcomeUnknown)
    )
}

fn summary<L: Layers>(vessel: &Vessel<L>) -> Result<crate::summary::Summary, VesselError> {
    let frames = vessel
        .chronicle()
        .frames()
        .map_err(|e| VesselError::Chronicle(crate::chronicle::ChronicleError::Segment(e)))?;
    crate::summary::Summary::of(&frames).map_err(|(lsn, error)| VesselError::Decode { lsn, error })
}

/// The highest ledger lsn, for a Seal's `ledger_pos`.
pub fn ledger_pos<L: Layers>(vessel: &Vessel<L>) -> Result<Lsn, VesselError> {
    Ok(summary(vessel)?.effect)
}

// ── Tests ───────────────────────────────────────────────────────────
//
// The engine with no sender: what the store promises whoever sends, and
// the no-trace property of forks.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::Segment;
    use crate::vessel::tests::{env, ns, Env, FakeLayers};
    use std::cell::Cell;
    use std::rc::Rc;
    use taso_core::canon::Canonical;
    use taso_core::envelope::{ChronicleId, Epoch, Stream};
    use taso_core::record::{
        BarrierId, Consequence, Dispatch, Payload, RetryPolicy, StreamCut, TurnId, Verdict,
    };

    /// A publisher that counts, and fails the next `fails` times.
    struct Counting {
        published: Rc<Cell<u32>>,
        fails: Rc<Cell<u32>>,
    }

    impl Publish for Counting {
        fn publish(
            &mut self,
            _: ChronicleId,
            _: Epoch,
            _: &[&Segment],
            _: Position,
        ) -> Result<(), PublishError> {
            if self.fails.get() > 0 {
                self.fails.set(self.fails.get() - 1);
                return Err(PublishError("store unavailable".into()));
            }
            self.published.set(self.published.get() + 1);
            Ok(())
        }
    }

    fn counting(published: &Rc<Cell<u32>>, fails: &Rc<Cell<u32>>) -> Box<dyn Publish> {
        Box::new(Counting {
            published: published.clone(),
            fails: fails.clone(),
        })
    }

    fn vessel(e: &Env) -> Vessel<FakeLayers> {
        e.host.ensure(ns(1), b"u").unwrap().0
    }

    fn declared(request: &str, consequence: Consequence) -> Declared {
        Declared {
            provider: "pay".into(),
            request: request.as_bytes().to_vec(),
            footprint: Vec::new(),
            dispatch: Dispatch::Immediate,
            retry: RetryPolicy::ProviderDeduplicated {
                key: request.as_bytes().to_vec(),
            },
            consequence,
            authority: b"user".to_vec(),
        }
    }

    fn pay(k: &str) -> Declared {
        declared(k, Consequence::Irreversible)
    }

    /// Effect records, decoded, in order.
    fn ledger(v: &Vessel<FakeLayers>) -> Vec<Payload> {
        v.chronicle()
            .frames()
            .unwrap()
            .iter()
            .filter(|f| f.envelope.stream == Stream::Effect)
            .map(|f| Payload::decode(&f.payload).unwrap())
            .collect()
    }

    fn states(v: &Vessel<FakeLayers>) -> Vec<(u64, OutcomeState)> {
        ledger(v)
            .into_iter()
            .filter_map(|p| match p {
                Payload::Outcome(o) => Some((o.op.get(), o.state)),
                _ => None,
            })
            .collect()
    }

    fn intents(v: &Vessel<FakeLayers>) -> Vec<IntentRecord> {
        ledger(v)
            .into_iter()
            .filter_map(|p| match p {
                Payload::Intent(i) => Some(i),
                _ => None,
            })
            .collect()
    }

    fn open_dispatch(v: &mut Vessel<FakeLayers>) -> (Effects, Reconciled) {
        Effects::open(Mode::Dispatch, Box::new(AlwaysPublish), v).unwrap()
    }

    fn auth() -> Authority {
        Authority {
            actor: "jarmo".into(),
            reason: "checked the provider by hand".into(),
        }
    }

    // ── asking and reporting ────────────────────────────────────────

    #[test]
    fn a_release_is_recorded_and_shipped_before_it_is_answered() {
        let e = env();
        let mut v = vessel(&e);
        let published = Rc::new(Cell::new(0));
        let fails = Rc::new(Cell::new(0));
        let (mut fx, r) =
            Effects::open(Mode::Dispatch, counting(&published, &fails), &mut v).unwrap();
        assert_eq!(r, Reconciled::default());
        let intent_lsn = v.tail().lsn.next();
        assert_eq!(
            fx.ask(&mut v, &pay("pay 1")).unwrap(),
            Asked::Released { op: OpId::new(1) }
        );
        assert_eq!(published.get(), 1, "shipped before the answer");
        let [i] = &intents(&v)[..] else { panic!() };
        assert_eq!(i.request, b"pay 1");
        assert_eq!(i.barrier, Some(BarrierId::new(intent_lsn.get())));
        assert_eq!(states(&v), vec![(1, OutcomeState::DispatchAuthorized)]);
        assert_eq!(
            fx.released(&v).unwrap(),
            vec![Released {
                intent: i.clone(),
                state: OutcomeState::DispatchAuthorized
            }]
        );
        assert!(
            fx.authorized(),
            "released is not an obligation until unknown"
        );

        // The sender reports.
        fx.report(
            &mut v,
            OpId::new(1),
            &Answer::Applied {
                receipt: b"ok".to_vec(),
            },
        )
        .unwrap();
        assert_eq!(
            states(&v).last(),
            Some(&(1, OutcomeState::ConfirmedApplied))
        );
        assert!(fx.released(&v).unwrap().is_empty());
        assert!(matches!(
            fx.report(&mut v, OpId::new(1), &Answer::Unknown),
            Err(ReportError::NotReleased(_))
        ));
        assert!(matches!(
            fx.report(&mut v, OpId::new(9), &Answer::Unknown),
            Err(ReportError::NotReleased(_))
        ));
    }

    #[test]
    fn a_failed_ship_withdraws_the_release_and_refuses() {
        let e = env();
        let mut v = vessel(&e);
        let published = Rc::new(Cell::new(0));
        let fails = Rc::new(Cell::new(1));
        let (mut fx, _) =
            Effects::open(Mode::Dispatch, counting(&published, &fails), &mut v).unwrap();
        assert!(matches!(
            fx.ask(&mut v, &pay("pay 1")).unwrap(),
            Asked::Refused { reason } if reason.contains("not shipped")
        ));
        assert_eq!(
            states(&v),
            vec![
                (1, OutcomeState::DispatchAuthorized),
                (1, OutcomeState::ConfirmedNotApplied)
            ]
        );
        assert!(
            fx.released(&v).unwrap().is_empty(),
            "nothing a sender may act on"
        );
        assert!(fx.authorized());
        assert_eq!(
            fx.ask(&mut v, &pay("pay 2")).unwrap(),
            Asked::Released { op: OpId::new(2) }
        );
    }

    #[test]
    fn an_unknown_report_withdraws_authority_until_an_operator_resolves() {
        let e = env();
        let mut v = vessel(&e);
        let (mut fx, _) = open_dispatch(&mut v);
        fx.ask(&mut v, &pay("pay 1")).unwrap();
        fx.report(&mut v, OpId::new(1), &Answer::Unknown).unwrap();
        assert!(!fx.authorized());
        assert_eq!(fx.open_obligations(), vec![OpId::new(1)]);
        assert!(matches!(
            fx.ask(&mut v, &pay("pay 2")).unwrap(),
            Asked::Refused { reason } if reason.contains("no effect authority")
        ));
        // Still released: the sender may yet find out and report.
        assert_eq!(
            fx.released(&v).unwrap()[0].state,
            OutcomeState::OutcomeUnknown
        );
        fx.report(
            &mut v,
            OpId::new(1),
            &Answer::NotApplied {
                reason: "provider says never seen".into(),
            },
        )
        .unwrap();
        assert!(fx.authorized());

        // Or an operator does.
        fx.ask(&mut v, &pay("pay 3")).unwrap();
        fx.report(&mut v, OpId::new(2), &Answer::Unknown).unwrap();
        assert!(!fx.authorized());
        fx.resolve(&mut v, OpId::new(2), Resolution::Applied, auth())
            .unwrap();
        assert!(fx.authorized());
        assert!(fx.released(&v).unwrap().is_empty());
    }

    #[test]
    fn no_external_mutation_is_released_without_a_barrier() {
        let e = env();
        let mut v = vessel(&e);
        let (mut fx, _) = open_dispatch(&mut v);
        fx.ask(&mut v, &declared("read", Consequence::NoExternalMutation))
            .unwrap();
        assert_eq!(intents(&v)[0].barrier, None);
        fx.report(&mut v, OpId::new(1), &Answer::Unknown).unwrap();
        assert!(fx.authorized(), "no barrier, no obligation");
    }

    // ── reopening ───────────────────────────────────────────────────

    /// Released, then the Warden died before any report: on reopen the
    /// effect is an open obligation recorded unknown, nothing is settled
    /// for it, and the sender's report still settles it.
    #[test]
    fn a_released_effect_without_a_report_is_an_obligation_after_a_crash() {
        let e = env();
        let mut v = vessel(&e);
        let (mut fx, _) = open_dispatch(&mut v);
        fx.ask(&mut v, &pay("pay 1")).unwrap();
        drop((fx, v));

        let mut v = vessel(&e);
        let (mut fx, r) = open_dispatch(&mut v);
        assert_eq!(r.settled, vec![]);
        assert_eq!(r.open, vec![OpId::new(1)]);
        assert!(!fx.authorized());
        assert_eq!(
            states(&v),
            vec![
                (1, OutcomeState::DispatchAuthorized),
                (1, OutcomeState::OutcomeUnknown)
            ],
            "the truth after a crash: unknown"
        );
        let [r] = &fx.released(&v).unwrap()[..] else {
            panic!()
        };
        assert_eq!(r.intent.request, b"pay 1");
        fx.report(
            &mut v,
            OpId::new(1),
            &Answer::Applied {
                receipt: b"k".to_vec(),
            },
        )
        .unwrap();
        assert!(fx.authorized());
        // Op ids continue.
        assert_eq!(
            fx.ask(&mut v, &pay("pay 2")).unwrap(),
            Asked::Released { op: OpId::new(2) }
        );
    }

    /// P4 spec D34: an unknown effect closed by an operator as
    /// `AcceptedUnknown` is no longer listed to the sender, a late report
    /// for it is refused, and a reopen neither lists nor settles it.
    #[test]
    fn accepted_unknown_is_closed_for_the_sender_and_for_reopen() {
        let e = env();
        let mut v = vessel(&e);
        let (mut fx, _) = open_dispatch(&mut v);
        fx.ask(&mut v, &pay("pay 1")).unwrap();
        fx.report(&mut v, OpId::new(1), &Answer::Unknown).unwrap();
        assert!(!fx.authorized());
        fx.resolve(&mut v, OpId::new(1), Resolution::AcceptedUnknown, auth())
            .unwrap();
        assert!(fx.authorized());
        assert!(fx.released(&v).unwrap().is_empty());
        assert!(matches!(
            fx.report(&mut v, OpId::new(1), &Answer::Unknown),
            Err(ReportError::NotReleased(_))
        ));
        assert_eq!(
            fx.result(&v, OpId::new(1)).unwrap().map(|r| r.state),
            Some(Some(OutcomeState::AcceptedUnknown))
        );
        drop((fx, v));
        let mut v = vessel(&e);
        let (fx, r) = open_dispatch(&mut v);
        assert_eq!(r, Reconciled::default());
        assert!(fx.authorized());
        assert!(fx.released(&v).unwrap().is_empty());
    }

    #[test]
    fn a_crash_after_the_intent_alone_never_happened() {
        let e = env();
        let mut v = vessel(&e);
        let (mut fx, _) = open_dispatch(&mut v);
        fx.ledger
            .append_intent_alone(&mut v, &pay("pay 1"))
            .unwrap();
        drop((fx, v));
        let mut v = vessel(&e);
        let (fx, r) = open_dispatch(&mut v);
        assert_eq!(r.settled, vec![OpId::new(1)]);
        assert!(fx.authorized());
        assert_eq!(states(&v), vec![(1, OutcomeState::ConfirmedNotApplied)]);
    }

    // ── holding and promotion: the no-trace property ────────────────

    /// A fork of `parent`'s last Seal, with `n` held proposals, sealed.
    fn child(e: &Env, parent: &Vessel<FakeLayers>, subject: &[u8], n: u64) -> ChronicleId {
        let mut c = e
            .host
            .fork_from_log(parent.id(), SealAt::Last, subject)
            .unwrap();
        c.seal_birth().unwrap();
        let (mut fx, _) = Effects::open(Mode::Hold, Box::new(AlwaysPublish), &mut c).unwrap();
        for k in 1..=n {
            let name = String::from_utf8_lossy(subject).to_string();
            assert_eq!(
                fx.ask(&mut c, &pay(&format!("{name}: pay {k}"))).unwrap(),
                Asked::Held { op: OpId::new(k) }
            );
        }
        assert!(
            fx.released(&c).unwrap().is_empty(),
            "a holder releases nothing"
        );
        assert!(fx.authorized());
        let pos = ledger_pos(&c).unwrap();
        c.seal(StreamCut::EMPTY, Verdict::Clean, pos, TurnId::new(1))
            .unwrap();
        c.id()
    }

    /// N children fork, each proposes; one is promoted: the parent's
    /// released set is exactly that child's proposals, and the other
    /// children's Chronicles hold only `Proposed`.  Reopening every
    /// Chronicle changes nothing.
    #[test]
    fn only_the_promoted_childs_proposals_are_released() {
        let e = env();
        let mut p = vessel(&e);
        p.append(Stream::Fs, Payload::Raw(vec![1])).unwrap();
        p.seal(
            StreamCut::EMPTY,
            Verdict::Clean,
            Lsn::new(0),
            TurnId::new(1),
        )
        .unwrap();
        let kids: Vec<ChronicleId> = (1..=3u64)
            .map(|k| child(&e, &p, format!("c{k}").as_bytes(), k))
            .collect();

        let published = Rc::new(Cell::new(0));
        let fails = Rc::new(Cell::new(0));
        let (mut fx, _) =
            Effects::open(Mode::Dispatch, counting(&published, &fails), &mut p).unwrap();
        let chosen = kids[1];
        let log = e.host.read_log_of(chosen).unwrap();
        let (record, adopted) = fx.promote(&mut p, &log, SealAt::Last).unwrap();
        assert_eq!(record.child, chosen);
        assert_eq!(adopted.len(), 2);
        assert_eq!(
            published.get(),
            2,
            "the Promotion shipped before the adoption, the adoption before it is listed"
        );
        assert_eq!(fx.pending_promotion(), None);

        let released = fx.released(&p).unwrap();
        let requests: Vec<&[u8]> = released
            .iter()
            .map(|r| r.intent.request.as_slice())
            .collect();
        assert_eq!(requests, [&b"c2: pay 1"[..], &b"c2: pay 2"[..]]);
        for (r, k) in released.iter().zip(1u64..) {
            assert_eq!(
                r.intent.authority,
                crate::ledger::AdoptedFrom {
                    child: chosen,
                    seal: record.seal,
                    op: OpId::new(k)
                }
                .canon_bytes()
            );
            assert_eq!(r.state, OutcomeState::DispatchAuthorized);
        }
        // The adopted intents are this Vessel's: new op ids after the
        // parent's own, each with its own barrier.
        assert_eq!(adopted[0].op, OpId::new(1));
        assert!(adopted.iter().all(|a| a.barrier.is_some()));

        // The siblings: only Proposed, nothing released, nothing changed.
        for (i, k) in kids.iter().enumerate() {
            let (mut c, _) = e.host.open(*k).unwrap();
            let (cfx, r) = Effects::open(Mode::Hold, Box::new(AlwaysPublish), &mut c).unwrap();
            assert_eq!(r, Reconciled::default());
            assert!(cfx.released(&c).unwrap().is_empty());
            let s = states(&c);
            assert_eq!(s.len(), i + 1);
            assert!(s.iter().all(|(_, st)| *st == OutcomeState::Proposed));
        }
        // Nothing of the siblings is in the parent.
        assert!(intents(&p).iter().all(|i| i.request.starts_with(b"c2: ")));
        // The parent, reopened: the same released set, no pending promotion.
        drop((fx, p));
        let mut p = vessel(&e);
        let (fx, _) = open_dispatch(&mut p);
        assert_eq!(fx.pending_promotion(), None);
        assert_eq!(fx.released(&p).unwrap().len(), 2);
    }

    /// A crash after the Promotion, before the adoption: on reopen the
    /// Promotion is pending, nothing is released, and finishing adopts
    /// everything at once.  A second finish adopts nothing more.
    #[test]
    fn a_promotion_cut_before_its_adoption_is_finished_on_reopen() {
        let e = env();
        let mut p = vessel(&e);
        p.seal(
            StreamCut::EMPTY,
            Verdict::Clean,
            Lsn::new(0),
            TurnId::new(1),
        )
        .unwrap();
        let c = child(&e, &p, b"c", 3);
        let log = e.host.read_log_of(c).unwrap();
        // The crash: the Promotion is recorded, the ship fails, nothing
        // adopted.
        let published = Rc::new(Cell::new(0));
        let fails = Rc::new(Cell::new(1));
        let (mut fx, _) =
            Effects::open(Mode::Dispatch, counting(&published, &fails), &mut p).unwrap();
        assert!(matches!(
            fx.promote(&mut p, &log, SealAt::Last),
            Err(PromoteError::NotShipped(_))
        ));
        assert!(intents(&p).is_empty(), "nothing adopted");
        assert!(fx.pending_promotion().is_some());
        drop((fx, p));

        let mut p = vessel(&e);
        let (mut fx, _) = open_dispatch(&mut p);
        let pending = fx.pending_promotion().expect("the Promotion survived");
        assert_eq!(pending.child, c);
        assert!(fx.released(&p).unwrap().is_empty());
        let adopted = fx.finish_promotion(&mut p, &log).unwrap();
        assert_eq!(adopted.len(), 3);
        assert_eq!(fx.pending_promotion(), None);
        assert_eq!(fx.released(&p).unwrap().len(), 3);
        assert!(fx.finish_promotion(&mut p, &log).unwrap().is_empty());
        // Reopened: nothing pending, still three, not six.
        drop((fx, p));
        let mut p = vessel(&e);
        let (fx, _) = open_dispatch(&mut p);
        assert_eq!(fx.pending_promotion(), None);
        assert_eq!(fx.released(&p).unwrap().len(), 3);
        assert_eq!(intents(&p).len(), 3);
    }

    /// The adoption's ship fails: the promotion is done (recorded, nothing
    /// pending, never adopted twice), but nothing is listed until a ship
    /// succeeds — also across a reopen while the store is still down.
    #[test]
    fn an_adoption_is_listed_only_once_shipped() {
        let e = env();
        let mut p = vessel(&e);
        p.seal(
            StreamCut::EMPTY,
            Verdict::Clean,
            Lsn::new(0),
            TurnId::new(1),
        )
        .unwrap();
        let c = child(&e, &p, b"c", 2);
        let log = e.host.read_log_of(c).unwrap();
        // The Promotion's ship (call 1) succeeds, the adoption's (call 2)
        // fails.
        let (mut fx, _) = Effects::open(
            Mode::Dispatch,
            Box::new(FailsAt {
                calls: Rc::new(Cell::new(0)),
                at: 2,
            }),
            &mut p,
        )
        .unwrap();
        let fx_promote = fx.promote(&mut p, &log, SealAt::Last).unwrap_err();
        let PromoteError::AdoptionNotShipped { adopted, .. } = fx_promote else {
            panic!("{fx_promote:?}")
        };
        assert_eq!(adopted.len(), 2);
        assert_eq!(fx.pending_promotion(), None, "the promotion is done");
        assert_eq!(intents(&p).len(), 2, "recorded");
        assert!(fx.released(&p).unwrap().is_empty(), "not listed");
        assert_eq!(fx.unlisted().len(), 2);
        // A sender cannot report on what it was never shown.
        assert!(matches!(
            fx.report(&mut p, adopted[0].op, &Answer::Unknown),
            Err(ReportError::NotReleased(_))
        ));

        // Reopened while the store is still down: still unlisted.
        drop(fx);
        let published = Rc::new(Cell::new(0));
        let fails = Rc::new(Cell::new(1));
        let (mut fx, _) =
            Effects::open(Mode::Dispatch, counting(&published, &fails), &mut p).unwrap();
        assert_eq!(fx.pending_promotion(), None);
        assert!(fx.released(&p).unwrap().is_empty());
        assert_eq!(fx.unlisted().len(), 2);
        // The store is back: listed, and adopted once.
        assert!(fx.ship_unlisted(&p).unwrap());
        assert!(fx.unlisted().is_empty());
        assert_eq!(fx.released(&p).unwrap().len(), 2);
        assert!(!fx.ship_unlisted(&p).unwrap(), "nothing left to ship");
        assert_eq!(intents(&p).len(), 2, "never adopted twice");
    }

    /// A publisher whose `at`-th call fails, every other succeeds.
    struct FailsAt {
        calls: Rc<Cell<u32>>,
        at: u32,
    }

    impl Publish for FailsAt {
        fn publish(
            &mut self,
            _: ChronicleId,
            _: Epoch,
            _: &[&Segment],
            _: Position,
        ) -> Result<(), PublishError> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() == self.at {
                return Err(PublishError("store unavailable".into()));
            }
            Ok(())
        }
    }

    /// A holder that promotes its own fork adopts the grandchild's
    /// proposals as proposals again: they travel up, never out.
    #[test]
    fn a_holder_adopts_as_held() {
        let e = env();
        let mut p = vessel(&e);
        p.seal(
            StreamCut::EMPTY,
            Verdict::Clean,
            Lsn::new(0),
            TurnId::new(1),
        )
        .unwrap();
        let mid = child(&e, &p, b"mid", 0);
        let (mut m, _) = e.host.open(mid).unwrap();
        let grand = child(&e, &m, b"grand", 2);
        let (mut mfx, _) = Effects::open(Mode::Hold, Box::new(AlwaysPublish), &mut m).unwrap();
        let log = e.host.read_log_of(grand).unwrap();
        let (_, adopted) = mfx.promote(&mut m, &log, SealAt::Last).unwrap();
        assert_eq!(adopted.len(), 2);
        assert!(mfx.released(&m).unwrap().is_empty());
        assert!(states(&m).iter().all(|(_, s)| *s == OutcomeState::Proposed));
        assert!(mfx.authorized());
    }

    #[test]
    fn a_promotion_refused_adopts_nothing() {
        let e = env();
        let mut p = vessel(&e);
        p.seal(
            StreamCut::EMPTY,
            Verdict::Clean,
            Lsn::new(0),
            TurnId::new(1),
        )
        .unwrap();
        let c = child(&e, &p, b"c", 1);
        // The parent moves on.
        p.append(Stream::Fs, Payload::Raw(vec![1])).unwrap();
        p.seal(
            StreamCut::EMPTY,
            Verdict::Clean,
            Lsn::new(0),
            TurnId::new(2),
        )
        .unwrap();
        let (mut fx, _) = open_dispatch(&mut p);
        let log = e.host.read_log_of(c).unwrap();
        assert!(matches!(
            fx.promote(&mut p, &log, SealAt::Last),
            Err(PromoteError::Vessel(VesselError::ParentMoved { .. }))
        ));
        assert!(intents(&p).is_empty());
        assert_eq!(fx.pending_promotion(), None);
    }

    #[test]
    fn mode_by_origin() {
        assert_eq!(Mode::of(&Origin::Void), Mode::Dispatch);
        let ps = taso_core::record::ParentSeal {
            chronicle: ChronicleId::from_bytes([1; 16]),
            seal: Lsn::new(1),
            seal_hash: taso_core::envelope::HashVal::GENESIS,
        };
        assert_eq!(Mode::of(&Origin::Fork { parent: ps }), Mode::Hold);
        assert_eq!(
            Mode::of(&Origin::Succession {
                parent: ps,
                authority: auth()
            }),
            Mode::Dispatch
        );
    }
}
