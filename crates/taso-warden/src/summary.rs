//! What the readers of a Chronicle need from its records, in one fold
//! (decision 1, 2026-10-16).
//!
//! Six readers used to scan the whole local log from lsn 1: Vessel open
//! (the Lineage), Chronicle open (the Seals), effect reconciliation (open
//! intents), the Field session (the Seal cut and the last sealed turn),
//! fork and succession (a Seal's `ledger_pos`, open obligations) and the
//! packs (the newest FsShipped record).  [`Summary`] is everything they
//! need, folded record by record.  A [`CheckpointRecord`] is a Summary
//! written into the log; [`Summary::of`] starts from the newest Checkpoint
//! it finds and folds only the records after it.  So the records before a
//! Checkpoint can leave the node ([`crate::chronicle::Chronicle::prune`])
//! and every reader still gets the same answer.  The property test below
//! holds that: folding a whole log equals folding from any Checkpoint
//! written into it.

use std::collections::BTreeMap;

use taso_core::canon::Canonical;
use taso_core::decode::DecodeError;
use taso_core::envelope::{Lsn, Stream};
use taso_core::record::{
    CheckpointRecord, CheckpointSeal, FsShippedRecord, LineageRecord, OpId, OpenEffect,
    OutcomeState, Payload, PromotionRecord, SuccessionRecord,
};

use crate::segment::Frame;

/// The fold of a Chronicle's records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// The Lineage record (lsn 1, or from a Checkpoint).
    pub lineage: Option<LineageRecord>,
    /// The Succession record, if the Chronicle ended with one.
    pub successor: Option<SuccessionRecord>,
    /// The last Transcript record's lsn.
    pub transcript: Lsn,
    /// The last Effect record's lsn.
    pub effect: Lsn,
    /// The last Seal record.
    pub seal: Option<CheckpointSeal>,
    /// The last FsShipped record.
    pub fs_shipped: Option<FsShippedRecord>,
    /// Effects whose latest outcome is not terminal, by op: the
    /// obligations ([`Summary::obligations`]) and, in a Vessel that may
    /// not release effects, the held proposals ([`Summary::proposals`]),
    /// which stay here so a prune never loses what a parent may adopt.
    pub open: BTreeMap<OpId, OpenEffect>,
    /// The next unused op id.
    pub next_op: u64,
    /// The last Promotion record whose adoption has not happened yet:
    /// cleared by the first intent adopted from it; carried by the
    /// Checkpoint in between.
    pub promotion: Option<PromotionRecord>,
    /// The lsn of the Checkpoint the fold started from, if any.
    pub from_checkpoint: Option<Lsn>,
}

impl Default for Summary {
    fn default() -> Self {
        Self {
            lineage: None,
            successor: None,
            transcript: Lsn::new(0),
            effect: Lsn::new(0),
            seal: None,
            fs_shipped: None,
            open: BTreeMap::new(),
            next_op: 0,
            promotion: None,
            from_checkpoint: None,
        }
    }
}

/// Settled for good: nothing will ever be done about it.  `Proposed` is
/// not here: it is terminal for the Vessel that wrote it, but its parent
/// may still adopt it, so it stays in `open` (as a proposal, never an
/// obligation).
fn terminal(s: OutcomeState) -> bool {
    matches!(
        s,
        OutcomeState::ConfirmedApplied | OutcomeState::ConfirmedNotApplied
    )
}

fn proposed(e: &OpenEffect) -> bool {
    e.state == Some(OutcomeState::Proposed)
}

impl Summary {
    /// The fold of `frames` (in lsn order): from the newest Checkpoint
    /// among them, or from the first frame if there is none.
    pub fn of(frames: &[Frame]) -> Result<Self, (Lsn, DecodeError)> {
        let start = frames
            .iter()
            .rposition(|f| {
                f.envelope.stream == Stream::Ctl
                    && matches!(Payload::decode(&f.payload), Ok(Payload::Checkpoint(_)))
            })
            .unwrap_or(0);
        let mut s = Summary::default();
        for f in &frames[start..] {
            s.apply(f)?;
        }
        Ok(s)
    }

    /// Fold one more record in.
    pub fn apply(&mut self, f: &Frame) -> Result<(), (Lsn, DecodeError)> {
        let lsn = f.envelope.lsn;
        let decode = || Payload::decode(&f.payload).map_err(|e| (lsn, e));
        match f.envelope.stream {
            Stream::Transcript => self.transcript = lsn,
            Stream::Effect => {
                self.effect = lsn;
                match decode()? {
                    Payload::Intent(intent) => {
                        self.next_op = self.next_op.max(intent.op.get().saturating_add(1));
                        // The adoption that finishes the pending promotion:
                        // an intent whose authority names its child and
                        // Seal (the first 24 bytes of an `AdoptedFrom`).
                        if let Some(p) = self.promotion {
                            let mut from = taso_core::canon::Canon::default();
                            p.child.canon(&mut from);
                            p.seal.canon(&mut from);
                            if intent.authority.starts_with(from.as_bytes()) {
                                self.promotion = None;
                            }
                        }
                        self.open.insert(
                            intent.op,
                            OpenEffect {
                                lsn,
                                intent,
                                state: None,
                            },
                        );
                    }
                    Payload::Outcome(o) if terminal(o.state) => {
                        self.open.remove(&o.op);
                    }
                    Payload::Outcome(o) => {
                        if let Some(e) = self.open.get_mut(&o.op) {
                            e.state = Some(o.state);
                        }
                    }
                    _ => {}
                }
            }
            Stream::Ctl => match decode()? {
                Payload::Lineage(l) => {
                    if self.lineage.is_none() {
                        self.lineage = Some(l);
                    }
                }
                Payload::Succession(s) => self.successor = Some(s),
                Payload::Seal(s) => {
                    self.seal = Some(CheckpointSeal {
                        lsn,
                        hash: f.envelope.hash,
                        turn: s.turn,
                        ledger_pos: s.ledger_pos,
                    })
                }
                Payload::FsShipped(r) => self.fs_shipped = Some(r),
                Payload::Promotion(p) => self.promotion = Some(p),
                Payload::Checkpoint(c) => {
                    *self = Summary {
                        lineage: Some(c.lineage),
                        successor: None,
                        transcript: c.transcript,
                        effect: c.effect,
                        seal: c.seal,
                        fs_shipped: c.fs_shipped,
                        open: c.open.into_iter().map(|e| (e.intent.op, e)).collect(),
                        next_op: c.next_op,
                        promotion: c.promotion,
                        from_checkpoint: Some(lsn),
                    }
                }
                _ => {}
            },
            Stream::Fs | Stream::Db => {}
        }
        Ok(())
    }

    /// This summary as a Checkpoint record; `None` without a Lineage.
    pub fn checkpoint(&self) -> Option<CheckpointRecord> {
        Some(CheckpointRecord {
            lineage: self.lineage.clone()?,
            transcript: self.transcript,
            effect: self.effect,
            seal: self.seal.clone(),
            fs_shipped: self.fs_shipped.clone(),
            open: self.open.values().cloned().collect(),
            next_op: self.next_op,
            promotion: self.promotion,
        })
    }

    /// The open effects somebody must still settle: released (or never
    /// authorized) intents whose outcome is not terminal.  What effect
    /// authority and reconciliation look at.
    pub fn obligations(&self) -> impl Iterator<Item = &OpenEffect> {
        self.open.values().filter(|e| !proposed(e))
    }

    /// The held proposals, in op order: what a parent adopts on
    /// promotion.  Never an obligation of the Vessel that holds them.
    pub fn proposals(&self) -> impl Iterator<Item = &OpenEffect> {
        self.open.values().filter(|e| proposed(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use taso_core::canon::Canonical;
    use taso_core::envelope::{BranchId, ChronicleId, Epoch, HashVal};
    use taso_core::record::{
        BarrierId, Consequence, Dispatch, IntentRecord, LayerRef, Namespace, Origin, OutcomeRecord,
        Record, RetryPolicy, SealRecord, StreamBase, StreamCut, TurnId, Verdict,
    };

    /// What a test log is made of.
    #[derive(Clone, Debug)]
    enum Step {
        Transcript,
        Fs,
        Intent(u8),
        Outcome(u8, u8),
        Seal(u64),
        Shipped,
        Promotion(u8),
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            Just(Step::Transcript),
            Just(Step::Fs),
            (0u8..6).prop_map(Step::Intent),
            (0u8..6, 0u8..6).prop_map(|(op, s)| Step::Outcome(op, s)),
            (1u64..1000).prop_map(Step::Seal),
            Just(Step::Shipped),
            (0u8..4).prop_map(Step::Promotion),
        ]
    }

    fn state(n: u8) -> OutcomeState {
        [
            OutcomeState::Prepared,
            OutcomeState::DispatchAuthorized,
            OutcomeState::OutcomeUnknown,
            OutcomeState::ConfirmedApplied,
            OutcomeState::ConfirmedNotApplied,
            OutcomeState::Proposed,
        ][usize::from(n)]
    }

    fn promotion(child: u8) -> PromotionRecord {
        PromotionRecord {
            child: ChronicleId::from_bytes([child; 16]),
            seal: Lsn::new(u64::from(child) + 1),
            seal_hash: HashVal::from_bytes([child; 32]),
            ledger_pos: Lsn::new(u64::from(child)),
        }
    }

    fn intent(op: u8) -> IntentRecord {
        IntentRecord {
            op: OpId::new(u64::from(op)),
            provider: "mail".into(),
            request: vec![op],
            footprint: vec![],
            dispatch: Dispatch::Immediate,
            retry: RetryPolicy::UnsafeToRetry,
            consequence: Consequence::Irreversible,
            authority: vec![],
            barrier: Some(BarrierId::new(u64::from(op))),
        }
    }

    /// Frames for `steps` after a Lineage record at lsn 1, chained.
    struct Log {
        frames: Vec<Frame>,
    }

    impl Log {
        fn new() -> Self {
            let mut l = Log { frames: Vec::new() };
            l.push(
                Stream::Ctl,
                Payload::Lineage(LineageRecord {
                    origin: Origin::Void,
                    namespace: Namespace::from_bytes([1; 16]),
                    ledger_pos: Lsn::new(0),
                }),
            );
            l
        }

        fn push(&mut self, stream: Stream, payload: Payload) {
            let (lsn, prev) = self
                .frames
                .last()
                .map_or((Lsn::new(1), HashVal::GENESIS), |f| {
                    (f.envelope.lsn.next(), f.envelope.hash)
                });
            let r = Record::new(
                ChronicleId::from_bytes([7; 16]),
                BranchId::TRUNK,
                Epoch::FIRST,
                stream,
                lsn,
                prev,
                payload,
            );
            self.frames.push(Frame {
                envelope: r.envelope,
                payload: r.payload.canon_bytes(),
            });
        }

        fn step(&mut self, s: &Step) {
            match s {
                Step::Transcript => self.push(Stream::Transcript, Payload::Raw(vec![1])),
                Step::Fs => self.push(Stream::Fs, Payload::Raw(vec![2])),
                Step::Intent(op) => self.push(Stream::Effect, Payload::Intent(intent(*op))),
                Step::Outcome(op, s) => self.push(
                    Stream::Effect,
                    Payload::Outcome(OutcomeRecord {
                        op: OpId::new(u64::from(*op)),
                        state: state(*s),
                        evidence: None,
                    }),
                ),
                Step::Seal(turn) => self.push(
                    Stream::Ctl,
                    Payload::Seal(SealRecord {
                        parent: None,
                        cut: StreamCut::EMPTY,
                        layer: LayerRef::new(0),
                        verdict: Verdict::Clean,
                        ledger_pos: Lsn::new(*turn),
                        turn: TurnId::new(*turn),
                    }),
                ),
                Step::Shipped => {
                    let seal = self.frames.last().unwrap().envelope;
                    self.push(
                        Stream::Ctl,
                        Payload::FsShipped(FsShippedRecord {
                            seal: seal.lsn,
                            seal_hash: seal.hash,
                            base: StreamBase::Full,
                            guid: 9,
                            bytes: 10,
                            digest: HashVal::from_bytes([3; 32]),
                        }),
                    )
                }
                Step::Promotion(child) => {
                    self.push(Stream::Ctl, Payload::Promotion(promotion(*child)))
                }
            }
        }

        /// Write a Checkpoint of everything so far.
        fn checkpoint(&mut self) {
            let cp = Summary::of(&self.frames).unwrap().checkpoint().unwrap();
            self.push(Stream::Ctl, Payload::Checkpoint(Box::new(cp)));
        }
    }

    /// Everything a reader sees, without which Checkpoint it came from and
    /// without chained hashes (the two logs chain differently by
    /// construction; that the hash is the record's is checked below).
    fn seen(s: &Summary) -> Summary {
        let mut s = Summary {
            from_checkpoint: None,
            ..s.clone()
        };
        if let Some(seal) = &mut s.seal {
            seal.hash = HashVal::GENESIS;
        }
        if let Some(f) = &mut s.fs_shipped {
            f.seal_hash = HashVal::GENESIS;
        }
        s
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Folding the whole log, or only from a Checkpoint written
        /// anywhere in it (and the records after), gives the same answer;
        /// so does dropping every record before that Checkpoint.
        #[test]
        fn a_checkpoint_replaces_the_records_before_it(
            before in proptest::collection::vec(step(), 0..40),
            after in proptest::collection::vec(step(), 0..40),
        ) {
            let mut plain = Log::new();
            let mut with_cp = Log::new();
            for s in &before {
                plain.step(s);
                with_cp.step(s);
            }
            with_cp.checkpoint();
            // A neutral Ctl record in its place keeps the lsns aligned.
            plain.push(Stream::Ctl, Payload::Raw(vec![0]));
            let cp_at = with_cp.frames.len() - 1;
            for s in &after {
                plain.step(s);
                with_cp.step(s);
            }
            let whole = Summary::of(&plain.frames).unwrap();
            let from_cp = Summary::of(&with_cp.frames).unwrap();
            let pruned = Summary::of(&with_cp.frames[cp_at..]).unwrap();
            // The Checkpoint itself is a Ctl record; nothing else moved.
            prop_assert_eq!(seen(&from_cp), seen(&whole));
            prop_assert_eq!(seen(&pruned), seen(&whole));
            prop_assert_eq!(from_cp.from_checkpoint, Some(with_cp.frames[cp_at].envelope.lsn));
            // The Seal's hash is its record's, in each log.
            for (log, s) in [(&plain, &whole), (&with_cp, &from_cp)] {
                if let Some(seal) = &s.seal {
                    let f = log.frames.iter().find(|f| f.envelope.lsn == seal.lsn).unwrap();
                    prop_assert_eq!(f.envelope.hash, seal.hash);
                }
            }
        }
    }

    #[test]
    fn open_effects_follow_their_latest_outcome() {
        let mut l = Log::new();
        for s in [
            Step::Intent(1),
            Step::Intent(2),
            Step::Outcome(1, 1),
            Step::Outcome(2, 3),
            Step::Intent(3),
            Step::Outcome(1, 2),
        ] {
            l.step(&s);
        }
        let s = Summary::of(&l.frames).unwrap();
        let open: Vec<(u64, Option<OutcomeState>)> = s
            .open
            .values()
            .map(|e| (e.intent.op.get(), e.state))
            .collect();
        assert_eq!(
            open,
            vec![(1, Some(OutcomeState::OutcomeUnknown)), (3, None)],
            "2 is terminal"
        );
        assert_eq!(s.next_op, 4);
        assert!(s.lineage.is_some() && s.checkpoint().is_some());
        assert_eq!(
            Summary::default().checkpoint(),
            None,
            "no Lineage, no Checkpoint"
        );
    }

    /// A held proposal is in `open` (so a Checkpoint carries it through a
    /// prune) but is never an obligation; the two views partition `open`.
    #[test]
    fn proposals_are_kept_but_are_not_obligations() {
        let mut l = Log::new();
        for s in [
            Step::Intent(1),
            Step::Outcome(1, 5), // held
            Step::Intent(2),
            Step::Outcome(2, 1), // released
            Step::Intent(3),
            Step::Outcome(3, 5), // held
            Step::Intent(4),     // never authorized
        ] {
            l.step(&s);
        }
        let ops = |it: Box<dyn Iterator<Item = &OpenEffect> + '_>| -> Vec<u64> {
            it.map(|e| e.intent.op.get()).collect()
        };
        let s = Summary::of(&l.frames).unwrap();
        assert_eq!(ops(Box::new(s.proposals())), vec![1, 3]);
        assert_eq!(ops(Box::new(s.obligations())), vec![2, 4]);
        assert_eq!(s.open.len(), 4);
        // Through a Checkpoint and a prune, the same.
        l.checkpoint();
        let at = l.frames.len() - 1;
        let pruned = Summary::of(&l.frames[at..]).unwrap();
        assert_eq!(ops(Box::new(pruned.proposals())), vec![1, 3]);
        assert_eq!(ops(Box::new(pruned.obligations())), vec![2, 4]);
    }

    /// The last Promotion is folded, carried by the Checkpoint, and a
    /// later one replaces it.
    #[test]
    fn the_last_promotion_is_folded_and_survives_a_prune() {
        let mut l = Log::new();
        assert_eq!(Summary::of(&l.frames).unwrap().promotion, None);
        l.step(&Step::Promotion(1));
        l.step(&Step::Intent(1));
        assert_eq!(
            Summary::of(&l.frames).unwrap().promotion,
            Some(promotion(1))
        );
        l.checkpoint();
        let at = l.frames.len() - 1;
        let cp = Payload::decode(&l.frames[at].payload).unwrap();
        let Payload::Checkpoint(cp) = cp else {
            unreachable!()
        };
        assert_eq!(cp.promotion, Some(promotion(1)));
        assert_eq!(
            Summary::of(&l.frames[at..]).unwrap().promotion,
            Some(promotion(1))
        );
        l.step(&Step::Promotion(2));
        assert_eq!(
            Summary::of(&l.frames).unwrap().promotion,
            Some(promotion(2))
        );
    }
}
