//! Canonical decoding: the exact inverse of [`crate::canon`] for every
//! payload type in [`crate::record`].
//!
//! The Warden stores payloads as opaque bytes (v0.4 §2.1) and the segment
//! and shipper never look inside.  Only Taso's own control logic decodes
//! Taso's own record types — lineage checks on open, succession closure,
//! Seal/snapshot reconciliation, the Navigator over a real segment.
//! [`Payload::Raw`] stays untouched bytes.
//!
//! The decoder is strict, so that the encoding is one-to-one: every input
//! either decodes to exactly one value whose canonical encoding is the
//! input itself, or is refused.  Refused are: an unknown tag, a `bool`
//! other than `0`/`1`, invalid UTF-8, truncation, and trailing bytes.
//! Lengths and counts are checked against the remaining input before
//! anything is allocated.

use std::fmt;

use crate::contract::ContractRecord;
use crate::envelope::{ChronicleId, HashVal, Lsn, Stream};
use crate::record::{
    Authority, BarrierId, CheckpointRecord, CheckpointSeal, Consequence, Dispatch, FsShippedRecord,
    GapRecord, GroupId, GroupRecord, IntentRecord, LayerRef, LineageRecord, Member, Namespace,
    OpId, OpenEffect, Origin, OutcomeRecord, OutcomeState, ParentSeal, Payload, PromotionRecord,
    RetryPolicy, SealRecord, StreamBase, StreamCut, SuccessionRecord, TaintKind, TemplateAsked,
    TurnId, Verdict,
};

// ── Errors ──────────────────────────────────────────────────────────

/// Why bytes are not a canonical payload.  `at` is the byte offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended early.
    Truncated {
        /// Where the read started.
        at: usize,
        /// How many bytes it needed.
        need: u64,
    },
    /// A tag is not valid for its type.
    BadTag {
        /// Where.
        at: usize,
        /// Which type.
        what: &'static str,
        /// The tag found.
        tag: u8,
    },
    /// A string is not UTF-8.
    BadUtf8 {
        /// Where the string's bytes start.
        at: usize,
    },
    /// Bytes remain after a complete payload.
    Trailing {
        /// Where the payload ended.
        at: usize,
        /// How many bytes remain.
        extra: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { at, need } => write!(f, "truncated at {at}: need {need} more bytes"),
            Self::BadTag { at, what, tag } => write!(f, "bad {what} tag {tag} at {at}"),
            Self::BadUtf8 { at } => write!(f, "invalid UTF-8 at {at}"),
            Self::Trailing { at, extra } => write!(f, "{extra} trailing bytes after {at}"),
        }
    }
}

impl std::error::Error for DecodeError {}

// ── Reader ──────────────────────────────────────────────────────────

/// A cursor over canonical bytes: the one strict reader every canonical
/// format in this crate decodes with.  The record decoders are here; the
/// contract decoders are a second `impl` block in [`crate::contract`].
pub(crate) struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

pub(crate) type R<T> = Result<T, DecodeError>;

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }

    /// The offset of the next byte: where an error about it is reported.
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    /// Take `n` bytes, or fail without consuming.
    pub(crate) fn take(&mut self, n: u64) -> R<&'a [u8]> {
        if n > self.remaining() as u64 {
            return Err(DecodeError::Truncated {
                at: self.pos,
                need: n,
            });
        }
        let start = self.pos;
        self.pos += n as usize;
        Ok(&self.b[start..self.pos])
    }

    pub(crate) fn u8(&mut self) -> R<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u64(&mut self) -> R<u64> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }

    pub(crate) fn u32(&mut self) -> R<u32> {
        Ok(u32::from_le_bytes(self.fixed::<4>()?))
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> R<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N as u64)?);
        Ok(a)
    }

    /// A tag, with its offset (for errors).
    pub(crate) fn tag(&mut self) -> R<(usize, u8)> {
        let at = self.pos;
        Ok((at, self.u8()?))
    }

    pub(crate) fn bad<T>(at: usize, what: &'static str, tag: u8) -> R<T> {
        Err(DecodeError::BadTag { at, what, tag })
    }

    pub(crate) fn bool(&mut self) -> R<bool> {
        match self.tag()? {
            (_, 0) => Ok(false),
            (_, 1) => Ok(true),
            (at, tag) => Err(DecodeError::BadTag {
                at,
                what: "bool",
                tag,
            }),
        }
    }

    pub(crate) fn bytes(&mut self) -> R<Vec<u8>> {
        let len = self.u64()?;
        Ok(self.take(len)?.to_vec())
    }

    pub(crate) fn string(&mut self) -> R<String> {
        let len = self.u64()?;
        let at = self.pos;
        let raw = self.take(len)?;
        std::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| DecodeError::BadUtf8 { at })
    }

    pub(crate) fn option<T>(&mut self, f: impl FnOnce(&mut Self) -> R<T>) -> R<Option<T>> {
        match self.tag()? {
            (_, 0) => Ok(None),
            (_, 1) => f(self).map(Some),
            (at, tag) => Err(DecodeError::BadTag {
                at,
                what: "option",
                tag,
            }),
        }
    }

    /// A count-prefixed sequence.  Every element is at least one byte, so a
    /// count larger than the remaining input is refused before any
    /// allocation.
    pub(crate) fn seq<T>(&mut self, mut f: impl FnMut(&mut Self) -> R<T>) -> R<Vec<T>> {
        let at = self.pos;
        let n = self.u64()?;
        if n > self.remaining() as u64 {
            return Err(DecodeError::Truncated { at, need: n });
        }
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            out.push(f(self)?);
        }
        Ok(out)
    }

    pub(crate) fn finish(&self) -> R<()> {
        match self.remaining() {
            0 => Ok(()),
            extra => Err(DecodeError::Trailing {
                at: self.pos,
                extra,
            }),
        }
    }

    // ── envelope and record types ───────────────────────────────────

    pub(crate) fn lsn(&mut self) -> R<Lsn> {
        self.u64().map(Lsn::new)
    }

    pub(crate) fn hash(&mut self) -> R<HashVal> {
        self.fixed().map(HashVal::from_bytes)
    }

    pub(crate) fn chronicle(&mut self) -> R<ChronicleId> {
        self.fixed().map(ChronicleId::from_bytes)
    }

    fn stream(&mut self) -> R<Stream> {
        Ok(match self.tag()? {
            (_, 0) => Stream::Fs,
            (_, 1) => Stream::Db,
            (_, 2) => Stream::Transcript,
            (_, 3) => Stream::Effect,
            (_, 4) => Stream::Ctl,
            (at, tag) => {
                return Err(DecodeError::BadTag {
                    at,
                    what: "stream",
                    tag,
                })
            }
        })
    }

    fn verdict(&mut self) -> R<Verdict> {
        Ok(match self.tag()? {
            (_, 0) => Verdict::Clean,
            (_, 1) => Verdict::Unverified(self.string()?),
            (_, 2) => Verdict::Tainted(match self.tag()? {
                (_, 0) => TaintKind::ChainBroken,
                (_, 1) => TaintKind::GroupIncomplete,
                (_, 2) => TaintKind::BarrierViolation,
                (at, tag) => {
                    return Err(DecodeError::BadTag {
                        at,
                        what: "taint kind",
                        tag,
                    })
                }
            }),
            (at, tag) => {
                return Err(DecodeError::BadTag {
                    at,
                    what: "verdict",
                    tag,
                })
            }
        })
    }

    fn seal(&mut self) -> R<SealRecord> {
        Ok(SealRecord {
            parent: self.option(Self::hash)?,
            cut: StreamCut {
                fs: self.lsn()?,
                db: self.lsn()?,
                transcript: self.lsn()?,
            },
            layer: LayerRef::new(self.u64()?),
            verdict: self.verdict()?,
            ledger_pos: self.lsn()?,
            turn: TurnId::new(self.u64()?),
        })
    }

    fn group(&mut self) -> R<GroupRecord> {
        Ok(GroupRecord {
            gid: GroupId::new(self.u64()?),
            members: self.seq(|r| {
                Ok(Member {
                    stream: r.stream()?,
                    lsn: r.lsn()?,
                })
            })?,
            depends_on: self.seq(|r| r.u64().map(GroupId::new))?,
            commit: self.bool()?,
        })
    }

    fn intent(&mut self) -> R<IntentRecord> {
        let op = OpId::new(self.u64()?);
        let provider = self.string()?;
        let request = self.bytes()?;
        let footprint = self.bytes()?;
        let dispatch = match self.tag()? {
            (_, 0) => Dispatch::Immediate,
            (_, 1) => Dispatch::Deferrable,
            (at, tag) => {
                return Err(DecodeError::BadTag {
                    at,
                    what: "dispatch",
                    tag,
                })
            }
        };
        let retry = match self.tag()? {
            (_, 0) => RetryPolicy::ProviderDeduplicated { key: self.bytes()? },
            (_, 1) => RetryPolicy::Queryable {
                probe: self.bytes()?,
            },
            (_, 2) => RetryPolicy::UnsafeToRetry,
            (at, tag) => {
                return Err(DecodeError::BadTag {
                    at,
                    what: "retry policy",
                    tag,
                })
            }
        };
        let consequence = match self.tag()? {
            (_, 0) => Consequence::Irreversible,
            (_, 1) => Consequence::Compensatable {
                by: OpId::new(self.u64()?),
            },
            (_, 2) => Consequence::NoExternalMutation,
            (at, tag) => {
                return Err(DecodeError::BadTag {
                    at,
                    what: "consequence",
                    tag,
                })
            }
        };
        Ok(IntentRecord {
            op,
            provider,
            request,
            footprint,
            dispatch,
            retry,
            consequence,
            authority: self.bytes()?,
            barrier: self.option(|r| r.u64().map(BarrierId::new))?,
        })
    }

    fn outcome_state(&mut self) -> R<OutcomeState> {
        Ok(match self.tag()? {
            (_, 0) => OutcomeState::Prepared,
            (_, 1) => OutcomeState::DispatchAuthorized,
            (_, 2) => OutcomeState::OutcomeUnknown,
            (_, 3) => OutcomeState::ConfirmedApplied,
            (_, 4) => OutcomeState::ConfirmedNotApplied,
            (_, 5) => OutcomeState::Proposed,
            (_, 6) => OutcomeState::AcceptedUnknown,
            (at, tag) => {
                return Err(DecodeError::BadTag {
                    at,
                    what: "outcome state",
                    tag,
                })
            }
        })
    }

    fn outcome(&mut self) -> R<OutcomeRecord> {
        Ok(OutcomeRecord {
            op: OpId::new(self.u64()?),
            state: self.outcome_state()?,
            evidence: self.option(Self::bytes)?,
        })
    }

    fn checkpoint(&mut self) -> R<CheckpointRecord> {
        Ok(CheckpointRecord {
            lineage: self.lineage()?,
            transcript: self.lsn()?,
            effect: self.lsn()?,
            seal: self.option(|r| {
                Ok(CheckpointSeal {
                    lsn: r.lsn()?,
                    hash: r.hash()?,
                    turn: TurnId::new(r.u64()?),
                    ledger_pos: r.lsn()?,
                })
            })?,
            fs_shipped: self.option(Self::fs_shipped)?,
            open: self.seq(|r| {
                Ok(OpenEffect {
                    lsn: r.lsn()?,
                    intent: r.intent()?,
                    state: r.option(Self::outcome_state)?,
                })
            })?,
            next_op: self.u64()?,
            promotion: self.option(Self::promotion)?,
        })
    }

    fn namespace(&mut self) -> R<Namespace> {
        self.fixed().map(Namespace::from_bytes)
    }

    fn parent_seal(&mut self) -> R<ParentSeal> {
        Ok(ParentSeal {
            chronicle: self.chronicle()?,
            seal: self.lsn()?,
            seal_hash: self.hash()?,
        })
    }

    pub(crate) fn authority(&mut self) -> R<Authority> {
        Ok(Authority {
            actor: self.string()?,
            reason: self.string()?,
        })
    }

    fn lineage(&mut self) -> R<LineageRecord> {
        let origin = match self.tag()? {
            (_, 0) => Origin::Void,
            (_, 1) => Origin::Fork {
                parent: self.parent_seal()?,
            },
            (_, 2) => Origin::Succession {
                parent: self.parent_seal()?,
                authority: self.authority()?,
            },
            (_, 3) => Origin::Template {
                template_id: self.chronicle()?,
                layer_key: self.hash()?,
                asked: self.option(|r| {
                    Ok(TemplateAsked {
                        name: r.string()?,
                        version: r.u32()?,
                    })
                })?,
            },
            (at, tag) => {
                return Err(DecodeError::BadTag {
                    at,
                    what: "origin",
                    tag,
                })
            }
        };
        Ok(LineageRecord {
            origin,
            namespace: self.namespace()?,
            ledger_pos: self.lsn()?,
        })
    }

    fn succession(&mut self) -> R<SuccessionRecord> {
        Ok(SuccessionRecord {
            successor: self.chronicle()?,
            namespace: self.namespace()?,
            seal: self.lsn()?,
            seal_hash: self.hash()?,
            authority: self.authority()?,
        })
    }

    fn gap(&mut self) -> R<GapRecord> {
        Ok(GapRecord {
            kept: self.lsn()?,
            kept_hash: self.hash()?,
            resumes: self.lsn()?,
            resumes_hash: self.hash()?,
        })
    }

    fn stream_base(&mut self) -> R<StreamBase> {
        Ok(match self.tag()? {
            (_, 0) => StreamBase::Full,
            (_, 1) => StreamBase::Seal {
                lsn: self.lsn()?,
                hash: self.hash()?,
            },
            (_, 2) => StreamBase::Origin {
                parent: self.parent_seal()?,
                guid: self.u64()?,
            },
            (at, tag) => {
                return Err(DecodeError::BadTag {
                    at,
                    what: "stream base",
                    tag,
                })
            }
        })
    }

    fn fs_shipped(&mut self) -> R<FsShippedRecord> {
        Ok(FsShippedRecord {
            seal: self.lsn()?,
            seal_hash: self.hash()?,
            base: self.stream_base()?,
            guid: self.u64()?,
            bytes: self.u64()?,
            digest: self.hash()?,
        })
    }

    fn promotion(&mut self) -> R<PromotionRecord> {
        Ok(PromotionRecord {
            child: self.chronicle()?,
            seal: self.lsn()?,
            seal_hash: self.hash()?,
            ledger_pos: self.lsn()?,
        })
    }

    fn payload(&mut self) -> R<Payload> {
        Ok(match self.tag()? {
            (_, 0) => Payload::Seal(self.seal()?),
            (_, 1) => Payload::Group(self.group()?),
            (_, 2) => Payload::Intent(self.intent()?),
            (_, 3) => Payload::Outcome(self.outcome()?),
            (_, 4) => Payload::Raw(self.bytes()?),
            (_, 5) => Payload::Lineage(self.lineage()?),
            (_, 6) => Payload::Succession(self.succession()?),
            (_, 7) => Payload::Gap(self.gap()?),
            (_, 8) => Payload::FsShipped(self.fs_shipped()?),
            (_, 9) => Payload::Checkpoint(Box::new(self.checkpoint()?)),
            (_, 10) => Payload::Promotion(self.promotion()?),
            // The contract record is the rest of the payload; it has its
            // own strict decoder (offsets in its errors are from its
            // first byte).
            (_, 11) => {
                let rest = self.take(self.remaining() as u64)?;
                Payload::Contract(Box::new(ContractRecord::decode(rest)?))
            }
            (at, tag) => {
                return Err(DecodeError::BadTag {
                    at,
                    what: "payload",
                    tag,
                })
            }
        })
    }
}

// ── Public API ──────────────────────────────────────────────────────

impl Payload {
    /// Decode a payload from its canonical bytes.  Strict: the bytes must
    /// be exactly one complete payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let p = r.payload()?;
        r.finish()?;
        Ok(p)
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::Canonical;
    use proptest::prelude::*;

    // ── generators ──────────────────────────────────────────────────

    fn lsn() -> impl Strategy<Value = Lsn> {
        any::<u64>().prop_map(Lsn::new)
    }
    fn hash() -> impl Strategy<Value = HashVal> {
        any::<[u8; 32]>().prop_map(HashVal::from_bytes)
    }
    fn blob() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..40)
    }
    fn text() -> impl Strategy<Value = String> {
        "\\PC{0,20}"
    }
    fn stream() -> impl Strategy<Value = Stream> {
        prop_oneof![
            Just(Stream::Fs),
            Just(Stream::Db),
            Just(Stream::Transcript),
            Just(Stream::Effect),
            Just(Stream::Ctl)
        ]
    }
    fn verdict() -> impl Strategy<Value = Verdict> {
        prop_oneof![
            Just(Verdict::Clean),
            text().prop_map(Verdict::Unverified),
            prop_oneof![
                Just(TaintKind::ChainBroken),
                Just(TaintKind::GroupIncomplete),
                Just(TaintKind::BarrierViolation)
            ]
            .prop_map(Verdict::Tainted),
        ]
    }
    fn seal() -> impl Strategy<Value = Payload> {
        (
            proptest::option::of(hash()),
            lsn(),
            lsn(),
            lsn(),
            any::<u64>(),
            verdict(),
            lsn(),
            any::<u64>(),
        )
            .prop_map(
                |(parent, fs, db, transcript, layer, verdict, ledger_pos, turn)| {
                    Payload::Seal(SealRecord {
                        parent,
                        cut: StreamCut { fs, db, transcript },
                        layer: LayerRef::new(layer),
                        verdict,
                        ledger_pos,
                        turn: TurnId::new(turn),
                    })
                },
            )
    }
    fn group() -> impl Strategy<Value = Payload> {
        (
            any::<u64>(),
            proptest::collection::vec((stream(), lsn()), 0..6),
            proptest::collection::vec(any::<u64>(), 0..6),
            any::<bool>(),
        )
            .prop_map(|(gid, members, deps, commit)| {
                Payload::Group(GroupRecord {
                    gid: GroupId::new(gid),
                    members: members
                        .into_iter()
                        .map(|(stream, lsn)| Member { stream, lsn })
                        .collect(),
                    depends_on: deps.into_iter().map(GroupId::new).collect(),
                    commit,
                })
            })
    }
    fn intent() -> impl Strategy<Value = Payload> {
        let dispatch = prop_oneof![Just(Dispatch::Immediate), Just(Dispatch::Deferrable)];
        let retry = prop_oneof![
            blob().prop_map(|key| RetryPolicy::ProviderDeduplicated { key }),
            blob().prop_map(|probe| RetryPolicy::Queryable { probe }),
            Just(RetryPolicy::UnsafeToRetry),
        ];
        let consequence = prop_oneof![
            Just(Consequence::Irreversible),
            any::<u64>().prop_map(|b| Consequence::Compensatable { by: OpId::new(b) }),
            Just(Consequence::NoExternalMutation),
        ];
        let ids = (any::<u64>(), text(), blob());
        (
            ids,
            blob(),
            dispatch,
            retry,
            consequence,
            blob(),
            proptest::option::of(any::<u64>()),
        )
            .prop_map(
                |(
                    (op, provider, request),
                    footprint,
                    dispatch,
                    retry,
                    consequence,
                    authority,
                    barrier,
                )| {
                    Payload::Intent(IntentRecord {
                        op: OpId::new(op),
                        provider,
                        request,
                        footprint,
                        dispatch,
                        retry,
                        consequence,
                        authority,
                        barrier: barrier.map(BarrierId::new),
                    })
                },
            )
    }
    fn outcome() -> impl Strategy<Value = Payload> {
        let state = prop_oneof![
            Just(OutcomeState::Prepared),
            Just(OutcomeState::DispatchAuthorized),
            Just(OutcomeState::OutcomeUnknown),
            Just(OutcomeState::ConfirmedApplied),
            Just(OutcomeState::ConfirmedNotApplied),
            Just(OutcomeState::Proposed),
            Just(OutcomeState::AcceptedUnknown),
        ];
        (any::<u64>(), state, proptest::option::of(blob())).prop_map(|(op, state, evidence)| {
            Payload::Outcome(OutcomeRecord {
                op: OpId::new(op),
                state,
                evidence,
            })
        })
    }
    fn parent_seal() -> impl Strategy<Value = ParentSeal> {
        (any::<[u8; 16]>(), lsn(), hash()).prop_map(|(c, seal, seal_hash)| ParentSeal {
            chronicle: ChronicleId::from_bytes(c),
            seal,
            seal_hash,
        })
    }
    fn authority() -> impl Strategy<Value = Authority> {
        (text(), text()).prop_map(|(actor, reason)| Authority { actor, reason })
    }
    fn lineage() -> impl Strategy<Value = Payload> {
        let origin = prop_oneof![
            Just(Origin::Void),
            parent_seal().prop_map(|parent| Origin::Fork { parent }),
            (parent_seal(), authority())
                .prop_map(|(parent, authority)| Origin::Succession { parent, authority }),
            (
                any::<[u8; 16]>(),
                hash(),
                proptest::option::of((text(), any::<u32>()))
            )
                .prop_map(|(t, layer_key, asked)| Origin::Template {
                    template_id: ChronicleId::from_bytes(t),
                    layer_key,
                    asked: asked.map(|(name, version)| TemplateAsked { name, version }),
                }),
        ];
        (origin, any::<[u8; 16]>(), lsn()).prop_map(|(origin, ns, ledger_pos)| {
            Payload::Lineage(LineageRecord {
                origin,
                namespace: Namespace::from_bytes(ns),
                ledger_pos,
            })
        })
    }
    fn succession() -> impl Strategy<Value = Payload> {
        (
            any::<[u8; 16]>(),
            any::<[u8; 16]>(),
            lsn(),
            hash(),
            authority(),
        )
            .prop_map(|(c, ns, seal, seal_hash, authority)| {
                Payload::Succession(SuccessionRecord {
                    successor: ChronicleId::from_bytes(c),
                    namespace: Namespace::from_bytes(ns),
                    seal,
                    seal_hash,
                    authority,
                })
            })
    }
    fn gap() -> impl Strategy<Value = Payload> {
        (lsn(), hash(), lsn(), hash()).prop_map(|(kept, kept_hash, resumes, resumes_hash)| {
            Payload::Gap(GapRecord {
                kept,
                kept_hash,
                resumes,
                resumes_hash,
            })
        })
    }
    fn fs_shipped() -> impl Strategy<Value = Payload> {
        let base = prop_oneof![
            Just(StreamBase::Full),
            (lsn(), hash()).prop_map(|(lsn, hash)| StreamBase::Seal { lsn, hash }),
            (parent_seal(), any::<u64>())
                .prop_map(|(parent, guid)| StreamBase::Origin { parent, guid }),
        ];
        (lsn(), hash(), base, any::<u64>(), any::<u64>(), hash()).prop_map(
            |(seal, seal_hash, base, guid, bytes, digest)| {
                Payload::FsShipped(FsShippedRecord {
                    seal,
                    seal_hash,
                    base,
                    guid,
                    bytes,
                    digest,
                })
            },
        )
    }
    fn checkpoint() -> impl Strategy<Value = Payload> {
        let lineage = lineage().prop_map(|p| match p {
            Payload::Lineage(l) => l,
            _ => unreachable!(),
        });
        let cseal =
            (lsn(), hash(), any::<u64>(), lsn()).prop_map(|(lsn, hash, turn, ledger_pos)| {
                CheckpointSeal {
                    lsn,
                    hash,
                    turn: TurnId::new(turn),
                    ledger_pos,
                }
            });
        let fs = fs_shipped().prop_map(|p| match p {
            Payload::FsShipped(f) => f,
            _ => unreachable!(),
        });
        let state = prop_oneof![
            Just(OutcomeState::Prepared),
            Just(OutcomeState::DispatchAuthorized),
            Just(OutcomeState::OutcomeUnknown),
            Just(OutcomeState::Proposed),
        ];
        let promo = promotion().prop_map(|p| match p {
            Payload::Promotion(r) => r,
            _ => unreachable!(),
        });
        let open =
            (lsn(), intent(), proptest::option::of(state)).prop_map(|(lsn, i, state)| match i {
                Payload::Intent(intent) => OpenEffect { lsn, intent, state },
                _ => unreachable!(),
            });
        (
            lineage,
            lsn(),
            lsn(),
            proptest::option::of(cseal),
            proptest::option::of(fs),
            proptest::collection::vec(open, 0..3),
            any::<u64>(),
            proptest::option::of(promo),
        )
            .prop_map(
                |(lineage, transcript, effect, seal, fs_shipped, open, next_op, promotion)| {
                    Payload::Checkpoint(Box::new(CheckpointRecord {
                        lineage,
                        transcript,
                        effect,
                        seal,
                        fs_shipped,
                        open,
                        next_op,
                        promotion,
                    }))
                },
            )
    }
    fn promotion() -> impl Strategy<Value = Payload> {
        (any::<[u8; 16]>(), lsn(), hash(), lsn()).prop_map(|(c, seal, seal_hash, ledger_pos)| {
            Payload::Promotion(PromotionRecord {
                child: ChronicleId::from_bytes(c),
                seal,
                seal_hash,
                ledger_pos,
            })
        })
    }
    fn payload() -> impl Strategy<Value = Payload> {
        prop_oneof![
            seal(),
            group(),
            intent(),
            outcome(),
            blob().prop_map(Payload::Raw),
            lineage(),
            succession(),
            gap(),
            fs_shipped(),
            checkpoint(),
            promotion()
        ]
    }

    // ── properties ──────────────────────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// Every payload decodes back to itself.
        #[test]
        fn round_trip(p in payload()) {
            let bytes = p.canon_bytes();
            prop_assert_eq!(Payload::decode(&bytes), Ok(p));
        }

        /// Every proper prefix is refused.
        #[test]
        fn every_truncation_is_refused(p in payload(), pick in any::<prop::sample::Index>()) {
            let bytes = p.canon_bytes();
            let cut = pick.index(bytes.len());
            prop_assert!(Payload::decode(&bytes[..cut]).is_err());
        }

        /// Any extra byte is refused.
        #[test]
        fn trailing_bytes_are_refused(p in payload(), extra in proptest::collection::vec(any::<u8>(), 1..8)) {
            let mut bytes = p.canon_bytes();
            let at = bytes.len();
            bytes.extend_from_slice(&extra);
            prop_assert_eq!(
                Payload::decode(&bytes),
                Err(DecodeError::Trailing { at, extra: extra.len() })
            );
        }

        /// The encoding is one-to-one: whatever random bytes happen to
        /// decode re-encode to exactly those bytes.
        #[test]
        fn anything_that_decodes_is_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..120)) {
            if let Ok(p) = Payload::decode(&bytes) {
                prop_assert_eq!(p.canon_bytes(), bytes);
            }
        }

        /// Flipping one byte never decodes to the same payload.
        #[test]
        fn a_flipped_byte_never_decodes_to_the_same_value(
            p in payload(),
            pick in any::<prop::sample::Index>(),
            flip in 1u8..=255,
        ) {
            let mut bytes = p.canon_bytes();
            let i = pick.index(bytes.len());
            bytes[i] ^= flip;
            if let Ok(q) = Payload::decode(&bytes) {
                prop_assert_ne!(q, p);
            }
        }
    }

    // ── specific refusals ───────────────────────────────────────────

    #[test]
    fn unknown_payload_tag() {
        assert_eq!(
            Payload::decode(&[12]),
            Err(DecodeError::BadTag {
                at: 0,
                what: "payload",
                tag: 12
            })
        );
        assert_eq!(
            Payload::decode(&[]),
            Err(DecodeError::Truncated { at: 0, need: 1 })
        );
    }

    #[test]
    fn non_canonical_bool_is_refused() {
        let mut bytes = Payload::Group(GroupRecord {
            gid: GroupId::new(1),
            members: vec![],
            depends_on: vec![],
            commit: true,
        })
        .canon_bytes();
        *bytes.last_mut().unwrap() = 2;
        assert!(matches!(
            Payload::decode(&bytes),
            Err(DecodeError::BadTag { what: "bool", .. })
        ));
    }

    #[test]
    fn huge_length_is_refused_without_allocating() {
        // Raw payload claiming u64::MAX bytes.
        let mut bytes = vec![4];
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            Payload::decode(&bytes),
            Err(DecodeError::Truncated {
                at: 9,
                need: u64::MAX
            })
        );
        // Group claiming u64::MAX members.
        let mut bytes = vec![1];
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            Payload::decode(&bytes),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn invalid_utf8_is_refused() {
        let mut bytes = Payload::Lineage(LineageRecord {
            origin: Origin::Succession {
                parent: ParentSeal {
                    chronicle: ChronicleId::from_bytes([1; 16]),
                    seal: Lsn::new(1),
                    seal_hash: HashVal::GENESIS,
                },
                authority: Authority {
                    actor: "ab".into(),
                    reason: String::new(),
                },
            },
            namespace: Namespace::from_bytes([0; 16]),
            ledger_pos: Lsn::new(0),
        })
        .canon_bytes();
        // tag(1) + origin tag(1) + parent(16+8+32) + actor len(8) = 66: "ab" starts there.
        assert_eq!(&bytes[66..68], b"ab");
        bytes[66] = 0xFF;
        assert_eq!(
            Payload::decode(&bytes),
            Err(DecodeError::BadUtf8 { at: 66 })
        );
    }

    #[test]
    fn bad_inner_tags_name_their_type() {
        let cases: [(Payload, usize, &str); 3] = [
            // Seal: tag, option tag 0, cut 24, layer 8 -> verdict tag at 34.
            (
                Payload::Seal(SealRecord {
                    parent: None,
                    cut: StreamCut::EMPTY,
                    layer: LayerRef::new(0),
                    verdict: Verdict::Clean,
                    ledger_pos: Lsn::new(0),
                    turn: TurnId::new(0),
                }),
                34,
                "verdict",
            ),
            // Lineage: origin tag at 1.
            (
                Payload::Lineage(LineageRecord {
                    origin: Origin::Void,
                    namespace: Namespace::from_bytes([0; 16]),
                    ledger_pos: Lsn::new(0),
                }),
                1,
                "origin",
            ),
            // Outcome: tag, op 8 -> state tag at 9.
            (
                Payload::Outcome(OutcomeRecord {
                    op: OpId::new(0),
                    state: OutcomeState::Prepared,
                    evidence: None,
                }),
                9,
                "outcome state",
            ),
        ];
        for (p, at, what) in cases {
            let mut bytes = p.canon_bytes();
            bytes[at] = 99;
            assert_eq!(
                Payload::decode(&bytes),
                Err(DecodeError::BadTag { at, what, tag: 99 }),
                "{what}"
            );
        }
    }

    // ── P3: Promotion and Proposed ──────────────────────────────────

    /// The Promotion payload (tag 10) decodes to what was encoded, byte
    /// for byte, including the whole record: a truncated or extended one
    /// is refused like any other.
    #[test]
    fn promotion_round_trips_and_is_strict() {
        let p = Payload::Promotion(PromotionRecord {
            child: ChronicleId::from_bytes([4; 16]),
            seal: Lsn::new(21),
            seal_hash: HashVal::from_bytes([21; 32]),
            ledger_pos: Lsn::new(17),
        });
        let bytes = p.canon_bytes();
        // tag 1 + child 16 + seal 8 + hash 32 + ledger_pos 8
        assert_eq!(bytes.len(), 65);
        assert_eq!(Payload::decode(&bytes), Ok(p));
        assert_eq!(
            Payload::decode(&bytes[..64]),
            Err(DecodeError::Truncated { at: 57, need: 8 })
        );
        let mut longer = bytes;
        longer.push(0);
        assert_eq!(
            Payload::decode(&longer),
            Err(DecodeError::Trailing { at: 65, extra: 1 })
        );
    }

    /// `Proposed` (state tag 5) and `AcceptedUnknown` (state tag 6, P4
    /// spec D34) decode; the next tag does not, and the refusal names the
    /// type so a reader of an older binary sees "outcome state 7", not a
    /// generic failure.
    #[test]
    fn proposed_and_accepted_unknown_decode_and_the_next_state_tag_is_refused() {
        for state in [OutcomeState::Proposed, OutcomeState::AcceptedUnknown] {
            let p = Payload::Outcome(OutcomeRecord {
                op: OpId::new(3),
                state,
                evidence: None,
            });
            assert_eq!(Payload::decode(&p.canon_bytes()), Ok(p));
        }
        let mut bytes = Payload::Outcome(OutcomeRecord {
            op: OpId::new(3),
            state: OutcomeState::AcceptedUnknown,
            evidence: None,
        })
        .canon_bytes();
        // Outcome: tag, op 8 -> state tag at 9.
        assert_eq!(bytes[9], 6);
        bytes[9] = 7;
        assert_eq!(
            Payload::decode(&bytes),
            Err(DecodeError::BadTag {
                at: 9,
                what: "outcome state",
                tag: 7
            })
        );
    }
}
