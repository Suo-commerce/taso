//! The coordinator log's journal (P4 spec rev. 12 §1.1, §1.7; file 1d-1).
//!
//! The coordinator log ([`taso_core::coordlog::CoordLog`]) is a pure
//! state machine.  It is made durable by journalling every operation that
//! changes it, in order, together with **every answer the store gave**
//! while it ran ([`Recorder`]) and the operation's own answer.  Opening a
//! coordinator replays the journal into a fresh log, answering the store
//! reads from the recording ([`Replayer`]), and checks that every
//! operation gives the answer it gave the first time.
//!
//! Why the store answers are recorded: some predicates read the store
//! ("is this pack readable?").  Re-running them at replay could answer
//! differently — originals are deleted after a purge — and the rebuilt
//! state would drift from the one the callers were told.  With the
//! answers recorded, replay is deterministic, and a replayed answer that
//! differs from the journalled one is corruption, refused.
//!
//! The encodings are the canonical encoding of `taso-core/src/canon.rs`;
//! decoding is strict.  They are internal to the coordinator's database.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 12, BLAKE3
//! `37c75f30580bf3edd79674be38702d7893af413813bbfe6d4585231e9477144a`.

use std::cell::{Cell, RefCell};
use std::fmt;

use taso_core::canon::{Canon, Canonical};
use taso_core::contract::{ContractRecord, Inventory, InventoryItem};
use taso_core::coordlog::{
    Answer, ChronicleView, ClaimAuthority, ClaimError, CoordLog, Final, Head, ObjectId, StoreView,
    SubmissionStatus, Submitted, Transient,
};
use taso_core::envelope::{ChronicleId, Epoch, HashVal, Lsn};
use taso_core::record::Payload;

/// The op id of the obligation a Chronicle gets if it had records before
/// the coordinator tracked obligations (D33): its effects were never seen,
/// so it is treated as having one that never closes — sanction and purge
/// are refused for it (fail closed).
pub const LEGACY_OBLIGATION: u64 = u64::MAX;

/// A journalled operation.
// One at a time, never held in bulk: the size of `Accept` costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Bring the log's epoch for `chronicle` up to the ownership epoch
    /// (tag 0): claimed as a Vessel if the log does not know it (with the
    /// legacy obligation if it already had records), then fenced until
    /// equal.
    Sync {
        /// The Chronicle.
        chronicle: ChronicleId,
        /// The ownership epoch.
        epoch: Epoch,
        /// It had records before the log knew it.
        legacy: bool,
    },
    /// `claim_chronicle` (tag 1).
    Claim {
        /// The new id.
        id: ChronicleId,
        /// By what right.
        authority: ClaimAuthority,
    },
    /// `takeover_target` (tag 2).
    Takeover {
        /// The target.
        id: ChronicleId,
        /// By what right.
        authority: ClaimAuthority,
        /// The epoch the caller read.
        current_epoch: Epoch,
    },
    /// `announce` (tag 3).
    Announce {
        /// The Chronicle.
        chronicle: ChronicleId,
        /// The caller's epoch.
        epoch: Epoch,
        /// The submission.
        submission: HashVal,
        /// Its logical id.
        logical: HashVal,
        /// Its record digest.
        digest: HashVal,
        /// The coordinator's time.
        now: u64,
    },
    /// `accept` (tag 4).
    Accept {
        /// The Chronicle.
        chronicle: ChronicleId,
        /// The caller's epoch.
        epoch: Epoch,
        /// The submission.
        submission: HashVal,
        /// The head the caller read.
        expected_head: Head,
        /// The pack that carries the record.
        pack: String,
        /// The record.
        record: Submitted,
        /// The coordinator's time.
        now: u64,
    },
    /// `cancel` (tag 5).
    Cancel {
        /// The Chronicle.
        chronicle: ChronicleId,
        /// The caller's epoch.
        epoch: Epoch,
        /// The submission.
        submission: HashVal,
    },
    /// An effect obligation opened or closed by an accepted append
    /// (tag 6, §1.5, D33).
    Obligation {
        /// The Chronicle.
        chronicle: ChronicleId,
        /// The effect's op id.
        op: u64,
        /// Opened (`true`) or closed.
        open: bool,
    },
    /// `set_retention_pin` (tag 7).
    Pin {
        /// The Chronicle.
        chronicle: ChronicleId,
        /// Pinned or lifted.
        pinned: bool,
    },
}

/// What an operation answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Done {
    /// [`Op::Sync`]: the epoch now, or the log's epoch if it was already
    /// past the ownership epoch (never expected; the caller refuses).
    Sync(Result<Epoch, Epoch>),
    /// [`Op::Claim`].
    Claim(Result<Epoch, ClaimError>),
    /// [`Op::Takeover`].
    Takeover(Result<(Epoch, Head), ClaimError>),
    /// [`Op::Announce`].
    Announce(Result<(), Answer>),
    /// [`Op::Accept`], [`Op::Cancel`].
    Answer(Answer),
    /// [`Op::Obligation`], [`Op::Pin`].
    Unit,
}

/// Run `op` against `log`, reading the store through `store`.
pub fn apply(log: &mut CoordLog, op: &Op, store: &dyn StoreView) -> Done {
    match op {
        Op::Sync {
            chronicle,
            epoch,
            legacy,
        } => {
            if log.epoch(*chronicle).is_none() {
                log.claim_chronicle(*chronicle, ClaimAuthority::Vessel)
                    .expect("not known, so claimable");
                if *legacy {
                    log.note_obligation(*chronicle, LEGACY_OBLIGATION, true);
                }
            }
            let mut now = log.epoch(*chronicle).expect("known");
            while now < *epoch {
                now = log.fence(*chronicle).expect("known");
            }
            Done::Sync(if now == *epoch { Ok(now) } else { Err(now) })
        }
        Op::Claim { id, authority } => Done::Claim(log.claim_chronicle(*id, *authority)),
        Op::Takeover {
            id,
            authority,
            current_epoch,
        } => Done::Takeover(log.takeover_target(*id, *authority, *current_epoch)),
        Op::Announce {
            chronicle,
            epoch,
            submission,
            logical,
            digest,
            now,
        } => Done::Announce(log.announce(*chronicle, *epoch, *submission, *logical, *digest, *now)),
        Op::Accept {
            chronicle,
            epoch,
            submission,
            expected_head,
            pack,
            record,
            now,
        } => Done::Answer(log.accept(
            *chronicle,
            *epoch,
            *submission,
            *expected_head,
            pack,
            record.clone(),
            store,
            *now,
        )),
        Op::Cancel {
            chronicle,
            epoch,
            submission,
        } => Done::Answer(log.cancel(*chronicle, *epoch, *submission)),
        Op::Obligation {
            chronicle,
            op,
            open,
        } => {
            log.note_obligation(*chronicle, *op, *open);
            Done::Unit
        }
        Op::Pin { chronicle, pinned } => {
            log.set_retention_pin(*chronicle, *pinned);
            Done::Unit
        }
    }
}

// ── A journal entry ─────────────────────────────────────────────────

/// One journal entry: the operation, the store's answers in the order
/// they were read, and the operation's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The operation.
    pub op: Op,
    /// The recorded store calls ([`Recorder::into_bytes`]).
    pub calls: Vec<u8>,
    /// The answer, encoded ([`Done::bytes`]).
    pub done: Vec<u8>,
}

impl Entry {
    /// Its stored bytes.
    pub fn bytes(&self) -> Vec<u8> {
        let mut c = Canon::new();
        put_op(&mut c, &self.op);
        c.bytes(&self.calls).bytes(&self.done);
        c.into_bytes()
    }

    /// Strict decoding of stored bytes.
    pub fn decode(b: &[u8]) -> Result<Self, JournalError> {
        let mut r = Rd::new(b);
        let op = get_op(&mut r)?;
        let calls = r.bytes()?;
        let done = r.bytes()?;
        r.finish()?;
        Ok(Self { op, calls, done })
    }
}

/// Run `op` live: against `log`, reading `store` and recording what it
/// answered.  Returns the answer and the entry to journal.
pub fn run(log: &mut CoordLog, op: Op, store: &dyn StoreView) -> (Done, Entry) {
    let rec = Recorder::new(store);
    let done = apply(log, &op, &rec);
    let entry = Entry {
        calls: rec.into_bytes(),
        done: done.bytes(),
        op,
    };
    (done, entry)
}

/// Replay one journalled entry into `log`: the store's answers come from
/// the recording, and the answer must equal the journalled one.
pub fn replay(log: &mut CoordLog, entry: &Entry) -> Result<(), JournalError> {
    let rep = Replayer::new(&entry.calls);
    let done = apply(log, &entry.op, &rep);
    if rep.diverged.get() || rep.pos.get() != entry.calls.len() {
        return Err(JournalError("replay read the store differently"));
    }
    if done.bytes() != entry.done {
        return Err(JournalError("replay answered differently"));
    }
    Ok(())
}

/// A journal that does not decode or does not replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalError(pub &'static str);

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "coordinator journal: {}", self.0)
    }
}

impl std::error::Error for JournalError {}

// ── Recording and replaying the store ───────────────────────────────

const CALL_CARRIES: u8 = 0;
const CALL_EXISTS: u8 = 1;
const CALL_INVENTORY: u8 = 2;
const CALL_FS_PACKS: u8 = 3;
const CALL_SEAL_CLOSURE: u8 = 4;
const CALL_VERIFY_REPLACEMENT: u8 = 5;

/// A [`StoreView`] that answers from `inner` and records each call and
/// its answer.
pub struct Recorder<'a> {
    inner: &'a dyn StoreView,
    out: RefCell<Canon>,
}

impl<'a> Recorder<'a> {
    /// Record calls to `inner`.
    pub fn new(inner: &'a dyn StoreView) -> Self {
        Self {
            inner,
            out: RefCell::new(Canon::new()),
        }
    }

    /// The recording.
    pub fn into_bytes(self) -> Vec<u8> {
        self.out.into_inner().into_bytes()
    }
}

impl StoreView for Recorder<'_> {
    fn carries(&self, chronicle: ChronicleId, name: &str, digest: HashVal) -> bool {
        let a = self.inner.carries(chronicle, name, digest);
        let mut o = self.out.borrow_mut();
        call_carries(&mut o, chronicle, name, digest);
        o.bool(a);
        a
    }
    fn exists(&self, object: &ObjectId) -> bool {
        let a = self.inner.exists(object);
        let mut o = self.out.borrow_mut();
        call_exists(&mut o, object);
        o.bool(a);
        a
    }
    fn inventory(&self, key: HashVal) -> Option<Inventory> {
        let a = self.inner.inventory(key);
        let mut o = self.out.borrow_mut();
        call_inventory(&mut o, key);
        match &a {
            None => o.tag(0),
            Some(inv) => o.tag(1).bytes(&inv.bytes()),
        };
        a
    }
    fn fs_packs(&self, chronicle: ChronicleId) -> Option<Vec<InventoryItem>> {
        let a = self.inner.fs_packs(chronicle);
        let mut o = self.out.borrow_mut();
        call_fs_packs(&mut o, chronicle);
        match &a {
            None => {
                o.tag(0);
            }
            Some(items) => {
                o.tag(1).u64(items.len() as u64);
                for it in items {
                    o.bytes(&item_bytes(it));
                }
            }
        }
        a
    }
    fn seal_closure(&self, chronicle: ChronicleId, seal: Lsn) -> Vec<ObjectId> {
        let a = self.inner.seal_closure(chronicle, seal);
        let mut o = self.out.borrow_mut();
        call_seal_closure(&mut o, chronicle, seal);
        o.u64(a.len() as u64);
        for obj in &a {
            put_object(&mut o, obj);
        }
        a
    }
    fn verify_replacement(&self, chronicle: ChronicleId, item: &InventoryItem) -> Option<HashVal> {
        let a = self.inner.verify_replacement(chronicle, item);
        let mut o = self.out.borrow_mut();
        call_verify_replacement(&mut o, chronicle, item);
        match &a {
            None => o.tag(0),
            Some(h) => o.tag(1).fixed(h.as_bytes()),
        };
        a
    }
}

fn call_carries(o: &mut Canon, chronicle: ChronicleId, name: &str, digest: HashVal) {
    o.tag(CALL_CARRIES)
        .fixed(chronicle.as_bytes())
        .str(name)
        .fixed(digest.as_bytes());
}
fn call_exists(o: &mut Canon, object: &ObjectId) {
    o.tag(CALL_EXISTS);
    put_object(o, object);
}
fn call_inventory(o: &mut Canon, key: HashVal) {
    o.tag(CALL_INVENTORY).fixed(key.as_bytes());
}
fn call_fs_packs(o: &mut Canon, chronicle: ChronicleId) {
    o.tag(CALL_FS_PACKS).fixed(chronicle.as_bytes());
}
fn call_seal_closure(o: &mut Canon, chronicle: ChronicleId, seal: Lsn) {
    o.tag(CALL_SEAL_CLOSURE)
        .fixed(chronicle.as_bytes())
        .u64(seal.get());
}
fn call_verify_replacement(o: &mut Canon, chronicle: ChronicleId, item: &InventoryItem) {
    o.tag(CALL_VERIFY_REPLACEMENT)
        .fixed(chronicle.as_bytes())
        .bytes(&item_bytes(item));
}

/// One item, as the bytes of a one-item inventory (so it decodes with
/// [`Inventory::decode`] and a list keeps its order).
fn item_bytes(item: &InventoryItem) -> Vec<u8> {
    Inventory::new(vec![item.clone()])
        .expect("one item is ordered")
        .bytes()
}

fn item_from(b: &[u8]) -> Option<InventoryItem> {
    let inv = Inventory::decode(b).ok()?;
    match inv.items() {
        [one] => Some(one.clone()),
        _ => None,
    }
}

/// A [`StoreView`] that answers from a recording.  A call that differs
/// from the recorded one, or one past its end, marks it diverged (and is
/// answered with nothing).
pub struct Replayer<'a> {
    bytes: &'a [u8],
    pos: Cell<usize>,
    diverged: Cell<bool>,
}

impl<'a> Replayer<'a> {
    /// Answer from `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: Cell::new(0),
            diverged: Cell::new(false),
        }
    }

    /// The recorded call must be exactly `call`; then read its answer.
    fn expect<T>(
        &self,
        call: Canon,
        answer: impl FnOnce(&mut Rd<'_>) -> Result<T, JournalError>,
    ) -> Option<T> {
        if self.diverged.get() {
            return None;
        }
        let want = call.into_bytes();
        let start = self.pos.get();
        let got = self.bytes.get(start..start + want.len());
        if got != Some(&want[..]) {
            self.diverged.set(true);
            return None;
        }
        let mut r = Rd {
            b: self.bytes,
            pos: start + want.len(),
        };
        match answer(&mut r) {
            Ok(v) => {
                self.pos.set(r.pos);
                Some(v)
            }
            Err(_) => {
                self.diverged.set(true);
                None
            }
        }
    }
}

impl StoreView for Replayer<'_> {
    fn carries(&self, chronicle: ChronicleId, name: &str, digest: HashVal) -> bool {
        let mut c = Canon::new();
        call_carries(&mut c, chronicle, name, digest);
        self.expect(c, |r| r.bool()).unwrap_or(false)
    }
    fn exists(&self, object: &ObjectId) -> bool {
        let mut c = Canon::new();
        call_exists(&mut c, object);
        self.expect(c, |r| r.bool()).unwrap_or(false)
    }
    fn inventory(&self, key: HashVal) -> Option<Inventory> {
        let mut c = Canon::new();
        call_inventory(&mut c, key);
        self.expect(c, |r| match r.u8()? {
            0 => Ok(None),
            1 => Inventory::decode(&r.bytes()?)
                .map(Some)
                .map_err(|_| JournalError("bad inventory")),
            _ => Err(JournalError("bad option tag")),
        })
        .flatten()
    }
    fn fs_packs(&self, chronicle: ChronicleId) -> Option<Vec<InventoryItem>> {
        let mut c = Canon::new();
        call_fs_packs(&mut c, chronicle);
        self.expect(c, |r| match r.u8()? {
            0 => Ok(None),
            1 => {
                let n = r.count()?;
                (0..n)
                    .map(|_| item_from(&r.bytes()?).ok_or(JournalError("bad item")))
                    .collect::<Result<Vec<_>, _>>()
                    .map(Some)
            }
            _ => Err(JournalError("bad option tag")),
        })
        .flatten()
    }
    fn seal_closure(&self, chronicle: ChronicleId, seal: Lsn) -> Vec<ObjectId> {
        let mut c = Canon::new();
        call_seal_closure(&mut c, chronicle, seal);
        self.expect(c, |r| {
            let n = r.count()?;
            (0..n).map(|_| get_object(r)).collect()
        })
        .unwrap_or_default()
    }
    fn verify_replacement(&self, chronicle: ChronicleId, item: &InventoryItem) -> Option<HashVal> {
        let mut c = Canon::new();
        call_verify_replacement(&mut c, chronicle, item);
        self.expect(c, |r| match r.u8()? {
            0 => Ok(None),
            1 => Ok(Some(HashVal::from_bytes(r.fixed()?))),
            _ => Err(JournalError("bad option tag")),
        })
        .flatten()
    }
}

// ── Encodings ───────────────────────────────────────────────────────

pub(crate) fn put_object(o: &mut Canon, obj: &ObjectId) {
    match obj {
        ObjectId::Content(h) => {
            o.tag(0).fixed(h);
        }
        ObjectId::Pack(c, name) => {
            o.tag(1).fixed(c).str(name);
        }
    }
}

pub(crate) fn get_object(r: &mut Rd<'_>) -> Result<ObjectId, JournalError> {
    match r.u8()? {
        0 => Ok(ObjectId::Content(r.fixed()?)),
        1 => {
            let c: [u8; 16] = r.fixed()?;
            Ok(ObjectId::Pack(c, r.string()?))
        }
        _ => Err(JournalError("bad object tag")),
    }
}

pub(crate) fn put_authority(o: &mut Canon, a: &ClaimAuthority) {
    match a {
        ClaimAuthority::Vessel => o.tag(0),
        ClaimAuthority::Genesis => o.tag(1),
        ClaimAuthority::GenesisStarted => o.tag(2),
        ClaimAuthority::Sanction { commit } => o.tag(3).fixed(commit.as_bytes()),
    };
}

pub(crate) fn get_authority(r: &mut Rd<'_>) -> Result<ClaimAuthority, JournalError> {
    Ok(match r.u8()? {
        0 => ClaimAuthority::Vessel,
        1 => ClaimAuthority::Genesis,
        2 => ClaimAuthority::GenesisStarted,
        3 => ClaimAuthority::Sanction {
            commit: HashVal::from_bytes(r.fixed()?),
        },
        _ => return Err(JournalError("bad authority tag")),
    })
}

pub(crate) fn put_head(o: &mut Canon, h: &Head) {
    o.u64(h.pos).fixed(h.digest.as_bytes());
}

pub(crate) fn get_head(r: &mut Rd<'_>) -> Result<Head, JournalError> {
    Ok(Head {
        pos: r.u64()?,
        digest: HashVal::from_bytes(r.fixed()?),
    })
}

pub(crate) fn put_submitted(o: &mut Canon, s: &Submitted) {
    match s {
        Submitted::Contract(rec) => {
            o.tag(0).bytes(&rec.canon_bytes());
        }
        Submitted::Birth { chronicle, lineage } => {
            o.tag(1)
                .fixed(chronicle.as_bytes())
                .bytes(&Payload::Lineage(lineage.clone()).canon_bytes());
        }
    }
}

pub(crate) fn get_submitted(r: &mut Rd<'_>) -> Result<Submitted, JournalError> {
    match r.u8()? {
        0 => ContractRecord::decode(&r.bytes()?)
            .map(Submitted::Contract)
            .map_err(|_| JournalError("bad contract record")),
        1 => {
            let chronicle = ChronicleId::from_bytes(r.fixed()?);
            match Payload::decode(&r.bytes()?) {
                Ok(Payload::Lineage(lineage)) => Ok(Submitted::Birth { chronicle, lineage }),
                _ => Err(JournalError("bad lineage")),
            }
        }
        _ => Err(JournalError("bad submitted tag")),
    }
}

fn put_op(o: &mut Canon, op: &Op) {
    match op {
        Op::Sync {
            chronicle,
            epoch,
            legacy,
        } => {
            o.tag(0)
                .fixed(chronicle.as_bytes())
                .u64(epoch.get())
                .bool(*legacy);
        }
        Op::Claim { id, authority } => {
            o.tag(1).fixed(id.as_bytes());
            put_authority(o, authority);
        }
        Op::Takeover {
            id,
            authority,
            current_epoch,
        } => {
            o.tag(2).fixed(id.as_bytes());
            put_authority(o, authority);
            o.u64(current_epoch.get());
        }
        Op::Announce {
            chronicle,
            epoch,
            submission,
            logical,
            digest,
            now,
        } => {
            o.tag(3)
                .fixed(chronicle.as_bytes())
                .u64(epoch.get())
                .fixed(submission.as_bytes())
                .fixed(logical.as_bytes())
                .fixed(digest.as_bytes())
                .u64(*now);
        }
        Op::Accept {
            chronicle,
            epoch,
            submission,
            expected_head,
            pack,
            record,
            now,
        } => {
            o.tag(4)
                .fixed(chronicle.as_bytes())
                .u64(epoch.get())
                .fixed(submission.as_bytes());
            put_head(o, expected_head);
            o.str(pack);
            put_submitted(o, record);
            o.u64(*now);
        }
        Op::Cancel {
            chronicle,
            epoch,
            submission,
        } => {
            o.tag(5)
                .fixed(chronicle.as_bytes())
                .u64(epoch.get())
                .fixed(submission.as_bytes());
        }
        Op::Obligation {
            chronicle,
            op,
            open,
        } => {
            o.tag(6).fixed(chronicle.as_bytes()).u64(*op).bool(*open);
        }
        Op::Pin { chronicle, pinned } => {
            o.tag(7).fixed(chronicle.as_bytes()).bool(*pinned);
        }
    }
}

fn get_op(r: &mut Rd<'_>) -> Result<Op, JournalError> {
    let chron = |r: &mut Rd<'_>| r.fixed().map(ChronicleId::from_bytes);
    let hash = |r: &mut Rd<'_>| r.fixed().map(HashVal::from_bytes);
    let epoch = |r: &mut Rd<'_>| r.u64().map(Epoch::new);
    Ok(match r.u8()? {
        0 => Op::Sync {
            chronicle: chron(r)?,
            epoch: epoch(r)?,
            legacy: r.bool()?,
        },
        1 => Op::Claim {
            id: chron(r)?,
            authority: get_authority(r)?,
        },
        2 => Op::Takeover {
            id: chron(r)?,
            authority: get_authority(r)?,
            current_epoch: epoch(r)?,
        },
        3 => Op::Announce {
            chronicle: chron(r)?,
            epoch: epoch(r)?,
            submission: hash(r)?,
            logical: hash(r)?,
            digest: hash(r)?,
            now: r.u64()?,
        },
        4 => Op::Accept {
            chronicle: chron(r)?,
            epoch: epoch(r)?,
            submission: hash(r)?,
            expected_head: get_head(r)?,
            pack: r.string()?,
            record: get_submitted(r)?,
            now: r.u64()?,
        },
        5 => Op::Cancel {
            chronicle: chron(r)?,
            epoch: epoch(r)?,
            submission: hash(r)?,
        },
        6 => Op::Obligation {
            chronicle: chron(r)?,
            op: r.u64()?,
            open: r.bool()?,
        },
        7 => Op::Pin {
            chronicle: chron(r)?,
            pinned: r.bool()?,
        },
        _ => return Err(JournalError("bad op tag")),
    })
}

pub(crate) fn put_transient(o: &mut Canon, t: &Transient) {
    match t {
        Transient::HeadMoved { head } => {
            o.tag(0);
            put_head(o, head);
        }
        Transient::NotReadable => {
            o.tag(1);
        }
        Transient::Pending { submission } => {
            o.tag(2).fixed(submission.as_bytes());
        }
    }
}

pub(crate) fn put_final(o: &mut Canon, f: &Final) {
    match f {
        Final::Conflict => {
            o.tag(0);
        }
        Final::StaleEpoch => {
            o.tag(1);
        }
        Final::NotAnnounced => {
            o.tag(2);
        }
        Final::Predicate(rule) => {
            o.tag(3).str(rule);
        }
        Final::Claimed(obj) => {
            o.tag(4);
            put_object(o, obj);
        }
        Final::Quarantined(obj) => {
            o.tag(5);
            put_object(o, obj);
        }
        Final::NoSuchObject(obj) => {
            o.tag(6);
            put_object(o, obj);
        }
        Final::Cancelled => {
            o.tag(7);
        }
        Final::Expired => {
            o.tag(8);
        }
    }
}

pub(crate) fn put_answer(o: &mut Canon, a: &Answer) {
    match a {
        Answer::Accepted {
            log_pos,
            logical_id,
        } => {
            o.tag(0).u64(*log_pos).fixed(logical_id.as_bytes());
        }
        Answer::AlreadyAccepted {
            log_pos,
            record_digest,
        } => {
            o.tag(1).u64(*log_pos).fixed(record_digest.as_bytes());
        }
        Answer::Refused(t) => {
            o.tag(2);
            put_transient(o, t);
        }
        Answer::FinalRefused(f) => {
            o.tag(3);
            put_final(o, f);
        }
    }
}

fn put_claim_error(o: &mut Canon, e: &ClaimError) {
    match e {
        ClaimError::AlreadyClaimed { epoch } => o.tag(0).u64(epoch.get()),
        ClaimError::BadAuthority => o.tag(1),
        ClaimError::Unknown => o.tag(2),
        ClaimError::EpochMoved { epoch } => o.tag(3).u64(epoch.get()),
    };
}

impl Done {
    /// Its canonical bytes: what replay compares.
    pub fn bytes(&self) -> Vec<u8> {
        let mut o = Canon::new();
        match self {
            Done::Sync(r) => {
                o.tag(0);
                match r {
                    Ok(e) => o.tag(0).u64(e.get()),
                    Err(e) => o.tag(1).u64(e.get()),
                };
            }
            Done::Claim(r) => {
                o.tag(1);
                match r {
                    Ok(e) => {
                        o.tag(0).u64(e.get());
                    }
                    Err(e) => {
                        o.tag(1);
                        put_claim_error(&mut o, e);
                    }
                }
            }
            Done::Takeover(r) => {
                o.tag(2);
                match r {
                    Ok((e, h)) => {
                        o.tag(0).u64(e.get());
                        put_head(&mut o, h);
                    }
                    Err(e) => {
                        o.tag(1);
                        put_claim_error(&mut o, e);
                    }
                }
            }
            Done::Announce(r) => {
                o.tag(3);
                match r {
                    Ok(()) => {
                        o.tag(0);
                    }
                    Err(a) => {
                        o.tag(1);
                        put_answer(&mut o, a);
                    }
                }
            }
            Done::Answer(a) => {
                o.tag(4);
                put_answer(&mut o, a);
            }
            Done::Unit => {
                o.tag(5);
            }
        }
        o.into_bytes()
    }
}

// ── Decoding answers (the coordinator's wire, `coordsrv`) ──────────

/// A rule name read back from the wire, owned.  The coordinator's rule
/// names are a fixed set; a name longer than 128 bytes is refused.
fn rule_name(r: &mut Rd<'_>) -> Result<std::borrow::Cow<'static, str>, JournalError> {
    let name = r.string()?;
    if name.len() > 128 {
        return Err(JournalError("rule name too long"));
    }
    Ok(name.into())
}

pub(crate) fn get_transient(r: &mut Rd<'_>) -> Result<Transient, JournalError> {
    Ok(match r.u8()? {
        0 => Transient::HeadMoved { head: get_head(r)? },
        1 => Transient::NotReadable,
        2 => Transient::Pending {
            submission: HashVal::from_bytes(r.fixed()?),
        },
        _ => return Err(JournalError("bad transient tag")),
    })
}

pub(crate) fn get_final(r: &mut Rd<'_>) -> Result<Final, JournalError> {
    Ok(match r.u8()? {
        0 => Final::Conflict,
        1 => Final::StaleEpoch,
        2 => Final::NotAnnounced,
        3 => Final::Predicate(rule_name(r)?),
        4 => Final::Claimed(get_object(r)?),
        5 => Final::Quarantined(get_object(r)?),
        6 => Final::NoSuchObject(get_object(r)?),
        7 => Final::Cancelled,
        8 => Final::Expired,
        _ => return Err(JournalError("bad final tag")),
    })
}

pub(crate) fn get_answer(r: &mut Rd<'_>) -> Result<Answer, JournalError> {
    Ok(match r.u8()? {
        0 => Answer::Accepted {
            log_pos: r.u64()?,
            logical_id: HashVal::from_bytes(r.fixed()?),
        },
        1 => Answer::AlreadyAccepted {
            log_pos: r.u64()?,
            record_digest: HashVal::from_bytes(r.fixed()?),
        },
        2 => Answer::Refused(get_transient(r)?),
        3 => Answer::FinalRefused(get_final(r)?),
        _ => return Err(JournalError("bad answer tag")),
    })
}

pub(crate) fn put_status(o: &mut Canon, s: &SubmissionStatus) {
    match s {
        SubmissionStatus::Accepted(p) => {
            o.tag(0).u64(*p);
        }
        SubmissionStatus::AbsentAtRead => {
            o.tag(1);
        }
        SubmissionStatus::FinalRefused(f) => {
            o.tag(2);
            put_final(o, f);
        }
    }
}

pub(crate) fn get_status(r: &mut Rd<'_>) -> Result<SubmissionStatus, JournalError> {
    Ok(match r.u8()? {
        0 => SubmissionStatus::Accepted(r.u64()?),
        1 => SubmissionStatus::AbsentAtRead,
        2 => SubmissionStatus::FinalRefused(get_final(r)?),
        _ => return Err(JournalError("bad status tag")),
    })
}

pub(crate) fn put_view(o: &mut Canon, v: &ChronicleView) {
    o.u64(v.epoch.get());
    put_head(o, &v.head);
    o.bool(v.retired);
    match &v.pending {
        None => o.tag(0),
        Some(s) => o.tag(1).fixed(s.as_bytes()),
    };
    o.u64(v.accepted.len() as u64);
    for p in &v.accepted {
        o.u64(*p);
    }
    o.u64(v.holds.len() as u64);
    for h in &v.holds {
        put_object(o, h);
    }
}

pub(crate) fn get_view(r: &mut Rd<'_>) -> Result<ChronicleView, JournalError> {
    Ok(ChronicleView {
        epoch: Epoch::new(r.u64()?),
        head: get_head(r)?,
        retired: r.bool()?,
        pending: match r.u8()? {
            0 => None,
            1 => Some(HashVal::from_bytes(r.fixed()?)),
            _ => return Err(JournalError("bad option tag")),
        },
        accepted: {
            let n = r.count()?;
            (0..n).map(|_| r.u64()).collect::<Result<_, _>>()?
        },
        holds: {
            let n = r.count()?;
            (0..n).map(|_| get_object(r)).collect::<Result<_, _>>()?
        },
    })
}

// ── Reading ─────────────────────────────────────────────────────────

pub(crate) struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    pub(crate) fn take(&mut self, n: u64) -> Result<&'a [u8], JournalError> {
        if n > (self.b.len() - self.pos) as u64 {
            return Err(JournalError("truncated"));
        }
        let s = &self.b[self.pos..self.pos + n as usize];
        self.pos += n as usize;
        Ok(s)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, JournalError> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn bool(&mut self) -> Result<bool, JournalError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(JournalError("bad bool")),
        }
    }
    pub(crate) fn u64(&mut self) -> Result<u64, JournalError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8")))
    }
    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], JournalError> {
        Ok(self.take(N as u64)?.try_into().expect("N"))
    }
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, JournalError> {
        let n = self.u64()?;
        Ok(self.take(n)?.to_vec())
    }
    pub(crate) fn string(&mut self) -> Result<String, JournalError> {
        String::from_utf8(self.bytes()?).map_err(|_| JournalError("not UTF-8"))
    }
    /// A count no larger than the bytes left (every item is ≥ 1 byte).
    pub(crate) fn count(&mut self) -> Result<u64, JournalError> {
        let n = self.u64()?;
        if n > (self.b.len() - self.pos) as u64 {
            return Err(JournalError("truncated"));
        }
        Ok(n)
    }
    pub(crate) fn finish(&self) -> Result<(), JournalError> {
        if self.pos == self.b.len() {
            Ok(())
        } else {
            Err(JournalError("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use taso_core::contract::{genesis_id, Consistency, GenesisStarted, Peer, TRANSFORM_VERSION};
    use taso_core::record::{Authority, LineageRecord, Namespace, Origin};

    fn h(n: u8) -> HashVal {
        HashVal::from_bytes([n; 32])
    }

    fn c(n: u8) -> ChronicleId {
        ChronicleId::from_bytes([n; 16])
    }

    fn every_op() -> Vec<Op> {
        let g = GenesisStarted {
            genesis_id: genesis_id(h(1), h(2), TRANSFORM_VERSION, Some("waived"), "jarmo"),
            source_key: h(1),
            consistency: Consistency::BestEffort,
            classmap_key: h(2),
            transform_version: TRANSFORM_VERSION,
            hook_waiver: Some("waived".into()),
            authority: Authority {
                actor: "jarmo".into(),
                reason: "why".into(),
            },
            peer: Peer { uid: 1, pid: 2 },
        };
        vec![
            Op::Sync {
                chronicle: c(1),
                epoch: Epoch::new(3),
                legacy: true,
            },
            Op::Claim {
                id: c(2),
                authority: ClaimAuthority::Sanction { commit: h(3) },
            },
            Op::Takeover {
                id: c(2),
                authority: ClaimAuthority::GenesisStarted,
                current_epoch: Epoch::new(4),
            },
            Op::Announce {
                chronicle: c(1),
                epoch: Epoch::FIRST,
                submission: h(4),
                logical: h(5),
                digest: h(6),
                now: 77,
            },
            Op::Accept {
                chronicle: c(1),
                epoch: Epoch::FIRST,
                submission: h(4),
                expected_head: Head {
                    pos: 9,
                    digest: h(7),
                },
                pack: "00000000000000000001-00000000000000000000-00000000000000000001".into(),
                record: Submitted::Contract(ContractRecord::GenesisStarted(Box::new(g))),
                now: 78,
            },
            Op::Accept {
                chronicle: c(3),
                epoch: Epoch::FIRST,
                submission: h(8),
                expected_head: Head::EMPTY,
                pack: "p".into(),
                record: Submitted::Birth {
                    chronicle: c(3),
                    lineage: LineageRecord {
                        origin: Origin::Void,
                        namespace: Namespace::from_bytes([1; 16]),
                        ledger_pos: Lsn::new(0),
                    },
                },
                now: 79,
            },
            Op::Cancel {
                chronicle: c(1),
                epoch: Epoch::FIRST,
                submission: h(4),
            },
            Op::Obligation {
                chronicle: c(1),
                op: LEGACY_OBLIGATION,
                open: true,
            },
            Op::Pin {
                chronicle: c(1),
                pinned: false,
            },
        ]
    }

    #[test]
    fn every_entry_round_trips_and_decoding_is_strict() {
        for (i, op) in every_op().into_iter().enumerate() {
            let e = Entry {
                op,
                calls: vec![i as u8; i],
                done: Done::Unit.bytes(),
            };
            let b = e.bytes();
            assert_eq!(Entry::decode(&b), Ok(e.clone()), "op {i}");
            assert!(Entry::decode(&b[..b.len() - 1]).is_err(), "truncated {i}");
            let mut longer = b.clone();
            longer.push(0);
            assert!(Entry::decode(&longer).is_err(), "trailing {i}");
        }
        let mut bad = Entry {
            op: Op::Pin {
                chronicle: c(1),
                pinned: true,
            },
            calls: vec![],
            done: vec![],
        }
        .bytes();
        bad[0] = 8;
        assert_eq!(Entry::decode(&bad), Err(JournalError("bad op tag")));
        bad[0] = 7;
        bad[17] = 2;
        assert_eq!(Entry::decode(&bad), Err(JournalError("bad bool")));
    }

    /// A store that answers yes to everything, with one inventory item.
    struct Yes;
    impl StoreView for Yes {
        fn carries(&self, _: ChronicleId, _: &str, _: HashVal) -> bool {
            true
        }
        fn exists(&self, _: &ObjectId) -> bool {
            true
        }
        fn inventory(&self, _: HashVal) -> Option<Inventory> {
            Some(Inventory::new(vec![]).unwrap())
        }
        fn fs_packs(&self, ch: ChronicleId) -> Option<Vec<InventoryItem>> {
            // Chronicle 7 cannot be listed; the rest list to nothing.
            (ch != c(7)).then(Vec::new)
        }
        fn seal_closure(&self, ch: ChronicleId, _: Lsn) -> Vec<ObjectId> {
            vec![
                ObjectId::pack(ch, "b"),
                ObjectId::content(h(1)),
                ObjectId::pack(ch, "a"),
            ]
        }
        fn verify_replacement(&self, _: ChronicleId, _: &InventoryItem) -> Option<HashVal> {
            Some(h(9))
        }
    }

    #[test]
    fn a_recording_replays_exactly_and_refuses_another_call() {
        let rec = Recorder::new(&Yes);
        assert!(rec.carries(c(1), "p", h(2)));
        assert!(rec.exists(&ObjectId::content(h(3))));
        assert_eq!(rec.inventory(h(4)), Some(Inventory::new(vec![]).unwrap()));
        let closure = rec.seal_closure(c(1), Lsn::new(5));
        assert_eq!(closure.len(), 3);
        assert_eq!(rec.fs_packs(c(1)), Some(Vec::new()));
        assert_eq!(rec.fs_packs(c(7)), None, "unlistable is recorded as such");
        let bytes = rec.into_bytes();

        let rep = Replayer::new(&bytes);
        assert!(rep.carries(c(1), "p", h(2)));
        assert!(rep.exists(&ObjectId::content(h(3))));
        assert_eq!(rep.inventory(h(4)), Some(Inventory::new(vec![]).unwrap()));
        assert_eq!(rep.seal_closure(c(1), Lsn::new(5)), closure, "order kept");
        assert_eq!(rep.fs_packs(c(1)), Some(Vec::new()));
        assert_eq!(rep.fs_packs(c(7)), None, "and replays as such");
        assert!(!rep.diverged.get());
        assert_eq!(rep.pos.get(), bytes.len());

        // Asked something else than was recorded: diverged, answers nothing.
        let rep = Replayer::new(&bytes);
        assert!(!rep.carries(c(1), "q", h(2)));
        assert!(rep.diverged.get());
        // Asked past the end: diverged.
        let rep = Replayer::new(&[]);
        assert!(!rep.exists(&ObjectId::content(h(3))));
        assert!(rep.diverged.get());
    }
}
