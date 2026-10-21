//! In-memory model for property testing (v1.0 §9.2, §12 P0).
//!
//! A simplified coordinator + Warden model that captures the
//! sealed-prefix transfer invariant without any I/O.  Two Wardens,
//! one coordinator, one Chronicle.
//!
//! The model is intentionally minimal: it exists so that property tests
//! can exercise the CAS + transfer interleaving before any runtime code
//! is written.  The adapter and fake provider are added in §9.3.
//!
//! Normative references: v0.4 §8, v1.0 §9.2, §12 P0.

use crate::envelope::{BranchId, ChronicleHead, ChronicleId, Epoch, HashVal, Lsn, Stream};
use crate::record::{Payload, Record};

// ── WardenId ────────────────────────────────────────────────────────

/// A Warden's identity in the model.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct WardenId(u64);

impl WardenId {
    /// Wrap a raw value.
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

// ── Ownership ───────────────────────────────────────────────────────

/// What the coordinator holds per Chronicle (v0.4 §8.1).
#[derive(Clone, Debug)]
pub struct Ownership {
    /// Current ownership epoch.
    pub epoch: Epoch,
    /// Which Warden currently holds this Chronicle.
    pub holder: WardenId,
    /// Last head accepted under the previous epoch.
    pub sealed_prefix: ChronicleHead,
}

// ── AppendError ─────────────────────────────────────────────────────

/// Why the coordinator refused an append.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppendError {
    /// The Warden is not the current holder.
    NotHolder {
        /// Who tried.
        warden: WardenId,
        /// Who actually holds it.
        holder: WardenId,
    },
    /// The epoch in the record doesn't match the current epoch.
    EpochMismatch {
        /// What the record carried.
        record_epoch: Epoch,
        /// What the coordinator has.
        current: Epoch,
    },
    /// The record's `prev` doesn't match the coordinator's anchored head.
    HeadMismatch {
        /// What the record pointed to.
        prev: HashVal,
        /// What the coordinator has.
        anchored: HashVal,
    },
}

// ── Shipped anchor ──────────────────────────────────────────────────

/// A position in the chain: an lsn and the hash of the record at it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// The lsn.
    pub lsn: Lsn,
    /// The record hash at it.
    pub hash: HashVal,
}

impl Anchor {
    /// Before the first record.
    pub const GENESIS: Self = Self {
        lsn: Lsn::new(0),
        hash: HashVal::GENESIS,
    };
}

/// Why the coordinator refused to advance the shipped anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShipError {
    /// The Warden is not the current holder.
    NotHolder {
        /// Who tried.
        warden: WardenId,
        /// Who actually holds it.
        holder: WardenId,
    },
    /// The Warden's epoch is not the current epoch.
    EpochMismatch {
        /// What the Warden said.
        epoch: Epoch,
        /// What the coordinator has.
        current: Epoch,
    },
    /// The position is past the anchored head: only accepted records can
    /// have been shipped.
    Ahead {
        /// What was reported.
        to: Lsn,
        /// The anchored head.
        head: Lsn,
    },
    /// The position names a record the coordinator knows to be another:
    /// at the head, or at the current shipped anchor.
    Conflict {
        /// Where.
        lsn: Lsn,
    },
}

/// Why the coordinator refused a conditional transfer: the ownership is
/// not the one the caller read.  Nothing changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnershipChanged {
    /// Who holds the Chronicle now.
    pub holder: WardenId,
    /// At which epoch.
    pub epoch: Epoch,
}

// ── Coordinator ─────────────────────────────────────────────────────

/// In-memory coordinator: ownership + anchored head + accepted log.
///
/// One coordinator per Chronicle.  In the real system this is a
/// single-node `redb` store (v1.0 §3); here it is a struct.
#[derive(Clone, Debug)]
pub struct Coordinator {
    chronicle: ChronicleId,
    ownership: Ownership,
    /// The anchored head — the authority (v0.4 §8.3).
    head: ChronicleHead,
    /// Every accepted record, in order.
    log: Vec<Record>,
    /// How far the log is known to be shipped off the node.
    shipped: Anchor,
}

impl Coordinator {
    /// Bootstrap a coordinator for a fresh Chronicle with an initial holder.
    pub fn new(chronicle: ChronicleId, initial_holder: WardenId) -> Self {
        let genesis_head = ChronicleHead {
            lsn: Lsn::new(0),
            hash: HashVal::GENESIS,
            epoch: Epoch::FIRST,
        };
        Self {
            chronicle,
            ownership: Ownership {
                epoch: Epoch::FIRST,
                holder: initial_holder,
                sealed_prefix: genesis_head,
            },
            head: genesis_head,
            log: Vec::new(),
            shipped: Anchor::GENESIS,
        }
    }

    /// The Chronicle this coordinator manages.
    pub fn chronicle(&self) -> ChronicleId {
        self.chronicle
    }

    /// Current ownership state.
    pub fn ownership(&self) -> &Ownership {
        &self.ownership
    }

    /// The anchored head (the authority, not a cache).
    pub fn head(&self) -> ChronicleHead {
        self.head
    }

    /// The full accepted log.
    pub fn log(&self) -> &[Record] {
        &self.log
    }

    /// CAS append (v0.4 §8.3).
    ///
    /// Accepts only when:
    /// 1. `warden` is the current holder,
    /// 2. the record's epoch matches the current epoch,
    /// 3. the record's `prev` matches the anchored head's hash.
    ///
    /// On success, advances the anchored head and appends the record
    /// to the log.
    pub fn append(
        &mut self,
        warden: WardenId,
        record: Record,
    ) -> Result<ChronicleHead, AppendError> {
        // 1. Holder check.
        if warden != self.ownership.holder {
            return Err(AppendError::NotHolder {
                warden,
                holder: self.ownership.holder,
            });
        }
        // 2. Epoch check.
        if record.envelope.epoch != self.ownership.epoch {
            return Err(AppendError::EpochMismatch {
                record_epoch: record.envelope.epoch,
                current: self.ownership.epoch,
            });
        }
        // 3. Head CAS.
        if record.envelope.prev != self.head.hash {
            return Err(AppendError::HeadMismatch {
                prev: record.envelope.prev,
                anchored: self.head.hash,
            });
        }
        // Accept: advance the anchored head.
        self.head = ChronicleHead {
            lsn: record.envelope.lsn,
            hash: record.envelope.hash,
            epoch: self.ownership.epoch,
        };
        self.log.push(record);
        Ok(self.head)
    }

    /// Atomic ownership transfer (v0.4 §8.2), conditional: it happens
    /// only if the ownership is exactly `expected` (holder, epoch) — the
    /// one the caller read before deciding.  A Warden may take only
    /// ownership it has read: a restart claims `(me, epoch)`, a takeover
    /// claims the holder it means to fence.  Two Wardens racing for the
    /// same ownership cannot both win, and a stale decision refuses
    /// itself (fencing review 2026-10-17, F1).
    ///
    /// On success as [`Coordinator::transfer`]; on refusal nothing changed
    /// and the current ownership is returned.
    pub fn transfer_if(
        &mut self,
        new_holder: WardenId,
        expected: (WardenId, Epoch),
    ) -> Result<Epoch, OwnershipChanged> {
        if (self.ownership.holder, self.ownership.epoch) != expected {
            return Err(OwnershipChanged {
                holder: self.ownership.holder,
                epoch: self.ownership.epoch,
            });
        }
        Ok(self.transfer(new_holder))
    }

    /// Atomic ownership transfer (v0.4 §8.2), unconditional.
    ///
    /// In one transaction:
    /// 1. `sealed_prefix = current head`,
    /// 2. `epoch += 1`,
    /// 3. `holder = new_holder`.
    ///
    /// Returns the new epoch.  The anchored head stays; it now belongs
    /// to the new epoch's Warden.
    ///
    /// For tests and tooling: a Warden deciding from what it read uses
    /// [`Coordinator::transfer_if`], since an unconditional transfer takes
    /// a Vessel back from whoever took it over in the meantime.
    pub fn transfer(&mut self, new_holder: WardenId) -> Epoch {
        self.ownership.sealed_prefix = self.head;
        self.ownership.epoch = self.ownership.epoch.next();
        self.ownership.holder = new_holder;
        // The anchored head's epoch must reflect the new epoch so that
        // new appends carry the right epoch.
        self.head = ChronicleHead {
            lsn: self.head.lsn,
            hash: self.head.hash,
            epoch: self.ownership.epoch,
        };
        self.ownership.epoch
    }

    /// How far the log is known to be shipped.
    pub fn shipped(&self) -> Anchor {
        self.shipped
    }

    /// The holder reports that the log up to `to` is durable in the
    /// object store.  The anchor only moves forward; a report at or below
    /// it changes nothing.
    ///
    /// Checks, in order: holder; epoch; `to` not past the head; at the
    /// head, `to` has the head's hash; at the current anchor, the anchor's
    /// hash.  Below the head the coordinator holds no record bodies, so
    /// it cannot check other hashes; the real one cannot either, and the
    /// model must not be stricter than the system it describes.
    pub fn advance_shipped(
        &mut self,
        warden: WardenId,
        epoch: Epoch,
        to: Anchor,
    ) -> Result<Anchor, ShipError> {
        if warden != self.ownership.holder {
            return Err(ShipError::NotHolder {
                warden,
                holder: self.ownership.holder,
            });
        }
        if epoch != self.ownership.epoch {
            return Err(ShipError::EpochMismatch {
                epoch,
                current: self.ownership.epoch,
            });
        }
        if to.lsn > self.head.lsn {
            return Err(ShipError::Ahead {
                to: to.lsn,
                head: self.head.lsn,
            });
        }
        if (to.lsn == self.head.lsn && to.hash != self.head.hash)
            || (to.lsn == self.shipped.lsn && to.hash != self.shipped.hash)
        {
            return Err(ShipError::Conflict { lsn: to.lsn });
        }
        if to.lsn > self.shipped.lsn {
            self.shipped = to;
        }
        Ok(self.shipped)
    }

    /// Records that a rebirth would use: everything up to and including
    /// the sealed prefix.
    ///
    /// In the real system this is "fetch Template, last Seal ≤ prefix,
    /// state-stream groups up to the prefix, the entire ledger and ctl"
    /// (v0.4 §8.4).  In the model, it is the log prefix up to
    /// `sealed_prefix.lsn`.
    pub fn rebirth_log(&self) -> &[Record] {
        let cutoff = self.ownership.sealed_prefix.lsn.get() as usize;
        // LSNs are 1-based; log indices are 0-based.
        let end = cutoff.min(self.log.len());
        &self.log[..end]
    }
}

// ── WardenModel ─────────────────────────────────────────────────────

/// A simplified Warden for the in-memory model.
///
/// Holds its own identity, the epoch it believes it is operating under,
/// and a local head.  Builds records locally, then submits them through
/// the coordinator's CAS.
#[derive(Clone, Debug)]
pub struct WardenModel {
    id: WardenId,
    chronicle: ChronicleId,
    branch: BranchId,
    epoch: Epoch,
    head: ChronicleHead,
    next_lsn: Lsn,
}

impl WardenModel {
    /// Create a Warden model that starts at the genesis of a Chronicle.
    pub fn new(id: WardenId, chronicle: ChronicleId, epoch: Epoch) -> Self {
        Self {
            id,
            chronicle,
            branch: BranchId::TRUNK,
            epoch,
            head: ChronicleHead {
                lsn: Lsn::new(0),
                hash: HashVal::GENESIS,
                epoch,
            },
            next_lsn: Lsn::new(1),
        }
    }

    /// Create a Warden model that continues from an existing head.
    pub fn resume(
        id: WardenId,
        chronicle: ChronicleId,
        epoch: Epoch,
        head: ChronicleHead,
        next_lsn: Lsn,
    ) -> Self {
        Self {
            id,
            chronicle,
            branch: BranchId::TRUNK,
            epoch,
            head,
            next_lsn,
        }
    }

    /// This Warden's identity.
    pub fn id(&self) -> WardenId {
        self.id
    }

    /// The epoch this Warden believes it is operating under.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Build a record locally and submit it through the coordinator.
    ///
    /// On success, advances the local head and lsn.
    /// On failure, the local state is unchanged.
    pub fn append(
        &mut self,
        coord: &mut Coordinator,
        stream: Stream,
        payload: Payload,
    ) -> Result<ChronicleHead, AppendError> {
        let record = Record::new(
            self.chronicle,
            self.branch,
            self.epoch,
            stream,
            self.next_lsn,
            self.head.hash,
            payload,
        );
        let new_head = coord.append(self.id, record)?;
        self.head = new_head;
        self.next_lsn = self.next_lsn.next();
        Ok(new_head)
    }

    /// Build a record locally but do NOT submit it yet.
    ///
    /// Used to model the interleaving where a Warden builds a record,
    /// then a transfer happens, then it tries to submit the stale record.
    pub fn build_record(&self, stream: Stream, payload: Payload) -> Record {
        Record::new(
            self.chronicle,
            self.branch,
            self.epoch,
            stream,
            self.next_lsn,
            self.head.hash,
            payload,
        )
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cid() -> ChronicleId {
        ChronicleId::from_bytes([1; 16])
    }
    fn warden_a() -> WardenId {
        WardenId::new(1)
    }
    fn warden_b() -> WardenId {
        WardenId::new(2)
    }

    fn raw(data: &[u8]) -> Payload {
        Payload::Raw(data.to_vec())
    }

    /// Helper: set up a coordinator and two Wardens.
    fn setup() -> (Coordinator, WardenModel, WardenModel) {
        let c = Coordinator::new(cid(), warden_a());
        let a = WardenModel::new(warden_a(), cid(), Epoch::FIRST);
        let b = WardenModel::new(warden_b(), cid(), Epoch::FIRST);
        (c, a, b)
    }

    // ── Deterministic tests ─────────────────────────────────────────

    #[test]
    fn basic_append_succeeds() {
        let (mut coord, mut a, _b) = setup();
        let result = a.append(&mut coord, Stream::Fs, raw(b"hello"));
        assert!(result.is_ok());
        assert_eq!(coord.log().len(), 1);
        assert_eq!(coord.head().lsn, Lsn::new(1));
    }

    #[test]
    fn chained_appends_succeed() {
        let (mut coord, mut a, _b) = setup();
        a.append(&mut coord, Stream::Fs, raw(b"one")).unwrap();
        a.append(&mut coord, Stream::Db, raw(b"two")).unwrap();
        a.append(&mut coord, Stream::Fs, raw(b"three")).unwrap();
        assert_eq!(coord.log().len(), 3);
        assert_eq!(coord.head().lsn, Lsn::new(3));
        // Chain is linked.
        assert_eq!(coord.log()[1].envelope.prev, coord.log()[0].envelope.hash);
        assert_eq!(coord.log()[2].envelope.prev, coord.log()[1].envelope.hash);
    }

    #[test]
    fn cas_rejects_wrong_holder() {
        let (mut coord, _a, mut b) = setup();
        // B is not the holder (A is).
        let result = b.append(&mut coord, Stream::Fs, raw(b"intruder"));
        assert!(matches!(result, Err(AppendError::NotHolder { .. })));
        assert_eq!(coord.log().len(), 0);
    }

    #[test]
    fn cas_rejects_stale_head() {
        let (mut coord, mut a, _b) = setup();
        // A appends one record.
        a.append(&mut coord, Stream::Fs, raw(b"first")).unwrap();
        // Build a record from a stale head (manually).
        let stale = Record::new(
            cid(),
            BranchId::TRUNK,
            Epoch::FIRST,
            Stream::Fs,
            Lsn::new(2),
            HashVal::GENESIS, // stale: points to genesis, not to record 1
            raw(b"stale"),
        );
        let result = coord.append(warden_a(), stale);
        assert!(matches!(result, Err(AppendError::HeadMismatch { .. })));
    }

    #[test]
    fn cas_rejects_wrong_epoch() {
        let (mut coord, _a, _b) = setup();
        // Build a record with epoch 99.
        let record = Record::new(
            cid(),
            BranchId::TRUNK,
            Epoch::new(99),
            Stream::Fs,
            Lsn::new(1),
            HashVal::GENESIS,
            raw(b"wrong epoch"),
        );
        let result = coord.append(warden_a(), record);
        assert!(matches!(result, Err(AppendError::EpochMismatch { .. })));
    }

    #[test]
    fn transfer_updates_ownership() {
        let (mut coord, mut a, _b) = setup();
        // A writes 3 records.
        a.append(&mut coord, Stream::Fs, raw(b"one")).unwrap();
        a.append(&mut coord, Stream::Fs, raw(b"two")).unwrap();
        a.append(&mut coord, Stream::Fs, raw(b"three")).unwrap();

        let head_before = coord.head();
        let new_epoch = coord.transfer(warden_b());

        assert_eq!(new_epoch, Epoch::new(2));
        assert_eq!(coord.ownership().holder, warden_b());
        assert_eq!(coord.ownership().epoch, Epoch::new(2));
        // Sealed prefix is where the old holder left off.
        assert_eq!(coord.ownership().sealed_prefix.lsn, head_before.lsn,);
        assert_eq!(coord.ownership().sealed_prefix.hash, head_before.hash,);
    }

    /// F1: A reads the ownership, B takes over in between, A's claim is
    /// refused with the current ownership and changes nothing; B keeps
    /// appending.  A claim on the current ownership wins, once.
    #[test]
    fn transfer_if_takes_only_what_was_read() {
        let (mut coord, mut a, _b) = setup();
        a.append(&mut coord, Stream::Fs, raw(b"one")).unwrap();
        let read = (coord.ownership().holder, coord.ownership().epoch);
        assert_eq!(read, (warden_a(), Epoch::FIRST));

        // B takes over (as the operator asked), from what B read.
        let e2 = coord.transfer_if(warden_b(), read).unwrap();
        assert_eq!(e2, Epoch::new(2));
        let mut b = WardenModel::resume(
            warden_b(),
            cid(),
            e2,
            coord.head(),
            Lsn::new(coord.head().lsn.get() + 1),
        );
        b.append(&mut coord, Stream::Fs, raw(b"two")).unwrap();

        // A restarts on its stale read: refused, nothing moved.
        let head_before = coord.head();
        assert_eq!(
            coord.transfer_if(warden_a(), read),
            Err(OwnershipChanged {
                holder: warden_b(),
                epoch: Epoch::new(2)
            })
        );
        assert_eq!(coord.ownership().holder, warden_b());
        assert_eq!(coord.ownership().epoch, Epoch::new(2));
        assert_eq!(coord.head(), head_before);
        b.append(&mut coord, Stream::Fs, raw(b"three")).unwrap();

        // The same claim cannot win twice: B's own restart moves the epoch.
        let now = (warden_b(), Epoch::new(2));
        assert_eq!(coord.transfer_if(warden_b(), now), Ok(Epoch::new(3)));
        assert_eq!(
            coord.transfer_if(warden_b(), now),
            Err(OwnershipChanged {
                holder: warden_b(),
                epoch: Epoch::new(3)
            })
        );
        // Equal to transfer in effect: sealed prefix at the head.
        assert_eq!(coord.ownership().sealed_prefix.lsn, coord.head().lsn);
    }

    #[test]
    fn old_warden_cas_after_transfer_rejected() {
        let (mut coord, mut a, _b) = setup();
        // A writes a record.
        a.append(&mut coord, Stream::Fs, raw(b"before transfer"))
            .unwrap();

        // Transfer to B.
        coord.transfer(warden_b());

        // A still thinks it's the holder — its append must fail.
        let result = a.append(&mut coord, Stream::Fs, raw(b"after transfer"));
        // Fails on either NotHolder or EpochMismatch (both are correct
        // refusals; the order of checks is an implementation detail).
        assert!(result.is_err());
        // The log has only the one record from before transfer.
        assert_eq!(coord.log().len(), 1);
    }

    #[test]
    fn old_warden_prebuilt_record_after_transfer_rejected() {
        let (mut coord, mut a, _b) = setup();
        // A writes a record.
        a.append(&mut coord, Stream::Fs, raw(b"before")).unwrap();

        // A builds a record BEFORE transfer (has the right prev hash).
        let prebuilt = a.build_record(Stream::Fs, raw(b"prebuilt"));
        assert_eq!(prebuilt.envelope.prev, coord.head().hash);

        // Transfer to B.
        coord.transfer(warden_b());

        // A submits the prebuilt record — must be rejected even though
        // its prev hash matches.
        let result = coord.append(warden_a(), prebuilt);
        assert!(result.is_err());
    }

    #[test]
    fn new_warden_appends_after_transfer() {
        let (mut coord, mut a, _b) = setup();
        // A writes 2 records.
        a.append(&mut coord, Stream::Fs, raw(b"one")).unwrap();
        a.append(&mut coord, Stream::Fs, raw(b"two")).unwrap();

        // Transfer to B.
        let new_epoch = coord.transfer(warden_b());

        // B resumes from the current head.
        let mut b = WardenModel::resume(
            warden_b(),
            cid(),
            new_epoch,
            coord.head(),
            Lsn::new(coord.head().lsn.get() + 1),
        );

        // B appends successfully.
        let result = b.append(&mut coord, Stream::Fs, raw(b"three"));
        assert!(result.is_ok());
        assert_eq!(coord.log().len(), 3);
        assert_eq!(coord.head().epoch, new_epoch);
    }

    #[test]
    fn rebirth_log_contains_sealed_prefix() {
        let (mut coord, mut a, _b) = setup();
        // A writes 3 records.
        a.append(&mut coord, Stream::Fs, raw(b"one")).unwrap();
        a.append(&mut coord, Stream::Fs, raw(b"two")).unwrap();
        a.append(&mut coord, Stream::Fs, raw(b"three")).unwrap();

        // Transfer to B.
        let new_epoch = coord.transfer(warden_b());

        // B writes 2 more records.
        let mut b = WardenModel::resume(warden_b(), cid(), new_epoch, coord.head(), Lsn::new(4));
        b.append(&mut coord, Stream::Fs, raw(b"four")).unwrap();
        b.append(&mut coord, Stream::Fs, raw(b"five")).unwrap();

        // Total log: 5 records.
        assert_eq!(coord.log().len(), 5);
        // Rebirth log: only the first 3 (the sealed prefix).
        let rebirth = coord.rebirth_log();
        assert_eq!(rebirth.len(), 3);
        // All rebirth records are from epoch 1.
        for r in rebirth {
            assert_eq!(r.envelope.epoch, Epoch::FIRST);
        }
    }

    #[test]
    fn rebirth_log_empty_before_first_transfer() {
        let (mut coord, mut a, _b) = setup();
        a.append(&mut coord, Stream::Fs, raw(b"one")).unwrap();
        a.append(&mut coord, Stream::Fs, raw(b"two")).unwrap();
        // No transfer has happened; sealed prefix is genesis (lsn 0).
        let rebirth = coord.rebirth_log();
        assert_eq!(rebirth.len(), 0);
    }

    #[test]
    fn double_transfer() {
        let (mut coord, mut a, _b) = setup();
        // A writes 2 records.
        a.append(&mut coord, Stream::Fs, raw(b"one")).unwrap();
        a.append(&mut coord, Stream::Fs, raw(b"two")).unwrap();

        // Transfer A → B.
        let epoch2 = coord.transfer(warden_b());
        let _sealed_after_first = coord.ownership().sealed_prefix;

        // B writes 1 record.
        let mut b = WardenModel::resume(warden_b(), cid(), epoch2, coord.head(), Lsn::new(3));
        b.append(&mut coord, Stream::Fs, raw(b"three")).unwrap();

        // Transfer B → A.
        let epoch3 = coord.transfer(warden_a());
        assert_eq!(epoch3, Epoch::new(3));

        // Sealed prefix now includes B's record.
        assert_eq!(coord.ownership().sealed_prefix.lsn, Lsn::new(3));

        // A resumes.
        let mut a2 = WardenModel::resume(warden_a(), cid(), epoch3, coord.head(), Lsn::new(4));
        a2.append(&mut coord, Stream::Fs, raw(b"four")).unwrap();

        // Rebirth log includes all 3 records up to second sealed prefix.
        let rebirth = coord.rebirth_log();
        assert_eq!(rebirth.len(), 3);

        // B is now fenced.
        let result = b.append(&mut coord, Stream::Fs, raw(b"fenced"));
        assert!(result.is_err());
    }

    #[test]
    fn accepted_records_all_verify() {
        let (mut coord, mut a, _b) = setup();
        for i in 0..10 {
            a.append(
                &mut coord,
                Stream::Fs,
                raw(format!("record-{i}").as_bytes()),
            )
            .unwrap();
        }
        for r in coord.log() {
            assert!(
                r.verify(),
                "record at lsn {} failed verify",
                r.envelope.lsn.get()
            );
        }
    }

    // ── Property test ───────────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        /// An operation in the random schedule.
        #[derive(Clone, Debug)]
        enum Op {
            /// Warden A appends a record.
            AppendA,
            /// Warden B appends a record.
            AppendB,
            /// Transfer ownership to A.
            TransferA,
            /// Transfer ownership to B.
            TransferB,
        }

        fn op_strategy() -> impl Strategy<Value = Op> {
            prop_oneof![
                6 => Just(Op::AppendA),
                6 => Just(Op::AppendB),
                1 => Just(Op::TransferA),
                1 => Just(Op::TransferB),
            ]
        }

        proptest! {
            #[test]
            fn sealed_prefix_invariant(
                ops in proptest::collection::vec(op_strategy(), 1..100)
            ) {
                let mut coord = Coordinator::new(cid(), warden_a());
                let mut a = WardenModel::new(warden_a(), cid(), Epoch::FIRST);
                let mut b = WardenModel::new(warden_b(), cid(), Epoch::FIRST);
                let mut seq = 0u64;

                for op in &ops {
                    seq += 1;
                    match op {
                        Op::AppendA => {
                            let _ = a.append(
                                &mut coord,
                                Stream::Fs,
                                raw(format!("a-{seq}").as_bytes()),
                            );
                            // Failure is fine — A may be fenced.
                        }
                        Op::AppendB => {
                            let _ = b.append(
                                &mut coord,
                                Stream::Fs,
                                raw(format!("b-{seq}").as_bytes()),
                            );
                        }
                        Op::TransferA => {
                            let new_epoch = coord.transfer(warden_a());
                            a = WardenModel::resume(
                                warden_a(),
                                cid(),
                                new_epoch,
                                coord.head(),
                                Lsn::new(coord.head().lsn.get() + 1),
                            );
                        }
                        Op::TransferB => {
                            let new_epoch = coord.transfer(warden_b());
                            b = WardenModel::resume(
                                warden_b(),
                                cid(),
                                new_epoch,
                                coord.head(),
                                Lsn::new(coord.head().lsn.get() + 1),
                            );
                        }
                    }
                }

                // ── Invariant: rebirth log ⊆ sealed prefix ────────
                let rebirth = coord.rebirth_log();
                let sealed_lsn = coord.ownership().sealed_prefix.lsn.get();

                // Every record in the rebirth log is within the sealed
                // prefix.
                for r in rebirth {
                    prop_assert!(
                        r.envelope.lsn.get() <= sealed_lsn,
                        "rebirth contains record at lsn {} but sealed prefix is at {}",
                        r.envelope.lsn.get(),
                        sealed_lsn,
                    );
                }

                // The rebirth log is exactly the accepted records up to
                // the sealed prefix — no gaps, no extras.
                let expected_len = coord.log().iter()
                    .filter(|r| r.envelope.lsn.get() <= sealed_lsn)
                    .count();
                prop_assert_eq!(
                    rebirth.len(),
                    expected_len,
                    "rebirth log length mismatch: got {} but {} records are at or below sealed prefix lsn {}",
                    rebirth.len(),
                    expected_len,
                    sealed_lsn,
                );

                // ── Invariant: every accepted record verifies ─────
                for r in coord.log() {
                    prop_assert!(
                        r.verify(),
                        "accepted record at lsn {} failed verify",
                        r.envelope.lsn.get(),
                    );
                }

                // ── Invariant: the chain is linked ────────────────
                let log = coord.log();
                for i in 1..log.len() {
                    prop_assert_eq!(
                        log[i].envelope.prev,
                        log[i - 1].envelope.hash,
                        "chain break between lsn {} and {}",
                        log[i - 1].envelope.lsn.get(),
                        log[i].envelope.lsn.get(),
                    );
                }
            }
        }
    }
}
