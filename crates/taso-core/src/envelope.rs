//! Envelope: identities, the hash chain, and record authentication.
//!
//! Every record in a Chronicle carries an [`Envelope`] that binds its
//! content to its position in the chain.  The hash chain uses BLAKE3 in
//! derive-key mode with domain-separation strings so that payload hashes
//! and record hashes can never collide (v0.4 §4).
//!
//! The authenticated structure covers `(chronicle, branch, epoch, stream,
//! lsn, prev, payload_hash)` in canonical encoding.  Epoch is included so
//! that a record written under an old epoch and a record at the same lsn
//! under the new epoch are distinct: even if the old Warden's CAS lands
//! on the store after transfer, a replayer following the sealed prefix
//! cannot be fooled into accepting it on hash alone (v0.4 §8.3).

use crate::canon::{Canon, Canonical};

// ── Hash ────────────────────────────────────────────────────────────

/// A BLAKE3 hash value (32 bytes).
///
/// [`HashVal::GENESIS`] is the conventional "previous hash" for the first
/// record in a chain.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HashVal([u8; 32]);

impl HashVal {
    /// The genesis hash: 32 zero bytes.  Used as `prev` for record 1.
    pub const GENESIS: Self = Self([0u8; 32]);

    /// Wrap raw bytes.
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// The raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Canonical for HashVal {
    fn canon(&self, out: &mut Canon) {
        out.fixed(&self.0);
    }
}

impl std::fmt::Debug for HashVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash({})", self)
    }
}

impl std::fmt::Display for HashVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// ── ChronicleId ─────────────────────────────────────────────────────

/// A Chronicle's unique identity (128-bit, random or assigned).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ChronicleId([u8; 16]);

impl ChronicleId {
    /// Wrap raw bytes.
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    /// The raw 16 bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Canonical for ChronicleId {
    fn canon(&self, out: &mut Canon) {
        out.fixed(&self.0);
    }
}

// ── BranchId ────────────────────────────────────────────────────────

/// A branch within a Chronicle.
///
/// Branch 0 is the trunk; forks create new branch ids.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BranchId(u64);

impl BranchId {
    /// The trunk (main line).
    pub const TRUNK: Self = Self(0);

    /// Wrap a raw id.
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Canonical for BranchId {
    fn canon(&self, out: &mut Canon) {
        out.u64(self.0);
    }
}

// ── Epoch ───────────────────────────────────────────────────────────

/// An ownership epoch.
///
/// Incremented by the coordinator on every ownership transfer (v0.4 §8).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Epoch(u64);

impl Epoch {
    /// The first epoch.
    pub const FIRST: Self = Self(1);

    /// Wrap a raw value.
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next epoch after this one.
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl Canonical for Epoch {
    fn canon(&self, out: &mut Canon) {
        out.u64(self.0);
    }
}

// ── Lsn ─────────────────────────────────────────────────────────────

/// A log sequence number: the position of a record in its Chronicle,
/// counted from 1 across all streams (each record takes the next one).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Lsn(u64);

impl Lsn {
    /// Wrap a raw value.
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next LSN.
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl Canonical for Lsn {
    fn canon(&self, out: &mut Canon) {
        out.u64(self.0);
    }
}

// ── Stream ──────────────────────────────────────────────────────────

/// A named stream within a Chronicle.
///
/// State streams (`Fs`, `Db`, `Transcript`) are cut by Seals and can be
/// reverted.  The effect ledger (`Effect`) and control stream (`Ctl`) are
/// never reverted (v0.4 §5.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Stream {
    /// Filesystem state.
    Fs = 0,
    /// Database state.
    Db = 1,
    /// Agent transcript.
    Transcript = 2,
    /// Effect ledger (intents, outcomes, barriers).  Never reverted.
    Effect = 3,
    /// Control records (ownership changes, rebirth markers).  Never reverted.
    Ctl = 4,
}

impl Stream {
    /// True for state streams: `Fs`, `Db`, `Transcript`.  These are cut
    /// by Seals and may be reverted.
    pub const fn is_state(self) -> bool {
        matches!(self, Self::Fs | Self::Db | Self::Transcript)
    }

    /// True for streams that are never reverted: `Effect` and `Ctl`.
    pub const fn is_ledger(self) -> bool {
        matches!(self, Self::Effect | Self::Ctl)
    }
}

impl Canonical for Stream {
    fn canon(&self, out: &mut Canon) {
        out.tag(*self as u8);
    }
}

// ── ChronicleHead ───────────────────────────────────────────────────

/// What the coordinator anchors for each Chronicle (v0.4 §4).
///
/// The coordinator advances this on every accepted append, and transfer
/// sets the sealed prefix to the current head.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChronicleHead {
    /// The highest accepted LSN.
    pub lsn: Lsn,
    /// The hash of the record at that LSN.
    pub hash: HashVal,
    /// The current ownership epoch.
    pub epoch: Epoch,
}

impl Canonical for ChronicleHead {
    fn canon(&self, out: &mut Canon) {
        self.lsn.canon(out);
        self.hash.canon(out);
        self.epoch.canon(out);
    }
}

// ── Domain strings ──────────────────────────────────────────────────

/// Domain string for payload hashing.
const PAYLOAD_DOMAIN: &str = "taso.chronicle.payload.v2";

/// Domain string for record hashing.
const RECORD_DOMAIN: &str = "taso.chronicle.record.v1";

/// Hash a payload's raw bytes under the payload domain.
///
/// This is a separate domain from the record hash, so a payload that
/// happens to equal some record's canonical encoding still produces a
/// different hash.
pub fn payload_hash(data: &[u8]) -> HashVal {
    let h = blake3::derive_key(PAYLOAD_DOMAIN, data);
    HashVal(h)
}

// ── Envelope ────────────────────────────────────────────────────────

/// The authenticated structure around every Chronicle record.
///
/// An envelope binds a record's payload to its position in the chain by
/// hashing all positional fields together with the payload hash and the
/// previous record's hash.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Envelope {
    /// Which Chronicle this record belongs to.
    pub chronicle: ChronicleId,
    /// Which branch within the Chronicle.
    pub branch: BranchId,
    /// The ownership epoch at the time of writing.
    pub epoch: Epoch,
    /// Which stream this record lives in.
    pub stream: Stream,
    /// This record's sequence number.
    pub lsn: Lsn,
    /// Hash of the previous record, or [`HashVal::GENESIS`] for the first.
    pub prev: HashVal,
    /// Hash of this record's payload bytes.
    pub payload_hash: HashVal,
    /// The chained hash binding all the above.
    pub hash: HashVal,
}

impl Envelope {
    /// Construct an envelope, computing its chained hash.
    ///
    /// `payload_hash` should be produced by [`payload_hash()`] so the two
    /// domains cannot collide.
    pub fn new(
        chronicle: ChronicleId,
        branch: BranchId,
        epoch: Epoch,
        stream: Stream,
        lsn: Lsn,
        prev: HashVal,
        payload_hash: HashVal,
    ) -> Self {
        let hash = record_hash(chronicle, branch, epoch, stream, lsn, prev, payload_hash);
        Self {
            chronicle,
            branch,
            epoch,
            stream,
            lsn,
            prev,
            payload_hash,
            hash,
        }
    }

    /// Recompute the hash and check it matches.
    pub fn verify(&self) -> bool {
        let expected = record_hash(
            self.chronicle,
            self.branch,
            self.epoch,
            self.stream,
            self.lsn,
            self.prev,
            self.payload_hash,
        );
        self.hash == expected
    }

    /// The [`ChronicleHead`] this record would advance to.
    pub fn head(&self) -> ChronicleHead {
        ChronicleHead {
            lsn: self.lsn,
            hash: self.hash,
            epoch: self.epoch,
        }
    }
}

/// Compute the record hash over canonical-encoded fields.
fn record_hash(
    chronicle: ChronicleId,
    branch: BranchId,
    epoch: Epoch,
    stream: Stream,
    lsn: Lsn,
    prev: HashVal,
    ph: HashVal,
) -> HashVal {
    let mut c = Canon::new();
    chronicle.canon(&mut c);
    branch.canon(&mut c);
    epoch.canon(&mut c);
    stream.canon(&mut c);
    lsn.canon(&mut c);
    prev.canon(&mut c);
    ph.canon(&mut c);
    let h = blake3::derive_key(RECORD_DOMAIN, c.as_bytes());
    HashVal(h)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chronicle() -> ChronicleId {
        ChronicleId::from_bytes([1; 16])
    }

    fn make_chain(n: usize) -> Vec<Envelope> {
        let cid = test_chronicle();
        let mut chain = Vec::new();
        let mut prev = HashVal::GENESIS;
        for i in 0..n {
            let ph = payload_hash(format!("payload-{i}").as_bytes());
            let env = Envelope::new(
                cid,
                BranchId::TRUNK,
                Epoch::FIRST,
                Stream::Fs,
                Lsn::new(i as u64 + 1),
                prev,
                ph,
            );
            prev = env.hash;
            chain.push(env);
        }
        chain
    }

    #[test]
    fn genesis_chain_verifies() {
        let chain = make_chain(3);
        for env in &chain {
            assert!(
                env.verify(),
                "record at lsn {} failed verify",
                env.lsn.get()
            );
        }
        // Chain is linked: each record's prev is the prior's hash.
        assert_eq!(chain[0].prev, HashVal::GENESIS);
        assert_eq!(chain[1].prev, chain[0].hash);
        assert_eq!(chain[2].prev, chain[1].hash);
    }

    #[test]
    fn flipping_chronicle_breaks_verify() {
        let mut env = make_chain(1).pop().unwrap();
        env.chronicle = ChronicleId::from_bytes([99; 16]);
        assert!(!env.verify());
    }

    #[test]
    fn flipping_branch_breaks_verify() {
        let mut env = make_chain(1).pop().unwrap();
        env.branch = BranchId::new(42);
        assert!(!env.verify());
    }

    #[test]
    fn flipping_epoch_breaks_verify() {
        let mut env = make_chain(1).pop().unwrap();
        env.epoch = Epoch::new(999);
        assert!(!env.verify());
    }

    #[test]
    fn flipping_stream_breaks_verify() {
        let mut env = make_chain(1).pop().unwrap();
        env.stream = Stream::Effect;
        assert!(!env.verify());
    }

    #[test]
    fn flipping_lsn_breaks_verify() {
        let mut env = make_chain(1).pop().unwrap();
        env.lsn = Lsn::new(9999);
        assert!(!env.verify());
    }

    #[test]
    fn flipping_prev_breaks_verify() {
        let mut env = make_chain(1).pop().unwrap();
        env.prev = HashVal::from_bytes([0xff; 32]);
        assert!(!env.verify());
    }

    #[test]
    fn flipping_payload_hash_breaks_verify() {
        let mut env = make_chain(1).pop().unwrap();
        env.payload_hash = payload_hash(b"tampered");
        assert!(!env.verify());
    }

    #[test]
    fn payload_and_record_domains_do_not_collide() {
        // Build the canonical encoding of a record's fields, then hash it
        // as a payload.  The result must differ from the actual record hash
        // on the same fields — that's domain separation at work.
        let mut c = Canon::new();
        test_chronicle().canon(&mut c);
        BranchId::TRUNK.canon(&mut c);
        Epoch::FIRST.canon(&mut c);
        Stream::Fs.canon(&mut c);
        Lsn::new(1).canon(&mut c);
        HashVal::GENESIS.canon(&mut c);
        HashVal::GENESIS.canon(&mut c);

        let as_payload = payload_hash(c.as_bytes());
        let as_record = record_hash(
            test_chronicle(),
            BranchId::TRUNK,
            Epoch::FIRST,
            Stream::Fs,
            Lsn::new(1),
            HashVal::GENESIS,
            HashVal::GENESIS,
        );
        assert_ne!(
            as_payload, as_record,
            "domain separation must prevent collisions"
        );
    }

    #[test]
    fn head_reflects_envelope() {
        let env = make_chain(1).pop().unwrap();
        let head = env.head();
        assert_eq!(head.lsn, env.lsn);
        assert_eq!(head.hash, env.hash);
        assert_eq!(head.epoch, env.epoch);
    }

    #[test]
    fn hash_display_is_lowercase_hex() {
        let h = HashVal::from_bytes([0xab; 32]);
        let s = format!("{h}");
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(&s[..4], "abab");
    }

    #[test]
    fn stream_classification() {
        assert!(Stream::Fs.is_state());
        assert!(Stream::Db.is_state());
        assert!(Stream::Transcript.is_state());
        assert!(!Stream::Effect.is_state());
        assert!(!Stream::Ctl.is_state());

        assert!(!Stream::Fs.is_ledger());
        assert!(!Stream::Db.is_ledger());
        assert!(!Stream::Transcript.is_ledger());
        assert!(Stream::Effect.is_ledger());
        assert!(Stream::Ctl.is_ledger());
    }

    #[test]
    fn distinct_payloads_produce_distinct_hashes() {
        let h1 = payload_hash(b"alpha");
        let h2 = payload_hash(b"beta");
        assert_ne!(h1, h2);
    }

    #[test]
    fn epoch_ordering() {
        assert!(Epoch::new(1) < Epoch::new(2));
        assert_eq!(Epoch::FIRST.next(), Epoch::new(2));
    }
}
