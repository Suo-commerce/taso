//! Rebirth: a Vessel whose node is gone continues on this one, from what
//! was shipped and anchored (v1.0 §1 P2; v0.4 §8).
//!
//! # Order
//!
//! 1. **Fence.**  Take ownership ([`crate::coordinator::Coord::transfer`]) before reading
//!    anything.  A previous holder still alive can then no longer append
//!    or move the shipped anchor, so the anchor read next stays the anchor
//!    for the whole rebirth, and a retry reads the same one.
//! 2. **Chain.**  The shipped anchor, and [`Packs::chain`] up to it: the
//!    verified frames, and the `fs` sections an `FsShipped` record names.
//!    Records the anchor does not cover are lost, and so is any Seal whose
//!    section was never named.
//! 3. **Dataset.**  Receive the sections in order: the first is a full
//!    stream (born from the void) or an incremental from the parent's Seal
//!    snapshot, which must already be on this node (a Template); each
//!    later one is incremental from the one before.  With no section
//!    shipped, the dataset is what it was born as: empty, or a clone of
//!    the parent's Seal.  Each stream is checked against its `FsShipped`
//!    record as it is read, and every received snapshot's guid against the
//!    chain.
//! 4. **Log.**  [`restore_log`] writes the frames into the state
//!    directory, in segment files joined as on any node.
//! 5. **Open.**  [`crate::chronicle::Chronicle::open_after_gap`] through the Host: a new
//!    epoch, a Gap record for the records past the anchor, every check of
//!    an ordinary open, and the Seals whose layer did not come with it
//!    reported missing.
//!
//! Effect authority is not granted here: dispatching needs
//! [`crate::effects::Effects::open`], which reconciles every open intent
//! first (v0.4 §7.2, §8.4).  The dataset is at the last *anchored, named*
//! Seal; per v0.4 §8.5 the first Seal after a rebirth should be
//! `Unverified`.
//!
//! # Interruption
//!
//! Each step can be repeated.  Receiving a snapshot that is already there
//! binds and returns; the log is restored by an atomic rename, and a
//! complete one is left alone; the open re-verifies everything.  A
//! dataset or state directory that is *not* this chain's rebirth in
//! progress is refused, never overwritten.
//!
//! Normative references: v1.0 §1 (P2); v0.4 §8.2–8.5.

use std::fmt;

use taso_core::envelope::{ChronicleId, Epoch, Lsn};
use taso_core::record::{LineageRecord, Origin, ParentSeal, Payload};

use crate::chronicle::{restore_log, Chronicle, ChronicleError, Claim, Layers};
use crate::pack::{FsBase, Packs};
use crate::segment::Position;
use crate::ship::{ObjectStore, Sender};
use crate::vessel::{Host, Pool, Vessel, VesselError};
use crate::zfs::CloneBase;

/// What a rebirth found and did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reborn {
    /// The epoch this Warden now holds.
    pub epoch: Epoch,
    /// The shipped anchor the Vessel was rebuilt from.
    pub anchor: Position,
    /// Records past the anchor, lost: the last kept and the head the log
    /// continues from.  `None` if everything accepted was shipped.
    pub gap: Option<(Position, Position)>,
    /// The Seals whose `fs` sections were received, in order.
    pub received: Vec<Lsn>,
    /// The Seal the dataset is at: the last received one; `None` if the
    /// dataset is what it was born as.
    pub dataset_at: Option<Position>,
    /// Accepted Seals whose layer is not here (their section was never
    /// shipped and named).
    pub missing_layers: Vec<Position>,
}

impl fmt::Display for Reborn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reborn at epoch {} from anchor lsn {}", self.epoch.get(), self.anchor.lsn.get())?;
        if let Some((kept, head)) = self.gap {
            write!(f, ", records {}..={} lost", kept.lsn.get() + 1, head.lsn.get())?;
        }
        match self.dataset_at {
            Some(s) => write!(f, ", dataset at Seal {}", s.lsn.get()),
            None => write!(f, ", dataset as born"),
        }
    }
}

impl<P: Pool> Host<P> {
    /// Continue the Vessel `id` on this node from what `packs` holds up to
    /// the coordinator's shipped anchor (see the module docs), taking it
    /// over from whoever holds it as read now.  A caller that decided from
    /// its own read passes that read to [`Host::rebirth_as`] instead.
    pub fn rebirth<S: ObjectStore, X: Sender>(
        &self,
        id: ChronicleId,
        packs: &Packs<S, X>,
    ) -> Result<(Vessel<P::Layers>, Reborn), VesselError> {
        let o = self.coord.ownership(id).map_err(VesselError::Coord)?;
        let claim = if o.holder == self.warden { Claim::Mine } else { Claim::TakeOver { from: o.holder, epoch: o.epoch } };
        self.rebirth_as(id, packs, claim)
    }

    /// [`Host::rebirth`] on `claim`: the ownership the caller read when it
    /// decided.  Refused ([`crate::coordinator::CoordError::OwnershipChanged`]) if it moved
    /// since, before anything is fenced (fencing review F1).
    pub fn rebirth_as<S: ObjectStore, X: Sender>(
        &self,
        id: ChronicleId,
        packs: &Packs<S, X>,
        claim: Claim,
    ) -> Result<(Vessel<P::Layers>, Reborn), VesselError> {
        // 1. Fence, on the claim: from here on the anchor cannot move
        //    under us, and a stale decision changes nothing.
        let expected = Chronicle::<P::Layers>::expected(self.coord.as_ref(), id, self.warden, claim).map_err(VesselError::Coord)?;
        self.coord.transfer_if(id, self.warden, expected).map_err(VesselError::Coord)?;

        // 2. What was shipped and anchored.
        let anchor = self.coord.shipped(id).map_err(VesselError::Coord)?;
        if anchor.lsn == Lsn::new(0) {
            return Err(VesselError::NothingShipped(id));
        }
        let chain = packs.chain(Some(anchor)).map_err(VesselError::Pack)?;
        let lineage = match chain.frames.first().map(|f| Payload::decode(&f.payload)) {
            Some(Ok(Payload::Lineage(l))) => l,
            _ => return Err(VesselError::NotAVessel("lsn 1 of the shipped chain is not a Lineage record")),
        };

        // 3. The dataset.
        let dataset = self.dataset_for(id);
        let here = self.seals_here(&dataset)?;
        let named: Vec<(Lsn, taso_core::envelope::HashVal)> =
            chain.seals.iter().map(|s| (s.fs.to.lsn, s.fs.to.hash)).collect();
        if let Some(stray) = here.iter().find(|s| !named.contains(s)) {
            return Err(VesselError::LocalState(format!(
                "{dataset} has Seal {} that the shipped chain does not name",
                stray.0.get()
            )));
        }
        let parent_ds = |p: &ParentSeal| self.dataset_for(p.chronicle);
        let mut received = Vec::new();
        for s in &chain.seals {
            let to = (s.fs.to.lsn, s.fs.to.hash);
            received.push(to.0);
            if here.contains(&to) {
                continue; // received by an interrupted rebirth
            }
            let mut stream = packs
                .open_fs(s)
                .map_err(VesselError::Pack)?
                .ok_or_else(|| VesselError::LocalState(format!("no pack holds the fs of Seal {}", to.0.get())))?;
            let guid = match s.fs.base {
                FsBase::Full => self.pool.receive(&dataset, None, to, &mut stream),
                FsBase::Seal(prev) => self.pool.receive(&dataset, Some((prev.lsn, prev.hash)), to, &mut stream),
                FsBase::Origin { chronicle, seal, guid } => {
                    let parent = ParentSeal { chronicle, seal: seal.lsn, seal_hash: seal.hash };
                    self.parent_present(&parent)?;
                    let base = CloneBase { dataset: parent_ds(&parent), seal: seal.lsn, hash: seal.hash, guid };
                    self.pool.receive_clone(&dataset, &base, to, &mut stream)
                }
            }
            .map_err(VesselError::Pool)?;
            if guid != s.fs.guid {
                return Err(VesselError::WrongSnapshot { seal: to.0, expected: s.fs.guid, got: guid });
            }
        }
        if chain.seals.is_empty() {
            self.as_born(&lineage, &dataset)?;
        }

        // 4. The log, unless an interrupted rebirth already restored it
        //    (the open below checks that it ends at the anchor).
        let dir = self.dir_for(id);
        if !dir.exists() {
            restore_log(&dir, id, &chain.frames).map_err(VesselError::Chronicle)?;
        }

        // 5. Open: a new epoch, the Gap, every check of an ordinary open.
        let (vessel, recovery) = self.open_after_gap(id).map_err(|e| match e {
            VesselError::Chronicle(ChronicleError::SegmentsDisagree { at, why }) => VesselError::LocalState(format!(
                "the state directory {} does not end at the shipped anchor (lsn {}; at lsn {}: {why})",
                dir.display(),
                anchor.lsn.get(),
                at.get()
            )),
            e => e,
        })?;
        let reborn = Reborn {
            epoch: recovery.epoch,
            anchor,
            gap: recovery.gap,
            received,
            dataset_at: chain.seals.last().map(|s| s.fs.to),
            missing_layers: recovery.missing_layers,
        };
        Ok((vessel, reborn))
    }

    /// The Seal snapshots of `dataset` on this node; none if the dataset is
    /// not here (`zfs list` fails on a dataset that does not exist).
    fn seals_here(&self, dataset: &crate::zfs::Dataset) -> Result<Vec<(Lsn, taso_core::envelope::HashVal)>, VesselError> {
        if self.pool.info(dataset).map_err(VesselError::Pool)?.is_none() {
            return Ok(Vec::new());
        }
        self.pool.layers(dataset).list().map_err(VesselError::Pool)
    }

    /// The parent's Seal snapshot must be on this node with its hash.
    fn parent_present(&self, parent: &ParentSeal) -> Result<(), VesselError> {
        if self.seals_here(&self.dataset_for(parent.chronicle))?.contains(&(parent.seal, parent.seal_hash)) {
            Ok(())
        } else {
            Err(VesselError::ParentMissing(*parent))
        }
    }

    /// No section shipped: the dataset is what the Vessel was born as.
    fn as_born(&self, lineage: &LineageRecord, dataset: &crate::zfs::Dataset) -> Result<(), VesselError> {
        if self.pool.info(dataset).map_err(VesselError::Pool)?.is_some() {
            return Ok(()); // made by an interrupted rebirth; the open checks it
        }
        match lineage.origin {
            Origin::Void => self.pool.create(dataset).map(|_| ()),
            Origin::Fork { parent } | Origin::Succession { parent, .. } => {
                self.parent_present(&parent)?;
                self.pool.clone(&self.dataset_for(parent.chronicle), parent.seal, parent.seal_hash, dataset).map(|_| ())
            }
        }
        .map_err(VesselError::Pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::{Coord, Coordinator};
    use crate::effects::{CrashAfter, Effects};
    use crate::pack::PackPublisher;
    use crate::ship::{ByteStream, LocalStore};
    use crate::vessel::tests::{fake_guid, ns, FakePool};
    use crate::zfs::{Dataset, Snapshot};
    use std::io;
    use std::sync::Arc;
    use taso_core::envelope::{HashVal, Stream};
    use taso_core::model::WardenId;
    use taso_core::record::{StreamCut, TurnId, Verdict};
    use taso_field::adapter::{Call, FakeProvider, Registry};

    /// Streams that say what they are.
    struct Says;
    impl Sender for Says {
        fn send(&self, d: &Dataset, from: Option<&str>, to: Lsn) -> io::Result<ByteStream> {
            Ok(Box::new(io::Cursor::new(said(d, from, to))))
        }
    }
    fn said(d: &Dataset, from: Option<&str>, to: Lsn) -> Vec<u8> {
        format!("{d} from {from:?} to {} ", to.get()).repeat(500).into_bytes()
    }

    /// Nodes sharing one coordinator and one pack store, each with its own
    /// pool and state directory.
    struct Nodes {
        tmp: tempfile::TempDir,
        coord: Arc<Coordinator>,
    }

    impl Nodes {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let coord = Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap());
            Self { tmp, coord }
        }
        fn host(&self, n: u64) -> Host<FakePool> {
            Host {
                coord: self.coord.clone(),
                pool: FakePool::default(),
                root: Dataset::new("tank/vessels").unwrap(),
                state_dir: self.tmp.path().join(format!("node-{n}")),
                warden: WardenId::new(n),
            }
        }
        /// A node's view of the store: a fresh `Packs` (fresh cache).
        fn packs(&self, id: ChronicleId) -> Packs<LocalStore, Says> {
            Packs::new(LocalStore::new(self.tmp.path().join("store")), Says, "vessels", id).unwrap()
        }
    }

    fn snap<L: Layers>(v: &Vessel<L>, seal: Position) -> Snapshot {
        Snapshot { dataset: v.dataset().clone(), seal: seal.lsn, createtxg: 1, guid: fake_guid(seal.lsn), seal_hash: Some(seal.hash) }
    }

    fn raw(n: u8) -> Payload {
        Payload::Raw(vec![n; 8])
    }

    /// A turn: a record, then a Seal.
    fn turn<L: Layers>(v: &mut Vessel<L>, n: u8) -> Position {
        v.append(Stream::Fs, raw(n)).unwrap();
        v.seal(StreamCut::EMPTY, Verdict::Clean, Lsn::new(0), TurnId::new(n as u64)).unwrap().seal
    }

    /// Ship the log to the tail and anchor it, without a Seal (what a
    /// dispatch flush does).
    fn flush<L: Layers>(n: &Nodes, v: &Vessel<L>, warden: u64) {
        let c = v.chronicle();
        n.packs(v.id()).ship_log(&c.segments(), c.tail()).unwrap();
        n.coord.advance_shipped(WardenId::new(warden), v.id(), c.epoch(), c.tail()).unwrap();
    }

    fn lsns<L: Layers>(v: &Vessel<L>) -> Vec<u64> {
        v.chronicle().frames().unwrap().iter().map(|f| f.envelope.lsn.get()).collect()
    }

    #[test]
    fn a_vessel_is_reborn_from_its_published_seals() {
        let n = Nodes::new();
        let (a, b) = (n.host(1), n.host(2));
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        let pa = n.packs(v.id());
        let s1 = turn(&mut v, 1);
        v.publish_seal(&pa, &snap(&v, s1), None).unwrap();
        let s2 = turn(&mut v, 2);
        v.publish_seal(&pa, &snap(&v, s2), None).unwrap();
        let anchor = n.coord.shipped(v.id()).unwrap();
        v.append(Stream::Fs, raw(3)).unwrap(); // never shipped: lost
        let head = v.tail();

        let (w, r) = b.rebirth(v.id(), &n.packs(v.id())).unwrap();
        assert_eq!(r.anchor, anchor);
        assert_eq!(r.received, vec![s1.lsn, s2.lsn]);
        assert_eq!(r.dataset_at, Some(s2));
        assert_eq!(r.gap, Some((anchor, head)));
        assert!(r.missing_layers.is_empty());
        let ds = b.dataset_for(v.id());
        assert_eq!(b.pool.snaps_of(ds.as_str()), vec![(s1.lsn, s1.hash), (s2.lsn, s2.hash)]);
        assert_eq!(
            b.pool.received_of(ds.as_str()),
            vec![said(&ds, None, s1.lsn), said(&ds, Some(&ds.seal_snapshot(s1.lsn)), s2.lsn)]
        );
        assert_eq!(w.lineage(), v.lineage());
        assert_eq!(w.last_seal(), Some(s2));
        assert_eq!(w.tail().lsn, head.lsn.next(), "the Gap record");
        let kept: Vec<_> = v.chronicle().frames().unwrap().into_iter().filter(|f| f.envelope.lsn <= anchor.lsn).collect();
        assert_eq!(w.chronicle().frames().unwrap()[..kept.len()], kept[..]);
        // The old holder is fenced.
        assert!(matches!(v.append(Stream::Fs, raw(9)), Err(VesselError::Chronicle(ChronicleError::Refused(_)))));
    }

    #[test]
    fn everything_shipped_means_no_gap() {
        let n = Nodes::new();
        let (a, b) = (n.host(1), n.host(2));
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        let s1 = turn(&mut v, 1);
        v.publish_seal(&n.packs(v.id()), &snap(&v, s1), None).unwrap();
        let (w, r) = b.rebirth(v.id(), &n.packs(v.id())).unwrap();
        assert_eq!((r.gap, r.anchor), (None, v.tail()));
        assert_eq!(w.tail(), v.tail());
    }

    #[test]
    fn nothing_shipped_is_refused() {
        let n = Nodes::new();
        let (a, b) = (n.host(1), n.host(2));
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        turn(&mut v, 1);
        assert!(matches!(b.rebirth(v.id(), &n.packs(v.id())), Err(VesselError::NothingShipped(_))));
    }

    /// The log was shipped by a dispatch flush, but no Seal: the dataset
    /// is what the Vessel was born as.
    #[test]
    fn no_seal_shipped_is_reborn_as_born() {
        let n = Nodes::new();
        let (a, b) = (n.host(1), n.host(2));
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        v.append(Stream::Fs, raw(1)).unwrap();
        flush(&n, &v, 1);
        let (w, r) = b.rebirth(v.id(), &n.packs(v.id())).unwrap();
        assert_eq!((r.received.len(), r.dataset_at, r.gap), (0, None, None));
        assert!(b.pool.info(w.dataset()).unwrap().is_some());
        assert!(b.pool.snaps_of(w.dataset().as_str()).is_empty());
    }

    /// A fork needs its Template's Seal on this node; with it, its first
    /// section is received as a clone of it.
    #[test]
    fn a_fork_is_reborn_on_its_template() {
        let n = Nodes::new();
        let (a, b) = (n.host(1), n.host(2));
        let (mut t, _) = a.ensure(ns(1), b"template").unwrap();
        let ts = turn(&mut t, 1);
        let mut c = a.fork(&t, ts, b"child").unwrap();
        let cs = turn(&mut c, 2);
        c.publish_seal(&n.packs(c.id()), &snap(&c, cs), Some(&snap(&t, ts))).unwrap();
        let parent = ParentSeal { chronicle: t.id(), seal: ts.lsn, seal_hash: ts.hash };
        assert!(matches!(b.rebirth(c.id(), &n.packs(c.id())), Err(VesselError::ParentMissing(p)) if p == parent));
        b.pool.put_snapshot(b.dataset_for(t.id()).as_str(), ts.lsn, ts.hash);
        let (w, r) = b.rebirth(c.id(), &n.packs(c.id())).unwrap();
        assert_eq!(r.received, vec![cs.lsn]);
        let info = b.pool.info(w.dataset()).unwrap().unwrap();
        assert_eq!(info.origin, Some(b.dataset_for(t.id()).seal_snapshot(ts.lsn)));
        assert_eq!(info.parent, Some(ts.hash));
    }

    /// A fork that shipped no Seal is reborn as a clone of its Template.
    #[test]
    fn a_fork_without_a_seal_is_reborn_as_a_clone() {
        let n = Nodes::new();
        let (a, b) = (n.host(1), n.host(2));
        let (mut t, _) = a.ensure(ns(1), b"template").unwrap();
        let ts = turn(&mut t, 1);
        let mut c = a.fork(&t, ts, b"child").unwrap();
        c.append(Stream::Fs, raw(2)).unwrap();
        flush(&n, &c, 1);
        assert!(matches!(b.rebirth(c.id(), &n.packs(c.id())), Err(VesselError::ParentMissing(_))));
        b.pool.put_snapshot(b.dataset_for(t.id()).as_str(), ts.lsn, ts.hash);
        let (w, r) = b.rebirth(c.id(), &n.packs(c.id())).unwrap();
        assert_eq!(r.dataset_at, None);
        assert_eq!(b.pool.info(w.dataset()).unwrap().unwrap().parent, Some(ts.hash));
    }

    /// A Seal whose section was put but never named (a crash before its
    /// FsShipped record), while its record was anchored by a later flush:
    /// the dataset is at the Seal before it, which is reported missing.
    #[test]
    fn an_unnamed_seal_is_reported_missing() {
        let n = Nodes::new();
        let (a, b) = (n.host(1), n.host(2));
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        let pa = n.packs(v.id());
        let s1 = turn(&mut v, 1);
        v.publish_seal(&pa, &snap(&v, s1), None).unwrap();
        let s2 = turn(&mut v, 2);
        pa.ship_seal(&v.chronicle().segments(), &snap(&v, s2), None).unwrap().unwrap();
        flush(&n, &v, 1);
        let (w, r) = b.rebirth(v.id(), &n.packs(v.id())).unwrap();
        assert_eq!((r.received.clone(), r.dataset_at), (vec![s1.lsn], Some(s1)));
        assert_eq!(r.missing_layers, vec![s2]);
        assert!(w.chronicle().layer_missing(s2.lsn));
        assert_eq!(w.last_seal(), Some(s2), "the record is in the log");
    }

    /// A → B → C: the second rebirth reads a chain with B's Gap in it and
    /// rebuilds its log with the joint where B had it.
    #[test]
    fn a_vessel_is_reborn_twice() {
        let n = Nodes::new();
        let (a, b, c) = (n.host(1), n.host(2), n.host(3));
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        let s1 = turn(&mut v, 1);
        v.publish_seal(&n.packs(v.id()), &snap(&v, s1), None).unwrap();
        v.append(Stream::Fs, raw(2)).unwrap(); // lost
        let pb = n.packs(v.id());
        let (mut w, rb) = b.rebirth(v.id(), &pb).unwrap();
        assert!(rb.gap.is_some());
        let s3 = turn(&mut w, 3);
        w.publish_seal(&pb, &snap(&w, s3), None).unwrap();
        w.append(Stream::Fs, raw(4)).unwrap(); // lost
        let (x, rc) = c.rebirth(v.id(), &n.packs(v.id())).unwrap();
        assert_eq!(rc.received, vec![s1.lsn, s3.lsn]);
        assert_eq!(rc.dataset_at, Some(s3));
        let lost_on_a = s1.lsn.get() + 2; // the FsShipped record of s1 is kept; raw(2) is lost
        assert!(!lsns(&x).contains(&lost_on_a));
        assert_eq!(lsns(&x)[..lsns(&w).len() - 1], lsns(&w)[..lsns(&w).len() - 1]);
        assert!(matches!(w.append(Stream::Fs, raw(9)), Err(VesselError::Chronicle(ChronicleError::Refused(_)))));
        // C's log reopens as written.
        let id = v.id();
        drop(x);
        let (x, _) = c.open(id).unwrap();
        assert_eq!(x.last_seal(), Some(s3));
    }

    /// A rebirth that failed after receiving is finished by calling again;
    /// nothing is received twice.
    #[test]
    fn an_interrupted_rebirth_is_finished_by_calling_again() {
        let n = Nodes::new();
        let a = n.host(1);
        let b = n.host(2);
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        let pa = n.packs(v.id());
        let s1 = turn(&mut v, 1);
        v.publish_seal(&pa, &snap(&v, s1), None).unwrap();
        let s2 = turn(&mut v, 2);
        v.publish_seal(&pa, &snap(&v, s2), None).unwrap();
        // The state directory cannot be made: the log is not restored.
        std::fs::write(&b.state_dir, b"in the way").unwrap();
        assert!(matches!(b.rebirth(v.id(), &n.packs(v.id())), Err(VesselError::Chronicle(_))));
        let ds = b.dataset_for(v.id());
        assert_eq!(b.pool.received_of(ds.as_str()).len(), 2);
        std::fs::remove_file(&b.state_dir).unwrap();
        let (w, r) = b.rebirth(v.id(), &n.packs(v.id())).unwrap();
        assert_eq!(b.pool.received_of(ds.as_str()).len(), 2, "not received again");
        assert_eq!((r.dataset_at, w.last_seal()), (Some(s2), Some(s2)));
    }

    /// What [`AfterShipped`] does once.
    type Then = Box<dyn FnOnce(&Coordinator) + Send>;

    /// The coordinator, with something done right after the shipped anchor
    /// is read: the moment a holder that is still alive could move it.
    struct AfterShipped {
        inner: Arc<Coordinator>,
        then: std::sync::Mutex<Option<Then>>,
    }

    impl Coord for AfterShipped {
        fn register(&self, c: ChronicleId, h: WardenId) -> Result<taso_core::envelope::ChronicleHead, crate::coordinator::CoordError> {
            self.inner.register(c, h)
        }
        fn append(&self, w: WardenId, e: &taso_core::envelope::Envelope) -> Result<taso_core::envelope::ChronicleHead, crate::coordinator::CoordError> {
            self.inner.append(w, e)
        }
        fn append_batch(&self, w: WardenId, es: &[taso_core::envelope::Envelope]) -> Result<taso_core::envelope::ChronicleHead, crate::coordinator::CoordError> {
            self.inner.append_batch(w, es)
        }
        fn transfer_if(&self, c: ChronicleId, h: WardenId, e: (WardenId, Epoch)) -> Result<Epoch, crate::coordinator::CoordError> {
            self.inner.transfer_if(c, h, e)
        }
        fn transfer(&self, c: ChronicleId, h: WardenId) -> Result<Epoch, crate::coordinator::CoordError> {
            self.inner.transfer(c, h)
        }
        fn ownership(&self, c: ChronicleId) -> Result<taso_core::model::Ownership, crate::coordinator::CoordError> {
            self.inner.ownership(c)
        }
        fn head(&self, c: ChronicleId) -> Result<taso_core::envelope::ChronicleHead, crate::coordinator::CoordError> {
            self.inner.head(c)
        }
        fn advance_shipped(&self, w: WardenId, c: ChronicleId, e: Epoch, to: Position) -> Result<Position, crate::coordinator::CoordError> {
            self.inner.advance_shipped(w, c, e, to)
        }
        fn shipped(&self, c: ChronicleId) -> Result<Position, crate::coordinator::CoordError> {
            let r = self.inner.shipped(c);
            if let Some(f) = self.then.lock().unwrap().take() {
                f(&self.inner);
            }
            r
        }
    }

    /// The old holder is still alive and moves the shipped anchor just
    /// after the rebirth read it.  Because the rebirth took ownership
    /// first, that move is refused and the anchor it read stays true.
    #[test]
    fn the_old_holder_cannot_move_the_anchor_during_a_rebirth() {
        let n = Nodes::new();
        let a = n.host(1);
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        let s1 = turn(&mut v, 1);
        v.publish_seal(&n.packs(v.id()), &snap(&v, s1), None).unwrap();
        // Accepted but not yet anchored as shipped; A is about to report it.
        v.append(Stream::Fs, raw(2)).unwrap();
        let (id, epoch, tail) = (v.id(), v.chronicle().epoch(), v.tail());
        let coord = Arc::new(AfterShipped {
            inner: n.coord.clone(),
            then: std::sync::Mutex::new(Some(Box::new(move |c: &Coordinator| {
                let moved = c.advance_shipped(WardenId::new(1), id, epoch, tail);
                assert!(moved.is_err(), "the old holder moved the anchor: {moved:?}");
            }))),
        });
        let b = Host { coord, ..n.host(2) };
        let (_, r) = b.rebirth(id, &n.packs(id)).unwrap();
        assert_eq!(r.dataset_at, Some(s1));
    }

    /// The chain names the snapshot the Seal was taken from by its guid;
    /// receiving something else is refused.
    #[test]
    fn a_snapshot_with_another_guid_is_refused() {
        let n = Nodes::new();
        let (a, b) = (n.host(1), n.host(2));
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        let s1 = turn(&mut v, 1);
        let mut other = snap(&v, s1);
        other.guid = 7;
        v.publish_seal(&n.packs(v.id()), &other, None).unwrap();
        let r = b.rebirth(v.id(), &n.packs(v.id())).err();
        assert!(
            matches!(r, Some(VesselError::WrongSnapshot { seal, expected: 7, got }) if seal == s1.lsn && got == fake_guid(s1.lsn)),
            "{r:?}"
        );
    }

    /// State that is not this chain's rebirth in progress is refused.
    #[test]
    fn stale_local_state_is_refused() {
        let n = Nodes::new();
        let (a, b) = (n.host(1), n.host(2));
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        let pa = n.packs(v.id());
        let s1 = turn(&mut v, 1);
        v.publish_seal(&pa, &snap(&v, s1), None).unwrap();
        let ds = b.dataset_for(v.id());
        // A snapshot the chain does not name.
        b.pool.put_snapshot(ds.as_str(), Lsn::new(99), HashVal::from_bytes([9; 32]));
        assert!(matches!(b.rebirth(v.id(), &n.packs(v.id())), Err(VesselError::LocalState(_))));
        b.pool.remove(ds.as_str());
        // A log that does not end at the anchor.
        let frames = v.chronicle().frames().unwrap();
        crate::chronicle::restore_log(&b.dir_for(v.id()), v.id(), &frames[..1]).unwrap();
        let r = b.rebirth(v.id(), &n.packs(v.id())).err();
        assert!(matches!(r, Some(VesselError::LocalState(_))), "{r:?}");
    }

    /// An effect authorized and anchored, then the node died before the
    /// send: on the new node nothing is sent until the engine reconciles
    /// it, and then it is settled once.
    #[test]
    fn an_open_effect_is_reconciled_after_rebirth() {
        let n = Nodes::new();
        let (a, b) = (n.host(1), n.host(2));
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        let s1 = turn(&mut v, 1);
        v.publish_seal(&n.packs(v.id()), &snap(&v, s1), None).unwrap();
        let mut reg = Registry::new();
        reg.register(Box::new(FakeProvider::new("mail")));
        let publisher = PackPublisher::new(n.packs(v.id()), n.coord.clone(), a.warden);
        let (mut fx, _) = Effects::open(reg, Box::new(publisher), &mut v).unwrap();
        let call = Call { operation: "send".into(), args: b"someone".to_vec() };
        assert_eq!(fx.dispatch_until(&mut v, "mail", call, Some(CrashAfter::Published)).unwrap(), None);

        let (mut w, _) = b.rebirth(v.id(), &n.packs(v.id())).unwrap();
        let mut reg = Registry::new();
        reg.register(Box::new(FakeProvider::new("mail")));
        let publisher = PackPublisher::new(n.packs(v.id()), n.coord.clone(), b.warden);
        let (fx, rec) = Effects::open(reg, Box::new(publisher), &mut w).unwrap();
        assert_eq!(rec.settled.len(), 1, "{rec:?}");
        assert!(rec.open.is_empty());
        assert!(fx.open_obligations().is_empty());
    }

    /// The Navigator on a reborn log (amendment 19): the Seals before the
    /// gap are judged as usual, the first after it is unverified, and the
    /// old holder's log no longer reaches the anchored head.
    #[test]
    fn seals_before_the_gap_navigate_after_rebirth() {
        use taso_core::navigator::{Navigation, Reason};
        let n = Nodes::new();
        let (a, b) = (n.host(1), n.host(2));
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        let s1 = turn(&mut v, 1);
        v.publish_seal(&n.packs(v.id()), &snap(&v, s1), None).unwrap();
        let s2 = turn(&mut v, 2);
        v.publish_seal(&n.packs(v.id()), &snap(&v, s2), None).unwrap();
        assert_eq!(v.navigate(&n.packs(v.id()), s2.lsn).unwrap(), Navigation::Consistent(vec![]));
        v.append(Stream::Fs, raw(3)).unwrap(); // never shipped: lost

        let (mut w, r) = b.rebirth(v.id(), &n.packs(v.id())).unwrap();
        assert!(r.gap.is_some());
        for s in [s1, s2] {
            assert_eq!(w.navigate(&n.packs(w.id()), s.lsn).unwrap(), Navigation::Consistent(vec![]), "{s:?}");
        }
        let why = "reborn: 1 record lost".to_string();
        let s3 = w.seal(StreamCut::EMPTY, Verdict::Unverified(why.clone()), Lsn::new(0), TurnId::new(3)).unwrap().seal;
        assert_eq!(w.navigate(&n.packs(w.id()), s3.lsn).unwrap(), Navigation::Insufficient(vec![Reason::MissingVerification(why)]));
        assert_eq!(w.navigate(&n.packs(w.id()), s2.lsn).unwrap(), Navigation::Consistent(vec![]));
        assert!(matches!(v.navigate(&n.packs(v.id()), s2.lsn).unwrap(), Navigation::Inconsistent(_)));
    }

    /// An effect sent before the node died, its outcome never shipped:
    /// after rebirth the Seal before it waits on that outcome until the
    /// engine reconciles it.
    #[test]
    fn an_outcome_lost_in_the_gap_is_missing_until_reconciled() {
        use taso_core::navigator::{Navigation, Reason};
        let n = Nodes::new();
        let (a, b) = (n.host(1), n.host(2));
        let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
        let s1 = turn(&mut v, 1);
        v.publish_seal(&n.packs(v.id()), &snap(&v, s1), None).unwrap();
        let mut reg = Registry::new();
        reg.register(Box::new(FakeProvider::new("mail")));
        let publisher = PackPublisher::new(n.packs(v.id()), n.coord.clone(), a.warden);
        let (mut fx, _) = Effects::open(reg, Box::new(publisher), &mut v).unwrap();
        let call = Call { operation: "send".into(), args: b"someone".to_vec() };
        assert!(fx.dispatch_until(&mut v, "mail", call, None).unwrap().is_some(), "sent and applied");
        let known = v.navigate(&n.packs(v.id()), s1.lsn).unwrap();
        let Navigation::Consistent(obligations) = &known else { panic!("{known:?}") };
        let [o] = obligations[..] else { panic!("{obligations:?}") };

        let (mut w, r) = b.rebirth(v.id(), &n.packs(v.id())).unwrap();
        assert!(r.gap.is_some(), "the applied outcome was not shipped");
        assert_eq!(w.navigate(&n.packs(w.id()), s1.lsn).unwrap(), Navigation::Insufficient(vec![Reason::MissingOutcome(o.op)]));
        let mut reg = Registry::new();
        reg.register(Box::new(FakeProvider::new("mail")));
        let publisher = PackPublisher::new(n.packs(v.id()), n.coord.clone(), b.warden);
        let (_fx, rec) = Effects::open(reg, Box::new(publisher), &mut w).unwrap();
        assert_eq!(rec.settled, vec![o.op]);
        assert_eq!(w.navigate(&n.packs(w.id()), s1.lsn).unwrap(), known, "reconciled: the same answer as before the gap");
    }

    // ── on a real pool ──────────────────────────────────────────────

    mod node {
        use super::*;
        use crate::ship::ZfsSend;
        use crate::zfs::{Cli, Zfs};
        use std::path::Path;
        use std::process::Command;

        fn zfs_ok(args: &[&str]) -> String {
            let out = Command::new("zfs").args(args).output().expect("run zfs");
            assert!(out.status.success(), "zfs {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        fn mounted(ds: &Dataset) -> std::path::PathBuf {
            let _ = Command::new("zfs").args(["mount", ds.as_str()]).output();
            std::path::PathBuf::from(zfs_ok(&["get", "-H", "-o", "value", "mountpoint", ds.as_str()]).trim())
        }

        fn host(root: &str, state: &Path, coord: Arc<Coordinator>, w: u64) -> Host<Zfs<Cli>> {
            Host {
                coord,
                pool: Zfs::cli(),
                root: Dataset::new(root).unwrap(),
                state_dir: state.join(format!("node-{w}")),
                warden: WardenId::new(w),
            }
        }

        fn seal_snapshot(z: &Zfs<Cli>, v: &Vessel<crate::chronicle::ZfsLayers<Cli>>, seal: Position) -> Snapshot {
            z.get(v.dataset(), seal.lsn).unwrap().expect("the Seal's snapshot")
        }

        /// Node A writes, seals and publishes twice, then writes more and
        /// dies; node B (another dataset root, its own state directory)
        /// rebirths it: the files are those of the last published Seal,
        /// and A is fenced.  Then the same for a Vessel forked from a
        /// Template that B already holds.
        #[test]
        #[ignore = "needs a ZFS pool: set TASO_ZFS_DATASET"]
        fn rebirth_on_another_root_on_zfs() {
            let base = std::env::var("TASO_ZFS_DATASET").expect("set TASO_ZFS_DATASET");
            let root = format!("{base}/rb-{}", std::process::id());
            zfs_ok(&["create", &root]);
            struct Cleanup(String);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = Command::new("zfs").args(["destroy", "-R", &self.0]).status();
                }
            }
            let _c = Cleanup(root.clone());
            let (ra, rb) = (format!("{root}/a"), format!("{root}/b"));
            zfs_ok(&["create", &ra]);
            zfs_ok(&["create", &rb]);
            let tmp = tempfile::tempdir().unwrap();
            let coord = Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap());
            let (a, b) = (host(&ra, tmp.path(), coord.clone(), 1), host(&rb, tmp.path(), coord.clone(), 2));
            let z = Zfs::cli();
            let packs = |id| Packs::new(LocalStore::new(tmp.path().join("store")), ZfsSend::default(), "vessels", id).unwrap();

            // ── a Vessel born from the void ──
            let (mut v, _) = a.ensure(ns(1), b"user").unwrap();
            let ma = mounted(v.dataset());
            std::fs::write(ma.join("notes.txt"), b"one").unwrap();
            let s1 = turn(&mut v, 1);
            v.publish_seal(&packs(v.id()), &seal_snapshot(&z, &v, s1), None).unwrap();
            std::fs::write(ma.join("notes.txt"), b"two").unwrap();
            std::fs::write(ma.join("big.bin"), vec![7u8; 1 << 20]).unwrap();
            let s2 = turn(&mut v, 2);
            let g2 = seal_snapshot(&z, &v, s2).guid;
            v.publish_seal(&packs(v.id()), &seal_snapshot(&z, &v, s2), None).unwrap();
            std::fs::write(ma.join("notes.txt"), b"three, never sealed").unwrap();
            v.append(Stream::Fs, raw(3)).unwrap();

            let started = std::time::Instant::now();
            let (w, r) = b.rebirth(v.id(), &packs(v.id())).unwrap();
            println!("void-born: {r} in {:?}", started.elapsed());
            assert_eq!((r.received.clone(), r.dataset_at), (vec![s1.lsn, s2.lsn], Some(s2)));
            assert!(r.gap.is_some());
            assert_eq!(z.get(w.dataset(), s2.lsn).unwrap().unwrap().guid, g2);
            let mb = mounted(w.dataset());
            assert_eq!(std::fs::read(mb.join("notes.txt")).unwrap(), b"two");
            assert_eq!(std::fs::read(mb.join("big.bin")).unwrap(), vec![7u8; 1 << 20]);
            assert!(matches!(v.append(Stream::Fs, raw(9)), Err(VesselError::Chronicle(ChronicleError::Refused(_)))));

            // ── a Vessel forked from a Template ──
            let (mut t, _) = a.ensure(ns(1), b"template").unwrap();
            std::fs::write(mounted(t.dataset()).join("base.txt"), b"template").unwrap();
            let ts = turn(&mut t, 1);
            let tsnap = seal_snapshot(&z, &t, ts);
            // The Template is on B first, keeping its guid.
            let sent = Command::new("zfs").args(["send", &t.dataset().seal_snapshot(ts.lsn)]).output().unwrap();
            assert!(sent.status.success());
            let tb = z.receive(&b.dataset_for(t.id()), None, (ts.lsn, ts.hash), &mut &sent.stdout[..]).unwrap();
            assert_eq!(tb.guid, tsnap.guid);
            let mut c = a.fork(&t, ts, b"child").unwrap();
            std::fs::write(mounted(c.dataset()).join("mine.txt"), b"child").unwrap();
            let cs = turn(&mut c, 2);
            c.publish_seal(&packs(c.id()), &seal_snapshot(&z, &c, cs), Some(&tsnap)).unwrap();
            let (x, r) = b.rebirth(c.id(), &packs(c.id())).unwrap();
            println!("forked: {r}");
            let mx = mounted(x.dataset());
            assert_eq!(std::fs::read(mx.join("base.txt")).unwrap(), b"template");
            assert_eq!(std::fs::read(mx.join("mine.txt")).unwrap(), b"child");
            assert!(matches!(c.append(Stream::Fs, raw(9)), Err(VesselError::Chronicle(ChronicleError::Refused(_)))));
        }
    }
}
