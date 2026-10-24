//! Benchmarks of the hot paths: measurements, not tests.
//!
//! Each one turns [`crate::timing`] on, drives the real code path many
//! times, and prints a span table plus how latency changes as the log
//! grows.  Run them alone and in release, or other tests' spans mix in:
//!
//! ```text
//! cargo test --release -p taso-warden bench:: -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `TMPDIR` picks the disk the segment, coordinator and pack store live on
//! (local NVMe for gate numbers).  `TASO_BENCH_N` sets the iterations.
//! `bench::node::*` needs `TASO_ZFS_DATASET`, as the node tests do.
//!
//! What is real: segment appends (fsync), the coordinator (redb, fsync,
//! in-process: no socket), packs over [`LocalStore`] (fsync, rename), the
//! effect engine and the publish flow.  What is fake: the provider, and
//! outside `node`, the layers and the `fs` stream.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;
    use std::time::Instant;

    use taso_core::envelope::{Lsn, Stream};
    use taso_core::record::{
        Consequence, Dispatch, Payload, RetryPolicy, StreamCut, TurnId, Verdict,
    };

    use crate::chronicle::Layers;
    use crate::effects::{Asked, Effects, Mode};
    use crate::ledger::{Answer, Declared};
    use crate::pack::{PackPublisher, Packs};
    use crate::segment::Position;
    use crate::ship::{ByteStream, LocalStore, Sender};
    use crate::timing;
    use crate::vessel::tests::{env, ns};
    use crate::vessel::Vessel;
    use crate::zfs::{Dataset, Snapshot};

    fn n(default: usize) -> usize {
        std::env::var("TASO_BENCH_N")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// p50 and p95 (ms) of `durations` (µs) in consecutive blocks of `block`:
    /// how a path's latency moves as the log grows.
    fn growth(name: &str, durations: &[u64], block: usize) -> String {
        let mut out = format!("{name} by position in the run (p50 / p95 ms):\n");
        for (i, chunk) in durations.chunks(block).enumerate() {
            let mut v = chunk.to_vec();
            v.sort_unstable();
            out += &format!(
                "  {:>5}..{:<5} {:>8.3} / {:>8.3}\n",
                i * block,
                i * block + chunk.len(),
                timing::quantile(&v, 0.5) as f64 / 1000.0,
                timing::quantile(&v, 0.95) as f64 / 1000.0
            );
        }
        out
    }

    fn print(
        title: &str,
        spans: &BTreeMap<&'static str, Vec<u64>>,
        growth_of: &str,
        block: usize,
        wall: f64,
    ) {
        println!("\n=== {title} ===");
        println!(
            "TMPDIR={}",
            std::env::var("TMPDIR").unwrap_or_else(|_| "(default)".into())
        );
        print!("{}", timing::report(spans));
        if let Some(v) = spans.get(growth_of) {
            print!("{}", growth(growth_of, v, block));
            println!("throughput: {:.0} per second", v.len() as f64 / wall);
        }
    }

    /// M7 (P3 close-out C8): what one promotion costs at 1, 10 and 100
    /// proposals.  Per size a fresh parent, then `TASO_BENCH_N` (20)
    /// rounds: the parent seals and publishes a new fork point, a child is
    /// forked from it and proposes `n` held effects and seals, the parent
    /// reads the child's log and promotes it (Promotion recorded and
    /// shipped, adoption recorded and shipped, C2).  Real segment fsyncs,
    /// coordinator and pack store; the layers are fake (promotion moves no
    /// files yet: C7).
    ///
    /// Predictions, written before the first run (2026-10-23):
    /// - flat in n: p50 of `promote.total` at 100 within 1.5x of the p50 at
    ///   1 (one batched adoption write and two ships, whatever n);
    /// - its parts: two ships (`promote.ship_promotion`,
    ///   `promote.ship_adoption`) dominate; `effect.adopt` (one write, one
    ///   fsync, one CAS) is about one effect release; `promote.record` and
    ///   reading the child's log grow with n but stay small;
    /// - a promotion costs about two single releases (`effect.total` of
    ///   `dispatch`).
    #[test]
    #[ignore = "benchmark: run alone, in release"]
    fn promotion_cost() {
        use crate::vessel::tests::{fake_guid, FakeLayers};
        use crate::vessel::SealAt;
        let rounds = n(20);
        let e = env();
        let store = tempfile::tempdir().unwrap();
        let packs = |id| {
            Packs::new(
                LocalStore::new(store.path().join("store")),
                FixedSend(64 << 10),
                "vessels",
                id,
            )
            .unwrap()
        };
        let snap = |v: &Vessel<FakeLayers>, s: Position| Snapshot {
            dataset: v.dataset().clone(),
            seal: s.lsn,
            createtxg: 1,
            guid: fake_guid(s.lsn),
            seal_hash: Some(s.hash),
        };
        let held = |k: usize| Declared {
            provider: "pay".into(),
            request: format!("pay {k}").into_bytes(),
            footprint: Vec::new(),
            dispatch: Dispatch::Immediate,
            retry: RetryPolicy::ProviderDeduplicated {
                key: format!("k{k}").into_bytes(),
            },
            consequence: Consequence::NoExternalMutation,
            authority: Vec::new(),
        };
        println!("\n=== M7: promotion cost, {rounds} promotions per size ===");
        println!(
            "TMPDIR={}",
            std::env::var("TMPDIR").unwrap_or_else(|_| "(default)".into())
        );
        let parts = [
            "promote.total",
            "promote.read_log",
            "promote.record",
            "promote.ship_promotion",
            "effect.adopt",
            "promote.ship_adoption",
        ];
        println!(
            "{:>4}  {}",
            "n",
            parts
                .iter()
                .map(|p| format!("  {p:>22}"))
                .collect::<String>()
        );
        let mut p50s = Vec::new();
        for size in [1usize, 10, 100] {
            let (mut p, _) = e
                .host
                .ensure(ns(1), format!("prime-{size}").as_bytes())
                .unwrap();
            let s0 = p.seal_birth().unwrap().seal;
            p.publish_seal(&packs(p.id()), &snap(&p, s0), None).unwrap();
            let publisher = PackPublisher::new(packs(p.id()), e.host.coord.clone(), e.host.warden);
            let (mut fx, _) = Effects::open(Mode::Dispatch, Box::new(publisher), &mut p).unwrap();
            timing::take();
            timing::enable(true);
            for r in 0..rounds {
                p.append(Stream::Fs, Payload::Raw(vec![1; 200])).unwrap();
                let s = p
                    .seal(
                        StreamCut::EMPTY,
                        Verdict::Clean,
                        crate::effects::ledger_pos(&p).unwrap(),
                        TurnId::new(r as u64 + 1),
                    )
                    .unwrap()
                    .seal;
                p.publish_seal(&packs(p.id()), &snap(&p, s), None).unwrap();
                let subject = format!("child-{size}-{r}");
                let cid = {
                    let mut c = e
                        .host
                        .fork_from_log(p.id(), SealAt::Last, subject.as_bytes())
                        .unwrap();
                    c.seal_birth().unwrap();
                    let (mut cfx, _) =
                        Effects::open(Mode::Hold, Box::new(crate::effects::AlwaysPublish), &mut c)
                            .unwrap();
                    for k in 0..size {
                        assert!(matches!(
                            cfx.ask(&mut c, &held(k)).unwrap(),
                            Asked::Held { .. }
                        ));
                    }
                    let pos = crate::effects::ledger_pos(&c).unwrap();
                    c.seal(StreamCut::EMPTY, Verdict::Clean, pos, TurnId::new(1))
                        .unwrap();
                    c.id()
                };
                let t = timing::span("promote.read_log");
                let log = e.host.read_log_of(cid).unwrap();
                drop(t);
                let (_, adopted) = fx.promote(&mut p, &log, SealAt::Last).unwrap();
                assert_eq!(adopted.len(), size);
            }
            timing::enable(false);
            let spans = timing::take();
            let q = |name: &str, at: f64| {
                let mut v = spans.get(name).cloned().unwrap_or_default();
                v.sort_unstable();
                timing::quantile(&v, at) as f64 / 1000.0
            };
            println!(
                "{size:>4}  {}",
                parts
                    .iter()
                    .map(|n| format!("  {:>13.3} / {:>6.3}", q(n, 0.5), q(n, 0.95)))
                    .collect::<String>()
            );
            assert_eq!(spans["promote.total"].len(), rounds);
            p50s.push(q("promote.total", 0.5));
        }
        println!("(each cell: p50 / p95 ms)");
        let ratio = p50s[2] / p50s[0];
        println!(
            "prediction 'flat in n' (p50 at 100 within 1.5x of p50 at 1): {ratio:.2}x -> {}",
            if ratio <= 1.5 { "held" } else { "NOT held" }
        );
    }

    /// A stream of fixed size; only publishing is measured, not `zfs send`.
    struct FixedSend(usize);
    impl Sender for FixedSend {
        fn send(&self, _: &Dataset, _: Option<&str>, _: Lsn) -> io::Result<ByteStream> {
            Ok(Box::new(io::Cursor::new(vec![7u8; self.0])))
        }
    }

    /// One effect at a time through the whole sequence: intent, authorize,
    /// publish (log pack + shipped anchor), send, outcome.
    #[test]
    #[ignore = "benchmark: run alone, in release"]
    fn dispatch() {
        let count = n(1000);
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"bench").unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let packs = Packs::new(
            LocalStore::new(store_dir.path()),
            FixedSend(0),
            "vessels",
            v.id(),
        )
        .unwrap();
        let publisher = PackPublisher::new(packs, e.host.coord.clone(), e.host.warden);
        let (mut fx, _) = Effects::open(Mode::Dispatch, Box::new(publisher), &mut v).unwrap();

        timing::take();
        timing::enable(true);
        let start = Instant::now();
        for i in 0..count {
            let d = Declared {
                provider: "mail".into(),
                request: format!("send user-{i}").into_bytes(),
                footprint: Vec::new(),
                dispatch: Dispatch::Immediate,
                retry: RetryPolicy::ProviderDeduplicated {
                    key: format!("user-{i}").into_bytes(),
                },
                consequence: Consequence::Irreversible,
                authority: Vec::new(),
            };
            let Asked::Released { op } = fx.ask(&mut v, &d).unwrap() else {
                panic!("not released")
            };
            fx.report(
                &mut v,
                op,
                &Answer::Applied {
                    receipt: b"ok".to_vec(),
                },
            )
            .unwrap();
        }
        let wall = start.elapsed().as_secs_f64();
        timing::enable(false);
        let spans = timing::take();
        print(
            &format!("dispatch: {count} effects, one Vessel"),
            &spans,
            "effect.total",
            count / 4,
            wall,
        );
        assert_eq!(spans["effect.total"].len(), count);
    }

    fn snapshot_of<L: Layers>(v: &Vessel<L>, seal: Position) -> Snapshot {
        Snapshot {
            dataset: v.dataset().clone(),
            seal: seal.lsn,
            createtxg: 1,
            guid: 1000 + seal.lsn.get(),
            seal_hash: Some(seal.hash),
        }
    }

    /// A turn of `records` appends, then a Seal and its publication (Seal
    /// pack with a 64 KiB stream, FsShipped, log, shipped anchor).
    #[test]
    #[ignore = "benchmark: run alone, in release"]
    fn seal_and_publish() {
        let count = n(300);
        let records = 5;
        let e = env();
        let (mut v, _) = e.host.ensure(ns(1), b"bench").unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let packs = Packs::new(
            LocalStore::new(store_dir.path()),
            FixedSend(64 << 10),
            "vessels",
            v.id(),
        )
        .unwrap();

        timing::take();
        timing::enable(true);
        let start = Instant::now();
        for turn in 0..count {
            for r in 0..records {
                v.append(Stream::Fs, Payload::Raw(vec![r as u8; 200]))
                    .unwrap();
            }
            let seal = v
                .seal(
                    StreamCut::EMPTY,
                    Verdict::Clean,
                    Lsn::new(0),
                    TurnId::new(turn as u64 + 1),
                )
                .unwrap()
                .seal;
            v.publish_seal(&packs, &snapshot_of(&v, seal), None)
                .unwrap();
        }
        let wall = start.elapsed().as_secs_f64();
        timing::enable(false);
        let spans = timing::take();
        print(
            &format!("seal + publish: {count} turns of {records} records, one Vessel, fake layers"),
            &spans,
            "publish.total",
            count / 4,
            wall,
        );
        assert_eq!(spans["publish.total"].len(), count);
    }

    mod node {
        use super::*;
        use crate::coordinator::Coordinator;
        use crate::ship::ZfsSend;
        use crate::vessel::Host;
        use crate::zfs::{Cli, Zfs};
        use std::process::Command;
        use std::sync::Arc;
        use taso_core::model::WardenId;

        /// The P1 gate's Seal line at its concurrency: `TASO_BENCH_VESSELS`
        /// Vessels (64) on one pool, each writing a 16 KiB file, appending
        /// a record and sealing, `TASO_BENCH_N` (20) turns each, all at
        /// once.  Gate: Seal p95 < 50 ms at p64 (v1.0 §1 P1).  On network
        /// block storage this is a warning signal, not a gate number.
        #[test]
        #[ignore = "benchmark on a ZFS pool: set TASO_ZFS_DATASET; run alone, in release"]
        fn seals_at_p64_on_zfs() {
            p64(false);
        }

        /// As `seals_at_p64_on_zfs`, with Seal snapshots batched: one
        /// channel program and one txg per batch ([`crate::snapbatch`]).
        #[test]
        #[ignore = "benchmark on a ZFS pool: set TASO_ZFS_DATASET; run alone, in release"]
        fn seals_at_p64_batched_on_zfs() {
            p64(true);
        }

        fn p64(batched: bool) {
            let turns = n(20);
            let vessels: usize = std::env::var("TASO_BENCH_VESSELS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(64);
            let Ok(base) = std::env::var("TASO_ZFS_DATASET") else {
                println!(
                    "\n=== seals at p{vessels} on ZFS: skipped, TASO_ZFS_DATASET is not set ==="
                );
                return;
            };
            let root = format!(
                "{base}/p64{}-{}",
                if batched { "b" } else { "" },
                std::process::id()
            );
            let zfs = if batched {
                Zfs::<Cli>::cli().batched()
            } else {
                Zfs::<Cli>::cli()
            };
            Zfs::create(&zfs, &Dataset::new(&root).unwrap()).unwrap();
            struct Cleanup(String);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = Command::new("zfs")
                        .args(["destroy", "-R", &self.0])
                        .status();
                }
            }
            let _c = Cleanup(root.clone());
            let tmp = tempfile::tempdir().unwrap();
            let host = Host {
                coord: Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap()),
                pool: Clone::clone(&zfs),
                root: Dataset::new(&root).unwrap(),
                state_dir: tmp.path().join("state"),
                warden: WardenId::new(1),
            };
            let mut all = Vec::new();
            for i in 0..vessels {
                let (v, _) = host.ensure(ns(1), format!("bench-{i}").as_bytes()).unwrap();
                let mount = zfs
                    .dataset_info(v.dataset())
                    .unwrap()
                    .unwrap()
                    .mountpoint
                    .unwrap();
                all.push((v, mount));
            }

            timing::take();
            timing::enable(true);
            let start = Instant::now();
            let go = std::sync::Barrier::new(vessels);
            std::thread::scope(|scope| {
                for (v, mount) in all.iter_mut() {
                    let go = &go;
                    scope.spawn(move || {
                        go.wait();
                        for turn in 0..turns {
                            std::fs::write(
                                mount.join(format!("f{}", turn % 4)),
                                vec![turn as u8; 16 << 10],
                            )
                            .unwrap();
                            v.append(Stream::Fs, Payload::Raw(vec![1; 200])).unwrap();
                            v.seal(
                                StreamCut::EMPTY,
                                Verdict::Clean,
                                Lsn::new(0),
                                TurnId::new(turn as u64 + 1),
                            )
                            .unwrap();
                        }
                    });
                }
            });
            let wall = start.elapsed().as_secs_f64();
            timing::enable(false);
            let spans = timing::take();
            let how = if batched {
                "batched snapshots"
            } else {
                "one zfs snapshot per Seal"
            };
            let title =
                format!("seals at p{vessels} on ZFS, {how}: {turns} turns each, dataset {root}");
            print(
                &title,
                &spans,
                "seal.total",
                (vessels * turns / 4).max(1),
                wall,
            );
            let mut seal = spans["seal.total"].clone();
            seal.sort_unstable();
            let p95 = timing::quantile(&seal, 0.95) as f64 / 1000.0;
            println!(
                "gate (Seal p95 < 50 ms): {p95:.1} ms -> {}",
                if p95 < 50.0 { "within" } else { "OVER" }
            );
            assert_eq!(seal.len(), vessels * turns);
        }

        /// As `seal_and_publish`, on a real dataset: a 64 KiB file written
        /// per turn, a ZFS snapshot per Seal, `zfs send -i` into the pack.
        #[test]
        #[ignore = "benchmark on a ZFS pool: set TASO_ZFS_DATASET; run alone, in release"]
        fn seal_and_publish_on_zfs() {
            let count = n(100);
            let Ok(base) = std::env::var("TASO_ZFS_DATASET") else {
                println!("\n=== seal + publish on ZFS: skipped, TASO_ZFS_DATASET is not set ===");
                return;
            };
            let root = format!("{base}/bench-{}", std::process::id());
            let zfs = Zfs::<Cli>::cli();
            Zfs::create(&zfs, &Dataset::new(&root).unwrap()).unwrap();
            struct Cleanup(String);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = Command::new("zfs")
                        .args(["destroy", "-R", &self.0])
                        .status();
                }
            }
            let _c = Cleanup(root.clone());
            let tmp = tempfile::tempdir().unwrap();
            let host = Host {
                coord: Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap()),
                pool: Clone::clone(&zfs),
                root: Dataset::new(&root).unwrap(),
                state_dir: tmp.path().join("state"),
                warden: WardenId::new(1),
            };
            let (mut v, _) = host.ensure(ns(1), b"bench").unwrap();
            let mount = zfs
                .dataset_info(v.dataset())
                .unwrap()
                .unwrap()
                .mountpoint
                .unwrap();
            let packs = Packs::new(
                LocalStore::new(tmp.path().join("store")),
                ZfsSend::default(),
                "vessels",
                v.id(),
            )
            .unwrap();

            timing::take();
            timing::enable(true);
            let start = Instant::now();
            for turn in 0..count {
                std::fs::write(
                    mount.join(format!("f{}", turn % 8)),
                    vec![turn as u8; 64 << 10],
                )
                .unwrap();
                v.append(Stream::Fs, Payload::Raw(vec![1; 200])).unwrap();
                let seal = v
                    .seal(
                        StreamCut::EMPTY,
                        Verdict::Clean,
                        Lsn::new(0),
                        TurnId::new(turn as u64 + 1),
                    )
                    .unwrap()
                    .seal;
                let snap = {
                    // One snapshot, not the whole list (which grows with
                    // every Seal: the 2026-10-16 finding).
                    let _t = timing::span("bench.zfs_get");
                    zfs.get(v.dataset(), seal.lsn)
                        .unwrap()
                        .expect("the Seal's snapshot")
                };
                v.publish_seal(&packs, &snap, None).unwrap();
            }
            let wall = start.elapsed().as_secs_f64();
            timing::enable(false);
            let spans = timing::take();
            print(
                &format!("seal + publish on ZFS: {count} turns, dataset {root}"),
                &spans,
                "publish.total",
                count / 4,
                wall,
            );
            assert_eq!(spans["publish.total"].len(), count);
        }

        /// M7 with files (P3 close-out C8 part 2): what adopting a promoted
        /// fork's files costs on ZFS ([`Host::adopt_files`], C7: rollback,
        /// `zfs diff`, copy, snapshot), by the parent's size (`base` files
        /// of 4 KiB) and the fork's changes (`changed` new files of 64 KiB
        /// and one rewritten base file).  Per pair a fresh parent, then
        /// `TASO_BENCH_N` (10) rounds: the parent seals and publishes a fork
        /// point, a fork writes its files, proposes one held effect and
        /// seals, the parent promotes it (effects, as `promotion_cost`) and
        /// adopts its files, and publishes the adoption Seal (`zfs send -i`
        /// into the pack store).  The fork's dataset is destroyed after
        /// each round (not timed).
        ///
        /// Predictions, written before the first run (2026-10-23):
        /// - flat in the parent's size: for each `changed`, the p50 of
        ///   `adopt.total` at base 10000 within 1.5x of base 100 (`zfs
        ///   diff` and the copy touch only what the fork changed);
        /// - a fixed cost of about ten `zfs` commands (checks, rollback,
        ///   two mounts, diff, snapshot): `adopt.total` p50 under 100 ms at
        ///   one changed file;
        /// - linear in the changes: at 1000 changed files (64 MiB)
        ///   `adopt.copy` is the largest part of `adopt.total`;
        /// - `adopt.publish` grows with the bytes changed, as any Seal's.
        #[test]
        #[ignore = "benchmark on a ZFS pool: set TASO_ZFS_DATASET; run alone, in release"]
        fn adoption_on_zfs() {
            use crate::vessel::SealAt;
            let rounds = n(10);
            let Ok(base_ds) = std::env::var("TASO_ZFS_DATASET") else {
                println!("\n=== M7 adoption on ZFS: skipped, TASO_ZFS_DATASET is not set ===");
                return;
            };
            let root = format!("{base_ds}/m7-{}", std::process::id());
            let zfs = Zfs::<Cli>::cli();
            Zfs::create(&zfs, &Dataset::new(&root).unwrap()).unwrap();
            struct Cleanup(String);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = Command::new("zfs")
                        .args(["destroy", "-R", &self.0])
                        .status();
                }
            }
            let _c = Cleanup(root.clone());
            let tmp = tempfile::tempdir().unwrap();
            let host = Host {
                coord: Arc::new(Coordinator::open(tmp.path().join("coord.redb")).unwrap()),
                pool: Clone::clone(&zfs),
                root: Dataset::new(&root).unwrap(),
                state_dir: tmp.path().join("state"),
                warden: WardenId::new(1),
            };
            let packs = |id| {
                Packs::new(
                    LocalStore::new(tmp.path().join("store")),
                    ZfsSend::default(),
                    "vessels",
                    id,
                )
                .unwrap()
            };
            let mount = |ds: &Dataset| {
                zfs.ensure_mounted(ds).unwrap();
                zfs.dataset_info(ds).unwrap().unwrap().mountpoint.unwrap()
            };
            let held = Declared {
                provider: "pay".into(),
                request: b"pay".to_vec(),
                footprint: Vec::new(),
                dispatch: Dispatch::Immediate,
                retry: RetryPolicy::ProviderDeduplicated { key: b"k".to_vec() },
                consequence: Consequence::NoExternalMutation,
                authority: Vec::new(),
            };
            println!("\n=== M7: adoption on ZFS, {rounds} promotions per pair, dataset {root} ===");
            println!(
                "TMPDIR={}",
                std::env::var("TMPDIR").unwrap_or_else(|_| "(default)".into())
            );
            let parts = [
                "adopt.total",
                "adopt.checks",
                "adopt.rollback",
                "adopt.mount",
                "adopt.diff",
                "adopt.copy",
                "adopt.snapshot",
                "adopt.publish",
                "promote.total",
            ];
            println!(
                "{:>6} {:>6} {}",
                "base",
                "chgd",
                parts
                    .iter()
                    .map(|p| format!(" {p:>17}"))
                    .collect::<String>()
            );
            let mut p50 = BTreeMap::new();
            for base in [100usize, 10_000] {
                for changed in [1usize, 100, 1000] {
                    let (mut p, _) = host
                        .ensure(ns(1), format!("m7-{base}-{changed}").as_bytes())
                        .unwrap();
                    let pm = mount(p.dataset());
                    for i in 0..base {
                        let d = pm.join(format!("b{}", i / 100));
                        std::fs::create_dir_all(&d).unwrap();
                        std::fs::write(d.join(format!("f{i}")), vec![i as u8; 4 << 10]).unwrap();
                    }
                    let s0 = p.seal_birth().unwrap().seal;
                    let snap0 = zfs.get(p.dataset(), s0.lsn).unwrap().unwrap();
                    p.publish_seal(&packs(p.id()), &snap0, None).unwrap();
                    let publisher =
                        PackPublisher::new(packs(p.id()), host.coord.clone(), host.warden);
                    let (mut fx, _) =
                        Effects::open(Mode::Dispatch, Box::new(publisher), &mut p).unwrap();
                    timing::take();
                    timing::enable(true);
                    for r in 0..rounds {
                        p.append(Stream::Fs, Payload::Raw(vec![1; 200])).unwrap();
                        let s = p
                            .seal(
                                StreamCut::EMPTY,
                                Verdict::Clean,
                                crate::effects::ledger_pos(&p).unwrap(),
                                TurnId::new(r as u64 + 1),
                            )
                            .unwrap()
                            .seal;
                        let snap = zfs.get(p.dataset(), s.lsn).unwrap().unwrap();
                        p.publish_seal(&packs(p.id()), &snap, None).unwrap();
                        let (cid, cds) = {
                            let mut c = host
                                .fork_from_log(
                                    p.id(),
                                    SealAt::Last,
                                    format!("fork-{base}-{changed}-{r}").as_bytes(),
                                )
                                .unwrap();
                            c.seal_birth().unwrap();
                            let cm = mount(c.dataset());
                            let d = cm.join(format!("r{r}"));
                            std::fs::create_dir_all(&d).unwrap();
                            for k in 0..changed {
                                std::fs::write(d.join(format!("n{k}")), vec![k as u8; 64 << 10])
                                    .unwrap();
                            }
                            std::fs::write(cm.join("b0/f0"), format!("round {r}")).unwrap();
                            let (mut cfx, _) = Effects::open(
                                Mode::Hold,
                                Box::new(crate::effects::AlwaysPublish),
                                &mut c,
                            )
                            .unwrap();
                            assert!(matches!(
                                cfx.ask(&mut c, &held).unwrap(),
                                Asked::Held { .. }
                            ));
                            let pos = crate::effects::ledger_pos(&c).unwrap();
                            c.append(Stream::Fs, Payload::Raw(vec![1; 200])).unwrap();
                            c.seal(StreamCut::EMPTY, Verdict::Clean, pos, TurnId::new(1))
                                .unwrap();
                            (c.id(), c.dataset().clone())
                        };
                        let log = host.read_log_of(cid).unwrap();
                        fx.promote(&mut p, &log, SealAt::Last).unwrap();
                        let promotion = p.adoption_pending().unwrap().expect("pending");
                        let a = host
                            .adopt_files(&mut p, &promotion, &log, &ZfsSend::default())
                            .unwrap();
                        let t = timing::span("adopt.publish");
                        let snap = zfs.get(p.dataset(), a.lsn).unwrap().unwrap();
                        p.publish_seal(&packs(p.id()), &snap, None).unwrap();
                        drop(t);
                        assert_eq!(
                            std::fs::read_to_string(pm.join("b0/f0")).unwrap(),
                            format!("round {r}")
                        );
                        assert!(pm.join(format!("r{r}/n{}", changed - 1)).exists());
                        timing::enable(false);
                        let _ = Command::new("zfs")
                            .args(["destroy", "-r", cds.as_str()])
                            .status();
                        timing::enable(true);
                    }
                    timing::enable(false);
                    let spans = timing::take();
                    let q = |name: &str, at: f64| {
                        let mut v = spans.get(name).cloned().unwrap_or_default();
                        v.sort_unstable();
                        timing::quantile(&v, at) as f64 / 1000.0
                    };
                    println!(
                        "{base:>6} {changed:>6} {}",
                        parts
                            .iter()
                            .map(|n| format!(" {:>8.1} / {:>6.1}", q(n, 0.5), q(n, 0.95)))
                            .collect::<String>()
                    );
                    assert_eq!(spans["adopt.total"].len(), rounds);
                    p50.insert(
                        (base, changed),
                        (q("adopt.total", 0.5), q("adopt.copy", 0.5)),
                    );
                }
            }
            println!("(each cell: p50 / p95 ms)");
            for changed in [1usize, 100, 1000] {
                let ratio = p50[&(10_000, changed)].0 / p50[&(100, changed)].0;
                println!(
                    "prediction 'flat in the parent's size' at {changed} changed: {ratio:.2}x -> {}",
                    if ratio <= 1.5 { "held" } else { "NOT held" }
                );
            }
            let fixed = p50[&(100, 1)].0;
            println!(
                "prediction 'fixed cost under 100 ms' (1 changed, base 100): {fixed:.1} ms -> {}",
                if fixed < 100.0 { "held" } else { "NOT held" }
            );
            println!("prediction 'copy is the largest part at 1000 changed': see the table");
        }
    }
    // ── P4: the coordinator log (file 1d-4) ─────────────────────────

    /// The coordinator log's costs (P4 spec D33, §0.4): an append carrying
    /// an effect record's bytes against a plain append of the same size,
    /// and a contract record's announce and accept (one pack read through
    /// [`crate::coordstore::CoordStore`]); then the journal's replay at
    /// open.  Real redb with fsync, in-process (no socket); packs over
    /// [`LocalStore`].  `TASO_BENCH_N` rounds (500).
    ///
    /// Predictions, written before the first run (2026-10-24):
    /// 1. effect append within +10% of a plain append at p50 (the same
    ///    fsync dominates; the journal row and the decode share it) — over
    ///    +10% is a defect to fix (D33);
    /// 2. announce about one plain append (within ±20% at p50);
    /// 3. accept a plain append + 5–30% at p50 (one small pack read);
    /// 4. replay linear, ≤ 0.1 ms per journal entry.
    #[test]
    #[ignore = "benchmark: run alone, in release"]
    fn coordinator_log() {
        use std::collections::BTreeSet;
        use std::sync::Arc;
        use taso_core::canon::Canonical;
        use taso_core::contract::{
            submission_id, ContractRecord, NominationRefusal, NominationRefused, SealRef,
        };
        use taso_core::coordlog::{Answer, Head, Submitted};
        use taso_core::envelope::{BranchId, ChronicleId, Epoch, HashVal};
        use taso_core::model::WardenId;
        use taso_core::record::{IntentRecord, OpId, OutcomeRecord, OutcomeState, Record};

        use crate::coordinator::{Coord, Coordinator, LogConfig};
        use crate::coordstore::CoordStore;
        use crate::segment::Segment;

        struct NoSend;
        impl Sender for NoSend {
            fn send(&self, _: &Dataset, _: Option<&str>, _: Lsn) -> io::Result<ByteStream> {
                Err(io::ErrorKind::Unsupported.into())
            }
        }

        let rounds = n(500);
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<LocalStore> = Arc::new(LocalStore::new(dir.path().join("bucket")));
        let config = || LogConfig {
            store: Arc::new(CoordStore::new(store.clone(), "vessels")),
            ..LogConfig::default()
        };
        let db = dir.path().join("coord.redb");
        let coord = Coordinator::open_with(&db, config()).unwrap();
        let a = WardenId::new(1);
        let c = ChronicleId::from_bytes([0x4d; 16]);
        let g = coord.register(c, a).unwrap();
        let mut seg = Segment::create(dir.path().join("seg"), c, Position::GENESIS).unwrap();
        let packs = Packs::new(store.clone(), NoSend, "vessels", c).unwrap();
        let mut tail = Position {
            lsn: g.lsn,
            hash: g.hash,
        };
        let next = |seg: &mut Segment, tail: &mut Position, stream: Stream, p: Payload| {
            let r = Record::new(
                c,
                BranchId::TRUNK,
                Epoch::FIRST,
                stream,
                tail.lsn.next(),
                tail.hash,
                p,
            );
            seg.append(&r.envelope, &r.payload.canon_bytes()).unwrap();
            *tail = Position {
                lsn: r.envelope.lsn,
                hash: r.envelope.hash,
            };
            r
        };
        let us = |t: Instant| t.elapsed().as_micros() as u64;
        let (mut plain, mut effect, mut announce, mut accept) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut head = Head::EMPTY;
        let started = Instant::now();
        for i in 0..rounds as u64 {
            let intent = Payload::Intent(IntentRecord {
                op: OpId::new(i + 1),
                provider: "mail".into(),
                request: vec![7; 200],
                footprint: Vec::new(),
                dispatch: Dispatch::Immediate,
                retry: RetryPolicy::UnsafeToRetry,
                consequence: Consequence::Irreversible,
                authority: Vec::new(),
                barrier: Some(taso_core::record::BarrierId::new(i + 1)),
            });
            let size = intent.canon_bytes().len();
            // 1. A plain append of the same size.
            let r = next(
                &mut seg,
                &mut tail,
                Stream::Fs,
                Payload::Raw(vec![1; size - 9]),
            );
            let t = Instant::now();
            coord.append(a, &r.envelope).unwrap();
            plain.push(us(t));
            // 2. The effect record, with its bytes.
            let r = next(&mut seg, &mut tail, Stream::Effect, intent);
            let bytes = r.payload.canon_bytes();
            let t = Instant::now();
            coord.append_batch_with(a, &[r.envelope], &[bytes]).unwrap();
            effect.push(us(t));
            let o = next(
                &mut seg,
                &mut tail,
                Stream::Effect,
                Payload::Outcome(OutcomeRecord {
                    op: OpId::new(i + 1),
                    state: OutcomeState::ConfirmedApplied,
                    evidence: None,
                }),
            );
            coord
                .append_batch_with(a, &[o.envelope], &[o.payload.canon_bytes()])
                .unwrap();
            // 3. A contract record: appended, shipped in its own pack,
            // announced, accepted.
            let rec = ContractRecord::NominationRefused(NominationRefused {
                chronicle: c,
                seal: SealRef {
                    lsn: Lsn::new(i + 1),
                    hash: HashVal::from_bytes(*blake3::hash(&i.to_le_bytes()).as_bytes()),
                },
                exclude: BTreeSet::new(),
                reason: NominationRefusal::SealNotAccepted,
                input_manifest_key: None,
            });
            let r = next(
                &mut seg,
                &mut tail,
                Stream::Ctl,
                Payload::Contract(Box::new(rec.clone())),
            );
            coord.append(a, &r.envelope).unwrap();
            let shipped = packs.ship_log(&[&seg], tail).unwrap().unwrap();
            let name = format!(
                "{:020}-{:020}-{:020}",
                shipped.end.lsn.get(),
                shipped.base.lsn.get(),
                0
            );
            let sub = Submitted::Contract(rec);
            let s = submission_id(sub.logical_id(), sub.digest(), Epoch::FIRST, i);
            let t = Instant::now();
            coord
                .announce(a, c, Epoch::FIRST, s, sub.logical_id(), sub.digest())
                .unwrap()
                .unwrap();
            announce.push(us(t));
            let digest = sub.digest();
            let t = Instant::now();
            let got = coord
                .accept(a, c, Epoch::FIRST, s, head, name, sub)
                .unwrap();
            accept.push(us(t));
            let Answer::Accepted { log_pos, .. } = got else {
                panic!("not accepted: {got:?}");
            };
            head = Head {
                pos: log_pos,
                digest,
            };
        }
        let wall = started.elapsed().as_secs_f64();
        assert!(coord.obligations(c).unwrap().is_empty());
        drop(coord);
        // 4. Replay at open.
        let t = Instant::now();
        let coord = Coordinator::open_with(&db, config()).unwrap();
        let replay_ms = t.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(coord.query_chronicle(c).unwrap().unwrap().head, head);

        let line = |name: &str, v: &mut Vec<u64>| {
            v.sort_unstable();
            println!(
                "  {name:<18} p50 {:>8.3} ms   p95 {:>8.3} ms   (n={})",
                timing::quantile(v, 0.5) as f64 / 1000.0,
                timing::quantile(v, 0.95) as f64 / 1000.0,
                v.len()
            );
            timing::quantile(v, 0.5) as f64
        };
        println!("\n=== coordinator log (P4 1d-4) ===");
        println!(
            "TMPDIR={}",
            std::env::var("TMPDIR").unwrap_or_else(|_| "(default)".into())
        );
        let block = (rounds / 5).max(1);
        for (name, v) in [
            ("plain append", &plain),
            ("effect append", &effect),
            ("announce", &announce),
            ("accept", &accept),
        ] {
            print!("{}", growth(name, v, block));
        }
        let p = line("plain append", &mut plain);
        let e = line("effect append", &mut effect);
        let an = line("announce", &mut announce);
        let ac = line("accept", &mut accept);
        // Journal entries: one per announce, accept, two obligation changes
        // per round, and the register's sync.
        let entries = rounds * 4 + 1;
        println!(
            "  effect / plain {:+.1}%   announce / plain {:+.1}%   accept / plain {:+.1}%",
            (e / p - 1.0) * 100.0,
            (an / p - 1.0) * 100.0,
            (ac / p - 1.0) * 100.0
        );
        println!(
            "  replay at open: {replay_ms:.1} ms for {entries} journal entries ({:.4} ms each)",
            replay_ms / entries as f64
        );
        println!("  wall {wall:.1} s");
    }
}
