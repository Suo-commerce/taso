//! Batched Seal snapshots: one ZFS transaction group for many Vessels.
//!
//! # Why
//!
//! Every `zfs snapshot` waits for its own pool transaction group (txg)
//! to sync.  With 64 Vessels sealing at once they queue on the pool:
//! measured on the test server, `seal.snapshot` p50 195 ms and Seal p95
//! 374 ms at p64, against the P1 gate's 50 ms (finding 2026-10-16).
//!
//! # How
//!
//! Seals that arrive while a batch is running are queued.  The first
//! caller leads: it takes everything queued and runs **one channel
//! program** (`zfs program`, Lua, run in syncing context) per pool.  The
//! program takes each snapshot and sets its `taso:seal` binding in the
//! same txg, so a snapshot is never visible without its binding, which
//! is what `zfs snapshot -o` guarantees for one.  If the binding cannot
//! be set, the program destroys the snapshot it just took.
//!
//! Then one `zfs list` of every requested snapshot decides each answer.
//! The program's report is not trusted alone, because a program that
//! fails part way may have done some of its work:
//!
//! - the program says the snapshot already existed →
//!   [`ZfsError::AlreadyExists`], as for a single snapshot;
//! - listed and bound to the requested hash → the [`Snapshot`];
//! - listed but not bound to it → [`ZfsError::SealMismatch`];
//! - not listed → the program's error for it.
//!
//! A dataset appears at most once per program; a second Seal of the same
//! dataset waits for the next batch (a Vessel seals one at a time, so this
//! is only a guard).
//!
//! Batching is opt-in: [`crate::zfs::Zfs::batched`].  Clones of a batched
//! driver share one queue, so every Vessel of a node made from one driver
//! is batched together.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Cursor;
use std::sync::{mpsc, Mutex};

use taso_core::envelope::{HashVal, Lsn};

use crate::zfs::{parse_line_for, Dataset, Runner, Snapshot, ZfsError, LIST_COLUMNS, SEAL_PROPERTY};

/// The channel program.  Arguments: pairs of (snapshot name, seal hash).
/// Returns a table: snapshot name → 0 or an errno.  A failure to bind is
/// reported as 1000 + errno, after the snapshot was destroyed.
pub(crate) const PROGRAM: &str = r#"
local args = ...
local argv = args["argv"]
local out = {}
for i = 1, #argv, 2 do
  local snap = argv[i]
  local hash = argv[i + 1]
  local err = zfs.sync.snapshot(snap)
  if err == 0 then
    local perr = zfs.sync.set_prop(snap, "taso:seal", hash)
    if perr ~= 0 then
      zfs.sync.destroy(snap)
      err = 1000 + perr
    end
  end
  out[snap] = err
end
return out
"#;

/// `EEXIST`: the snapshot was already there.
const EEXIST: i64 = 17;

/// The queue shared by the clones of one batched driver.
#[derive(Default)]
pub struct SnapBatch {
    queue: Mutex<Queue>,
    /// Programs run so far (tests check that Seals were grouped).
    #[cfg(test)]
    pub(crate) programs: std::sync::atomic::AtomicUsize,
}

impl fmt::Debug for SnapBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SnapBatch")
    }
}

#[derive(Default)]
struct Queue {
    jobs: Vec<Job>,
    leading: bool,
}

struct Job {
    dataset: Dataset,
    seal: Lsn,
    hash: HashVal,
    answer: mpsc::Sender<Result<Snapshot, ZfsError>>,
}

impl Job {
    fn name(&self) -> String {
        self.dataset.seal_snapshot(self.seal)
    }
}

impl SnapBatch {
    /// Take the snapshot for the Seal at `seal` bound to `hash`, in a batch
    /// with whatever else is queued.  `runner` runs the batch if this
    /// caller leads it.
    pub(crate) fn snapshot(
        &self,
        runner: &dyn Runner,
        dataset: &Dataset,
        seal: Lsn,
        hash: HashVal,
    ) -> Result<Snapshot, ZfsError> {
        let (answer, rx) = mpsc::channel();
        let job = Job { dataset: dataset.clone(), seal, hash, answer };
        let lead = {
            let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
            q.jobs.push(job);
            !std::mem::replace(&mut q.leading, true)
        };
        if lead {
            self.lead(runner);
        }
        rx.recv().unwrap_or_else(|_| {
            Err(ZfsError::Spawn("the snapshot batch leader is gone".to_string()))
        })
    }

    /// Run batches until the queue is empty.
    fn lead(&self, runner: &dyn Runner) {
        // If a batch panics, give up leading and drop what is queued (each
        // dropped job answers its caller with an error), so the next
        // caller leads instead of every later Seal waiting forever.
        struct Abdicate<'a>(&'a Mutex<Queue>);
        impl Drop for Abdicate<'_> {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    let mut q = self.0.lock().unwrap_or_else(|e| e.into_inner());
                    q.jobs.clear();
                    q.leading = false;
                }
            }
        }
        let _abdicate = Abdicate(&self.queue);
        loop {
            let jobs = {
                let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
                if q.jobs.is_empty() {
                    q.leading = false;
                    return;
                }
                // One Seal per dataset per batch; the rest wait.
                let mut seen = BTreeSet::new();
                let (now, later): (Vec<Job>, Vec<Job>) =
                    std::mem::take(&mut q.jobs).into_iter().partition(|j| seen.insert(j.dataset.as_str().to_string()));
                q.jobs = later;
                now
            };
            let mut by_pool: BTreeMap<String, Vec<Job>> = BTreeMap::new();
            for job in jobs {
                by_pool.entry(job.dataset.pool().to_string()).or_default().push(job);
            }
            for (pool, jobs) in by_pool {
                self.run(runner, &pool, jobs);
            }
        }
    }

    /// One channel program for `jobs` (all in `pool`), one list, answers.
    fn run(&self, runner: &dyn Runner, pool: &str, jobs: Vec<Job>) {
        #[cfg(test)]
        self.programs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let names: Vec<String> = jobs.iter().map(Job::name).collect();

        let program = {
            let _t = crate::timing::span("zfs.program");
            let mut args = vec!["program".to_string(), "-j".to_string(), pool.to_string(), "-".to_string()];
            for (job, name) in jobs.iter().zip(&names) {
                args.push(name.clone());
                args.push(job.hash.to_string());
            }
            run_program(runner, args)
        };

        let listed = {
            let _t = crate::timing::span("zfs.batch_list");
            let mut args: Vec<String> =
                ["list", "-H", "-p", "-t", "snapshot", "-o", LIST_COLUMNS].iter().map(|s| s.to_string()).collect();
            args.extend(names.iter().cloned());
            // Missing names make `zfs list` exit non-zero but it still
            // prints the others: read stdout whatever the status.
            runner.run(&args).map(|out| out.stdout)
        };

        for (job, name) in jobs.into_iter().zip(names) {
            let errno = program.as_ref().ok().and_then(|r| r.get(&name).copied());
            let answer = decide(&job, &name, &program, errno, &listed);
            let _ = job.answer.send(answer);
        }
    }
}

/// Run the program; its report, snapshot name → errno.
fn run_program(runner: &dyn Runner, args: Vec<String>) -> Result<BTreeMap<String, i64>, ZfsError> {
    let out = runner.run_input(&args, &mut Cursor::new(PROGRAM.as_bytes()))?;
    if !out.success {
        return Err(ZfsError::Exit { args, code: out.code, stderr: out.stderr });
    }
    parse_report(&out.stdout)
}

/// `zfs program -j` prints `{"return": {name: errno, ...}}`.
pub(crate) fn parse_report(stdout: &str) -> Result<BTreeMap<String, i64>, ZfsError> {
    let bad = |why| ZfsError::Parse { line: stdout.trim().to_string(), why };
    let v: serde_json::Value = serde_json::from_str(stdout).map_err(|_| bad("zfs program output is not JSON"))?;
    let table = v.get("return").and_then(|r| r.as_object()).ok_or_else(|| bad("no return table"))?;
    table
        .iter()
        .map(|(k, v)| Ok((k.clone(), v.as_i64().ok_or_else(|| bad("an errno is not an integer"))?)))
        .collect()
}

/// The answer for one job (see the module docs for the rules).
fn decide(
    job: &Job,
    name: &str,
    program: &Result<BTreeMap<String, i64>, ZfsError>,
    errno: Option<i64>,
    listed: &Result<String, ZfsError>,
) -> Result<Snapshot, ZfsError> {
    if errno == Some(EEXIST) {
        return Err(ZfsError::AlreadyExists(name.to_string()));
    }
    let stdout = listed.as_ref().map_err(Clone::clone)?;
    let mut found = None;
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        if let Some(s) = parse_line_for(&job.dataset, line)? {
            if s.seal == job.seal {
                found = Some(s);
            }
        }
    }
    match found {
        Some(s) if s.seal_hash == Some(job.hash) => Ok(s),
        Some(_) => Err(ZfsError::SealMismatch(name.to_string())),
        None => Err(match (program, errno) {
            (Err(e), _) => e.clone(),
            (Ok(_), Some(errno)) => ZfsError::Channel { name: name.to_string(), errno },
            (Ok(_), None) => ZfsError::Parse {
                line: name.to_string(),
                why: "zfs program did not report this snapshot",
            },
        }),
    }
}

/// The binding property must be the one [`PROGRAM`] sets.
const _: () = assert!(SEAL_PROPERTY.len() == "taso:seal".len());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zfs::{Output, Zfs};
    use std::io::Read;
    use std::sync::{Arc, Barrier};

    #[test]
    fn program_names_the_binding_property() {
        assert!(PROGRAM.contains(&format!("\"{SEAL_PROPERTY}\"")));
    }

    #[test]
    fn report_parses() {
        let r = parse_report(r#"{"return": {"p/a@taso-seal-1": 0, "p/b@taso-seal-2": 17}}"#).unwrap();
        assert_eq!(r["p/a@taso-seal-1"], 0);
        assert_eq!(r["p/b@taso-seal-2"], 17);
        assert!(parse_report("Channel program fully executed").is_err());
        assert!(parse_report(r#"{"return": {"x": "zero"}}"#).is_err());
        assert!(parse_report(r#"{"other": {}}"#).is_err());
    }

    /// (createtxg, guid, binding).
    type FakeSnap = (u64, u64, Option<String>);

    /// A fake pool behind the runner: `zfs program` and `zfs list`, with
    /// snapshots as name → (createtxg, guid, binding).
    #[derive(Clone, Default)]
    struct FakeZfs {
        snaps: Arc<Mutex<BTreeMap<String, FakeSnap>>>,
        /// Make the next program's `set_prop` fail with this errno.
        bind_fails: Arc<Mutex<Option<i64>>>,
        /// Make the next program bind every snapshot to this hash instead.
        binds_wrong: Arc<Mutex<Option<String>>>,
        /// Per program, in order: die after this many snapshots.
        dies_after: Arc<Mutex<std::collections::VecDeque<Option<usize>>>>,
        /// Hold every program until released, to queue callers behind it.
        gate: Arc<Mutex<Option<mpsc::Receiver<()>>>>,
        calls: Arc<Mutex<Vec<Vec<String>>>>,
        txg: Arc<std::sync::atomic::AtomicU64>,
    }

    impl Runner for FakeZfs {
        fn run(&self, args: &[String]) -> Result<Output, ZfsError> {
            self.calls.lock().unwrap().push(args.to_vec());
            assert_eq!(&args[..7], &["list", "-H", "-p", "-t", "snapshot", "-o", LIST_COLUMNS]);
            let snaps = self.snaps.lock().unwrap();
            let mut stdout = String::new();
            let mut missing = false;
            for name in &args[7..] {
                match snaps.get(name) {
                    Some((txg, guid, b)) => {
                        stdout += &format!("{name}\t{txg}\t{guid}\t{}\n", b.as_deref().unwrap_or("-"))
                    }
                    None => missing = true,
                }
            }
            Ok(Output {
                success: !missing,
                code: Some(i32::from(missing)),
                stdout,
                stderr: if missing { "dataset does not exist".into() } else { String::new() },
            })
        }

        fn run_input(&self, args: &[String], input: &mut dyn Read) -> Result<Output, ZfsError> {
            self.calls.lock().unwrap().push(args.to_vec());
            let mut script = String::new();
            input.read_to_string(&mut script).unwrap();
            assert_eq!(script, PROGRAM);
            assert_eq!(&args[..4], &["program", "-j", &args[2], "-"]);
            if let Some(gate) = self.gate.lock().unwrap().as_ref() {
                gate.recv().unwrap();
            }
            let txg = self.txg.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 100;
            let bind_fails = self.bind_fails.lock().unwrap().take();
            let binds_wrong = self.binds_wrong.lock().unwrap().take();
            let dies_after = self.dies_after.lock().unwrap().pop_front().flatten();
            let mut snaps = self.snaps.lock().unwrap();
            let mut report = serde_json::Map::new();
            for (i, pair) in args[4..].chunks(2).enumerate() {
                if dies_after == Some(i) {
                    return Ok(Output { success: false, code: Some(1), stdout: String::new(), stderr: "out of instructions".into() });
                }
                let (name, hash) = (&pair[0], &pair[1]);
                assert!(name.starts_with(&format!("{}/", args[2])), "{name} is not in pool {}", args[2]);
                let errno = if snaps.contains_key(name) {
                    EEXIST
                } else if let Some(e) = bind_fails {
                    1000 + e
                } else {
                    let guid = 5000 + snaps.len() as u64;
                    snaps.insert(name.clone(), (txg, guid, Some(binds_wrong.clone().unwrap_or(hash.clone()))));
                    0
                };
                report.insert(name.clone(), errno.into());
            }
            Ok(Output {
                success: true,
                code: Some(0),
                stdout: serde_json::json!({ "return": report }).to_string(),
                stderr: String::new(),
            })
        }
    }

    fn ds(name: &str) -> Dataset {
        Dataset::new(name).unwrap()
    }

    fn h(n: u8) -> HashVal {
        HashVal::from_bytes([n; 32])
    }

    fn driver(fake: &FakeZfs) -> Zfs<FakeZfs> {
        Zfs::with_runner(fake.clone()).batched()
    }

    #[test]
    fn one_seal_is_snapshotted_bound_and_listed() {
        let fake = FakeZfs::default();
        let zfs = driver(&fake);
        let s = zfs.snapshot(&ds("p/v1"), Lsn::new(3), h(3)).unwrap();
        assert_eq!((s.seal, s.seal_hash, s.createtxg), (Lsn::new(3), Some(h(3)), 100));
        assert_eq!(s.dataset, ds("p/v1"));
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 2, "one program, one list: {calls:?}");
        assert_eq!(&calls[0][4..], &["p/v1@taso-seal-00000000000000000003".to_string(), h(3).to_string()]);
    }

    #[test]
    fn an_existing_seal_snapshot_is_already_exists() {
        let fake = FakeZfs::default();
        let zfs = driver(&fake);
        zfs.snapshot(&ds("p/v1"), Lsn::new(3), h(3)).unwrap();
        assert!(matches!(zfs.snapshot(&ds("p/v1"), Lsn::new(3), h(3)), Err(ZfsError::AlreadyExists(_))));
    }

    #[test]
    fn a_failed_binding_leaves_no_snapshot() {
        let fake = FakeZfs::default();
        *fake.bind_fails.lock().unwrap() = Some(1);
        let zfs = driver(&fake);
        let e = zfs.snapshot(&ds("p/v1"), Lsn::new(3), h(3)).unwrap_err();
        assert_eq!(e, ZfsError::Channel { name: "p/v1@taso-seal-00000000000000000003".into(), errno: 1001 });
        assert!(fake.snaps.lock().unwrap().is_empty());
        // And the next one works.
        zfs.snapshot(&ds("p/v1"), Lsn::new(3), h(3)).unwrap();
    }

    #[test]
    fn a_snapshot_bound_to_another_seal_is_a_mismatch() {
        let fake = FakeZfs::default();
        fake.snaps.lock().unwrap().insert("p/v1@taso-seal-00000000000000000003".into(), (1, 2, Some(h(9).to_string())));
        // The program reports EEXIST for it: AlreadyExists, as for one.
        let zfs = driver(&fake);
        assert!(matches!(zfs.snapshot(&ds("p/v1"), Lsn::new(3), h(3)), Err(ZfsError::AlreadyExists(_))));
    }

    /// The program said it worked but the list shows another binding: the
    /// list wins.
    #[test]
    fn a_wrong_binding_is_a_mismatch() {
        let fake = FakeZfs::default();
        *fake.binds_wrong.lock().unwrap() = Some(h(9).to_string());
        let zfs = driver(&fake);
        assert_eq!(
            zfs.snapshot(&ds("p/v1"), Lsn::new(3), h(3)),
            Err(ZfsError::SealMismatch("p/v1@taso-seal-00000000000000000003".into()))
        );
    }

    /// A program that dies part way: what it did is found by the list,
    /// what it did not is the program's error.
    #[test]
    fn a_program_that_dies_part_way_is_judged_by_the_list() {
        let fake = FakeZfs::default();
        let zfs = driver(&fake);
        // Queue three Seals behind a held program; the next one dies
        // after its first snapshot.
        fake.dies_after.lock().unwrap().extend([None, Some(1)]);
        let (release, gate) = mpsc::channel();
        *fake.gate.lock().unwrap() = Some(gate);
        std::thread::scope(|s| {
            let first = {
                let zfs = Clone::clone(&zfs);
                s.spawn(move || zfs.snapshot(&ds("p/v0"), Lsn::new(1), h(1)))
            };
            while fake.calls.lock().unwrap().is_empty() {
                std::thread::yield_now();
            }
            let rest: Vec<_> = (1..=3u8)
                .map(|i| {
                    let zfs = Clone::clone(&zfs);
                    s.spawn(move || zfs.snapshot(&ds(&format!("p/v{i}")), Lsn::new(1), h(i)))
                })
                .collect();
            while queued(&zfs) < 3 {
                std::thread::yield_now();
            }
            release.send(()).unwrap();
            release.send(()).unwrap();
            first.join().unwrap().unwrap();
            let got: Vec<_> = rest.into_iter().map(|t| t.join().unwrap()).collect();
            // Whichever was queued first was taken; the program died
            // before the others.
            let ok: Vec<_> = got.iter().filter_map(|g| g.as_ref().ok()).collect();
            assert_eq!(ok.len(), 1, "{got:?}");
            assert!(fake.snaps.lock().unwrap().contains_key(&ok[0].name()));
            for g in got.iter().filter(|g| g.is_err()) {
                assert!(matches!(g, Err(ZfsError::Exit { .. })), "{g:?}");
            }
        });
        assert_eq!(fake.snaps.lock().unwrap().len(), 2);
    }

    fn queued(zfs: &Zfs<FakeZfs>) -> usize {
        zfs.batch().unwrap().queue.lock().unwrap().jobs.len()
    }

    /// Many Vessels sealing at once share programs; each gets its own
    /// bound snapshot; a dataset never appears twice in one program.
    #[test]
    fn concurrent_seals_share_programs() {
        const VESSELS: u8 = 32;
        const TURNS: u64 = 10;
        let fake = FakeZfs::default();
        let zfs = driver(&fake);
        let start = Barrier::new(usize::from(VESSELS));
        std::thread::scope(|s| {
            for v in 0..VESSELS {
                let (zfs, start) = (Clone::clone(&zfs), &start);
                s.spawn(move || {
                    start.wait();
                    for t in 1..=TURNS {
                        let snap = zfs.snapshot(&ds(&format!("p/v{v}")), Lsn::new(t), h(v)).unwrap();
                        assert_eq!((snap.seal, snap.seal_hash), (Lsn::new(t), Some(h(v))));
                    }
                });
            }
        });
        let seals = usize::from(VESSELS) * TURNS as usize;
        assert_eq!(fake.snaps.lock().unwrap().len(), seals);
        let programs = zfs.batch().unwrap().programs.load(std::sync::atomic::Ordering::Relaxed);
        assert!(programs < seals, "{programs} programs for {seals} Seals: nothing was batched");
        for call in fake.calls.lock().unwrap().iter().filter(|c| c[0] == "program") {
            let names: Vec<&String> = call[4..].iter().step_by(2).collect();
            let datasets: BTreeSet<&str> = names.iter().map(|n| n.split('@').next().unwrap()).collect();
            assert_eq!(datasets.len(), names.len(), "a dataset twice in one program: {call:?}");
        }
    }

    /// Two pools: one program per pool, each given only its own snapshots.
    #[test]
    fn one_program_per_pool() {
        let fake = FakeZfs::default();
        let zfs = driver(&fake);
        let (release, gate) = mpsc::channel();
        *fake.gate.lock().unwrap() = Some(gate);
        std::thread::scope(|s| {
            let first = {
                let zfs = Clone::clone(&zfs);
                s.spawn(move || zfs.snapshot(&ds("p/a"), Lsn::new(1), h(1)))
            };
            while fake.calls.lock().unwrap().is_empty() {
                std::thread::yield_now();
            }
            let rest: Vec<_> = ["p/b", "q/c", "q/d"]
                .into_iter()
                .map(|d| {
                    let zfs = Clone::clone(&zfs);
                    s.spawn(move || zfs.snapshot(&ds(d), Lsn::new(1), h(2)))
                })
                .collect();
            while queued(&zfs) < 3 {
                std::thread::yield_now();
            }
            for _ in 0..3 {
                release.send(()).unwrap();
            }
            first.join().unwrap().unwrap();
            for t in rest {
                t.join().unwrap().unwrap();
            }
        });
        let programs: Vec<Vec<String>> =
            fake.calls.lock().unwrap().iter().filter(|c| c[0] == "program").cloned().collect();
        assert_eq!(programs.len(), 3, "{programs:?}");
        assert_eq!(programs[1][2], "p");
        assert_eq!(programs[1].len(), 6);
        assert_eq!(programs[2][2], "q");
        assert_eq!(programs[2].len(), 8);
    }

    /// A second Seal of the same dataset waits for the next program.
    #[test]
    fn a_dataset_twice_goes_in_two_programs() {
        let fake = FakeZfs::default();
        let zfs = driver(&fake);
        let (release, gate) = mpsc::channel();
        *fake.gate.lock().unwrap() = Some(gate);
        std::thread::scope(|s| {
            let first = {
                let zfs = Clone::clone(&zfs);
                s.spawn(move || zfs.snapshot(&ds("p/z"), Lsn::new(1), h(1)))
            };
            while fake.calls.lock().unwrap().is_empty() {
                std::thread::yield_now();
            }
            let rest: Vec<_> = [2u64, 3]
                .into_iter()
                .map(|l| {
                    let zfs = Clone::clone(&zfs);
                    s.spawn(move || zfs.snapshot(&ds("p/a"), Lsn::new(l), h(1)))
                })
                .collect();
            while queued(&zfs) < 2 {
                std::thread::yield_now();
            }
            for _ in 0..3 {
                release.send(()).unwrap();
            }
            first.join().unwrap().unwrap();
            for t in rest {
                t.join().unwrap().unwrap();
            }
        });
        let programs = fake.calls.lock().unwrap().iter().filter(|c| c[0] == "program").count();
        assert_eq!(programs, 3);
    }

    /// A leader that panics: callers queued behind it are answered, and
    /// the next Seal leads.
    #[test]
    fn a_panicking_leader_does_not_wedge_the_queue() {
        #[derive(Clone)]
        struct Panics(FakeZfs, Arc<Mutex<Option<mpsc::Receiver<()>>>>);
        impl Runner for Panics {
            fn run(&self, args: &[String]) -> Result<Output, ZfsError> {
                self.0.run(args)
            }
            fn run_input(&self, args: &[String], input: &mut dyn Read) -> Result<Output, ZfsError> {
                let gate = self.1.lock().unwrap().take();
                if let Some(gate) = gate {
                    gate.recv().unwrap();
                    panic!("boom");
                }
                self.0.run_input(args, input)
            }
        }
        let fake = FakeZfs::default();
        let (release, gate) = mpsc::channel();
        let zfs = Zfs::with_runner(Panics(fake.clone(), Arc::new(Mutex::new(Some(gate))))).batched();
        std::thread::scope(|s| {
            let leader = {
                let zfs = Clone::clone(&zfs);
                s.spawn(move || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        zfs.snapshot(&ds("p/a"), Lsn::new(1), h(1))
                    }))
                })
            };
            // Wait until the leader has taken its job.
            loop {
                let q = zfs.batch().unwrap().queue.lock().unwrap();
                if q.leading && q.jobs.is_empty() {
                    break;
                }
                drop(q);
                std::thread::yield_now();
            }
            let queued_one = {
                let zfs = Clone::clone(&zfs);
                s.spawn(move || zfs.snapshot(&ds("p/b"), Lsn::new(1), h(2)))
            };
            while zfs.batch().unwrap().queue.lock().unwrap().jobs.is_empty() {
                std::thread::yield_now();
            }
            release.send(()).unwrap();
            assert!(leader.join().unwrap().is_err(), "the leader panicked");
            assert!(queued_one.join().unwrap().is_err(), "queued behind the panic: answered with an error");
        });
        zfs.snapshot(&ds("p/c"), Lsn::new(1), h(3)).unwrap();
    }
}
