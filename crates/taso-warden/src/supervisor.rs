//! A long-running Warden's loop (W1; plan: claude/Taso_plan_k8s_docker_2026-10-17.md).
//!
//! The [`Supervisor`] keeps what runs equal to what a [`VesselSource`] says
//! should run.  Each round it polls the source, passes the answer through the
//! [`Guard`] (nothing from a source is trusted), and then:
//!
//! - starts a Vessel that should run and does not;
//! - stops a running Vessel that should not run any more ([`Stop`]: its
//!   container is killed; the next start rolls back to its last Seal);
//! - after a Vessel's run ends without a stop, starts it again if its
//!   [`Restart`](crate::daemon::Restart) policy says so, after a backoff;
//!   otherwise it stays done until it is removed and listed again.
//!
//! # Rules that keep it safe
//!
//! - **One run per Vessel at a time.**  A Vessel being stopped is waited for
//!   to the end before it may start again; the Chronicle's directory lock is
//!   the backstop, not the mechanism.
//! - **A source that fails changes nothing**: no start, no stop, until it
//!   answers again.
//! - **A refused entry changes nothing** for a running Vessel (the guard keeps
//!   its last good entry); refusals are reported as events.
//! - **Entries take effect at the next start.**  A changed restart policy or
//!   takeover is used the next time the Vessel starts; a running agent is
//!   never bounced because its entry changed.
//! - **A Vessel stopped on purpose is never restarted** by its policy.  If it
//!   was listed again while its run was being stopped, it starts afresh once
//!   that run has ended (a new listing, not a restart).
//! - **A panicking run** is reported and counts as a run whose agent never
//!   ran (a failure for the restart policy).
//!
//! # Ending
//!
//! With a finite source (the daemon config: today's `taso-wardend`), the
//! loop returns once the source has answered, nothing runs and nothing waits
//! to restart.  With an infinite source it returns only on shutdown, after
//! stopping every Vessel and waiting for each.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::daemon::{DaemonError, Node, Report, Stop, VesselConf};
use crate::source::{Guard, Refused, SourceError, VesselKey, VesselSource};

/// How one Vessel's run is done; [`Node`] does it for real.
pub trait RunVessel: Send + Sync + 'static {
    /// What a run returns.
    type Out: Send + 'static;
    /// Run `vc` until its agent exits or `stop` is requested.
    fn run(&self, vc: &VesselConf, stop: &Stop) -> Self::Out;
    /// Whether the agent exited ok (`None`: it never ran) and whether the
    /// run ended on a stop.
    fn outcome(out: &Self::Out) -> (Option<bool>, bool);
}

impl RunVessel for Node {
    type Out = Result<Report, DaemonError>;

    fn run(&self, vc: &VesselConf, stop: &Stop) -> Self::Out {
        self.run_vessel_until(vc, stop)
    }

    fn outcome(out: &Self::Out) -> (Option<bool>, bool) {
        match out {
            Ok(r) => (r.agent.as_ref().map(|(ok, _)| *ok), r.stopped),
            Err(_) => (None, false),
        }
    }
}

/// What the supervisor reports, in order.
#[derive(Debug)]
pub enum Event<O> {
    /// A run started.
    Started(VesselConf),
    /// A run ended.  `restart_in` says when it starts again, if it does.
    Exited {
        /// The entry it ran with.
        vc: VesselConf,
        /// What the run returned.
        out: O,
        /// The run ended on a stop.
        stopped: bool,
        /// When it runs again, if its policy says so.
        restart_in: Option<Duration>,
    },
    /// A run panicked; treated as an agent that never ran.
    Panicked {
        /// The entry it ran with.
        vc: VesselConf,
        /// When it runs again, if its policy says so.
        restart_in: Option<Duration>,
    },
    /// A stop was requested (removed from the source, or shutdown).
    Stopping(VesselConf),
    /// The guard refused an entry.
    Refused(Refused),
    /// The source could not answer; nothing changed.
    SourceFailed(SourceError),
}

/// The loop's clock settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// How long one poll of the source may wait (one round).
    pub tick: Duration,
    /// The first restart delay; doubled per restart in a row.
    pub backoff_first: Duration,
    /// The longest restart delay.
    pub backoff_max: Duration,
    /// A run at least this long resets the backoff.
    pub healthy: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            tick: Duration::from_millis(200),
            backoff_first: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            healthy: Duration::from_secs(600),
        }
    }
}

impl Timing {
    /// The delay before restart number `n` in a row (1 = the first).
    fn backoff(&self, n: u32) -> Duration {
        let factor = 1u32.checked_shl(n.saturating_sub(1)).unwrap_or(u32::MAX);
        self.backoff_first
            .saturating_mul(factor)
            .min(self.backoff_max)
    }
}

/// One Vessel the supervisor knows of.
struct Slot<O> {
    /// The entry the next start uses (the guard's latest good one).
    vc: VesselConf,
    state: State<O>,
    /// Restarts in a row without a healthy run.
    streak: u32,
}

enum State<O> {
    /// Should start now (new, or a restart whose time came).
    Ready,
    /// A restart waits until then.
    Waiting(Instant),
    /// A run is going.
    Running {
        handle: JoinHandle<O>,
        stop: Stop,
        since: Instant,
        vc: VesselConf,
    },
    /// Ran and is not restarted (its policy, or stopped on purpose).
    Done,
}

/// Keeps what runs equal to what the source says (see the module docs).
pub struct Supervisor<R: RunVessel> {
    runner: Arc<R>,
    guard: Guard,
    timing: Timing,
    vessels: BTreeMap<VesselKey, Slot<R::Out>>,
    /// The keys the source wants now (after the guard).
    wanted: BTreeMap<VesselKey, VesselConf>,
    answered: bool,
}

impl<R: RunVessel> Supervisor<R> {
    /// A supervisor running Vessels with `runner`, checking every set with
    /// `guard`.
    pub fn new(runner: Arc<R>, guard: Guard, timing: Timing) -> Self {
        Self {
            runner,
            guard,
            timing,
            vessels: BTreeMap::new(),
            wanted: BTreeMap::new(),
            answered: false,
        }
    }

    /// Run until a finite source is done, or `shutdown` is requested (see
    /// the module docs).  Every event goes to `on_event` as it happens.
    pub fn run(
        &mut self,
        source: &mut dyn VesselSource,
        shutdown: &Stop,
        mut on_event: impl FnMut(Event<R::Out>),
    ) {
        loop {
            if shutdown.requested() {
                self.wanted.clear();
            } else {
                match source.poll(self.timing.tick) {
                    Ok(Some(set)) => {
                        self.answered = true;
                        let admitted = self.guard.admit(set);
                        for r in admitted.refused {
                            on_event(Event::Refused(r));
                        }
                        self.wanted = admitted
                            .set
                            .into_iter()
                            .map(|vc| (*vc.id().as_bytes(), vc))
                            .collect();
                    }
                    Ok(None) => {}
                    Err(e) => {
                        on_event(Event::SourceFailed(e));
                        // Unknown, not empty: reap ended runs, start and stop nothing.
                        self.reap(&mut on_event);
                        std::thread::sleep(self.timing.tick);
                        continue;
                    }
                }
            }
            self.reap(&mut on_event);
            self.converge(&mut on_event);

            let idle = self
                .vessels
                .values()
                .all(|s| matches!(s.state, State::Done));
            if shutdown.requested()
                && self
                    .vessels
                    .values()
                    .all(|s| !matches!(s.state, State::Running { .. }))
            {
                return;
            }
            if source.is_finite() && self.answered && idle {
                return;
            }
            if shutdown.requested() {
                std::thread::sleep(self.timing.tick.min(Duration::from_millis(20)));
            }
        }
    }

    /// Collect runs that ended; decide restarts.  A restart waits out its
    /// backoff; while the source fails nothing starts at all (the loop does
    /// not converge then), so a restart due meanwhile waits for an answer.
    fn reap(&mut self, on_event: &mut impl FnMut(Event<R::Out>)) {
        let now = Instant::now();
        for (key, slot) in self.vessels.iter_mut() {
            let finished =
                matches!(&slot.state, State::Running { handle, .. } if handle.is_finished());
            if !finished {
                continue;
            }
            let State::Running {
                handle,
                since,
                vc,
                stop,
            } = std::mem::replace(&mut slot.state, State::Done)
            else {
                unreachable!()
            };
            if now.duration_since(since) >= self.timing.healthy {
                slot.streak = 0;
            }
            let (agent_ok, stopped, out) = match handle.join() {
                Ok(out) => {
                    let (ok, stopped) = R::outcome(&out);
                    (ok, stopped || stop.requested(), Some(out))
                }
                Err(_) => (None, stop.requested(), None),
            };
            // A stop on purpose never restarts; otherwise the latest entry's policy decides.
            let restart = !stopped && slot.vc.restart.again(agent_ok);
            let restart_in = restart.then(|| {
                slot.streak += 1;
                self.timing.backoff(slot.streak)
            });
            slot.state = match restart_in {
                Some(d) => State::Waiting(now + d),
                // Stopped because it was removed, but listed again before
                // the run ended: a new listing, not a restart (no backoff).
                None if stopped && self.wanted.contains_key(key) => State::Ready,
                None => State::Done,
            };
            match out {
                Some(out) => on_event(Event::Exited {
                    vc,
                    out,
                    stopped,
                    restart_in,
                }),
                None => on_event(Event::Panicked { vc, restart_in }),
            }
        }
    }

    /// Start what should run, stop what should not.
    fn converge(&mut self, on_event: &mut impl FnMut(Event<R::Out>)) {
        let now = Instant::now();
        // Stop runs no longer wanted; forget idle Vessels no longer wanted.
        self.vessels.retain(|key, slot| {
            if self.wanted.contains_key(key) {
                return true;
            }
            match &slot.state {
                State::Running { stop, vc, .. } => {
                    if !stop.requested() {
                        stop.request();
                        on_event(Event::Stopping(vc.clone()));
                    }
                    true // kept until the run has ended
                }
                _ => false,
            }
        });
        for (key, vc) in &self.wanted {
            let slot = self.vessels.entry(*key).or_insert_with(|| Slot {
                vc: vc.clone(),
                state: State::Ready,
                streak: 0,
            });
            // The latest good entry is used at the next start.
            slot.vc = vc.clone();
            let due = match &slot.state {
                State::Ready => true,
                State::Waiting(at) => *at <= now,
                // A run that is going (or being stopped) is left alone.
                State::Running { .. } | State::Done => false,
            };
            if !due {
                continue;
            }
            let (runner, stop, run_vc) = (self.runner.clone(), Stop::new(), slot.vc.clone());
            let handle = {
                let (stop, run_vc) = (stop.clone(), run_vc.clone());
                std::thread::spawn(move || runner.run(&run_vc, &stop))
            };
            on_event(Event::Started(run_vc.clone()));
            slot.state = State::Running {
                handle,
                stop,
                since: now,
                vc: run_vc,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{Restart, RuntimeConf};
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex;
    use taso_core::record::Namespace;

    // ── fixtures ────────────────────────────────────────────────────

    fn runtime() -> RuntimeConf {
        RuntimeConf {
            rootfs: Some("/r".into()),
            host_uid_base: 200_000,
            landlock_shim: None,
            args: vec!["/a".into()],
            env: vec![],
            memory_bytes: None,
            pids: None,
        }
    }

    fn vc(subject: &str, slot: u32, restart: Restart) -> VesselConf {
        VesselConf {
            namespace: Namespace::from_bytes([7; 16]),
            subject: subject.into(),
            takeover: None,
            uid_slot: slot,
            restart,
            runtime: None,
        }
    }

    fn timing() -> Timing {
        Timing {
            tick: Duration::from_millis(2),
            backoff_first: Duration::from_millis(5),
            backoff_max: Duration::from_millis(40),
            healthy: Duration::from_secs(60),
        }
    }

    /// What one fake run does.
    #[derive(Clone, Copy, Debug)]
    enum Act {
        /// Exit after a while with this agent result.
        Exit(Option<bool>),
        /// Exit with this agent result after this many milliseconds.
        Slow(Option<bool>, u64),
        /// Run until stopped.
        UntilStop,
        /// Panic.
        Panic,
    }

    /// One recorded run: subject, the restart policy it ran with, start,
    /// end, and whether it ended on a stop.
    type RunRecord = (String, Restart, Instant, Instant, bool);

    /// A runner that follows a script per subject and records every run.
    #[derive(Default)]
    struct Fake {
        script: Mutex<HashMap<String, VecDeque<Act>>>,
        /// (subject, restart policy it ran with, started, ended, stopped)
        runs: Mutex<Vec<RunRecord>>,
        live: Mutex<HashMap<String, u32>>,
        overlap: Mutex<bool>,
    }

    impl Fake {
        fn with(script: &[(&str, &[Act])]) -> Arc<Self> {
            let f = Fake::default();
            for (s, acts) in script {
                f.script
                    .lock()
                    .unwrap()
                    .insert(s.to_string(), acts.iter().copied().collect());
            }
            Arc::new(f)
        }
        fn runs_of(&self, s: &str) -> Vec<(Restart, Instant, Instant, bool)> {
            self.runs
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.0 == s)
                .map(|r| (r.1, r.2, r.3, r.4))
                .collect()
        }
    }

    impl RunVessel for Fake {
        type Out = (Option<bool>, bool);
        fn run(&self, vc: &VesselConf, stop: &Stop) -> Self::Out {
            {
                let mut live = self.live.lock().unwrap();
                let n = live.entry(vc.subject.clone()).or_default();
                *n += 1;
                if *n > 1 {
                    *self.overlap.lock().unwrap() = true;
                }
            }
            let start = Instant::now();
            let act = self
                .script
                .lock()
                .unwrap()
                .get_mut(&vc.subject)
                .and_then(|q| q.pop_front())
                .unwrap_or(Act::UntilStop);
            let leave = |stopped: bool| {
                *self.live.lock().unwrap().get_mut(&vc.subject).unwrap() -= 1;
                self.runs.lock().unwrap().push((
                    vc.subject.clone(),
                    vc.restart,
                    start,
                    Instant::now(),
                    stopped,
                ));
            };
            match act {
                Act::Exit(ok) => {
                    std::thread::sleep(Duration::from_millis(3));
                    leave(false);
                    (ok, false)
                }
                Act::Slow(ok, ms) => {
                    std::thread::sleep(Duration::from_millis(ms));
                    leave(false);
                    (ok, false)
                }
                Act::UntilStop => {
                    while !stop.requested() {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    leave(true);
                    (Some(false), true)
                }
                Act::Panic => {
                    leave(false);
                    panic!("scripted panic")
                }
            }
        }
        fn outcome(out: &Self::Out) -> (Option<bool>, bool) {
            *out
        }
    }

    /// One scripted answer of a source.
    type Answer = Result<Option<Vec<VesselConf>>, String>;

    /// A source following a script of answers, one per poll; then
    /// unchanged.
    struct Scripted {
        steps: VecDeque<Answer>,
        finite: bool,
    }

    impl VesselSource for Scripted {
        fn poll(&mut self, wait: Duration) -> Result<Option<Vec<VesselConf>>, SourceError> {
            match self.steps.pop_front() {
                Some(r) => r.map_err(SourceError),
                None => {
                    std::thread::sleep(wait);
                    Ok(None)
                }
            }
        }
        fn is_finite(&self) -> bool {
            self.finite
        }
    }

    /// A source driven from the test thread.
    #[derive(Clone, Default)]
    struct Live(Arc<Mutex<VecDeque<Answer>>>);

    impl VesselSource for Live {
        fn poll(&mut self, wait: Duration) -> Result<Option<Vec<VesselConf>>, SourceError> {
            let next = self.0.lock().unwrap().pop_front();
            match next {
                Some(r) => r.map_err(SourceError),
                None => {
                    std::thread::sleep(wait);
                    Ok(None)
                }
            }
        }
        fn is_finite(&self) -> bool {
            false
        }
    }

    impl Live {
        fn push(&self, r: Answer) {
            self.0.lock().unwrap().push_back(r);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum E {
        Started(String),
        Exited(String, bool, bool),
        Panicked(String, bool),
        Stopping(String),
        Refused(String),
        SourceFailed,
    }

    fn simple(e: Event<(Option<bool>, bool)>) -> E {
        match e {
            Event::Started(v) => E::Started(v.subject),
            Event::Exited {
                vc,
                stopped,
                restart_in,
                ..
            } => E::Exited(vc.subject, stopped, restart_in.is_some()),
            Event::Panicked { vc, restart_in } => E::Panicked(vc.subject, restart_in.is_some()),
            Event::Stopping(v) => E::Stopping(v.subject),
            Event::Refused(r) => E::Refused(r.subject),
            Event::SourceFailed(_) => E::SourceFailed,
        }
    }

    fn supervisor(f: &Arc<Fake>) -> Supervisor<Fake> {
        Supervisor::new(f.clone(), Guard::new(runtime()), timing())
    }

    /// Run the supervisor on its own thread with a Live source; returns the
    /// source, the shutdown and the events so far.
    fn spawn_live(f: &Arc<Fake>) -> (Live, Stop, Arc<Mutex<Vec<E>>>, JoinHandle<()>) {
        let (live, shutdown, events) = (
            Live::default(),
            Stop::new(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let h = {
            let (mut src, sd, ev, f) = (live.clone(), shutdown.clone(), events.clone(), f.clone());
            std::thread::spawn(move || {
                supervisor(&f).run(&mut src, &sd, |e| ev.lock().unwrap().push(simple(e)))
            })
        };
        (live, shutdown, events, h)
    }

    fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    // ── finite source: today's taso-wardend ─────────────────────────

    #[test]
    fn a_finite_source_runs_each_vessel_once_and_returns() {
        let f = Fake::with(&[
            ("a", &[Act::Exit(Some(true))]),
            ("b", &[Act::Exit(Some(false))]),
        ]);
        let mut src = Scripted {
            steps: [Ok(Some(vec![
                vc("a", 0, Restart::Never),
                vc("b", 1, Restart::Never),
            ]))]
            .into(),
            finite: true,
        };
        let mut ev = Vec::new();
        supervisor(&f).run(&mut src, &Stop::new(), |e| ev.push(simple(e)));
        assert_eq!(f.runs_of("a").len(), 1);
        assert_eq!(f.runs_of("b").len(), 1);
        assert!(ev.contains(&E::Exited("a".into(), false, false)));
        assert!(
            ev.contains(&E::Exited("b".into(), false, false)),
            "never: a failure is not restarted"
        );
    }

    #[test]
    fn a_finite_source_that_never_answered_does_not_return_early() {
        // First poll: unchanged (no answer yet); then the set.  The loop must
        // not take "nothing runs" before the first answer as "done".
        let f = Fake::with(&[("a", &[Act::Exit(Some(true))])]);
        let mut src = Scripted {
            steps: [Ok(None), Ok(Some(vec![vc("a", 0, Restart::Never)]))].into(),
            finite: true,
        };
        supervisor(&f).run(&mut src, &Stop::new(), |_| {});
        assert_eq!(f.runs_of("a").len(), 1);
    }

    // ── restart policies and backoff ────────────────────────────────

    #[test]
    fn on_failure_restarts_until_ok_with_growing_backoff() {
        let fail = Act::Exit(Some(false));
        let f = Fake::with(&[("a", &[fail, Act::Exit(None), fail, Act::Exit(Some(true))])]);
        let mut src = Scripted {
            steps: [Ok(Some(vec![vc("a", 0, Restart::OnFailure)]))].into(),
            finite: true,
        };
        let mut ev = Vec::new();
        supervisor(&f).run(&mut src, &Stop::new(), |e| ev.push(simple(e)));
        let runs = f.runs_of("a");
        assert_eq!(runs.len(), 4, "failed, never ran, failed, ok");
        // Gaps between runs grow: 5, 10, 20 ms (backoff_first doubling).
        let gaps: Vec<Duration> = runs
            .windows(2)
            .map(|w| w[1].1.duration_since(w[0].2))
            .collect();
        for (gap, at_least) in gaps.iter().zip([5u64, 10, 20]) {
            assert!(*gap >= Duration::from_millis(at_least), "{gaps:?}");
        }
        assert_eq!(
            ev.last(),
            Some(&E::Exited("a".into(), false, false)),
            "ok: no restart"
        );
    }

    /// The restart delays the supervisor announces: doubling while runs are
    /// short; back to the first delay after every run that counts as healthy.
    #[test]
    fn a_healthy_run_resets_the_backoff() {
        let fail = Act::Exit(Some(false));
        for (healthy, want) in [
            (Duration::from_secs(60), [5u64, 10, 20]),
            (Duration::ZERO, [5, 5, 5]),
        ] {
            let f = Fake::with(&[("a", &[fail, fail, fail, Act::Exit(Some(true))])]);
            let mut src = Scripted {
                steps: [Ok(Some(vec![vc("a", 0, Restart::OnFailure)]))].into(),
                finite: true,
            };
            let mut delays = Vec::new();
            let mut sup = Supervisor::new(
                f.clone(),
                Guard::new(runtime()),
                Timing {
                    healthy,
                    ..timing()
                },
            );
            sup.run(&mut src, &Stop::new(), |e| {
                if let Event::Exited {
                    restart_in: Some(d),
                    ..
                } = e
                {
                    delays.push(d.as_millis() as u64);
                }
            });
            assert_eq!(delays, want, "healthy after {healthy:?}");
        }
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        let t = timing();
        let d: Vec<u64> = (1..=6).map(|n| t.backoff(n).as_millis() as u64).collect();
        assert_eq!(d, vec![5, 10, 20, 40, 40, 40]);
        assert_eq!(t.backoff(200), t.backoff_max, "no overflow");
    }

    #[test]
    fn always_restarts_until_removed_then_never_again() {
        let ok = Act::Exit(Some(true));
        let f = Fake::with(&[("a", &[ok, ok, Act::UntilStop])]);
        let (live, shutdown, events, h) = spawn_live(&f);
        live.push(Ok(Some(vec![vc("a", 0, Restart::Always)])));
        wait_for("a third run", || {
            f.live.lock().unwrap().get("a") == Some(&1) && f.runs_of("a").len() == 2
        });
        live.push(Ok(Some(vec![])));
        wait_for("the stop", || f.runs_of("a").len() == 3);
        std::thread::sleep(Duration::from_millis(60)); // longer than any backoff
        assert_eq!(
            f.runs_of("a").len(),
            3,
            "a Vessel stopped on purpose is not restarted"
        );
        assert!(f.runs_of("a")[2].3, "the third run ended on its stop");
        shutdown.request();
        h.join().unwrap();
        let ev = events.lock().unwrap();
        assert!(ev.contains(&E::Stopping("a".into())));
        assert!(ev.contains(&E::Exited("a".into(), true, false)));
    }

    // ── removal, overlap, source failure ────────────────────────────

    /// Removed and listed again at once: the new run starts only after the
    /// old one has ended.  Never two runs of one Vessel.
    #[test]
    fn a_vessel_never_runs_twice_at_once() {
        let f = Fake::with(&[("a", &[Act::UntilStop, Act::UntilStop])]);
        let (live, shutdown, _events, h) = spawn_live(&f);
        live.push(Ok(Some(vec![vc("a", 0, Restart::Never)])));
        wait_for("a to run", || f.live.lock().unwrap().get("a") == Some(&1));
        live.push(Ok(Some(vec![])));
        live.push(Ok(Some(vec![vc("a", 0, Restart::Never)])));
        wait_for("a second run", || {
            f.runs_of("a").len() == 1 && f.live.lock().unwrap().get("a") == Some(&1)
        });
        shutdown.request();
        h.join().unwrap();
        assert!(
            !*f.overlap.lock().unwrap(),
            "two runs of one Vessel overlapped"
        );
        assert_eq!(f.runs_of("a").len(), 2);
    }

    /// While the source fails, nothing is stopped and nothing new starts;
    /// once it answers, the answer is acted on.
    #[test]
    fn a_failing_source_changes_nothing() {
        let f = Fake::with(&[("a", &[Act::UntilStop]), ("b", &[Act::UntilStop])]);
        let (live, shutdown, events, h) = spawn_live(&f);
        live.push(Ok(Some(vec![vc("a", 0, Restart::Never)])));
        wait_for("a to run", || f.live.lock().unwrap().get("a") == Some(&1));
        for _ in 0..20 {
            live.push(Err("api server unreachable".into()));
        }
        wait_for("the failures to be read", || {
            live.0.lock().unwrap().is_empty()
        });
        assert_eq!(f.live.lock().unwrap().get("a"), Some(&1), "a still runs");
        assert!(f.runs_of("a").is_empty(), "a was not stopped");
        live.push(Ok(Some(vec![vc("b", 1, Restart::Never)])));
        wait_for("b to run and a to stop", || {
            f.live.lock().unwrap().get("b") == Some(&1) && f.runs_of("a").len() == 1
        });
        shutdown.request();
        h.join().unwrap();
        assert!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|e| **e == E::SourceFailed)
                .count()
                >= 20
        );
    }

    /// A run that ends while the source fails is not restarted until the
    /// source answers again, and then on its own policy.
    #[test]
    fn no_restart_while_the_source_fails() {
        let f = Fake::with(&[("a", &[Act::Exit(Some(false)), Act::UntilStop])]);
        let mut src = Scripted {
            steps: [Ok(Some(vec![vc("a", 0, Restart::OnFailure)]))]
                .into_iter()
                .chain((0..30).map(|_| Err("down".to_string())))
                .collect(),
            finite: false,
        };
        let shutdown = Stop::new();
        let mut sup = supervisor(&f);
        let h = {
            let (f, sd) = (f.clone(), shutdown.clone());
            std::thread::spawn(move || {
                wait_for("the second run", || {
                    f.live.lock().unwrap().get("a") == Some(&1) && f.runs_of("a").len() == 1
                });
                sd.request();
            })
        };
        let started_at = Instant::now();
        sup.run(&mut src, &shutdown, |_| {});
        h.join().unwrap();
        let runs = f.runs_of("a");
        assert_eq!(runs.len(), 2);
        // 30 failing polls at a 2 ms tick each passed before the restart.
        assert!(
            runs[1].1.duration_since(started_at) >= Duration::from_millis(30 * 2),
            "restarted while the source failed"
        );
    }

    /// A run that ends by itself after its stop was requested still counts
    /// as stopped: it is reported so, and its policy does not restart it.
    #[test]
    fn a_requested_stop_counts_even_if_the_agent_exited_by_itself() {
        // The run ignores the stop and exits ok on its own, reporting "not stopped".
        let f = Fake::with(&[("a", &[Act::Slow(Some(true), 150)])]);
        let (live, shutdown, events, h) = spawn_live(&f);
        live.push(Ok(Some(vec![vc("a", 0, Restart::Always)])));
        wait_for("a to run", || f.live.lock().unwrap().get("a") == Some(&1));
        live.push(Ok(Some(vec![])));
        wait_for("the run to end", || f.runs_of("a").len() == 1);
        std::thread::sleep(Duration::from_millis(60));
        shutdown.request();
        h.join().unwrap();
        assert!(!f.runs_of("a")[0].3, "the run itself did not see the stop");
        let ev = events.lock().unwrap();
        assert!(
            ev.contains(&E::Exited("a".into(), true, false)),
            "stopped, no restart: {ev:?}"
        );
        assert_eq!(f.runs_of("a").len(), 1);
    }

    // ── the guard in the loop ───────────────────────────────────────

    #[test]
    fn refused_entries_are_reported_and_never_run() {
        let f = Fake::with(&[
            ("a", &[Act::Exit(Some(true))]),
            ("b", &[Act::Exit(Some(true))]),
        ]);
        // b takes a's slot: refused.
        let mut src = Scripted {
            steps: [Ok(Some(vec![
                vc("a", 3, Restart::Never),
                vc("b", 3, Restart::Never),
            ]))]
            .into(),
            finite: true,
        };
        let mut ev = Vec::new();
        supervisor(&f).run(&mut src, &Stop::new(), |e| ev.push(simple(e)));
        let refused: Vec<&E> = ev.iter().filter(|e| matches!(e, E::Refused(_))).collect();
        assert_eq!(refused.len(), 1, "{ev:?}");
        let ran = f.runs_of("a").len() + f.runs_of("b").len();
        assert_eq!(ran, 1, "exactly one of the two ran");
    }

    /// A changed entry (here the restart policy) is used at the next start;
    /// the running agent is not bounced for it.
    #[test]
    fn a_changed_entry_takes_effect_at_the_next_start() {
        let f = Fake::with(&[("a", &[Act::UntilStop, Act::UntilStop])]);
        let (live, shutdown, _events, h) = spawn_live(&f);
        live.push(Ok(Some(vec![vc("a", 0, Restart::Never)])));
        wait_for("a to run", || f.live.lock().unwrap().get("a") == Some(&1));
        live.push(Ok(Some(vec![vc("a", 0, Restart::Always)])));
        std::thread::sleep(Duration::from_millis(30));
        assert!(f.runs_of("a").is_empty(), "not bounced by the change");
        shutdown.request();
        h.join().unwrap();
        let runs = f.runs_of("a");
        assert_eq!(runs.len(), 1);
        assert_eq!(
            runs[0].0,
            Restart::Never,
            "the running agent kept the entry it started with"
        );
    }

    /// The entry a Vessel starts with is its latest good one: a policy
    /// changed during a run decides what happens after that run.
    #[test]
    fn the_next_start_follows_the_changed_entry() {
        let f = Fake::with(&[("a", &[Act::Slow(Some(true), 200), Act::UntilStop])]);
        let (live, shutdown, events, h) = spawn_live(&f);
        live.push(Ok(Some(vec![vc("a", 0, Restart::Never)])));
        wait_for("a to run", || f.live.lock().unwrap().get("a") == Some(&1));
        // During the run: never -> always.  Under "never" an ok exit would end it.
        live.push(Ok(Some(vec![vc("a", 0, Restart::Always)])));
        wait_for("a second run", || {
            f.runs_of("a").len() == 1 && f.live.lock().unwrap().get("a") == Some(&1)
        });
        shutdown.request();
        h.join().unwrap();
        let runs = f.runs_of("a");
        assert_eq!(
            (runs[0].0, runs[1].0),
            (Restart::Never, Restart::Always),
            "each run used the entry current at its start"
        );
        assert!(
            events
                .lock()
                .unwrap()
                .contains(&E::Exited("a".into(), false, true)),
            "the ok exit restarted under the new policy"
        );
    }

    // ── shutdown and panics ─────────────────────────────────────────

    #[test]
    fn shutdown_stops_every_vessel_and_waits_for_each() {
        let f = Fake::with(&[("a", &[Act::UntilStop]), ("b", &[Act::UntilStop])]);
        let (live, shutdown, _events, h) = spawn_live(&f);
        live.push(Ok(Some(vec![
            vc("a", 0, Restart::Always),
            vc("b", 1, Restart::Always),
        ])));
        wait_for("both to run", || {
            f.live.lock().unwrap().values().sum::<u32>() == 2
        });
        shutdown.request();
        h.join().unwrap();
        assert_eq!(
            f.live.lock().unwrap().values().sum::<u32>(),
            0,
            "nothing runs after return"
        );
        assert!(
            f.runs_of("a")[0].3 && f.runs_of("b")[0].3,
            "both ended on their stop, none restarted"
        );
        assert_eq!(f.runs.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_panicking_run_is_reported_and_counts_as_never_ran() {
        let f = Fake::with(&[
            ("a", &[Act::Panic, Act::Exit(Some(true))]),
            ("b", &[Act::Panic]),
        ]);
        let mut src = Scripted {
            steps: [Ok(Some(vec![
                vc("a", 0, Restart::OnFailure),
                vc("b", 1, Restart::Never),
            ]))]
            .into(),
            finite: true,
        };
        let mut ev = Vec::new();
        supervisor(&f).run(&mut src, &Stop::new(), |e| ev.push(simple(e)));
        assert!(
            ev.contains(&E::Panicked("a".into(), true)),
            "on-failure restarts after a panic: {ev:?}"
        );
        assert!(ev.contains(&E::Panicked("b".into(), false)));
        assert_eq!(f.runs_of("a").len(), 2);
        assert_eq!(f.runs_of("b").len(), 1);
    }
}
