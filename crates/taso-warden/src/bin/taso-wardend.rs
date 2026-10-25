//! `taso-wardend <config.json> [--takeover <subject>=<warden>@<epoch>]...`:
//! run a node's Vessels ([`taso_warden::daemon`]).
//!
//! `--takeover` is the one-shot form of a static entry's `"takeover"`
//! (`{"holder": <warden>, "epoch": <n>}`): for this run only, the Vessel
//! with that subject is taken over from exactly that ownership, as the
//! operator read it (`taso-logcheck`, or the daemon's refusal line).
//! Nothing is left in the config to fence anyone on a later restart
//! (fencing review F2).  A subject not in `"vessels"` is an error; with a
//! kubernetes source the flag is refused (the cluster names takeovers).
//!
//! The Vessels come from the config's `"source"` and run under the
//! [`taso_warden::supervisor`], each through the guard, each restarted (or
//! not) by its `"restart"` policy:
//!
//! - **static** (the default): the config's `"vessels"`.  The daemon exits
//!   once every Vessel is done and none waits to restart.
//! - **kubernetes**: the Vessel resources of this node
//!   ([`taso_warden::source_kube`]), their status written back
//!   ([`taso_warden::status_kube`]).  The daemon runs until it is told to
//!   stop.
//!
//! # Failpoints
//!
//! `TASO_FAILPOINT=<name>` stops every Template birth at that point, one
//! of [`taso_warden::daemon::BIRTH_FAILPOINTS`] (P4 spec §10.2, file 5;
//! tests on a node): the Vessel's start is refused with
//! `stopped at failpoint <name>` and a run without it finishes the birth.
//! Any other name refuses to start.
//!
//! # Purge at TTL
//!
//! With `"purge": {"ttl_seconds": …}`, a thread checks every
//! `recheck_seconds` (default 3600) and purges each Vessel held here that
//! is not sanctioned, not running and past its TTL
//! ([`taso_warden::daemon::Node::ttl_pass`], P4 §6.7).
//!
//! # The decider socket
//!
//! `decider.socket` (default `<run_dir>/decide/decide.sock`) takes
//! verdicts on this node's Vessels while the daemon runs
//! ([`taso_warden::decidesrv`]; the `taso-decide` command).
//!
//! # Stopping
//!
//! SIGTERM or SIGINT asks for a stop: every running agent is stopped (its
//! container killed, as a stop always does: the next start rolls back to
//! its last Seal), the daemon waits for each run to end, writes the last
//! statuses, and exits.  This is no safer than a crash — the Warden is
//! built to be killed — but it leaves no agent behind and says what it did.
//! A second signal exits at once, which is a crash.
//!
//! The signals are blocked in every thread from the start of `main` and
//! taken by one thread with `sigwait`; programs the daemon runs (runc, zfs)
//! start with the default signal mask (std resets it in the child).
//!
//! Exit status: 0 if every Vessel's last run had its agent exit
//! successfully with nothing failing to publish or prune (static), or after
//! a requested stop (kubernetes); 1 if any did not (or an entry was
//! refused), or the daemon could not start; 2 for a bad command line or
//! configuration.  `TASO_TIMING=1` prints the timing spans at exit;
//! `TASO_TIMING_RAW=<file>` also writes every sample, `<span>
//! <microseconds>` per line (for quantiles across runs).

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use taso_warden::coordinator::{Coord, Coordinator};
use taso_warden::coordsrv::{RemoteCoord, Server};
use taso_warden::daemon::{
    Config, CoordConf, DaemonError, KubeSourceConf, Node, Report, SourceConf, Stop,
};
use taso_warden::kube::{Kube, KubeConfig};
use taso_warden::source::{Guard, StaticSource, WithRequested};
use taso_warden::source_kube::{KubeSource, DEFAULT_TICK};
use taso_warden::status_kube::StatusWriter;
use taso_warden::supervisor::{Event, Supervisor, Timing};

/// How long one request to the API server may take.
const KUBE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the status writer writes.
const STATUS_TICK: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    // Before any other thread exists, so that every thread inherits it.
    let shutdown = Stop::new();
    let signals = match signals::block() {
        Ok(set) => set,
        Err(e) => {
            eprintln!("taso-wardend: blocking signals: {e}");
            return ExitCode::FAILURE;
        }
    };
    {
        let shutdown = shutdown.clone();
        signals::spawn_waiter(signals, move |n| {
            if n == 1 {
                eprintln!("taso-wardend: stopping: every agent is stopped, then the daemon exits (again to exit at once)");
                shutdown.request();
            } else {
                eprintln!("taso-wardend: a second signal: exiting now");
                std::process::exit(1);
            }
        });
    }

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (path, takeovers) = match cli::parse(&argv) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("taso-wardend: {e}\n{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };
    let mut config = match std::fs::read_to_string(&path)
        .map_err(|e| e.to_string())
        .and_then(|t| Config::parse(&t).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("taso-wardend: {path}: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = cli::apply_takeovers(&mut config, &takeovers) {
        eprintln!("taso-wardend: {e}");
        return ExitCode::from(2);
    }
    // The cluster's API, before anything else is touched.
    let kube = match &config.source {
        SourceConf::Static => None,
        SourceConf::Kubernetes(k) => match kube_clients(k) {
            Ok(c) => Some((k.clone(), c)),
            Err(e) => {
                eprintln!("taso-wardend: kubernetes: {e}");
                return ExitCode::from(2);
            }
        },
    };
    let raw = std::env::var_os("TASO_TIMING_RAW");
    let timing = std::env::var("TASO_TIMING").is_ok_and(|v| v == "1") || raw.is_some();
    taso_warden::timing::enable(timing);

    let mut _server = None;
    let coord: Arc<dyn Coord> = match &config.coordinator {
        CoordConf::Local { path, serve } => {
            let c: Arc<dyn Coord> = match Coordinator::open(path) {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    eprintln!("taso-wardend: coordinator {}: {e}", path.display());
                    return ExitCode::FAILURE;
                }
            };
            if let Some(sock) = serve {
                match Server::spawn(sock, c.clone()) {
                    Ok(s) => _server = Some(s),
                    Err(e) => {
                        eprintln!(
                            "taso-wardend: serving the coordinator on {}: {e}",
                            sock.display()
                        );
                        return ExitCode::FAILURE;
                    }
                }
            }
            c
        }
        CoordConf::Remote { socket } => Arc::new(RemoteCoord::new(socket)),
    };
    let storage = config.storage.open(config.batched_snapshots);
    eprintln!(
        "taso-wardend[{}]: storage {}",
        config.warden.get(),
        storage.kind()
    );
    let failpoint = std::env::var("TASO_FAILPOINT").ok();
    let node = match Node::new(config, coord, storage)
        .map_err(|e| e.to_string())
        .and_then(|n| n.with_failpoint(failpoint.as_deref()))
    {
        Ok(n) => Arc::new(n),
        Err(e) => {
            eprintln!("taso-wardend: starting: {e}");
            return ExitCode::FAILURE;
        }
    };
    let warden = node.config.warden;
    // The decider socket (P4 §5.1, D72): verdicts on this node's Vessels.
    let decider = match taso_warden::decidesrv::DeciderServer::spawn(
        &node.config.decider,
        Arc::new(taso_warden::daemon::NodeDecider(node.clone())),
    ) {
        Ok(d) => {
            eprintln!(
                "taso-wardend[{}]: decider socket {}",
                warden.get(),
                d.path().display()
            );
            d
        }
        Err(e) => {
            eprintln!(
                "taso-wardend: the decider socket {}: {e}",
                node.config.decider.socket.display()
            );
            return ExitCode::FAILURE;
        }
    };
    // Purge at TTL (P4 §6.7, D81): a pass at start, then every
    // `purge.recheck_seconds`.
    let ttl_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ttl = node.config.purge.map(|conf| {
        let (node, stop) = (node.clone(), ttl_stop.clone());
        eprintln!(
            "taso-wardend[{}]: purge at TTL {}s, checked every {}s",
            warden.get(),
            conf.ttl.as_secs(),
            conf.recheck.as_secs()
        );
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                node.ttl_pass();
                let t = std::time::Instant::now();
                while t.elapsed() < conf.recheck && !stop.load(std::sync::atomic::Ordering::SeqCst)
                {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        })
    });

    // Seeded with what the pool holds: a uid slot whose range owns a
    // Vessel's files stays that Vessel's across restarts of the Warden.
    let guard = Guard::seeded(node.config.runtime.clone(), node.held().to_vec());
    let mut supervisor = Supervisor::new(node.clone(), guard, Timing::default());
    // Per Vessel, whether its last run went well (a refused entry counts as
    // not).  The exit status is about how each Vessel ended, not about
    // failures a restart has since made good.
    let mut last: BTreeMap<String, bool> = BTreeMap::new();
    let mut ok = match kube {
        None => {
            // A static source is finite: the loop ends once every Vessel is
            // done and none waits to restart.
            let mut inner = StaticSource::new(node.config.vessels.clone());
            let mut source = WithRequested::new(&mut inner, node.requested().clone());
            supervisor.run(&mut source, &shutdown, |event| {
                report(&node, &event, &mut last)
            });
            last.values().all(|well| *well)
        }
        Some((k, (list, status))) => {
            eprintln!(
                "taso-wardend[{}]: Vessels of node {} from Kubernetes ({} namespaces)",
                warden.get(),
                k.node,
                k.tenants.len()
            );
            let mut inner =
                KubeSource::new(list, k.clone(), node.config.runtime.clone(), DEFAULT_TICK);
            let writer =
                StatusWriter::spawn(status, inner.view(), k.node.clone(), warden, STATUS_TICK);
            let mut source = WithRequested::new(&mut inner, node.requested().clone());
            // Infinite: the loop returns only once a stop was asked for and
            // every run has ended.
            supervisor.run(&mut source, &shutdown, |event| {
                writer.event(&event);
                report(&node, &event, &mut last);
            });
            writer.finish();
            true
        }
    };

    decider.stop();
    if let Some(t) = ttl {
        ttl_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = t.join();
    }

    if timing {
        let spans = taso_warden::timing::take();
        print!("{}", taso_warden::timing::report(&spans));
        if let Some(path) = raw {
            let mut text = String::new();
            for (name, samples) in &spans {
                for us in samples {
                    text.push_str(&format!("{name} {us}\n"));
                }
            }
            if let Err(e) = std::fs::write(&path, text) {
                eprintln!(
                    "taso-wardend: writing {}: {e}",
                    std::path::Path::new(&path).display()
                );
                ok = false;
            }
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Two clients for the cluster's API (one lists, one writes status; each
/// is used by one thread), from the config's `api` or the pod's service
/// account.
fn kube_clients(k: &KubeSourceConf) -> Result<(Kube, Kube), String> {
    let cfg = match &k.api {
        Some(a) => KubeConfig {
            api: a.url.clone(),
            token_file: a.token_file.clone(),
            ca_file: a.ca_file.clone(),
        },
        None => KubeConfig::in_cluster()
            .map_err(|e| format!("in-cluster configuration: {e} (or set kubernetes.api)"))?,
    };
    let client = || Kube::new(&cfg, KUBE_TIMEOUT).map_err(|e| format!("{}: {e}", cfg.api));
    Ok((client()?, client()?))
}

/// Log an event; record how each Vessel's last run went.  The line for an
/// ended run is the one the gate scripts match: keep its form.
fn report(
    node: &Node,
    event: &Event<Result<Report, DaemonError>>,
    last: &mut BTreeMap<String, bool>,
) {
    let w = node.config.warden.get();
    match event {
        Event::Started(vc) => eprintln!("taso-wardend[{w}] {}: starting", vc.subject),
        Event::Stopping(vc) => eprintln!("taso-wardend[{w}] {}: stopping", vc.subject),
        Event::Exited {
            vc,
            out,
            restart_in,
            ..
        } => {
            let well = match out {
                Ok(r) => {
                    let agent_ok = r.agent.as_ref().is_some_and(|(ok, _)| *ok);
                    println!(
                        "{}: {:?}, {} connections, {} Seals published, {} publish failures, {} segments pruned, {} prune failures{}, agent {}",
                        r.subject,
                        r.start,
                        r.connections,
                        r.published,
                        r.publish_failures,
                        r.pruned,
                        r.prune_failures.0,
                        r.prune_failures.1.as_deref().map(|e| format!(" (last: {e})")).unwrap_or_default(),
                        if agent_ok { "ok" } else { "failed" }
                    );
                    agent_ok && r.publish_failures == 0 && r.prune_failures.0 == 0
                }
                Err(e) => {
                    println!("{}: {e}", vc.subject);
                    false
                }
            };
            if let Some(d) = restart_in {
                eprintln!("taso-wardend[{w}] {}: restarting in {d:?}", vc.subject);
            }
            last.insert(vc.subject.clone(), well);
        }
        Event::Panicked { vc, restart_in } => {
            println!(
                "{}: the run panicked{}",
                vc.subject,
                if restart_in.is_some() {
                    ", restarting"
                } else {
                    ""
                }
            );
            last.insert(vc.subject.clone(), false);
        }
        Event::Refused(r) => {
            println!("{}: refused: {}", r.subject, r.reason);
            last.entry(r.subject.clone()).or_insert(false);
        }
        Event::SourceFailed(e) => eprintln!("taso-wardend: {e}"),
    }
}

/// SIGTERM and SIGINT, taken by one thread (see "Stopping").
/// The command line: the config path and the one-shot takeovers.
mod cli {
    use taso_core::envelope::Epoch;
    use taso_core::model::WardenId;
    use taso_warden::daemon::{Config, SourceConf, TakeOver};

    pub const USAGE: &str =
        "usage: taso-wardend <config.json> [--takeover <subject>=<warden>@<epoch>]...";

    /// `(path, [(subject, takeover)])`.
    pub fn parse(args: &[String]) -> Result<(String, Vec<(String, TakeOver)>), String> {
        let mut path = None;
        let mut takeovers = Vec::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--takeover" => {
                    let v = it
                        .next()
                        .ok_or("--takeover needs <subject>=<warden>@<epoch>")?;
                    let (subject, rest) = v.split_once('=').ok_or_else(|| {
                        format!("--takeover {v}: expected <subject>=<warden>@<epoch>")
                    })?;
                    let (warden, epoch) = rest.split_once('@').ok_or_else(|| {
                        format!("--takeover {v}: expected <subject>=<warden>@<epoch>")
                    })?;
                    let num = |what: &str, s: &str| -> Result<u64, String> {
                        s.parse::<u64>().ok().filter(|n| *n > 0).ok_or_else(|| {
                            format!("--takeover {v}: {what} is not a positive number")
                        })
                    };
                    if subject.is_empty() {
                        return Err(format!("--takeover {v}: empty subject"));
                    }
                    if takeovers.iter().any(|(s, _)| s == subject) {
                        return Err(format!("--takeover {v}: subject given twice"));
                    }
                    takeovers.push((
                        subject.to_string(),
                        TakeOver {
                            holder: WardenId::new(num("warden", warden)?),
                            epoch: Epoch::new(num("epoch", epoch)?),
                        },
                    ));
                }
                s if s.starts_with("--") => return Err(format!("unknown option {s}")),
                _ if path.is_none() => path = Some(a.clone()),
                _ => return Err(format!("unexpected argument {a}")),
            }
        }
        Ok((path.ok_or("missing <config.json>")?, takeovers))
    }

    /// Put each one-shot takeover on its entry.
    pub fn apply_takeovers(
        config: &mut Config,
        takeovers: &[(String, TakeOver)],
    ) -> Result<(), String> {
        if takeovers.is_empty() {
            return Ok(());
        }
        if !matches!(config.source, SourceConf::Static) {
            return Err("--takeover needs a static \"vessels\" list; with a kubernetes source the Vessel resource names the takeover".into());
        }
        for (subject, t) in takeovers {
            let vc = config
                .vessels
                .iter_mut()
                .find(|v| &v.subject == subject)
                .ok_or_else(|| format!("--takeover {subject}: no such subject in \"vessels\""))?;
            vc.takeover = Some(*t);
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn p(args: &[&str]) -> Result<(String, Vec<(String, TakeOver)>), String> {
            parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        }

        #[test]
        fn path_and_takeovers() {
            assert_eq!(p(&["c.json"]).unwrap(), ("c.json".to_string(), vec![]));
            let (path, t) =
                p(&["--takeover", "sim-1=2@7", "c.json", "--takeover", "x=1@1"]).unwrap();
            assert_eq!(path, "c.json");
            assert_eq!(
                t[0],
                (
                    "sim-1".to_string(),
                    TakeOver {
                        holder: WardenId::new(2),
                        epoch: Epoch::new(7)
                    }
                )
            );
            assert_eq!(t[1].0, "x");
        }

        #[test]
        fn mistakes_are_named() {
            for (args, want) in [
                (&[][..], "missing <config.json>"),
                (&["a", "b"], "unexpected argument b"),
                (
                    &["c", "--takeover"],
                    "--takeover needs <subject>=<warden>@<epoch>",
                ),
                (
                    &["c", "--takeover", "s"],
                    "--takeover s: expected <subject>=<warden>@<epoch>",
                ),
                (
                    &["c", "--takeover", "s=2"],
                    "--takeover s=2: expected <subject>=<warden>@<epoch>",
                ),
                (
                    &["c", "--takeover", "=2@3"],
                    "--takeover =2@3: empty subject",
                ),
                (
                    &["c", "--takeover", "s=x@3"],
                    "--takeover s=x@3: warden is not a positive number",
                ),
                (
                    &["c", "--takeover", "s=2@0"],
                    "--takeover s=2@0: epoch is not a positive number",
                ),
                (
                    &["c", "--takeover", "s=2@3", "--takeover", "s=2@4"],
                    "--takeover s=2@4: subject given twice",
                ),
                (&["c", "--tls"], "unknown option --tls"),
            ] {
                assert_eq!(p(args).unwrap_err(), want, "{args:?}");
            }
        }
    }
}

mod signals {
    use std::io;
    use std::thread::JoinHandle;

    /// The signals asking for a stop.
    pub const STOP: [libc::c_int; 2] = [libc::SIGTERM, libc::SIGINT];

    /// The set of [`STOP`], blocked in the calling thread (and so in every
    /// thread it starts from now on).
    pub fn block() -> io::Result<libc::sigset_t> {
        // SAFETY: sigset_t is plain data, initialised by sigemptyset before use.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut set) != 0 {
                return Err(io::Error::last_os_error());
            }
            for s in STOP {
                if libc::sigaddset(&mut set, s) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc));
            }
            Ok(set)
        }
    }

    /// A thread that waits for the signals in `set` (blocked: [`block`])
    /// and calls `on(n)` for the n-th one (1, 2, ...).
    pub fn spawn_waiter(
        set: libc::sigset_t,
        mut on: impl FnMut(u32) + Send + 'static,
    ) -> JoinHandle<()> {
        std::thread::spawn(move || {
            let mut n = 0;
            loop {
                let mut sig: libc::c_int = 0;
                // SAFETY: set is a valid, initialised signal set.
                let rc = unsafe { libc::sigwait(&set, &mut sig) };
                if rc != 0 {
                    continue; // EINTR and the like: wait again
                }
                n += 1;
                on(n);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::signals;
    use std::os::unix::process::ExitStatusExt;
    use std::os::unix::thread::JoinHandleExt;
    use std::sync::mpsc;
    use std::time::Duration;

    /// The stop signals are blocked in the daemon, but a program it runs
    /// (runc, zfs) must start with them unblocked: a SIGTERM sent to it
    /// ends it.
    #[test]
    fn children_start_with_the_signals_unblocked() {
        std::thread::spawn(|| {
            signals::block().unwrap();
            let status = std::process::Command::new("sh")
                .args(["-c", "kill -TERM $$; sleep 5"])
                .status()
                .unwrap();
            assert_eq!(
                status.signal(),
                Some(libc::SIGTERM),
                "the child ignored SIGTERM: {status:?}"
            );
        })
        .join()
        .unwrap();
    }

    /// The waiter takes each signal and counts them.
    #[test]
    fn the_waiter_counts_the_signals() {
        let (tx, rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let set = signals::block().unwrap();
            let w = signals::spawn_waiter(set, move |n| tx.send(n).unwrap());
            w.as_pthread_t()
        })
        .join()
        .unwrap();
        // Directed at the waiter thread only (a signal to the process would
        // reach the test harness's threads, which do not block it).
        for want in [1, 2] {
            // SAFETY: waiter is a live thread that blocks SIGTERM and waits for it.
            assert_eq!(unsafe { libc::pthread_kill(waiter, libc::SIGTERM) }, 0);
            assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(want));
        }
        assert_eq!(unsafe { libc::pthread_kill(waiter, libc::SIGINT) }, 0);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(3),
            "SIGINT counts too"
        );
    }
}
