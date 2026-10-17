//! `taso-wardend <config.json>`: run a node's Vessels ([`taso_warden::daemon`]).
//!
//! The Vessels run under the [`taso_warden::supervisor`]: each through the
//! guard, each restarted (or not) by its `"restart"` policy; the daemon
//! exits once every Vessel is done and none waits to restart.  SIGTERM and
//! SIGKILL are a crash, by design (see [`taso_warden::daemon`], Stopping).
//!
//! Exit status: 0 if every Vessel's last run had its agent exit
//! successfully with nothing failing to publish or prune, 1 if any did not
//! (or an entry was refused), 2 for a bad command line or configuration.
//! `TASO_TIMING=1` prints the timing spans at exit; `TASO_TIMING_RAW=<file>`
//! also writes every sample, `<span> <microseconds>` per line (for
//! quantiles across runs).

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::Arc;

use taso_warden::coordinator::{Coord, Coordinator};
use taso_warden::coordsrv::{RemoteCoord, Server};
use taso_warden::daemon::{Config, CoordConf, Node, Stop};
use taso_warden::source::{Guard, StaticSource};
use taso_warden::supervisor::{Event, Supervisor, Timing};
use taso_warden::zfs::Zfs;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, path] = &args[..] else {
        eprintln!("usage: taso-wardend <config.json>");
        return ExitCode::from(2);
    };
    let config = match std::fs::read_to_string(path).map_err(|e| e.to_string()).and_then(|t| Config::parse(&t).map_err(|e| e.to_string())) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("taso-wardend: {path}: {e}");
            return ExitCode::from(2);
        }
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
                        eprintln!("taso-wardend: serving the coordinator on {}: {e}", sock.display());
                        return ExitCode::FAILURE;
                    }
                }
            }
            c
        }
        CoordConf::Remote { socket } => Arc::new(RemoteCoord::new(socket)),
    };
    let zfs = if config.batched_snapshots { Zfs::cli().batched() } else { Zfs::cli() };
    let node = match Node::new(config, coord, zfs) {
        Ok(n) => Arc::new(n),
        Err(e) => {
            eprintln!("taso-wardend: starting: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The config's Vessels, through the guard, under the supervisor.  A
    // static source is finite: the loop ends once every Vessel is done and
    // none waits to restart (each one's "restart" policy decides).
    let mut source = StaticSource::new(node.config.vessels.clone());
    let guard = Guard::new(node.config.runtime.clone());
    let mut supervisor = Supervisor::new(node.clone(), guard, Timing::default());
    // Per Vessel, whether its last run went well (a refused entry counts as
    // not).  The exit status is about how each Vessel ended, not about
    // failures a restart has since made good.
    let mut last: BTreeMap<String, bool> = BTreeMap::new();
    supervisor.run(&mut source, &Stop::new(), |event| match event {
        Event::Started(vc) => eprintln!("taso-wardend[{}] {}: starting", node.config.warden.get(), vc.subject),
        Event::Stopping(vc) => eprintln!("taso-wardend[{}] {}: stopping", node.config.warden.get(), vc.subject),
        Event::Exited { vc, out, restart_in, .. } => {
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
                eprintln!("taso-wardend[{}] {}: restarting in {d:?}", node.config.warden.get(), vc.subject);
            }
            last.insert(vc.subject, well);
        }
        Event::Panicked { vc, restart_in } => {
            println!("{}: the run panicked{}", vc.subject, if restart_in.is_some() { ", restarting" } else { "" });
            last.insert(vc.subject, false);
        }
        Event::Refused(r) => {
            println!("{}: refused: {}", r.subject, r.reason);
            last.entry(r.subject).or_insert(false);
        }
        Event::SourceFailed(e) => eprintln!("taso-wardend: {e}"),
    });
    let mut ok = last.values().all(|well| *well);
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
                eprintln!("taso-wardend: writing {}: {e}", std::path::Path::new(&path).display());
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
