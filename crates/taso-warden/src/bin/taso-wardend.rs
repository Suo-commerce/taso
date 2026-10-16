//! `taso-wardend <config.json>`: run a node's Vessels ([`taso_warden::daemon`]).
//!
//! Exit status: 0 if every Vessel ran and its agent exited successfully,
//! 1 if any did not, 2 for a bad command line or configuration.
//! `TASO_TIMING=1` prints the timing spans at exit.

use std::process::ExitCode;
use std::sync::Arc;

use taso_warden::coordinator::{Coord, Coordinator};
use taso_warden::coordsrv::{RemoteCoord, Server};
use taso_warden::daemon::{Config, CoordConf, Node};
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
    let timing = std::env::var("TASO_TIMING").is_ok_and(|v| v == "1");
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
    let node = Arc::new(Node { config, coord, zfs });

    let handles: Vec<_> = node
        .config
        .vessels
        .clone()
        .into_iter()
        .map(|vc| {
            let node = node.clone();
            std::thread::spawn(move || (vc.subject.clone(), node.run_vessel(&vc)))
        })
        .collect();
    let mut ok = true;
    for h in handles {
        match h.join() {
            Ok((_, Ok(r))) => {
                let agent_ok = r.agent.as_ref().is_some_and(|(ok, _)| *ok);
                ok &= agent_ok && r.publish_failures == 0;
                println!(
                    "{}: {:?}, {} connections, {} Seals published, {} publish failures, agent {}",
                    r.subject,
                    r.start,
                    r.connections,
                    r.published,
                    r.publish_failures,
                    if agent_ok { "ok" } else { "failed" }
                );
            }
            Ok((subject, Err(e))) => {
                ok = false;
                println!("{subject}: {e}");
            }
            Err(_) => {
                ok = false;
                println!("a Vessel thread panicked");
            }
        }
    }
    if timing {
        print!("{}", taso_warden::timing::report(&taso_warden::timing::take()));
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
