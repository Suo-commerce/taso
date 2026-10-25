//! `taso-ctl`: the operator's view (P4 spec rev. 27 §5.8, D83; file 12).
//!
//! ```text
//! taso-ctl <warden-config> explain <vessel or template id (32 hex) | candidate id (64 hex)>
//! ```
//!
//! `explain` rebuilds every decision about a Vessel, a Template or a
//! Candidate from the coordinator log's accepted records alone, and checks
//! them against the store ([`taso_warden::explain`]): every record intact
//! and carried by the pack the log names, every derived id what its
//! fields derive, every content object present and hashing to its key.
//! It uses the config's coordinator and store (a `"local"` coordinator
//! only while its daemon is not running: redb locks the file).
//!
//! # Output
//!
//! One JSON object: `{"explain": {…}, "checks": {"passed": n, "failed":
//! ["…", …]}}`.
//!
//! # Exit status
//!
//! 0 explained, every check held; 4 explained, a check failed (something
//! changed after it was accepted); 1 it could not be explained (no such
//! id, the coordinator or the store unreachable); 2 a bad command line or
//! configuration.

use std::process::ExitCode;
use std::sync::Arc;

use serde_json::json;
use taso_warden::coordinator::{Coord, Coordinator, LogConfig};
use taso_warden::coordsrv::RemoteCoord;
use taso_warden::coordstore::CoordStore;
use taso_warden::daemon::{Config, CoordConf};
use taso_warden::explain::{explain, Subject};

const USAGE: &str = "usage: taso-ctl <warden-config> explain <vessel or template id (32 hex) | candidate id (64 hex)>";

fn usage(why: &str) -> ExitCode {
    eprintln!("taso-ctl: {why}\n{USAGE}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [cfg, cmd, id] = args.as_slice() else {
        return usage("three arguments are needed");
    };
    if cmd != "explain" {
        return usage(&format!("unknown command {cmd:?}"));
    }
    let Some(subject) = Subject::parse(id) else {
        return usage("an id is 32 or 64 hex digits");
    };
    let config = match std::fs::read_to_string(cfg)
        .map_err(|e| e.to_string())
        .and_then(|t| Config::parse(&t).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => return usage(&format!("{cfg}: {e}")),
    };
    let store = match config.store.open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("taso-ctl: opening the store: {e}");
            return ExitCode::from(1);
        }
    };
    let coord: Arc<dyn Coord> = match &config.coordinator {
        CoordConf::Remote { socket } => Arc::new(RemoteCoord::new(socket)),
        CoordConf::Local { path, .. } => match Coordinator::open_with(
            path,
            LogConfig {
                store: Arc::new(CoordStore::new(store.clone(), &config.prefix)),
                ..LogConfig::default()
            },
        ) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                eprintln!("taso-ctl: coordinator {}: {e}", path.display());
                return ExitCode::from(1);
            }
        },
    };
    match explain(coord.as_ref(), &store, &config.prefix, subject) {
        Ok(e) => {
            let failed: Vec<&str> = e.failed().iter().map(|c| c.what.as_str()).collect();
            let passed = e.checks.len() - failed.len();
            println!(
                "{}",
                json!({"explain": e.explain, "checks": {"passed": passed, "failed": failed}})
            );
            if failed.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(4)
            }
        }
        Err(why) => {
            println!("{}", json!({"error": why}));
            ExitCode::from(1)
        }
    }
}
