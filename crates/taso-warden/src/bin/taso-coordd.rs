//! `taso-coordd <coord.redb> <socket>`: the coordinator on its own,
//! served on a Unix socket ([`taso_warden::coordsrv`]), until killed.
//!
//! The daemon can serve its in-process coordinator too, but then killing
//! that Warden kills the coordinator with it.  For rebirth (and its gate)
//! the coordinator must outlive any one Warden: run it here.

use std::process::ExitCode;
use std::sync::Arc;

use taso_warden::coordinator::{Coord, Coordinator};
use taso_warden::coordsrv::Server;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, db, sock] = &args[..] else {
        eprintln!("usage: taso-coordd <coord.redb> <socket>");
        return ExitCode::from(2);
    };
    let coord: Arc<dyn Coord> = match Coordinator::open(db) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("taso-coordd: {db}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let _server = match Server::spawn(sock, coord) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("taso-coordd: serving on {sock}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("taso-coordd: serving {db} on {sock}");
    loop {
        std::thread::park();
    }
}
