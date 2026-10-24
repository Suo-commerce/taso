//! `taso-coordd <coord.redb> <socket> [--peer UID=WARDEN]... [--socket-group GID]
//! [--store-config FILE]`: the coordinator on its own, served on a Unix
//! socket ([`taso_warden::coordsrv`]), until killed.
//!
//! The daemon can serve its in-process coordinator too, but then killing
//! that Warden kills the coordinator with it.  For rebirth (and its gate)
//! the coordinator must outlive any one Warden: run it here.
//!
//! `--peer UID=WARDEN` (repeatable) is the peer map: a connection from
//! `UID` may act only as Warden `WARDEN`, and a uid not listed is refused
//! on everything.  Give one per Warden; the same uid or the same Warden
//! twice is an error at start.  With no `--peer` the socket is
//! unauthenticated, as before.  `--socket-group GID` makes the socket
//! 0660 owned by that group so the forwarding users (one ssh login per
//! node, see `coordsrv`) can connect; a numeric gid only — resolve a name
//! with `getent group` in the unit that starts this.
//!
//! `--store-config FILE` is where the Wardens keep packs and objects: a
//! JSON object with the Wardens' own `"store"` (a directory, or
//! `{"s3": {...}}` with `secret_key_file`) and `"prefix"` (default
//! `vessels`), read as the Warden reads its config.  The coordinator log
//! reads the store through it ([`taso_warden::coordstore`], P4 spec §0.4,
//! D35, D36).  Without it the log can read nothing, so every contract
//! accept is refused `NotReadable`; ownership and appends work as before.

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::Arc;

use taso_core::model::WardenId;
use taso_warden::coordinator::{Coord, Coordinator, LogConfig};
use taso_warden::coordsrv::{Server, ServerOptions};
use taso_warden::coordstore::CoordStore;
use taso_warden::daemon::StoreConf;

const USAGE: &str = "usage: taso-coordd <coord.redb> <socket> [--peer UID=WARDEN]... \
                     [--socket-group GID] [--store-config FILE]";

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
struct Args {
    db: String,
    sock: String,
    options: ServerOptionsSpec,
    store_config: Option<String>,
}

/// What `--store-config` names: the Wardens' store and prefix.
#[derive(Debug, PartialEq, Eq)]
struct StoreSpec {
    store: StoreConf,
    prefix: String,
}

/// Read a `--store-config` file's text.
fn store_spec(text: &str) -> Result<StoreSpec, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let obj = v.as_object().ok_or("must be a JSON object")?;
    if let Some(k) = obj.keys().find(|k| *k != "store" && *k != "prefix") {
        return Err(format!("unknown key {k:?}"));
    }
    let prefix = match obj.get("prefix") {
        None => "vessels".to_string(),
        Some(serde_json::Value::String(p)) => p.clone(),
        Some(_) => return Err("\"prefix\" must be a string".into()),
    };
    Ok(StoreSpec {
        store: StoreConf::parse_in(&v).map_err(|e| e.to_string())?,
        prefix,
    })
}

/// `ServerOptions` as parsed, comparable in tests.
#[derive(Debug, Default, PartialEq, Eq)]
struct ServerOptionsSpec {
    peers: Option<Vec<(u32, u64)>>,
    group: Option<u32>,
}

impl ServerOptionsSpec {
    fn build(self) -> ServerOptions {
        ServerOptions {
            peers: self.peers.map(|p| {
                p.into_iter()
                    .map(|(uid, w)| (uid, WardenId::new(w)))
                    .collect::<HashMap<_, _>>()
            }),
            group: self.group,
        }
    }
}

/// Parse the arguments after the program name.  Every refusal says what
/// was wrong; the caller prints the usage line too.
fn parse(args: &[String]) -> Result<Args, String> {
    let mut positional = Vec::new();
    let mut peers: Vec<(u32, u64)> = Vec::new();
    let mut group = None;
    let mut store_config = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--peer" => {
                let v = it.next().ok_or("--peer needs UID=WARDEN")?;
                let (uid, warden) = v
                    .split_once('=')
                    .ok_or_else(|| format!("--peer {v}: expected UID=WARDEN"))?;
                let uid: u32 = uid
                    .parse()
                    .map_err(|_| format!("--peer {v}: uid is not a number"))?;
                let warden: u64 = warden
                    .parse()
                    .map_err(|_| format!("--peer {v}: warden is not a number"))?;
                if peers.iter().any(|(u, _)| *u == uid) {
                    return Err(format!("--peer {v}: uid {uid} given twice"));
                }
                if peers.iter().any(|(_, w)| *w == warden) {
                    return Err(format!("--peer {v}: warden {warden} given twice"));
                }
                peers.push((uid, warden));
            }
            "--socket-group" => {
                let v = it.next().ok_or("--socket-group needs a GID")?;
                if group.is_some() {
                    return Err("--socket-group given twice".into());
                }
                group = Some(
                    v.parse()
                        .map_err(|_| format!("--socket-group {v}: not a numeric gid"))?,
                );
            }
            "--store-config" => {
                let v = it.next().ok_or("--store-config needs a FILE")?;
                if store_config.is_some() {
                    return Err("--store-config given twice".into());
                }
                store_config = Some(v.clone());
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            _ => positional.push(a.clone()),
        }
    }
    let [db, sock] = &positional[..] else {
        return Err(format!("expected 2 arguments, got {}", positional.len()));
    };
    Ok(Args {
        db: db.clone(),
        sock: sock.clone(),
        options: ServerOptionsSpec {
            peers: (!peers.is_empty()).then_some(peers),
            group,
        },
        store_config,
    })
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Args {
        db,
        sock,
        options,
        store_config,
    } = match parse(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("taso-coordd: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let who = match &options.peers {
        None => "unauthenticated".to_string(),
        Some(p) => format!("{} mapped peer(s)", p.len()),
    };
    let mut config = LogConfig::default();
    let reads = match &store_config {
        None => "no store: contract accepts are refused NotReadable".to_string(),
        Some(path) => {
            let spec = match std::fs::read_to_string(path)
                .map_err(|e| e.to_string())
                .and_then(|t| store_spec(&t))
            {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("taso-coordd: --store-config {path}: {e}");
                    return ExitCode::from(2);
                }
            };
            let store = match spec.store.open() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("taso-coordd: --store-config {path}: opening the store: {e}");
                    return ExitCode::FAILURE;
                }
            };
            config.store = Arc::new(CoordStore::new(store, &spec.prefix));
            format!("reads the store under {:?}", spec.prefix)
        }
    };
    let coord: Arc<dyn Coord> = match Coordinator::open_with(&db, config) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("taso-coordd: {db}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let _server = match Server::spawn_with(&sock, coord, options.build()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("taso-coordd: serving on {sock}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("taso-coordd: serving {db} on {sock} ({who}; {reads})");
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Args, String> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn positional_only_is_unauthenticated() {
        let a = p(&["c.redb", "c.sock"]).unwrap();
        assert_eq!((a.db.as_str(), a.sock.as_str()), ("c.redb", "c.sock"));
        assert_eq!(a.options, ServerOptionsSpec::default());
        assert_eq!(a.store_config, None);
        let o = a.options.build();
        assert!(o.peers.is_none() && o.group.is_none());
    }

    #[test]
    fn peers_and_group_parse_in_any_order() {
        let a = p(&[
            "--peer",
            "1001=1",
            "c.redb",
            "--socket-group",
            "990",
            "c.sock",
            "--peer",
            "1002=2",
        ])
        .unwrap();
        assert_eq!(
            a.options,
            ServerOptionsSpec {
                peers: Some(vec![(1001, 1), (1002, 2)]),
                group: Some(990)
            }
        );
        let o = a.options.build();
        let peers = o.peers.unwrap();
        assert_eq!(peers.get(&1001), Some(&WardenId::new(1)));
        assert_eq!(peers.get(&1002), Some(&WardenId::new(2)));
        assert_eq!(o.group, Some(990));
    }

    #[test]
    fn mistakes_are_named() {
        let bad = [
            (&["c.redb"][..], "expected 2 arguments, got 1"),
            (&["a", "b", "c"], "expected 2 arguments, got 3"),
            (&["a", "b", "--peer"], "--peer needs UID=WARDEN"),
            (
                &["a", "b", "--peer", "1001"],
                "--peer 1001: expected UID=WARDEN",
            ),
            (
                &["a", "b", "--peer", "x=1"],
                "--peer x=1: uid is not a number",
            ),
            (
                &["a", "b", "--peer", "1=y"],
                "--peer 1=y: warden is not a number",
            ),
            (
                &["a", "b", "--peer", "1=1", "--peer", "1=2"],
                "--peer 1=2: uid 1 given twice",
            ),
            (
                &["a", "b", "--peer", "1=7", "--peer", "2=7"],
                "--peer 2=7: warden 7 given twice",
            ),
            (&["a", "b", "--socket-group"], "--socket-group needs a GID"),
            (
                &["a", "b", "--socket-group", "wardens"],
                "--socket-group wardens: not a numeric gid",
            ),
            (
                &["a", "b", "--socket-group", "1", "--socket-group", "2"],
                "--socket-group given twice",
            ),
            (&["a", "b", "--tls"], "unknown option --tls"),
            (&["a", "b", "--store-config"], "--store-config needs a FILE"),
            (
                &["a", "b", "--store-config", "x", "--store-config", "y"],
                "--store-config given twice",
            ),
        ];
        for (args, want) in bad {
            assert_eq!(p(args).unwrap_err(), want, "{args:?}");
        }
    }

    #[test]
    fn a_store_config_is_the_wardens_store_and_prefix() {
        let a = p(&["a", "b", "--store-config", "/etc/taso/store.json"]).unwrap();
        assert_eq!(a.store_config.as_deref(), Some("/etc/taso/store.json"));
        assert_eq!(
            store_spec(r#"{"store": "/srv/taso/store"}"#).unwrap(),
            StoreSpec {
                store: StoreConf::Local("/srv/taso/store".into()),
                prefix: "vessels".into()
            }
        );
        let s3 = store_spec(
            r#"{"store": {"s3": {"endpoint": "http://127.0.0.1:3900", "bucket": "taso",
                "access_key_id": "GK1", "secret_key_file": "/root/s3.secret"}},
                "prefix": "gate-p4"}"#,
        )
        .unwrap();
        assert_eq!(s3.prefix, "gate-p4");
        assert!(matches!(s3.store, StoreConf::S3 { ref region, .. } if region == "garage"));
        for (bad, why) in [
            ("[]", "must be a JSON object"),
            (r#"{"store": "/s", "extra": 1}"#, "unknown key \"extra\""),
            (
                r#"{"store": "/s", "prefix": 3}"#,
                "\"prefix\" must be a string",
            ),
        ] {
            assert_eq!(store_spec(bad).unwrap_err(), why, "{bad}");
        }
        assert!(store_spec(r#"{"prefix": "p"}"#).is_err(), "no store");
        assert!(
            store_spec(r#"{"store": "relative/dir"}"#).is_err(),
            "not absolute"
        );
    }
}
