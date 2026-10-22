//! `taso-sim`: an agent stand-in for the P1 gate (v1.0 §1 P1).
//!
//! The gate is measured on Hermes's `state.db`.  Until the Hermes image
//! exists, this does what matters about it: a SQLite database in WAL mode
//! on the Vessel's dataset, written in transactions, with a turn boundary
//! after each batch.
//!
//! Each turn:
//! 1. `--txns` transactions of `--rows` rows of `--row-bytes` bytes, each
//!    commit timed (the gate's "write latency");
//! 2. one `Transcript` entry;
//! 3. `TurnEnd { quiescent: true }`, timed (the Warden seals and
//!    publishes there).
//!
//! It resumes after the last sealed turn the Warden reports in `Hello`,
//! so a reborn Vessel continues where its Chronicle says it was.
//!
//! P3 (file 11), the agent's side of forks and promotions over the Field:
//! `--effects N` declares N effects per turn after its transactions
//! (`NoExternalMutation`, deduplicated by key `t<turn>-<k>`: released,
//! held or refused, counted); `--promote NAME` (repeatable) asks right
//! after `Hello` for the child `NAME` to be promoted at its newest Seal,
//! and then lists `Open`; `--forks N` asks for N forks after the last
//! turn.  Every answer goes into the stats; a refusal is an answer, not an
//! error.
//!
//! `--bare` runs the same writes with no Field at all: the baseline the
//! gate compares against ("p95 write latency ≤ 1.5× bare local NVMe").
//!
//! At the end it writes `--stats` (JSON), with `--samples` every commit's
//! latency and with `--turn-samples` every TurnEnd's round trip, in
//! microseconds (for quantiles across Vessels), and
//! exits 0; any protocol or
//! database error exits 1.  A SIGBUS kills it, which the runtime reports
//! as a failed agent: the gate counts those.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use serde_json::json;
use taso_core::record::{Consequence, RetryPolicy};
use taso_field::protocol::{
    recv_reply, send_request, EffectResult, ForkResult, PromoteResult, Reply, Request, VERSION,
};

/// The command line.
#[derive(Clone, Debug, PartialEq)]
struct Opts {
    turns: u64,
    txns: u32,
    rows: u32,
    row_bytes: usize,
    db: PathBuf,
    stats: PathBuf,
    bare: bool,
    synchronous: String,
    /// Pause after each turn (an agent thinking), so a harness can catch
    /// it mid-run.
    turn_sleep_ms: u64,
    /// Write every TurnEnd's round trip here (the agent's pause at the
    /// turn boundary: Seal and publish), in microseconds, one per line.
    turn_samples: Option<PathBuf>,
    /// Write every commit's latency here, in microseconds, one per line.
    samples: Option<PathBuf>,
    /// Effects declared per turn.
    effects: u64,
    /// Forks asked for after the last turn.
    forks: u64,
    /// Children to promote, right after Hello.
    promote: Vec<String>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            turns: 50,
            txns: 4,
            rows: 8,
            row_bytes: 512,
            db: "/work/state.db".into(),
            stats: "/work/sim-stats.json".into(),
            bare: false,
            synchronous: "normal".into(),
            samples: None,
            turn_samples: None,
            turn_sleep_ms: 0,
            effects: 0,
            forks: 0,
            promote: Vec::new(),
        }
    }
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
        let num = |v: String| {
            v.parse::<u64>()
                .map_err(|_| format!("{a}: {v:?} is not a number"))
        };
        match a.as_str() {
            "--turns" => o.turns = num(val()?)?,
            "--txns" => o.txns = u32::try_from(num(val()?)?).map_err(|_| "--txns is too large")?,
            "--rows" => o.rows = u32::try_from(num(val()?)?).map_err(|_| "--rows is too large")?,
            "--row-bytes" => {
                o.row_bytes =
                    usize::try_from(num(val()?)?).map_err(|_| "--row-bytes is too large")?
            }
            "--db" => o.db = val()?.into(),
            "--stats" => o.stats = val()?.into(),
            "--bare" => o.bare = true,
            "--samples" => o.samples = Some(val()?.into()),
            "--turn-samples" => o.turn_samples = Some(val()?.into()),
            "--turn-sleep-ms" => o.turn_sleep_ms = num(val()?)?,
            "--effects" => o.effects = num(val()?)?,
            "--forks" => o.forks = num(val()?)?,
            "--promote" => o.promote.push(val()?),
            "--synchronous" => {
                o.synchronous = val()?;
                if !["off", "normal", "full", "extra"].contains(&o.synchronous.as_str()) {
                    return Err("--synchronous must be off, normal, full or extra".into());
                }
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if o.turns == 0 || o.txns == 0 || o.rows == 0 {
        return Err("--turns, --txns and --rows must be positive".into());
    }
    Ok(o)
}

/// Quantiles of a set of durations, in milliseconds.
fn summary(mut v: Vec<Duration>) -> serde_json::Value {
    if v.is_empty() {
        return json!(null);
    }
    v.sort_unstable();
    let q = |p: f64| {
        let i = ((v.len() as f64 * p).ceil() as usize).clamp(1, v.len()) - 1;
        v[i].as_secs_f64() * 1000.0
    };
    json!({ "n": v.len(), "p50_ms": q(0.50), "p95_ms": q(0.95), "p99_ms": q(0.99), "max_ms": q(1.0) })
}

/// The Field connection, or none (`--bare`).
struct Field(Option<UnixStream>);

impl Field {
    fn ask(&mut self, req: Request) -> Result<Option<Reply>, String> {
        let Some(s) = self.0.as_mut() else {
            return Ok(None);
        };
        send_request(s, &req).map_err(|e| format!("send: {e}"))?;
        match recv_reply(s).map_err(|e| format!("receive: {e}"))? {
            Some(Reply::Error { code, message }) => {
                Err(format!("the Warden refused: {code:?}: {message}"))
            }
            Some(r) => Ok(Some(r)),
            None => Err("the Warden closed the connection".into()),
        }
    }
}

/// Run the turns, over the Field socket at `field` (`None`: bare).
fn run(o: &Opts, field: Option<&std::path::Path>) -> Result<serde_json::Value, String> {
    let mut field = match field {
        None => Field(None),
        Some(path) => Field(Some(
            UnixStream::connect(path).map_err(|e| format!("connect {}: {e}", path.display()))?,
        )),
    };
    let resumed_after = match field.ask(Request::Hello { version: VERSION })? {
        None => None,
        Some(Reply::Hello {
            last_sealed_turn, ..
        }) => last_sealed_turn,
        Some(r) => return Err(format!("unexpected answer to Hello: {r:?}")),
    };
    let first = resumed_after.map_or(1, |t| t + 1);
    if !o.promote.is_empty() && field.0.is_none() {
        return Err("--promote needs the Field (not --bare)".into());
    }
    let mut promotions = Vec::new();
    for child in &o.promote {
        promotions.push(
            match field.ask(Request::Promote {
                child: child.clone(),
                seal: None,
            })? {
                Some(Reply::Promote {
                    child,
                    result: PromoteResult::Promoted { seal, adopted },
                }) => json!({ "child": child, "seal": seal, "adopted": adopted }),
                Some(Reply::Promote {
                    child,
                    result: PromoteResult::Refused { reason },
                }) => json!({ "child": child, "refused": reason }),
                r => return Err(format!("unexpected answer to Promote: {r:?}")),
            },
        );
    }
    let open_after_promote = if o.promote.is_empty() {
        None
    } else {
        match field.ask(Request::Open)? {
            Some(Reply::Open { effects }) => Some(effects.len()),
            r => return Err(format!("unexpected answer to Open: {r:?}")),
        }
    };

    let db =
        rusqlite::Connection::open(&o.db).map_err(|e| format!("open {}: {e}", o.db.display()))?;
    db.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| e.to_string())?;
    db.pragma_update(None, "synchronous", &o.synchronous)
        .map_err(|e| e.to_string())?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS events (turn INTEGER, n INTEGER, body BLOB)")
        .map_err(|e| e.to_string())?;

    let body = vec![0x5au8; o.row_bytes];
    let mut writes = Vec::new();
    let mut turn_ends = Vec::new();
    let (mut sealed, mut not_sealed) = (0u64, 0u64);
    let (mut released, mut held, mut refused) = (0u64, 0u64, Vec::new());
    let start = Instant::now();
    for turn in first..first + o.turns {
        for _ in 0..o.txns {
            let t = Instant::now();
            let tx = db.unchecked_transaction().map_err(|e| e.to_string())?;
            {
                let mut ins = tx
                    .prepare_cached("INSERT INTO events VALUES (?1, ?2, ?3)")
                    .map_err(|e| e.to_string())?;
                for n in 0..o.rows {
                    ins.execute(rusqlite::params![turn as i64, n, &body])
                        .map_err(|e| e.to_string())?;
                }
            }
            tx.commit().map_err(|e| e.to_string())?;
            writes.push(t.elapsed());
        }
        for k in 0..o.effects {
            let key = format!("t{turn}-{k}").into_bytes();
            match field.ask(Request::Effect {
                call: k,
                provider: "sim".into(),
                request: key.clone(),
                footprint: Vec::new(),
                retry: RetryPolicy::ProviderDeduplicated { key },
                consequence: Consequence::NoExternalMutation,
                authority: b"taso-sim".to_vec(),
            })? {
                None => {}
                Some(Reply::Effect { result, .. }) => match result {
                    EffectResult::Released { .. } => released += 1,
                    EffectResult::Held { .. } => held += 1,
                    EffectResult::Refused { reason } => refused.push(reason),
                },
                Some(r) => return Err(format!("unexpected answer to Effect: {r:?}")),
            }
        }
        field.ask(Request::Transcript {
            entry: format!("turn {turn}: {} transactions", o.txns).into_bytes(),
        })?;
        let t = Instant::now();
        match field.ask(Request::TurnEnd {
            turn,
            quiescent: true,
        })? {
            None => {}
            Some(Reply::TurnEnd {
                sealed: Some(_), ..
            }) => sealed += 1,
            Some(Reply::TurnEnd { sealed: None, .. }) => not_sealed += 1,
            Some(r) => return Err(format!("unexpected answer to TurnEnd: {r:?}")),
        }
        if field.0.is_some() {
            turn_ends.push(t.elapsed());
        }
        if o.turn_sleep_ms > 0 {
            std::thread::sleep(Duration::from_millis(o.turn_sleep_ms));
        }
    }
    for (path, v) in [(&o.samples, &writes), (&o.turn_samples, &turn_ends)] {
        if let Some(path) = path {
            let text: String = v.iter().map(|d| format!("{}\n", d.as_micros())).collect();
            std::fs::write(path, text).map_err(|e| format!("writing {}: {e}", path.display()))?;
        }
    }
    let mut forks = Vec::new();
    for _ in 0..o.forks {
        forks.push(match field.ask(Request::Fork { seal: None })? {
            None => json!({ "refused": "bare: no Field" }),
            Some(Reply::Fork {
                result: ForkResult::Forked { child, seal },
            }) => json!({ "child": child, "seal": seal }),
            Some(Reply::Fork {
                result: ForkResult::Refused { reason },
            }) => json!({ "refused": reason }),
            Some(r) => return Err(format!("unexpected answer to Fork: {r:?}")),
        });
    }
    let rows: i64 = db
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "bare": o.bare,
        "resumed_after": resumed_after,
        "turns": [first, first + o.turns - 1],
        "rows_in_db": rows,
        "sealed": sealed,
        "not_sealed": not_sealed,
        "wall_s": start.elapsed().as_secs_f64(),
        "write": summary(writes),
        "turn_end": summary(turn_ends),
        "effects": { "released": released, "held": held, "refused": refused },
        "promotions": promotions,
        "open_after_promote": open_after_promote,
        "forks": forks,
    }))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let o = match parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("taso-sim: {e}");
            return ExitCode::from(2);
        }
    };
    let field = if o.bare {
        None
    } else {
        match std::env::var("TASO_FIELD") {
            Ok(p) => Some(PathBuf::from(p)),
            Err(_) => {
                eprintln!("taso-sim: TASO_FIELD is not set (or use --bare)");
                return ExitCode::from(2);
            }
        }
    };
    match run(&o, field.as_deref()) {
        Ok(stats) => {
            let text = serde_json::to_string_pretty(&stats).expect("JSON");
            if let Err(e) =
                std::fs::File::create(&o.stats).and_then(|mut f| f.write_all(text.as_bytes()))
            {
                eprintln!("taso-sim: writing {}: {e}", o.stats.display());
                return ExitCode::FAILURE;
            }
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("taso-sim: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn options() {
        assert_eq!(parse(&[]).unwrap(), Opts::default());
        let o = parse(&s(&[
            "--turns",
            "3",
            "--txns",
            "2",
            "--rows",
            "5",
            "--row-bytes",
            "64",
            "--bare",
            "--synchronous",
            "full",
        ]))
        .unwrap();
        assert_eq!(
            (o.turns, o.txns, o.rows, o.row_bytes, o.bare),
            (3, 2, 5, 64, true)
        );
        assert_eq!(o.synchronous, "full");
        let o = parse(&s(&[
            "--effects",
            "2",
            "--forks",
            "1",
            "--promote",
            "a",
            "--promote",
            "b",
        ]))
        .unwrap();
        assert_eq!((o.effects, o.forks), (2, 1));
        assert_eq!(o.promote, ["a", "b"]);
        for bad in [
            &["--turns"][..],
            &["--turns", "x"],
            &["--turns", "0"],
            &["--synchronous", "maybe"],
            &["--what"],
            &["--promote"],
            &["--forks", "-1"],
        ] {
            assert!(parse(&s(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn bare_run_writes_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        let o = Opts {
            turns: 3,
            txns: 2,
            rows: 4,
            row_bytes: 16,
            db: dir.path().join("state.db"),
            stats: dir.path().join("stats.json"),
            bare: true,
            synchronous: "normal".into(),
            samples: Some(dir.path().join("samples")),
            turn_samples: None,
            turn_sleep_ms: 1,
            ..Opts::default()
        };
        let st = run(&o, None).unwrap();
        let samples = std::fs::read_to_string(dir.path().join("samples")).unwrap();
        assert_eq!(samples.lines().count(), 6);
        assert!(samples.lines().all(|l| l.parse::<u64>().is_ok()));
        assert_eq!(st["rows_in_db"], 24);
        assert_eq!(st["write"]["n"], 6);
        assert_eq!(st["turns"], json!([1, 3]));
        assert!(st["turn_end"].is_null());
    }

    /// Against a stand-in Warden: promotions right after Hello, then
    /// Open; effects per turn; forks after the last turn.  Every answer,
    /// a refusal too, is in the stats.
    #[test]
    fn field_run_promotes_declares_and_forks() {
        use std::os::unix::net::UnixListener;
        use taso_field::protocol::{recv_request, send_reply, OpenEffect};
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("f.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let warden = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut forks = 0;
            while let Some(req) = recv_request(&mut c).unwrap() {
                let reply = match &req {
                    Request::Hello { .. } => Reply::Hello {
                        version: VERSION,
                        last_sealed_turn: None,
                    },
                    Request::Promote { child, .. } if child == "c1" => Reply::Promote {
                        child: child.clone(),
                        result: PromoteResult::Promoted {
                            seal: 9,
                            adopted: vec![4, 5],
                        },
                    },
                    Request::Promote { child, .. } => Reply::Promote {
                        child: child.clone(),
                        result: PromoteResult::Refused {
                            reason: "already promoted".into(),
                        },
                    },
                    Request::Open => Reply::Open {
                        effects: vec![
                            OpenEffect {
                                op: 4,
                                provider: "sim".into(),
                                request: vec![],
                                retry: RetryPolicy::UnsafeToRetry,
                                unknown: false,
                            };
                            2
                        ],
                    },
                    Request::Effect { call, .. } => Reply::Effect {
                        call: *call,
                        result: match call {
                            0 => EffectResult::Held { op: 1 },
                            _ => EffectResult::Refused {
                                reason: "quota".into(),
                            },
                        },
                    },
                    Request::Transcript { .. } => Reply::Recorded { lsn: 1 },
                    Request::TurnEnd { turn, .. } => Reply::TurnEnd {
                        turn: *turn,
                        sealed: Some(*turn),
                    },
                    Request::Fork { seal: None } => {
                        forks += 1;
                        Reply::Fork {
                            result: if forks == 1 {
                                ForkResult::Forked {
                                    child: "p-fork-3".into(),
                                    seal: 12,
                                }
                            } else {
                                ForkResult::Refused {
                                    reason: "no fork slot left".into(),
                                }
                            },
                        }
                    }
                    r => panic!("unexpected {r:?}"),
                };
                seen.push(req);
                send_reply(&mut c, &reply).unwrap();
            }
            seen
        });
        let o = Opts {
            turns: 1,
            txns: 1,
            rows: 1,
            row_bytes: 8,
            db: dir.path().join("s.db"),
            stats: dir.path().join("x"),
            effects: 2,
            forks: 2,
            promote: vec!["c1".into(), "c2".into()],
            ..Opts::default()
        };
        let st = run(&o, Some(&sock)).unwrap();
        let seen = warden.join().unwrap();
        assert_eq!(
            st["promotions"],
            json!([
                {"child": "c1", "seal": 9, "adopted": [4, 5]},
                {"child": "c2", "refused": "already promoted"},
            ])
        );
        assert_eq!(st["open_after_promote"], 2);
        assert_eq!(
            st["effects"],
            json!({"released": 0, "held": 1, "refused": ["quota"]})
        );
        assert_eq!(
            st["forks"],
            json!([{"child": "p-fork-3", "seal": 12}, {"refused": "no fork slot left"}])
        );
        // The order: Hello, the promotions and Open, the turn, the forks.
        let tags: Vec<&str> = seen
            .iter()
            .map(|r| match r {
                Request::Hello { .. } => "hello",
                Request::Promote { .. } => "promote",
                Request::Open => "open",
                Request::Effect { .. } => "effect",
                Request::Transcript { .. } => "transcript",
                Request::TurnEnd { .. } => "turn",
                Request::Fork { .. } => "fork",
                Request::Outcome { .. } => "outcome",
            })
            .collect();
        assert_eq!(
            tags,
            [
                "hello",
                "promote",
                "promote",
                "open",
                "effect",
                "effect",
                "transcript",
                "turn",
                "fork",
                "fork"
            ]
        );
        // Each effect is the declared key, never mutating the world.
        assert!(seen.iter().any(|r| matches!(r,
            Request::Effect { request, consequence: Consequence::NoExternalMutation, .. }
                if request == b"t1-1")));
    }

    /// Against a stand-in Warden: resumes after the reported turn, sends
    /// a transcript entry and a quiescent TurnEnd per turn, counts Seals.
    #[test]
    fn field_run_resumes_and_counts_seals() {
        use std::os::unix::net::UnixListener;
        use taso_field::protocol::{recv_request, send_reply};
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("f.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let warden = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            while let Some(req) = recv_request(&mut c).unwrap() {
                let reply = match &req {
                    Request::Hello { .. } => Reply::Hello {
                        version: VERSION,
                        last_sealed_turn: Some(5),
                    },
                    Request::Transcript { .. } => Reply::Recorded { lsn: 1 },
                    // Every other turn is not sealed.
                    Request::TurnEnd { turn, .. } => Reply::TurnEnd {
                        turn: *turn,
                        sealed: (turn % 2 == 0).then_some(*turn),
                    },
                    Request::Effect { .. }
                    | Request::Outcome { .. }
                    | Request::Open
                    | Request::Fork { .. }
                    | Request::Promote { .. } => {
                        unreachable!()
                    }
                };
                seen.push(req);
                send_reply(&mut c, &reply).unwrap();
            }
            seen
        });
        let o = Opts {
            turns: 3,
            txns: 1,
            rows: 1,
            row_bytes: 8,
            db: dir.path().join("s.db"),
            stats: dir.path().join("x"),
            bare: false,
            synchronous: "normal".into(),
            samples: None,
            turn_samples: Some(dir.path().join("turns")),
            turn_sleep_ms: 0,
            ..Opts::default()
        };
        let st = run(&o, Some(&sock)).unwrap();
        let seen = warden.join().unwrap();
        assert_eq!(st["resumed_after"], 5);
        assert_eq!(st["turns"], json!([6, 8]));
        assert_eq!(
            (st["sealed"].clone(), st["not_sealed"].clone()),
            (json!(2), json!(1))
        );
        assert_eq!(st["turn_end"]["n"], 3);
        let turns = std::fs::read_to_string(dir.path().join("turns")).unwrap();
        assert_eq!(
            turns.lines().filter(|l| l.parse::<u64>().is_ok()).count(),
            3
        );
        let turn_ends: Vec<(u64, bool)> = seen
            .iter()
            .filter_map(|r| match r {
                Request::TurnEnd { turn, quiescent } => Some((*turn, *quiescent)),
                _ => None,
            })
            .collect();
        assert_eq!(turn_ends, vec![(6, true), (7, true), (8, true)]);
        assert_eq!(
            seen.iter()
                .filter(|r| matches!(r, Request::Transcript { .. }))
                .count(),
            3
        );
    }
}
