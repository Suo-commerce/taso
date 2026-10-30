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
//! and then asks `Result` for each adopted op; `--forks N` asks for N
//! forks after the last turn.  Every answer goes into the stats; a refusal
//! is an answer, not an error.
//!
//! P4 (file 6c): `--nominate CLASSES` (repeatable) asks, after the last
//! turn and before any fork, for the newest Seal to be nominated with the
//! comma-separated classes dropped (`""`: none); each answer goes into
//! the stats as `nominations`.
//!
//! P5 E3 (B2, file E3-3a): `--step DIR` runs no turns of its own.  It is
//! driven one operation at a time by a crash harness that must place a
//! failure between two of them.  The agent cannot read the harness's
//! stdin (it runs under runc, its root read-only), so the channel is
//! files in `DIR` (default `/tmp/e3`, the container's own tmpfs, never on
//! the Vessel's dataset or the device being cut): the agent writes
//! `ready` (JSON: its pid and the turn it resumed after), then for n = 1,
//! 2, … waits for `op.<n>` (one line), does it, and writes `reply.<n>`
//! (one JSON line), each file renamed into place whole.  The harness, as
//! root, reaches `DIR` through `/proc/<pid>/root`, and removes each reply
//! once read; on its last reply (`exit`, or a promotion) the agent waits,
//! up to 30 s, until it is taken, since `DIR` goes with the process.  Operations (plan
//! P5-18): `write [TAG]` one transaction of `--rows` rows of the current
//! turn, `n = TAG·1 000 000 + i` (a fork's child is driven with tag 1);
//! `seal` a Transcript entry and a quiescent `TurnEnd`, then the next
//! turn; `fork`; `promote CHILD` (a promotion ends the run: the agent
//! exits after the reply and the Warden restarts it, C7); `effect` one
//! `NoExternalMutation` effect, key `t<turn>-e<k>`; `exit`.  A refusal is
//! a reply, not an error; a closed Field ends the agent.
//!
//! P5 B1 (the first write into a large file in a fork): `--big-file-mib N`
//! makes `big` beside the database, N MiB, written and synced before the
//! first turn, if it is not there whole; if it is (inherited: a fork's
//! child, or a Vessel reborn) the agent writes 4 KiB into its middle and
//! fdatasyncs, timed, before anything else, into `--first-write-samples`
//! (microseconds, one line).
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
    recv_reply, send_request, EffectResult, ForkResult, NominateResult, PromoteResult, Reply,
    Request, VERSION,
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
    /// Nominations asked for after the last turn: the classes each drops.
    nominate: Vec<Vec<String>>,
    /// Driven one operation at a time through files in this directory
    /// (P5 E3); no turns of its own.
    step: Option<PathBuf>,
    /// A file of this many MiB beside the database (P5 B1); 0: none.
    big_file_mib: u64,
    /// Where the first 4 KiB write into an inherited big file is timed.
    first_write_samples: Option<PathBuf>,
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
            nominate: Vec::new(),
            step: None,
            big_file_mib: 0,
            first_write_samples: None,
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
            "--nominate" => o.nominate.push(
                val()?
                    .split(',')
                    .filter(|c| !c.is_empty())
                    .map(str::to_string)
                    .collect(),
            ),
            "--step" => o.step = Some(val()?.into()),
            "--big-file-mib" => o.big_file_mib = num(val()?)?,
            "--first-write-samples" => o.first_write_samples = Some(val()?.into()),
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

/// `--big-file-mib`: make the file whole, or, inherited whole, time the
/// first 4 KiB written into its middle and made durable.  Returns that time.
fn big_file(o: &Opts) -> Result<Option<Duration>, String> {
    use std::os::unix::fs::FileExt;
    if o.big_file_mib == 0 {
        return Ok(None);
    }
    let path = o.db.with_file_name("big");
    let size = o.big_file_mib << 20;
    let err = |what: &str, e: std::io::Error| format!("{what} {}: {e}", path.display());
    if std::fs::metadata(&path).is_ok_and(|m| m.len() == size) {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|e| err("open", e))?;
        let block = [0xa5u8; 4096];
        let t = Instant::now();
        f.write_all_at(&block, (size / 2) & !4095)
            .map_err(|e| err("write", e))?;
        f.sync_data().map_err(|e| err("fdatasync", e))?;
        let took = t.elapsed();
        if let Some(out) = &o.first_write_samples {
            std::fs::write(out, format!("{}\n", took.as_micros()))
                .map_err(|e| format!("writing {}: {e}", out.display()))?;
        }
        return Ok(Some(took));
    }
    let f = std::fs::File::create(&path).map_err(|e| err("create", e))?;
    let chunk = vec![0x3cu8; 1 << 20];
    for i in 0..o.big_file_mib {
        f.write_all_at(&chunk, i << 20).map_err(|e| err("write", e))?;
    }
    f.sync_all().map_err(|e| err("fsync", e))?;
    Ok(None)
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
        // Promoted: nothing more is asked (C7: the Warden restarts this
        // agent on the child's files).
        if promotions
            .iter()
            .any(|p: &serde_json::Value| p.get("adopted").is_some())
        {
            break;
        }
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
    // What became of each adopted op, as the agent may ask (C5: listing
    // is the sender's).
    let mut adopted_states = Vec::new();
    for p in &promotions {
        for op in p["adopted"].as_array().into_iter().flatten() {
            let op = op.as_u64().expect("op ids are numbers");
            adopted_states.push(match field.ask(Request::Result { op })? {
                Some(Reply::Result { state, .. }) => json!(format!("{state:?}")),
                r => return Err(format!("unexpected answer to Result: {r:?}")),
            });
        }
    }

    let first_write = if promotions.iter().any(|p| p.get("adopted").is_some()) {
        None
    } else {
        big_file(o)?
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
    // Promoted: the Warden adopts the child's files at the next start and
    // runs this agent again on them (C7); no turn is taken until then.
    let promoted = promotions.iter().any(|p| p.get("adopted").is_some());
    let (turns, fork_asks) = if promoted { (0, 0) } else { (o.turns, o.forks) };
    let start = Instant::now();
    for turn in first..first + turns {
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
    let mut nominations = Vec::new();
    for exclude in if promoted { &[][..] } else { &o.nominate[..] } {
        nominations.push(
            match field.ask(Request::Nominate {
                seal: None,
                exclude: exclude.clone(),
            })? {
                None => json!({ "retry": "bare: no Field" }),
                Some(Reply::Nominate { result }) => match result {
                    NominateResult::Nominated { candidate } => json!({ "nominated": candidate }),
                    NominateResult::Pending { candidate } => json!({ "pending": candidate }),
                    NominateResult::Refused { reason } => json!({ "refused": reason }),
                    NominateResult::Retry { why } => json!({ "retry": why }),
                    NominateResult::NoVerifier => json!({ "no_verifier": true }),
                },
                Some(r) => return Err(format!("unexpected answer to Nominate: {r:?}")),
            },
        );
    }
    let mut forks = Vec::new();
    for _ in 0..fork_asks {
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
        "turns": if turns > 0 { json!([first, first + turns - 1]) } else { json!(null) },
        "promoted_then_exited": promoted,
        "rows_in_db": rows,
        "sealed": sealed,
        "not_sealed": not_sealed,
        "wall_s": start.elapsed().as_secs_f64(),
        "write": summary(writes),
        "turn_end": summary(turn_ends),
        "effects": { "released": released, "held": held, "refused": refused },
        "promotions": promotions,
        "nominations": nominations,
        "adopted_states": adopted_states,
        "forks": forks,
        "first_write_ms": first_write.map(|d| d.as_secs_f64() * 1000.0),
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
    let result = match &o.step {
        Some(dir) => step::run(&o, field.as_deref(), dir),
        None => run(&o, field.as_deref()),
    };
    match result {
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

/// `--step DIR`: one operation at a time, from a crash harness (P5 E3).
mod step {
    use super::*;
    use std::path::Path;

    /// One parsed operation.
    #[derive(Debug, PartialEq)]
    pub(crate) enum Op {
        Write { tag: u64 },
        Seal,
        Fork,
        Promote { child: String },
        Effect,
        Exit,
    }

    pub(crate) fn parse_op(line: &str) -> Result<Op, String> {
        let mut w = line.split_whitespace();
        let op = w.next().ok_or("an empty operation")?;
        let arg = w.next();
        let op = match (op, arg) {
            ("write", None) => Op::Write { tag: 0 },
            ("write", Some(t)) => Op::Write {
                tag: t.parse().map_err(|_| format!("write: tag {t:?} is not a number"))?,
            },
            ("seal", None) => Op::Seal,
            ("fork", None) => Op::Fork,
            ("promote", Some(c)) => Op::Promote { child: c.to_string() },
            ("effect", None) => Op::Effect,
            ("exit", None) => Op::Exit,
            _ => return Err(format!("unknown operation {line:?} (write [TAG] | seal | fork | promote CHILD | effect | exit)")),
        };
        if w.next().is_some() {
            return Err(format!("{line:?}: too many words"));
        }
        Ok(op)
    }

    /// Write `name` in `dir` whole: a temporary name, then a rename.
    fn put(dir: &Path, name: &str, text: &str) -> Result<(), String> {
        let tmp = dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, text).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, dir.join(name)).map_err(|e| format!("renaming into {name}: {e}"))
    }

    /// Wait for `op.<n>` in `dir` and return its line.
    fn next(dir: &Path, n: u64) -> Result<String, String> {
        let p = dir.join(format!("op.{n}"));
        loop {
            match std::fs::read_to_string(&p) {
                Ok(t) => return Ok(t.trim().to_string()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(e) => return Err(format!("reading {}: {e}", p.display())),
            }
        }
    }

    pub(crate) fn run(
        o: &Opts,
        field: Option<&Path>,
        dir: &Path,
    ) -> Result<serde_json::Value, String> {
        let mut field = match field {
            None => Field(None),
            Some(path) => Field(Some(
                UnixStream::connect(path)
                    .map_err(|e| format!("connect {}: {e}", path.display()))?,
            )),
        };
        let resumed_after = match field.ask(Request::Hello { version: VERSION })? {
            None => None,
            Some(Reply::Hello {
                last_sealed_turn, ..
            }) => last_sealed_turn,
            Some(r) => return Err(format!("unexpected answer to Hello: {r:?}")),
        };
        let db = rusqlite::Connection::open(&o.db)
            .map_err(|e| format!("open {}: {e}", o.db.display()))?;
        db.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| e.to_string())?;
        db.pragma_update(None, "synchronous", &o.synchronous)
            .map_err(|e| e.to_string())?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS events (turn INTEGER, n INTEGER, body BLOB)")
            .map_err(|e| e.to_string())?;
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        put(
            dir,
            "ready",
            &format!(
                "{}\n",
                json!({ "pid": std::process::id(), "resumed_after": resumed_after })
            ),
        )?;
        let body = vec![0x5au8; o.row_bytes];
        let mut turn = resumed_after.map_or(1, |t| t + 1);
        let (mut written, mut effects) = (0u64, 0u64);
        let mut done = Vec::new();
        for n in 1u64.. {
            let line = next(dir, n)?;
            let reply = match parse_op(&line) {
                Err(e) => json!({ "n": n, "op": line, "refused": e }),
                Ok(op) => match act(
                    o,
                    &mut field,
                    &db,
                    &body,
                    &op,
                    &mut turn,
                    &mut written,
                    &mut effects,
                ) {
                    Ok(v) => {
                        let mut v = v;
                        v["n"] = json!(n);
                        v
                    }
                    Err(e)
                        if e.contains("closed the connection")
                            || e.starts_with("send:")
                            || e.starts_with("receive:") =>
                    {
                        let _ = put(
                            dir,
                            &format!("reply.{n}"),
                            &format!("{}\n", json!({ "n": n, "op": line, "lost": e })),
                        );
                        return Err(e);
                    }
                    Err(e) => json!({ "n": n, "op": line, "error": e }),
                },
            };
            put(dir, &format!("reply.{n}"), &format!("{reply}\n"))?;
            done.push(line.clone());
            let promoted = reply["result"]["adopted"].is_array();
            if line == "exit" || promoted {
                // The last reply: DIR goes with this process, so wait until
                // the harness has taken it (removed it), bounded.
                let taken = dir.join(format!("reply.{n}"));
                let until = Instant::now() + Duration::from_secs(30);
                while taken.exists() && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(2));
                }
                break;
            }
        }
        Ok(
            json!({ "step": done, "resumed_after": resumed_after, "turn": turn, "rows_written": written }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn act(
        o: &Opts,
        field: &mut Field,
        db: &rusqlite::Connection,
        body: &[u8],
        op: &Op,
        turn: &mut u64,
        written: &mut u64,
        effects: &mut u64,
    ) -> Result<serde_json::Value, String> {
        Ok(match op {
            Op::Write { tag } => {
                let t = Instant::now();
                let tx = db.unchecked_transaction().map_err(|e| e.to_string())?;
                {
                    let mut ins = tx
                        .prepare_cached("INSERT INTO events VALUES (?1, ?2, ?3)")
                        .map_err(|e| e.to_string())?;
                    for i in 0..o.rows {
                        let nn = tag * 1_000_000 + *written + u64::from(i);
                        ins.execute(rusqlite::params![*turn as i64, nn as i64, body])
                            .map_err(|e| e.to_string())?;
                    }
                }
                tx.commit().map_err(|e| e.to_string())?;
                *written += u64::from(o.rows);
                json!({ "op": "write", "turn": *turn, "tag": tag, "rows": o.rows, "ms": t.elapsed().as_secs_f64() * 1000.0 })
            }
            Op::Seal => {
                field.ask(Request::Transcript {
                    entry: format!("turn {turn}: step").into_bytes(),
                })?;
                let r = match field.ask(Request::TurnEnd {
                    turn: *turn,
                    quiescent: true,
                })? {
                    None => json!({ "op": "seal", "turn": *turn, "sealed": null, "bare": true }),
                    Some(Reply::TurnEnd { sealed, .. }) => {
                        json!({ "op": "seal", "turn": *turn, "sealed": sealed })
                    }
                    Some(r) => return Err(format!("unexpected answer to TurnEnd: {r:?}")),
                };
                *turn += 1;
                r
            }
            Op::Fork => match field.ask(Request::Fork { seal: None })? {
                None => json!({ "op": "fork", "refused": "bare: no Field" }),
                Some(Reply::Fork {
                    result: ForkResult::Forked { child, seal },
                }) => {
                    json!({ "op": "fork", "child": child, "seal": seal })
                }
                Some(Reply::Fork {
                    result: ForkResult::Refused { reason },
                }) => {
                    json!({ "op": "fork", "refused": reason })
                }
                Some(r) => return Err(format!("unexpected answer to Fork: {r:?}")),
            },
            Op::Promote { child } => match field.ask(Request::Promote {
                child: child.clone(),
                seal: None,
            })? {
                None => json!({ "op": "promote", "refused": "bare: no Field" }),
                Some(Reply::Promote {
                    child,
                    result: PromoteResult::Promoted { seal, adopted },
                }) => {
                    json!({ "op": "promote", "child": child, "result": { "seal": seal, "adopted": adopted } })
                }
                Some(Reply::Promote {
                    child,
                    result: PromoteResult::Refused { reason },
                }) => {
                    json!({ "op": "promote", "child": child, "refused": reason })
                }
                Some(r) => return Err(format!("unexpected answer to Promote: {r:?}")),
            },
            Op::Effect => {
                let k = *effects;
                *effects += 1;
                let key = format!("t{turn}-e{k}").into_bytes();
                match field.ask(Request::Effect {
                    call: k,
                    provider: "sim".into(),
                    request: key.clone(),
                    footprint: Vec::new(),
                    retry: RetryPolicy::ProviderDeduplicated { key: key.clone() },
                    consequence: Consequence::NoExternalMutation,
                    authority: b"taso-sim".to_vec(),
                })? {
                    None => json!({ "op": "effect", "refused": "bare: no Field" }),
                    Some(Reply::Effect { result, .. }) => json!({
                        "op": "effect",
                        "key": String::from_utf8_lossy(&key),
                        "result": match result {
                            EffectResult::Released { .. } => json!("released"),
                            EffectResult::Held { .. } => json!("held"),
                            EffectResult::Refused { reason } => json!({ "refused": reason }),
                        },
                    }),
                    Some(r) => return Err(format!("unexpected answer to Effect: {r:?}")),
                }
            }
            Op::Exit => json!({ "op": "exit", "turn": *turn }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn step_operations() {
        use step::{parse_op, Op};
        assert_eq!(parse_op("write").unwrap(), Op::Write { tag: 0 });
        assert_eq!(parse_op("write 1").unwrap(), Op::Write { tag: 1 });
        assert_eq!(parse_op(" seal ").unwrap(), Op::Seal);
        assert_eq!(parse_op("fork").unwrap(), Op::Fork);
        assert_eq!(
            parse_op("promote v-fork-1").unwrap(),
            Op::Promote {
                child: "v-fork-1".into()
            }
        );
        assert_eq!(parse_op("effect").unwrap(), Op::Effect);
        assert_eq!(parse_op("exit").unwrap(), Op::Exit);
        for bad in [
            "",
            "flush",
            "purge",
            "write x",
            "seal now",
            "promote",
            "promote a b",
        ] {
            assert!(parse_op(bad).is_err(), "{bad:?}");
        }
        let o = parse(&s(&["--step", "/tmp/e3"])).unwrap();
        assert_eq!(o.step, Some(PathBuf::from("/tmp/e3")));
    }

    /// Bare (no Field): the file channel end to end, from another thread
    /// playing the harness.
    #[test]
    fn step_drives_writes_through_files() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("e3");
        let o = Opts {
            db: d.path().join("state.db"),
            rows: 3,
            bare: true,
            step: Some(dir.clone()),
            ..Opts::default()
        };
        let harness = {
            let dir = dir.clone();
            std::thread::spawn(move || {
                let wait = |name: &str| loop {
                    if let Ok(t) = std::fs::read_to_string(dir.join(name)) {
                        return t;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                };
                let ready: serde_json::Value = serde_json::from_str(&wait("ready")).unwrap();
                assert!(ready["resumed_after"].is_null());
                let mut replies = Vec::new();
                for (n, op) in ["write", "write 1", "seal", "flush", "exit"]
                    .iter()
                    .enumerate()
                {
                    let n = n + 1;
                    std::fs::write(dir.join(format!(".op.{n}")), op).unwrap();
                    std::fs::rename(dir.join(format!(".op.{n}")), dir.join(format!("op.{n}")))
                        .unwrap();
                    let r: serde_json::Value =
                        serde_json::from_str(&wait(&format!("reply.{n}"))).unwrap();
                    std::fs::remove_file(dir.join(format!("reply.{n}"))).unwrap();
                    replies.push(r);
                }
                replies
            })
        };
        let out = step::run(&o, None, &dir).unwrap();
        let r = harness.join().unwrap();
        assert_eq!(
            (
                r[0]["op"].as_str(),
                r[0]["rows"].as_u64(),
                r[0]["turn"].as_u64()
            ),
            (Some("write"), Some(3), Some(1))
        );
        assert_eq!(r[1]["tag"], 1);
        assert_eq!(r[2]["turn"], 1, "the seal closes turn 1");
        assert!(r[3]["refused"].is_string(), "flush is no operation (P5-18)");
        assert_eq!(r[4]["turn"], 2);
        assert_eq!(out["rows_written"], 6);
        let db = rusqlite::Connection::open(d.path().join("state.db")).unwrap();
        let child: i64 = db
            .query_row("SELECT count(*) FROM events WHERE n >= 1000000", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(child, 3, "tag 1 rows are told apart by n");
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
        let o = parse(&s(&["--nominate", "Scratch", "--nominate", ""])).unwrap();
        assert_eq!(o.nominate, [vec!["Scratch".to_string()], vec![]]);
        for bad in [
            &["--nominate"][..],
            &["--turns"],
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

    /// Against a stand-in Warden, two runs.  With promotions: right after
    /// Hello, then each adopted op's Result; one succeeded, so no turn and
    /// no fork follows (C7: the Warden restarts the agent on the child's
    /// files).  Without: effects per turn, forks after the last turn.
    /// Every answer, a refusal too, is in the stats.
    #[test]
    fn field_run_promotes_declares_and_forks() {
        use std::os::unix::net::UnixListener;
        use taso_field::protocol::{recv_request, send_reply, OpState};
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("f.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let warden = std::thread::spawn(move || {
            let mut runs = Vec::new();
            let mut forks = 0;
            for _ in 0..2 {
                let (mut c, _) = listener.accept().unwrap();
                let mut seen = Vec::new();
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
                        Request::Result { op } => Reply::Result {
                            op: *op,
                            state: OpState::Pending,
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
                runs.push(seen);
            }
            runs
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
            promote: vec!["c2".into(), "c1".into(), "c3".into()],
            ..Opts::default()
        };
        let st = run(&o, Some(&sock)).unwrap();
        let plain = run(
            &Opts {
                promote: Vec::new(),
                ..o.clone()
            },
            Some(&sock),
        )
        .unwrap();
        let runs = warden.join().unwrap();
        let tag = |r: &Request| match r {
            Request::Hello { .. } => "hello",
            Request::Promote { .. } => "promote",
            Request::Open => "open",
            Request::Result { .. } => "result",
            Request::Effect { .. } => "effect",
            Request::Transcript { .. } => "transcript",
            Request::TurnEnd { .. } => "turn",
            Request::Fork { .. } => "fork",
            Request::Outcome { .. } => "outcome",
            Request::Nominate { .. } => "nominate",
        };
        assert_eq!(
            runs[0].iter().map(tag).collect::<Vec<_>>(),
            ["hello", "promote", "promote", "result", "result"],
            "promoted (c1): no third promotion, nothing after the results"
        );
        assert_eq!(st["promoted_then_exited"], true);
        assert_eq!(st["turns"], json!(null));
        let st = {
            let promoted = st;
            assert_eq!(
                promoted["promotions"],
                json!([
                    {"child": "c2", "refused": "already promoted"},
                    {"child": "c1", "seal": 9, "adopted": [4, 5]},
                ])
            );
            assert_eq!(promoted["adopted_states"], json!(["Pending", "Pending"]));
            plain
        };
        let seen = &runs[1];
        assert_eq!(
            st["effects"],
            json!({"released": 0, "held": 1, "refused": ["quota"]})
        );
        assert_eq!(
            st["forks"],
            json!([{"child": "p-fork-3", "seal": 12}, {"refused": "no fork slot left"}])
        );
        // The order: Hello, the turn, the forks.
        assert_eq!(
            seen.iter().map(tag).collect::<Vec<_>>(),
            [
                "hello",
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
                    | Request::Promote { .. }
                    | Request::Result { .. }
                    | Request::Nominate { .. } => {
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

    /// `--big-file-mib`: the first run makes the file and times nothing;
    /// a run that finds it whole (a fork's child) times one 4 KiB write.
    #[test]
    fn a_big_file_is_made_once_then_its_first_write_is_timed() {
        let dir = tempfile::tempdir().unwrap();
        let o = Opts {
            turns: 1,
            txns: 1,
            rows: 1,
            row_bytes: 8,
            db: dir.path().join("s.db"),
            stats: dir.path().join("x"),
            bare: true,
            big_file_mib: 2,
            first_write_samples: Some(dir.path().join("first")),
            ..Opts::default()
        };
        let made = run(&o, None).unwrap();
        assert_eq!(made["first_write_ms"], json!(null));
        assert_eq!(std::fs::metadata(dir.path().join("big")).unwrap().len(), 2 << 20);
        assert!(!dir.path().join("first").exists());
        let child = run(&o, None).unwrap();
        assert!(child["first_write_ms"].as_f64().unwrap() > 0.0);
        let first = std::fs::read_to_string(dir.path().join("first")).unwrap();
        assert_eq!(first.lines().filter(|l| l.parse::<u64>().is_ok()).count(), 1);
        let big = std::fs::read(dir.path().join("big")).unwrap();
        assert_eq!(big.len(), 2 << 20);
        assert_eq!(&big[1 << 20..(1 << 20) + 4096], &[0xa5u8; 4096][..]);
        assert_eq!(big[0], 0x3c);
    }
}
