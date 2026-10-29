//! `taso-genesis`: make a Template from a tree nobody verified (P4 spec
//! rev. 14 §7; D40, D48; file 4c).
//!
//! ```text
//! taso-genesis <warden-config> --from <source> --classmap <file> --actor <name>
//!              --reason <text> [--best-effort] [--hook-waiver <reason>]
//! taso-genesis <warden-config> --resume <genesis_id>
//! ```
//!
//! Run on a node with that node's Warden config: its storage, store,
//! prefix, coordinator, Warden id, state directory, root dataset and
//! `runtime.host_uid_base` ([`taso_warden::genesis`]).  `<source>` is a
//! Vessel's Seal, `<dataset>@<lsn>`, or an absolute directory (it starts
//! with `/`), which needs `--best-effort`.  `--resume` finishes a genesis
//! whose `GenesisStarted` is accepted, from the log and the store alone
//! (D48), and takes no other option.
//!
//! Running it again with the same inputs resumes it (§7 step 8), on this
//! node or another; a node that is not the holder takes it over (D42).
//!
//! # Output
//!
//! One JSON object on stdout:
//!
//! ```json
//! { "genesis_id": "…32 hex…", "source_key": "…",
//!   "outcome": "ready", "template_id": "…", "layer": "…", "output_manifest_key": "…",
//!   "cleaned": true, "notes": ["…"] }
//! { …, "outcome": "refused", "reason": "SecretPaths", "input_manifest_key": "…" }
//! ```
//!
//! Notes (a takeover, a leftover scratch destroyed, an earlier reason that
//! stands, a resume by id) also go to stderr.
//!
//! # Exit status
//!
//! 0 the Template is ready; 3 the genesis is refused (a recorded outcome,
//! final); 1 the run stopped with an error (rerun to resume); 2 a bad
//! command line or configuration; 9 stopped by a failpoint.
//!
//! # Failpoints (§10.1)
//!
//! `TASO_FAILPOINT=<name>` exits with status 9 at that point, one of the
//! eight `genesis.*` names of §10.2.  `TASO_LOSE_REPLY=<record>` lets the
//! coordinator accept that record (`GenesisStarted`, `GenesisRefused`,
//! `TemplateReady` or `GenesisCleanedUp`) and exits with status 9 before
//! the reply is used: the accept happened, nobody heard of it.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 14, BLAKE3
//! `0d964e34a75a6c46cd3fcac21c752f863b1a6b431f325e1600e6a00cf1d30ba5`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use serde_json::{json, Value};
use taso_core::contract::{ContractRecord, Peer};
use taso_core::coordlog::{
    Answer, ChronicleView, ClaimAuthority, Head, SubmissionStatus, Submitted,
};
use taso_core::envelope::{ChronicleHead, ChronicleId, Envelope, Epoch, HashVal, Lsn};
use taso_core::model::{Ownership, WardenId};
use taso_core::record::Authority;
use taso_warden::classify::{Limits, Reserved};
use taso_warden::coordinator::{Coord, CoordError, Coordinator, LogConfig};
use taso_warden::coordsrv::RemoteCoord;
use taso_warden::coordstore::CoordStore;
use taso_warden::daemon::{refuse_selinux, Config, CoordConf};
use taso_warden::genesis::{Failpoint, Genesis, GenesisError, Outcome, Report, Request, Source};
use taso_warden::segment::Position;
use taso_warden::storage::Dataset;

/// The usage line.
const USAGE: &str = "usage: taso-genesis <warden-config> --from <source> --classmap <file> \
                     --actor <name> --reason <text> [--best-effort] [--hook-waiver <reason>]\n       \
                     taso-genesis <warden-config> --resume <genesis_id>";

/// Exit status of a run a failpoint stopped.
const FAILPOINT_EXIT: i32 = 9;

/// The eight failpoints of §10.2 for a genesis.
const FAILPOINTS: [&str; 8] = [
    "genesis.after_source_put",
    "genesis.before_started_accept",
    "genesis.after_started_accept",
    "genesis.after_materialise",
    "genesis.after_artifact_put",
    "genesis.before_ready_accept",
    "genesis.after_ready_accept",
    "genesis.before_cleanup",
];

/// The records whose accept reply `TASO_LOSE_REPLY` can lose.
const RECORDS: [&str; 4] = [
    "GenesisStarted",
    "GenesisRefused",
    "TemplateReady",
    "GenesisCleanedUp",
];

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match cli::parse(&argv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("taso-genesis: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let failpoint = match std::env::var("TASO_FAILPOINT") {
        Ok(p) if !FAILPOINTS.contains(&p.as_str()) => {
            eprintln!(
                "taso-genesis: TASO_FAILPOINT={p:?} is not one of {}",
                FAILPOINTS.join(", ")
            );
            return ExitCode::from(2);
        }
        Ok(p) => Some(p),
        Err(_) => None,
    };
    let lose_reply = match std::env::var("TASO_LOSE_REPLY") {
        Ok(r) if !RECORDS.contains(&r.as_str()) => {
            eprintln!(
                "taso-genesis: TASO_LOSE_REPLY={r:?} is not one of {}",
                RECORDS.join(", ")
            );
            return ExitCode::from(2);
        }
        Ok(r) => Some(r),
        Err(_) => None,
    };
    let config = match std::fs::read_to_string(&cmd.config)
        .map_err(|e| e.to_string())
        .and_then(|t| Config::parse(&t).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("taso-genesis: {}: {e}", cmd.config);
            return ExitCode::from(2);
        }
    };
    // What the Warden refuses, a genesis refuses too (D32).
    if let Err(e) = refuse_selinux(Path::new("/sys")) {
        eprintln!("taso-genesis: {e}");
        return ExitCode::FAILURE;
    }

    let genesis = match build(&config, failpoint, lose_reply) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("taso-genesis: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = match &cmd.what {
        cli::What::Run(r) => match load_request(r) {
            Ok(req) => genesis.run(&req),
            Err(e) => {
                eprintln!("taso-genesis: {e}");
                return ExitCode::from(2);
            }
        },
        cli::What::Resume(id) => genesis.resume(*id),
    };
    match result {
        Ok(report) => {
            for n in &report.notes {
                eprintln!("taso-genesis: {n}");
            }
            println!("{}", report_json(&report));
            match report.outcome {
                Outcome::Ready { .. } => ExitCode::SUCCESS,
                Outcome::Refused { .. } => ExitCode::from(3),
            }
        }
        Err(GenesisError::Failpoint(p)) => {
            eprintln!("taso-genesis: stopped at failpoint {p}");
            ExitCode::from(FAILPOINT_EXIT as u8)
        }
        Err(e) => {
            eprintln!("taso-genesis: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The genesis of this node, from its Warden config.
fn build(
    config: &Config,
    failpoint: Option<String>,
    lose_reply: Option<String>,
) -> Result<Genesis<taso_warden::storage::Storage>, String> {
    let store = config
        .store
        .open()
        .map_err(|e| format!("opening the store: {e}"))?;
    let coord: Arc<dyn Coord> = match &config.coordinator {
        // The Warden's own coordinator file: only while its daemon is not
        // running (redb locks the file).  The log reads the store, as
        // taso-coordd's does with --store-config.
        CoordConf::Local { path, .. } => Arc::new(
            Coordinator::open_with(
                path,
                LogConfig {
                    store: Arc::new(CoordStore::new(store.clone(), &config.prefix)),
                    ..LogConfig::default()
                },
            )
            .map_err(|e| format!("coordinator {}: {e}", path.display()))?,
        ),
        CoordConf::Remote { socket } => Arc::new(RemoteCoord::new(socket)),
    };
    let coord: Arc<dyn Coord> = match lose_reply {
        Some(record) => Arc::new(LoseReply {
            inner: coord,
            record,
        }),
        None => coord,
    };
    let failpoint: Failpoint = match failpoint {
        Some(name) => Box::new(move |p| {
            if p == name {
                Err(GenesisError::Failpoint(p))
            } else {
                Ok(())
            }
        }),
        None => taso_warden::genesis::no_failpoints(),
    };
    Ok(Genesis {
        pool: config.storage.open(false),
        store,
        prefix: config.prefix.clone(),
        coord,
        warden: config.warden,
        state_dir: config.state_dir.clone(),
        root: config.root.clone(),
        host_uid_base: config.runtime.host_uid_base,
        limits: Limits::default(),
        reserved: Reserved::defaults(),
        failpoint,
    })
}

/// The request, with the map read from its file.
fn load_request(r: &cli::RunArgs) -> Result<Request, String> {
    let classmap =
        std::fs::read(&r.classmap).map_err(|e| format!("{}: {e}", r.classmap.display()))?;
    Ok(Request {
        source: r.source.clone(),
        classmap,
        authority: Authority {
            actor: r.actor.clone(),
            reason: r.reason.clone(),
        },
        hook_waiver: r.hook_waiver.clone(),
        best_effort: r.best_effort,
        peer: Peer {
            uid: rustix::process::getuid().as_raw(),
            pid: std::process::id(),
        },
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn report_json(r: &Report) -> Value {
    let mut v = json!({
        "genesis_id": hex(r.genesis_id.as_bytes()),
        "source_key": hex(r.source_key.as_bytes()),
        "cleaned": r.cleaned,
        "notes": r.notes,
    });
    let o = v.as_object_mut().expect("an object");
    match &r.outcome {
        Outcome::Ready {
            template_id,
            layer,
            output_manifest_key,
        } => {
            o.insert("outcome".into(), "ready".into());
            o.insert("template_id".into(), hex(template_id.as_bytes()).into());
            o.insert("layer".into(), hex(layer.as_bytes()).into());
            o.insert(
                "output_manifest_key".into(),
                hex(output_manifest_key.as_bytes()).into(),
            );
        }
        Outcome::Refused {
            reason,
            input_manifest_key,
            ..
        } => {
            o.insert("outcome".into(), "refused".into());
            o.insert("reason".into(), format!("{reason:?}").into());
            o.insert(
                "input_manifest_key".into(),
                input_manifest_key.map_or(Value::Null, |k| hex(k.as_bytes()).into()),
            );
        }
    }
    v
}

// ── TASO_LOSE_REPLY ─────────────────────────────────────────────────

/// A coordinator whose reply to the accept of one record kind is lost:
/// the accept is made, then the process exits (§10.1, lost reply).
struct LoseReply {
    inner: Arc<dyn Coord>,
    record: String,
}

fn record_kind(r: &Submitted) -> &'static str {
    match r {
        Submitted::Contract(ContractRecord::GenesisStarted(_)) => "GenesisStarted",
        Submitted::Contract(ContractRecord::GenesisRefused(_)) => "GenesisRefused",
        Submitted::Contract(ContractRecord::TemplateReady(_)) => "TemplateReady",
        Submitted::Contract(ContractRecord::GenesisCleanedUp(_)) => "GenesisCleanedUp",
        _ => "other",
    }
}

impl Coord for LoseReply {
    fn register(&self, c: ChronicleId, w: WardenId) -> Result<ChronicleHead, CoordError> {
        self.inner.register(c, w)
    }
    fn append(&self, w: WardenId, e: &Envelope) -> Result<ChronicleHead, CoordError> {
        self.inner.append(w, e)
    }
    fn append_batch_with(
        &self,
        w: WardenId,
        e: &[Envelope],
        x: &[Vec<u8>],
    ) -> Result<ChronicleHead, CoordError> {
        self.inner.append_batch_with(w, e, x)
    }
    fn transfer_if(
        &self,
        c: ChronicleId,
        w: WardenId,
        x: (WardenId, Epoch),
    ) -> Result<Epoch, CoordError> {
        self.inner.transfer_if(c, w, x)
    }
    fn transfer(&self, c: ChronicleId, w: WardenId) -> Result<Epoch, CoordError> {
        self.inner.transfer(c, w)
    }
    fn ownership(&self, c: ChronicleId) -> Result<Ownership, CoordError> {
        self.inner.ownership(c)
    }
    fn head(&self, c: ChronicleId) -> Result<ChronicleHead, CoordError> {
        self.inner.head(c)
    }
    fn advance_shipped(
        &self,
        w: WardenId,
        c: ChronicleId,
        e: Epoch,
        to: Position,
    ) -> Result<Position, CoordError> {
        self.inner.advance_shipped(w, c, e, to)
    }
    fn shipped(&self, c: ChronicleId) -> Result<Position, CoordError> {
        self.inner.shipped(c)
    }
    fn claim_chronicle(
        &self,
        id: ChronicleId,
        w: WardenId,
        a: ClaimAuthority,
    ) -> Result<Epoch, CoordError> {
        self.inner.claim_chronicle(id, w, a)
    }
    fn takeover_target(
        &self,
        id: ChronicleId,
        w: WardenId,
        a: ClaimAuthority,
        e: Epoch,
    ) -> Result<(Epoch, Head), CoordError> {
        self.inner.takeover_target(id, w, a, e)
    }
    fn announce(
        &self,
        w: WardenId,
        c: ChronicleId,
        e: Epoch,
        s: HashVal,
        l: HashVal,
        d: HashVal,
    ) -> Result<Result<(), Answer>, CoordError> {
        self.inner.announce(w, c, e, s, l, d)
    }
    fn accept(
        &self,
        w: WardenId,
        c: ChronicleId,
        e: Epoch,
        s: HashVal,
        h: Head,
        p: String,
        r: Submitted,
    ) -> Result<Answer, CoordError> {
        let lose = record_kind(&r) == self.record;
        let a = self.inner.accept(w, c, e, s, h, p, r)?;
        if lose {
            eprintln!(
                "taso-genesis: TASO_LOSE_REPLY: the accept of {} answered {a:?}; exiting before it is used",
                self.record
            );
            std::process::exit(FAILPOINT_EXIT);
        }
        Ok(a)
    }
    fn cancel(
        &self,
        w: WardenId,
        c: ChronicleId,
        e: Epoch,
        s: HashVal,
    ) -> Result<Answer, CoordError> {
        self.inner.cancel(w, c, e, s)
    }
    fn query_submission(&self, c: ChronicleId, s: HashVal) -> Result<SubmissionStatus, CoordError> {
        self.inner.query_submission(c, s)
    }
    fn query_logical(&self, l: HashVal) -> Result<Option<(u64, Submitted)>, CoordError> {
        self.inner.query_logical(l)
    }
    fn query_chronicle(&self, c: ChronicleId) -> Result<Option<ChronicleView>, CoordError> {
        self.inner.query_chronicle(c)
    }
    fn obligations(&self, c: ChronicleId) -> Result<Vec<u64>, CoordError> {
        self.inner.obligations(c)
    }
}

// ── The command line ────────────────────────────────────────────────

mod cli {
    use super::*;

    /// A parsed command line.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Cmd {
        /// The Warden config file.
        pub config: String,
        /// What to do.
        pub what: What,
    }

    /// A genesis, or a resume.
    #[derive(Debug, PartialEq, Eq)]
    pub enum What {
        /// `--from …`.
        Run(RunArgs),
        /// `--resume <genesis_id>` (D48).
        Resume(ChronicleId),
    }

    /// The options of a genesis.
    #[derive(Debug, PartialEq, Eq)]
    pub struct RunArgs {
        pub source: Source,
        pub classmap: PathBuf,
        pub actor: String,
        pub reason: String,
        pub best_effort: bool,
        pub hook_waiver: Option<String>,
    }

    /// `<dataset>@<lsn>`, or an absolute directory.
    pub fn source(s: &str) -> Result<Source, String> {
        if s.starts_with('/') {
            return Ok(Source::Dir(PathBuf::from(s)));
        }
        let bad = || format!("--from {s:?}: neither <dataset>@<lsn> nor an absolute directory");
        let (ds, lsn) = s.split_once('@').ok_or_else(bad)?;
        if lsn.is_empty() || !lsn.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let lsn: u64 = lsn.parse().map_err(|_| bad())?;
        if lsn == 0 {
            return Err(format!("--from {s:?}: a Seal's lsn is at least 1"));
        }
        let dataset = Dataset::new(ds).map_err(|e| format!("--from {s:?}: {e}"))?;
        Ok(Source::Seal {
            dataset,
            lsn: Lsn::new(lsn),
        })
    }

    /// A genesis id: 32 lowercase hex digits.
    pub fn genesis_id(s: &str) -> Result<ChronicleId, String> {
        let bad = || format!("--resume {s:?}: not 32 lowercase hex digits");
        if s.len() != 32
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(bad());
        }
        let mut b = [0u8; 16];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
        }
        Ok(ChronicleId::from_bytes(b))
    }

    pub fn parse(argv: &[String]) -> Result<Cmd, String> {
        let mut it = argv.iter();
        let config = it
            .next()
            .filter(|c| !c.starts_with("--"))
            .ok_or("the Warden config comes first")?
            .clone();
        let mut from = None;
        let mut classmap = None;
        let mut actor = None;
        let mut reason = None;
        let mut best_effort = false;
        let mut hook_waiver = None;
        let mut resume = None;
        let mut seen = std::collections::BTreeSet::new();
        while let Some(flag) = it.next() {
            if !seen.insert(flag.clone()) {
                return Err(format!("{flag} given twice"));
            }
            let mut value = || {
                it.next()
                    .cloned()
                    .ok_or_else(|| format!("{flag} needs a value"))
            };
            match flag.as_str() {
                "--from" => from = Some(source(&value()?)?),
                "--classmap" => classmap = Some(PathBuf::from(value()?)),
                "--actor" => actor = Some(value()?),
                "--reason" => reason = Some(value()?),
                "--hook-waiver" => hook_waiver = Some(value()?),
                "--best-effort" => best_effort = true,
                "--resume" => resume = Some(genesis_id(&value()?)?),
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        let nonempty = |name: &str, v: Option<String>| -> Result<String, String> {
            match v {
                Some(s) if !s.trim().is_empty() => Ok(s),
                Some(_) => Err(format!("{name} is empty")),
                None => Err(format!("{name} is required")),
            }
        };
        if let Some(id) = resume {
            if seen.len() > 1 {
                return Err("--resume takes no other option (D48)".into());
            }
            return Ok(Cmd {
                config,
                what: What::Resume(id),
            });
        }
        if let Some(w) = &hook_waiver {
            if w.trim().is_empty() {
                return Err("--hook-waiver is empty".into());
            }
        }
        Ok(Cmd {
            config,
            what: What::Run(RunArgs {
                source: from.ok_or("--from or --resume is required")?,
                classmap: classmap.ok_or("--classmap is required")?,
                actor: nonempty("--actor", actor)?,
                reason: nonempty("--reason", reason)?,
                best_effort,
                hook_waiver,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::cli::*;
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn a_seal_source_and_every_option() {
        let c = parse(&args(&[
            "/etc/taso/warden.json",
            "--from",
            "tank/taso/v-00ff@12",
            "--classmap",
            "/etc/taso/map.toml",
            "--actor",
            "jarmo",
            "--reason",
            "T(0)",
            "--hook-waiver",
            "reviewed",
        ]))
        .unwrap();
        assert_eq!(c.config, "/etc/taso/warden.json");
        let What::Run(r) = c.what else { panic!() };
        assert_eq!(
            r.source,
            Source::Seal {
                dataset: Dataset::new("tank/taso/v-00ff").unwrap(),
                lsn: Lsn::new(12)
            }
        );
        assert_eq!(r.classmap, PathBuf::from("/etc/taso/map.toml"));
        assert_eq!((r.actor.as_str(), r.reason.as_str()), ("jarmo", "T(0)"));
        assert_eq!(r.hook_waiver.as_deref(), Some("reviewed"));
        assert!(!r.best_effort);
    }

    #[test]
    fn a_directory_source() {
        let c = parse(&args(&[
            "w.json",
            "--from",
            "/srv/t0",
            "--classmap",
            "m",
            "--actor",
            "a",
            "--reason",
            "r",
            "--best-effort",
        ]))
        .unwrap();
        let What::Run(r) = c.what else { panic!() };
        assert_eq!(r.source, Source::Dir(PathBuf::from("/srv/t0")));
        assert!(r.best_effort);
    }

    #[test]
    fn resume_takes_an_id_and_nothing_else() {
        let id = "00112233445566778899aabbccddeeff";
        let c = parse(&args(&["w.json", "--resume", id])).unwrap();
        assert_eq!(
            c.what,
            What::Resume(ChronicleId::from_bytes([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]))
        );
        assert!(parse(&args(&["w.json", "--resume", id, "--actor", "a"])).is_err());
        for bad in [
            "00112233445566778899AABBCCDDEEFF",
            "0011",
            "00112233445566778899aabbccddeefg",
        ] {
            assert!(parse(&args(&["w.json", "--resume", bad])).is_err(), "{bad}");
        }
    }

    #[test]
    fn bad_command_lines_are_refused() {
        let ok = [
            "w.json",
            "--from",
            "/d",
            "--classmap",
            "m",
            "--actor",
            "a",
            "--reason",
            "r",
        ];
        assert!(parse(&args(&ok)).is_ok());
        let cases: &[&[&str]] = &[
            &[],
            &["--from", "/d"],
            &["w.json"],
            &["w.json", "--from", "/d", "--classmap", "m", "--actor", "a"],
            &[
                "w.json",
                "--from",
                "/d",
                "--classmap",
                "m",
                "--actor",
                " ",
                "--reason",
                "r",
            ],
            &[
                "w.json",
                "--from",
                "/d",
                "--from",
                "/e",
                "--classmap",
                "m",
                "--actor",
                "a",
                "--reason",
                "r",
            ],
            &[
                "w.json",
                "--from",
                "/d",
                "--classmap",
                "m",
                "--actor",
                "a",
                "--reason",
                "r",
                "--extra",
            ],
            &[
                "w.json",
                "--from",
                "/d",
                "--classmap",
                "m",
                "--actor",
                "a",
                "--reason",
                "r",
                "--hook-waiver",
                "",
            ],
            &["w.json", "--from", "/d", "--classmap"],
        ];
        for c in cases {
            assert!(parse(&args(c)).is_err(), "{c:?}");
        }
        for bad in [
            "tank/v@",
            "tank/v@x",
            "tank/v",
            "relative/dir",
            "tank/v@0",
            "/@1x",
        ] {
            if bad.starts_with('/') {
                continue; // any absolute path is a directory
            }
            assert!(source(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_report_is_json_with_hex_ids() {
        let r = Report {
            genesis_id: ChronicleId::from_bytes([1; 16]),
            source_key: HashVal::from_bytes([2; 32]),
            outcome: Outcome::Refused {
                genesis_id: ChronicleId::from_bytes([1; 16]),
                reason: taso_core::contract::WalkRefusal::SecretPaths,
                input_manifest_key: Some(HashVal::from_bytes([3; 32])),
            },
            cleaned: false,
            notes: vec!["n".into()],
        };
        let v = report_json(&r);
        assert_eq!(v["genesis_id"], "01".repeat(16));
        assert_eq!(v["outcome"], "refused");
        assert_eq!(v["reason"], "SecretPaths");
        assert_eq!(v["input_manifest_key"], "03".repeat(32));
        assert_eq!(v["cleaned"], false);
    }
}
