//! `taso-logcheck <coordinator socket> <state dir> <vessel id, hex>`
//!
//! Prints one Vessel's Chronicle and what the coordinator holds for it,
//! as JSON, for the gate harness to judge.  Read-only: the segment files
//! are opened for reading (a torn tail is ignored, never cut) and the
//! coordinator is only asked.  Nothing here decides pass or fail.
//!
//! ```json
//! { "ownership": { "epoch": 4, "holder": 2,
//!                  "sealed_prefix": { "lsn": 69, "hash": "…" } },
//!   "head": { "lsn": 75, "hash": "…" },
//!   "shipped": { "lsn": 75, "hash": "…" },
//!   "frames": [ { "lsn": 1, "epoch": 1, "stream": "ctl", "hash": "…",
//!                 "prev": "…", "kind": "lineage" },
//!               { …, "kind": "gap", "kept": 67, "kept_hash": "…",
//!                 "resumes": 69, "resumes_hash": "…" },
//!               { …, "kind": "seal", "turn": 6,
//!                 "verdict": "unverified", "reason": "reborn: …" } ],
//!   "coordlog": { "accepted": 1, "holds": ["content:…", "pack:…"],
//!                 "retired": false, "birth": "accepted" } }
//! ```
//!
//! A Lineage frame names its `origin` (`void`, `fork`, `succession`,
//! `template`; a Template origin with its `template_id`, `layer_key` and
//! `asked`); an `fs_shipped` frame its `base` (`full`, `seal`, `origin`
//! with `base_chronicle`, `base_seal`, `base_hash`).  `coordlog` is the
//! coordinator log's view of the Chronicle (`null` if it does not know
//! it): how many of its records are accepted, the objects it holds,
//! whether its purge is committed (`retired`, P4 file 11), and
//! for a Lineage at lsn 1 whether its `Birth` is accepted (`accepted`,
//! `none`, or `other` for another record under its logical id; absent
//! for a Chronicle without a Lineage).  P4 file 5h.

use std::path::Path;
use std::process::ExitCode;

use serde_json::{json, Value};
use taso_core::coordlog::{ObjectId, Submitted};
use taso_core::envelope::{ChronicleId, HashVal, Stream};
use taso_core::record::{Origin, Payload, StreamBase, Verdict};
use taso_warden::chronicle::read_log;
use taso_warden::coordinator::Coord;
use taso_warden::coordsrv::RemoteCoord;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [sock, state_dir, id_hex] = args.as_slice() else {
        eprintln!("usage: taso-logcheck <coordinator socket> <state dir> <vessel id, hex>");
        return ExitCode::from(2);
    };
    match run(sock, Path::new(state_dir), id_hex) {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("taso-logcheck: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(sock: &str, state_dir: &Path, id_hex: &str) -> Result<Value, String> {
    let id = parse_id(id_hex)?;
    let coord = RemoteCoord::new(sock);
    let own = coord.ownership(id).map_err(|e| format!("ownership: {e}"))?;
    let head = coord.head(id).map_err(|e| format!("head: {e}"))?;
    let shipped = coord.shipped(id).map_err(|e| format!("shipped: {e}"))?;
    let dir = state_dir.join(id_hex);
    let frames = read_log(&dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
    let lineage = frames
        .first()
        .and_then(|f| match Payload::decode(&f.payload) {
            Ok(Payload::Lineage(l)) => Some(l),
            _ => None,
        });
    let coordlog = match coord
        .query_chronicle(id)
        .map_err(|e| format!("query chronicle: {e}"))?
    {
        None => Value::Null,
        Some(view) => {
            let holds: Vec<String> = view
                .holds
                .iter()
                .map(|o| match o {
                    ObjectId::Content(k) => format!("content:{}", HashVal::from_bytes(*k)),
                    ObjectId::Pack(_, name) => format!("pack:{name}"),
                })
                .collect();
            let mut v = json!({
                "accepted": view.accepted.len(),
                "holds": holds,
                "retired": view.retired,
            });
            if let Some(l) = &lineage {
                let birth = Submitted::Birth {
                    chronicle: id,
                    lineage: l.clone(),
                };
                let state = match coord
                    .query_logical(birth.logical_id())
                    .map_err(|e| format!("query logical: {e}"))?
                {
                    None => "none",
                    Some((_, r)) if r.digest() == birth.digest() => "accepted",
                    Some(_) => "other",
                };
                v["birth"] = json!(state);
            }
            v
        }
    };
    let frames: Vec<Value> = frames
        .iter()
        .map(|f| {
            let e = &f.envelope;
            let mut v = json!({
                "lsn": e.lsn.get(),
                "epoch": e.epoch.get(),
                "stream": stream(e.stream),
                "hash": e.hash.to_string(),
                "prev": e.prev.to_string(),
            });
            describe(&mut v, Payload::decode(&f.payload).ok());
            v
        })
        .collect();
    Ok(json!({
        "ownership": {
            "epoch": own.epoch.get(),
            "holder": own.holder.get(),
            "sealed_prefix": { "lsn": own.sealed_prefix.lsn.get(), "hash": own.sealed_prefix.hash.to_string() },
        },
        "head": { "lsn": head.lsn.get(), "hash": head.hash.to_string() },
        "shipped": { "lsn": shipped.lsn.get(), "hash": shipped.hash.to_string() },
        "frames": frames,
        "coordlog": coordlog,
    }))
}

fn describe(v: &mut Value, payload: Option<Payload>) {
    let o = v.as_object_mut().expect("an object");
    let kind = match payload {
        None => "undecodable",
        Some(Payload::Gap(g)) => {
            o.insert("kept".into(), json!(g.kept.get()));
            o.insert("kept_hash".into(), json!(g.kept_hash.to_string()));
            o.insert("resumes".into(), json!(g.resumes.get()));
            o.insert("resumes_hash".into(), json!(g.resumes_hash.to_string()));
            "gap"
        }
        Some(Payload::Seal(s)) => {
            o.insert("turn".into(), json!(s.turn.get()));
            let (verdict, reason) = match &s.verdict {
                Verdict::Clean => ("clean", String::new()),
                Verdict::Unverified(why) => ("unverified", why.clone()),
                Verdict::Tainted(k) => ("tainted", format!("{k:?}")),
            };
            o.insert("verdict".into(), json!(verdict));
            o.insert("reason".into(), json!(reason));
            "seal"
        }
        Some(Payload::Lineage(l)) => {
            let origin = match &l.origin {
                Origin::Void => "void",
                Origin::Fork { .. } => "fork",
                Origin::Succession { .. } => "succession",
                Origin::Template {
                    template_id,
                    layer_key,
                    asked,
                } => {
                    o.insert("template_id".into(), json!(hex(template_id.as_bytes())));
                    o.insert("layer_key".into(), json!(layer_key.to_string()));
                    o.insert(
                        "asked".into(),
                        json!(asked.as_ref().map(|a| format!("{}@{}", a.name, a.version))),
                    );
                    "template"
                }
            };
            o.insert("origin".into(), json!(origin));
            "lineage"
        }
        Some(Payload::Succession(_)) => "succession",
        Some(Payload::FsShipped(r)) => {
            let base = match &r.base {
                StreamBase::Full => "full",
                StreamBase::Seal { .. } => "seal",
                StreamBase::Origin { parent, .. } => {
                    o.insert(
                        "base_chronicle".into(),
                        json!(hex(parent.chronicle.as_bytes())),
                    );
                    o.insert("base_seal".into(), json!(parent.seal.get()));
                    o.insert("base_hash".into(), json!(parent.seal_hash.to_string()));
                    "origin"
                }
            };
            o.insert("base".into(), json!(base));
            "fs_shipped"
        }
        Some(Payload::Checkpoint(_)) => "checkpoint",
        Some(Payload::Contract(r)) => {
            o.insert("logical_id".into(), json!(r.logical_id().to_string()));
            o.insert("digest".into(), json!(r.digest().to_string()));
            "contract"
        }
        Some(Payload::Promotion(p)) => {
            let child: String = p
                .child
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            o.insert("child".into(), json!(child));
            o.insert("seal".into(), json!(p.seal.get()));
            o.insert("seal_hash".into(), json!(p.seal_hash.to_string()));
            o.insert("ledger_pos".into(), json!(p.ledger_pos.get()));
            "promotion"
        }
        Some(Payload::Group(_)) => "group",
        Some(Payload::Intent(_)) => "intent",
        Some(Payload::Outcome(_)) => "outcome",
        Some(Payload::Raw(_)) => "raw",
    };
    o.insert("kind".into(), json!(kind));
}

fn stream(s: Stream) -> &'static str {
    match s {
        Stream::Fs => "fs",
        Stream::Db => "db",
        Stream::Transcript => "transcript",
        Stream::Effect => "effect",
        Stream::Ctl => "ctl",
    }
}

fn parse_id(hex: &str) -> Result<ChronicleId, String> {
    let bad = || format!("{hex:?} is not a 32-digit hex vessel id");
    if hex.len() != 32 {
        return Err(bad());
    }
    let mut b = [0u8; 16];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(ChronicleId::from_bytes(b))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
