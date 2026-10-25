//! `taso-decide`: a caller of the decider socket (P4 spec rev. 21 §5.1,
//! D72, D73, D77; file 8c).
//!
//! ```text
//! taso-decide <warden-config> pending
//! taso-decide <warden-config> verdict <candidate_id> <attempt_id> sanction|hold|never
//!             --actor <name> --reason <text> [--never <why>] [--facts-hash <hex>]
//! taso-decide <warden-config> resend <request hex>
//! ```
//!
//! The socket is the config's `decider.socket`; the peer is this process
//! (its uid and pid), so run it as the user who decides. `verdict` binds
//! the request to what `pending` shows of that Candidate and attempt
//! (`facts_hash`, `artifact_key`, `requirement`, `exclude`,
//! `result_digest`); `--facts-hash` replaces the bound facts (a stale
//! request, for tests). `never` needs `--never <why>`. `resend` sends the
//! exact request a `verdict` printed (`"request"`), as a retry does: the
//! same `request_id`.
//!
//! # Output
//!
//! One JSON object on stdout:
//!
//! ```json
//! {"pending": [{"candidate_id": "…", "chronicle": "…", "facts_hash": "…",
//!   "attempts": [{"attempt_id": "…", "outcome": "Exit { code: 0 }", "result_digest": "…"}]}]}
//! {"answer": "Committed", "template_id": "…", "request_id": "…", "request": "…"}
//! {"answer": "NotCommitted", "rule": "OpenAttempt", "request_id": "…", "request": "…"}
//! {"error": "…"}
//! ```
//!
//! # Exit status
//!
//! 0 answered; 1 an `Error` reply or no connection; 2 a bad command line or
//! configuration; 3 the Candidate or attempt is not pending here.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 21, BLAKE3
//! `9f602ee814d9e785a7f1dd1012320ef068a100e36a71602d49b07c5990260205`.

use std::process::ExitCode;

use serde_json::{json, Value};
use taso_core::contract::{request_id, Decision, OpKind, VerdictRequest};
use taso_core::decider::{PendingItem, Reply, Request, VerdictAnswer};
use taso_core::envelope::HashVal;
use taso_core::record::Authority;
use taso_warden::daemon::Config;
use taso_warden::decidesrv::DeciderClient;

const USAGE: &str = "usage: taso-decide <warden-config> pending\n       \
    taso-decide <warden-config> verdict <candidate_id> <attempt_id> sanction|hold|never \
    --actor <name> --reason <text> [--never <why>] [--facts-hash <hex>]\n       \
    taso-decide <warden-config> resend <request hex>";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn hash(s: &str) -> Option<HashVal> {
    let b: [u8; 32] = unhex(s)?.try_into().ok()?;
    Some(HashVal::from_bytes(b))
}

fn usage(why: &str) -> ExitCode {
    eprintln!("taso-decide: {why}\n{USAGE}");
    ExitCode::from(2)
}

fn print(v: Value) {
    println!("{v}");
}

fn item_json(i: &PendingItem) -> Value {
    json!({
        "candidate_id": i.candidate.candidate_id.to_string(),
        "chronicle": hex(i.candidate.chronicle.as_bytes()),
        "facts_hash": i.candidate.facts_hash.to_string(),
        "artifact_key": i.candidate.artifact_key.to_string(),
        "attempts": i.attempts.iter().map(|(s, f)| json!({
            "attempt_id": s.attempt_id.to_string(),
            "started_at": s.started_at.get(),
            "outcome": format!("{:?}", f.outcome),
            "result_digest": f.result_digest.to_string(),
        })).collect::<Vec<_>>(),
    })
}

fn answer_json(a: &VerdictAnswer, r: &VerdictRequest) -> Value {
    let mut v = match a {
        VerdictAnswer::Committed { template_id } => {
            json!({"answer": "Committed", "template_id": hex(template_id.as_bytes())})
        }
        VerdictAnswer::Held => json!({"answer": "Held"}),
        VerdictAnswer::ClosedNever => json!({"answer": "ClosedNever"}),
        VerdictAnswer::Refused(rule) => json!({"answer": "Refused", "rule": format!("{rule:?}")}),
        VerdictAnswer::NotCommitted(rule) => {
            json!({"answer": "NotCommitted", "rule": format!("{rule:?}")})
        }
        VerdictAnswer::NotClosed(rule) => {
            json!({"answer": "NotClosed", "rule": format!("{rule:?}")})
        }
        VerdictAnswer::Pending(why) => json!({"answer": "Pending", "why": why}),
        VerdictAnswer::NotHere(why) => json!({"answer": "NotHere", "why": why}),
    };
    v["request_id"] = json!(r.request_id.to_string());
    v["request"] = json!(hex(&Request::Verdict {
        request: Box::new(r.clone())
    }
    .encode()));
    v
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        return usage("a config and a command are needed");
    }
    let config = match std::fs::read_to_string(&args[0])
        .map_err(|e| e.to_string())
        .and_then(|t| Config::parse(&t).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => return usage(&format!("{}: {e}", args[0])),
    };
    let rest = &args[2..];
    // What to send, checked before connecting.
    enum Ask {
        Pending,
        Verdict {
            cid: HashVal,
            attempt: HashVal,
            decision: Decision,
            authority: Authority,
            facts: Option<HashVal>,
        },
        Resend(Box<VerdictRequest>),
    }
    let ask = match args[1].as_str() {
        "pending" if rest.is_empty() => Ask::Pending,
        "verdict" => {
            if rest.len() < 3 {
                return usage("verdict needs a candidate, an attempt and a decision");
            }
            let (Some(cid), Some(attempt)) = (hash(&rest[0]), hash(&rest[1])) else {
                return usage("a candidate_id and an attempt_id are 64 hex digits");
            };
            let (mut actor, mut reason, mut never, mut facts) = (None, None, None, None);
            let mut it = rest[3..].iter();
            while let Some(flag) = it.next() {
                let Some(val) = it.next() else {
                    return usage(&format!("{flag} needs a value"));
                };
                match flag.as_str() {
                    "--actor" => actor = Some(val.clone()),
                    "--reason" => reason = Some(val.clone()),
                    "--never" => never = Some(val.clone()),
                    "--facts-hash" => match hash(val) {
                        Some(h) => facts = Some(h),
                        None => return usage("--facts-hash is 64 hex digits"),
                    },
                    _ => return usage(&format!("unknown option {flag}")),
                }
            }
            let decision = match (rest[2].as_str(), never) {
                ("sanction", None) => Decision::Sanction,
                ("hold", None) => Decision::Hold,
                ("never", Some(reason)) => Decision::Never { reason },
                ("never", None) => return usage("never needs --never <why>"),
                (_, Some(_)) => return usage("--never goes with never"),
                (d, _) => return usage(&format!("{d:?} is not sanction, hold or never")),
            };
            let (Some(actor), Some(reason)) = (actor, reason) else {
                return usage("--actor and --reason are needed");
            };
            Ask::Verdict {
                cid,
                attempt,
                decision,
                authority: Authority { actor, reason },
                facts,
            }
        }
        "resend" if rest.len() == 1 => {
            match unhex(&rest[0]).and_then(|b| Request::decode(&b).ok()) {
                Some(Request::Verdict { request }) => Ask::Resend(request),
                _ => return usage("resend takes the \"request\" a verdict printed"),
            }
        }
        _ => return usage("unknown command or arguments"),
    };
    let mut c = match DeciderClient::connect(&config.decider.socket) {
        Ok(c) => c,
        Err(e) => {
            print(json!({"error": format!("{}: {e}", config.decider.socket.display())}));
            return ExitCode::from(1);
        }
    };
    let call = |c: &mut DeciderClient, r: &Request| match c.call(r) {
        Ok(Reply::Error { message }) => Err(message),
        Ok(r) => Ok(r),
        Err(e) => Err(e.to_string()),
    };
    let request = match ask {
        Ask::Pending => {
            return match call(&mut c, &Request::Pending) {
                Ok(Reply::Pending { items }) => {
                    print(json!({"pending": items.iter().map(item_json).collect::<Vec<_>>()}));
                    ExitCode::SUCCESS
                }
                Ok(other) => {
                    print(json!({"error": format!("unexpected reply {other:?}")}));
                    ExitCode::from(1)
                }
                Err(e) => {
                    print(json!({"error": e}));
                    ExitCode::from(1)
                }
            }
        }
        Ask::Resend(r) => *r,
        Ask::Verdict {
            cid,
            attempt,
            decision,
            authority,
            facts,
        } => {
            let items = match call(&mut c, &Request::Pending) {
                Ok(Reply::Pending { items }) => items,
                Ok(other) => {
                    print(json!({"error": format!("unexpected reply {other:?}")}));
                    return ExitCode::from(1);
                }
                Err(e) => {
                    print(json!({"error": e}));
                    return ExitCode::from(1);
                }
            };
            let Some(item) = items.iter().find(|i| i.candidate.candidate_id == cid) else {
                print(json!({"error": format!("Candidate {cid} is not pending here")}));
                return ExitCode::from(3);
            };
            let Some((_, f)) = item.attempts.iter().find(|(s, _)| s.attempt_id == attempt) else {
                print(
                    json!({"error": format!("attempt {attempt} of Candidate {cid} is not finished here")}),
                );
                return ExitCode::from(3);
            };
            let k = &item.candidate;
            let mut r = VerdictRequest {
                request_id: HashVal::from_bytes([0; 32]),
                candidate_id: cid,
                facts_hash: facts.unwrap_or(k.facts_hash),
                artifact_key: k.artifact_key,
                requirement: k.requirement,
                exclude: k.exclude.clone(),
                attempt_id: attempt,
                result_digest: f.result_digest,
                decision,
                authority,
                policy_digest: None,
            };
            r.request_id = request_id(
                rustix::process::getuid().as_raw(),
                OpKind::Verdict,
                &r.body(),
            );
            r
        }
    };
    match call(
        &mut c,
        &Request::Verdict {
            request: Box::new(request.clone()),
        },
    ) {
        Ok(Reply::Verdict { answer }) => {
            print(answer_json(&answer, &request));
            ExitCode::SUCCESS
        }
        Ok(other) => {
            print(json!({"error": format!("unexpected reply {other:?}")}));
            ExitCode::from(1)
        }
        Err(e) => {
            print(json!({"error": e}));
            ExitCode::from(1)
        }
    }
}
