//! `taso-policy`: the default caller of the decider socket (P4 spec rev. 24
//! §5.4, D1, D2, D80; file 10).
//!
//! ```text
//! taso-policy <warden-config> <policy.toml> [--once] [--dry-run] [--interval-secs <n>]
//! ```
//!
//! Each pass lists the pending Candidates (`Pending`, D73), decides each
//! on its newest finished attempt by the policy ([`taso_warden::policy`]),
//! and sends that verdict: `authority = { actor: <policy actor>, reason:
//! "rule <name>" | "default" }`, `policy_digest` = the policy file's
//! BLAKE3.  The same facts and policy make the same request, so a
//! Candidate still pending at the next pass (a `Hold`, a `Retry`)
//! is answered from the log, not recorded again.  Without `--once` it
//! passes every `--interval-secs` (default 10) until killed; a pass that
//! cannot reach the socket is logged and the next one tries again.
//! `--dry-run` decides and prints, and sends nothing.
//!
//! # Output
//!
//! One JSON object per decided Candidate on stdout:
//!
//! ```json
//! {"candidate_id": "…", "chronicle": "…", "attempt_id": "…", "rule": "passed",
//!  "decision": "sanction", "answer": "Committed", "template_id": "…", "request_id": "…"}
//! ```
//!
//! and, at the end of each pass, `{"pass": <n>, "pending": <n>, "sent": <n>}`.
//!
//! # Exit status
//!
//! 0 a `--once` pass done (whatever the answers); 1 it could not reach the
//! socket or was answered `Error`; 2 a bad command line, configuration or
//! policy.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 24, BLAKE3
//! `6e94168a59236aa86cf5b26bdeb5e518f05ec8445132da88ab5df96d7954ad81`.

use std::process::ExitCode;
use std::time::Duration;

use serde_json::{json, Value};
use taso_core::contract::Decision;
use taso_core::decider::{Reply, Request, RetryReason, VerdictAnswer};
use taso_core::record::Authority;
use taso_warden::daemon::Config;
use taso_warden::decidesrv::DeciderClient;
use taso_warden::policy::Policy;

const USAGE: &str = "usage: taso-policy <warden-config> <policy.toml> [--once] [--dry-run] \
                     [--interval-secs <n>]";

fn usage(why: &str) -> ExitCode {
    eprintln!("taso-policy: {why}\n{USAGE}");
    ExitCode::from(2)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn decision_word(d: &Decision) -> &'static str {
    match d {
        Decision::Sanction => "sanction",
        Decision::Hold => "hold",
        Decision::Never { .. } => "never",
    }
}

fn answer_fields(v: &mut Value, a: &VerdictAnswer) {
    let (word, extra) = match a {
        VerdictAnswer::Committed { template_id } => (
            "Committed",
            Some(("template_id", hex(template_id.as_bytes()))),
        ),
        VerdictAnswer::Held => ("Held", None),
        VerdictAnswer::ClosedNever => ("ClosedNever", None),
        VerdictAnswer::Refused(r) => ("Refused", Some(("rule_refused", format!("{r:?}")))),
        VerdictAnswer::Retry(r) => {
            let (reason, extra) = match r {
                RetryReason::NotHere(w) => ("NotHere", ("why", w.clone())),
                RetryReason::Pending(w) => ("Pending", ("why", w.clone())),
                RetryReason::Rule(rule) => ("Rule", ("rule_refused", format!("{rule:?}"))),
            };
            v["reason"] = json!(reason);
            ("Retry", Some(extra))
        }
    };
    v["answer"] = json!(word);
    if let Some((k, x)) = extra {
        v[k] = json!(x);
    }
}

/// One pass: `Err` if the socket could not be used.
fn pass(n: u64, socket: &std::path::Path, policy: &Policy, dry: bool) -> Result<(), String> {
    let mut c = DeciderClient::connect(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    let items = match c.call(&Request::Pending).map_err(|e| e.to_string())? {
        Reply::Pending { items } => items,
        Reply::Error { message } => return Err(message),
        other => return Err(format!("unexpected reply {other:?}")),
    };
    let uid = rustix::process::getuid().as_raw();
    let mut sent = 0;
    for item in &items {
        let Some(choice) = policy.decide(item) else {
            continue;
        };
        let req = item.request(
            choice.attempt,
            choice.decision.clone(),
            Authority {
                actor: policy.actor.clone(),
                reason: choice.reason.clone(),
            },
            Some(policy.digest),
            uid,
        );
        let mut v = json!({
            "candidate_id": item.candidate.candidate_id.to_string(),
            "chronicle": hex(item.candidate.chronicle.as_bytes()),
            "attempt_id": req.attempt_id.to_string(),
            "rule": choice.rule.clone().unwrap_or_else(|| "default".into()),
            "decision": decision_word(&choice.decision),
            "request_id": req.request_id.to_string(),
        });
        if dry {
            v["answer"] = json!("dry-run");
        } else {
            match c
                .call(&Request::Verdict {
                    request: Box::new(req),
                })
                .map_err(|e| e.to_string())?
            {
                Reply::Verdict { answer } => answer_fields(&mut v, &answer),
                Reply::Error { message } => {
                    v["error"] = json!(message);
                    println!("{v}");
                    return Err(message);
                }
                other => return Err(format!("unexpected reply {other:?}")),
            }
            sent += 1;
        }
        println!("{v}");
    }
    println!(
        "{}",
        json!({"pass": n, "pending": items.len(), "sent": sent})
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        return usage("a config and a policy are needed");
    }
    let (mut once, mut dry, mut interval) = (false, false, 10u64);
    let mut it = args[2..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--once" => once = true,
            "--dry-run" => dry = true,
            "--interval-secs" => match it.next().and_then(|v| v.parse::<u64>().ok()) {
                Some(n) if n > 0 => interval = n,
                _ => return usage("--interval-secs takes a positive integer"),
            },
            _ => return usage(&format!("unknown option {a}")),
        }
    }
    let config = match std::fs::read_to_string(&args[0])
        .map_err(|e| e.to_string())
        .and_then(|t| Config::parse(&t).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => return usage(&format!("{}: {e}", args[0])),
    };
    let policy = match std::fs::read(&args[1])
        .map_err(|e| e.to_string())
        .and_then(|b| Policy::parse(&b).map_err(|e| e.to_string()))
    {
        Ok(p) => p,
        Err(e) => return usage(&format!("{}: {e}", args[1])),
    };
    eprintln!(
        "taso-policy: policy {} ({} rules, default {:?}), actor {:?}",
        policy.digest,
        policy.rules.len(),
        policy.default,
        policy.actor
    );
    let mut n = 0;
    loop {
        n += 1;
        match pass(n, &config.decider.socket, &policy, dry) {
            Ok(()) if once => return ExitCode::SUCCESS,
            Err(e) if once => {
                println!("{}", json!({"error": e}));
                return ExitCode::from(1);
            }
            Ok(()) => {}
            Err(e) => eprintln!("taso-policy: pass {n}: {e}"),
        }
        std::thread::sleep(Duration::from_secs(interval));
    }
}
