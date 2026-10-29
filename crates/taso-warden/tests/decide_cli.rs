//! `taso-decide` against a decider socket served by a stand-in Warden
//! (P4 file 8c): what it sends, what it prints, its exit status.

use std::process::Command;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use taso_core::contract::{
    request_id, Decision, OpKind, Peer, Refusal, VerdictRequest, VerifierRequirement,
};
use taso_core::decider::{PendingItem, Request, RetryReason, VerdictAnswer};
use taso_core::envelope::{ChronicleId, HashVal};
use taso_core::record::Authority;
use taso_warden::decidesrv::{Decide, DeciderConf, DeciderServer};

const DECIDE: &str = env!("CARGO_BIN_EXE_taso-decide");

#[derive(Default)]
struct Fake {
    seen: Mutex<Vec<(VerdictRequest, Peer)>>,
}

impl Decide for Fake {
    fn pending(&self) -> Result<Vec<PendingItem>, String> {
        Ok(Vec::new())
    }
    fn verdict(&self, r: &VerdictRequest, peer: Peer) -> Result<VerdictAnswer, String> {
        self.seen.lock().unwrap().push((r.clone(), peer));
        Ok(match r.decision {
            Decision::Hold => VerdictAnswer::Held,
            _ => VerdictAnswer::Retry(RetryReason::Rule(Refusal::LaterAttemptFailed)),
        })
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn run(cfg: &std::path::Path, args: &[&str]) -> (i32, Value) {
    let o = Command::new(DECIDE).arg(cfg).args(args).output().unwrap();
    let v = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    (o.status.code().unwrap(), v)
}

#[test]
fn pending_verdict_like_and_resend() {
    let dir = tempfile::tempdir().unwrap();
    let run_dir = dir.path().join("run");
    let cfg = dir.path().join("w.json");
    std::fs::write(
        &cfg,
        format!(
            r#"{{"warden": 1, "coordinator": {{"remote": "/nonexistent/coord.sock"}}, "storage": "zfs",
               "root": "tank/vessel", "state_dir": "/var/lib/taso/state",
               "store": "/srv/taso/store", "run_dir": "{}",
               "runtime": {{"rootfs": "/srv/taso/rootfs", "host_uid_base": 200000,
                           "args": ["/usr/bin/agent"], "memory_bytes": 268435456, "pids": 64}},
               "vessels": []}}"#,
            run_dir.display()
        ),
    )
    .unwrap();
    let fake = Arc::new(Fake::default());
    let _srv = DeciderServer::spawn(&DeciderConf::defaults(&run_dir), fake.clone()).unwrap();

    let (rc, v) = run(&cfg, &["pending"]);
    assert_eq!((rc, v["pending"].as_array().map(Vec::len)), (0, Some(0)));

    let (cid, aid) = (hex(&[1; 32]), hex(&[2; 32]));
    let (rc, v) = run(
        &cfg,
        &[
            "verdict", &cid, &aid, "sanction", "--actor", "a", "--reason", "r",
        ],
    );
    assert_eq!(rc, 3, "{v}");
    assert!(v["error"].as_str().unwrap().contains("is not pending here"));

    // --like: bound to an earlier request; a new decision, a new id.
    let mut like = VerdictRequest {
        request_id: HashVal::from_bytes([0; 32]),
        candidate_id: HashVal::from_bytes([1; 32]),
        facts_hash: HashVal::from_bytes([3; 32]),
        artifact_key: HashVal::from_bytes([4; 32]),
        requirement: VerifierRequirement {
            template: ChronicleId::from_bytes([5; 16]),
            vconf_key: HashVal::from_bytes([6; 32]),
            version: 1,
        },
        exclude: Default::default(),
        attempt_id: HashVal::from_bytes([2; 32]),
        result_digest: HashVal::from_bytes([7; 32]),
        decision: Decision::Sanction,
        authority: Authority {
            actor: "x".into(),
            reason: "y".into(),
        },
        policy_digest: None,
    };
    like.request_id = request_id(9, OpKind::Verdict, &like.body());
    let like_hex = hex(&Request::Verdict {
        request: Box::new(like.clone()),
    }
    .encode());
    let (rc, v) = run(
        &cfg,
        &[
            "verdict", &cid, &aid, "hold", "--actor", "a", "--reason", "r", "--like", &like_hex,
        ],
    );
    assert_eq!((rc, v["answer"].as_str()), (0, Some("Held")), "{v}");
    let (rc, v2) = run(&cfg, &["resend", v["request"].as_str().unwrap()]);
    assert_eq!((rc, v2["answer"].as_str()), (0, Some("Held")));
    assert_eq!(v2["request_id"], v["request_id"]);
    let (rc, v3) = run(
        &cfg,
        &[
            "verdict", &cid, &aid, "never", "--never", "no", "--actor", "a", "--reason", "r",
            "--like", &like_hex,
        ],
    );
    assert_eq!(
        (
            rc,
            v3["answer"].as_str(),
            v3["reason"].as_str(),
            v3["rule"].as_str()
        ),
        (0, Some("Retry"), Some("Rule"), Some("LaterAttemptFailed"))
    );
    let seen = fake.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3);
    let me = rustix::process::getuid().as_raw();
    for (r, p) in &seen {
        assert!(r.id_matches(*p), "the id is the sender's");
        assert_eq!(p.uid, me);
        assert_eq!(
            (r.facts_hash, r.result_digest),
            (like.facts_hash, like.result_digest)
        );
        assert_eq!(r.authority.actor, "a");
    }
    assert_eq!(seen[0].0, seen[1].0, "resend sends the same request");
    assert_eq!(
        seen[2].0.decision,
        Decision::Never {
            reason: "no".into()
        }
    );

    // Usage errors.
    let (rc, _) = run(
        &cfg,
        &[
            "verdict", &cid, &aid, "never", "--actor", "a", "--reason", "r",
        ],
    );
    assert_eq!(rc, 2);
    let (rc, _) = run(&cfg, &["resend", "zz"]);
    assert_eq!(rc, 2);
}
