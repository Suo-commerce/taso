//! `taso-policy` against a decider socket served by a stand-in Warden
//! (P4 file 10): what it decides, what it sends, and that a second pass
//! sends the same requests.

use std::process::Command;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use taso_core::contract::{Decision, Outcome, Peer, VerdictRequest};
use taso_core::decider::{PendingItem, VerdictAnswer};
use taso_core::envelope::ChronicleId;
use taso_warden::decidesrv::{Decide, DeciderConf, DeciderServer};

mod support {
    include!("support/pending.rs");
}
use support::{clean, item};

const POLICY: &str = env!("CARGO_BIN_EXE_taso-policy");

struct Fake {
    items: Vec<PendingItem>,
    seen: Mutex<Vec<(VerdictRequest, Peer)>>,
}

impl Decide for Fake {
    fn pending(&self) -> Result<Vec<PendingItem>, String> {
        Ok(self.items.clone())
    }
    fn verdict(&self, r: &VerdictRequest, peer: Peer) -> Result<VerdictAnswer, String> {
        self.seen.lock().unwrap().push((r.clone(), peer));
        Ok(match &r.decision {
            Decision::Sanction => VerdictAnswer::Committed {
                template_id: ChronicleId::from_bytes([0xee; 16]),
            },
            Decision::Hold => VerdictAnswer::Held,
            Decision::Never { .. } => VerdictAnswer::ClosedNever,
        })
    }
}

fn lines(out: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(out)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn a_pass_decides_each_pending_candidate_and_a_second_sends_the_same() {
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
    let policy_text = "version = 1\nactor = \"policy-bot\"\ndefault = \"hold\"\n\
        [[rule]]\nname = \"failed\"\ndecision = \"never\"\nwhen = { outcome = \"fail\" }\n\
        [[rule]]\nname = \"passed\"\ndecision = \"sanction\"\nwhen = { outcome = \"pass\" }\n";
    let policy = dir.path().join("policy.toml");
    std::fs::write(&policy, policy_text).unwrap();
    let fake = Arc::new(Fake {
        items: vec![
            item(1, clean(2), &[Outcome::Exit { code: 0 }]),
            item(2, clean(2), &[Outcome::Exit { code: 3 }]),
            item(3, clean(2), &[Outcome::Timeout]),
            item(4, clean(2), &[]),
        ],
        seen: Mutex::new(Vec::new()),
    });
    let _srv = DeciderServer::spawn(&DeciderConf::defaults(&run_dir), fake.clone()).unwrap();
    let run = |extra: &[&str]| {
        Command::new(POLICY)
            .arg(&cfg)
            .arg(&policy)
            .args(extra)
            .output()
            .unwrap()
    };

    // A dry run sends nothing.
    let o = run(&["--once", "--dry-run"]);
    assert_eq!(o.status.code(), Some(0));
    let l = lines(&o.stdout);
    assert_eq!(l.len(), 4, "three decided, then the pass line");
    assert!(fake.seen.lock().unwrap().is_empty());
    assert_eq!(l[3]["sent"], 0);

    let o = run(&["--once"]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let l = lines(&o.stdout);
    let got: Vec<(String, String, String)> = l[..3]
        .iter()
        .map(|v| {
            (
                v["rule"].as_str().unwrap().into(),
                v["decision"].as_str().unwrap().into(),
                v["answer"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            ("passed".into(), "sanction".into(), "Committed".into()),
            ("failed".into(), "never".into(), "ClosedNever".into()),
            ("default".into(), "hold".into(), "Held".into()),
        ]
    );
    assert_eq!(
        (l[3]["pending"].as_u64(), l[3]["sent"].as_u64()),
        (Some(4), Some(3))
    );
    let digest = blake3::hash(policy_text.as_bytes());
    let first = fake.seen.lock().unwrap().clone();
    for (r, p) in &first {
        assert!(r.id_matches(*p));
        assert_eq!(r.authority.actor, "policy-bot");
        assert_eq!(r.policy_digest.unwrap().as_bytes(), digest.as_bytes());
    }
    assert_eq!(first[0].0.authority.reason, "rule passed");
    assert_eq!(first[2].0.authority.reason, "default");

    // The same facts, the same policy: the same requests.
    let o = run(&["--once"]);
    assert_eq!(o.status.code(), Some(0));
    let all = fake.seen.lock().unwrap().clone();
    assert_eq!(all.len(), 6);
    for i in 0..3 {
        assert_eq!(all[i].0.request_id, all[i + 3].0.request_id);
    }

    // A bad policy never runs.
    std::fs::write(&policy, "version = 1\nactor = \"x\"\nmode = \"yolo\"\n").unwrap();
    assert_eq!(run(&["--once"]).status.code(), Some(2));
}
