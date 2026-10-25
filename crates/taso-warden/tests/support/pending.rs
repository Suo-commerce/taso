// A pending item for tests of callers (the policy, `taso-policy`).

use taso_core::contract::{
    Candidate, ClassCounts, Facts, NominatedBy, Outcome, SealRef, VerificationFinished,
    VerificationStarted, VerifierRequirement,
};
use taso_core::decider::PendingItem;
use taso_core::envelope::{ChronicleId, HashVal, Lsn};

/// Candidate `n` with input counts `input`, and one finished attempt per
/// outcome, started in that order.
pub fn item(n: u8, input: ClassCounts, outcomes: &[Outcome]) -> PendingItem {
    let h = |b: u8| HashVal::from_bytes([b; 32]);
    let requirement = VerifierRequirement {
        template: ChronicleId::from_bytes([0x70; 16]),
        vconf_key: h(0x71),
        version: 1,
    };
    let candidate = Candidate {
        candidate_id: h(n),
        chronicle: ChronicleId::from_bytes([n; 16]),
        seal: SealRef {
            lsn: Lsn::new(4),
            hash: h(0x40),
        },
        exclude: Default::default(),
        transform_version: 1,
        classmap_key: h(0x41),
        input_manifest_key: h(0x42),
        output_manifest_key: h(0x43),
        artifact_key: h(0x44),
        requirement,
        facts: Facts {
            input,
            excluded: ClassCounts::default(),
            open_obligations: 0,
            effects_adopted: 0,
            ledger_lsn: Lsn::new(3),
            requirement,
        },
        facts_hash: h(0x45),
        nominated_by: NominatedBy::Agent,
        nominated_at: Lsn::new(5),
    };
    let attempts = outcomes
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let a = h(0x80 + i as u8 + n);
            (
                VerificationStarted {
                    candidate_id: h(n),
                    attempt_id: a,
                    artifact_key: h(0x44),
                    requirement,
                    started_at: Lsn::new(10 + 2 * i as u64),
                },
                VerificationFinished {
                    attempt_id: a,
                    outcome: *o,
                    output_digest: h(0x50),
                    output: Vec::new(),
                    result_digest: h(0x90 + i as u8 + n),
                    finished_at: Lsn::new(11 + 2 * i as u64),
                },
            )
        })
        .collect();
    PendingItem {
        candidate,
        attempts,
    }
}

/// Counts with only `source` set.
pub fn clean(source: u64) -> ClassCounts {
    ClassCounts {
        source,
        ..ClassCounts::default()
    }
}
