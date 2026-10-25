//! `taso ctl explain` (P4 spec rev. 27 §5.8, D83; file 12): every decision
//! about a Vessel, a Candidate or a Template, rebuilt from the
//! coordinator log's accepted records alone, and checked.
//!
//! [`explain`] reads the accepted records of the Chronicle (`query
//! { chronicle }` then `query_entry` for each position) and tells, per
//! Candidate: its facts, its attempts and how they ended, every verdict
//! (decision, the claimed authority and policy digest, the authenticated
//! peer) and every refusal, and how it ended (sanctioned into which
//! Template, and whether that Template is ready and the sanction
//! completed; never, and why; closed by the purge; still open, and what
//! a sanction still waits for: `pending_reason`).  For a Vessel also its
//! purge (deferrals, the commit, the items, the end); for a Template its
//! definition and where it was born (a sanction's trail, or a genesis,
//! which has no Candidate, no attempt and no track record).
//!
//! **The checks**, each named in the answer:
//!
//! - *intact*: every record's logical id and digest, recomputed, are the
//!   ones the log accepted;
//! - *derived*: every id a record derives is what its fields derive
//!   (`candidate_id`, `facts_hash`, `attempt_id`, `output_digest`,
//!   `result_digest`, `request_id` against its peer, `template_id`);
//! - *carried*: the pack the log names carries the record, in the store;
//! - *content*: every content object a record names is in the store and
//!   hashes to its key.
//!
//! A record or object changed after it was accepted fails a check; the
//! explanation is still given, and says which.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 27, BLAKE3
//! `7793e63dbab800e98051061cc0ee4f6f42faae8d7cd3ee8c754c2be9c62e3fad`.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use taso_core::contract::{
    attempt_id, candidate_id, facts_hash, logical_id, output_digest, result_digest, template_id,
    BornFrom, CloseKind, ContractRecord, Decision, LogicalKey, ObjectKind, VerificationStarted,
};
use taso_core::coordlog::{LogEntry, Submitted};
use taso_core::envelope::{ChronicleId, HashVal};
use taso_core::record::Payload;

use crate::coordinator::Coord;
use crate::coordstore::object_key_path;
use crate::finish::NoSend;
use crate::pack::Packs;
use crate::ship::SharedStore;

/// One check and its result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    /// What was checked.
    pub what: String,
    /// Whether it held.
    pub ok: bool,
}

/// An explanation and its checks.
#[derive(Clone, Debug)]
pub struct Explained {
    /// The decisions, as JSON.
    pub explain: Value,
    /// Every check made.
    pub checks: Vec<Check>,
}

impl Explained {
    /// The checks that failed.
    pub fn failed(&self) -> Vec<&Check> {
        self.checks.iter().filter(|c| !c.ok).collect()
    }
}

/// What to explain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject {
    /// A Vessel or a Template (32 hex digits).
    Chronicle(ChronicleId),
    /// A Candidate (64 hex digits).
    Candidate(HashVal),
}

impl Subject {
    /// From hex: 32 digits a Chronicle, 64 a Candidate.
    pub fn parse(s: &str) -> Option<Self> {
        let b: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
            .collect::<Option<_>>()?;
        match b.len() {
            16 => Some(Self::Chronicle(ChronicleId::from_bytes(b.try_into().ok()?))),
            32 => Some(Self::Candidate(HashVal::from_bytes(b.try_into().ok()?))),
            _ => None,
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Ctx<'a> {
    coord: &'a dyn Coord,
    store: &'a SharedStore,
    prefix: &'a str,
    checks: Vec<Check>,
}

impl Ctx<'_> {
    fn check(&mut self, what: String, ok: bool) {
        self.checks.push(Check { what, ok });
    }

    fn accepted(&self, key: LogicalKey) -> Result<Option<ContractRecord>, String> {
        Ok(
            match self
                .coord
                .query_logical(logical_id(&key))
                .map_err(|e| e.to_string())?
            {
                Some((_, Submitted::Contract(r))) => Some(r),
                _ => None,
            },
        )
    }

    /// The accepted records of `id`, in log order, each checked intact
    /// and carried.
    fn entries(&mut self, id: ChronicleId) -> Result<Option<Vec<LogEntry>>, String> {
        let Some(view) = self.coord.query_chronicle(id).map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let packs =
            Packs::new(self.store.clone(), NoSend, self.prefix, id).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for pos in view.accepted {
            let e = self
                .coord
                .query_entry(pos)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("log position {pos} has no record"))?;
            let intact = e.record.logical_id() == e.logical && e.record.digest() == e.digest;
            self.check(format!("intact: record at log position {pos}"), intact);
            // A purged pack's frames are in its log-only replacement
            // (§6.2, D25): the record is carried there.
            let read = match packs.read_pack_log(&e.pack) {
                Ok(Some(x)) => Some(x),
                _ => taso_core::contract::replacement_name(&e.pack)
                    .and_then(|r| packs.read_pack_log(&r).ok().flatten()),
            };
            let carried = match read {
                Some((_, frames)) => frames.iter().any(|f| match Payload::decode(&f.payload) {
                    Ok(Payload::Contract(r)) => Submitted::Contract(*r).digest() == e.digest,
                    Ok(Payload::Lineage(l)) => {
                        Submitted::Birth {
                            chronicle: id,
                            lineage: l,
                        }
                        .digest()
                            == e.digest
                    }
                    _ => false,
                }),
                None => false,
            };
            self.check(
                format!("carried: record at log position {pos} by pack {}", e.pack),
                carried,
            );
            out.push(e);
        }
        Ok(Some(out))
    }

    /// Whether the content object `key` of `kind` is in the store and
    /// hashes to its key.
    fn content(&mut self, kind: ObjectKind, key: HashVal, of: &str) {
        let path = object_key_path(self.prefix, kind, key).expect("a content kind");
        let ok = match self.store.get(&path) {
            Ok(Some(mut r)) => {
                let mut h = blake3::Hasher::new_derive_key(kind.prefix());
                std::io::copy(&mut r, &mut h).is_ok() && h.finalize().as_bytes() == key.as_bytes()
            }
            _ => false,
        };
        self.check(format!("content: {of} {path}"), ok);
    }
}

/// Explain `subject` from the coordinator log (and check it against the
/// store).
pub fn explain(
    coord: &dyn Coord,
    store: &SharedStore,
    prefix: &str,
    subject: Subject,
) -> Result<Explained, String> {
    let mut cx = Ctx {
        coord,
        store,
        prefix,
        checks: Vec::new(),
    };
    let explain = match subject {
        Subject::Candidate(cid) => {
            let Some(ContractRecord::Candidate(c)) = cx.accepted(LogicalKey::Candidate(cid))?
            else {
                return Err(format!("no Candidate {cid} is accepted"));
            };
            let mut v = vessel(&mut cx, c.chronicle)?;
            if let Some(Value::Array(cs)) = v.get_mut("candidates") {
                cs.retain(|x| x["candidate_id"] == json!(cid.to_string()));
            }
            v
        }
        Subject::Chronicle(id) => {
            if let Some(ContractRecord::TemplateReady(_)) = cx.accepted(LogicalKey::Template(id))? {
                template(&mut cx, id)?
            } else {
                vessel(&mut cx, id)?
            }
        }
    };
    Ok(Explained {
        explain,
        checks: cx.checks,
    })
}

fn template(cx: &mut Ctx<'_>, id: ChronicleId) -> Result<Value, String> {
    let entries = cx.entries(id)?.unwrap_or_default();
    let Some(ContractRecord::TemplateReady(t)) = cx.accepted(LogicalKey::Template(id))? else {
        return Err("not a Template".into());
    };
    cx.content(ObjectKind::Artifact, t.layer, "its layer (the artifact)");
    cx.content(
        ObjectKind::Manifest,
        t.output_manifest_key,
        "its output manifest",
    );
    cx.content(
        ObjectKind::Classmap,
        t.classmap_key,
        "its classification map",
    );
    if let Some(k) = t.vconf_key {
        cx.content(ObjectKind::Vconf, k, "its verifier config");
    }
    let born = match t.born_from {
        BornFrom::Sanction {
            source,
            candidate_id: cid,
            verdict,
        } => {
            let ok = template_id(cid, verdict) == id;
            cx.check("derived: template_id of the sanction".into(), ok);
            let src = vessel(cx, source)?;
            let trail = src["candidates"]
                .as_array()
                .and_then(|cs| {
                    cs.iter()
                        .find(|c| c["candidate_id"] == json!(cid.to_string()))
                })
                .cloned()
                .unwrap_or(Value::Null);
            json!({"sanction": {"source": hex(source.as_bytes()), "candidate_id": cid.to_string(),
                "verdict": verdict.to_string(), "trail": trail}})
        }
        BornFrom::Genesis { genesis_id } => json!({"genesis": {
            "genesis_id": hex(genesis_id.as_bytes()),
            "note": "a genesis Template has no Candidate, no attempt and no track record"}}),
    };
    Ok(json!({
        "template_id": hex(id.as_bytes()),
        "records": entries.len(),
        "born_from": born,
        "parent_template": t.parent_template.map(|p| hex(p.as_bytes())),
        "layer": t.layer.to_string(),
        "output_manifest_key": t.output_manifest_key.to_string(),
        "classmap_key": t.classmap_key.to_string(),
        "vconf_key": t.vconf_key.map(|k| k.to_string()),
        "authority": {"actor": t.authority.actor, "reason": t.authority.reason},
    }))
}

#[derive(Default)]
struct Trail {
    candidate: Option<Value>,
    attempts: Vec<Value>,
    verdicts: Vec<Value>,
    outcome: Option<Value>,
    committed: Option<(ChronicleId, HashVal)>,
}

fn decision_word(d: &Decision) -> Value {
    match d {
        Decision::Sanction => json!("sanction"),
        Decision::Hold => json!("hold"),
        Decision::Never { reason } => json!({"never": reason}),
    }
}

fn vessel(cx: &mut Ctx<'_>, id: ChronicleId) -> Result<Value, String> {
    let Some(entries) = cx.entries(id)? else {
        return Err(format!(
            "the coordinator does not know {}",
            hex(id.as_bytes())
        ));
    };
    let mut trails: BTreeMap<[u8; 32], Trail> = BTreeMap::new();
    let mut order: Vec<[u8; 32]> = Vec::new();
    let mut started: BTreeMap<[u8; 32], VerificationStarted> = BTreeMap::new();
    let mut purge = json!({"deferred": [], "replaced": 0, "lost": 0});
    let mut retired = false;
    let trail = |cid: HashVal, order: &mut Vec<[u8; 32]>| -> [u8; 32] {
        let k = *cid.as_bytes();
        if !order.contains(&k) {
            order.push(k);
        }
        k
    };
    for e in &entries {
        let Submitted::Contract(r) = &e.record else {
            continue;
        };
        match r {
            ContractRecord::Candidate(c) => {
                let derived = candidate_id(
                    c.chronicle,
                    c.seal.hash,
                    &c.exclude,
                    c.classmap_key,
                    c.transform_version,
                    &c.requirement,
                ) == c.candidate_id
                    && facts_hash(&c.facts) == c.facts_hash
                    && c.chronicle == id;
                cx.check(
                    format!("derived: Candidate {} and its facts", c.candidate_id),
                    derived,
                );
                cx.content(
                    ObjectKind::Artifact,
                    c.artifact_key,
                    "the Candidate's artifact",
                );
                cx.content(
                    ObjectKind::Manifest,
                    c.input_manifest_key,
                    "its input manifest",
                );
                cx.content(
                    ObjectKind::Manifest,
                    c.output_manifest_key,
                    "its output manifest",
                );
                cx.content(
                    ObjectKind::Classmap,
                    c.classmap_key,
                    "its classification map",
                );
                cx.content(
                    ObjectKind::Vconf,
                    c.requirement.vconf_key,
                    "its verifier config",
                );
                let k = trail(c.candidate_id, &mut order);
                let f = &c.facts;
                trails.entry(k).or_default().candidate = Some(json!({
                    "seal": c.seal.lsn.get(),
                    "nominated_by": format!("{:?}", c.nominated_by),
                    "exclude": c.exclude.iter().map(|x| format!("{x:?}")).collect::<Vec<_>>(),
                    "verifier": hex(c.requirement.template.as_bytes()),
                    "input": format!("{:?}", f.input),
                    "excluded": format!("{:?}", f.excluded),
                    "open_obligations": f.open_obligations,
                    "artifact_key": c.artifact_key.to_string(),
                }));
            }
            ContractRecord::VerificationStarted(s) => {
                cx.check(
                    format!("derived: attempt {}", s.attempt_id),
                    attempt_id(s.candidate_id, s.started_at) == s.attempt_id,
                );
                started.insert(*s.attempt_id.as_bytes(), *s);
                trail(s.candidate_id, &mut order);
            }
            ContractRecord::VerificationFinished(f) => {
                let Some(s) = started.get(f.attempt_id.as_bytes()).copied() else {
                    cx.check(
                        format!("derived: attempt {} was started", f.attempt_id),
                        false,
                    );
                    continue;
                };
                let ok = output_digest(&f.output) == f.output_digest
                    && result_digest(
                        s.candidate_id,
                        s.artifact_key,
                        &s.requirement,
                        s.attempt_id,
                        &f.outcome,
                        f.output_digest,
                    ) == f.result_digest;
                cx.check(
                    format!("derived: the result of attempt {}", f.attempt_id),
                    ok,
                );
                let k = trail(s.candidate_id, &mut order);
                trails.entry(k).or_default().attempts.push(json!({
                    "attempt_id": f.attempt_id.to_string(),
                    "started_at": s.started_at.get(),
                    "outcome": format!("{:?}", f.outcome),
                    "output": String::from_utf8_lossy(&f.output),
                    "result_digest": f.result_digest.to_string(),
                }));
            }
            ContractRecord::VerdictSubmitted(v) => {
                let q = &v.request;
                cx.check(
                    format!("derived: request {} from uid {}", q.request_id, v.peer.uid),
                    q.id_matches(v.peer),
                );
                let k = trail(q.candidate_id, &mut order);
                trails.entry(k).or_default().verdicts.push(json!({
                    "request_id": q.request_id.to_string(),
                    "decision": decision_word(&q.decision),
                    "attempt_id": q.attempt_id.to_string(),
                    "actor": q.authority.actor,
                    "reason": q.authority.reason,
                    "policy_digest": q.policy_digest.map(|d| d.to_string()),
                    "peer": {"uid": v.peer.uid, "pid": v.peer.pid},
                    "recorded": "submitted",
                }));
            }
            ContractRecord::Refused(r) => {
                let k = trail(r.candidate_id, &mut order);
                trails.entry(k).or_default().verdicts.push(json!({
                    "request_id": r.request_id.to_string(),
                    "peer": {"uid": r.peer.uid, "pid": r.peer.pid},
                    "recorded": {"refused": format!("{:?}", r.rule)},
                }));
            }
            ContractRecord::CandidateClosed(c) => {
                let k = trail(c.candidate_id, &mut order);
                trails.entry(k).or_default().outcome = Some(match &c.how {
                    CloseKind::Never { reason, verdict } => {
                        json!({"never": {"reason": reason, "verdict": verdict.to_string()}})
                    }
                    CloseKind::Cancelled { authority } => {
                        json!({"cancelled": {"actor": authority.actor, "reason": authority.reason}})
                    }
                    CloseKind::Superseded { authority, by } => json!({"superseded": {
                        "by": by.to_string(), "actor": authority.actor, "reason": authority.reason}}),
                });
            }
            ContractRecord::SanctionCommitted(s) => {
                cx.check(
                    format!("derived: template_id of Candidate {}", s.candidate_id),
                    template_id(s.candidate_id, s.verdict) == s.template_id && s.is_consistent(),
                );
                let k = trail(s.candidate_id, &mut order);
                trails.entry(k).or_default().committed = Some((s.template_id, s.verdict));
            }
            ContractRecord::PurgeDeferred(d) => {
                purge["deferred"].as_array_mut().expect("an array").push(
                    json!({"checked_at": d.checked_at.get(), "reason": format!("{:?}", d.reason)}),
                );
            }
            ContractRecord::PurgeCommitted(p) => {
                retired = true;
                cx.content(
                    ObjectKind::Inventory,
                    p.inventory_key,
                    "the purge's inventory",
                );
                cx.content(ObjectKind::Local, p.local_key, "the purge's local state");
                purge["committed"] = json!({"cutoff_seal": p.cutoff.seal.lsn.get(),
                    "inventory_key": p.inventory_key.to_string()});
            }
            ContractRecord::ReplacementInstalled(_) => {
                purge["replaced"] = json!(purge["replaced"].as_u64().unwrap_or(0) + 1);
            }
            ContractRecord::ItemLost(_) => {
                purge["lost"] = json!(purge["lost"].as_u64().unwrap_or(0) + 1);
            }
            ContractRecord::PurgeComplete(p) => {
                purge["end"] = json!({"complete": {"items_replaced": p.items_replaced,
                    "history_attestation": p.history_attestation.to_string()}});
            }
            ContractRecord::PurgeDamaged(p) => {
                purge["end"] = json!({"damaged": {"items_replaced": p.items_replaced,
                    "items_lost": p.items_lost}});
            }
            _ => {}
        }
    }
    let mut candidates = Vec::new();
    for k in order {
        let t = trails.remove(&k).unwrap_or_default();
        let cid = HashVal::from_bytes(k);
        let (outcome, pending_reason) = match (&t.committed, &t.outcome) {
            (Some((tid, _)), _) => {
                let ready = matches!(
                    cx.accepted(LogicalKey::Template(*tid))?,
                    Some(ContractRecord::TemplateReady(_))
                );
                let done = cx.accepted(LogicalKey::SanctionCompleted(*tid))?.is_some();
                (
                    json!({"sanctioned": {"template_id": hex(tid.as_bytes()), "ready": ready, "completed": done}}),
                    match (ready, done) {
                        (false, _) => Some("its TemplateReady is not accepted: the sanction stays committed until a finish publishes it"),
                        (true, false) => Some("its SanctionCompleted is not accepted"),
                        (true, true) => None,
                    },
                )
            }
            (None, Some(o)) => (o.clone(), None),
            (None, None) if retired => (json!("closed by the purge"), None),
            (None, None) if t.verdicts.iter().any(|v| v["decision"] == json!("hold")) => {
                (json!("held"), None)
            }
            (None, None) => (json!("open"), None),
        };
        candidates.push(json!({
            "candidate_id": cid.to_string(),
            "nomination": t.candidate,
            "attempts": t.attempts,
            "verdicts": t.verdicts,
            "outcome": outcome,
            "pending_reason": pending_reason,
        }));
    }
    let birth = entries
        .iter()
        .any(|e| matches!(e.record, Submitted::Birth { .. }));
    Ok(json!({
        "vessel": hex(id.as_bytes()),
        "records": entries.len(),
        "birth_accepted": birth,
        "retired": retired,
        "candidates": candidates,
        "purge": purge,
    }))
}
