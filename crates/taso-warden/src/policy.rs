//! The default caller's soft policy (P4 spec rev. 24 §5.7, D1, D2, D80;
//! file 10): a TOML file of ordered rules over a pending Candidate's
//! facts, deciding Sanction, Hold or Never.
//!
//! ```toml
//! version = 1
//! actor = "taso-policy"        # authority.actor of every verdict
//! default = "hold"             # when no rule matches
//!
//! [[rule]]
//! name = "no secrets"
//! decision = "never"
//! reason = "a secret is in the input"     # Never's reason (default: the rule's name)
//! when = { input_secret = { min = 1 } }
//!
//! [[rule]]
//! name = "passed"
//! decision = "sanction"
//! when = { outcome = "pass", input_unknown = { max = 0 } }
//! ```
//!
//! A pending Candidate is decided on its **newest** finished attempt (the
//! greatest `started_at`).  Rules are tried in order; the first whose
//! `when` holds in full decides (an empty `when` always holds); none:
//! `default`.  A condition is on one fact: a number against `{ min, max,
//! eq }` (each optional, all that are given must hold) or a bare number
//! (`eq`); a word against a string or `{ in = [...] }`.  Facts:
//!
//! - `input_<class>`, `excluded_<class>` for each class (`source`,
//!   `config`, `hook`, `secret`, `scratch`, `artifact`, `unknown`,
//!   `structural`, `unsupported`): the Candidate's counts;
//! - `open_obligations`, `effects_adopted`: the Candidate's facts;
//! - `attempts`: its finished attempts;
//! - `exit_code`: the newest attempt's exit code (absent, so failing
//!   every condition, unless it ended `Exit`);
//! - `outcome`: `pass` (`Exit { 0 }`), `fail` (any other exit),
//!   `timeout`, `output_limit`, `launch_failed`, `interrupted`;
//! - `nominated_by`: `agent`, `config` or `supersede`.
//!
//! Unknown keys, facts, decisions and condition forms are refused when
//! the file is read: a policy that does not say what its author meant
//! never runs.  The policy's digest, recorded as claimed on every
//! verdict (`policy_digest`, §11.2), is the file's plain BLAKE3 (as
//! `b3sum` prints it).  The hard rules stay the Warden's: a policy that
//! sanctions what they forbid gets the Warden's `Refused`.
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 24, BLAKE3
//! `6e94168a59236aa86cf5b26bdeb5e518f05ec8445132da88ab5df96d7954ad81`.

use std::collections::BTreeMap;
use std::fmt;

use taso_core::contract::{Decision, NominatedBy, Outcome};
use taso_core::decider::PendingItem;
use taso_core::envelope::HashVal;

/// Why a policy file is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

fn bad(why: impl Into<String>) -> PolicyError {
    PolicyError(why.into())
}

/// What a rule decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `sanction`.
    Sanction,
    /// `hold`.
    Hold,
    /// `never`.
    Never,
}

impl Kind {
    fn parse(s: &str) -> Result<Self, PolicyError> {
        match s {
            "sanction" => Ok(Self::Sanction),
            "hold" => Ok(Self::Hold),
            "never" => Ok(Self::Never),
            _ => Err(bad(format!(
                "{s:?} is not a decision (sanction, hold, never)"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Cond {
    Num {
        min: Option<u64>,
        max: Option<u64>,
        eq: Option<u64>,
    },
    Word(Vec<String>),
}

const CLASSES: [&str; 9] = [
    "source",
    "config",
    "hook",
    "secret",
    "scratch",
    "artifact",
    "unknown",
    "structural",
    "unsupported",
];

const OUTCOMES: [&str; 6] = [
    "pass",
    "fail",
    "timeout",
    "output_limit",
    "launch_failed",
    "interrupted",
];

const NOMINATORS: [&str; 3] = ["agent", "config", "supersede"];

/// The words a word fact takes, or `None` for a number fact; `Err` for no
/// such fact.
fn fact_kind(name: &str) -> Result<Option<&'static [&'static str]>, PolicyError> {
    match name {
        "outcome" => Ok(Some(&OUTCOMES)),
        "nominated_by" => Ok(Some(&NOMINATORS)),
        "open_obligations" | "effects_adopted" | "attempts" | "exit_code" => Ok(None),
        _ => {
            let class = name
                .strip_prefix("input_")
                .or_else(|| name.strip_prefix("excluded_"));
            match class {
                Some(c) if CLASSES.contains(&c) => Ok(None),
                _ => Err(bad(format!("{name:?} is not a fact"))),
            }
        }
    }
}

/// One rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Its name, in every verdict it decides.
    pub name: String,
    /// What it decides.
    pub decision: Kind,
    /// Never's reason.
    pub reason: String,
    when: BTreeMap<String, Cond>,
}

/// A policy, read and checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// `authority.actor`.
    pub actor: String,
    /// When no rule matches.
    pub default: Kind,
    /// In order.
    pub rules: Vec<Rule>,
    /// The file's BLAKE3.
    pub digest: HashVal,
}

/// What the policy decides for one pending Candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    /// The attempt decided on (the newest finished one).
    pub attempt: usize,
    /// The decision.
    pub decision: Decision,
    /// The rule that decided, or `None` for the default.
    pub rule: Option<String>,
    /// `authority.reason`: `rule <name>` or `default`.
    pub reason: String,
}

fn only(t: &toml::Table, what: &str, keys: &[&str]) -> Result<(), PolicyError> {
    match t.keys().find(|k| !keys.contains(&k.as_str())) {
        Some(k) => Err(bad(format!("{what}: unknown key {k:?}"))),
        None => Ok(()),
    }
}

fn number(v: &toml::Value, what: &str) -> Result<u64, PolicyError> {
    v.as_integer()
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(|| bad(format!("{what} must be a non-negative integer")))
}

fn cond(fact: &str, v: &toml::Value) -> Result<Cond, PolicyError> {
    let what = format!("condition on {fact:?}");
    match fact_kind(fact)? {
        None => match v {
            toml::Value::Integer(_) => Ok(Cond::Num {
                min: None,
                max: None,
                eq: Some(number(v, &what)?),
            }),
            toml::Value::Table(t) => {
                only(t, &what, &["min", "max", "eq"])?;
                if t.is_empty() {
                    return Err(bad(format!("{what} is empty")));
                }
                let get = |k: &str| t.get(k).map(|x| number(x, &what)).transpose();
                Ok(Cond::Num {
                    min: get("min")?,
                    max: get("max")?,
                    eq: get("eq")?,
                })
            }
            _ => Err(bad(format!(
                "{what} must be a number or {{ min, max, eq }}"
            ))),
        },
        Some(words) => {
            let list: Vec<String> = match v {
                toml::Value::String(s) => vec![s.clone()],
                toml::Value::Table(t) => {
                    only(t, &what, &["in"])?;
                    match t.get("in") {
                        Some(toml::Value::Array(a)) if !a.is_empty() => a
                            .iter()
                            .map(|x| {
                                x.as_str()
                                    .map(str::to_string)
                                    .ok_or_else(|| bad(format!("{what}: 'in' takes words")))
                            })
                            .collect::<Result<_, _>>()?,
                        _ => return Err(bad(format!("{what}: 'in' must be a non-empty array"))),
                    }
                }
                _ => return Err(bad(format!("{what} must be a word or {{ in = [...] }}"))),
            };
            for w in &list {
                if !words.contains(&w.as_str()) {
                    return Err(bad(format!(
                        "{what}: {w:?} is not one of {}",
                        words.join(", ")
                    )));
                }
            }
            Ok(Cond::Word(list))
        }
    }
}

impl Policy {
    /// Read and check a policy file.
    pub fn parse(bytes: &[u8]) -> Result<Self, PolicyError> {
        let text = std::str::from_utf8(bytes).map_err(|_| bad("not UTF-8"))?;
        let doc: toml::Table = text.parse().map_err(|e| bad(format!("{e}")))?;
        only(&doc, "policy", &["version", "actor", "default", "rule"])?;
        if doc.get("version").and_then(|v| v.as_integer()) != Some(1) {
            return Err(bad("version must be 1"));
        }
        let actor = match doc.get("actor") {
            Some(toml::Value::String(s)) if !s.is_empty() => s.clone(),
            _ => return Err(bad("actor must be a non-empty string")),
        };
        let default = match doc.get("default") {
            Some(toml::Value::String(s)) => Kind::parse(s)?,
            None => Kind::Hold,
            _ => return Err(bad("default must be a decision")),
        };
        let rules = match doc.get("rule") {
            None => Vec::new(),
            Some(toml::Value::Array(a)) => a.clone(),
            Some(_) => return Err(bad("'rule' must be an array of tables")),
        };
        let mut out: Vec<Rule> = Vec::new();
        for (i, r) in rules.iter().enumerate() {
            let what = format!("rule {}", i + 1);
            let t = r
                .as_table()
                .ok_or_else(|| bad(format!("{what} must be a table")))?;
            only(t, &what, &["name", "decision", "reason", "when"])?;
            let name = match t.get("name") {
                Some(toml::Value::String(s)) if !s.is_empty() => s.clone(),
                _ => return Err(bad(format!("{what}: name must be a non-empty string"))),
            };
            if out.iter().any(|o| o.name == name) {
                return Err(bad(format!("{what}: the name {name:?} is used twice")));
            }
            let decision = match t.get("decision") {
                Some(toml::Value::String(s)) => Kind::parse(s)?,
                _ => return Err(bad(format!("{what}: decision is needed"))),
            };
            let reason = match t.get("reason") {
                None => name.clone(),
                Some(toml::Value::String(s)) if decision == Kind::Never && !s.is_empty() => {
                    s.clone()
                }
                Some(_) => {
                    return Err(bad(format!(
                        "{what}: reason is a non-empty string, for a never rule only"
                    )))
                }
            };
            let mut when = BTreeMap::new();
            match t.get("when") {
                None => {}
                Some(toml::Value::Table(w)) => {
                    for (k, v) in w {
                        when.insert(k.clone(), cond(k, v)?);
                    }
                }
                Some(_) => return Err(bad(format!("{what}: when must be a table"))),
            }
            out.push(Rule {
                name,
                decision,
                reason,
                when,
            });
        }
        Ok(Self {
            actor,
            default,
            rules: out,
            digest: HashVal::from_bytes(*blake3::hash(bytes).as_bytes()),
        })
    }

    /// Decide `item`; `None` if it has no finished attempt.
    pub fn decide(&self, item: &PendingItem) -> Option<Choice> {
        let (i, _) = item
            .attempts
            .iter()
            .enumerate()
            .max_by_key(|(_, (s, _))| s.started_at)?;
        let facts = Facts::of(item, i);
        for r in &self.rules {
            if r.when.iter().all(|(k, c)| facts.holds(k, c)) {
                return Some(Choice {
                    attempt: i,
                    decision: decision(r.decision, &r.reason),
                    rule: Some(r.name.clone()),
                    reason: format!("rule {}", r.name),
                });
            }
        }
        Some(Choice {
            attempt: i,
            decision: decision(self.default, "default"),
            rule: None,
            reason: "default".into(),
        })
    }
}

fn decision(k: Kind, reason: &str) -> Decision {
    match k {
        Kind::Sanction => Decision::Sanction,
        Kind::Hold => Decision::Hold,
        Kind::Never => Decision::Never {
            reason: reason.to_string(),
        },
    }
}

/// A Candidate's facts, by name.
struct Facts {
    nums: BTreeMap<String, u64>,
    words: BTreeMap<&'static str, &'static str>,
}

impl Facts {
    fn of(item: &PendingItem, newest: usize) -> Self {
        let f = &item.candidate.facts;
        let mut nums = BTreeMap::new();
        for (prefix, c) in [("input", &f.input), ("excluded", &f.excluded)] {
            let v = [
                c.source,
                c.config,
                c.hook,
                c.secret,
                c.scratch,
                c.artifact,
                c.unknown,
                c.structural,
                c.unsupported,
            ];
            for (name, n) in CLASSES.iter().zip(v) {
                nums.insert(format!("{prefix}_{name}"), n);
            }
        }
        nums.insert("open_obligations".into(), f.open_obligations);
        nums.insert("effects_adopted".into(), f.effects_adopted);
        nums.insert("attempts".into(), item.attempts.len() as u64);
        let outcome = &item.attempts[newest].1.outcome;
        if let Outcome::Exit { code } = outcome {
            nums.insert("exit_code".into(), u64::from(*code));
        }
        let mut words = BTreeMap::new();
        words.insert(
            "outcome",
            match outcome {
                Outcome::Exit { code: 0 } => "pass",
                Outcome::Exit { .. } => "fail",
                Outcome::Timeout => "timeout",
                Outcome::OutputLimit => "output_limit",
                Outcome::LaunchFailed => "launch_failed",
                Outcome::Interrupted => "interrupted",
            },
        );
        words.insert(
            "nominated_by",
            match item.candidate.nominated_by {
                NominatedBy::Agent => "agent",
                NominatedBy::Config => "config",
                NominatedBy::Supersede { .. } => "supersede",
            },
        );
        Self { nums, words }
    }

    fn holds(&self, fact: &str, c: &Cond) -> bool {
        match c {
            Cond::Num { min, max, eq } => match self.nums.get(fact) {
                None => false,
                Some(&n) => {
                    min.is_none_or(|m| n >= m)
                        && max.is_none_or(|m| n <= m)
                        && eq.is_none_or(|m| n == m)
                }
            },
            Cond::Word(list) => self
                .words
                .get(fact)
                .is_some_and(|w| list.iter().any(|x| x == w)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use taso_core::contract::ClassCounts;

    mod pending {
        include!("../tests/support/pending.rs");
    }
    use pending::{clean, item};

    const POLICY: &str = r#"
version = 1
actor = "taso-policy"
default = "hold"

[[rule]]
name = "no secrets"
decision = "never"
reason = "a secret is in the input"
when = { input_secret = { min = 1 } }

[[rule]]
name = "failed"
decision = "never"
when = { outcome = { in = ["fail", "timeout", "output_limit"] } }

[[rule]]
name = "passed"
decision = "sanction"
when = { outcome = "pass", input_unknown = 0, input_unsupported = { max = 0 }, input_source = { min = 1 } }
"#;

    fn p() -> Policy {
        Policy::parse(POLICY.as_bytes()).unwrap()
    }

    #[test]
    fn the_first_matching_rule_decides_on_the_newest_attempt() {
        let p = p();
        let pass = Outcome::Exit { code: 0 };
        let secret = ClassCounts {
            source: 3,
            secret: 1,
            ..ClassCounts::default()
        };
        let unknown = ClassCounts {
            source: 3,
            unknown: 2,
            ..ClassCounts::default()
        };
        // (item, rule, decision)
        let table = [
            (
                item(1, clean(3), &[pass]),
                Some("passed"),
                Decision::Sanction,
            ),
            (
                item(2, secret, &[pass]),
                Some("no secrets"),
                Decision::Never {
                    reason: "a secret is in the input".into(),
                },
            ),
            (
                item(3, clean(3), &[Outcome::Exit { code: 7 }]),
                Some("failed"),
                Decision::Never {
                    reason: "failed".into(),
                },
            ),
            (
                item(4, clean(3), &[Outcome::Timeout]),
                Some("failed"),
                Decision::Never {
                    reason: "failed".into(),
                },
            ),
            // Not listed: the default.
            (
                item(5, clean(3), &[Outcome::LaunchFailed]),
                None,
                Decision::Hold,
            ),
            (item(6, unknown, &[pass]), None, Decision::Hold),
            (item(7, clean(0), &[pass]), None, Decision::Hold),
            // The newest attempt decides: a pass after a failure, and back.
            (
                item(8, clean(3), &[Outcome::Exit { code: 1 }, pass]),
                Some("passed"),
                Decision::Sanction,
            ),
            (
                item(9, clean(3), &[pass, Outcome::Exit { code: 1 }]),
                Some("failed"),
                Decision::Never {
                    reason: "failed".into(),
                },
            ),
        ];
        for (it, rule, d) in table {
            let c = p.decide(&it).unwrap();
            assert_eq!(
                (c.rule.as_deref(), &c.decision),
                (rule, &d),
                "item {}",
                it.candidate.candidate_id
            );
            assert_eq!(c.attempt, it.attempts.len() - 1);
            assert_eq!(
                c.reason,
                rule.map_or("default".into(), |r| format!("rule {r}"))
            );
        }
        // No finished attempt: nothing to decide.
        assert_eq!(p.decide(&item(10, clean(3), &[])), None);
    }

    #[test]
    fn the_digest_is_the_files_blake3_and_the_defaults_hold() {
        let p = p();
        assert_eq!(
            p.digest.as_bytes(),
            blake3::hash(POLICY.as_bytes()).as_bytes()
        );
        assert_eq!(
            (p.actor.as_str(), p.default, p.rules.len()),
            ("taso-policy", Kind::Hold, 3)
        );
        let q = Policy::parse(b"version = 1\nactor = \"a\"\n").unwrap();
        assert_eq!((q.default, q.rules.len()), (Kind::Hold, 0));
        let c = q
            .decide(&item(1, clean(1), &[Outcome::Exit { code: 0 }]))
            .unwrap();
        assert_eq!((c.decision, c.rule), (Decision::Hold, None));
        // exit_code is a fact only for an Exit.
        let r = Policy::parse(
            b"version = 1\nactor = \"a\"\ndefault = \"never\"\n[[rule]]\nname = \"seven\"\ndecision = \"hold\"\nwhen = { exit_code = 7 }\n",
        )
        .unwrap();
        let held = r
            .decide(&item(1, clean(1), &[Outcome::Exit { code: 7 }]))
            .unwrap();
        assert_eq!(held.rule.as_deref(), Some("seven"));
        let timeout = r.decide(&item(1, clean(1), &[Outcome::Timeout])).unwrap();
        assert_eq!(
            (timeout.rule, timeout.decision),
            (
                None,
                Decision::Never {
                    reason: "default".into()
                }
            )
        );
    }

    #[test]
    fn a_policy_that_does_not_say_what_it_means_is_refused() {
        let head = "version = 1\nactor = \"a\"\n";
        let rule = |body: &str| format!("{head}[[rule]]\nname = \"r\"\n{body}\n");
        for (text, why) in [
            ("actor = \"a\"\n".to_string(), "version"),
            ("version = 2\nactor = \"a\"\n".into(), "version"),
            ("version = 1\n".into(), "actor"),
            (format!("{head}colour = 1\n"), "unknown key"),
            (format!("{head}default = \"maybe\"\n"), "not a decision"),
            (rule("decision = \"sanction\"\nwhen = { input_secrets = 0 }"), "not a fact"),
            (rule("decision = \"sanction\"\nwhen = { outcome = \"passed\" }"), "not one of"),
            (rule("decision = \"sanction\"\nwhen = { outcome = 0 }"), "a word"),
            (rule("decision = \"sanction\"\nwhen = { attempts = \"one\" }"), "a number"),
            (rule("decision = \"sanction\"\nwhen = { attempts = { least = 1 } }"), "unknown key"),
            (rule("decision = \"sanction\"\nwhen = { attempts = { min = -1 } }"), "non-negative"),
            (rule("decision = \"sanction\"\nwhen = { attempts = {} }"), "empty"),
            (rule("when = { attempts = 1 }"), "decision is needed"),
            (rule("decision = \"hold\"\nreason = \"x\""), "never rule only"),
            (rule("decision = \"never\"\nwhy = \"x\""), "unknown key"),
            (
                format!("{head}[[rule]]\nname = \"r\"\ndecision = \"hold\"\n[[rule]]\nname = \"r\"\ndecision = \"hold\"\n"),
                "used twice",
            ),
            ("version = 1\nactor = \"a\"\nrule = 1\n".into(), "array of tables"),
            ("version = [\n".into(), ""),
        ] {
            let e = Policy::parse(text.as_bytes()).unwrap_err();
            assert!(e.0.contains(why), "{text:?}: {e}");
        }
        assert!(Policy::parse(&[0xff, 0xfe]).is_err());
    }
}
