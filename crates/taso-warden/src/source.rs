//! Where a long-running Warden learns which Vessels to run (W1; plan:
//! claude/Taso_plan_k8s_docker_2026-10-17.md).
//!
//! A [`VesselSource`] reports the set of Vessels this Warden should run
//! — the daemon config's list today ([`StaticSource`]), a Kubernetes watch
//! later.  The supervisor compares that set with what runs and acts on the
//! difference.
//!
//! # Nothing from a source is trusted
//!
//! A source is outside input.  Every set it reports goes through a
//! [`Guard`] before anything acts on it, and the guard enforces the
//! invariants itself, whatever the source (or a CRD in front of it) claims
//! to have checked:
//!
//! - **One entry per Vessel id**, and a slot range that fits above the
//!   node's `host_uid_base`.
//! - **No two Vessels share a uid slot** — not at once, and not over time:
//!   a slot once admitted for one Vessel stays bound to it for the life of
//!   this Warden, also after that Vessel is removed (its files on the node
//!   are owned by that range).
//! - **Immutable once admitted:** a Vessel's uid slot never changes for the
//!   life of this Warden, also across a removal and a return (its dataset's
//!   files are owned by its range); an entry that tries is refused.
//! - **Deterministic:** when two new entries want the same slot, the one with
//!   the smaller Vessel id gets it, whatever order the source lists them in.
//! - **A bad entry hurts only itself:** a new entry that fails is not
//!   admitted; an admitted Vessel whose new entry fails keeps its last good
//!   entry (it is neither changed nor stopped).  Every refusal is reported
//!   with its reason.
//!
//! And a source that **fails** changes nothing: [`VesselSource::poll`]
//! returning an error means "unknown", never "empty"; running Vessels stay
//! as they are.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use crate::daemon::{RuntimeConf, VesselConf};

/// Why a source could not answer.  The caller keeps what it had.
#[derive(Debug)]
pub struct SourceError(pub String);

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vessel source: {}", self.0)
    }
}

impl std::error::Error for SourceError {}

/// The Vessels a Warden should run.
pub trait VesselSource: Send {
    /// The whole set to run now, if it changed since the last call
    /// (`Ok(None)`: unchanged).  Waits at most `wait` for a change.  An
    /// error means the source could not tell: the caller changes nothing.
    fn poll(&mut self, wait: Duration) -> Result<Option<Vec<VesselConf>>, SourceError>;

    /// True if the set never changes after its first answer.  Only then may
    /// a Warden exit once every Vessel is done (today's `taso-wardend`).
    fn is_finite(&self) -> bool;
}

/// The daemon config's `vessels` list: answered once, then unchanged.
#[derive(Debug)]
pub struct StaticSource {
    vessels: Option<Vec<VesselConf>>,
}

impl StaticSource {
    /// A source that reports `vessels` once.
    pub fn new(vessels: Vec<VesselConf>) -> Self {
        Self { vessels: Some(vessels) }
    }
}

impl VesselSource for StaticSource {
    fn poll(&mut self, wait: Duration) -> Result<Option<Vec<VesselConf>>, SourceError> {
        match self.vessels.take() {
            Some(v) => Ok(Some(v)),
            None => {
                // Nothing will ever change; do not make the caller spin.
                std::thread::sleep(wait);
                Ok(None)
            }
        }
    }

    fn is_finite(&self) -> bool {
        true
    }
}

/// A Vessel's key: its Chronicle id.
pub type VesselKey = [u8; 16];

/// An entry the [`Guard`] did not take as given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    /// The entry's subject (its Vessel id may be shared with another entry).
    pub subject: String,
    /// The entry's Vessel id.
    pub key: VesselKey,
    /// Why.
    pub reason: String,
    /// The Vessel keeps running with its last admitted entry.
    pub kept_previous: bool,
}

/// What a [`Guard`] made of a proposed set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Admitted {
    /// The set to run: admitted entries, plus the last good entry of every
    /// admitted Vessel whose new entry was refused.  Sorted by key.
    pub set: Vec<VesselConf>,
    /// What was refused, and why.
    pub refused: Vec<Refused>,
}

/// Checks every set a source reports (see the module docs).
#[derive(Debug)]
pub struct Guard {
    runtime: RuntimeConf,
    /// The Vessels in the current set: their last good entry.
    running: BTreeMap<VesselKey, VesselConf>,
    /// Every Vessel ever admitted and its slot, for good (both directions).
    bound: BTreeMap<VesselKey, u32>,
    slots: BTreeMap<u32, VesselKey>,
}

impl Guard {
    /// A guard for a node whose runtime is `runtime` (its `host_uid_base`
    /// decides which slots fit).
    pub fn new(runtime: RuntimeConf) -> Self {
        Self { runtime, running: BTreeMap::new(), bound: BTreeMap::new(), slots: BTreeMap::new() }
    }

    /// Check a proposed set against the invariants and against everything
    /// admitted before.  Never fails: what does not pass is refused and
    /// reported, the rest is admitted.
    pub fn admit(&mut self, proposed: Vec<VesselConf>) -> Admitted {
        let mut refused = Vec::new();
        let mut refuse = |vc: &VesselConf, key: VesselKey, reason: String, running: &BTreeMap<VesselKey, VesselConf>| {
            refused.push(Refused {
                subject: vc.subject.clone(),
                key,
                reason,
                kept_previous: running.contains_key(&key),
            });
        };

        // Entries naming the same Vessel twice: none of them is taken.
        let mut count: BTreeMap<VesselKey, usize> = BTreeMap::new();
        for vc in &proposed {
            *count.entry(*vc.id().as_bytes()).or_default() += 1;
        }

        let mut set: BTreeMap<VesselKey, VesselConf> = BTreeMap::new();
        let mut slots_now: BTreeMap<u32, VesselKey> = BTreeMap::new();
        // By Vessel id, so the outcome does not depend on the source's order.
        // (A newcomer can never take a bound slot: see `slots` below.)
        let mut ordered: Vec<&VesselConf> = proposed.iter().collect();
        ordered.sort_by_key(|vc| *vc.id().as_bytes());
        for vc in ordered {
            let key = *vc.id().as_bytes();
            if count[&key] > 1 {
                refuse(vc, key, format!("vessel {:?} is listed {} times", vc.subject, count[&key]), &self.running);
                continue;
            }
            if vc.host_uid(&self.runtime).is_none() {
                refuse(vc, key, format!("uid_slot {} does not fit above host_uid_base {}", vc.uid_slot, self.runtime.host_uid_base), &self.running);
                continue;
            }
            if let Some(&slot) = self.bound.get(&key) {
                if slot != vc.uid_slot {
                    refuse(vc, key, format!("uid_slot is fixed once admitted: {} stays {}, not {}", vc.subject, slot, vc.uid_slot), &self.running);
                    continue;
                }
            }
            if let Some(owner) = self.slots.get(&vc.uid_slot) {
                if *owner != key {
                    refuse(vc, key, format!("uid_slot {} is bound to another Vessel on this node", vc.uid_slot), &self.running);
                    continue;
                }
            }
            if let Some(other) = slots_now.get(&vc.uid_slot) {
                if *other != key {
                    refuse(vc, key, format!("uid_slot {} is taken by another entry in this set", vc.uid_slot), &self.running);
                    continue;
                }
            }
            slots_now.insert(vc.uid_slot, key);
            set.insert(key, vc.clone());
        }

        // A refused entry of an admitted Vessel: its last good entry stays.
        for r in &refused {
            if r.kept_previous {
                let prev = self.running[&r.key].clone();
                slots_now.insert(prev.uid_slot, r.key);
                set.entry(r.key).or_insert(prev);
            }
        }

        // Record what runs now; bindings are kept for good.
        for (key, vc) in &set {
            self.slots.entry(vc.uid_slot).or_insert(*key);
            self.bound.entry(*key).or_insert(vc.uid_slot);
        }
        self.running = set.clone();

        Admitted { set: set.into_values().collect(), refused }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::Restart;
    use taso_core::record::Namespace;

    fn runtime() -> RuntimeConf {
        RuntimeConf {
            rootfs: "/srv/taso/rootfs".into(),
            host_uid_base: 200_000,
            landlock_shim: None,
            args: vec!["/agent".into()],
            env: vec![],
            memory_bytes: None,
            pids: None,
        }
    }

    fn vc(subject: &str, slot: u32) -> VesselConf {
        VesselConf {
            namespace: Namespace::from_bytes([7; 16]),
            subject: subject.into(),
            takeover: false,
            uid_slot: slot,
            restart: Restart::Never,
        }
    }

    fn subjects(a: &Admitted) -> Vec<(String, u32)> {
        let mut v: Vec<_> = a.set.iter().map(|v| (v.subject.clone(), v.uid_slot)).collect();
        v.sort();
        v
    }

    fn reasons(a: &Admitted) -> Vec<(String, bool)> {
        let mut v: Vec<_> = a.refused.iter().map(|r| (r.subject.clone(), r.kept_previous)).collect();
        v.sort();
        v
    }

    #[test]
    fn static_source_answers_once_and_is_finite() {
        let mut s = StaticSource::new(vec![vc("a", 0)]);
        assert!(s.is_finite());
        assert_eq!(s.poll(Duration::ZERO).unwrap(), Some(vec![vc("a", 0)]));
        assert_eq!(s.poll(Duration::ZERO).unwrap(), None);
        assert_eq!(s.poll(Duration::from_millis(1)).unwrap(), None);
    }

    #[test]
    fn a_good_set_is_admitted_whole() {
        let mut g = Guard::new(runtime());
        let a = g.admit(vec![vc("b", 1), vc("a", 0)]);
        assert_eq!(subjects(&a), vec![("a".into(), 0), ("b".into(), 1)]);
        assert!(a.refused.is_empty());
    }

    #[test]
    fn a_vessel_listed_twice_is_not_taken() {
        let mut g = Guard::new(runtime());
        let a = g.admit(vec![vc("a", 0), vc("a", 1), vc("b", 2)]);
        assert_eq!(subjects(&a), vec![("b".into(), 2)]);
        assert_eq!(reasons(&a), vec![("a".into(), false), ("a".into(), false)]);
    }

    #[test]
    fn a_slot_that_does_not_fit_is_refused() {
        let mut g = Guard::new(runtime());
        let a = g.admit(vec![vc("a", 65_535), vc("b", 0)]);
        assert_eq!(subjects(&a), vec![("b".into(), 0)]);
        assert!(a.refused[0].reason.contains("does not fit"), "{:?}", a.refused);
    }

    /// Two new entries on one slot: one runs, and which one does not depend
    /// on the order the source lists them in.
    #[test]
    fn two_entries_on_one_slot_only_one_runs_deterministically() {
        let first = Guard::new(runtime()).admit(vec![vc("a", 3), vc("b", 3)]);
        let second = Guard::new(runtime()).admit(vec![vc("b", 3), vc("a", 3)]);
        assert_eq!(first.set.len(), 1);
        assert_eq!(first.refused.len(), 1);
        assert!(first.refused[0].reason.contains("taken by another entry"));
        assert_eq!(first.set, second.set, "the same one wins in either order");
        assert_eq!(first.refused, second.refused);
    }

    /// An admitted Vessel keeps its slot; a changed slot is refused and the
    /// Vessel keeps running with its last good entry.
    #[test]
    fn a_slot_is_fixed_once_admitted() {
        let mut g = Guard::new(runtime());
        g.admit(vec![vc("a", 3)]);
        let a = g.admit(vec![vc("a", 4)]);
        assert_eq!(subjects(&a), vec![("a".into(), 3)], "still running as it was");
        assert_eq!(reasons(&a), vec![("a".into(), true)]);
        assert!(a.refused[0].reason.contains("fixed once admitted"));
        // And the next good answer is taken as usual.
        let a = g.admit(vec![vc("a", 3)]);
        assert_eq!(subjects(&a), vec![("a".into(), 3)]);
        assert!(a.refused.is_empty());
    }

    /// A newcomer never displaces an admitted Vessel from its slot, even if
    /// it sorts first.
    #[test]
    fn a_newcomer_never_takes_an_admitted_slot() {
        let mut g = Guard::new(runtime());
        g.admit(vec![vc("zz", 5)]);
        for order in [vec![vc("aa", 5), vc("zz", 5)], vec![vc("zz", 5), vc("aa", 5)]] {
            let a = g.admit(order);
            assert_eq!(subjects(&a), vec![("zz".into(), 5)]);
            assert_eq!(reasons(&a), vec![("aa".into(), false)]);
        }
    }

    /// A slot stays bound to its Vessel after that Vessel is removed: its
    /// files are owned by that range.  The Vessel itself may come back on it.
    #[test]
    fn a_removed_vessels_slot_is_never_reused_by_another() {
        let mut g = Guard::new(runtime());
        g.admit(vec![vc("a", 3)]);
        let a = g.admit(vec![]);
        assert!(a.set.is_empty(), "a is removed");
        let a = g.admit(vec![vc("b", 3)]);
        assert!(a.set.is_empty());
        assert!(a.refused[0].reason.contains("bound to another Vessel"));
        let a = g.admit(vec![vc("a", 3)]);
        assert_eq!(subjects(&a), vec![("a".into(), 3)], "a comes back on its own slot");
    }

    /// A removed Vessel that comes back keeps its slot: on another one, its
    /// dataset's files (owned by the old range) would not match.  And a bad
    /// entry for a removed Vessel does not bring it back.
    #[test]
    fn a_returning_vessel_keeps_its_slot_and_a_bad_entry_does_not_revive_it() {
        let mut g = Guard::new(runtime());
        g.admit(vec![vc("a", 3)]);
        g.admit(vec![]);
        let a = g.admit(vec![vc("a", 4)]);
        assert!(a.set.is_empty(), "not on slot 4: {a:?}");
        assert_eq!(reasons(&a), vec![("a".into(), false)], "refused, nothing kept: it was not running");
        assert!(a.refused[0].reason.contains("fixed once admitted"));
        assert!(g.admit(vec![vc("b", 4)]).refused.is_empty(), "slot 4 was never bound to a");
    }

    /// A refused entry of an admitted Vessel does not stop it, even when it
    /// is listed twice in the new set.
    #[test]
    fn a_bad_entry_never_stops_a_running_vessel() {
        let mut g = Guard::new(runtime());
        g.admit(vec![vc("a", 1), vc("b", 2)]);
        let a = g.admit(vec![vc("a", 1), vc("a", 1), vc("b", 9)]);
        assert_eq!(subjects(&a), vec![("a".into(), 1), ("b".into(), 2)]);
        assert_eq!(reasons(&a), vec![("a".into(), true), ("a".into(), true), ("b".into(), true)]);
    }

    /// Removal is explicit: an admitted Vessel missing from a good set is
    /// removed; one whose entry is refused is not.
    #[test]
    fn only_a_missing_entry_removes() {
        let mut g = Guard::new(runtime());
        g.admit(vec![vc("a", 1), vc("b", 2)]);
        let a = g.admit(vec![vc("b", 2)]);
        assert_eq!(subjects(&a), vec![("b".into(), 2)]);
    }

    /// Other fields of an admitted Vessel may change (restart policy,
    /// takeover): only identity and slot are fixed.
    #[test]
    fn non_identity_fields_may_change() {
        let mut g = Guard::new(runtime());
        g.admit(vec![vc("a", 1)]);
        let mut changed = vc("a", 1);
        changed.restart = Restart::Always;
        let a = g.admit(vec![changed.clone()]);
        assert_eq!(a.set, vec![changed]);
        assert!(a.refused.is_empty());
    }
}
