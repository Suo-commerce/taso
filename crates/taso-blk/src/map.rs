//! The block map: for every branch and Seal, where each block's bytes are.
//!
//! A device is a stack of **layers**.  The bottom is the base image (the
//! Template's ext4 image, outside this map).  Above it sit **Seals**:
//! frozen layers, each holding the blocks written between its parent Seal
//! and itself.  On top of a Seal sits a **branch**: the one mutable layer,
//! holding what the branch wrote since its Seal.
//!
//! ```text
//!   branch b2 ─┐        branch b1 ── tail: blocks b1 wrote
//!              │            │
//!              └── Seal S2 ─┘   ← frozen: blocks written before S2
//!                    │
//!                 Seal S1       ← frozen
//!                    │
//!                 base image    (outside the map)
//! ```
//!
//! - **Read** walks up from a layer: the first layer that has the block
//!   answers; if none has it, the base image does.
//! - **Write** goes to the branch's own layer only.  Nothing below changes.
//! - **Fork** from a Seal makes a new, empty branch whose parent is that
//!   Seal.  No block is copied: cost does not depend on the device's size.
//! - **Seal** a branch: its layer is frozen as a new Seal (moved, not
//!   copied), and the branch continues with an empty layer on top of it.
//! - **Discard** (TRIM) records [`Loc::Zero`], which hides the parent's
//!   block: the device reads zeros there.
//! - **Drop** a branch, or a Seal with no children: its own blocks are
//!   returned as garbage for the store to reclaim.
//!
//! Every log location the store hands to [`Map::write`] belongs to exactly
//! one layer.  It comes back as garbage exactly once: when it is
//! overwritten or discarded in that same branch layer, or when its layer is
//! dropped.  A location still reachable from a live layer is never garbage.
//! (Property-tested below: no leak, no double free.)
//!
//! This module is pure: no I/O, no clock.  The store (`store.rs`) journals
//! every call, so replaying the journal rebuilds the same map with the same
//! ids.  Ids are assigned in call order for that reason.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

/// Logical block size: what ext4 and the device agree a block is.
pub const BLOCK: u64 = 4096;

/// A layer: a branch or a Seal.  Assigned in call order, never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LayerId(u64);

impl LayerId {
    /// The id as a number (for records and logs).
    pub fn get(self) -> u64 {
        self.0
    }

    /// The id a record names, read back from the log.  Only the store
    /// makes ids from numbers, and only ones the map gave out.
    pub(crate) fn from_raw(n: u64) -> Self {
        Self(n)
    }
}

impl fmt::Display for LayerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L{}", self.0)
    }
}

/// Where a block's bytes are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Loc {
    /// In the store's data log, at this byte offset.
    Log(u64),
    /// Zeros (discarded or written as zeros).  Hides any parent block.
    Zero,
}

/// What a layer is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The one mutable layer of a branch.
    Branch,
    /// A frozen layer, taken at a flush point.
    Seal {
        /// The log position (the FlushRecord's LSN) this Seal stands for.
        lsn: u64,
    },
}

/// Why a map operation was refused.  A refused operation changes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MapError {
    /// No such layer (never made, or dropped).
    Unknown(LayerId),
    /// The layer is a Seal; Seals never change.
    NotABranch(LayerId),
    /// Forks start only from Seals: a branch is still changing.
    NotASeal(LayerId),
    /// The Seal still has branches or Seals on top of it.
    HasChildren(LayerId),
    /// A block range runs past the end of the address space.
    Overflow,
}

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(l) => write!(f, "no layer {l}"),
            Self::NotABranch(l) => write!(f, "{l} is a Seal; Seals never change"),
            Self::NotASeal(l) => write!(f, "{l} is a branch; fork from a Seal"),
            Self::HasChildren(l) => write!(f, "{l} still has layers on top of it"),
            Self::Overflow => write!(f, "block range overflows"),
        }
    }
}

impl std::error::Error for MapError {}

struct Layer {
    kind: Kind,
    parent: Option<LayerId>,
    /// Blocks this layer itself holds, by logical block address.
    blocks: BTreeMap<u64, Loc>,
    /// Layers whose parent is this one.
    children: u32,
    /// Layers below this one, base image not counted (a root Seal is 0).
    depth: u32,
}

/// The block map of one Template's devices: its Seals and branches.
#[derive(Default)]
pub struct Map {
    layers: HashMap<LayerId, Layer>,
    next: u64,
}

impl Map {
    /// An empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// A root Seal: nothing on top of the base image yet.  A Template's
    /// first Seal, which every Vessel of it forks from.
    pub fn root_seal(&mut self, lsn: u64) -> LayerId {
        self.insert(Kind::Seal { lsn }, None, BTreeMap::new())
    }

    /// A new, empty branch on top of `seal`.  No block is copied.
    pub fn fork(&mut self, seal: LayerId) -> Result<LayerId, MapError> {
        match self.layer(seal)?.kind {
            Kind::Seal { .. } => {}
            Kind::Branch => return Err(MapError::NotASeal(seal)),
        }
        Ok(self.insert(Kind::Branch, Some(seal), BTreeMap::new()))
    }

    /// Where block `lba` of `layer` is.  `None`: in the base image.
    pub fn read(&self, layer: LayerId, lba: u64) -> Result<Option<Loc>, MapError> {
        let mut l = self.layer(layer)?;
        // A chain is never longer than the number of layers.  If it were,
        // it would be a cycle, a bug: fail loudly rather than loop forever.
        for _ in 0..=self.layers.len() {
            if let Some(loc) = l.blocks.get(&lba) {
                return Ok(Some(*loc));
            }
            match l.parent {
                // A parent outlives its children (drop_seal refuses otherwise).
                Some(p) => l = &self.layers[&p],
                None => return Ok(None),
            }
        }
        panic!("block map: parent chain of {layer} is a cycle");
    }

    /// Branch `branch` now has block `lba` at `loc`.  Returns what this
    /// call made garbage: the branch's own previous location for `lba`, if
    /// it had one in the log.  A parent's block is hidden, never garbage.
    pub fn write(&mut self, branch: LayerId, lba: u64, loc: Loc) -> Result<Option<u64>, MapError> {
        let l = self.branch_mut(branch)?;
        Ok(match l.blocks.insert(lba, loc) {
            Some(Loc::Log(off)) => Some(off),
            _ => None,
        })
    }

    /// Discard `count` blocks from `lba`: they read as zeros.  Returns the
    /// branch's own log locations this made garbage.
    pub fn discard(&mut self, branch: LayerId, lba: u64, count: u64) -> Result<Vec<u64>, MapError> {
        let end = lba.checked_add(count).ok_or(MapError::Overflow)?;
        let l = self.branch_mut(branch)?;
        let mut garbage = Vec::new();
        for b in lba..end {
            if let Some(Loc::Log(off)) = l.blocks.insert(b, Loc::Zero) {
                garbage.push(off);
            }
        }
        Ok(garbage)
    }

    /// Freeze `branch`'s layer as a new Seal at `lsn`.  The layer is moved,
    /// not copied; the branch continues with an empty layer on top of the
    /// new Seal.  Returns the new Seal.
    pub fn seal(&mut self, branch: LayerId, lsn: u64) -> Result<LayerId, MapError> {
        let l = self.branch_mut(branch)?;
        let blocks = std::mem::take(&mut l.blocks);
        let parent = l.parent;
        // The new Seal takes the branch's place on its old parent: the old
        // parent's child count is unchanged.
        let seal = LayerId(self.next);
        self.next += 1;
        let depth = parent.map_or(0, |p| self.layers[&p].depth + 1);
        self.layers.insert(seal, Layer { kind: Kind::Seal { lsn }, parent, blocks, children: 1, depth });
        let b = self.layers.get_mut(&branch).expect("checked above");
        b.parent = Some(seal);
        b.depth = depth + 1;
        Ok(seal)
    }

    /// Drop a branch.  Returns its own log locations, now garbage.
    pub fn drop_branch(&mut self, branch: LayerId) -> Result<Vec<u64>, MapError> {
        self.branch_mut(branch)?;
        Ok(self.remove(branch))
    }

    /// Drop a Seal that nothing stands on.  Returns its own log locations,
    /// now garbage.
    pub fn drop_seal(&mut self, seal: LayerId) -> Result<Vec<u64>, MapError> {
        let l = self.layer(seal)?;
        match l.kind {
            Kind::Branch => return Err(MapError::NotASeal(seal)),
            Kind::Seal { .. } if l.children > 0 => return Err(MapError::HasChildren(seal)),
            Kind::Seal { .. } => {}
        }
        Ok(self.remove(seal))
    }

    /// What `layer` is.
    pub fn kind(&self, layer: LayerId) -> Result<Kind, MapError> {
        Ok(self.layer(layer)?.kind)
    }

    /// `layer`'s parent; `None` for a root Seal.
    pub fn parent(&self, layer: LayerId) -> Result<Option<LayerId>, MapError> {
        Ok(self.layer(layer)?.parent)
    }

    /// How many layers a cold read of `layer` may walk before the base
    /// image (itself included).  What flattening keeps small.
    pub fn depth(&self, layer: LayerId) -> Result<u32, MapError> {
        Ok(self.layer(layer)?.depth + 1)
    }

    /// How many blocks `layer` itself holds.
    pub fn len(&self, layer: LayerId) -> Result<usize, MapError> {
        Ok(self.layer(layer)?.blocks.len())
    }

    /// True if `layer` holds no blocks itself.
    pub fn is_empty(&self, layer: LayerId) -> Result<bool, MapError> {
        Ok(self.layer(layer)?.blocks.is_empty())
    }

    /// The blocks `layer` itself holds, in address order: a Seal's delta
    /// over its parent (what ships for it).
    pub fn delta(&self, layer: LayerId) -> Result<impl Iterator<Item = (u64, Loc)> + '_, MapError> {
        Ok(self.layer(layer)?.blocks.iter().map(|(b, l)| (*b, *l)))
    }

    /// Live layers.
    pub fn layers(&self) -> usize {
        self.layers.len()
    }

    // ── internals ───────────────────────────────────────────────────

    fn insert(&mut self, kind: Kind, parent: Option<LayerId>, blocks: BTreeMap<u64, Loc>) -> LayerId {
        let id = LayerId(self.next);
        self.next += 1;
        let depth = match parent {
            Some(p) => {
                let pl = self.layers.get_mut(&p).expect("parent checked by caller");
                pl.children += 1;
                pl.depth + 1
            }
            None => 0,
        };
        self.layers.insert(id, Layer { kind, parent, blocks, children: 0, depth });
        id
    }

    fn remove(&mut self, id: LayerId) -> Vec<u64> {
        let l = self.layers.remove(&id).expect("checked by caller");
        if let Some(p) = l.parent {
            self.layers.get_mut(&p).expect("a parent outlives its children").children -= 1;
        }
        l.blocks
            .into_values()
            .filter_map(|loc| match loc {
                Loc::Log(off) => Some(off),
                Loc::Zero => None,
            })
            .collect()
    }

    fn layer(&self, id: LayerId) -> Result<&Layer, MapError> {
        self.layers.get(&id).ok_or(MapError::Unknown(id))
    }

    fn branch_mut(&mut self, id: LayerId) -> Result<&mut Layer, MapError> {
        let l = self.layers.get_mut(&id).ok_or(MapError::Unknown(id))?;
        match l.kind {
            Kind::Branch => Ok(l),
            Kind::Seal { .. } => Err(MapError::NotABranch(id)),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::{BTreeSet, HashSet};

    fn log(o: u64) -> Loc {
        Loc::Log(o)
    }

    #[test]
    fn a_fork_reads_through_to_its_seal_and_the_base() {
        let mut m = Map::new();
        let s = m.root_seal(0);
        let b = m.fork(s).unwrap();
        assert_eq!(m.read(b, 7).unwrap(), None, "nothing written: the base image");
        assert_eq!(m.depth(b).unwrap(), 2);
        assert_eq!(m.kind(b).unwrap(), Kind::Branch);
        assert_eq!(m.parent(b).unwrap(), Some(s));
    }

    #[test]
    fn writes_stay_in_their_branch() {
        let mut m = Map::new();
        let s = m.root_seal(0);
        let (a, b) = (m.fork(s).unwrap(), m.fork(s).unwrap());
        assert_eq!(m.write(a, 1, log(100)).unwrap(), None);
        assert_eq!(m.read(a, 1).unwrap(), Some(log(100)));
        assert_eq!(m.read(b, 1).unwrap(), None, "a sibling never sees it");
        assert_eq!(m.read(s, 1).unwrap(), None, "the Seal never changes");
    }

    #[test]
    fn seals_never_change() {
        let mut m = Map::new();
        let s = m.root_seal(0);
        assert_eq!(m.write(s, 0, log(1)), Err(MapError::NotABranch(s)));
        assert_eq!(m.discard(s, 0, 1), Err(MapError::NotABranch(s)));
        assert_eq!(m.seal(s, 1), Err(MapError::NotABranch(s)));
        assert_eq!(m.drop_branch(s), Err(MapError::NotABranch(s)));
    }

    #[test]
    fn forks_start_only_from_seals() {
        let mut m = Map::new();
        let s = m.root_seal(0);
        let b = m.fork(s).unwrap();
        assert_eq!(m.fork(b), Err(MapError::NotASeal(b)));
        assert_eq!(m.drop_seal(b), Err(MapError::NotASeal(b)));
    }

    #[test]
    fn sealing_freezes_the_layer_and_the_branch_goes_on() {
        let mut m = Map::new();
        let s1 = m.root_seal(0);
        let b = m.fork(s1).unwrap();
        let old = m.fork(s1).unwrap();
        m.write(b, 1, log(10)).unwrap();
        let s2 = m.seal(b, 42).unwrap();
        assert_eq!(m.kind(s2).unwrap(), Kind::Seal { lsn: 42 });
        assert_eq!(m.parent(s2).unwrap(), Some(s1));
        assert_eq!(m.parent(b).unwrap(), Some(s2));
        assert!(m.is_empty(b).unwrap(), "the branch starts a fresh layer");
        assert_eq!(m.len(s2).unwrap(), 1);
        assert_eq!(m.depth(b).unwrap(), 3);

        // Writing on: the new Seal keeps what it had.
        m.write(b, 1, log(11)).unwrap();
        assert_eq!(m.read(b, 1).unwrap(), Some(log(11)));
        assert_eq!(m.read(s2, 1).unwrap(), Some(log(10)));

        // A fork of the new Seal sees the sealed block; a fork of the old
        // Seal never did.
        let c = m.fork(s2).unwrap();
        assert_eq!(m.read(c, 1).unwrap(), Some(log(10)));
        assert_eq!(m.read(old, 1).unwrap(), None);
        assert_eq!(m.delta(s2).unwrap().collect::<Vec<_>>(), vec![(1, log(10))]);
    }

    #[test]
    fn discard_hides_the_parent_and_frees_only_own_blocks() {
        let mut m = Map::new();
        let s1 = m.root_seal(0);
        let b = m.fork(s1).unwrap();
        m.write(b, 1, log(10)).unwrap();
        m.write(b, 2, log(20)).unwrap();
        m.seal(b, 1).unwrap();
        m.write(b, 2, log(21)).unwrap();
        // Block 1 is in the Seal (hidden, not freed); block 2's 21 is the
        // branch's own (freed); block 3 was never written.
        assert_eq!(m.discard(b, 1, 3).unwrap(), vec![21]);
        for lba in 1..4 {
            assert_eq!(m.read(b, lba).unwrap(), Some(Loc::Zero));
        }
        assert_eq!(m.discard(b, u64::MAX, 2), Err(MapError::Overflow));
    }

    #[test]
    fn overwrite_returns_only_the_branchs_own_old_location() {
        let mut m = Map::new();
        let s = m.root_seal(0);
        let b = m.fork(s).unwrap();
        assert_eq!(m.write(b, 5, log(1)).unwrap(), None);
        assert_eq!(m.write(b, 5, log(2)).unwrap(), Some(1));
        assert_eq!(m.write(b, 5, Loc::Zero).unwrap(), Some(2));
        assert_eq!(m.write(b, 5, log(3)).unwrap(), None, "zeros held no log space");
    }

    #[test]
    fn dropping_returns_own_blocks_and_respects_children() {
        let mut m = Map::new();
        let s1 = m.root_seal(0);
        let b = m.fork(s1).unwrap();
        m.write(b, 1, log(10)).unwrap();
        let s2 = m.seal(b, 1).unwrap();
        m.write(b, 2, log(20)).unwrap();
        m.discard(b, 3, 1).unwrap();
        assert_eq!(m.drop_seal(s2), Err(MapError::HasChildren(s2)));
        assert_eq!(m.drop_seal(s1), Err(MapError::HasChildren(s1)));
        assert_eq!(m.drop_branch(b).unwrap(), vec![20], "zeros are not garbage");
        assert_eq!(m.drop_seal(s1), Err(MapError::HasChildren(s1)), "s2 stands on it");
        assert_eq!(m.drop_seal(s2).unwrap(), vec![10]);
        assert_eq!(m.drop_seal(s1).unwrap(), Vec::<u64>::new());
        assert_eq!(m.layers(), 0);
        assert_eq!(m.read(b, 1), Err(MapError::Unknown(b)));
    }

    #[test]
    fn ids_follow_call_order_and_are_never_reused() {
        let mut m = Map::new();
        let s = m.root_seal(0);
        let b = m.fork(s).unwrap();
        m.drop_branch(b).unwrap();
        let c = m.fork(s).unwrap();
        assert_eq!((s.get(), b.get(), c.get()), (0, 1, 2));
        let mut again = Map::new();
        let s_ = again.root_seal(0);
        let b_ = again.fork(s_).unwrap();
        again.drop_branch(b_).unwrap();
        assert_eq!(again.fork(s_).unwrap(), c, "same calls, same ids: replay rebuilds the same map");
    }

    #[test]
    fn fork_cost_does_not_depend_on_what_the_seal_holds() {
        let mut m = Map::new();
        let s = m.root_seal(0);
        let b = m.fork(s).unwrap();
        for lba in 0..100_000 {
            m.write(b, lba, log(lba * BLOCK)).unwrap();
        }
        let big = m.seal(b, 1).unwrap();
        let f = m.fork(big).unwrap();
        assert!(m.is_empty(f).unwrap(), "a fork holds nothing until it writes");
        assert_eq!(m.read(f, 99_999).unwrap(), Some(log(99_999 * BLOCK)));
    }

    // ── model-based property test ───────────────────────────────────
    //
    // The model materialises every layer: a branch is a full copy of what
    // it reads, copied on fork.  The map must answer every read the same
    // way, never leak a log location and never free one twice.

    #[derive(Clone, Debug)]
    enum Op {
        Fork(usize),
        Write(usize, u64),
        Discard(usize, u64, u64),
        Seal(usize),
        DropBranch(usize),
        DropSeal(usize),
    }

    fn op() -> impl Strategy<Value = Op> {
        let ix = 0usize..8;
        let lba = 0u64..16;
        prop_oneof![
            2 => ix.clone().prop_map(Op::Fork),
            6 => (ix.clone(), lba.clone()).prop_map(|(i, b)| Op::Write(i, b)),
            1 => (ix.clone(), lba, 0u64..4).prop_map(|(i, b, n)| Op::Discard(i, b, n)),
            2 => ix.clone().prop_map(Op::Seal),
            1 => ix.clone().prop_map(Op::DropBranch),
            1 => ix.prop_map(Op::DropSeal),
        ]
    }

    /// What a layer reads as: block -> Some(loc) or the base image (absent).
    type Image = BTreeMap<u64, Loc>;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn the_map_matches_a_materialised_model(ops in proptest::collection::vec(op(), 1..120)) {
            let mut m = Map::new();
            let root = m.root_seal(0);
            let mut model: BTreeMap<LayerId, Image> = BTreeMap::new();
            model.insert(root, Image::new());
            let mut next_off = 0u64;
            let mut handed: BTreeSet<u64> = BTreeSet::new();
            let mut freed: HashSet<u64> = HashSet::new();
            let free = |g: Vec<u64>, freed: &mut HashSet<u64>| {
                for o in g {
                    assert!(freed.insert(o), "log location {o} freed twice");
                }
            };
            let pick = |i: usize, model: &BTreeMap<LayerId, Image>| model.keys().nth(i % model.len()).copied();

            for o in ops {
                let Some(id) = (match &o {
                    Op::Fork(i) | Op::Write(i, _) | Op::Discard(i, _, _) | Op::Seal(i)
                    | Op::DropBranch(i) | Op::DropSeal(i) => pick(*i, &model),
                }) else { break };
                let is_branch = m.kind(id).unwrap() == Kind::Branch;
                match o {
                    Op::Fork(_) => match m.fork(id) {
                        Ok(b) => { prop_assert!(!is_branch); let img = model[&id].clone(); model.insert(b, img); }
                        Err(e) => prop_assert_eq!((e, is_branch), (MapError::NotASeal(id), true)),
                    },
                    Op::Write(_, lba) => {
                        let off = next_off; next_off += BLOCK;
                        match m.write(id, lba, Loc::Log(off)) {
                            Ok(g) => {
                                handed.insert(off);
                                free(g.into_iter().collect(), &mut freed);
                                model.get_mut(&id).unwrap().insert(lba, Loc::Log(off));
                            }
                            Err(e) => prop_assert_eq!((e, is_branch), (MapError::NotABranch(id), false)),
                        }
                    }
                    Op::Discard(_, lba, n) => match m.discard(id, lba, n) {
                        Ok(g) => {
                            free(g, &mut freed);
                            let img = model.get_mut(&id).unwrap();
                            for b in lba..lba + n { img.insert(b, Loc::Zero); }
                        }
                        Err(e) => prop_assert_eq!((e, is_branch), (MapError::NotABranch(id), false)),
                    },
                    Op::Seal(_) => match m.seal(id, next_off) {
                        Ok(s) => { let img = model[&id].clone(); model.insert(s, img); }
                        Err(e) => prop_assert_eq!((e, is_branch), (MapError::NotABranch(id), false)),
                    },
                    Op::DropBranch(_) => match m.drop_branch(id) {
                        Ok(g) => { free(g, &mut freed); model.remove(&id); }
                        Err(e) => prop_assert_eq!((e, is_branch), (MapError::NotABranch(id), false)),
                    },
                    Op::DropSeal(_) => match m.drop_seal(id) {
                        Ok(g) => { free(g, &mut freed); model.remove(&id); }
                        Err(MapError::NotASeal(x)) => prop_assert!(is_branch && x == id),
                        Err(MapError::HasChildren(x)) => prop_assert!(!is_branch && x == id),
                        Err(e) => prop_assert!(false, "unexpected {e}"),
                    },
                }
                if model.is_empty() { break; }

                // Every live layer reads exactly as its materialised image.
                for (layer, img) in &model {
                    for lba in 0..20 {
                        prop_assert_eq!(m.read(*layer, lba).unwrap(), img.get(&lba).copied(),
                            "layer {} block {}", layer, lba);
                    }
                }
                // No leak, no premature free: every handed-out location is
                // either reachable from a live layer or freed, never both.
                let mut live: HashSet<u64> = HashSet::new();
                for layer in model.keys() {
                    for (_, loc) in m.delta(*layer).unwrap() {
                        if let Loc::Log(off) = loc { prop_assert!(live.insert(off), "{} held by two layers", off); }
                    }
                }
                for off in &handed {
                    prop_assert!(live.contains(off) ^ freed.contains(off),
                        "location {} live={} freed={}", off, live.contains(off), freed.contains(off));
                }
                prop_assert_eq!(m.layers(), model.len());
            }
        }
    }
}
