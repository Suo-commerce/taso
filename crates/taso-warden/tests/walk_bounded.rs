//! Round 2, R2-02 (Kimi; D&D R2-02 a): the walk never holds more of a
//! directory's names than it can still list.  The agent owns the tree, so
//! a directory of many names must not cost the Warden memory beyond the
//! walk's own limits.  Its own binary: the counting allocator is global.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use taso_warden::classify::{walk, Classmap, Incomplete, Limits, Owner};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static A: Counting = Counting;

const NAMES: usize = 20_000;
const NAME_LEN: usize = 200;

#[test]
fn a_directory_of_many_names_costs_what_the_limit_allows() {
    let d = tempfile::tempdir().unwrap();
    for i in 0..NAMES {
        let name = format!("{i:0>width$}", width = NAME_LEN);
        std::fs::write(d.path().join(name), b"").unwrap();
    }
    let map = Classmap::parse(b"version = 1\n").unwrap();
    let owner = Owner {
        uid_base: rustix::process::getuid().as_raw(),
        gid_base: rustix::process::getgid().as_raw(),
    };
    for max_entries in [0u64, 10] {
        let limits = Limits {
            max_entries,
            ..Default::default()
        };
        let base = LIVE.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        let m = walk(d.path(), &map, owner, &limits, &[]).unwrap();
        let peak = PEAK.load(Ordering::Relaxed) - base;
        assert_eq!(m.incomplete, Some(Incomplete::Entries));
        assert_eq!(m.root_entries, NAMES as u64, "the count is the directory's");
        // The listed entries are the smallest names, as a full read gives.
        let want: Vec<Vec<u8>> = (0..max_entries)
            .map(|i| format!("{i:0>width$}", width = NAME_LEN).into_bytes())
            .collect();
        let got: Vec<Vec<u8>> = m.entries.iter().map(|e| e.path.clone()).collect();
        assert_eq!(got, want);
        // All names would be 20,000 x 200 bytes (4 MB); a bounded read holds
        // a few names and the directory buffer.
        assert!(
            peak < 512 << 10,
            "max_entries {max_entries}: the walk peaked at {peak} bytes"
        );
    }
}
