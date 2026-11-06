//! Audit 2026-11-06, finding 2: a compaction that fails after its rename
//! must not leave the store writing to the unlinked old log.
//!
//! Run with the injector, which fails the first descriptor duplication
//! after the rename onto the log (as EMFILE would):
//!
//! ```text
//! cc -shared -fPIC -o target/audit-fail-dup.so crates/taso-blk/tests/audit_support/fail_dup.c -ldl
//! LD_PRELOAD="$PWD/target/audit-fail-dup.so" cargo test -p taso-blk --test audit_compaction -- --ignored
//! ```
//!
//! Either outcome is right: the compaction finishes (nothing fallible
//! after the rename, so the injector has nothing to fail), or it fails
//! and the store is poisoned.  What must not happen: an error, the store
//! not poisoned, and a later acknowledged write lost on reopen.
use taso_blk::map::BLOCK;
use taso_blk::store::Store;

#[test]
#[ignore = "requires LD_PRELOAD of audit_support/fail_dup.c"]
fn audit_compaction_dup_failure_must_not_lose_later_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log");
    let mut store = Store::create(&path).unwrap();
    let root = store.root_seal().unwrap();
    let branch = store.fork(root).unwrap();
    store
        .write(branch, 0, &vec![0x11; BLOCK as usize], true)
        .unwrap();
    let mut compact = store.compaction().unwrap();
    compact.copy().unwrap();
    std::env::set_var("TASO_AUDIT_RENAME_TARGET", &path);
    let result = compact.finish(&mut store);
    std::env::remove_var("TASO_AUDIT_RENAME_TARGET");
    match &result {
        Ok(_) => println!("compaction finished"),
        Err(e) => {
            println!("compaction error: {e}; poisoned: {}", store.is_poisoned());
            assert!(store.is_poisoned(), "an error after the rename poisons the store");
            return;
        }
    }
    store
        .write(branch, 0, &vec![0x22; BLOCK as usize], true)
        .unwrap();
    drop(store);
    let (reopened, _) = Store::open(&path).unwrap();
    let mut data = vec![0; BLOCK as usize];
    reopened.read(branch, 0, &mut data).unwrap();
    assert!(
        data.iter().all(|b| *b == 0x22),
        "write acknowledged after the compaction disappeared after reopen"
    );
}
