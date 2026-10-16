# Taso — Phase 4 plan: the Chronicle block log

*Put forward when Phase 1 (P0–P4) has passed its gates. Supersedes §6 of "Taso spec v1.0 build plan". Amendments to Phases 1–3 are in §9.*

---

## 0. What Phase 4 is now

Phase 4 was "a Chronicle-native filesystem, gated on ZFS being the measured bottleneck." The filesystem investigation (14 Oct 2026) changed the target, not the ambition: nobody has built a storage layer that is simultaneously live POSIX, fork-as-pointer, and write-path-is-the-log — and the reason is that a *file-level* log has to re-promise POSIX, which is where professionals' filesystems fail crash tests. The industry's answer (E2B, Replit, Tensorlake, DeepSeek) is a log *below* POSIX: a virtual block device that ext4 believes is a disk.

**Phase 4 therefore builds the Chronicle block log:** a userspace block device, served by the Warden over ublk, whose writes are Chronicle records, whose Seal is an LSN, whose fork is a parent pointer, and whose rebirth is replay. ext4 sits on top and provides POSIX. Taso reaches the empty centre of the landscape by owning the device, not the filesystem. Lifting the log to file level becomes Phase 5, with its own gate.

## 1. Entry gate (all required)

1. Phase 1 exit gates passed on the Hetzner pilot (P1 latency, P2 rebirth 20/20, P3 attacks refused, P4 sanction loop).
2. The ZFS experiment from the landscape report has been run: 64 datasets × 2,000 snapshots with rolling trim; Seal p95 at p64 and neighbour write p95 during trim are recorded. **Phase 4 proceeds if either** Seal p95 exceeds the turn-cadence budget measured in P3, **or** `zfs send -i` CPU exceeds 25% of the Warden at p64, **or** Hetzner kernel upgrades have broken the DKMS ZFS module at least once during Phase 1. If none, Phase 4 is parked and ZFS stays — recorded as a decision, not a failure.
3. YoloFS (SOSP'26, GPL-2.0, public) has been built and run on one pilot node; its session-journal numbers reproduced or refuted and written down. It is the validation ancestor for the file-level question (Phase 5), and running it now is cheap.
4. The pilot kernel supports ublk (6.0+) — verified on the actual Hetzner image, not assumed. If not, NBD is the fallback transport with the same device code behind it.
5. Phase 2 (`taso-store`) status is recorded: done, parked, or in progress. Phase 4 does not depend on it; Phase 5 does.

## 2. Design

### 2.1 The device
```
Vessel (runc / Firecracker)
   └─ ext4 (data=ordered, default)         ← POSIX lives here; never modified
        └─ /dev/ublkbN  ──────────────┐
                                       │ io_uring
                             Warden: taso-blocklog
                               ├─ write path → Chronicle `blk` stream
                               ├─ read path  → local extent cache → CAS → parent chain
                               ├─ flush/FUA  → group commit → candidate Seal point
                               └─ fork/seal/rebirth over LSNs
```
- One ublk device per Vessel, created at fork, destroyed at purge. Device size is the Template's virtual size; it is sparse.
- The Warden runs one `libublk` queue per device, io_uring-driven, in `taso-warden`. No kernel code; no out-of-tree module.
- ext4 is formatted once per **Template**, never per Vessel: a Vessel's device starts as a pointer to the Template's block image.

### 2.2 Records
A new state stream `blk` replaces `fs` for the device:
```
BlkRecord {
  lsn: u64,
  epoch: u64,
  device: VesselId,
  extent: { lba: u64, len_blocks: u32 },     // 4 KiB logical blocks; coalesced per request
  chunks: Vec<ChunkRef>,                      // content-addressed, 64 KiB chunks (BLAKE3)
  flags: { fua: bool, discard: bool },
  hash, prev_hash,
}
FlushRecord { lsn, epoch, device, flags: { fua } }   // group boundary
```
- Data goes to the CAS (local extent cache + Garage); the record carries hashes, not bytes. A 1 GB write is a few thousand records and a few thousand chunk puts, deduplicated against the Template and every sibling fork.
- **Group = writes between two FlushRecords.** ext4's `data=ordered` journal commit ends with a flush; so a group boundary is, by construction, a point where ext4's own on-disk state is consistent. This is what makes the block log inherit crash consistency: Taso only ever seals at an ext4-consistent LSN.
- Discard (TRIM) is recorded so GC can reclaim chunks the filesystem released.

### 2.3 Seal, fork, revert, rebirth at the device
| Operation | Device semantics |
|---|---|
| **Seal** | Choose the LSN of the most recent FlushRecord ≤ now. Write a `ctl: seal { lsn }`. No data moves. ext4 is not told; it does not need to be. The Phase 1 quiescence check and `-wal` watch are deleted. |
| **Fork** | New device whose `parent = (chronicle, seal.lsn)`. Reads: local cache → own tail → parent chain → CAS. Writes: own tail only. Creation is a metadata write; target < 5 ms including ublk device setup. |
| **Revert** | Device re-opened at an earlier Seal LSN with a fresh tail; the Vessel is restarted quiescent (§5.4 of v0.4). Navigator gates it exactly as before; the block log changes nothing about barriers. |
| **Rebirth** | On node B: create device, point at Template image + Seal LSN + the sealed prefix's `blk` tail (committed groups only); reads fault chunks from Garage lazily; ext4 mounts in seconds because it reads only the superblock and journal first. REAP/FaaSnap-style prefetch of the Template's hot block set makes first-touch fast — record the hot set per Template. |
| **Purge** | Drop a device's tail segments and any chunk no live Seal, Template or lineage references (refcount in the Warden index, never a scan of Garage). |

### 2.4 What stays exactly as in v0.4
Effect ledger, intents, outcomes, barriers, obligations, Navigator, sanction, Candidate, policy engine, coordinator, sealed-prefix transfer, epoch fencing, audit retention. The block log only replaces the *state* stream and the ZFS driver. The strong-bound rule is what makes this a swap and not a rewrite: nothing above the Chronicle record schema changes except that `fs` records become `blk` records.

### 2.5 What is lost, and how it is recovered
- **Path visibility** — the device sees LBAs, not paths. The classification map and partial sanction need paths. Recovery: at Seal time the Warden mounts the sealed image read-only (ext4 on a read-only fork of the device, in a helper namespace) and walks it to produce the `fs` envelope aggregates the policy engine consumes. This costs a mount and a walk per Seal that is a Candidate — not per Seal — so it is on the sanction path, not the hot path. Alternative for later: an inotify/fanotify shim in the Vessel producing path hints as *advisory* records; never authoritative.
- **Whole-block CoW granularity** — a 1-byte change dirties a 4 KiB block. Acceptable; it is what every block-level system in the landscape pays, and chunk dedup against the parent keeps storage flat.

## 3. Work breakdown

| # | Deliverable | Est. lines | Depends on |
|---|---|---|---|
| 4.1 | `taso-blocklog` crate: `BlkRecord`/`FlushRecord` types, LSN algebra for parent chains (read resolution across N ancestors), refcounted chunk index in redb | ~2,000 | taso-core |
| 4.2 | ublk backend on `libublk`: queue loop, request coalescing, flush/FUA semantics, discard; NBD fallback behind the same trait | ~2,500 | 4.1 |
| 4.3 | CAS: 64 KiB content-defined chunking (BLAKE3), local extent cache on NVMe with LRU, Garage put/get with conditional head, Template image import | ~1,500 | 4.1 |
| 4.4 | Seal/fork/revert/rebirth at the device; hot-set recording and prefetch | ~1,200 | 4.2, 4.3 |
| 4.5 | Read-only sealed-image walk for policy aggregates (helper mount + classification map) | ~600 | 4.4 |
| 4.6 | Test harness: xfstests + fsx + pjdfstest over ext4-on-ublk; CrashMonkey-style flush-point crash injection on the device; replay equivalence checker (image after replay == image before crash, block for block) | ~1,500 | 4.2 |
| 4.7 | Migration: a Phase 1 ZFS Vessel → block-log Vessel (one-time import of the dataset into a Template image), and the reverse for rollback of the whole phase | ~500 | 4.3 |
| | **Total** | **~9,800** | E2B's device layer is 9.6k Go — the estimate is calibrated, not optimistic |

Order: 4.1 → 4.6 (tests first, against a null device) → 4.2 → 4.3 → 4.4 → 4.5 → 4.7.

## 4. Tests and gates

### 4.1 Correctness (must pass before any latency work)
- **xfstests** quick group on ext4-over-ublk: same pass set as ext4-over-loop on the same kernel.
- **Crash injection:** for 10k randomized schedules, kill the Warden between any two block writes and at every flush; replay the sealed prefix; mount; `fsck.ext4 -n` clean and every file whose `fsync` returned before the kill is intact. This is CrashMonkey's property applied one layer down.
- **Fork isolation:** 1,000 forks from one Seal, each writing a disjoint file; no fork observes another's blocks; parent image byte-identical throughout.
- **Replay equivalence:** image(after replay to LSN n) == image(at LSN n on the original node), block for block, for 100 Seals across 10 Vessels.

### 4.2 Performance exit gate (measured on the pilot, p64 concurrent Vessels)
| Metric | Gate |
|---|---|
| Fork (device ready to mount) | p95 < 5 ms |
| Seal | p95 < 2 ms (it is a `ctl` write) |
| Small-write latency inside the Vessel (4 KiB, fsync) | p95 ≤ 1.5× ext4 on local NVMe |
| Hermes `state.db` ops/s at p64 | ≥ Phase 1 (ZFS) figure |
| Rebirth on node B to first successful `ls` of the workspace | p95 < 10 s |
| Warden CPU at p64 steady state | < 20% of node |
| Chunk dedup: 1,000 forks of a 2 GB Template each changing 10 MB | total new chunks ≤ 12 GB |

### 4.3 Comparison targets (vendor-only, for orientation not acceptance)
Tensorlake: +100 MB snapshot in 167 ms †. E2B: pause ~4 s/GiB †. Replit: constant-time fork via manifest copy. Taso's claims must come from §4.2, not from these.

## 5. Runtime coupling (decide with Phase 3)
The block log is **native under Firecracker** (virtio-blk is its only storage device) and **taxed under gVisor** (every block I/O crosses the Sentry; the alternative is a Go fsimpl fork). If Phase 3 is reached, choose Firecracker unless the threat model specifically needs gVisor's syscall surface; if gVisor is chosen, accept the tax and measure it against §4.2, or keep ZFS under gVisor and the block log under Firecracker — the Field API allows both to coexist per Template.

## 6. Phase 5 — lifting the log to file level (gated, not planned)
Opens only if, after Phase 4 is in production: (a) the per-Candidate sealed-image walk (§2.5) is measured to dominate sanction latency, **and** (b) partial sanction is used often enough that path-level records would change outcomes, **and** (c) YoloFS's session-journal approach has been reproduced on the pilot and shown to keep ext4's crash behaviour (it stacks over ext4 rather than replacing it — that is the property to copy). Phase 5 would then be a VFS-interposition layer in the style of YoloFS producing *authoritative* path records, with the block log remaining the durability substrate. It is the hardest version of the idea and it is earned, not assumed.

## 7. Risks specific to this phase
- **ublk availability on the Hetzner image.** Mitigated by the NBD fallback (slower, same code path). Verify at entry gate.
- **Flush semantics under coalescing.** A reordered write across a FUA boundary silently breaks ext4's assumptions. The crash-injection suite exists for this; it runs before any coalescing optimisation lands.
- **Chunk GC correctness.** A dropped chunk that a parent still references is data loss. Refcounts are in the Warden index, updated in the same `ctl` record as the Seal/purge that changes them; a reconciliation job compares the index to Garage weekly and reports — never auto-deletes on mismatch.
- **Read amplification on deep fork chains.** A fork chain 1,000 deep makes a cold read walk 1,000 parents. Mitigation: flatten chains at sanction (a Template is a full image, so chains reset at every round) and cap chain depth with a background materialise step past 32.
- **Scope creep toward a filesystem.** The device must stay a device. Any feature that needs to know what a block *means* goes to Phase 5's gate, not into Phase 4.

## 8. Timeline shape (one developer, calibrated to ZeroFS: 6 months to v1.0 for a larger scope)
- Month 1: 4.1 + 4.6 on a null device; crash-injection suite green on the in-memory model.
- Month 2: 4.2 + 4.3; xfstests green on one node.
- Month 3: 4.4 + 4.5; fork/seal/rebirth gates measured; 4.7 migration of one real Hermes Vessel.
- Month 4: p64 soak, GC reconciliation, §4.2 exit gate. Decision: swap Phase 1 ZFS driver for the block log in production, or keep both per Template.

## 9. Amendments to "Taso spec v1.0 build plan" (apply now, before Phase 4)
1. **§3 Phase 1:** strike Btrfs as the fallback (snapshot creation ~70 s by the 1,000th snapshot; write throughput 1–5% at 100 snapshots). If ZFS is unavailable, the fallback is bringing Phase 4 forward, not Btrfs.
2. **§3 Phase 1, ZFS rules:** add a live-snapshot cap per dataset (default 200), send-then-trim cadence with one `zfs destroy` per TXG and never `destroy -r`, a Warden-side snapshot index (never `zfs list` on the hot path), and a gate line "Seal p95 at p64 concurrent Vessels < 50 ms".
3. **§1 Phase 4 row:** replace with this document.
4. **§6 (old):** delete; the three-condition gate is now §1 above, with DeltaFS replaced by YoloFS as the ancestor to validate.
5. **§1 Phase 3 row:** add "decide the runtime with Phase 4 in view (§5)".
6. **§14 open problems:** add "ublk vs NBD on the pilot kernel" and "ZFS DKMS breakage count during Phase 1" as measured inputs to the Phase 4 entry gate.

## 10. One-line summary for the stakeholder slide
*Phase 4 makes the workspace device itself the replication log: fork in milliseconds, checkpoint as a pointer, recovery on any node by replay — with ext4 unchanged on top, so every tool keeps working. Under 10k lines, calibrated against the one open-source system (E2B) that has shipped the same layer.*
