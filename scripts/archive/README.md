# Archived scripts

One-off probes and benchmarks, and setup scripts for machines no longer
in use. No gate, the nightly or the README runs them, and they are not
kept working as the code changes. They stay because comments in the code
cite them as the source of a measurement (for example the cost of an
ext4 freeze on a block-log branch, or where a freeze's time goes in the
kernel), so the method behind a number can still be read.

Read a script before running it: some need root, change the host
(install packages, unmount ublk devices) or delete the directory they
are given.

| Script | What it measured or did |
| --- | --- |
| `audit-fix-tests.sh` | ran the tests of the fixes for the audit of 2026-11-09, one by one |
| `blk-freeze-ftrace.sh` | where a freeze's time goes inside the kernel (2026-10-26) |
| `blk-freeze-probe.sh` | what an ext4 freeze costs on a block-log branch, and why (2026-10-26) |
| `blk-thin-probe.sh` | why xfstests generic/347 exhausts its thin pool |
| `blk-trace-freeze.sh` | the kernel's request trace of one freeze (blktrace, 2026-10-26) |
| `branch-bench.py` | whether a Seal can carry 1000 live branches at little cost |
| `f6-idmap-probe.sh` | whether a fork in another uid slot can use its parent's files through an idmapped mount |
| `garage-put-bench.sh` | the cost of one synchronous object put to a local Garage |
| `p5-facts.sh` | the durability facts of a measurement host (what the stack claims, a flush's cost, a power cut's witness) |
| `p5-metal-partitioning.json` | the bare-metal node's disk layout |
| `scaleway-node.sh` | prepared a fresh Scaleway server to build and test the block log |
