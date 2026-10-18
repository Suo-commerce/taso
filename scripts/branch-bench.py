#!/usr/bin/env python3
"""Branch cost on one node: can a Seal carry 1000 live branches for free?

Question (finding 2026-10-17, "free branches"): the probability approach
needs many candidate futures of one Seal alive at once.  This measures the
mechanism proposed there, on the machine and filesystem it runs on:

  base     an immutable directory (the Seal): FILES files of SIZE bytes in
           50 directories, plus one BIG MiB file (a database)
  branch   one overlayfs mount: lowerdir = base, its own upperdir (the
           branch's delta) and workdir
  write    each branch changes 4 KiB of the big file and one small file,
           fsync included: the first write copies the file up into the
           branch; on a filesystem with reflinks that is a clone
  discard  unmount, remove the branch's directories
  flatten  turn one branch into a new immutable base: walk its merged view,
           clone each regular file from the layer that holds it (the
           branch's upper, else the base) with FICLONE, and copy metadata
           (mode, owner, times, xattrs, symlinks).  The result is checked
           against the merged view, byte for byte and metadata for metadata.

It reports, per phase, p50 / p99 / max per branch and the total; kernel
memory (Slab) and disk used (statvfs) before and after; whether the
filesystem cloned or copied.  Nothing here is Taso code: it measures the
kernel and the filesystem underneath, so the numbers mean the same for any
implementation built on them.

Usage (as root; ROOT must be an empty or missing directory on the
filesystem under test, e.g. a ZFS dataset or an XFS mount with reflink=1):

    scripts/branch-bench.py ROOT [--branches 1000] [--files 2000]
        [--size 65536] [--big 1024] [--json OUT]

Examples:
    scripts/branch-bench.py /tasotest/branch-bench           # ZFS on taso-test
    scripts/branch-bench.py /mnt/xfs/branch-bench --big 0    # no big file

Everything it creates is under ROOT and is removed at the end, also on
error or Ctrl-C (mounts are unmounted first).  It never touches anything
outside ROOT.  Before building anything it probes whether the filesystem
clones (FICLONE) and refuses if the worst case could fill the disk:
without reflinks every branch's first write to the big file copies all
of it (measured 2026-10-18: on a filesystem without reflinks, 17 branches
of a 1 GiB file used 17 GiB).
"""

import argparse
import ctypes
import errno
import fcntl
import json
import os
import platform
import shutil
import stat
import statistics
import sys
import time

FICLONE = 0x40049409  # _IOW(0x94, 9, int)
MNT_DETACH = 2

libc = ctypes.CDLL("libc.so.6", use_errno=True)


def mount_overlay(lower, upper, work, target):
    opts = f"lowerdir={lower},upperdir={upper},workdir={work}".encode()
    if libc.mount(b"overlay", target.encode(), b"overlay", 0, opts) != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"mount overlay on {target}: {os.strerror(e)}")


def umount(target, lazy=False):
    if libc.umount2(target.encode(), MNT_DETACH if lazy else 0) != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"umount {target}: {os.strerror(e)}")


def meminfo_kib(key):
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith(key + ":"):
                return int(line.split()[1])
    return 0


def disk_used(path):
    s = os.statvfs(path)
    return (s.f_blocks - s.f_bfree) * s.f_frsize


def fstype(path):
    """The filesystem type, mount point and source (device, or ZFS dataset)
    of the mount holding path, from /proc/self/mountinfo."""
    path = os.path.realpath(path)
    best, kind, source = "", "?", "?"
    with open("/proc/self/mountinfo") as f:
        for line in f:
            left, right = line.split(" - ", 1)
            mnt = left.split()[4].replace("\\040", " ")
            if (path == mnt or path.startswith(mnt.rstrip("/") + "/")) and len(mnt) > len(best):
                best, kind, source = mnt, right.split()[0], right.split()[1]
    return kind, best, source


class Disk:
    """Bytes physically used, as the filesystem can tell.

    statvfs is right where shared extents are counted once (XFS, Btrfs,
    ext4).  On ZFS it is not: a dataset's used space counts every clone of a
    block again (measured 2026-10-18: 1000 clones of a 1 GiB file showed
    1 TB used on a pool with 3.6 GiB free).  There the pool's ALLOCATED is
    the physical figure, after `zpool sync` so frees and writes have landed;
    BCLONEUSED / BCLONESAVED say what block cloning shares.
    """

    def __init__(self, root, kind, source):
        self.root, self.pool = root, None
        if kind == "zfs":
            self.pool = source.split("/")[0]

    def _zpool(self, *props):
        import subprocess
        subprocess.run(["zpool", "sync", self.pool], check=True)
        out = subprocess.run(["zpool", "get", "-Hp", "-o", "property,value", ",".join(props), self.pool],
                             check=True, capture_output=True, text=True).stdout
        vals = {}
        for line in out.splitlines():
            k, v = line.split("\t")
            vals[k] = int(v) if v.isdigit() else None  # "-": not on this pool
        return vals

    def used(self):
        """Physical bytes used: pool ALLOCATED on ZFS, statvfs elsewhere."""
        if self.pool:
            return self._zpool("allocated")["allocated"]
        return disk_used(self.root)

    def logical(self):
        """What statvfs says (on ZFS: counts every clone)."""
        return disk_used(self.root)

    def clones(self):
        """ZFS block-cloning counters, or None elsewhere."""
        if not self.pool:
            return None
        return self._zpool("bcloneused", "bclonesaved")


def stats(samples):
    if not samples:
        return {}
    s = sorted(samples)
    return {
        "n": len(s),
        "p50_ms": statistics.median(s) * 1e3,
        "p99_ms": s[max(0, int(len(s) * 0.99) - 1)] * 1e3,
        "max_ms": s[-1] * 1e3,
        "total_s": sum(s),
    }


def line(name, st):
    if not st:
        return f"  {name:<34} (none)"
    return (f"  {name:<34} p50 {st['p50_ms']:8.3f} ms   p99 {st['p99_ms']:8.3f} ms"
            f"   max {st['max_ms']:8.3f} ms   total {st['total_s']:7.3f} s")


# ── building the base ───────────────────────────────────────────────

def small_path(i):
    return f"d{i % 50:02d}/f{i:06d}"


def build_base(base, files, size, big_mib):
    os.makedirs(base)
    blob = os.urandom(size)
    for i in range(files):
        p = os.path.join(base, small_path(i))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(blob)
    os.symlink("d00", os.path.join(base, "link-to-d00"))
    os.chmod(os.path.join(base, small_path(0)), 0o640)
    if big_mib:
        chunk = os.urandom(1 << 20)
        with open(os.path.join(base, "db.sqlite"), "wb") as f:
            for _ in range(big_mib):
                f.write(chunk)
    os.sync()


# ── flatten: a branch becomes a new immutable base ──────────────────

class Clone:
    def __init__(self):
        self.cloned = 0
        self.copied = 0


def copy_meta(src_st, dst, is_link):
    if not is_link:
        os.chmod(dst, stat.S_IMODE(src_st.st_mode))
    os.chown(dst, src_st.st_uid, src_st.st_gid, follow_symlinks=False)
    os.utime(dst, ns=(src_st.st_atime_ns, src_st.st_mtime_ns), follow_symlinks=False)


def copy_xattrs(src, dst, is_link):
    try:
        names = os.listxattr(src, follow_symlinks=not is_link)
    except OSError:
        return
    for n in names:
        if n.startswith("trusted.overlay."):
            continue  # overlay's own bookkeeping never belongs in a Seal
        try:
            os.setxattr(dst, n, os.getxattr(src, n, follow_symlinks=not is_link),
                        follow_symlinks=not is_link)
        except OSError:
            pass


def clone_file(src, dst, counts):
    with open(src, "rb") as s, open(dst, "wb") as d:
        try:
            fcntl.ioctl(d.fileno(), FICLONE, s.fileno())
            counts.cloned += 1
        except OSError as e:
            if e.errno not in (errno.EOPNOTSUPP, errno.EXDEV, errno.EINVAL, errno.ENOTTY):
                raise
            shutil.copyfileobj(s, d, 1 << 20)
            counts.copied += 1


def flatten(merged, upper, base, out):
    """Walk the merged view (it has the file set: deletions are already
    gone); take each regular file's bytes from the layer that holds it."""
    counts = Clone()
    os.makedirs(out)
    for dp, dirs, files in os.walk(merged):
        rel = os.path.relpath(dp, merged)
        tgt_dir = os.path.normpath(os.path.join(out, rel))
        if rel != ".":
            os.makedirs(tgt_dir, exist_ok=True)
        for name in sorted(files) + sorted(d for d in dirs if os.path.islink(os.path.join(dp, d))):
            src_m = os.path.join(dp, name)
            dst = os.path.join(tgt_dir, name)
            st = os.lstat(src_m)
            if stat.S_ISLNK(st.st_mode):
                os.symlink(os.readlink(src_m), dst)
            elif stat.S_ISREG(st.st_mode):
                r = os.path.normpath(os.path.join(rel, name))
                in_upper = os.path.join(upper, r)
                layer = in_upper if os.path.lexists(in_upper) else os.path.join(base, r)
                clone_file(layer, dst, counts)
            else:
                os.mknod(dst, st.st_mode, st.st_rdev)
            copy_xattrs(src_m, dst, stat.S_ISLNK(st.st_mode))
            copy_meta(st, dst, stat.S_ISLNK(st.st_mode))
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(dp, d))]
    # Directory metadata last, deepest first, so file creation does not
    # change the times we copy.
    for dp, dirs, _ in os.walk(merged, topdown=False):
        rel = os.path.relpath(dp, merged)
        tgt = os.path.normpath(os.path.join(out, rel))
        st = os.lstat(dp)
        copy_xattrs(dp, tgt, False)
        copy_meta(st, tgt, False)
    os.sync()
    return counts


def tree_digest(root):
    """Every entry's path, type, mode, owner, mtime, size, link target and
    content, for comparing two trees exactly."""
    import hashlib
    out = {}
    for dp, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files + [d for d in dirs if os.path.islink(os.path.join(dp, d))]) + ["."]:
            p = os.path.normpath(os.path.join(dp, name))
            st = os.lstat(p)
            rel = os.path.relpath(p, root)
            entry = [stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid]
            if stat.S_ISLNK(st.st_mode):
                entry.append(os.readlink(p))
            elif stat.S_ISREG(st.st_mode):
                entry += [st.st_size, st.st_mtime_ns]
                h = hashlib.blake2b(digest_size=16)
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                entry.append(h.hexdigest())
            elif not stat.S_ISDIR(st.st_mode):
                entry.append(st.st_rdev)
            out[rel] = entry
    return out


# ── the run ─────────────────────────────────────────────────────────

def reflink_works(root):
    """Clone a small file inside root: does this filesystem do reflinks here?"""
    a, b = os.path.join(root, ".probe-a"), os.path.join(root, ".probe-b")
    try:
        with open(a, "wb") as f:
            f.write(os.urandom(65536))
        with open(a, "rb") as s, open(b, "wb") as d:
            try:
                fcntl.ioctl(d.fileno(), FICLONE, s.fileno())
                return True
            except OSError:
                return False
    finally:
        for p in (a, b):
            if os.path.exists(p):
                os.unlink(p)


def preflight(root, args):
    """Refuse a run that could fill the disk.  Without reflinks every branch
    that writes the big file copies all of it; with them a branch costs a
    few CoW extents.  Worst case is checked against free space."""
    clones = reflink_works(root)
    s = os.statvfs(root)
    free = s.f_bavail * s.f_frsize
    base = args.files * args.size + (args.big << 20)
    if clones:
        # Each branch: one small file copied up (its size) and one CoW unit
        # of the big file.  1 MiB covers ZFS's largest common recordsize
        # (measured on XFS: 196 KiB per branch).  Flatten clones: ~free.
        per_branch = args.size + (1 << 20)
        need = base + args.branches * per_branch + (64 << 20)
    else:
        # Each branch copies the whole small file and the whole big file;
        # flatten copies the base once more.
        per_branch = args.size + (args.big << 20)
        need = 2 * base + args.branches * per_branch
    if need > free * 0.9:
        sys.exit(
            f"refusing: worst case {need / 2**30:.1f} GiB, {free / 2**30:.1f} GiB free on {root}"
            f" (reflink {'works' if clones else 'NOT available'}: each branch's write"
            f" {'clones' if clones else 'copies the whole file'}).  Use --big 0, fewer"
            f" --branches, or a filesystem with reflinks (XFS reflink=1, Btrfs, ZFS block cloning).")
    return clones


def run(args):
    root = os.path.abspath(args.root)
    if os.path.exists(root) and os.listdir(root):
        sys.exit(f"{root} is not empty; give an empty or missing directory")
    created = not os.path.exists(root)
    os.makedirs(root, exist_ok=True)
    try:
        clones = preflight(root, args)
    except SystemExit:
        if created:
            os.rmdir(root)
        raise
    kind, mnt, source = fstype(root)
    disk = Disk(root, kind, source)
    base = os.path.join(root, "base")
    br = os.path.join(root, "br")
    mounted = []
    result = {
        "host": platform.node(), "kernel": platform.release(), "root": root,
        "fstype": kind, "mount": mnt, "source": source, "zfs_pool": disk.pool, "reflink": clones, "branches": args.branches, "files": args.files,
        "size": args.size, "big_mib": args.big, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        t = time.perf_counter()
        build_base(base, args.files, args.size, args.big)
        result["base_build_s"] = time.perf_counter() - t
        result["base_bytes"] = disk.used()

        slab0, avail0 = meminfo_kib("Slab"), meminfo_kib("MemAvailable")
        disk0, logical0, clones0 = disk.used(), disk.logical(), disk.clones()
        fork = []
        for b in range(args.branches):
            u, w, m = (os.path.join(br, str(b), x) for x in "uwm")
            t = time.perf_counter()
            os.makedirs(u)
            os.makedirs(w)
            os.makedirs(m)
            mount_overlay(base, u, w, m)
            fork.append(time.perf_counter() - t)
            mounted.append(m)
        slab1, avail1 = meminfo_kib("Slab"), meminfo_kib("MemAvailable")

        read, write_small, write_big = [], [], []
        for b in range(args.branches):
            m = mounted[b]
            t = time.perf_counter()
            with open(os.path.join(m, small_path(b % args.files)), "rb") as f:
                f.read()
            read.append(time.perf_counter() - t)
            t = time.perf_counter()
            with open(os.path.join(m, small_path((b + 1) % args.files)), "r+b") as f:
                f.write(b"x")
                f.flush()
                os.fsync(f.fileno())
            write_small.append(time.perf_counter() - t)
            if args.big:
                t = time.perf_counter()
                with open(os.path.join(m, "db.sqlite"), "r+b") as f:
                    f.seek((b * 4096 * 37) % (args.big << 20))
                    f.write(b"y" * 4096)
                    f.flush()
                    os.fsync(f.fileno())
                write_big.append(time.perf_counter() - t)
        os.sync()
        disk1, logical1, clones1 = disk.used(), disk.logical(), disk.clones()

        # Flatten branch 0 after one more change: a deletion (a whiteout).
        m0 = mounted[0]
        os.unlink(os.path.join(m0, small_path(2 % args.files)))
        before = disk.used()
        t = time.perf_counter()
        counts = flatten(m0, os.path.join(br, "0", "u"), base, os.path.join(root, "seal1"))
        result["flatten"] = {"s": time.perf_counter() - t, "cloned": counts.cloned,
                             "copied": counts.copied, "extra_bytes": disk.used() - before}
        result["flatten"]["identical"] = tree_digest(m0) == tree_digest(os.path.join(root, "seal1"))

        discard = []
        for b in range(args.branches):
            t = time.perf_counter()
            umount(mounted[b])
            shutil.rmtree(os.path.join(br, str(b)))
            discard.append(time.perf_counter() - t)
        mounted.clear()

        result.update({
            "fork": stats(fork), "first_read": stats(read),
            "write_small_fsync": stats(write_small), "write_big_4k_fsync": stats(write_big),
            "discard": stats(discard),
            "slab_kib_delta": slab1 - slab0, "mem_available_kib_delta": avail0 - avail1,
            "disk_bytes_for_writes": disk1 - disk0,
            "logical_bytes_for_writes": logical1 - logical0,
            "zfs_clones_before": clones0, "zfs_clones_after": clones1,
        })
    finally:
        for m in reversed(mounted):
            try:
                umount(m)
            except OSError:
                umount(m, lazy=True)
        shutil.rmtree(root, ignore_errors=True)
    return result


def report(r):
    n = r["branches"]
    print(f"branch-bench {r['time']} {r['host']} kernel {r['kernel']}")
    print(f"  root {r['root']} on {r['fstype']} (mount {r['mount']}), reflink {'yes' if r['reflink'] else 'NO'}")
    print(f"  base: {r['files']} files x {r['size']} B + {r['big_mib']} MiB file; built in {r['base_build_s']:.1f} s")
    print(line(f"fork ({n})", r["fork"]))
    print(line("first read in a branch", r["first_read"]))
    print(line(f"write 1 B of a {r['size']} B file + fsync", r["write_small_fsync"]))
    if r["big_mib"]:
        print(line(f"write 4 KiB of the {r['big_mib']} MiB file + fsync", r["write_big_4k_fsync"]))
    print(line(f"discard ({n})", r["discard"]))
    print(f"  kernel memory for {n} live branches: slab +{r['slab_kib_delta'] / 1024:.1f} MiB,"
          f" available -{r['mem_available_kib_delta'] / 1024:.1f} MiB")
    d = r["disk_bytes_for_writes"]
    what = f"zpool {r['zfs_pool']} ALLOCATED" if r["zfs_pool"] else "statvfs"
    print(f"  disk used by the writes of all branches: {d / 2**20:.1f} MiB ({d / n / 1024:.0f} KiB per branch) [{what}]")
    if r["zfs_pool"]:
        lg = r["logical_bytes_for_writes"]
        print(f"    dataset view (counts every clone): {lg / 2**20:.1f} MiB")
        a, b = r["zfs_clones_before"], r["zfs_clones_after"]
        if a and b and a.get("bclonesaved") is not None and b.get("bclonesaved") is not None:
            print(f"    block cloning: bcloneused +{(b['bcloneused'] - a['bcloneused']) / 2**20:.1f} MiB,"
                  f" bclonesaved +{(b['bclonesaved'] - a['bclonesaved']) / 2**20:.1f} MiB")
    f = r["flatten"]
    print(f"  flatten one branch: {f['s']:.3f} s, {f['cloned']} cloned, {f['copied']} copied,"
          f" {f['extra_bytes'] / 2**20:.2f} MiB extra disk, identical to its view: {f['identical']}")
    if f["copied"]:
        print("  NOTE: files were copied, not cloned: this filesystem (or its settings) has no reflink here")


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("root")
    p.add_argument("--branches", type=int, default=1000)
    p.add_argument("--files", type=int, default=2000)
    p.add_argument("--size", type=int, default=65536)
    p.add_argument("--big", type=int, default=1024, help="MiB of the big file; 0 for none")
    p.add_argument("--json", help="also write the results here")
    args = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root (mounting overlays needs CAP_SYS_ADMIN)")
    if args.files < 3 or args.branches < 1:
        sys.exit("need --files >= 3 and --branches >= 1")
    r = run(args)
    report(r)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(r, f, indent=2)


if __name__ == "__main__":
    main()
