//! Who holds a mount, or a block device, when an unmount or a stop is
//! refused as busy: for the refusal to name them (spec rev. 33, D93: a
//! failure is reported in a form the next layer can act on).
//!
//! Found on the test VM (2026-11-27, bench at 64 Vessels): a Vessel's reset
//! after its birth was refused, "target is busy" from `umount` or "in use"
//! from `taso-blkd`'s stop, a few times in a run.  Every Vessel mount is
//! also present in the mount namespaces of the host's sandboxed services
//! (udev, chronyd, logind, ...), since `/` propagates as shared.  Which
//! holder refused each time is what this module reports.
//!
//! Everything is read from `/proc` (a root given, so tests can make one):
//! each process's mount table (`mountinfo`), its open files (`fd`), its
//! working and root directories, its name (`comm`) and its mount
//! namespace (`ns/mnt`).  Read only after a refusal; a process that ends
//! while it is read is skipped.  Nothing is changed.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// One process that holds the thing asked about, and how.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holder {
    /// Its process id.
    pub pid: u32,
    /// Its name (`comm`).
    pub comm: String,
    /// Its mount namespace, as `ns/mnt` reads (`mnt:[4026531841]`).
    pub mnt_ns: String,
    /// The mounts in its mount table that hold it: "at …" with the
    /// mount's propagation.  Every process of a namespace sees the same.
    pub mounted: Vec<String>,
    /// How it uses it itself: "open", "working directory", "root
    /// directory", "open file …".
    pub uses: Vec<String>,
}

/// The processes under `proc` whose mount table has a mount on `dir`, or
/// whose open files, working or root directory are at or under `dir`.
pub fn of_mount(proc: &Path, dir: &Path) -> Vec<Holder> {
    let mut out = Vec::new();
    for (pid, p) in processes(proc) {
        let mut mounted = Vec::new();
        for m in mounts(&p) {
            if m.point == dir {
                mounted.push(format!("at {} ({})", m.point.display(), m.tags));
            }
        }
        let mut uses = Vec::new();
        for (name, what) in [("cwd", "working directory"), ("root", "root directory")] {
            if std::fs::read_link(p.join(name)).is_ok_and(|t| t.starts_with(dir)) {
                uses.push(what.to_string());
            }
        }
        for t in open_files(&p) {
            if t.starts_with(dir) {
                uses.push(format!("open file {}", t.display()));
            }
        }
        push(&mut out, pid, &p, mounted, uses);
    }
    out
}

/// The processes under `proc` whose mount table has a filesystem on the
/// block device `dev` (by its device number, or by name), or that have
/// `dev` open.
pub fn of_device(proc: &Path, dev: &Path) -> Vec<Holder> {
    let number = std::fs::metadata(dev).ok().map(|m| device_number(m.rdev()));
    let mut out = Vec::new();
    for (pid, p) in processes(proc) {
        let mut mounted = Vec::new();
        for m in mounts(&p) {
            if Some(m.device.as_str()) == number.as_deref() || m.source == dev {
                mounted.push(format!("at {} ({})", m.point.display(), m.tags));
            }
        }
        let mut uses = Vec::new();
        if open_files(&p).iter().any(|t| t == dev) {
            uses.push("open".to_string());
        }
        push(&mut out, pid, &p, mounted, uses);
    }
    out
}

/// One line for an error message.  First every process that uses it
/// itself (open, working or root directory under it), all of them; then
/// each mount namespace whose mount table holds it, once, with the
/// mount's propagation, how many processes are in it and one of them
/// (every process of a namespace sees the same mounts: listing them would
/// hide the few that matter, as the first report on the test VM did).  The
/// caller's own namespace is named as such; at most `most` lines of each
/// kind.  "nobody found" when nothing holds it: whoever held it let go
/// before it was looked for.
pub fn report(holders: &[Holder], own_ns: Option<&str>, most: usize) -> String {
    if holders.is_empty() {
        return "held by: nobody found (whoever held it had let go when it was looked for)"
            .to_string();
    }
    let users: Vec<String> = holders
        .iter()
        .filter(|h| !h.uses.is_empty())
        .map(|h| {
            format!(
                "{} {} in {}: {}",
                h.pid,
                h.comm,
                h.mnt_ns,
                h.uses.join(", ")
            )
        })
        .collect();
    let mut namespaces: Vec<&str> = holders
        .iter()
        .filter(|h| !h.mounted.is_empty())
        .map(|h| h.mnt_ns.as_str())
        .collect();
    namespaces.sort_unstable();
    namespaces.dedup();
    let mounts: Vec<String> = namespaces
        .iter()
        .map(|ns| {
            let here: Vec<&Holder> = holders
                .iter()
                .filter(|h| h.mnt_ns == *ns && !h.mounted.is_empty())
                .collect();
            let mine = if own_ns == Some(*ns) {
                " (this process's)"
            } else {
                ""
            };
            format!(
                "{ns}{mine}: mounted {}, {} process(es), e.g. {} {}",
                here[0].mounted.join(" and "),
                here.len(),
                here[0].pid,
                here[0].comm
            )
        })
        .collect();
    let capped = |v: &[String]| {
        let mut s = v.iter().take(most).cloned().collect::<Vec<_>>().join("; ");
        if v.len() > most {
            s.push_str(&format!("; and {} more", v.len() - most));
        }
        s
    };
    let mut out = String::from("held by");
    if users.is_empty() {
        out.push_str(" no process using it itself");
    } else {
        out.push_str(&format!(
            " {} process(es) using it: {}",
            users.len(),
            capped(&users)
        ));
    }
    if !mounts.is_empty() {
        out.push_str(&format!(
            "; mounted in {} mount namespace(s): {}",
            mounts.len(),
            capped(&mounts)
        ));
    }
    out
}

/// This process's own mount namespace under `proc`.
pub fn own_ns(proc: &Path) -> Option<String> {
    std::fs::read_link(proc.join("self/ns/mnt"))
        .ok()
        .map(|t| t.display().to_string())
}

fn push(out: &mut Vec<Holder>, pid: u32, p: &Path, mounted: Vec<String>, uses: Vec<String>) {
    if mounted.is_empty() && uses.is_empty() {
        return;
    }
    let comm = std::fs::read_to_string(p.join("comm"))
        .map(|c| c.trim_end().to_string())
        .unwrap_or_default();
    let mnt_ns = std::fs::read_link(p.join("ns/mnt"))
        .map(|t| t.display().to_string())
        .unwrap_or_else(|_| "mnt:[?]".to_string());
    out.push(Holder {
        pid,
        comm,
        mnt_ns,
        mounted,
        uses,
    });
}

/// Every process directory under `proc`, by pid, in pid order.
fn processes(proc: &Path) -> Vec<(u32, PathBuf)> {
    let mut out: Vec<(u32, PathBuf)> = std::fs::read_dir(proc)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let pid = e.file_name().to_str()?.parse::<u32>().ok()?;
            Some((pid, e.path()))
        })
        .collect();
    out.sort_by_key(|(pid, _)| *pid);
    out
}

/// What a process's open descriptors point at.
fn open_files(p: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(p.join("fd"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| std::fs::read_link(e.path()).ok())
        .collect()
}

/// One line of a `mountinfo`.
struct Mount {
    /// `major:minor` of the filesystem's device.
    device: String,
    point: PathBuf,
    /// The optional fields (`shared:N`, `master:N`, ...), or "private".
    tags: String,
    source: PathBuf,
}

/// A process's mount table; empty if it cannot be read.
fn mounts(p: &Path) -> Vec<Mount> {
    let Ok(text) = std::fs::read_to_string(p.join("mountinfo")) else {
        return Vec::new();
    };
    text.lines().filter_map(parse_mount).collect()
}

/// `36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw`
fn parse_mount(line: &str) -> Option<Mount> {
    let (before, after) = line.split_once(" - ")?;
    let f: Vec<&str> = before.split(' ').collect();
    if f.len() < 6 {
        return None;
    }
    let tags = f[6..].join(" ");
    let source = after.split(' ').nth(1)?;
    Some(Mount {
        device: f[2].to_string(),
        point: PathBuf::from(unescape(f[4])),
        tags: if tags.is_empty() {
            "private".to_string()
        } else {
            tags
        },
        source: PathBuf::from(unescape(source)),
    })
}

/// `mountinfo`'s octal escapes (`\040` for a space, and the like).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        // Three octal digits, read as bytes (never a slice of the str,
        // which a multi-byte name would cut inside a character).
        if b[i] == b'\\'
            && i + 4 <= b.len()
            && b[i + 1..i + 4].iter().all(|d| (b'0'..=b'7').contains(d))
        {
            let n = b[i + 1..i + 4]
                .iter()
                .fold(0u32, |n, d| n * 8 + u32::from(d - b'0'));
            if let Ok(n) = u8::try_from(n) {
                out.push(n);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A device number as `mountinfo` writes it: `major:minor` (Linux's
/// encoding of `dev_t`).
fn device_number(rdev: u64) -> String {
    let major = ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff);
    let minor = (rdev & 0xff) | ((rdev >> 12) & !0xff);
    format!("{major}:{minor}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A process directory under `proc`, as `/proc` shows one.
    fn process(proc: &Path, pid: u32, comm: &str, ns: &str, mountinfo: &str) -> PathBuf {
        let p = proc.join(pid.to_string());
        std::fs::create_dir_all(p.join("fd")).unwrap();
        std::fs::create_dir_all(p.join("ns")).unwrap();
        std::fs::write(p.join("comm"), format!("{comm}\n")).unwrap();
        std::fs::write(p.join("mountinfo"), mountinfo).unwrap();
        symlink(ns, p.join("ns/mnt")).unwrap();
        symlink("/", p.join("cwd")).unwrap();
        symlink("/", p.join("root")).unwrap();
        p
    }

    const HOST: &str = "mnt:[4026531841]";
    const UDEV: &str = "mnt:[4026532301]";
    const MNT: &str = "/mnt/p5-bench/p5bench/w1/v-ab";

    fn line(id: u32, dev: &str, point: &str, tags: &str, source: &str) -> String {
        format!("{id} 1 {dev} / {point} rw,relatime {tags} - ext4 {source} rw\n")
    }

    #[test]
    fn a_mount_held_in_another_namespace_is_named_with_its_holder() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        let shared = line(40, "259:7", MNT, "shared:12", "/dev/ublkb7");
        let slave = line(90, "259:7", MNT, "master:12", "/dev/ublkb7");
        process(proc, 1, "systemd", HOST, &shared);
        process(proc, 812, "(udev-worker)", UDEV, &slave);
        let busy = process(proc, 900, "sh", HOST, &shared);
        std::fs::remove_file(busy.join("cwd")).unwrap();
        symlink(format!("{MNT}/sub"), busy.join("cwd")).unwrap();
        process(
            proc,
            901,
            "other",
            HOST,
            &line(41, "259:8", "/mnt/elsewhere", "", "/dev/x"),
        );
        let h = of_mount(proc, Path::new(MNT));
        assert_eq!(
            h.iter()
                .map(|h| (h.pid, h.mounted.len(), h.uses.clone()))
                .collect::<Vec<_>>(),
            [
                (1, 1, vec![]),
                (812, 1, vec![]),
                (900, 1, vec!["working directory".to_string()]),
            ]
        );
        let r = report(&h, Some(HOST), 10);
        assert_eq!(
            r,
            format!(
                "held by 1 process(es) using it: 900 sh in {HOST}: working directory; \
                 mounted in 2 mount namespace(s): \
                 {HOST} (this process's): mounted at {MNT} (shared:12), 2 process(es), e.g. 1 systemd; \
                 {UDEV}: mounted at {MNT} (master:12), 1 process(es), e.g. 812 (udev-worker)"
            )
        );
        let one = report(&h, Some(HOST), 1);
        assert!(one.ends_with("e.g. 1 systemd; and 1 more"), "{one}");
    }

    /// The first report on the test VM (2026-11-27) listed every process of
    /// the host's namespace, each seeing the host's own mount, and the
    /// cap ran out before any that mattered.  A user of the mount in
    /// another namespace comes first, however many processes see it.
    #[test]
    fn a_user_is_never_hidden_behind_the_processes_that_only_see_the_mount() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        let shared = line(40, "259:7", MNT, "shared:12", "/dev/ublkb7");
        for pid in 1..=400 {
            process(proc, pid, "kworker", HOST, &shared);
        }
        let slave = line(90, "259:7", MNT, "master:12", "/dev/ublkb7");
        let svc = process(proc, 4000, "chronyd", "mnt:[4026532400]", &slave);
        symlink(format!("{MNT}/f"), svc.join("fd/7")).unwrap();
        let r = report(&of_mount(proc, Path::new(MNT)), Some(HOST), 12);
        assert!(
            r.starts_with(&format!(
                "held by 1 process(es) using it: 4000 chronyd in mnt:[4026532400]: open file {MNT}/f; \
                 mounted in 2 mount namespace(s): "
            )),
            "{r}"
        );
        assert!(r.contains("400 process(es), e.g. 1 kworker"), "{r}");
    }

    #[test]
    fn a_device_is_held_by_a_mount_anywhere_or_an_open_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        // The device by name (no node to read a number from in a test).
        let dev = Path::new("/dev/ublkb7");
        process(proc, 1, "systemd", HOST, "");
        process(
            proc,
            77,
            "chronyd",
            "mnt:[4026532400]",
            &line(50, "259:7", MNT, "", "/dev/ublkb7"),
        );
        let probe = process(proc, 813, "(udev-worker)", UDEV, "");
        symlink("/dev/ublkb7", probe.join("fd/5")).unwrap();
        let h = of_device(proc, dev);
        assert_eq!(
            h.iter()
                .map(|h| (h.pid, h.mounted.clone(), h.uses.clone()))
                .collect::<Vec<_>>(),
            [
                (77, vec![format!("at {MNT} (private)")], vec![]),
                (813, vec![], vec!["open".to_string()]),
            ]
        );
        assert_eq!(
            report(&h, Some(HOST), 10),
            format!(
                "held by 1 process(es) using it: 813 (udev-worker) in {UDEV}: open; \
                 mounted in 1 mount namespace(s): mnt:[4026532400]: mounted at {MNT} (private), 1 process(es), e.g. 77 chronyd"
            )
        );
    }

    #[test]
    fn nobody_found_is_said_as_such() {
        let dir = tempfile::tempdir().unwrap();
        process(dir.path(), 1, "systemd", HOST, "");
        let h = of_mount(dir.path(), Path::new(MNT));
        assert!(h.is_empty());
        assert!(report(&h, Some(HOST), 10).starts_with("held by: nobody found"));
    }

    #[test]
    fn mountinfo_lines_are_read_as_the_kernel_writes_them() {
        let m = parse_mount(
            "36 35 98:0 / /mnt/with\\040space rw,noatime master:1 shared:3 - ext4 /dev/root rw",
        )
        .unwrap();
        assert_eq!(m.device, "98:0");
        assert_eq!(m.point, Path::new("/mnt/with space"));
        assert_eq!(m.tags, "master:1 shared:3");
        assert_eq!(m.source, Path::new("/dev/root"));
        assert!(parse_mount("garbage").is_none());
        // A name with characters of more than one byte, and a backslash
        // not followed by three octal digits, read as they are.
        assert_eq!(
            unescape("/mnt/\u{e4}\u{f6}\\040x\\9"),
            "/mnt/\u{e4}\u{f6} x\\9"
        );
        // A device number as the kernel encodes one (major 259, minor 7).
        assert_eq!(device_number((259 << 8) | 7), "259:7");
        assert_eq!(
            device_number(((259u64 & 0xfff) << 8) | (300 & 0xff) | ((300 & !0xff) << 12)),
            "259:300"
        );
    }

    #[test]
    fn the_real_proc_reads() {
        // On any Linux host: this process's own namespace, and a scan that
        // finds nobody holding a directory no one mounts.
        let proc = Path::new("/proc");
        assert!(own_ns(proc).is_some_and(|n| n.starts_with("mnt:[")));
        let dir = tempfile::tempdir().unwrap();
        assert!(of_mount(proc, &dir.path().join("none")).is_empty());
    }
}
