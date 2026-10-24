//! Classification and manifests (P4 spec rev. 9 §8; D26–D32).
//!
//! A **classification map** gives every path of a tree a class
//! ([`PathClass`]): an ordered list of globs, read from TOML (D28), where
//! the most specific matching glob wins (D26).  A **manifest** is the walk
//! of a sealed tree: every entry, sorted by path bytes, with its kind,
//! content (plain BLAKE3 for files, D27), size, mode, ownership slot,
//! mtime and class; plus the entries no class can describe, each with its
//! reason.  It is what a Candidate is judged and materialised from, so the
//! walk fails closed: anything it cannot describe exactly makes the
//! manifest unusable for a nomination (spec §3.1, §8).
//!
//! The walk never follows a symlink: every entry is opened relative to its
//! directory's file descriptor with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`
//! (`openat2`), and link targets are read with `readlinkat`.
//!
//! Supported hosts are Linux without SELinux (D32): any xattr makes an
//! entry unsupported, so under SELinux every entry would be; the Warden
//! refuses to start there (file 3b).
//!
//! Normative reference: `Taso_spec_p4_contracts` rev. 9, BLAKE3
//! `9c3a984fc45d213b024a4b93a1cb519c4f176c0a3366db7a3f81484029892dc5`.

use std::ffi::CStr;
use std::fmt;
use std::io::{self, Read};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::fs::{
    flistxattr, llistxattr, openat2, readlinkat, statat, AtFlags, FileType, Mode, OFlags,
    ResolveFlags, CWD,
};
use taso_core::canon::Canon;
use taso_core::contract::{object_key, ClassCounts, ObjectKind, PathClass};
use taso_core::envelope::HashVal;

// ── The classification map (D26, D28) ───────────────────────────────

/// Why a classification map is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapError(pub String);

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "classification map: {}", self.0)
    }
}

impl std::error::Error for MapError {}

/// One component of a glob.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    /// `**`: zero or more whole components.
    Any,
    /// A component pattern: bytes, `*` and `?`.
    Pat(Vec<u8>),
}

/// A glob (D26).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Glob {
    text: String,
    parts: Vec<Part>,
    /// Ends with `/`: matches the directory and everything below it.
    dir: bool,
    /// (literal components, literal bytes).
    specificity: (u32, u32),
}

impl Glob {
    /// Parse a glob.  Refused: empty, a leading `/`, an empty, `.` or `..`
    /// component, `**` mixed with other bytes in one component.
    pub fn parse(text: &str) -> Result<Self, MapError> {
        let bad = |why: &str| MapError(format!("glob {text:?}: {why}"));
        if text.is_empty() {
            return Err(bad("empty"));
        }
        if text.starts_with('/') {
            return Err(bad("leading '/'"));
        }
        let (body, dir) = match text.strip_suffix('/') {
            Some(b) => (b, true),
            None => (text, false),
        };
        let mut parts = Vec::new();
        let (mut lit_c, mut lit_b) = (0u32, 0u32);
        for c in body.split('/') {
            match c {
                "" => return Err(bad("empty component")),
                "." | ".." => return Err(bad("'.' or '..' component")),
                "**" => parts.push(Part::Any),
                _ if c.contains("**") => return Err(bad("'**' must be a whole component")),
                _ => {
                    let wild = c.bytes().filter(|b| matches!(b, b'*' | b'?')).count() as u32;
                    if wild == 0 {
                        lit_c += 1;
                    } else {
                        lit_b += c.len() as u32 - wild;
                    }
                    parts.push(Part::Pat(c.as_bytes().to_vec()));
                }
            }
        }
        Ok(Self {
            text: text.to_string(),
            parts,
            dir,
            specificity: (lit_c, lit_b),
        })
    }

    /// The glob as written.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// (literal components, literal bytes): the larger, the more specific.
    pub fn specificity(&self) -> (u32, u32) {
        self.specificity
    }

    /// Whether the glob matches `path` (components joined by `/`).  A
    /// directory glob also matches every path below what it matches.
    pub fn matches(&self, path: &[u8]) -> bool {
        let comps: Vec<&[u8]> = path.split(|&b| b == b'/').collect();
        if self.dir {
            (1..=comps.len()).any(|n| match_parts(&self.parts, &comps[..n]))
        } else {
            match_parts(&self.parts, &comps)
        }
    }
}

fn match_parts(parts: &[Part], comps: &[&[u8]]) -> bool {
    match parts.split_first() {
        None => comps.is_empty(),
        Some((Part::Any, rest)) => (0..=comps.len()).any(|k| match_parts(rest, &comps[k..])),
        Some((Part::Pat(p), rest)) => {
            !comps.is_empty() && match_comp(p, comps[0]) && match_parts(rest, &comps[1..])
        }
    }
}

/// `*` any run, `?` one byte, everything else itself (within a component).
fn match_comp(p: &[u8], s: &[u8]) -> bool {
    match p.split_first() {
        None => s.is_empty(),
        Some((b'*', rest)) => (0..=s.len()).any(|k| match_comp(rest, &s[k..])),
        Some((b'?', rest)) => !s.is_empty() && match_comp(rest, &s[1..]),
        Some((c, rest)) => s.first() == Some(c) && match_comp(rest, &s[1..]),
    }
}

/// A classification map: ordered rules, and the key of its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classmap {
    rules: Vec<(Glob, PathClass)>,
    key: HashVal,
}

impl Classmap {
    /// Read a map from its TOML bytes (D28): `version = 1` and `[[rule]]`
    /// tables with exactly `glob` and `class`.  Anything else is refused.
    pub fn parse(bytes: &[u8]) -> Result<Self, MapError> {
        let text = std::str::from_utf8(bytes).map_err(|_| MapError("not UTF-8".into()))?;
        let doc: toml::Table = text.parse().map_err(|e| MapError(format!("{e}")))?;
        for k in doc.keys() {
            if k != "version" && k != "rule" {
                return Err(MapError(format!("unknown key {k:?}")));
            }
        }
        if doc.get("version").and_then(|v| v.as_integer()) != Some(1) {
            return Err(MapError("version must be 1".into()));
        }
        let rules = match doc.get("rule") {
            None => &Vec::new(),
            Some(toml::Value::Array(a)) => a,
            Some(_) => return Err(MapError("'rule' must be an array of tables".into())),
        };
        let mut out: Vec<(Glob, PathClass)> = Vec::new();
        for (i, r) in rules.iter().enumerate() {
            let t = r
                .as_table()
                .ok_or_else(|| MapError(format!("rule {i} is not a table")))?;
            for k in t.keys() {
                if k != "glob" && k != "class" {
                    return Err(MapError(format!("rule {i}: unknown key {k:?}")));
                }
            }
            let glob = t
                .get("glob")
                .and_then(|v| v.as_str())
                .ok_or_else(|| MapError(format!("rule {i}: 'glob' must be a string")))?;
            let class = t
                .get("class")
                .and_then(|v| v.as_str())
                .ok_or_else(|| MapError(format!("rule {i}: 'class' must be a string")))?;
            let class = match class {
                "Source" => PathClass::Source,
                "Config" => PathClass::Config,
                "Hook" => PathClass::Hook,
                "Secret" => PathClass::Secret,
                "Scratch" => PathClass::Scratch,
                "Artifact" => PathClass::Artifact,
                other => return Err(MapError(format!("rule {i}: unknown class {other:?}"))),
            };
            let g = Glob::parse(glob)?;
            if out.iter().any(|(o, c)| o.text == g.text && *c == class) {
                return Err(MapError(format!("rule {i}: duplicate rule")));
            }
            out.push((g, class));
        }
        Ok(Self {
            rules: out,
            key: object_key(ObjectKind::Classmap, bytes),
        })
    }

    /// The map's `classmap_key`: the content key of the bytes it was read
    /// from.
    pub fn key(&self) -> HashVal {
        self.key
    }

    /// The class of `path`: the most specific matching glob's; `Unknown`
    /// if none matches or the most specific ones disagree.
    pub fn classify(&self, path: &[u8]) -> PathClass {
        let mut best: Option<((u32, u32), PathClass)> = None;
        let mut tie = false;
        for (g, c) in &self.rules {
            if !g.matches(path) {
                continue;
            }
            match best {
                None => best = Some((g.specificity, *c)),
                Some((s, _)) if g.specificity > s => {
                    best = Some((g.specificity, *c));
                    tie = false;
                }
                Some((s, bc)) if g.specificity == s && *c != bc => tie = true,
                _ => {}
            }
        }
        match best {
            Some((_, c)) if !tie => c,
            _ => PathClass::Unknown,
        }
    }
}

// ── Manifests ───────────────────────────────────────────────────────

/// What an entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A regular file (tag 0).
    File,
    /// A directory (tag 1).
    Dir,
    /// A symlink whose target stays inside the root (tag 2).
    Symlink,
}

/// An entry's content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// A directory (tag 0).
    None,
    /// A file: plain BLAKE3 of its bytes (tag 1, D27).
    Blake3(HashVal),
    /// A symlink: its target bytes (tag 2).
    Target(Vec<u8>),
}

/// A modification time as the kernel stores it (D30): any date, before
/// 1970 or after 2262, exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mtime {
    /// Seconds since the epoch; negative before 1970.
    pub secs: i64,
    /// Nanoseconds, below 10⁹.
    pub nsec: u32,
}

/// One manifest entry (spec §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Relative path bytes, `/`-joined.
    pub path: Vec<u8>,
    /// What it is.
    pub kind: Kind,
    /// Its content.
    pub content: Content,
    /// Bytes for a file, target length for a symlink, 0 for a directory.
    pub size: u64,
    /// Permission bits (`st_mode & 0o7777`).
    pub mode: u32,
    /// Owner uid relative to the Vessel's slot base.
    pub uid_slot: u32,
    /// Owner gid relative to the Vessel's slot base.
    pub gid_slot: u32,
    /// Modification time (D30).
    pub mtime: Mtime,
    /// Its class.
    pub class: PathClass,
}

/// Why an entry cannot be described (spec §8, fail closed).  Tags in
/// the order the spec lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// A regular file with more than one name (tag 0).
    HardLink,
    /// A block or character device (tag 1).
    Device,
    /// A socket (tag 2).
    Socket,
    /// A FIFO (tag 3).
    Fifo,
    /// An absolute symlink, or one whose target leaves the root (tag 4).
    OutOfTreeLink,
    /// An extended attribute or ACL is present (tag 5).
    Xattr,
    /// It could not be opened or read (tag 6).
    Unreadable,
    /// Its path is longer than `max_path_bytes` (tag 7).
    PathTooLong,
    /// A reserved entry that does not match its definition (tag 8).
    ReservedMismatch,
    /// A kept symlink whose target the transform drops (tag 9; file 6).
    DanglingByExclusion,
    /// Owned outside the tree's slot range: something outside the Vessel
    /// wrote it (tag 10, D29).
    OwnerOutOfRange,
}

impl Unsupported {
    const ALL: [Self; 11] = [
        Self::HardLink,
        Self::Device,
        Self::Socket,
        Self::Fifo,
        Self::OutOfTreeLink,
        Self::Xattr,
        Self::Unreadable,
        Self::PathTooLong,
        Self::ReservedMismatch,
        Self::DanglingByExclusion,
        Self::OwnerOutOfRange,
    ];
}

/// Why a walk stopped early (spec §8, limits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incomplete {
    /// `max_entries` (tag 0).
    Entries,
    /// `max_total_bytes` (tag 1).
    TotalBytes,
    /// `max_depth` (tag 2).
    Depth,
    /// `max_walk_seconds` (tag 3).
    WalkTime,
    /// `max_manifest_bytes` (tag 4).
    ManifestBytes,
}

impl Incomplete {
    const ALL: [Self; 5] = [
        Self::Entries,
        Self::TotalBytes,
        Self::Depth,
        Self::WalkTime,
        Self::ManifestBytes,
    ];
}

/// A manifest (spec §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// The map it was classified with.
    pub classmap_key: HashVal,
    /// Every name directly under the root, reserved and unsupported
    /// ones included.
    pub root_entries: u64,
    /// The sum of the described files' sizes.
    pub total_bytes: u64,
    /// `None` if the walk finished; else why it stopped.
    pub incomplete: Option<Incomplete>,
    /// Every described entry, ascending by path bytes.
    pub entries: Vec<Entry>,
    /// Entries that cannot be described, ascending by path bytes.
    pub unsupported: Vec<(Vec<u8>, Unsupported)>,
}

/// The format version every manifest carries.
pub const MANIFEST_VERSION: u32 = 1;

impl Manifest {
    /// Whether the walk finished.
    pub fn complete(&self) -> bool {
        self.incomplete.is_none()
    }

    /// Per-class counts, and the unsupported count.
    pub fn counts(&self) -> ClassCounts {
        let mut c = ClassCounts {
            unsupported: self.unsupported.len() as u64,
            ..Default::default()
        };
        for e in &self.entries {
            let n = match e.class {
                PathClass::Source => &mut c.source,
                PathClass::Config => &mut c.config,
                PathClass::Hook => &mut c.hook,
                PathClass::Secret => &mut c.secret,
                PathClass::Scratch => &mut c.scratch,
                PathClass::Artifact => &mut c.artifact,
                PathClass::Unknown => &mut c.unknown,
                PathClass::Structural => &mut c.structural,
            };
            *n += 1;
        }
        c
    }

    /// The canonical bytes stored as the manifest object.
    pub fn bytes(&self) -> Vec<u8> {
        let mut c = Canon::new();
        c.u32(MANIFEST_VERSION);
        c.fixed(self.classmap_key.as_bytes());
        c.u64(self.root_entries).u64(self.total_bytes);
        match self.incomplete {
            None => {
                c.tag(0);
            }
            Some(i) => {
                c.tag(1).tag(i as u8);
            }
        }
        c.u64(self.entries.len() as u64);
        for e in &self.entries {
            c.bytes(&e.path).tag(e.kind as u8);
            match &e.content {
                Content::None => {
                    c.tag(0);
                }
                Content::Blake3(h) => {
                    c.tag(1).fixed(h.as_bytes());
                }
                Content::Target(t) => {
                    c.tag(2).bytes(t);
                }
            }
            c.u64(e.size)
                .u32(e.mode)
                .u32(e.uid_slot)
                .u32(e.gid_slot)
                .u64(e.mtime.secs as u64)
                .u32(e.mtime.nsec)
                .tag(e.class as u8);
        }
        c.u64(self.unsupported.len() as u64);
        for (p, u) in &self.unsupported {
            c.bytes(p).tag(*u as u8);
        }
        c.into_bytes()
    }

    /// Its object key (`taso.manifest.v1`).
    pub fn key(&self) -> HashVal {
        object_key(ObjectKind::Manifest, &self.bytes())
    }

    /// Strict decoding of a manifest object: the inverse of
    /// [`Manifest::bytes`]; entries and unsupported paths must be strictly
    /// ascending, and nothing may follow.
    pub fn decode(b: &[u8]) -> Result<Self, MapError> {
        let mut r = Rd { b, pos: 0 };
        let bad = |why: &str| MapError(format!("manifest: {why}"));
        if r.u32()? != MANIFEST_VERSION {
            return Err(bad("unknown version"));
        }
        let classmap_key = HashVal::from_bytes(r.fixed()?);
        let root_entries = r.u64()?;
        let total_bytes = r.u64()?;
        let incomplete = match r.u8()? {
            0 => None,
            1 => Some(
                *Incomplete::ALL
                    .get(r.u8()? as usize)
                    .ok_or_else(|| bad("bad incomplete reason"))?,
            ),
            _ => return Err(bad("bad option tag")),
        };
        let n = r.count()?;
        let mut entries: Vec<Entry> = Vec::new();
        for _ in 0..n {
            let path = r.bytes()?;
            let kind = match r.u8()? {
                0 => Kind::File,
                1 => Kind::Dir,
                2 => Kind::Symlink,
                _ => return Err(bad("bad kind")),
            };
            let content = match r.u8()? {
                0 => Content::None,
                1 => Content::Blake3(HashVal::from_bytes(r.fixed()?)),
                2 => Content::Target(r.bytes()?),
                _ => return Err(bad("bad content tag")),
            };
            let e = Entry {
                path,
                kind,
                content,
                size: r.u64()?,
                mode: r.u32()?,
                uid_slot: r.u32()?,
                gid_slot: r.u32()?,
                mtime: {
                    let secs = r.u64()? as i64;
                    let nsec = r.u32()?;
                    if nsec >= 1_000_000_000 {
                        return Err(bad("nsec out of range"));
                    }
                    Mtime { secs, nsec }
                },
                class: *CLASSES
                    .get(r.u8()? as usize)
                    .ok_or_else(|| bad("bad class"))?,
            };
            if entries.last().is_some_and(|l| l.path >= e.path) {
                return Err(bad("entries not strictly ascending"));
            }
            entries.push(e);
        }
        let n = r.count()?;
        let mut unsupported: Vec<(Vec<u8>, Unsupported)> = Vec::new();
        for _ in 0..n {
            let p = r.bytes()?;
            let u = *Unsupported::ALL
                .get(r.u8()? as usize)
                .ok_or_else(|| bad("bad unsupported reason"))?;
            if unsupported.last().is_some_and(|(l, _)| *l >= p) {
                return Err(bad("unsupported paths not strictly ascending"));
            }
            unsupported.push((p, u));
        }
        if r.pos != b.len() {
            return Err(bad("trailing bytes"));
        }
        Ok(Self {
            classmap_key,
            root_entries,
            total_bytes,
            incomplete,
            entries,
            unsupported,
        })
    }
}

const CLASSES: [PathClass; 8] = [
    PathClass::Source,
    PathClass::Config,
    PathClass::Hook,
    PathClass::Secret,
    PathClass::Scratch,
    PathClass::Artifact,
    PathClass::Unknown,
    PathClass::Structural,
];

struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Rd<'_> {
    fn take(&mut self, n: u64) -> Result<&[u8], MapError> {
        if n > (self.b.len() - self.pos) as u64 {
            return Err(MapError("manifest: truncated".into()));
        }
        let s = &self.b[self.pos..self.pos + n as usize];
        self.pos += n as usize;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, MapError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, MapError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn u64(&mut self) -> Result<u64, MapError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8")))
    }
    fn fixed(&mut self) -> Result<[u8; 32], MapError> {
        Ok(self.take(32)?.try_into().expect("32"))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, MapError> {
        let n = self.u64()?;
        Ok(self.take(n)?.to_vec())
    }
    /// A count no larger than the bytes left (every item is ≥ 1 byte).
    fn count(&mut self) -> Result<u64, MapError> {
        let n = self.u64()?;
        if n > (self.b.len() - self.pos) as u64 {
            return Err(MapError("manifest: truncated".into()));
        }
        Ok(n)
    }
}

// ── The walk ────────────────────────────────────────────────────────

/// Walk limits (spec §8, §11.1 defaults).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// `manifest.max_entries`.
    pub max_entries: u64,
    /// `manifest.max_total_bytes`.
    pub max_total_bytes: u64,
    /// `manifest.max_depth`.
    pub max_depth: u32,
    /// `manifest.max_path_bytes`.
    pub max_path_bytes: usize,
    /// `manifest.max_walk_seconds`.
    pub max_walk: Duration,
    /// `manifest.max_manifest_bytes`.
    pub max_manifest_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_total_bytes: 64 << 30,
            max_depth: 64,
            max_path_bytes: 4096,
            max_walk: Duration::from_secs(300),
            max_manifest_bytes: 256 << 20,
        }
    }
}

/// A reserved structural entry (spec §4.1.6, `fs.reserved`): a directory
/// directly under the root, with this name and mode, owned by slot 0,
/// empty.  Verified, not listed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reserved {
    /// Its name.
    pub name: Vec<u8>,
    /// Its permission bits.
    pub mode: u32,
}

impl Reserved {
    /// The default: `lost+found`, mode 0700.
    pub fn defaults() -> Vec<Self> {
        vec![Self {
            name: b"lost+found".to_vec(),
            mode: 0o700,
        }]
    }
}

/// The width of a slot range (spec §8, D29).
pub const SLOT_WIDTH: u32 = 65536;

/// The slot range the tree is stored in on disk (D29): `base ..
/// base + SLOT_WIDTH`.  For a Vessel whose files sit in its parent's
/// range (an idmapped work mount), that is the parent's range, not the
/// Vessel's host range.
#[derive(Clone, Copy, Debug)]
pub struct Owner {
    /// First uid of the range.
    pub uid_base: u32,
    /// First gid of the range.
    pub gid_base: u32,
}

/// The header [`Manifest::bytes`] writes for a complete walk: version,
/// classmap key, root entries, total bytes, the `None` tag, and the two
/// list counts.  `max_manifest_bytes` bounds the complete encoding; a
/// walk it stops carries one byte more, the reason.
const HEADER: u64 = 4 + 32 + 8 + 8 + 1 + 8 + 8;

struct Walker<'a> {
    map: &'a Classmap,
    owner: Owner,
    limits: &'a Limits,
    reserved: &'a [Reserved],
    deadline: Instant,
    entries: Vec<Entry>,
    unsupported: Vec<(Vec<u8>, Unsupported)>,
    total: u64,
    /// The exact length [`Manifest::bytes`] would have now.
    size: u64,
    stop: Option<Incomplete>,
}

/// Walk the tree at `root` (a directory, normally a sealed, read-only
/// mount) into a manifest.  Errors are only for the root itself; every
/// entry below it is described or listed as unsupported.
pub fn walk(
    root: &Path,
    map: &Classmap,
    owner: Owner,
    limits: &Limits,
    reserved: &[Reserved],
) -> io::Result<Manifest> {
    let fd = openat2(
        CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::empty(),
    )?;
    let mut w = Walker {
        map,
        owner,
        limits,
        reserved,
        deadline: Instant::now() + limits.max_walk,
        entries: Vec::new(),
        unsupported: Vec::new(),
        total: 0,
        size: HEADER,
        stop: None,
    };
    let root_entries = w.dir(&fd, &[], 1)?;
    w.entries.sort_by(|a, b| a.path.cmp(&b.path));
    w.unsupported.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Manifest {
        classmap_key: map.key(),
        root_entries,
        total_bytes: w.total,
        incomplete: w.stop,
        entries: w.entries,
        unsupported: w.unsupported,
    })
}

fn names(dir: &OwnedFd) -> io::Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for e in rustix::fs::Dir::read_from(dir)? {
        let e = e?;
        let n = e.file_name().to_bytes();
        if n != b"." && n != b".." {
            out.push(n.to_vec());
        }
    }
    out.sort();
    Ok(out)
}

/// Whether an xattr list (asked with an empty buffer, so the answer is
/// the list's length) names any attribute.  A filesystem without xattrs
/// has none.
fn has_xattr(list: rustix::io::Result<usize>) -> Result<bool, ()> {
    match list {
        Ok(n) => Ok(n > 0),
        Err(rustix::io::Errno::NOTSUP) => Ok(false),
        Err(_) => Err(()),
    }
}

/// Lexically resolve a symlink target from the link's directory; whether
/// it stays inside the root.
fn in_tree(link_dir: &[u8], target: &[u8]) -> bool {
    if target.is_empty() || target.starts_with(b"/") {
        return false;
    }
    let mut stack: Vec<&[u8]> = link_dir
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .collect();
    for c in target.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                if stack.pop().is_none() {
                    return false;
                }
            }
            other => stack.push(other),
        }
    }
    true
}

impl Walker<'_> {
    fn over(&mut self, i: Incomplete) -> bool {
        if self.stop.is_none() {
            self.stop = Some(i);
        }
        true
    }

    fn stopped(&mut self) -> bool {
        if self.stop.is_some() {
            return true;
        }
        if Instant::now() > self.deadline {
            return self.over(Incomplete::WalkTime);
        }
        false
    }

    /// List an entry as unsupported, unless a limit stops the walk.
    fn unsupported(&mut self, path: Vec<u8>, why: Unsupported) {
        let cost = 8 + path.len() as u64 + 1;
        if self.room(cost) {
            self.unsupported.push((path, why));
        }
    }

    /// Whether one more listed item of `cost` bytes fits `max_entries`
    /// (which counts described and unsupported entries alike) and
    /// `max_manifest_bytes`; if it does, it is counted.
    fn room(&mut self, cost: u64) -> bool {
        if (self.entries.len() + self.unsupported.len()) as u64 >= self.limits.max_entries {
            self.over(Incomplete::Entries);
            return false;
        }
        if self.size + cost > self.limits.max_manifest_bytes {
            self.over(Incomplete::ManifestBytes);
            return false;
        }
        self.size += cost;
        true
    }

    /// Walk directory `fd` (path `prefix`, at `depth`); returns how many
    /// entries it holds.
    fn dir(&mut self, fd: &OwnedFd, prefix: &[u8], depth: u32) -> io::Result<u64> {
        let list = names(fd)?;
        let n = list.len() as u64;
        for name in list {
            if self.stopped() {
                break;
            }
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                [prefix, b"/", &name].concat()
            };
            self.entry(fd, &name, path, prefix, depth);
        }
        Ok(n)
    }

    fn entry(&mut self, dir: &OwnedFd, name: &[u8], path: Vec<u8>, prefix: &[u8], depth: u32) {
        if path.len() > self.limits.max_path_bytes {
            return self.unsupported(path, Unsupported::PathTooLong);
        }
        let cname = match std::ffi::CString::new(name) {
            Ok(c) => c,
            Err(_) => return self.unsupported(path, Unsupported::Unreadable),
        };
        let st = match statat(dir, cname.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(s) => s,
            Err(_) => return self.unsupported(path, Unsupported::Unreadable),
        };
        let ft = FileType::from_raw_mode(st.st_mode as _);
        let mode = st.st_mode as u32 & 0o7777;
        let (uid, gid) = (st.st_uid as u32, st.st_gid as u32);
        // Reserved structural entries: verified, never listed.
        if prefix.is_empty() {
            if let Some(r) = self.reserved.iter().find(|r| r.name == name) {
                let ok = ft == FileType::Directory
                    && mode == r.mode
                    && uid == self.owner.uid_base
                    && gid == self.owner.gid_base
                    && self.empty_dir(dir, cname.as_c_str());
                if !ok {
                    self.unsupported(path, Unsupported::ReservedMismatch);
                }
                return;
            }
        }
        let in_range = |v: u32, base: u32| v.checked_sub(base).filter(|s| *s < SLOT_WIDTH);
        let (Some(uid_slot), Some(gid_slot)) = (
            in_range(uid, self.owner.uid_base),
            in_range(gid, self.owner.gid_base),
        ) else {
            return self.unsupported(path, Unsupported::OwnerOutOfRange);
        };
        let mtime = Mtime {
            secs: st.st_mtime as i64,
            nsec: st.st_mtime_nsec as u32,
        };
        let class = self.map.classify(&path);
        let mut e = Entry {
            path: path.clone(),
            kind: Kind::Dir,
            content: Content::None,
            size: 0,
            mode,
            uid_slot,
            gid_slot,
            mtime,
            class,
        };
        match ft {
            FileType::Directory => {
                if depth > self.limits.max_depth {
                    self.over(Incomplete::Depth);
                    return;
                }
                let sub = match self.open(dir, cname.as_c_str(), OFlags::DIRECTORY) {
                    Ok(f) => f,
                    Err(_) => return self.unsupported(path, Unsupported::Unreadable),
                };
                match has_xattr(flistxattr(&sub, &mut [0u8; 0][..])) {
                    Ok(false) => {}
                    Ok(true) => return self.unsupported(path, Unsupported::Xattr),
                    Err(()) => return self.unsupported(path, Unsupported::Unreadable),
                }
                if !self.push(e) {
                    return;
                }
                if self.dir(&sub, &path, depth + 1).is_err() {
                    self.unsupported(path, Unsupported::Unreadable);
                }
            }
            FileType::RegularFile => {
                if st.st_nlink as u64 > 1 {
                    return self.unsupported(path, Unsupported::HardLink);
                }
                let f = match self.open(dir, cname.as_c_str(), OFlags::empty()) {
                    Ok(f) => f,
                    Err(_) => return self.unsupported(path, Unsupported::Unreadable),
                };
                match has_xattr(flistxattr(&f, &mut [0u8; 0][..])) {
                    Ok(false) => {}
                    Ok(true) => return self.unsupported(path, Unsupported::Xattr),
                    Err(()) => return self.unsupported(path, Unsupported::Unreadable),
                }
                let size = st.st_size as u64;
                if self.total + size > self.limits.max_total_bytes {
                    self.over(Incomplete::TotalBytes);
                    return;
                }
                let mut h = blake3::Hasher::new();
                let mut file = std::fs::File::from(f);
                let mut buf = vec![0u8; 1 << 16];
                let mut read = 0u64;
                loop {
                    match file.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            h.update(&buf[..n]);
                            read += n as u64;
                        }
                        Err(_) => return self.unsupported(path, Unsupported::Unreadable),
                    }
                }
                if read != size {
                    return self.unsupported(path, Unsupported::Unreadable);
                }
                self.total += size;
                e.kind = Kind::File;
                e.size = size;
                e.content = Content::Blake3(HashVal::from_bytes(*h.finalize().as_bytes()));
                self.push(e);
            }
            FileType::Symlink => {
                let target = match readlinkat(dir, cname.as_c_str(), Vec::new()) {
                    Ok(t) => t.into_bytes(),
                    Err(_) => return self.unsupported(path, Unsupported::Unreadable),
                };
                if !in_tree(prefix, &target) {
                    return self.unsupported(path, Unsupported::OutOfTreeLink);
                }
                let proc = format!("/proc/self/fd/{}/", std::os::fd::AsRawFd::as_raw_fd(dir));
                let full = [proc.as_bytes(), name].concat();
                let cfull = match std::ffi::CString::new(full) {
                    Ok(c) => c,
                    Err(_) => return self.unsupported(path, Unsupported::Unreadable),
                };
                match has_xattr(llistxattr(cfull.as_c_str(), &mut [0u8; 0][..])) {
                    Ok(false) => {}
                    Ok(true) => return self.unsupported(path, Unsupported::Xattr),
                    Err(()) => return self.unsupported(path, Unsupported::Unreadable),
                }
                e.kind = Kind::Symlink;
                e.size = target.len() as u64;
                e.content = Content::Target(target);
                self.push(e);
            }
            FileType::BlockDevice | FileType::CharacterDevice => {
                self.unsupported(path, Unsupported::Device)
            }
            FileType::Socket => self.unsupported(path, Unsupported::Socket),
            FileType::Fifo => self.unsupported(path, Unsupported::Fifo),
            _ => self.unsupported(path, Unsupported::Unreadable),
        }
    }

    fn open(&self, dir: &OwnedFd, name: &CStr, extra: OFlags) -> io::Result<OwnedFd> {
        Ok(openat2(
            dir.as_fd(),
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | extra,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )?)
    }

    fn empty_dir(&self, dir: &OwnedFd, name: &CStr) -> bool {
        self.open(dir, name, OFlags::DIRECTORY)
            .and_then(|f| names(&f))
            .is_ok_and(|n| n.is_empty())
    }

    /// Add an entry, unless a limit stops the walk.  Whether it was added.
    fn push(&mut self, e: Entry) -> bool {
        // Path, kind, content tag, content, size, mode, slots, mtime, class.
        let cost = 8
            + e.path.len() as u64
            + 2
            + match &e.content {
                Content::None => 0,
                Content::Blake3(_) => 32,
                Content::Target(t) => 8 + t.len() as u64,
            }
            + 8
            + 4
            + 4
            + 4
            + 8
            + 4
            + 1;
        if !self.room(cost) {
            return false;
        }
        self.entries.push(e);
        true
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn map(toml: &str) -> Classmap {
        Classmap::parse(toml.as_bytes()).unwrap()
    }

    const MAP: &str = r#"
version = 1
[[rule]]
glob = "src/**"
class = "Source"
[[rule]]
glob = "build/"
class = "Scratch"
[[rule]]
glob = "build/keep.txt"
class = "Artifact"
[[rule]]
glob = "*.toml"
class = "Config"
[[rule]]
glob = ".env"
class = "Secret"
[[rule]]
glob = "hooks/*.sh"
class = "Hook"
"#;

    // ── globs ───────────────────────────────────────────────────────

    #[test]
    fn globs_match_by_component() {
        let g = |s: &str| Glob::parse(s).unwrap();
        assert!(g("src/*.rs").matches(b"src/a.rs"));
        assert!(
            !g("src/*.rs").matches(b"src/x/a.rs"),
            "'*' stays in one component"
        );
        assert!(
            g("src/**/a.rs").matches(b"src/a.rs"),
            "'**' matches zero components"
        );
        assert!(g("src/**/a.rs").matches(b"src/x/y/a.rs"));
        assert!(
            g("src/**").matches(b"src"),
            "'**' at the end matches the directory itself"
        );
        assert!(g("a?c").matches(b"abc"));
        assert!(!g("a?c").matches(b"ac"));
        assert!(g("build/").matches(b"build"));
        assert!(
            g("build/").matches(b"build/x/y"),
            "a directory glob covers its subtree"
        );
        assert!(!g("build").matches(b"build/x"), "a plain glob does not");
        assert!(!g("build/").matches(b"buildx"));
    }

    #[test]
    fn bad_globs_are_refused() {
        for bad in ["", "/a", "a//b", "./a", "a/../b", "a/**b", "a**/b"] {
            assert!(Glob::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn specificity_is_literal_components_then_literal_bytes() {
        let s = |x: &str| Glob::parse(x).unwrap().specificity();
        assert_eq!(s("src/**"), (1, 0));
        assert_eq!(s("build/keep.txt"), (2, 0));
        assert_eq!(s("*.toml"), (0, 5));
        assert_eq!(s("**"), (0, 0));
        assert!(s("build/keep.txt") > s("build/"));
        assert!(s("src/*.rs") > s("src/**"));
    }

    // ── maps ────────────────────────────────────────────────────────

    #[test]
    fn the_most_specific_rule_wins_and_ties_are_unknown() {
        let m = map(MAP);
        assert_eq!(m.classify(b"src/a/b.rs"), PathClass::Source);
        assert_eq!(m.classify(b"build/x.o"), PathClass::Scratch);
        assert_eq!(
            m.classify(b"build/keep.txt"),
            PathClass::Artifact,
            "deeper literal glob wins"
        );
        assert_eq!(m.classify(b"Cargo.toml"), PathClass::Config);
        assert_eq!(m.classify(b".env"), PathClass::Secret);
        assert_eq!(m.classify(b"hooks/pre.sh"), PathClass::Hook);
        assert_eq!(m.classify(b"README"), PathClass::Unknown, "no match");
        let tie = map(
            "version = 1\n[[rule]]\nglob = \"*.md\"\nclass = \"Source\"\n[[rule]]\nglob = \"?.md\"\nclass = \"Scratch\"\n",
        );
        assert_eq!(
            tie.classify(b"a.md"),
            PathClass::Unknown,
            "equal specificity, different classes"
        );
    }

    #[test]
    fn maps_are_strict() {
        for bad in [
            "",
            "version = 2",
            "version = 1\nextra = 1",
            "version = 1\n[[rule]]\nglob = \"a\"\nclass = \"Source\"\nwhy = \"x\"",
            "version = 1\n[[rule]]\nglob = \"a\"\nclass = \"Structural\"",
            "version = 1\n[[rule]]\nglob = \"a\"\nclass = \"Source\"\n[[rule]]\nglob = \"a\"\nclass = \"Source\"",
            "version = 1\n[[rule]]\nglob = \"/a\"\nclass = \"Source\"",
            "version = 1\nrule = 3",
        ] {
            assert!(Classmap::parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let a = map(MAP);
        let b = map(&MAP.replace("Hook", "Config"));
        assert_ne!(a.key(), b.key(), "the key is the bytes'");
        assert_eq!(a.key(), object_key(ObjectKind::Classmap, MAP.as_bytes()));
    }

    // ── walks ───────────────────────────────────────────────────────

    fn me() -> Owner {
        // The test's own ids as slot 0.
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        Owner {
            uid_base: uid,
            gid_base: gid,
        }
    }

    fn tree() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        fs::create_dir_all(p.join("src/inner")).unwrap();
        fs::write(p.join("src/main.rs"), b"fn main() {}").unwrap();
        fs::write(p.join("src/inner/lib.rs"), b"").unwrap();
        fs::create_dir(p.join("build")).unwrap();
        fs::write(p.join("build/x.o"), vec![7u8; 1000]).unwrap();
        fs::write(p.join("Cargo.toml"), b"[package]").unwrap();
        fs::set_permissions(p.join("Cargo.toml"), fs::Permissions::from_mode(0o640)).unwrap();
        symlink("src/main.rs", p.join("main")).unwrap();
        d
    }

    fn walk_it(root: &Path) -> Manifest {
        walk(
            root,
            &map(MAP),
            me(),
            &Limits::default(),
            &Reserved::defaults(),
        )
        .unwrap()
    }

    #[test]
    fn a_tree_walks_to_a_sorted_classified_manifest() {
        let d = tree();
        let m = walk_it(d.path());
        assert!(m.complete());
        assert!(m.unsupported.is_empty(), "{:?}", m.unsupported);
        let paths: Vec<&[u8]> = m.entries.iter().map(|e| e.path.as_slice()).collect();
        assert_eq!(
            paths,
            vec![
                &b"Cargo.toml"[..],
                b"build",
                b"build/x.o",
                b"main",
                b"src",
                b"src/inner",
                b"src/inner/lib.rs",
                b"src/main.rs"
            ]
        );
        assert_eq!(m.root_entries, 4);
        assert_eq!(m.total_bytes, 12 + 1000 + 9);
        let get = |p: &[u8]| m.entries.iter().find(|e| e.path == p).unwrap();
        let main = get(b"src/main.rs");
        assert_eq!(
            main.content,
            Content::Blake3(HashVal::from_bytes(
                *blake3::hash(b"fn main() {}").as_bytes()
            )),
            "plain BLAKE3 (D27)"
        );
        assert_eq!(main.class, PathClass::Source);
        assert_eq!(get(b"Cargo.toml").mode, 0o640);
        assert_eq!(get(b"build").size, 0, "directories have size 0");
        assert_eq!(get(b"build/x.o").class, PathClass::Scratch);
        let link = get(b"main");
        assert_eq!(link.kind, Kind::Symlink);
        assert_eq!(link.content, Content::Target(b"src/main.rs".to_vec()));
        assert_eq!(link.class, PathClass::Unknown);
        let c = m.counts();
        assert_eq!(
            (c.source, c.scratch, c.config, c.unknown, c.unsupported),
            (4, 2, 1, 1, 0)
        );
    }

    #[test]
    fn manifests_encode_and_decode_strictly() {
        let d = tree();
        let m = walk_it(d.path());
        let b = m.bytes();
        assert_eq!(Manifest::decode(&b).unwrap(), m);
        assert_eq!(m.key(), object_key(ObjectKind::Manifest, &b));
        let mut t = b.clone();
        t.push(0);
        assert!(Manifest::decode(&t).is_err(), "trailing bytes");
        assert!(Manifest::decode(&b[..b.len() - 1]).is_err(), "truncated");
        let mut swapped = m.clone();
        swapped.entries.swap(0, 1);
        assert!(Manifest::decode(&swapped.bytes()).is_err(), "out of order");
        // The same tree walks to the same bytes.
        assert_eq!(walk_it(d.path()).bytes(), b);
    }

    #[test]
    fn what_cannot_be_described_is_listed_not_described() {
        let d = tree();
        let p = d.path();
        fs::hard_link(p.join("src/main.rs"), p.join("src/twin.rs")).unwrap();
        symlink("/etc/passwd", p.join("abs")).unwrap();
        symlink("../../outside", p.join("src/escape")).unwrap();
        rustix::fs::mknodat(
            CWD,
            p.join("fifo").as_path(),
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let m = walk_it(p);
        let un: Vec<(&[u8], Unsupported)> = m
            .unsupported
            .iter()
            .map(|(p, u)| (p.as_slice(), *u))
            .collect();
        assert!(un.contains(&(&b"abs"[..], Unsupported::OutOfTreeLink)));
        assert!(un.contains(&(&b"src/escape"[..], Unsupported::OutOfTreeLink)));
        assert!(un.contains(&(&b"fifo"[..], Unsupported::Fifo)));
        assert!(
            un.contains(&(&b"src/main.rs"[..], Unsupported::HardLink)),
            "both names of a hard link"
        );
        assert!(un.contains(&(&b"src/twin.rs"[..], Unsupported::HardLink)));
        assert!(m.entries.iter().all(|e| e.path != b"src/main.rs"));
        assert_eq!(m.counts().unsupported, 5);
    }

    #[test]
    fn an_xattr_makes_an_entry_unsupported() {
        let d = tree();
        let f = d.path().join("Cargo.toml");
        match rustix::fs::setxattr(&f, "user.taso", b"x", rustix::fs::XattrFlags::empty()) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("skipped: user xattrs not supported here ({e})");
                return;
            }
        }
        let m = walk_it(d.path());
        assert!(m
            .unsupported
            .contains(&(b"Cargo.toml".to_vec(), Unsupported::Xattr)));
    }

    #[test]
    fn reserved_entries_are_verified_not_listed() {
        let d = tree();
        let lf = d.path().join("lost+found");
        fs::create_dir(&lf).unwrap();
        fs::set_permissions(&lf, fs::Permissions::from_mode(0o700)).unwrap();
        let m = walk_it(d.path());
        assert!(m.entries.iter().all(|e| e.path != b"lost+found"));
        assert!(m.unsupported.is_empty());
        // With content, or another mode: refused.
        fs::write(lf.join("x"), b"").unwrap();
        let m = walk_it(d.path());
        assert!(m
            .unsupported
            .contains(&(b"lost+found".to_vec(), Unsupported::ReservedMismatch)));
        fs::remove_file(lf.join("x")).unwrap();
        fs::set_permissions(&lf, fs::Permissions::from_mode(0o755)).unwrap();
        let m = walk_it(d.path());
        assert!(m
            .unsupported
            .contains(&(b"lost+found".to_vec(), Unsupported::ReservedMismatch)));
        // Below the root it is an ordinary name.
        fs::create_dir(d.path().join("src/lost+found")).unwrap();
        let m = walk_it(d.path());
        assert!(m.entries.iter().any(|e| e.path == b"src/lost+found"));
    }

    #[test]
    fn any_date_is_described_exactly() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let d = tree();
        let set = |name: &str, t: SystemTime| {
            fs::File::options()
                .write(true)
                .open(d.path().join(name))
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(t))
                .unwrap();
        };
        // 1960-01-01 and 2300-01-01 (D30: never refused).  The manifest
        // carries what the filesystem stores; ext4 stores both exactly (its
        // own limit is the year 2446), other filesystems may clamp.
        set("Cargo.toml", UNIX_EPOCH - Duration::from_secs(315_619_200));
        set("src/main.rs", UNIX_EPOCH + Duration::new(10_413_792_000, 5));
        let m = walk_it(d.path());
        assert!(m.unsupported.is_empty(), "{:?}", m.unsupported);
        let get = |p: &[u8]| m.entries.iter().find(|e| e.path == p).unwrap().mtime;
        let stored = |p: &str| {
            use std::os::unix::fs::MetadataExt;
            let md = fs::metadata(d.path().join(p)).unwrap();
            Mtime {
                secs: md.mtime(),
                nsec: md.mtime_nsec() as u32,
            }
        };
        assert_eq!(get(b"Cargo.toml"), stored("Cargo.toml"));
        assert_eq!(get(b"src/main.rs"), stored("src/main.rs"));
        assert!(get(b"Cargo.toml").secs < 0, "before 1970 is described");
        eprintln!(
            "dates as stored here: {:?} {:?}",
            get(b"Cargo.toml"),
            get(b"src/main.rs")
        );
        assert_eq!(Manifest::decode(&m.bytes()).unwrap(), m);
        // A decoded nsec of 10⁹ or more is refused.
        let mut bad = m.clone();
        bad.entries[0].mtime.nsec = 1_000_000_000;
        assert!(Manifest::decode(&bad.bytes()).is_err());
    }

    #[test]
    fn ownership_outside_the_range_is_unsupported() {
        let d = tree();
        let o = me();
        let shifted = Owner {
            uid_base: o.uid_base.wrapping_add(1),
            ..o
        };
        let m = walk(d.path(), &map(MAP), shifted, &Limits::default(), &[]).unwrap();
        assert!(m.entries.is_empty());
        assert!(m
            .unsupported
            .iter()
            .all(|(_, u)| *u == Unsupported::OwnerOutOfRange));
    }

    #[test]
    fn limits_stop_the_walk_and_say_which() {
        let d = tree();
        let w = |l: Limits| walk(d.path(), &map(MAP), me(), &l, &[]).unwrap();
        let m = w(Limits {
            max_entries: 3,
            ..Default::default()
        });
        assert_eq!(m.incomplete, Some(Incomplete::Entries));
        assert_eq!(m.entries.len(), 3);
        let m = w(Limits {
            max_total_bytes: 100,
            ..Default::default()
        });
        assert_eq!(m.incomplete, Some(Incomplete::TotalBytes));
        let m = w(Limits {
            max_depth: 1,
            ..Default::default()
        });
        assert_eq!(m.incomplete, Some(Incomplete::Depth));
        let m = w(Limits {
            max_manifest_bytes: 200,
            ..Default::default()
        });
        assert_eq!(m.incomplete, Some(Incomplete::ManifestBytes));
        assert!(m.bytes().len() <= 200 + 1, "plus the reason byte");
        // The byte limit is exact: the full manifest fits its own length
        // and not one byte less.
        let full = w(Limits::default()).bytes().len() as u64;
        let m = w(Limits {
            max_manifest_bytes: full,
            ..Default::default()
        });
        assert!(m.complete());
        let m = w(Limits {
            max_manifest_bytes: full - 1,
            ..Default::default()
        });
        assert_eq!(m.incomplete, Some(Incomplete::ManifestBytes));
        let m = w(Limits {
            max_walk: Duration::ZERO,
            ..Default::default()
        });
        assert_eq!(m.incomplete, Some(Incomplete::WalkTime));
        let m = w(Limits {
            max_path_bytes: 5,
            ..Default::default()
        });
        assert!(m.complete(), "a long path is unsupported, not a stop");
        assert!(m
            .unsupported
            .contains(&(b"src/inner".to_vec(), Unsupported::PathTooLong)));
        assert!(!m.complete() || Manifest::decode(&m.bytes()).is_ok());
    }

    #[test]
    fn symlinks_are_resolved_lexically() {
        assert!(in_tree(b"", b"a/b"));
        assert!(in_tree(b"a", b"../b"));
        assert!(!in_tree(b"a", b"../../b"));
        assert!(!in_tree(b"", b"/etc"));
        assert!(in_tree(b"a/b", b"./c/../d"));
        assert!(!in_tree(b"", b""));
    }
}
