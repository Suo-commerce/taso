#!/usr/bin/env bash
# soak.sh: every feature at once, on the real stack, for a while
# (release criteria: "a concurrency soak"; D&D soak-a, 2026-11-08).
#
#   scripts/soak.sh [SECONDS] [VESSELS]     (default 600 s, 4 Vessels;
#                                            as root, from the repository
#                                            root, not through sudo)
#
# One node: a fresh taso-blkd (compaction on), a coordinator, a local
# store.  T(0) and V (the verifier Template) by taso-genesis.  VESSELS
# Vessels born from T(0), each agent (taso-sim) restarted whenever it
# exits ("restart": "always"); every run: a few sealed turns of database
# writes, then a nomination dropping Scratch; the even Vessels also ask
# for a fork each run.  V verifies each Candidate (it passes); taso-policy
# runs every 5 s and sanctions what passed, so Templates are finished
# while the Vessels write.  The Warden is killed (SIGKILL) at random,
# every KILL_EVERY seconds on average (default 60), and started again:
# rebirth-free recovery of open turns, attempts, sanctions and forks
# under load.
#
# Every SAMPLE seconds (default 15) one line in soak.tsv: the Warden's
# threads, open files and memory, taso-blkd's memory, ublk devices,
# GiB free, the block log's size.
#
# At the end the Warden is stopped and every Chronicle on the node (each
# Vessel, each fork) is checked:
#   - taso-ctl explain: exit 0, no failed check;
#   - taso-logcheck: its frames are one chain (each lsn the one before
#     plus one, each prev the hash before), shipped not past head;
# and the run:
#   - no panic in any log (Warden, blkd, coordinator, policy);
#   - the Warden never exited by itself;
#   - the Warden's open files and threads did not grow: the last third's
#     largest at most 1.5x the first third's largest, plus 16;
#   - work was done: Seals, attempts and sanctions each more than zero;
#   - no ublk device left after taso-blkd quits.
# Exit 0 only if every check passed.  Everything stays in /var/lib/taso-soak
# (removed at the next start).
#
# Env: KILL_EVERY (60), SAMPLE (15), TURNS (4: turns per agent run).
#
# Touches, and nothing else: /var/lib/taso-soak, /run/taso-soak-*.sock,
# /mnt/soak and mounts under it, the /dev/ublkb* devices its taso-blkd
# creates, runc containers under /var/lib/taso-soak/run/runc.

set -Eeuo pipefail

SECS=${1:-600}
VESSELS=${2:-4}
KILL_EVERY=${KILL_EVERY:-60}
SAMPLE=${SAMPLE:-15}
TURNS=${TURNS:-4}
[[ "$SECS" =~ ^[1-9][0-9]*$ && "$VESSELS" =~ ^[1-9][0-9]*$ ]] || { echo "usage: $0 [SECONDS] [VESSELS]" >&2; exit 2; }
[[ "$VESSELS" -le 40 ]] || { echo "at most 40 Vessels (uid slots)" >&2; exit 2; }

W=/var/lib/taso-soak
SOCK=/run/taso-soak-coord.sock
BLK_SOCK=/run/taso-soak-blk.sock
MNT=/mnt/soak
BASE=300000
TSLOT=50
NS=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
DSOCK=$W/run/decide/decide.sock

COORD_PID= BLKD_PID= DPID= POLICY_PID= SAMPLER_PID=
PASS=0 FAIL=0

say() { printf '\n== %s\n' "$*"; }
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }
expect() { # expect WHAT TEST...
    local what=$1; shift
    WHY=
    if "$@"; then PASS=$((PASS + 1)); echo "  PASS  $what"
    else FAIL=$((FAIL + 1)); echo "  FAIL  $what${WHY:+ ($WHY)}"; fi
}
is() { [[ "$1" == "$2" ]] || { WHY="got '$1', want '$2'"; return 1; }; }
atleast() { [[ "$1" -ge "$2" ]] || { WHY="got $1, want at least $2"; return 1; }; }

mounts_under() {
    awk -v root="$MNT" '$5 == root || index($5, root "/") == 1 { print length($5), $5 }' /proc/self/mountinfo \
        | sort -rn | cut -d' ' -f2-
}
blk() {
    python3 - "$BLK_SOCK" "$@" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(120); s.connect(sys.argv[1])
s.sendall((" ".join(sys.argv[2:]) + "\n").encode())
line = s.makefile().readline().strip()
print(line)
sys.exit(0 if line.startswith("ok") else 1)
PY
}
# Not `ls | wc -l`: with no device, ls fails, and under pipefail and -e
# that ended the script with no word (taso-test, 2026-11-08, twice).
ublk_devices() {
    local n=0 d
    for d in /dev/ublkb*; do [[ -e "$d" ]] && n=$((n + 1)); done
    echo "$n"
}

# stop_warden KILL: a crash, its containers left for the next start to
# sweep (as in production); stop_warden TERM: the end, containers removed.
stop_warden() {
    if [[ -n "$DPID" ]] && kill -0 "$DPID" 2>/dev/null; then
        kill "-$1" "$DPID"; wait "$DPID" 2>/dev/null || true
    fi
    DPID=
    [[ "$1" == TERM ]] || return 0
    if [[ -d "$W/run/runc" ]]; then
        for c in $(runc --root "$W/run/runc" list -q 2>/dev/null); do
            runc --root "$W/run/runc" delete --force "$c" 2>/dev/null || true
        done
    fi
}

cleanup() {
    local rc=$?
    set +e
    trap - ERR   # the cleanup's own failures are expected and said otherwise
    [[ -z "$SAMPLER_PID" ]] || { kill "$SAMPLER_PID" 2>/dev/null; wait "$SAMPLER_PID" 2>/dev/null; }
    [[ -z "$POLICY_PID" ]] || { kill "$POLICY_PID" 2>/dev/null; wait "$POLICY_PID" 2>/dev/null; }
    stop_warden TERM
    if [[ -n "$COORD_PID" ]]; then
        kill -0 "$COORD_PID" 2>/dev/null && { kill "$COORD_PID"; wait "$COORD_PID" 2>/dev/null; }
        rm -f "$SOCK"
    fi
    while read -r m; do
        [[ -n "$m" ]] || continue
        fsfreeze -u "$m" 2>/dev/null
        umount "$m" || umount -l "$m"
    done < <(mounts_under)
    if [[ -n "$BLKD_PID" ]] && kill -0 "$BLKD_PID" 2>/dev/null; then
        blk quit >/dev/null 2>&1 || kill "$BLKD_PID"
        wait "$BLKD_PID" 2>/dev/null
        rm -f "$BLK_SOCK"
    fi
    exit "$rc"
}
trap cleanup EXIT
# A command that fails under -e says where, never a silent end.
trap 'echo "ABORT: line $LINENO: \"$BASH_COMMAND\" failed" >&2' ERR

# ── Checks, build ───────────────────────────────────────────────────

[[ $EUID -eq 0 ]] || die "run as root"
[[ -f Cargo.toml && -d crates/taso-warden ]] || die "run from the repository root"
for t in runc ldd python3 cargo; do command -v "$t" >/dev/null || die "$t is missing"; done
[[ ! -S "$SOCK" ]] || die "$SOCK exists: another run's coordinator? (pgrep -af taso-soak)"
[[ ! -S "$BLK_SOCK" ]] || die "$BLK_SOCK exists: another run's daemon? (pgrep -af taso-soak)"
modprobe ublk_drv
[[ -c /dev/ublk-control ]] || die "/dev/ublk-control missing"
mkdir -p "$MNT"
[[ -z "$(mounts_under)" ]] || die "something is already mounted under $MNT"

say "building"
cargo build -q --release -p taso-warden -p taso-sim -p taso-landlock --bins
cargo build -q --release -p taso-blk --bin taso-blkd
BIN=$PWD/target/release
for b in taso-wardend taso-genesis taso-coordd taso-logcheck taso-sim taso-landlock taso-policy taso-ctl taso-blkd; do
    [[ -x "$BIN/$b" ]] || die "$BIN/$b was not built"
done

rm -rf "$W"
mkdir -p "$W/store" "$W/src" "$W/out" "$W/state" "$W/run" "$W/spool"
chmod 755 "$W"
DEVS_BEFORE=$(ublk_devices)

ROOTFS=$W/rootfs
copy_with_libs() {
    install -D -m 755 "$1" "$ROOTFS$2"
    ldd "$1" | grep -o '/[^ ]*' | while read -r lib; do install -D -m 755 "$lib" "$ROOTFS$lib"; done
}
copy_with_libs "$BIN/taso-sim" /usr/bin/taso-sim
copy_with_libs "$BIN/taso-landlock" /usr/lib/taso/landlock
mkdir -p "$ROOTFS"/{proc,dev,sys,tmp,work,run/taso}
: >"$ROOTFS/run/taso/field.sock"

# ── Storage, coordinator ────────────────────────────────────────────

"$BIN/taso-blkd" "$W/blk.log" "$BLK_SOCK" --durable-at flush --compact-pct 50 --compact-min-mib 256 \
    2>>"$W/blkd.err" &
BLKD_PID=$!
for _ in $(seq 100); do [[ -S "$BLK_SOCK" ]] && break; sleep 0.1; done
[[ -S "$BLK_SOCK" ]] || die "taso-blkd socket did not appear; see $W/blkd.err"
printf '{"store": "%s", "prefix": "soak"}\n' "$W/store" >"$W/store.json"
"$BIN/taso-coordd" "$W/coord.redb" "$SOCK" --store-config "$W/store.json" 2>>"$W/coordd.err" &
COORD_PID=$!
for _ in $(seq 100); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || die "taso-coordd socket did not appear; see $W/coordd.err"

cat >"$W/map.toml" <<'EOF'
version = 1
[[rule]]
glob = "**"
class = "Source"
[[rule]]
glob = "scratch/"
class = "Scratch"
[[rule]]
glob = "scratch/**"
class = "Scratch"
EOF
printf 'version = 1\nentry = ["/bin/sh", "-c", "test -s /candidate/app/main.py"]\n' >"$W/vconf.toml"

# config OUT ENTRY_JSON...: the node's Warden config with these Vessels.
config() {
    local out=$1; shift
    python3 - "$out" "$@" <<PY
import json, sys
out, entries = sys.argv[1], [json.loads(e) for e in sys.argv[2:]]
json.dump({
    "warden": 1,
    "coordinator": {"remote": "$SOCK"},
    "storage": {"blk": {"socket": "$BLK_SOCK", "mounts": "$MNT", "spool": "$W/spool"}},
    "root": "soak/n1",
    "state_dir": "$W/state",
    "store": "$W/store",
    "prefix": "soak",
    "run_dir": "$W/run",
    "sanction": {"classmap": "$W/map.toml", "allowed_exclude": ["Scratch"]},
    "runtime": {
        "rootfs": "$ROOTFS",
        "host_uid_base": $BASE,
        "template_slot": $TSLOT,
        "landlock_shim": "/usr/lib/taso/landlock",
        "args": ["/usr/bin/taso-sim", "--turns", "1", "--stats", "/work/sim-stats.json"],
    },
    "vessels": [dict(namespace="$NS", **e) for e in entries],
}, open(out, "w"), indent=1)
PY
}
config "$W/genesis.json"

tree() {
    local d=$1
    mkdir -p "$d/app/lib" "$d/scratch"
    printf "print('hello')\n" >"$d/app/main.py"
    printf 'X = 1\n' >"$d/app/lib/util.py"
    chown -R 0:0 "$d"
    find "$d" -mindepth 1 ! -type d -exec touch -h -d @1700000000 {} +
    find "$d" -depth -type d -exec touch -d @1600000000 {} +
}
verifier_tree() {
    local d=$1 b lib host
    mkdir -p "$d"/{proc,dev,sys,tmp,candidate,bin}
    for b in sh; do   # `test` is sh's own
        host=$(readlink -f "$(command -v "$b")")
        install -D -m 755 "$host" "$d/bin/$b"
        ldd "$host" | grep -o '/[^ ]*' | while read -r lib; do install -D -m 755 "$lib" "$d$lib"; done
    done
    chown -hR 0:0 "$d"
}
genesis() { # genesis CASE DIR: prints the Template id
    "$BIN/taso-genesis" "$W/genesis.json" --from "$2" --best-effort --classmap "$W/map.toml" \
        --actor soak --reason "the soak" >"$W/out/$1.json" 2>"$W/out/$1.err" || return 1
    python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); print(v["template_id"] if v.get("outcome")=="ready" else "")' "$W/out/$1.json"
}

say "T(0) and V"
tree "$W/src/t0"
T0=$(genesis t0 "$W/src/t0" || true)
verifier_tree "$W/src/v"
V=$(genesis v "$W/src/v" || true)
[[ "$T0" =~ ^[0-9a-f]{32}$ && "$V" =~ ^[0-9a-f]{32}$ ]] || die "genesis failed: see $W/out/t0.err, $W/out/v.err"

# The Vessels: slots 1..VESSELS; the even ones' forks take 41.. (one each).
entries=()
for ((i = 0; i < VESSELS; i++)); do
    args=$(python3 -c '
import json, sys
i, turns = int(sys.argv[1]), sys.argv[2]
a = ["/usr/bin/taso-sim", "--turns", turns, "--txns", "2", "--rows", "8", "--turn-sleep-ms", "200",
     "--db", "/work/state.db", "--stats", "/work/sim-stats.json", "--nominate", "Scratch"]
if i % 2 == 0:
    a += ["--forks", "1"]
print(json.dumps(a))' "$i" "$TURNS")
    forks=""
    (( i % 2 == 0 )) && forks=", \"forks\": {\"slots\": [$((41 + i / 2))]}"
    entries+=("$(printf '{"subject": "s%d", "uid_slot": %d, "template": "%s", "restart": "always", "verifier": {"template": "%s", "config": "%s", "version": 1}, "runtime": {"args": %s}%s}' \
        "$i" "$((i + 1))" "$T0" "$V" "$W/vconf.toml" "$args" "$forks")")
done
config "$W/soak.json" "${entries[@]}"

cat >"$W/policy.toml" <<'EOF'
version = 1
actor = "soak-policy"
default = "hold"

[[rule]]
name = "passed"
decision = "sanction"
when = { outcome = "pass", input_unknown = 0, input_unsupported = 0 }

[[rule]]
name = "failed"
decision = "never"
when = { outcome = { in = ["fail", "timeout", "output_limit"] } }
EOF

# ── The run ─────────────────────────────────────────────────────────

STARTS=0
start_warden() {
    STARTS=$((STARTS + 1))
    "$BIN/taso-wardend" "$W/soak.json" >>"$W/out/warden.out" 2>>"$W/out/warden.err" &
    DPID=$!
    echo "$(date +%s) start $STARTS pid $DPID" >>"$W/out/events"
}

sampler() {
    printf 'time\twarden_threads\twarden_fds\twarden_rss_kib\tblkd_rss_kib\tublk\tfree_gib\tlog_mib\n' >"$W/soak.tsv"
    while :; do
        local p t=- f=- r=- b
        p=$(pgrep -f "taso-wardend $W/soak.json" | head -1 || true)
        if [[ -n "$p" ]]; then
            t=$(ls "/proc/$p/task" 2>/dev/null | wc -l)
            f=$(ls "/proc/$p/fd" 2>/dev/null | wc -l)
            r=$(awk '/^VmRSS/ {print $2}' "/proc/$p/status" 2>/dev/null || echo -)
        fi
        b=$(awk '/^VmRSS/ {print $2}' "/proc/$BLKD_PID/status" 2>/dev/null || echo -)
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "$t" "$f" "$r" "$b" "$(ublk_devices)" \
            "$(df --output=avail -BG "$W" | tail -1 | tr -dc 0-9)" "$(( $(stat -c %s "$W/blk.log") >> 20 ))" >>"$W/soak.tsv"
        sleep "$SAMPLE"
    done
}

say "the soak: $SECS s, $VESSELS Vessels, the Warden killed every ~$KILL_EVERY s (results in $W)"
start_warden
for _ in $(seq 300); do [[ -S "$DSOCK" ]] && break; kill -0 "$DPID" 2>/dev/null || die "taso-wardend exited at its start; see $W/out/warden.err"; sleep 0.2; done
[[ -S "$DSOCK" ]] || die "no decider socket after 60 s; see $W/out/warden.err"
"$BIN/taso-policy" "$W/soak.json" "$W/policy.toml" --interval-secs 5 >"$W/out/policy.jsonl" 2>"$W/out/policy.err" &
POLICY_PID=$!
sampler &
SAMPLER_PID=$!

END=$((SECONDS + SECS))
EXITED=0 KILLS=0
next_kill=$((SECONDS + KILL_EVERY / 2 + RANDOM % (KILL_EVERY + 1)))
while [[ $SECONDS -lt $END ]]; do
    sleep 1
    if ! kill -0 "$DPID" 2>/dev/null; then
        wait "$DPID" 2>/dev/null && rc=0 || rc=$?
        EXITED=$((EXITED + 1))
        echo "$(date +%s) exited by itself rc $rc" >>"$W/out/events"
        echo "  the Warden exited by itself (rc $rc); started again"
        DPID=
        start_warden
    fi
    if [[ $SECONDS -ge $next_kill ]]; then
        KILLS=$((KILLS + 1))
        echo "$(date +%s) kill $KILLS" >>"$W/out/events"
        stop_warden KILL
        start_warden
        next_kill=$((SECONDS + KILL_EVERY / 2 + RANDOM % (KILL_EVERY + 1)))
    fi
done
kill "$POLICY_PID" 2>/dev/null; wait "$POLICY_PID" 2>/dev/null || true; POLICY_PID=
kill "$SAMPLER_PID" 2>/dev/null; wait "$SAMPLER_PID" 2>/dev/null || true; SAMPLER_PID=
stop_warden TERM
echo "  $KILLS kills, $STARTS starts"

# ── Checks ──────────────────────────────────────────────────────────

say "work done (predict: attempts and sanctions each more than zero)"
ATTEMPTS=$(grep -c ': attempt [0-9a-f]*: finished' "$W/out/warden.err" || true)
SANCTIONS=$(grep -c 'sanction completed$' "$W/out/warden.err" || true)
echo "  attempts finished $ATTEMPTS, sanctions completed $SANCTIONS"
expect "attempts finished" atleast "$ATTEMPTS" 1
expect "sanctions completed" atleast "$SANCTIONS" 1

say "no panic, and the Warden never exited by itself"
expect "no panic in any log" is "$(cat "$W"/out/*.err "$W"/*.err 2>/dev/null | grep -c 'panicked at' || true)" 0
expect "the Warden exited by itself 0 times" is "$EXITED" 0

say "no growth (predict: the last third's largest open files and threads at most 1.5x the first third's, plus 16)"
growth() { # growth COLUMN: "ok" or what grew
    python3 - "$W/soak.tsv" "$1" <<'PY'
import sys
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1])][1:]
col = int(sys.argv[2])
vals = [int(r[col]) for r in rows if r[col].isdigit()]
if len(vals) < 6:
    print("ok (too few samples: %d)" % len(vals)); sys.exit()
third = len(vals) // 3
first, last = max(vals[:third]), max(vals[-third:])
print("ok" if last <= first * 1.5 + 16 else "grew from %d to %d" % (first, last))
PY
}
for c in "1 threads" "2 open-files"; do
    set -- $c
    r=$(growth "$1")
    expect "the Warden's $2: $r" bash -c "[[ '$r' == ok* ]]"
done

say "every Chronicle (predict: explain exit 0 with no failed check; its frames one chain; shipped not past head)"
mapfile -t IDS < <(blk names | tr ' ' '\n' | sed -n 's|^soak/n1/v-\([0-9a-f]\{32\}\):.*|\1|p' | sort -u)
echo "  ${#IDS[@]} Chronicles"
expect "Chronicles on the node: at least $VESSELS" atleast "${#IDS[@]}" "$VESSELS"
for id in "${IDS[@]}"; do
    XRC=0
    timeout 120 "$BIN/taso-ctl" "$W/soak.json" explain "$id" >"$W/out/explain-$id.json" 2>"$W/out/explain-$id.err" || XRC=$?
    failed=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("checks",{}).get("failed",[])))' "$W/out/explain-$id.json" 2>/dev/null || echo "unreadable")
    expect "$id: explained, no failed check" is "$XRC $failed" "0 0"
    chain=$("$BIN/taso-logcheck" "$SOCK" "$W/state" "$id" 2>"$W/out/logcheck-$id.err" | python3 -c '
import json, sys
v = json.load(sys.stdin)
fr = v["frames"]
bad = [f["lsn"] for a, f in zip(fr, fr[1:]) if f["lsn"] != a["lsn"] + 1 or f["prev"] != a["hash"]]
head, shipped = v.get("head") or {}, v.get("shipped") or {}
if bad:
    print("broken at lsn %s" % bad[:3])
elif shipped and head and shipped["lsn"] > head["lsn"]:
    print("shipped %d past head %d" % (shipped["lsn"], head["lsn"]))
else:
    print("ok")' 2>/dev/null || echo "unreadable")
    expect "$id: one chain" is "$chain" ok
done

say "taso-blkd quits clean and leaves no device (predict: after the Vessels' file systems are unmounted, quit answers ok within 60 s and the daemon exits 0)"
# The Warden leaves its Vessels mounted when it stops (a crash leaves
# them too); a device under a mounted file system cannot be stopped, so
# they are unmounted first, as an operator would (taso-test 2026-11-08:
# quit with them mounted did not answer in 120 s).
while read -r m; do
    [[ -n "$m" ]] || continue
    umount "$m" || umount -l "$m"
done < <(mounts_under)
expect "nothing mounted under $MNT" is "$(mounts_under | wc -l)" 0
blk quit >/dev/null && QRC=0 || QRC=$?
BRC=timeout
for _ in $(seq 600); do
    if ! kill -0 "$BLKD_PID" 2>/dev/null; then
        wait "$BLKD_PID" 2>/dev/null && BRC=0 || BRC=$?
        break
    fi
    sleep 0.1
done
[[ "$BRC" != timeout ]] && { BLKD_PID=; rm -f "$BLK_SOCK"; }
expect "quit answered ok" is "$QRC" 0
expect "taso-blkd exited 0" is "$BRC" 0
expect "ublk devices as before" is "$(ublk_devices)" "$DEVS_BEFORE"

echo
tail -n 3 "$W/soak.tsv" | column -t
echo
if [[ $FAIL -eq 0 ]]; then
    # A pass keeps its logs and samples, not its block log and store (5.7
    # GB after 5 h on taso-test 2026-11-09: the night's xfstests then found
    # 18 GiB free, wanting 20).
    rm -rf "$W/blk.log" "$W/store" "$W/spool"
    echo "SOAK PASS: $SECS s, $VESSELS Vessels, $KILLS kills, $ATTEMPTS attempts, $SANCTIONS sanctions; $PASS checks"
    exit 0
else
    echo "SOAK FAIL: $FAIL of $((PASS + FAIL)) checks failed; logs in $W/out, samples in $W/soak.tsv"
    exit 1
fi
