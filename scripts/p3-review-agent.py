#!/usr/bin/env python3
"""The agent, the sender and the host's hand for p3-review.sh.

As the agent (`agent`, inside a Vessel's container, on its socket) it
decides nothing: it does what the gate tells it, one command at a time,
through files in /work, so the gate's script holds the whole story and
every step is the same on every run.

  /work/hello-<hostname>          {"nonce", "last_sealed_turn"}: written
                                  once by each agent process.  The
                                  hostname is the Vessel's, so a fork,
                                  which starts on a copy of its parent's
                                  files, has its own; the nonce is the
                                  process's, so a Vessel that is started
                                  again (on files rolled back to its last
                                  Seal, or on a promoted fork's) is told
                                  from its earlier run.
  /work/cmd-<nonce>-<k>.json      the gate's k-th command to that process
  /work/rep-<nonce>-<k>.json      its answer

Commands ({"do": ...}):
  effect   {"call", "request"}   -> the Field's Effect reply
  turn_end                       -> the TurnEnd reply (a Transcript first)
  fork                           -> the Fork reply
  promote  {"child"}             -> the Promote reply; promoted, it exits 0
                                    (the Warden starts it again on the
                                    fork's files)
  result   {"op"}                -> the Result reply
  write    {"path", "text"}      -> a file under /work
  exit     {"code"}              -> answers, then exits
  sleep                          -> answers, then sleeps until killed

As the host's hand (outside any Vessel):
  hello  --dir MOUNT --host H --seen FILE   wait for an agent process of H
                                            whose nonce is not in FILE;
                                            print it and add it to FILE
  cmd    --dir MOUNT --nonce N --json J     give one command, print the
                                            answer (--or-log FILE --pattern
                                            P: or, if P appears in FILE
                                            first, {"from_log": true})
  sender --socket S --receipt TEXT          on a Vessel's sender socket:
                                            Open, report Applied with the
                                            receipt for each; print what
                                            was listed and answered

The wire helpers are p3-relay.py's (the reference relay), next to this
file.
"""

import argparse
import glob
import importlib.util
import json
import os
import socket
import sys
import time
import uuid

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("relay", os.path.join(_here, "p3-relay.py"))
relay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(relay)

WORK = "/work"


def put(path, obj):
    """Write a JSON file so that a reader sees none of it or all of it."""
    d, name = os.path.split(path)
    tmp = os.path.join(d, f".tmp-{uuid.uuid4().hex}-{name}")
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def get(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        return None


# ── the Field's requests and replies p3-relay.py does not speak ────────

def encode_fork():
    return relay._pack_u8(6) + relay._pack_opt_u64(None)


def encode_promote(child):
    return relay._pack_u8(7) + relay._pack_str(child) + relay._pack_opt_u64(None)


def encode_result(op):
    return relay._pack_u8(8) + relay._pack_u64(op)


def decode(body):
    tag = body[0]
    if tag < 7:
        reply = relay.decode_reply(body)
        for k, v in list(reply.items()):
            if isinstance(v, bytes):
                reply[k] = v.decode("utf-8", "replace")
        return reply
    r = relay.Reader(body)
    r.u8()
    if tag == 7:
        t = r.u8()
        if t == 0:
            reply = {"type": "Fork", "result": "Forked", "child": r.string(), "seal": r.u64()}
        else:
            reply = {"type": "Fork", "result": "Refused", "reason": r.string()}
    elif tag == 8:
        child = r.string()
        t = r.u8()
        if t == 0:
            seal = r.u64()
            adopted = [r.u64() for _ in range(r.u64())]
            reply = {"type": "Promote", "child": child, "result": "Promoted",
                     "seal": seal, "adopted": adopted}
        else:
            reply = {"type": "Promote", "child": child, "result": "Refused", "reason": r.string()}
    elif tag == 9:
        op = r.u64()
        t = r.u8()
        names = {0: "Pending", 1: "Held", 2: "Applied", 3: "NotApplied", 4: "Unknown",
                 5: "NotFound", 6: "AcceptedUnknown"}
        reply = {"type": "Result", "op": op, "state": names.get(t, t)}
        if t == 2:
            reply["receipt"] = r.raw_bytes().decode("utf-8", "replace")
        elif t == 3:
            reply["reason"] = r.string()
    else:
        raise ValueError(f"unknown reply tag {tag}")
    r.finish()
    return reply


def ask(sock, body):
    relay.send_frame(sock, body)
    reply = relay.recv_frame(sock)
    if reply is None:
        raise ConnectionError("the Warden closed the connection")
    return decode(reply)


# ── the agent ──────────────────────────────────────────────────────────

def agent(args):
    sock, hello = relay.connect(args.socket)
    turn = (hello["last_sealed_turn"] or 0) + 1
    nonce = uuid.uuid4().hex
    put(f"{WORK}/hello-{socket.gethostname()}",
        {"nonce": nonce, "last_sealed_turn": hello["last_sealed_turn"]})
    print(f"agent {socket.gethostname()} nonce {nonce}, next turn {turn}", file=sys.stderr)
    k = 1
    idle_since = time.monotonic()
    while True:
        cmd = get(f"{WORK}/cmd-{nonce}-{k}.json")
        if cmd is None:
            if time.monotonic() - idle_since > args.idle:
                print("no command for too long: giving up", file=sys.stderr)
                sys.exit(3)
            time.sleep(0.05)
            continue
        do = cmd.get("do")
        after = None
        if do == "effect":
            rep = ask(sock, relay.encode_effect(
                cmd["call"], "fetch", cmd["request"].encode(), b"",
                ("ProviderDeduplicated", uuid.uuid4().bytes), "NoExternalMutation", b"test"))
        elif do == "turn_end":
            rep = ask(sock, relay.encode_transcript(f"turn {turn}".encode()))
            if rep["type"] == "Recorded":
                rep = ask(sock, relay.encode_turn_end(turn, True))
                if rep["type"] == "TurnEnd" and rep["sealed"] is not None:
                    turn += 1
        elif do == "fork":
            rep = ask(sock, encode_fork())
        elif do == "promote":
            rep = ask(sock, encode_promote(cmd["child"]))
            if rep.get("result") == "Promoted":
                after = ("exit", 0)
        elif do == "result":
            rep = ask(sock, encode_result(cmd["op"]))
        elif do == "write":
            with open(os.path.join(WORK, cmd["path"]), "w") as f:
                f.write(cmd["text"])
            rep = {"type": "Written"}
        elif do == "exit":
            rep, after = {"type": "Exit"}, ("exit", cmd.get("code", 0))
        elif do == "sleep":
            rep, after = {"type": "Sleep"}, ("sleep", 0)
        else:
            rep = {"type": "Unknown command", "do": do}
        print(f"  {k}: {cmd} -> {rep}", file=sys.stderr)
        put(f"{WORK}/rep-{nonce}-{k}.json", rep)
        k += 1
        idle_since = time.monotonic()
        if after and after[0] == "exit":
            sock.close()
            sys.exit(after[1])
        if after and after[0] == "sleep":
            while True:
                time.sleep(3600)


# ── the host's hand ────────────────────────────────────────────────────

def hello(args):
    seen = set()
    if os.path.exists(args.seen):
        seen = set(open(args.seen).read().split())
    deadline = time.monotonic() + args.timeout
    path = os.path.join(args.dir, f"hello-{args.host}")
    while time.monotonic() < deadline:
        h = get(path)
        if h and h["nonce"] not in seen:
            with open(args.seen, "a") as f:
                f.write(h["nonce"] + "\n")
            print(h["nonce"])
            return 0
        time.sleep(0.05)
    print(f"no new agent of {args.host} said hello in {args.dir} within {args.timeout:.0f} s",
          file=sys.stderr)
    return 1


def cmd(args):
    k = len(glob.glob(os.path.join(args.dir, f"cmd-{args.nonce}-*.json"))) + 1
    put(os.path.join(args.dir, f"cmd-{args.nonce}-{k}.json"), json.loads(args.json))
    rep_path = os.path.join(args.dir, f"rep-{args.nonce}-{k}.json")
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        rep = get(rep_path)
        if rep is not None:
            print(json.dumps(rep))
            return 0
        if args.or_log and os.path.exists(args.or_log):
            with open(args.or_log, errors="replace") as f:
                if args.pattern in f.read():
                    print(json.dumps({"from_log": True}))
                    return 0
        time.sleep(0.05)
    print(f"no answer to {args.json} (command {k}) within {args.timeout:.0f} s", file=sys.stderr)
    return 1


def sender(args):
    deadline = time.monotonic() + args.timeout
    while True:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(args.socket)
            break
        except (FileNotFoundError, ConnectionRefusedError) as e:
            sock.close()
            if time.monotonic() > deadline:
                print(f"no sender socket at {args.socket}: {e}", file=sys.stderr)
                return 1
            time.sleep(0.1)
    rep = ask(sock, relay.encode_hello(2))
    if rep["type"] != "Hello":
        print(f"Hello refused: {rep}", file=sys.stderr)
        return 1
    relay.send_frame(sock, relay.encode_open())
    listed = relay.decode_reply(relay.recv_frame(sock))
    assert listed["type"] == "Open", listed
    out = {"effects": [], "outcomes": []}
    for e in listed["effects"]:
        out["effects"].append({"op": e["op"], "provider": e["provider"],
                               "request": e["request"].decode("utf-8", "replace"),
                               "unknown": e["unknown"]})
        rep = ask(sock, relay.encode_outcome(e["op"], ("Applied", args.receipt.encode())))
        out["outcomes"].append({"op": e["op"], "refused": rep.get("refused"),
                                "type": rep["type"]})
    sock.close()
    print(json.dumps(out))
    return 0


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="role", required=True)
    a = sub.add_parser("agent")
    a.add_argument("--socket", default="/run/taso/field.sock")
    a.add_argument("--idle", type=float, default=900.0)
    h = sub.add_parser("hello")
    h.add_argument("--dir", required=True)
    h.add_argument("--host", required=True)
    h.add_argument("--seen", required=True)
    h.add_argument("--timeout", type=float, default=90.0)
    c = sub.add_parser("cmd")
    c.add_argument("--dir", required=True)
    c.add_argument("--nonce", required=True)
    c.add_argument("--json", required=True)
    c.add_argument("--timeout", type=float, default=60.0)
    c.add_argument("--or-log")
    c.add_argument("--pattern")
    s = sub.add_parser("sender")
    s.add_argument("--socket", required=True)
    s.add_argument("--receipt", required=True)
    s.add_argument("--timeout", type=float, default=60.0)
    args = p.parse_args()
    sys.exit({"agent": agent, "hello": hello, "cmd": cmd, "sender": sender}[args.role](args) or 0)


if __name__ == "__main__":
    main()
