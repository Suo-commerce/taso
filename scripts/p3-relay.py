#!/usr/bin/env python3
"""Reference relay and stub agent in one script (P3 file 10).

Runs as the agent inside a Vessel container.  Speaks Field protocol v2
over the per-Vessel Unix socket, declares effects, reads Open, reports
outcomes, and writes results to the dataset so the gate can check them.

Usage (from within a Vessel container):
    p3-relay.py [--effects N] [--provider PROV] [--socket PATH]
                [--keys-file PATH] [--turns T]

  --effects N       number of effects to declare per turn (default 2)
  --provider PROV   provider namespace for each effect (default "stub")
  --socket PATH     Field socket (default /run/taso/field.sock)
  --keys-file PATH  write each released effect's idempotency key here,
                    one hex-encoded key per line (default /work/keys.log)
  --turns T         number of turns to run (default 1)

Wire protocol v2:
  Frame = u32 BE length + body.
  Body  = u8 tag + fields; ints LE, bytes/strings as u64 LE len + data,
          enums as u8 tag, options as 0/1 + value.
"""

import argparse
import json
import os
import socket
import struct
import sys
import uuid


# ── Wire helpers ────────────────────────────────────────────────────

def _pack_u8(v):
    return struct.pack("<B", v)

def _pack_u16(v):
    return struct.pack("<H", v)

def _pack_u64(v):
    return struct.pack("<Q", v)

def _pack_bytes(b):
    return struct.pack("<Q", len(b)) + b

def _pack_str(s):
    return _pack_bytes(s.encode("utf-8"))

def _pack_bool(v):
    return _pack_u8(1 if v else 0)

def _pack_opt_u64(v):
    if v is None:
        return _pack_u8(0)
    return _pack_u8(1) + _pack_u64(v)


class Reader:
    """Strict binary reader for reply bodies."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def u8(self):
        if self.pos + 1 > len(self.data):
            raise ValueError("truncated at u8")
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(self):
        if self.pos + 2 > len(self.data):
            raise ValueError("truncated at u16")
        v, = struct.unpack_from("<H", self.data, self.pos)
        self.pos += 2
        return v

    def u64(self):
        if self.pos + 8 > len(self.data):
            raise ValueError("truncated at u64")
        v, = struct.unpack_from("<Q", self.data, self.pos)
        self.pos += 8
        return v

    def raw_bytes(self):
        n = self.u64()
        if self.pos + n > len(self.data):
            raise ValueError("truncated at bytes")
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v

    def string(self):
        return self.raw_bytes().decode("utf-8")

    def opt_u64(self):
        tag = self.u8()
        if tag == 0:
            return None
        if tag == 1:
            return self.u64()
        raise ValueError(f"bad option tag {tag}")

    def bool_(self):
        v = self.u8()
        if v > 1:
            raise ValueError(f"bad bool {v}")
        return v == 1

    def retry(self):
        tag = self.u8()
        if tag == 0:
            return ("ProviderDeduplicated", self.raw_bytes())
        if tag == 1:
            return ("Queryable", self.raw_bytes())
        if tag == 2:
            return ("UnsafeToRetry", None)
        raise ValueError(f"bad retry tag {tag}")

    def consequence(self):
        tag = self.u8()
        if tag == 0:
            return ("Irreversible", None)
        if tag == 1:
            return ("Compensatable", self.u64())
        if tag == 2:
            return ("NoExternalMutation", None)
        raise ValueError(f"bad consequence tag {tag}")

    def finish(self):
        if self.pos != len(self.data):
            raise ValueError(f"{len(self.data) - self.pos} trailing bytes")


def send_frame(sock, body):
    """Write one frame: u32 BE length + body."""
    frame = struct.pack(">I", len(body)) + body
    sock.sendall(frame)


def recv_frame(sock):
    """Read one frame; returns the body or None on clean close."""
    hdr = _recv_exact(sock, 4)
    if hdr is None:
        return None
    length, = struct.unpack(">I", hdr)
    if length > 16 * 1024 * 1024:
        raise ValueError(f"frame too large: {length}")
    return _recv_exact(sock, length)


def _recv_exact(sock, n):
    """Read exactly n bytes; returns None if the socket closed cleanly
    at the start (before any bytes were read)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            if not buf:
                return None
            raise ConnectionError("connection closed mid-frame")
        buf.extend(chunk)
    return bytes(buf)


# ── Request encoding ────────────────────────────────────────────────

def encode_hello(version=2):
    return _pack_u8(0) + _pack_u16(version)


def encode_effect(call, provider, request, footprint, retry, consequence, authority):
    """Encode a Request::Effect (tag 1).

    retry:       ("ProviderDeduplicated", key_bytes) |
                 ("Queryable", probe_bytes) | ("UnsafeToRetry", None)
    consequence: "Irreversible" | "NoExternalMutation"
    """
    body = _pack_u8(1) + _pack_u64(call) + _pack_str(provider)
    body += _pack_bytes(request) + _pack_bytes(footprint)
    # retry
    kind, val = retry
    if kind == "ProviderDeduplicated":
        body += _pack_u8(0) + _pack_bytes(val)
    elif kind == "Queryable":
        body += _pack_u8(1) + _pack_bytes(val)
    elif kind == "UnsafeToRetry":
        body += _pack_u8(2)
    else:
        raise ValueError(f"unknown retry kind: {kind}")
    # consequence
    if consequence == "Irreversible":
        body += _pack_u8(0)
    elif consequence == "NoExternalMutation":
        body += _pack_u8(2)
    else:
        raise ValueError(f"unknown consequence: {consequence}")
    body += _pack_bytes(authority)
    return body


def encode_transcript(entry):
    return _pack_u8(2) + _pack_bytes(entry)


def encode_turn_end(turn, quiescent):
    return _pack_u8(3) + _pack_u64(turn) + _pack_bool(quiescent)


def encode_outcome(op, result):
    """Encode a Request::Outcome (tag 4).

    result: ("Applied", receipt_bytes) | ("NotApplied", reason_str) | "Unknown"
    """
    body = _pack_u8(4) + _pack_u64(op)
    if isinstance(result, tuple):
        kind, val = result
        if kind == "Applied":
            body += _pack_u8(0) + _pack_bytes(val)
        elif kind == "NotApplied":
            body += _pack_u8(1) + _pack_str(val)
        else:
            raise ValueError(f"unknown outcome kind: {kind}")
    elif result == "Unknown":
        body += _pack_u8(2)
    else:
        raise ValueError(f"unknown result: {result}")
    return body


def encode_open():
    return _pack_u8(5)


# ── Reply decoding ──────────────────────────────────────────────────

def decode_reply(body):
    """Decode a Reply body into a dict with 'type' and fields."""
    r = Reader(body)
    tag = r.u8()
    if tag == 0:  # Hello
        reply = {"type": "Hello", "version": r.u16(), "last_sealed_turn": r.opt_u64()}
    elif tag == 1:  # Effect
        call = r.u64()
        result_tag = r.u8()
        if result_tag == 0:
            result = {"result": "Released", "op": r.u64()}
        elif result_tag == 1:
            result = {"result": "Held", "op": r.u64()}
        elif result_tag == 2:
            result = {"result": "Refused", "reason": r.string()}
        else:
            raise ValueError(f"bad effect result tag {result_tag}")
        reply = {"type": "Effect", "call": call, **result}
    elif tag == 2:  # Recorded
        reply = {"type": "Recorded", "lsn": r.u64()}
    elif tag == 3:  # TurnEnd
        reply = {"type": "TurnEnd", "turn": r.u64(), "sealed": r.opt_u64()}
    elif tag == 4:  # Error
        code = r.u8()
        codes = {0: "BadHello", 1: "Malformed", 2: "Closed", 3: "Fenced", 4: "Internal"}
        reply = {"type": "Error", "code": codes.get(code, code), "message": r.string()}
    elif tag == 5:  # Outcome
        op = r.u64()
        t = r.u8()
        if t == 0:
            refused = None
        elif t == 1:
            refused = r.string()
        else:
            raise ValueError(f"bad outcome option tag {t}")
        reply = {"type": "Outcome", "op": op, "refused": refused}
    elif tag == 6:  # Open
        n = r.u64()
        effects = []
        for _ in range(n):
            e = {
                "op": r.u64(),
                "provider": r.string(),
                "request": r.raw_bytes(),
                "retry": r.retry(),
                "consequence": r.consequence(),
                "authority": r.raw_bytes(),
                "unknown": r.bool_(),
            }
            effects.append(e)
        reply = {"type": "Open", "effects": effects}
    else:
        raise ValueError(f"unknown reply tag {tag}")
    r.finish()
    return reply


# ── Field session ───────────────────────────────────────────────────

def ask(sock, request_body):
    """Send a request, receive and decode its reply."""
    send_frame(sock, request_body)
    body = recv_frame(sock)
    if body is None:
        raise ConnectionError("the Warden closed the connection")
    return decode_reply(body)


def main():
    p = argparse.ArgumentParser(description="P3 reference relay / stub agent")
    p.add_argument("--effects", type=int, default=2, help="effects per turn")
    p.add_argument("--provider", default="stub", help="provider namespace")
    p.add_argument("--socket", default="/run/taso/field.sock", help="Field socket path")
    p.add_argument("--keys-file", default="/work/keys.log", help="write idempotency keys here")
    p.add_argument("--turns", type=int, default=1, help="number of turns")
    args = p.parse_args()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(args.socket)

    # Hello
    reply = ask(sock, encode_hello(2))
    if reply["type"] == "Error":
        print(f"Hello refused: {reply['code']}: {reply['message']}", file=sys.stderr)
        sys.exit(1)
    assert reply["type"] == "Hello", f"unexpected: {reply}"
    assert reply["version"] == 2, f"version mismatch: {reply['version']}"
    resumed_after = reply["last_sealed_turn"]
    first_turn = (resumed_after or 0) + 1
    print(f"hello: version {reply['version']}, resumed_after={resumed_after}", file=sys.stderr)

    # Declare effects, one turn at a time.
    declared = []  # (call, key_hex, op_or_none)
    for turn in range(first_turn, first_turn + args.turns):
        for i in range(args.effects):
            call = (turn - 1) * args.effects + i
            # Each effect gets a unique idempotency key derived from a UUID,
            # so the gate can tell which fork's effects were released.
            key = uuid.uuid4().bytes
            key_hex = key.hex()
            request_bytes = f"effect-{turn}-{i}".encode()
            footprint = b""
            retry = ("ProviderDeduplicated", key)
            consequence = "NoExternalMutation"
            authority = b"test"
            reply = ask(sock, encode_effect(
                call, args.provider, request_bytes, footprint,
                retry, consequence, authority,
            ))
            assert reply["type"] == "Effect", f"unexpected: {reply}"
            assert reply["call"] == call, f"call mismatch: {reply['call']} != {call}"
            result = reply["result"]
            op = reply.get("op")
            declared.append((call, key_hex, op, result))
            print(f"  effect call={call} key={key_hex[:16]}.. -> {result} op={op}", file=sys.stderr)

        # Transcript + TurnEnd
        entry = f"turn {turn}: {args.effects} effects declared".encode()
        reply = ask(sock, encode_transcript(entry))
        assert reply["type"] == "Recorded", f"unexpected: {reply}"

        reply = ask(sock, encode_turn_end(turn, True))
        assert reply["type"] == "TurnEnd", f"unexpected: {reply}"
        print(f"turn {turn}: sealed={reply['sealed']}", file=sys.stderr)

    # Write declared keys so the gate can compare against promoted keys.
    declared_path = os.path.join(os.path.dirname(args.keys_file), "declared.log")
    with open(declared_path, "w") as df:
        for _call, key_hex, _op, _result in declared:
            df.write(key_hex + "\n")

    # ── Sender role: read Open, report outcomes, log keys ────────────

    reply = ask(sock, encode_open())
    assert reply["type"] == "Open", f"unexpected: {reply}"
    released = reply["effects"]
    print(f"open: {len(released)} released effect(s)", file=sys.stderr)

    keys_dir = os.path.dirname(args.keys_file)
    if keys_dir:
        os.makedirs(keys_dir, exist_ok=True)
    with open(args.keys_file, "w") as kf:
        for e in released:
            # The retry policy is ProviderDeduplicated; the key is
            # the idempotency key we declared.
            kind, key_bytes = e["retry"]
            assert kind == "ProviderDeduplicated", f"unexpected retry: {kind}"
            kf.write(key_bytes.hex() + "\n")

            # Report Applied for every released effect.
            receipt = f"receipt-{e['op']}".encode()
            reply = ask(sock, encode_outcome(e["op"], ("Applied", receipt)))
            assert reply["type"] == "Outcome", f"unexpected: {reply}"
            if reply["refused"]:
                print(f"  outcome op={e['op']} refused: {reply['refused']}", file=sys.stderr)
            else:
                print(f"  outcome op={e['op']} recorded", file=sys.stderr)

    # Write a summary for the gate.
    summary = {
        "declared": len(declared),
        "released": len(released),
        "keys_file": args.keys_file,
        "results": {d[1]: d[3] for d in declared},  # key_hex -> "Released"|"Held"|"Refused"
    }
    summary_path = os.path.join(os.path.dirname(args.keys_file), "relay-summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=1)
    print(f"summary: {summary_path}", file=sys.stderr)

    sock.close()


if __name__ == "__main__":
    main()
