#!/usr/bin/env python3
"""Seed the fuzz corpora from the captured Moonlight session.

`tests/vectors/capture/session.json.gz` is a real client's traffic, decrypted
(`docs/roadmap.md` §4).  A fuzzer started from those bytes begins inside the
formats it is meant to explore, rather than spending its first hours finding
out what an RTSP request line or an ENet header looks like (`docs/roadmap.md`
§8).  This writes one file per input into `fuzz/seeds/<target>/`, named by
the SHA-1 of its contents as libFuzzer names what it adds.  The seeds are
committed; `fuzz/corpus/`, which libFuzzer grows as it runs, is not, and
`tests/tools/fuzz.sh` hands it both.  Seeds are written for:

- `rtsp_message`: every RTSP request the client sent, as plaintext;
- `sdp_announce`: the ANNOUNCE body;
- `input_batch`: every input batch, the payload of an `INPUT_DATA` message;
- `control_envelope`: every control message, re-encrypted under the target's
  fixed key.  The captured envelopes are sealed under the session's `rikey`,
  so as captured every one fails authentication at the first check and the
  fuzzer never reaches the message decoder behind it.  Before re-sealing, each
  is sealed again under the session key and must reproduce the captured bytes
  exactly, which proves the envelope is rebuilt the way the client built it;
- `enet_host`: the client's ENet datagrams, in the target's
  `[flags][u16le length][datagram]` framing, as one session per file and one
  file per datagram.

Deterministic: the same capture gives the same files.  Usage:

    python3 -I tests/tools/gen_fuzz_seeds.py [capture] [seeds-dir]
"""
import gzip
import hashlib
import json
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

# `fuzz/fuzz_targets/control_envelope.rs` decodes under this key.
FUZZ_CONTROL_KEY = bytes([0x33] * 16)
# `wire::control::msg::INPUT_DATA`.
INPUT_DATA = 0x0206
ENCRYPTED_HEADER_TYPE = 0x0001
TAG_LEN = 16


def fail(message):
    sys.exit(f"gen_fuzz_seeds: {message}")


def control_iv(sequence):
    """`wire::control::control_iv` for a client-originated message:
    the sequence little-endian, then 'C' (client) and 'C' (control)."""
    iv = bytearray(12)
    iv[0:4] = struct.pack("<I", sequence)
    iv[10] = ord("C")
    iv[11] = ord("C")
    return bytes(iv)


def seal_control(key, sequence, msg_type, payload):
    """An encrypted control envelope, as `ControlStream.c` builds one:
    header type, length, sequence, then the GCM tag, then the ciphertext of
    the V2 header and payload."""
    plaintext = struct.pack("<HH", msg_type, len(payload)) + payload
    sealed = AESGCM(key).encrypt(control_iv(sequence), plaintext, None)
    ciphertext, tag = sealed[:-TAG_LEN], sealed[-TAG_LEN:]
    header = struct.pack(
        "<HHI", ENCRYPTED_HEADER_TYPE, 4 + TAG_LEN + len(ciphertext), sequence
    )
    return header + tag + ciphertext


def enet_records(datagrams):
    """The `enet_host` target's framing: flags 0 (from the client, no
    timeout step), then the length, then the datagram."""
    out = b""
    for d in datagrams:
        out += bytes([0]) + struct.pack("<H", len(d)) + d
    return out


def write(corpus, target, data, written):
    directory = os.path.join(corpus, target)
    os.makedirs(directory, exist_ok=True)
    name = hashlib.sha1(data).hexdigest()
    with open(os.path.join(directory, name), "wb") as f:
        f.write(data)
    written.setdefault(target, set()).add(name)


def main():
    capture = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        ROOT, "tests", "vectors", "capture", "session.json.gz"
    )
    corpus = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "fuzz", "seeds")
    with gzip.open(capture, "rt") as f:
        v = json.load(f)
    rikey = bytes.fromhex(v["session"]["rikey"])
    written = {}

    announce = None
    for exchange in v["rtsp"]:
        request = exchange["request"].encode()
        write(corpus, "rtsp_message", request, written)
        if request.startswith(b"ANNOUNCE "):
            announce = request.split(b"\r\n\r\n", 1)[1]
    if not announce:
        fail("the capture has no ANNOUNCE body")
    write(corpus, "sdp_announce", announce, written)

    for message in v["control"]["client"]:
        payload = bytes.fromhex(message["payload"])
        sequence, msg_type = message["sequence"], message["type"]
        if seal_control(rikey, sequence, msg_type, payload) != bytes.fromhex(message["wire"]):
            fail(f"control message {sequence} does not re-seal to the captured bytes")
        write(
            corpus,
            "control_envelope",
            seal_control(FUZZ_CONTROL_KEY, sequence, msg_type, payload),
            written,
        )
        if msg_type == INPUT_DATA:
            write(corpus, "input_batch", payload, written)

    datagrams = [bytes.fromhex(d) for d in v["control"]["client_datagrams"]]
    write(corpus, "enet_host", enet_records(datagrams), written)
    for d in datagrams:
        write(corpus, "enet_host", enet_records([d]), written)

    for target in sorted(written):
        print(f"{target:18} {len(written[target]):3} seeds")


if __name__ == "__main__":
    main()
