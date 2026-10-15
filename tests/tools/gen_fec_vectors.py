#!/usr/bin/env python3
"""Freeze the nanors differential vectors into JSON for the Rust test suite.

`tests/vectors/fec/dump.c` links the real `nanors` and prints its parity matrix
and encoded parity; `tests/vectors/fec/check.py` reimplements the construction
independently.  This script runs both, requires them to agree, and writes the
result as golden vectors so CI does not need a C toolchain or a network.

Usage:
    python3 -I tests/tools/gen_fec_vectors.py <path-to-fec-dump> [outdir]

See tests/vectors/fec/README.md for how to build <path-to-fec-dump>.
"""
import json
import os
import subprocess
import sys

POLY = 285  # nanors/deps/obl/gf2_8_tables.h:1

# --- independent reimplementation (no bytes copied from nanors) -------------

EXP = [0] * 512
LOG = [0] * 256
_x = 1
for _i in range(255):
    EXP[_i] = _x
    LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= POLY
for _i in range(255, 512):
    EXP[_i] = EXP[_i - 255]


def mul(a, b):
    return 0 if a == 0 or b == 0 else EXP[LOG[a] + LOG[b]]


def inv(a):
    return EXP[255 - LOG[a]]


def cauchy_matrix(ds, ps):
    """nanors rs.c:128 -- row[i] = GF2_8_INV[(ps + i) ^ j]."""
    return [[inv((ps + i) ^ j) for i in range(ds)] for j in range(ps)]


# Nvidia's audio matrix, hard-coded in Sunshine at stream.cpp:1872-1878
# because the Cauchy construction does not reproduce it.
AUDIO_MATRIX = [[0x77, 0x40, 0x38, 0x0E], [0xC7, 0xA7, 0x0D, 0x6C]]


def test_data(ds, bs):
    """The pattern dump.c fills its shards with."""
    return [bytes((k * 31 + b * 7 + 11) & 0xFF for b in range(bs)) for k in range(ds)]


def encode(matrix, shards):
    out = []
    for row in matrix:
        acc = bytearray(len(shards[0]))
        for coeff, shard in zip(row, shards):
            if coeff:
                for k, byte in enumerate(shard):
                    acc[k] ^= mul(coeff, byte)
        out.append(bytes(acc))
    return out


def run_oracle(dump, ds, ps, bs):
    out = subprocess.run([dump, str(ds), str(ps), str(bs)],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    i = out.index(f"MATRIX {ds} {ps}")
    matrix = [[int(v) for v in out[i + 1 + j].split()] for j in range(ps)]
    i = out.index(f"PARITY {ds} {ps} {bs}")
    parity = [bytes(int(v) for v in out[i + 1 + j].split()) for j in range(ps)]
    return matrix, parity


CASES = [
    ("tiny", 6, 3, 8),
    ("small-frame", 1, 2, 32),
    ("min-required-fec-bump", 5, 2, 64),
    ("max-block-at-20pct", 212, 42, 96),
    ("near-max-shards", 235, 20, 128),
    ("real-blocksize", 100, 20, 1392 + 16),
]


def main():
    dump = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else "tests/vectors/fec"
    os.makedirs(outdir, exist_ok=True)

    cases = []
    for name, ds, ps, bs in CASES:
        c_matrix, c_parity = run_oracle(dump, ds, ps, bs)
        p_matrix = cauchy_matrix(ds, ps)
        data = test_data(ds, bs)
        p_parity = encode(p_matrix, data)
        assert c_matrix == p_matrix, f"{name}: matrix differs from nanors"
        assert c_parity == p_parity, f"{name}: parity differs from nanors"
        print(f"ds={ds:<4} ps={ps:<3} bs={bs:<5} matrix=MATCH  parity=MATCH")
        cases.append({
            "name": name,
            "data_shards": ds,
            "parity_shards": ps,
            "blocksize": bs,
            "matrix": [b for row in c_matrix for b in row],
            "parity": [p.hex() for p in c_parity],
        })

    with open(os.path.join(outdir, "video_cauchy.json"), "w") as f:
        json.dump({
            "source": "nanors (github.com/sleepybishop/nanors), via tests/vectors/fec/dump.c",
            "polynomial": POLY,
            "data_pattern": "data[k][b] = (k*31 + b*7 + 11) & 0xFF",
            "cases": cases,
        }, f, indent=1)

    # Audio is a different code and nanors is not its oracle: Sunshine's matrix
    # is the specification, so the vector pins our encoder against it.
    ds, ps, bs = 4, 2, 240
    data = test_data(ds, bs)
    with open(os.path.join(outdir, "audio_nvidia.json"), "w") as f:
        json.dump({
            "source": "Sunshine stream.cpp:1872-1878 (Nvidia-compatible RS(4,2))",
            "polynomial": POLY,
            "data_pattern": "data[k][b] = (k*31 + b*7 + 11) & 0xFF",
            "cases": [{
                "name": "audio-rs-4-2",
                "data_shards": ds,
                "parity_shards": ps,
                "blocksize": bs,
                "matrix": [b for row in AUDIO_MATRIX for b in row],
                "parity": [p.hex() for p in encode(AUDIO_MATRIX, data)],
            }],
        }, f, indent=1)

    spot = {
        "comment": "GF(2^8) spot checks under polynomial 285, pinning the field itself",
        "mul": [[a, b, mul(a, b)] for a, b in
                [(0x80, 0x02), (0x53, 0xCA), (0xFF, 0xFF), (0x02, 0x87), (0x1D, 0x1D)]],
        "inv": [[a, inv(a)] for a in [1, 2, 3, 0x53, 0x80, 0xFF]],
    }
    with open(os.path.join(outdir, "gf256_spot_checks.json"), "w") as f:
        json.dump(spot, f, indent=1)
    print(f"\nALL MATCH -- wrote vectors to {outdir}")


if __name__ == "__main__":
    main()
