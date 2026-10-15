#!/usr/bin/env python3
"""Freeze the SPICE codec differential vectors into the Rust test suite.

`tests/vectors/spice/dump.c` links the real `spice-common` QUIC and LZ codecs;
`tests/vectors/spice/glz-dump.c` links the real `spice-server` GLZ encoder.
This script runs both, sanity-checks the result, and writes the combined set
as gzipped JSON so CI needs neither a C toolchain, nor glib, nor a network.

Usage:
    python3 -I tests/tools/gen_spice_vectors.py <spice-dump> <glz-dump> [outdir]

See tests/vectors/spice/README.md for how to build the two programs.
"""
import gzip
import json
import os
import subprocess
import sys

# Every image type each codec must still be covered for. A generator change
# that quietly drops one would otherwise leave a passing test suite behind.
REQUIRED = {
    "quic": {"gray", "rgb16", "rgb24", "rgb32", "rgba"},
    "lz": {"rgb16", "rgb24", "rgb32", "rgba", "xxxa", "a8"},
    "glz": {
        "plt1_le", "plt1_be", "plt4_le", "plt4_be", "plt8",
        "rgb16", "rgb24", "rgb32", "rgba",
    },
}


def run(path):
    """Run a dump program and parse its JSON, failing loudly if it did not."""
    out = subprocess.run([path], capture_output=True)
    if out.returncode != 0:
        sys.exit(f"{path} exited {out.returncode}:\n{out.stderr.decode()}")
    if out.stderr:
        sys.exit(f"{path} wrote to stderr:\n{out.stderr.decode()}")
    return json.loads(out.stdout)


def check_coverage(cases):
    """Every codec covers every image type it is supposed to."""
    by_codec = {}
    for case in cases:
        by_codec.setdefault(case["codec"], set()).add(case["image_type"])
    for codec, required in REQUIRED.items():
        got = by_codec.get(codec, set())
        missing = required - got
        if missing:
            sys.exit(f"{codec}: vectors no longer cover {sorted(missing)}")


def check_far_distance(cases):
    """At least one LZ stream uses the 16-bit far-distance escape.

    No natural image reaches it -- the encoder has to be given a repeat more
    than 8191 pixels back on purpose -- so if the dump program's `farmatch`
    case stops working, this is the only thing that would notice.
    """
    literal_bytes = {"rgb16": 2, "rgb24": 3, "rgb32": 3, "a8": 1}
    found = 0
    for case in cases:
        if case["codec"] != "lz" or case["image_type"] not in literal_bytes:
            continue
        data = bytes.fromhex(case["compressed"])
        width = literal_bytes[case["image_type"]]
        i = 28  # seven big-endian 32-bit header fields
        while i < len(data):
            ctrl = data[i]
            i += 1
            if ctrl < 32:
                i += (ctrl + 1) * width
                continue
            if (ctrl >> 5) - 1 == 6:
                while True:
                    code = data[i]
                    i += 1
                    if code != 255:
                        break
            code = data[i]
            i += 1
            if code == 255 and (ctrl & 31) == 31:
                found += 1
                i += 2
    if not found:
        sys.exit("no LZ vector uses the far-distance escape; it would go untested")


def check_windows(cases):
    """GLZ windows are contiguous runs of ids, which is what lets the test
    replay them in order through one decoder."""
    windows = {}
    for case in cases:
        if case["codec"] == "glz":
            windows.setdefault(case["window"], []).append(case["id"])
    if not windows:
        sys.exit("no GLZ windows in the vectors")
    for name, ids in windows.items():
        ids.sort()
        if ids != list(range(ids[0], ids[0] + len(ids))):
            sys.exit(f"GLZ window {name} has non-contiguous ids {ids}")


def main():
    if not 3 <= len(sys.argv) <= 4:
        sys.exit(__doc__)
    spice_dump, glz_dump = sys.argv[1], sys.argv[2]
    outdir = sys.argv[3] if len(sys.argv) == 4 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "vectors", "spice"
    )

    cases = run(spice_dump) + run(glz_dump)
    check_coverage(cases)
    check_far_distance(cases)
    check_windows(cases)

    path = os.path.join(outdir, "vectors.json.gz")
    # Gzipped because the uncompressed set is about 3 MB of hex and the
    # expected pixels compress to a tenth of that.
    with gzip.open(path, "wt", compresslevel=9) as f:
        json.dump(cases, f)

    size = os.path.getsize(path)
    print(f"wrote {len(cases)} cases to {path} ({size // 1024} KiB)")


if __name__ == "__main__":
    main()
