# nanors differential FEC vectors

Moonlight's Reed–Solomon must match `nanors` byte-for-byte or recovery silently
corrupts video under packet loss. This harness proves an implementation matches.

`dump.c` links the real `nanors` and prints its parity matrix plus encoded
parity for deterministic input. `check.py` reimplements the construction
independently — GF(2⁸) log/exp tables built from the primitive polynomial, no
bytes copied from nanors — and compares.

## Run

```sh
git clone --depth 1 https://github.com/sleepybishop/nanors.git /tmp/nanors
make -C /tmp/nanors rs.o deps/obl/oblas_common.o deps/obl/oblas_lite.o

gcc -O2 -std=c11 -I/tmp/nanors -I/tmp/nanors/deps/obl \
    -o /tmp/fec-dump dump.c \
    /tmp/nanors/rs.o /tmp/nanors/deps/obl/oblas_common.o /tmp/nanors/deps/obl/oblas_lite.o

python3 -I check.py          # expects /tmp/fec-dump
```

Expected output:

```
ds=6    ps=3   bs=8     matrix=MATCH  parity=MATCH
ds=1    ps=2   bs=32    matrix=MATCH  parity=MATCH
ds=5    ps=2   bs=64    matrix=MATCH  parity=MATCH
ds=212  ps=42  bs=96    matrix=MATCH  parity=MATCH
ds=235  ps=20  bs=128   matrix=MATCH  parity=MATCH
ds=100  ps=20  bs=1408  matrix=MATCH  parity=MATCH

ALL MATCH
```

## The specification being verified

| | |
|---|---|
| Field | GF(2⁸), primitive polynomial 285 (0x11D) |
| Matrix | `P[j][i] = inv((ps + i) XOR j)` — a Cauchy matrix |
| Encode | systematic; `parity[j] = Σᵢ P[j][i] · data[i]` |

Cases are chosen to cover the real parameter space: `ds=1,ps=2` is a
single-packet P-frame on a static desktop after the `minRequiredFecPackets`
bump; `ds=212,ps=42` is the maximum block at 20%; `bs=1408` is the real
blocksize for `packetSize=1392`.

## Porting this to Rust

Point `check.py`'s comparison at the Rust implementation instead of its own
Python one — the C side stays as the oracle. Audio FEC is **not** covered here:
it uses Nvidia's hard-coded RS(4,2) matrix, which is a different construction
(see `docs/moonlight-sunshine-protocol.md` §5.4).
