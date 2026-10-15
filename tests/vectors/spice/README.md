# SPICE image-codec differential vectors

`crates/solstice-spice-codec` is a from-scratch Rust port of SPICE's QUIC, LZ
and GLZ decoders. Nothing about those codecs can be checked by reading the
code: QUIC's Golomb model evolves pseudo-randomly in lockstep with the
encoder, and GLZ's dictionary spans the whole session. A round-trip against a
Rust encoder would only prove the port is self-consistent. The only argument
that holds is that the port agrees with the implementation on the other end of
the wire, so this harness runs the real C encoders and freezes what they
produce.

Two programs:

- `dump.c` links `spice-common`'s **QUIC and LZ** codecs. For each test image
  it records the compressed bytes *and* the pixels the C **decoder**
  reconstructs from them, so both halves are pinned.
- `glz-dump.c` links `spice-server`'s **GLZ encoder**. GLZ has no standalone C
  decoder that is cheap to link — `spice-gtk`'s wants pixman and a coroutine
  runtime — so the expected pixels are the *source* image instead. GLZ is
  lossless, so that is a complete test of the control encoding and the window
  arithmetic, which is where GLZ's difficulty lives.

A GLZ vector is a **window**, not an image: a sequence encoded through one
dictionary, which must be decoded through one decoder in the same order. The
test groups them by the `window` field and replays each in `id` order.

## Run

```sh
git clone --depth 1 https://gitlab.freedesktop.org/spice/spice-common.git   /tmp/spice-ref/spice-common
git clone --depth 1 https://gitlab.freedesktop.org/spice/spice-protocol.git /tmp/spice-ref/spice-protocol
git clone --depth 1 https://gitlab.freedesktop.org/spice/spice.git          /tmp/spice-ref/spice-server

mkdir -p /tmp/spice-build && cd /tmp/spice-build
echo '#define HAVE_CONFIG_H 1' > config.h

COMMON=/tmp/spice-ref/spice-common/common
INC="-I. -I/tmp/spice-ref/spice-common -I/tmp/spice-ref/spice-protocol $(pkg-config --cflags glib-2.0)"
LIBS="$(pkg-config --libs glib-2.0)"
HERE=<this directory>

gcc -O1 $INC -o spice-dump "$HERE/dump.c" \
    $COMMON/quic.c $COMMON/lz.c $COMMON/log.c $COMMON/mem.c $COMMON/backtrace.c $LIBS
```

The GLZ encoder needs one shim. `glz-encoder.h` includes `"red-common.h"`,
which drags in most of `spice-server` including a generated header that only
exists after a full build. Copy the five GLZ sources somewhere of their own
and put a stub beside them:

```sh
mkdir -p /tmp/spice-build/glzsrc && cd /tmp/spice-build/glzsrc
cp /tmp/spice-ref/spice-server/server/glz-encoder{.c,.h,-priv.h,-dict.c,-dict.h} .
cp /tmp/spice-ref/spice-server/server/glz-encode{.tmpl.c,-match.tmpl.c} .
cat > red-common.h <<'EOF'
#ifndef RED_COMMON_H_STUB
#define RED_COMMON_H_STUB
#include <glib.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <spice/macros.h>
#include <common/log.h>
#include <common/mem.h>
#include <common/macros.h>
#endif
EOF

cd /tmp/spice-build
gcc -O1 -Iglzsrc $INC -o glz-dump "$HERE/glz-dump.c" \
    glzsrc/glz-encoder.c glzsrc/glz-encoder-dict.c \
    $COMMON/lz.c $COMMON/log.c $COMMON/mem.c $COMMON/backtrace.c $LIBS
```

Then freeze them:

```sh
python3 -I tests/tools/gen_spice_vectors.py /tmp/spice-build/spice-dump /tmp/spice-build/glz-dump
```

The script refuses to write a set that has stopped covering an image type, has
non-contiguous GLZ window ids, or no longer exercises LZ's far-distance
escape.

## What the images are chosen for

| Pattern | Reaches |
|---|---|
| `flat` | QUIC's melcode run mode; LZ matches that overlap their own output |
| `gradient` | smooth residuals, so the Golomb model settles on a short code |
| `noise` | the not-GR escape codeword; LZ literal runs |
| `bands`, `edges` | frequent model switches and medium-distance matches |
| `longperiod` | matches whose period is longer than one row |
| `farmatch` | **LZ's 16-bit far-distance escape**, which needs a repeat more than 8191 pixels back and no natural image produces |

Sizes run 1×1 and 3×2 (the row-0 and first-pixel special cases) up to 130×100,
which crosses QUIC's 2048-symbol wait-mask step more than once, and one
20000×1 strip for `farmatch`. Noise is deliberately absent above 17×5: it
compresses to nothing, so it would be most of the file for none of the
coverage.

`glz-dump.c` builds each window as a base frame plus scrolled and patched
variants, which is what gives the encoder long cross-image matches. Between
them the windows reach every branch of the GLZ control decoder — all four
image-distance widths, short, long and very-long pixel offsets, same-image and
cross-image matches — and `rgb32-evicting` uses a dictionary too small to hold
its own sequence, so images are evicted and `win_head_dist` stops being zero.

## The one place the vectors are not C-derived

`glz-dump.c` computes its expected BGRA from the source by mirroring the
`COPY_COMP_PIXEL` macros in `lz_decompress_tmpl.c`. For every type the C
`lz_decode` accepts, it then **certifies** that buffer by LZ-encoding the same
source and decoding it with the C, and aborts if they disagree.

Palette types are the exception: `lz_decode` rejects palette output outright
(`case LZ_IMAGE_TYPE_PLT*: error("bad image type")`), so there is no C decoder
to certify against without linking `canvas_base.c` and pixman. The palette
expansion in `expand()` is therefore this harness's reading of the C macros
rather than the C's own output. It is six lines — index the palette, write
`b`, `g`, `r`, and a zero — and the index extraction for each of the four
bit-orders is what it is really asserting.

## Licensing

`dump.c` and `glz-dump.c` are ours. The code they link is `spice-common` and
`spice-server`, LGPL-2.1-or-later. Nothing from either is vendored into this
repository: the clones are fetched at regeneration time and the committed
artefact is the generated vector file.
