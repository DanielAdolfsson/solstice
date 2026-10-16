#!/usr/bin/env bash
# Build mlc-probe: the reference Moonlight client, headless and asserting.
#
# Fetches `moonlight-common-c` at a pinned commit, compiles it with the debug
# hooks `docs/testing.md` §2.2 describes, and links `probe.c` against it. No
# CMake: the library is forty C files and three defines, and driving the build
# directly is what lets the flags be chosen per build rather than per preset.
#
#   ./tests/tools/mlc-probe/build.sh                # build if stale, else nothing
#   ./tests/tools/mlc-probe/build.sh --force        # rebuild unconditionally
#   ./tests/tools/mlc-probe/build.sh --update-lock  # re-pin to upstream HEAD
#
# Output lands in $SOLSTICE_MLC_DIR, or ~/.cache/solstice/mlc by default:
#   mlc-probe       the binary the Rust harness runs
#   manifest.lock   resolved commits; compared against the committed copy in
#                   tests/tools/mlc-probe/ so a moved pin is loud, not silent
set -euo pipefail

REPO=https://github.com/moonlight-stream/moonlight-common-c.git
# Pinned deliberately. A client that moves under the test turns a host
# regression and an upstream change into the same red, which is the one
# failure mode a conformance tool cannot afford.
COMMIT=aeba988e0a302145eff2e70fa3e11cd98ec01f5d

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUT=${SOLSTICE_MLC_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/solstice/mlc}
SRC=$OUT/moonlight-common-c

force=0 update_lock=0
for a in "$@"; do
    case $a in
        --force)       force=1 ;;
        --update-lock) update_lock=1; force=1 ;;
        *) echo "unknown argument: $a" >&2; exit 2 ;;
    esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*" >&2; }

for t in git gcc; do
    command -v "$t" >/dev/null || { echo "missing required tool: $t" >&2; exit 1; }
done
# moonlight-common-c uses OpenSSL's EVP for AES-GCM; MbedTLS is the other
# option upstream supports and is deliberately not wired up here.
echo '#include <openssl/evp.h>' | gcc -E -xc - >/dev/null 2>&1 || {
    echo "missing OpenSSL headers (apt install libssl-dev)" >&2; exit 1; }

if [[ $force -eq 0 && -x $OUT/mlc-probe && -f $OUT/manifest.lock && -f $HERE/manifest.lock ]] \
   && cmp -s "$OUT/manifest.lock" "$HERE/manifest.lock" \
   && [[ $OUT/mlc-probe -nt $HERE/probe.c ]]; then
    say "mlc-probe is current ($OUT/mlc-probe)"; exit 0
fi

# --- fetch ---------------------------------------------------------------
if [[ $update_lock -eq 1 ]]; then
    COMMIT=$(git ls-remote "$REPO" HEAD | cut -f1)
    say "re-pinning to upstream HEAD: $COMMIT"
fi

mkdir -p "$SRC"
if [[ ! -d $SRC/.git ]]; then
    git init --quiet "$SRC"
    git -C "$SRC" remote add origin "$REPO"
fi
if [[ $(git -C "$SRC" rev-parse HEAD 2>/dev/null || true) != "$COMMIT" ]]; then
    say "fetching moonlight-common-c $COMMIT"
    git -C "$SRC" fetch --quiet --depth 1 origin "$COMMIT"
    git -C "$SRC" checkout --quiet --detach FETCH_HEAD
fi
# enet and nanors are submodules, so the superproject commit pins them too.
git -C "$SRC" submodule update --quiet --init --depth 1 --recursive

# --- compile -------------------------------------------------------------
# enet does its feature detection in CMake rather than a configure header, so
# the answers for glibc are supplied here. Getting one of these wrong does not
# fail the build -- it silently compiles a different socket path -- which is
# why they are listed rather than guessed at per-platform.
ENET_FEATURES=(
    -DHAS_FCNTL=1 -DHAS_IOCTL=1 -DHAS_POLL=1
    -DHAS_GETADDRINFO=1 -DHAS_GETNAMEINFO=1
    -DHAS_GETHOSTBYNAME_R=1 -DHAS_GETHOSTBYADDR_R=1
    -DHAS_INET_PTON=1 -DHAS_INET_NTOP=1
    -DHAS_MSGHDR_FLAGS=1 -DHAS_SOCKLEN_T=1
)

# LC_DEBUG is the point of this build. It turns on FEC_VALIDATION_MODE (drop a
# random data shard per frame, recover it, assert the bytes match) and the
# LC_ASSERT family, including LC_ASSERT_VT, which checks values that came from
# the host -- so a malformed field aborts the probe instead of being tolerated.
#
# LC_FUZZING is deliberately absent. `docs/testing.md` §2.2 lists all three
# flags together, but RtpVideoQueue.c:5 gates FEC_VALIDATION_MODE on
# `LC_DEBUG && !LC_FUZZING`: the two are alternatives, and the oracle is the
# one worth having here.
PROBE_DEFINES=(-DLC_DEBUG -DLC_DEBUG_RECORD_MODE -DHAS_SOCKLEN_T)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/mlc-probe.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# Object files land wherever gcc is invoked from, so invoke it from $WORK.
say "compiling enet"
(cd "$WORK" && gcc -c -O2 -g -w "${ENET_FEATURES[@]}" -I"$SRC/enet/include" \
    "$SRC"/enet/*.c)

say "compiling moonlight-common-c (LC_DEBUG, LC_DEBUG_RECORD_MODE)"
(cd "$WORK" && gcc -c -O2 -g -w "${PROBE_DEFINES[@]}" \
    -I"$SRC/src" -I"$SRC/enet/include" \
    -I"$SRC/nanors" -I"$SRC/nanors/deps" -I"$SRC/nanors/deps/obl" \
    "$SRC"/src/*.c "$SRC"/nanors/rs.c \
    "$SRC"/nanors/deps/obl/oblas_common.c "$SRC"/nanors/deps/obl/oblas_lite.c)

say "linking the probe"
mkdir -p "$OUT"
gcc -O2 -g -std=gnu11 -Wall -Wextra -Wno-unused-parameter \
    "${PROBE_DEFINES[@]}" -I"$SRC/src" \
    -o "$WORK/mlc-probe" "$HERE/probe.c" "$WORK"/*.o \
    -lcrypto -lpthread -lm

{
    echo "# Generated by tests/tools/mlc-probe/build.sh -- commit this file."
    echo "# A mismatch against the built probe means the pin moved."
    echo "moonlight-common-c $COMMIT"
    git -C "$SRC" submodule status --recursive | awk '{gsub(/^[+-]/,"",$1); print $2, $1}'
} > "$WORK/manifest.lock"

mv "$WORK/mlc-probe" "$WORK/manifest.lock" "$OUT/"

if [[ ! -f $HERE/manifest.lock ]] || [[ $update_lock -eq 1 ]]; then
    cp "$OUT/manifest.lock" "$HERE/manifest.lock"
    say "wrote tests/tools/mlc-probe/manifest.lock"
elif ! cmp -s "$OUT/manifest.lock" "$HERE/manifest.lock"; then
    say "WARNING: the built probe does not match the committed lock:"
    diff -u "$HERE/manifest.lock" "$OUT/manifest.lock" >&2 || true
fi

say "built $OUT/mlc-probe"
