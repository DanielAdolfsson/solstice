#!/usr/bin/env bash
# Capture a real Moonlight session against this host, and freeze it as golden
# vectors (docs/roadmap.md §4, docs/testing.md §2.4).
#
# Runs `crates/solstice/tests/real_moonlight.rs` -- which drives the real
# moonlight-common-c through mlc-probe -- inside a private network namespace
# with tcpdump on its loopback, then hands the capture to
# gen_capture_vectors.py. No root: `unshare -rn` makes us root of a namespace
# that holds nothing but its own `lo`, which is all tcpdump needs, and keeps
# anything else on the machine out of the capture.
#
#   ./tests/tools/capture-session.sh            # writes tests/vectors/capture/
#   ./tests/tools/capture-session.sh --keep     # also keep the pcap and sidecar
#
# Needs: the probe (tests/tools/mlc-probe/build.sh), tcpdump, unshare, ip,
# and python3 with `cryptography` for the generator.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
MLC=${SOLSTICE_MLC_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/solstice/mlc}
PROBE=${SOLSTICE_MLC_PROBE:-$MLC/mlc-probe}

keep=0
for a in "$@"; do
    case $a in
        --keep) keep=1 ;;
        *) echo "unknown argument: $a" >&2; exit 2 ;;
    esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*" >&2; }

for t in tcpdump unshare ip python3 cargo; do
    command -v "$t" >/dev/null || { echo "missing required tool: $t" >&2; exit 1; }
done
[[ -x $PROBE ]] || { echo "no mlc-probe at $PROBE; run tests/tools/mlc-probe/build.sh" >&2; exit 1; }
python3 -I -c 'import cryptography' 2>/dev/null \
    || { echo "python3 needs the 'cryptography' module to decrypt the capture" >&2; exit 1; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/solstice-capture.XXXXXX")
if [[ $keep -eq 0 ]]; then trap 'rm -rf "$WORK"' EXIT; fi

# Build outside the namespace: it has no network, and cargo may want one.
say "building the real-Moonlight test"
TEST_BIN=$(cd "$ROOT" && cargo test -p solstice --test real_moonlight --no-run \
    --message-format=json 2>/dev/null \
    | python3 -I -c 'import json,sys
for l in sys.stdin:
    m = json.loads(l)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "real_moonlight":
        print(m["executable"])')
[[ -x $TEST_BIN ]] || { echo "could not find the real_moonlight test binary" >&2; exit 1; }

say "running the session under capture"
# The quoted script runs as root of a fresh network namespace whose only
# interface is its own loopback.
unshare -rn env WORK="$WORK" TEST_BIN="$TEST_BIN" PROBE="$PROBE" ROOT="$ROOT" bash -euo pipefail -c '
    ip link set lo up
    # -U so the file is complete the moment tcpdump is told to stop; -Z root
    # because there is no other user to drop to in here. Everything is
    # captured; the generator picks out the ports the sidecar names.
    tcpdump -U -Z root -i lo -s 0 -w "$WORK/session.pcap" 2>"$WORK/tcpdump.log" &
    dump=$!
    # tcpdump says when it is listening; anything sent before that is lost.
    for _ in $(seq 100); do grep -q listening "$WORK/tcpdump.log" && break; sleep 0.05; done
    cd "$ROOT/crates/solstice"
    SOLSTICE_MLC_PROBE="$PROBE" SOLSTICE_CAPTURE_DIR="$WORK" \
        "$TEST_BIN" --exact the_reference_moonlight_client_streams_from_this_host \
        --nocapture >"$WORK/test.log" 2>&1 || { cat "$WORK/test.log" >&2; kill $dump; exit 1; }
    sleep 0.2
    kill -INT $dump
    wait $dump || true
'
cat "$WORK/tcpdump.log" >&2
if ! grep -q '^0 packets dropped by kernel' "$WORK/tcpdump.log"; then
    echo "tcpdump dropped packets; a capture with holes is not a golden vector" >&2
    exit 1
fi
[[ -f $WORK/session.json ]] || { echo "the test passed but left no sidecar" >&2; exit 1; }

say "freezing the vectors"
python3 -I "$HERE/gen_capture_vectors.py" "$WORK" "$ROOT/tests/vectors/capture"

if [[ $keep -eq 1 ]]; then say "kept $WORK"; fi
