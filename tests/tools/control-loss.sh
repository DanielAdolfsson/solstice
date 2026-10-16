#!/usr/bin/env bash
# Run the real Moonlight client against this host with packet loss on the ENet
# control port alone (docs/roadmap.md §7).
#
# `crates/solstice-gamestream/tests/enet_interop.rs` loses packets against an
# independent ENet in simulation; this does it against the real client, over
# real sockets. Video and audio are left alone, so a failure is the control
# channel's.
#
# No root: `unshare -rn` makes us root of a network namespace that holds
# nothing but its own loopback, and netem goes on that.
#
#   ./tests/tools/control-loss.sh          # 20% loss, both directions
#   ./tests/tools/control-loss.sh 40       # 40%
#
# Needs: the probe (tests/tools/mlc-probe/build.sh), unshare, ip, tc, and a
# kernel with sch_netem.
set -euo pipefail

LOSS=${1:-20}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
MLC=${SOLSTICE_MLC_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/solstice/mlc}
PROBE=${SOLSTICE_MLC_PROBE:-$MLC/mlc-probe}
# `the_reference_moonlight_client_streams_from_this_host` runs from base port
# 49289, and the control port is base + 10.
CONTROL_PORT=49299

say() { printf '\033[1m==>\033[0m %s\n' "$*" >&2; }

for t in unshare ip tc python3 cargo; do
    command -v "$t" >/dev/null || { echo "missing required tool: $t" >&2; exit 1; }
done
[[ -x $PROBE ]] || { echo "no mlc-probe at $PROBE; run tests/tools/mlc-probe/build.sh" >&2; exit 1; }

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

say "streaming with ${LOSS}% loss on UDP $CONTROL_PORT"
unshare -rn env LOSS="$LOSS" PORT="$CONTROL_PORT" TEST_BIN="$TEST_BIN" PROBE="$PROBE" \
    ROOT="$ROOT" bash -euo pipefail -c '
    ip link set lo up
    # Everything to band 1, which is a plain FIFO; only the filters below send
    # anything to band 3, which is netem.
    tc qdisc add dev lo root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    tc qdisc add dev lo parent 1:3 handle 30: netem loss "$LOSS%"
    for dir in sport dport; do
        tc filter add dev lo parent 1: protocol ip prio 1 u32 \
            match ip protocol 17 0xff match ip $dir "$PORT" 0xffff flowid 1:3
    done
    cd "$ROOT/crates/solstice"
    rc=0
    SOLSTICE_MLC_PROBE="$PROBE" "$TEST_BIN" \
        --exact the_reference_moonlight_client_streams_from_this_host --nocapture || rc=$?
    # The proof that loss happened at all.
    tc -s qdisc show dev lo | grep -A1 netem >&2
    exit $rc
'
