#!/usr/bin/env bash
# Build every fuzz target and run each for a while, from the committed seeds
# (docs/roadmap.md §8, docs/testing.md §6).
#
# On the stable toolchain, without cargo-fuzz: the targets are built with the
# same instrumentation flags cargo-fuzz passes, which is how `enet_host` was
# run for roadmap §7. cargo-fuzz itself needs nightly, and this box has none.
# No AddressSanitizer: every crate under test forbids `unsafe`.
#
#   ./tests/tools/fuzz.sh                    # every target, 60 s each
#   ./tests/tools/fuzz.sh 600                # every target, ten minutes each
#   ./tests/tools/fuzz.sh 600 enet_host      # one target
#
# Each target reads `fuzz/seeds/<target>/` (committed, from the captured
# session; tests/tools/gen_fuzz_seeds.py) and grows `fuzz/corpus/<target>/`
# (ignored, kept between runs). A crash leaves its input in
# `fuzz/artifacts/<target>/` and fails the script; reproduce it with
#   fuzz/target/<triple>/release/<target> fuzz/artifacts/<target>/<file>
set -euo pipefail

SECONDS_EACH=${1:-60}
shift || true
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FUZZ=$(cd "$HERE/../../fuzz" && pwd)
TRIPLE=$(rustc -vV | sed -n 's/^host: //p')

say() { printf '\033[1m==>\033[0m %s\n' "$*" >&2; }

if [[ $# -gt 0 ]]; then
    targets=("$@")
else
    mapfile -t targets < <(sed -n 's/^name = "\(.*\)"$/\1/p' "$FUZZ/Cargo.toml" | grep -v '^solstice-fuzz$')
fi

say "building ${#targets[@]} targets for $TRIPLE"
# cargo-fuzz's own flags (`cargo fuzz build -O --sanitizer none`), so a
# corpus from here is a corpus for cargo-fuzz too. `--target` keeps them off
# build scripts and proc macros.
(
    cd "$FUZZ"
    RUSTFLAGS="-Cpasses=sancov-module \
        -Cllvm-args=-sanitizer-coverage-level=4 \
        -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
        -Cllvm-args=-sanitizer-coverage-pc-table \
        -Cllvm-args=-sanitizer-coverage-trace-compares \
        --cfg fuzzing -Cdebug-assertions -Coverflow-checks" \
    cargo build --release --target "$TRIPLE" $(printf -- '--bin %s ' "${targets[@]}")
)

failed=()
for t in "${targets[@]}"; do
    corpus="$FUZZ/corpus/$t" artifacts="$FUZZ/artifacts/$t/"
    mkdir -p "$corpus" "$artifacts"
    inputs=("$corpus")
    [[ -d $FUZZ/seeds/$t ]] && inputs+=("$FUZZ/seeds/$t")
    say "$t for ${SECONDS_EACH}s (${inputs[*]#$FUZZ/})"
    if ! "$FUZZ/target/$TRIPLE/release/$t" "${inputs[@]}" \
            -max_total_time="$SECONDS_EACH" -artifact_prefix="$artifacts" \
            -print_final_stats=1 2>"$FUZZ/artifacts/$t.log"; then
        failed+=("$t")
        tail -30 "$FUZZ/artifacts/$t.log" >&2
    fi
    grep -E '^stat::number_of_executed_units|^Done ' "$FUZZ/artifacts/$t.log" >&2 || true
done

if [[ ${#failed[@]} -gt 0 ]]; then
    say "FAILED: ${failed[*]} (inputs under fuzz/artifacts/)"
    exit 1
fi
say "all ${#targets[@]} targets ran clean"
