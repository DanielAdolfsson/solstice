# mlc-probe — the reference Moonlight client, headless and asserting

Every other GameStream test in this repository drives Solstice with a client
written from the same research as the server, so an assumption that is wrong at
*both* ends still passes. This is the fix: a driver linking the real
`moonlight-common-c`, the library every Moonlight port shares.

It found eight defects in a day. The list is in `docs/roadmap.md` §3.

## Build

```sh
./tests/tools/mlc-probe/build.sh
```

Needs `git`, `gcc` and OpenSSL headers (`libssl-dev`); no CMake. Output goes to
`$SOLSTICE_MLC_DIR`, or `~/.cache/solstice/mlc` by default. `manifest.lock`
records the resolved commits and is compared against the committed copy, so a
pin that has moved is loud rather than silent — `--update-lock` re-pins to
upstream `HEAD`.

Then:

```sh
cargo test -p solstice --test real_moonlight
```

The test skips with a printed note when the probe is absent, so a checkout
without a C toolchain still runs green.

## Build flags

`docs/testing.md` §2.2 names three debug hooks. Two of them are used:

| Flag | What it buys |
|---|---|
| `LC_DEBUG` | Turns on `FEC_VALIDATION_MODE` — drop one random data shard per frame, recover it from parity, assert the recovered bytes and header fields match the original — and the `LC_ASSERT`/`LC_ASSERT_VT` family, which checks values that came from the host. A malformed field aborts the probe rather than being tolerated. |
| `LC_DEBUG_RECORD_MODE` | Pass-through recorder callbacks that write the reassembled H.264 and Opus elementary streams to the paths given as `drContext`/`arContext`. |

`LC_FUZZING` is **not** used, and cannot be: `RtpVideoQueue.c:5` gates
`FEC_VALIDATION_MODE` on `LC_DEBUG && !LC_FUZZING`, and `Platform.h:128-132`
turns off `LC_ASSERT_VT` under it. It is for fuzzing the depacketiser, which is
a different job from conformance.

## What it covers, and what it does not

The probe does the streaming half only. Pairing, `/serverinfo` and `/launch`
are mutual-TLS HTTP that `moonlight-common-c` does not implement — each
Moonlight port has its own app layer for that — so the Rust harness
(`crates/solstice/tests/real_moonlight.rs`) performs them and passes the
negotiated parameters in. From there the probe exercises the encrypted RTSP
handshake, the ENet control channel, the UDP media binding, the packetiser,
the FEC geometry, the input path and the audio channel.

## Running it by hand

Useful when iterating on the host: start a daemon, pair, launch, then point the
probe at the session. The arguments are `name=value`, in any order.

```sh
~/.cache/solstice/mlc/mlc-probe \
    address=127.0.0.1 \
    rtspurl=rtspenc://127.0.0.1:48010 \
    rikey=000102030405060708090a0b0c0d0e0f rikeyid=305419896 \
    width=1280 height=720 fps=60 bitrate=10000 \
    frames=60 timeout=30 \
    video=/tmp/recorded.h264
```

Stdout carries one `PROBE <event> k=v …` line per event and a final
`PROBE summary …`; the harness parses those. Everything
`moonlight-common-c` logs goes to stderr untouched, because when this fails the
log is the whole diagnosis. Exit status is 0 only if the connection
established *and* the requested number of frames decoded.

`hold=N` keeps the connection open for at least N seconds even after the
frames have arrived. The still-screen test uses it to sit through a frozen
picture. The summary's `maxgap` is the longest wait between decode units in
milliseconds, and `poor` counts `CONN_STATUS_POOR` notifications. Every key
frame is logged as a `frame` line, so one that arrives mid-session, which is
what recovery looks like, is visible.

Decode the recording to look at it:

```sh
ffmpeg -i /tmp/recorded.h264 -vsync 0 /tmp/frame_%04d.png
```
