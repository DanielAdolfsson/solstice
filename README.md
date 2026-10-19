# Solstice

A proxy that lets a **Moonlight** client connect to a **VNC** or **SPICE**
desktop. Moonlight speaks to Solstice as if it were a GameStream host;
Solstice speaks to the remote desktop as a VNC or SPICE client, and bridges
the two.

```
Moonlight ──GameStream──▶ Solstice ──RFB / SPICE──▶ remote desktop
```

**Status: a real Moonlight client streams from it.** Not a Moonlight-shaped
client of our own -- the actual `moonlight-common-c`, the library every
Moonlight port shares, built with its FEC oracle and its host-value assertions
turned on. It pairs, launches, negotiates encrypted RTSP, establishes the ENet
control stream, receives an encrypted FEC-protected H.264 stream, and sends
input back. That path is a test (`real_moonlight.rs`), not a claim. Pointing
it at the host for the first time found **eight** defects that the project's
own end-to-end test could not, because that test's client was written from the
same research as the server and agreed with every mistake in it
([the list](docs/roadmap.md#3-validate-against-real-moonlight)).

The same stack delivers a real VNC desktop to a client that decodes it to the
right pixels (`a_client_receives_the_pixels_of_a_real_vnc_desktop`).

**Both backends work against a real server.** The SPICE one is complete —
channel links, the 2D rasteriser, all six image types, video streams, the
guest agent and audio — and `tests/real_server.rs` drives it against a live
a **real QEMU guest** — every image codec forced in turn, MJPEG streams,
input verified against the guest's own event stream, and a real
`spice-vdagent` granting and applying a resize and carrying the clipboard
both ways. What has *not* been exercised is written up in
[docs/roadmap.md §2.7](docs/roadmap.md#27-what-is-still-unvalidated).

See [Status](#status) for the full picture, including what is deliberately
absent.

---

## Build and test

Needs a stable Rust toolchain, a C compiler, CMake, libclang, nasm and
libx264's headers (`apt install cmake clang nasm libx264-dev` on Debian and
Ubuntu). The encoder is the system's libx264, bound at build time; libopus and
OpenH264, the fallback encoder, are built from vendored source.

nasm is not strictly required, and that is the trap: without it OpenH264's
build quietly leaves out all of its SIMD and runs up to three times slower.

`--no-default-features --features vnc,openh264` builds without libx264, with
OpenH264 as the encoder, and without CMake and the Opus codec: every stream
then carries canned stereo silence.

```sh
cargo build --release
cargo test --workspace        # 935 tests
cargo clippy --workspace --all-targets
```

The tests that need a real server build and boot a small QEMU guest. They
skip with a printed note if it is absent, so the suite runs without one — but
to actually exercise them:

```sh
./tests/guest/build-image.sh      # ~4 min cold, then cached
```

It needs `qemu-system-x86_64`, `curl` and unprivileged user namespaces, and
runs entirely without `sudo`: no installer is ever booted, the root
filesystem is assembled on the host and packed as a stateless initramfs. The
guest serves **both** backends — QEMU's RFB server and `spice-server` with a
real `spice-vdagent` — so one image covers the whole T3 tier.

The GameStream half has an equivalent, and it is the one that matters most:

```sh
./tests/tools/mlc-probe/build.sh  # ~30 s; needs git, gcc, libssl-dev
```

That fetches `moonlight-common-c` at a pinned commit and builds the real
client headless, with `FEC_VALIDATION_MODE` and the host-value assertions on.
`crates/solstice/tests/real_moonlight.rs` then drives a full session through
it. Same deal: skipped with a printed note when it has not been built.
[The README](tests/tools/mlc-probe/README.md).

The default features are `vnc`, `x264`, `openh264` and `audio`. SPICE is
**not** on by default:
it is excludable at compile time along with its whole dependency tree — the
image codecs, a JPEG decoder, LZ4 and zlib — none of which an RFB-only build
needs. So is the encoder:

```sh
cargo build --features spice                          # both backends
cargo build --no-default-features --features vnc      # no H.264 encoder
```

### Running it

```sh
cp contrib/solstice.example.toml /etc/solstice/solstice.toml
solstice --config /etc/solstice/solstice.toml run \
    --endpoint 'name=Windows VM,kind=spice,host=127.0.0.1,port=5901' \
    --endpoint 'name=Build box,kind=vnc,host=10.0.0.5,password_file=/etc/solstice/build.pw'
```

Each endpoint is one app in Moonlight's list: connect to the host, then pick
the desktop. They can come from `--endpoint`, repeated, or from
`[[endpoint]]` tables in the configuration, with the same keys either way.
None at all is a valid start: Moonlight shows one "No desktops on this
host" tile, and you can pair first and add desktops afterwards.
`--endpoint` takes no `password`, because every user on the machine can
read the command line; use `password_file`.

A running daemon takes more, or fewer, without a restart:

```sh
solstice endpoint add 'name=Scratch VM,kind=spice,host=127.0.0.1,port=5902'
solstice endpoint list
solstice endpoint remove 'Scratch VM'   # ends its stream, if one is running
```

These last until the daemon stops. A restart is back to the configuration
and the flags.

Pairing is opened from a second shell, as the user the daemon runs as, with
the PIN Moonlight is showing. The command waits until the client has paired,
and fails if the window runs out:

```sh
solstice pair --pin 1234            # window: security.pairing_window, 60s
solstice status
solstice list-clients
solstice revoke 3fa9c2d1            # a fingerprint prefix from list-clients
```

They reach the daemon over `$state_dir/control.sock`, a mode-0600 Unix socket.
There is no HTTP management API and no web UI.

The shipped defaults are the deployment `docs/security.md` recommends: bound to
loopback, pairing closed, encryption mandatory, one session, and a ceiling on
every resolution, rate and bitrate the client can ask for. There are no
endpoints by default. `--endpoint 'name=Bars,kind=testpattern'` offers the
built-in colour bars, so the host half can be brought up and pointed at a
client before any desktop is involved.

`contrib/solstice.service` is a hardened systemd unit: no capabilities,
`ProtectSystem=strict`, a seccomp filter, and one writable directory.

---

## Documents

| Document | Contents |
|---|---|
| [docs/moonlight-sunshine-protocol.md](docs/moonlight-sunshine-protocol.md) | The GameStream protocol Solstice serves: ports, NVHTTP, PIN pairing, RTSP, and the video / audio / control wire formats, read out of `moonlight-common-c` and `Sunshine` |
| [docs/rfb-vnc-protocol.md](docs/rfb-vnc-protocol.md) | RFB handshake, messages, encodings, and the extensions that matter for a low-latency bridge |
| [docs/spice-protocol.md](docs/spice-protocol.md) | SPICE channels, link handshake, the display command stream, and why this backend is the optional one |
| [docs/bridging-design.md](docs/bridging-design.md) | Where the protocols meet: the frame-clock problem, the encode pipeline, input translation, latency budget, build order |
| [docs/security.md](docs/security.md) | Threat analysis of all three protocols and of the bridge itself, with a direct answer on internet exposure |
| [docs/testing.md](docs/testing.md) | How to test and mock this: tiers, a headless Moonlight client, one QEMU guest serving both backends, loss injection, and what is deliberately not covered |
| [docs/implementation-notes.md](docs/implementation-notes.md) | **What building it settled**: which research claims held, which were wrong, and what the benchmarks say |
| [docs/roadmap.md](docs/roadmap.md) | **The work that is not done**, in enough detail to start on: why, what exactly, where it plugs in, and the tests that finish it |
| [PROJECT-LAYOUT.md](PROJECT-LAYOUT.md) | The Cargo workspace as built, crate responsibilities, feature flags, and where each piece of the protocol lives |

---

## Status

### Working

- **NVHTTP** on both listeners, with the documented split: `/serverinfo` and
  `/pair` in the clear, everything else behind mutual TLS and a paired client
  certificate. The real MAC is disclosed only over TLS.
- **PIN pairing**, all four phases, as a strict linear type — one owner, one
  transition per request, nothing persisted until step ④ verifies, session
  destroyed on any deviation. The three CVEs in Sunshine's version of this
  state machine each have a named negative test.
- **`solstice pair`, `status`, `list-clients` and `revoke`** against the
  running daemon, over a Unix socket rather than a web UI. A revocation takes
  effect in the daemon at once, not at its next restart, and ends a stream
  that client already has running.
- **RTSP**, plaintext and AES-GCM wrapped, with the ANNOUNCE attribute parser
  and server-side clamping of everything the client asks for.
- **The video path**: a synthetic frame clock that slows to a keep-alive rate
  on a still screen, BGRA→I420 conversion (whole-frame,
  per-damaged-rectangle, or letterboxed when the backend will not resize),
  H.264 encoding with keyframes on demand (libx264, or OpenH264 in a build
  without it), the `NV_VIDEO_PACKET` packetiser,
  Reed–Solomon FEC that matches `nanors` byte-for-byte, and AES-GCM shard
  encryption.
- **Audio**: the backend's Opus passed through when the client asked for what
  the backend sends, and otherwise decoded and re-encoded with libopus into the
  client's own layout and packet duration — stereo, 5.1 or 7.1, normal or high
  quality — behind a small jitter buffer, with encoded silence when there is
  nothing to play. Then RTP, AES-CBC, and the fixed RS(4,2) parity pair every
  four packets using Nvidia's matrix.
- **The control channel**: ENet -- the subset Moonlight uses, implemented here
  rather than linked, with no fragment reassembly and nothing answered before
  the launch's connect data is presented -- then the GCM envelope with a replay
  window, and the `0x0206` input batch decoder.
- **Input translation**: Windows VK → XT scancode as the primary path, X11
  keysym as the fallback, chosen per connection from what the peer supports.
- **The VNC backend**: RFB 3.3–3.8, `None` / VNC Authentication / VeNCrypt with
  real certificate verification, Raw / CopyRect / RRE / Hextile / ZRLE,
  ContinuousUpdates and Fence where offered, ExtendedDesktopSize resize
  requests, both keyboard paths, and the server's cursor, drawn where the
  client points.
- **The SPICE backend**: the per-channel link handshake with its RSA-OAEP
  ticket, TLS, both message framings and the ack window; a 2D rasteriser with
  binary and ternary raster operations, clip regions, stencil masks, brushes,
  scaled blits, strokes and raster glyphs; every image type SPICE defines —
  raw in all eleven layouts, QUIC, LZ, GLZ, zlib-over-GLZ, JPEG, JPEG+alpha
  and LZ4; MJPEG video streams composited over the draw output; the cursor
  channel; `spice-vdagent` for exact-resolution resize, absolute mouse and
  the by-demand clipboard; and guest audio, heard by the real Moonlight
  client both passed through and re-encoded.

### Not implemented

Each of these is written up in [docs/roadmap.md](docs/roadmap.md) with a plan,
the tests that would finish it, and what is already known to be hard. The
summaries below are just the shape of it.

- **A clipboard route to Moonlight.** The SPICE side is finished and runs
  both directions against a real `spice-vdagent` — a `SpiceSession` offers,
  requests, sends and declines, and the guest's own grabs and requests arrive
  as events. What is missing is a sink: GameStream has no clipboard channel,
  so nothing carries it to the client, and the API is therefore SPICE's own
  rather than part of the backend seam.
  [Why](docs/roadmap.md#25-what-is-deliberately-not-implemented).
- **`DRAW_COMPOSITE`, GL scanout, and two cursor types** on the SPICE side.
  Each is a deliberate omission rather than a gap, and the capability is not
  advertised in any of the three cases, so a conforming server will not send
  them. [The list](docs/roadmap.md#25-what-is-deliberately-not-implemented).
- **Tight's JPEG sub-encoding** on the RFB side. Tight itself is decoded and
  preferred, lossless-only: a JPEG hop in front of an H.264 encoder is a
  quality regression, so no quality level is advertised and a conforming
  server sends none. [Why](docs/roadmap.md#1-tight-encoding-rfb).
- **Controllers, touch and pen.** Neither backend protocol has any notion of
  them. They are dropped — and *counted*, because quietly swallowing input is
  the kind of thing that generates bug reports.
- **HEVC and AV1.** `ServerCodecModeSupport` advertises H.264 only, and the
  DESCRIBE omits the two markers a client reads as "HEVC" and "AV1".
- **Streaming two endpoints at once.** One stream at a time: every stream
  binds the same fixed UDP ports.
- **mDNS discovery.** Moonlight accepts a manually typed host.
- **Hardware encoders.** The `VideoEncoder` trait is the seam; VAAPI and NVENC
  would arrive behind an `ffmpeg` feature. Licence-compatible — Solstice is
  GPL-3.0-or-later — but a large native dependency, so it stays opt-in. Neither
  is automatic in FFmpeg either: each is opened by name and needs its own
  device setup and driver (`docs/roadmap.md` §8).

---

## The short version

**It is buildable, and the protocol work was not the hard part.** Serving
GameStream is a few thousand lines of well-understood plumbing: an XML HTTP
API, a PIN handshake, a non-standard RTSP dialect, three UDP channels and an
ENet control stream.

**The hard part is that there is no video to forward.** VNC delivers dirty
rectangles; SPICE delivers 2D drawing commands. Moonlight expects a continuous
H.264 stream with a frame clock. Solstice composites the backend's output into
a framebuffer and encodes it itself, in real time, with a synthetic frame clock
and on-demand keyframes. That is a video-engineering problem wearing a
networking problem's clothes, and it is where the latency and the CPU go.

**Do not expose this to the internet.** GameStream pairing is gated by a
**four-digit PIN** protected by AES-ECB over plaintext HTTP; VNC's standard
authentication is DES with an 8-character key; SPICE's is RSA-1024 with SHA-1.
Sunshine — the mature implementation of the host half — has had two
authentication bypasses, an out-of-bounds heap write and an unauthenticated DoS
published in the last two years, all in the code a reimplementation has to
write. Solstice makes video and audio encryption **mandatory by default**,
where Sunshine's default is "never on a LAN", and it binds to loopback out of
the box. Neither of those is a substitute for a VPN. Put Solstice behind
WireGuard or Tailscale. [docs/security.md](docs/security.md) gives the full
analysis and, if exposure is unavoidable anyway, what hardening it would
require.

---

## Testing

The strategy is in [docs/testing.md](docs/testing.md); what exists today:

| Tier | What | Where |
|---|---|---|
| T0 | Unit and property tests on pure functions | throughout; 381 total |
| T1 | **Differential FEC vectors against the real `nanors`** | `tests/vectors/fec/`, `crates/solstice-gamestream/tests/fec_vectors.rs` |
| T1 | **A real Moonlight session, captured and replayed**: the client's RTSP, pings and control messages decoded, the host's responses and packets reproduced byte for byte | `tests/vectors/capture/`, `crates/solstice-gamestream/tests/capture_vectors.rs` |
| T2 | The RFB client against a deliberately minimal recording mock server | `crates/solstice-vnc/tests/mock_server.rs` |
| T3 | The RFB client against **QEMU's RFB server**, on the same guest the SPICE tests use — skipped with a note when QEMU or the guest image is absent | `crates/solstice-vnc/tests/real_server.rs` |
| T3 | **The whole stack end to end**: pair, launch, RTSP, decrypt, reassemble, decode H.264 — twice, once against the colour-bar generator reading the frame counter off the picture, and once against a real guest desktop checking the pixels are the colour it was painted | `crates/solstice/tests/end_to_end.rs` |
| T3 | **`solstice pair` and `revoke` as a second process**: the real binary opens a window on a running daemon, a client pairs through it, and a revocation takes effect in the daemon's memory | `crates/solstice/tests/management.rs` |
| T5 | Ten `cargo-fuzz` targets over the parsers the CVEs lived in, four of them seeded from the captured session; `tests/tools/fuzz.sh` runs them all on stable | `fuzz/fuzz_targets/`, `fuzz/seeds/` |

Two `#[ignore]`d benchmarks measure where the CPU goes --
`solstice-vnc`'s `encoding_bench` for the backend decoders and
`solstice-video`'s `encode_cost` for the convert-and-encode path. The short
version: the H.264 encoder costs two to six times what the RFB decoder does, so
the backend encoding is not where the performance is.
`docs/implementation-notes.md` §3 has the numbers.

Both poles of the RFB testing earned their keep: the fuzzer found an integer
underflow in the ZRLE palette-RLE path reachable from any server, and a real
server found a livelock the mock could not — it sends an ExtendedDesktopSize
rectangle on every full update, which the client was treating as a resize. `docs/implementation-notes.md` §1 has both.

The FEC vectors are the ones worth explaining. Moonlight's Reed–Solomon must
match `nanors` byte-for-byte or recovery silently corrupts video under packet
loss. `tests/vectors/fec/dump.c` links the real C implementation and prints its
parity matrix and output; `tests/tools/gen_fec_vectors.py` runs that against an
independent reimplementation, requires them to agree, and freezes the result so
CI needs neither a C toolchain nor a network.

What is not automated, and why, is in `docs/testing.md` §8 — GUI clients,
subjective quality, real network conditions, hardware encoders, long-running
stability. A release gate still needs a human with a real client.

---

## Licence

**GPL-3.0-or-later.** The full text is in [LICENSE](LICENSE).

`deny.toml` enforces that dependency licences stay compatible. libx264 is
GPL-2.0-or-later, which a GPL-3.0-or-later project can link. `ffmpeg-sys-next`
is banned there on dependency-weight grounds rather than licence grounds: it
belongs behind the `ffmpeg` feature, for the hardware encoders, when that
exists.

---

## Research provenance

Read at **2026-10-15**, since none of these protocols has a usable public
specification:

- [`moonlight-stream/moonlight-common-c`](https://github.com/moonlight-stream/moonlight-common-c) — client core; authoritative for what a client sends and expects
- [`LizardByte/Sunshine`](https://github.com/LizardByte/Sunshine) — the de-facto host; authoritative for what a host must produce
- [`moonlight-stream/moonlight-qt`](https://github.com/moonlight-stream/moonlight-qt) — TLS pinning behaviour
- [`rfbproto/rfbproto`](https://github.com/rfbproto/rfbproto) — the living RFB spec, plus RFC 6143
- [`spice/spice-protocol`](https://gitlab.freedesktop.org/spice/spice-protocol) — canonical SPICE wire headers
- [`spice/spice-common`](https://gitlab.freedesktop.org/spice/spice-common) — `spice.proto`, the authoritative description of every SPICE message layout, plus the raster-operation mapping in `canvas_base.c` and `rop3.c`
- [`spice/spice-gtk`](https://gitlab.freedesktop.org/spice/spice-gtk) — the reference client, for the behaviour the wire format does not determine
- [`sleepybishop/nanors`](https://github.com/sleepybishop/nanors) — the client's Reed–Solomon implementation, now also the FEC oracle
- [Sunshine security advisories](https://github.com/LizardByte/Sunshine/security)

File and line references throughout the docs point into those trees at that
date. Nothing in the protocol docs is inferred from third-party guides, which
were checked and found to disagree with the source on basic facts such as
which UDP port carries which stream.
