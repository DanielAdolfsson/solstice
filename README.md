# Solstice

A proxy that lets a **Moonlight** client connect to a **VNC** or **SPICE**
desktop. Moonlight speaks to Solstice as if it were a GameStream host;
Solstice speaks to the remote desktop as a VNC or SPICE client, and bridges
the two.

```
Moonlight ──GameStream──▶ Solstice ──RFB / SPICE──▶ remote desktop
```

**Status: it works end to end.** A Moonlight-shaped client can pair, launch,
negotiate encrypted RTSP, and receive an encrypted, FEC-protected H.264 stream
of a real VNC desktop, which decodes to the right pixels. That path is a test
(`a_client_receives_the_pixels_of_a_real_vnc_desktop`), not a claim. SPICE is not implemented.
See [Status](#status) for the full picture, including what is deliberately
absent.

---

## Build and test

Needs a stable Rust toolchain and a C compiler (OpenH264 is built from vendored
source). No cmake, no nasm, no system libraries.

```sh
cargo build --release
cargo test --workspace        # 381 tests, about 15 s
cargo clippy --workspace --all-targets
```

The default features are `vnc` and `openh264`. SPICE is excludable at compile
time along with its dependency tree, and so is the encoder:

```sh
cargo build --no-default-features --features vnc      # no H.264 encoder
```

### Running it

```sh
cp contrib/solstice.example.toml /etc/solstice/solstice.toml
solstice --config /etc/solstice/solstice.toml run
```

The shipped defaults are the deployment `docs/security.md` recommends: bound to
loopback, pairing closed, encryption mandatory, one session, and a ceiling on
every resolution, rate and bitrate the client can ask for. The default backend
is the built-in colour-bar generator, so the host half can be brought up and
pointed at a client before any desktop is involved.

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
| [docs/testing.md](docs/testing.md) | How to test and mock this: tiers, a headless Moonlight client, `Xvnc` and `Xspice` as the only real servers needed, loss injection, and what is deliberately not covered |
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
- **RTSP**, plaintext and AES-GCM wrapped, with the ANNOUNCE attribute parser
  and server-side clamping of everything the client asks for.
- **The video path**: synthetic frame clock, BGRA→I420 conversion (whole-frame,
  per-damaged-rectangle, or letterboxed when the backend will not resize),
  OpenH264 encoding with keyframes on demand, the `NV_VIDEO_PACKET` packetiser,
  Reed–Solomon FEC that matches `nanors` byte-for-byte, and AES-GCM shard
  encryption.
- **Audio**: Opus silence at the negotiated packet duration, RTP, AES-CBC, and
  the fixed RS(4,2) parity pair every four packets using Nvidia's matrix.
- **The control channel**: ENet, the GCM envelope with a replay window, and the
  `0x0206` input batch decoder.
- **Input translation**: Windows VK → XT scancode as the primary path, X11
  keysym as the fallback, chosen per connection from what the peer supports.
- **The VNC backend**: RFB 3.3–3.8, `None` / VNC Authentication / VeNCrypt with
  real certificate verification, Raw / CopyRect / RRE / Hextile / ZRLE,
  ContinuousUpdates and Fence where offered, ExtendedDesktopSize resize
  requests, and both keyboard paths.

### Not implemented

Each of these is written up in [docs/roadmap.md](docs/roadmap.md) with a plan,
the tests that would finish it, and what is already known to be hard. The
summaries below are just the shape of it.

- **SPICE.** Feature-gated and deferred, as the research recommended: its image
  codecs — QUIC and GLZ — have no Rust implementations and GLZ is stateful
  across images, so the backend needs an FFI binding to `spice-common` or a
  port of its decoders. `backend.kind = "spice"` reports this rather than
  failing obscurely. [Staged plan](docs/roadmap.md#2-spice-backend), M1–M7.
- **Tight encoding** on the RFB side. Solstice does not advertise it, so a
  conforming server will not send it; a server that sends it anyway gets an
  error rather than a guess. ZRLE covers the same ground.
  [Plan](docs/roadmap.md#1-tight-encoding-rfb) — and note it should be
  implemented lossless-only, since a JPEG hop in front of an H.264 encoder is a
  quality regression.
- **`solstice pair`** needs a management socket to reach the running daemon.
  The pairing state machine and its window/lockout policy are complete and
  tested; only the IPC is missing. Until then the command says so instead of
  appearing to work.
- **Controllers, touch and pen.** Neither backend protocol has any notion of
  them. They are dropped — and *counted*, because quietly swallowing input is
  the kind of thing that generates bug reports.
- **HEVC and AV1.** `ServerCodecModeSupport` advertises H.264 only, and the
  DESCRIBE omits the two markers a client reads as "HEVC" and "AV1".
- **mDNS discovery.** Moonlight accepts a manually typed host.
- **Hardware encoders.** The `VideoEncoder` trait is the seam; VAAPI and NVENC
  would arrive behind an `ffmpeg` feature. Licence-compatible — Solstice is
  GPL-3.0-or-later — but a large native dependency, so it stays opt-in.

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
| T2 | The RFB client against a deliberately minimal recording mock server | `crates/solstice-vnc/tests/mock_server.rs` |
| T3 | The RFB client against **TigerVNC's `Xvnc`**, the feature-rich pole — skipped with a note when it is not installed | `crates/solstice-vnc/tests/real_server.rs` |
| T3 | **The whole stack end to end**: pair, launch, RTSP, decrypt, reassemble, decode H.264 — twice, once against the colour-bar generator reading the frame counter off the picture, and once against a real `Xvnc` desktop checking the pixels are the colour it was painted | `crates/solstice/tests/end_to_end.rs` |
| T5 | Five `cargo-fuzz` targets over the parsers the CVEs lived in | `fuzz/fuzz_targets/` |

Two `#[ignore]`d benchmarks measure where the CPU goes --
`solstice-vnc`'s `encoding_bench` for the backend decoders and
`solstice-video`'s `encode_cost` for the convert-and-encode path. The short
version: the H.264 encoder costs two to six times what the RFB decoder does, so
the backend encoding is not where the performance is.
`docs/implementation-notes.md` §3 has the numbers.

Both poles of the RFB testing earned their keep: the fuzzer found an integer
underflow in the ZRLE palette-RLE path reachable from any server, and the real
server found a livelock the mock could not — `Xvnc` sends an
ExtendedDesktopSize rectangle on every full update, which the client was
treating as a resize. `docs/implementation-notes.md` §1 has both.

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

`deny.toml` enforces that dependency licences stay compatible. `ffmpeg-sys-next`
and `x264` are banned there on dependency-weight grounds rather than licence
grounds — under GPL-3 they would be compatible, but they belong behind the
`ffmpeg` feature when it exists.

---

## Research provenance

Read at **2026-10-15**, since none of these protocols has a usable public
specification:

- [`moonlight-stream/moonlight-common-c`](https://github.com/moonlight-stream/moonlight-common-c) — client core; authoritative for what a client sends and expects
- [`LizardByte/Sunshine`](https://github.com/LizardByte/Sunshine) — the de-facto host; authoritative for what a host must produce
- [`moonlight-stream/moonlight-qt`](https://github.com/moonlight-stream/moonlight-qt) — TLS pinning behaviour
- [`rfbproto/rfbproto`](https://github.com/rfbproto/rfbproto) — the living RFB spec, plus RFC 6143
- [`spice/spice-protocol`](https://gitlab.freedesktop.org/spice/spice-protocol) — canonical SPICE wire headers
- [`sleepybishop/nanors`](https://github.com/sleepybishop/nanors) — the client's Reed–Solomon implementation, now also the FEC oracle
- [Sunshine security advisories](https://github.com/LizardByte/Sunshine/security)

File and line references throughout the docs point into those trees at that
date. Nothing in the protocol docs is inferred from third-party guides, which
were checked and found to disagree with the source on basic facts such as
which UDP port carries which stream.
