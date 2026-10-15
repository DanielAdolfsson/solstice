# The Rust project layout

**This describes what is built.** It started as a proposal derived from the
protocol research in `docs/` — in particular the backend abstraction sketched
in `docs/bridging-design.md` §6 — and the structure survived contact with the
implementation almost unchanged. Where it did not, the deviation is marked
**▲** and explained; `docs/implementation-notes.md` has the reasoning.

About 19 000 lines of Rust across six crates, roughly half of it tests.

Design constraints this layout satisfies:

- SPICE is **optional** and must be excludable at compile time, along with its
  dependency tree.
- The GameStream host side is one tightly-coupled state machine and should not
  be split across crates just for tidiness.
- The parsers that handle untrusted bytes should be reachable from `cargo
  fuzz` without dragging in a video encoder.
- Encoder choice (OpenH264 / FFmpeg / VAAPI) must be a feature flag, never a
  transitive default. ▲ The original reason was licensing — the project was
  MIT/Apache and a GPL encoder would have propagated. **Solstice is now
  GPL-3.0-or-later**, so that argument is gone and the constraint survives on
  its own merits: a video encoder is a large native dependency and the parsers
  that handle untrusted bytes should be reachable from `cargo fuzz` without
  dragging one in.

---

## 1. Tree

```
solstice/
├── Cargo.toml                    # workspace root; `fuzz/` is excluded
├── Cargo.lock
├── rust-toolchain.toml
├── deny.toml                     # cargo-deny: licence policy matters here
├── README.md
├── docs/
│   ├── moonlight-sunshine-protocol.md
│   ├── rfb-vnc-protocol.md
│   ├── spice-protocol.md
│   ├── bridging-design.md
│   ├── security.md
│   ├── testing.md
│   ├── implementation-notes.md   # ▲ what building it settled
│   └── roadmap.md                # ▲ what is not done, and how to start
├── crates/
│   ├── solstice/                 # [bin+lib] the daemon
│   ├── solstice-gamestream/      # [lib] the host half: everything Moonlight talks to
│   ├── solstice-backend/         # [lib] backend trait + neutral types. No I/O.
│   ├── solstice-vnc/             # [lib] RFB backend, plus the recording mock server
│   ├── solstice-video/           # [lib] colour conversion + encoder abstraction
│   └── solstice-input/           # [lib] VK → scancode / keysym tables. Pure data.
├── fuzz/                         # cargo-fuzz targets, its own workspace
│   └── fuzz_targets/
│       ├── rtsp_message.rs
│       ├── sdp_announce.rs
│       ├── input_batch.rs
│       ├── control_envelope.rs
│       └── rfb_rect.rs
├── tests/
│   ├── vectors/fec/              # nanors oracle (dump.c), its checker, frozen JSON
│   └── tools/
│       └── gen_fec_vectors.py    # runs the oracle, freezes the vectors
└── contrib/
    ├── solstice.service          # hardened systemd unit
    └── solstice.example.toml
```

▲ The integration tests live beside the crates they exercise rather than in a
top-level `tests/` tree, because Cargo already gives each crate a `tests/`
directory with the crate in scope:

| Test | Where |
|---|---|
| FEC differential vectors | `crates/solstice-gamestream/tests/fec_vectors.rs` |
| RFB client vs. the minimal mock server | `crates/solstice-vnc/tests/mock_server.rs` |
| RFB client vs. TigerVNC's `Xvnc` | `crates/solstice-vnc/tests/real_server.rs` |
| The whole stack, end to end, twice | `crates/solstice/tests/end_to_end.rs` |

▲ The mock RFB server is `solstice-vnc`'s `mock` module rather than a separate
`tests/mocks/` crate. It needs the same message definitions the client does,
and duplicating them is how a mock drifts into agreeing with a bug.

---

## 2. Crates

### `solstice` — the binary

Wiring only: CLI, config loading, logging, signal handling, session supervision.
No protocol logic. Keeping this thin means every piece below is testable
without starting a daemon.

```
src/
├── main.rs
├── lib.rs            # ▲ also a library, so the end-to-end test can start it
├── cli.rs            # clap: run, pair, list-clients, revoke
├── config.rs         # serde + toml; see §5
├── supervisor.rs     # session lifecycle, resource ceilings, shutdown
├── pipeline.rs       # ▲ the frame loop: framebuffer → convert → encode → packetise
├── testpattern.rs    # ▲ the colour-bar backend, for milestone 1 and the tests
├── tls.rs            # ▲ the mutual-TLS listener's client-certificate policy
├── backend_factory.rs# config → Arc<dyn Backend>, where the feature flags land
└── net/
    ├── nvhttp.rs     # the two HTTP listeners
    ├── rtsp.rs       # TCP 48010, plaintext and GCM-wrapped
    ├── media.rs      # UDP peer binding and paced sending
    └── control.rs    # the ENet host thread
```

▲ `config.rs` uses plain `serde` + `toml` rather than `figment`: there is one
file and no layering, and `deny_unknown_fields` turns a typo into a startup
error instead of a silently ignored setting.

### `solstice-gamestream` — the host half

The largest crate, and deliberately one crate: pairing state, launch session,
RTSP negotiation and the three media channels all share session state and
splitting them would mean publishing that state as an API.

```
src/
├── lib.rs
├── wire/                 # packed structs + encode/decode. No I/O, no async.
│   ├── mod.rs
│   ├── rtp.rs            # RTP_PACKET
│   ├── video.rs          # NV_VIDEO_PACKET, video_short_frame_header_t, enc prefix
│   ├── audio.rs          # AUDIO_FEC_HEADER
│   ├── control.rs        # NVCTL_* headers, packet type tables
│   ├── input.rs          # NV_*_PACKET, the 0x0206 batch decoder
│   └── ping.rs           # SS_PING
├── crypto/
│   ├── mod.rs
│   ├── pairing.rs        # SHA256(salt‖pin) → AES-128-ECB handshake
│   ├── gcm.rs            # deterministic IV construction, per NIST SP 800-38D
│   └── certs.rs          # self-signed host cert, client cert store, DER compare
├── nvhttp/
│   ├── mod.rs            # the two listeners (plaintext + mutual TLS)
│   ├── serverinfo.rs
│   ├── pair.rs           # the four-phase state machine — see security.md §1.3
│   ├── applist.rs
│   └── launch.rs         # rikey/rikeyid → session keys
├── rtsp/
│   ├── mod.rs
│   ├── message.rs        # the non-RFC parser; fuzz target
│   ├── sdp.rs            # DESCRIBE generation, ANNOUNCE attribute parsing
│   └── encrypted.rs      # the 24-byte GCM envelope
├── stream/
│   ├── mod.rs
│   ├── video_tx.rs       # packetise, FEC, encrypt, pace
│   ├── audio_tx.rs       # Opus → RTP, RS(4,2), AES-CBC
│   ├── control.rs        # ENet host, GCM envelope, message dispatch
│   └── fec.rs            # see §4 on the compatibility hazard
└── session.rs            # ▲ in nvhttp/: launch sessions are minted there
```

▲ `wire/` grew a `Reader`: a bounds-checked forward cursor that every decoder
uses and nothing bypasses. That is what makes "cannot over-read" a property of
the module rather than of each function, and it is why the fuzz targets are
short.

`wire/` is the fuzzing surface and must stay `no_std`-shaped: slices in, types
out, no allocation where avoidable, no async.

### `solstice-backend` — the seam

Traits and neutral types, no dependencies beyond `tokio` and `bytes`. Both
backends and the video pipeline depend on this; nothing depends on both
backends.

```
src/
├── lib.rs
├── backend.rs        # trait Backend, trait Session
├── framebuffer.rs    # FramebufferHandle, PixelFormat, Rect
├── damage.rs         # DamageEvent
├── input.rs          # InputEvent — scancode-first, optional keysym
└── audio.rs          # AudioFrame, AudioFormat
```

The input type should carry a scancode with an optional keysym alongside, so
the lossy keysym conversion stays inside `solstice-vnc` rather than in shared
code (`docs/bridging-design.md` §4.1).

### `solstice-vnc` — RFB backend

```
src/
├── lib.rs
├── handshake.rs      # version, security type, VeNCrypt
├── auth.rs           # None / VNC Auth / VeNCrypt — with the policy from security.md §4.1
├── session.rs        # the update loop; ContinuousUpdates + Fence when available
├── encodings/        # Raw, CopyRect, Hextile, ZRLE, Tight
├── pixel.rs          # PIXEL_FORMAT → BGRA blit
└── input.rs          # InputEvent → KeyEvent / QEMU ext key / PointerEvent
```

**Decided: implemented directly.** `vnc-rs` would have saved the encoding
decoders, but all three things a bridge needs — control over the update loop,
direct framebuffer access, and the `ContinuousUpdates`/`Fence`
pseudo-encodings — are the three things client crates hide. The decoders came
to about 700 lines including their tests, which is less than a fork would have
cost to maintain.

▲ `encodings/` has Raw, CopyRect, RRE, Hextile and ZRLE. **Tight is absent**
and is not advertised, so a conforming server will not send it; one that does
gets an error rather than a guess. ZRLE covers the same servers.

▲ `mock.rs` is the deliberately minimal recording server from
`docs/testing.md` §3.2: Raw only, no flow control, no -258, and it records
every client message so input is asserted on exactly rather than observed on a
live desktop.

### `solstice-spice` — SPICE backend (optional)

```
src/
├── lib.rs
├── link.rs           # SpiceLinkHeader/Mess/Reply, caps, RSA-OAEP ticket
├── channels/
│   ├── main.rs       # session setup, mouse mode, the vdagent tunnel
│   ├── display.rs    # draw commands + surfaces + video streams → framebuffer
│   ├── inputs.rs
│   ├── cursor.rs
│   └── playback.rs   # Opus; possible repacketise path
├── images/           # QUIC, LZ, GLZ, LZ4, JPEG — the gating item
└── agent.rs          # MONITORS_CONFIG, clipboard
```

Gated behind `--features spice`, off by default. `images/` is the reason: QUIC
and GLZ have no Rust implementations and GLZ is stateful across images
(`docs/spice-protocol.md` §5.1). Expect to FFI `spice-common` or port its
decoders.

### `solstice-video` — encode path

```
src/
├── lib.rs
├── convert.rs        # BGRA → NV12, incremental per damaged rect
├── encoder.rs        # trait VideoEncoder { encode(frame, force_idr) -> AnnexB }
├── openh264.rs       # #[cfg(feature = "openh264")]
├── null.rs           # ▲ a deterministic non-encoder, for testing the plumbing
├── frame.rs          # ▲ the I420 frame the encoder consumes
├── testsrc.rs        # ▲ colour bars and the barcode pattern
└── clock.rs          # the synthetic frame clock, damage-aware
```

▲ `convert.rs` produces **I420, not NV12**. NV12 is what hardware encoders
want; OpenH264 takes three planes, and a VAAPI backend would carry its own
conversion. It has three entry points: whole-frame, per-damaged-rectangle, and
letterboxed-with-scaling for when the backend declines to resize.

▲ `ffmpeg.rs` is not written. The `VideoEncoder` trait is the seam it would
plug into, and the licensing decision in §4 is unchanged.

### `solstice-input` — tables

Pure data, no dependencies, exhaustively unit-tested:

```
src/
├── lib.rs
├── vk.rs             # Windows VK constants
├── scancode.rs       # VK + EXTENDED flag → XT scancode (the primary path)
└── keysym.rs         # VK → X11 keysym (RFB fallback)
```

---

## 3. Dependency graph

```
                      solstice (bin)
                     /      |       \
     solstice-gamestream    |        backend_factory
            |               |          /          \
     solstice-video         |   solstice-vnc   solstice-spice
            \               |        /              /
             `------ solstice-backend -------------'
                            |
                     solstice-input
```

No cycles; neither backend is reachable from `solstice-gamestream`.

---

## 4. Dependencies

> **▲ The versions below are wrong.** They were "checked 2026-10-15" but
> several do not exist — the RustCrypto numbers are each one minor version
> ahead of reality. `docs/implementation-notes.md` §2 has the table of what
> actually resolves. Read this section as a list of *which* crates, not which
> versions; `Cargo.toml` is authoritative.
>
> One addition that is not a version: everything selects the **`ring`** crypto
> backend rather than the default `aws-lc-rs`, whose build needs `cmake`. The
> cost is nothing this project uses.

### Shared

| Crate | Version | Use |
|---|---|---|
| `tokio` | 1.53 | runtime, TCP/UDP, tasks |
| `bytes` | 1.12 | buffer management |
| `tracing` | 0.1 | structured logging |
| `thiserror` | 2.0 | error types |
| `serde` | 1.0 | config |
| `zerocopy` | 0.8 | safe reinterpretation of packed wire structs |

### `solstice-gamestream`

| Crate | Version | Use |
|---|---|---|
| `rustls` + `tokio-rustls` | 0.23 / 0.26 | TLS with client-cert requirement |
| `rcgen` | 0.14 | self-signed host certificate |
| `x509-parser` | 0.18 | client cert parsing; extract the signature for pairing |
| `rustls-pemfile` | 2.2 | cert store I/O |
| `sha2` | 0.11 | pairing hashes |
| `aes` | 0.9 | AES-128-ECB (pairing) |
| `aes-gcm` | 0.11 | control, RTSP, video encryption |
| `cbc` | 0.2 | audio encryption |
| `zeroize` | 1.9 | key material |
| `rusty_enet` | 0.4 | ENet control channel |
| `quick-xml` | 0.42 | NVHTTP XML responses |
| `hyper` / `axum` | 1.12 / 0.8 | the HTTP listeners |
| `socket2` | 0.6 | UDP socket options, DSCP, batched send |
| `opus` | 0.4 | silence generation / transcode |

> `rusty_enet` is a C-to-Rust transpilation of ENet 1.3.18. Its own README is
> candid that it "couldn't be much further from ready for serious use". Since
> it sits on the **pre-authentication** UDP path (`docs/security.md` §2.4),
> audit it, fuzz it, and be prepared to implement the subset of ENet that
> Moonlight actually uses.

### `solstice-video`

| Crate | Version | Use | Licence note |
|---|---|---|---|
| `openh264` | 0.9 | default software encoder | BSD-2; Cisco binary-grant model for patents |

> OpenH264's README documents **Constrained Baseline only** for the encoder,
> but High profile encoding was added in later releases (FFmpeg's wrapper
> accepts `high` for libopenh264 ≥ 1.8, switching CAVLC→CABAC) and the
> documentation was never updated. Moonlight advertises `VIDEO_FORMAT_H264` as
> *High Profile*; a Constrained Baseline stream should still decode, since High
> is a superset, but this needs confirming against a real client early — it is
> cheap to test and expensive to discover late.

| `ffmpeg-next` | 9.0 | optional: libx264, VAAPI, NVENC, QSV | usually GPL — ▲ compatible now that the project is GPL-3.0-or-later, but still a heavy native dependency |
| `dcv-color-primitives` | 1.0 | BGRA → NV12, SIMD | |
| `yuvutils-rs` | 0.8 | alternative colour conversion | |

### `solstice-vnc`

| Crate | Version | Use |
|---|---|---|
| `vnc-rs` | 0.6 | candidate RFB client; evaluate vs. implementing directly |
| `flate2` | 1.1 | zlib for Tight / ZRLE / zlibhex |
| `turbojpeg` | 1.5 | Tight's JPEG sub-encoding |
| `des` | — | only if VNC Authentication is supported at all |

### `solstice-spice` (optional)

| Crate | Version | Use |
|---|---|---|
| `spice-client` | 0.2 | evaluate — small and young; see `docs/spice-protocol.md` §8 |
| `rsa` | 0.9 | RSA-OAEP ticket |
| `image` | 0.25 | JPEG/PNG images on the display channel |

### FEC — a decision, not a dependency

`reed-solomon-simd` (3.1) and `reed-solomon-erasure` (6.0) are both well
maintained and **neither interoperates with Moonlight** — the first is
FFT-based over GF(2^16), the second Vandermonde-based. But this is not a
dependency problem: `nanors`' matrix is a closed-form Cauchy construction over
GF(2^8) with polynomial 0x11D, verified byte-exact in
`docs/moonlight-sunshine-protocol.md` §5.4. Implement it directly in
`solstice-gamestream/stream/fec.rs` — roughly 50 lines plus a GF table.

Two separate codes are needed:

1. **Video** — the Cauchy closed form, parameterised by `(ds, ps)`.
2. **Audio** — fixed RS(4,2) with Nvidia's hard-coded 8-byte matrix. *Not* the
   same construction; `nanors` would produce different parity for the same
   shape.

Validate against a compiled `nanors` (`tests/vectors/fec/`) and, end-to-end,
against `moonlight-common-c` built with `FEC_VALIDATION_MODE` — see
`docs/testing.md` §2.2.

---

## 5. Features

```toml
[features]
default  = ["vnc", "openh264"]
vnc      = ["dep:solstice-vnc"]
openh264 = ["solstice-video/openh264"]
# SPICE is excludable along with its dependency tree; the backend is not
# implemented, and the flag exists so that stays true when it is.
spice    = []
```

▲ `ffmpeg`, `vaapi`, `hevc` and `av1` are not declared. A feature flag that
selects nothing is a promise the build cannot keep; they go in with the code
behind them.

▲ **The licence policy changed with the project's own licence.** This section
used to say *"`cargo-deny` should fail the build when a GPL dependency appears
without the `ffmpeg` feature"*. Under GPL-3.0-or-later a GPL dependency is
compatible, so that check would be enforcing nothing. `deny.toml` now allows
GPL-3 and LGPL alongside the permissive licences, and keeps `ffmpeg-sys-next`
and `x264` banned on dependency-weight grounds instead — they belong behind the
`ffmpeg` feature, and the ban is what makes adding them a decision rather than
an accident.

---

## 6. Configuration sketch

```toml
[server]
name         = "solstice"
bind         = "127.0.0.1"      # see docs/security.md — not 0.0.0.0
port         = 47989            # base; offsets per the protocol doc
state_dir    = "/var/lib/solstice"

[security]
require_encryption = true       # SS_ENC_VIDEO | SS_ENC_AUDIO mandatory
pairing_enabled    = false      # opened by `solstice pair`, time-boxed
pairing_window     = "60s"   # the PIN is 4 digits and client-chosen, so
max_pair_attempts  = 3       # the window and the lockout are the real control
allow_pairing_from = ["192.168.0.0/16"]

[limits]
max_sessions   = 1
max_width      = 1920
max_height     = 1080
max_fps        = 60
max_bitrate_kbps = 20000

[video]
encoder   = "openh264"
codecs    = ["h264"]
fec_percentage = 0

[backend]
kind = "vnc"

[backend.vnc]
host     = "127.0.0.1"
port     = 5900
security = "vencrypt"           # refuse "none"/"vncauth" off-loopback
ca_file  = "/etc/solstice/vnc-ca.pem"

# [backend.spice]
# host = "127.0.0.1"
# port = 5900
# tls  = true
```

---

## 7. Testing

381 tests, about 15 seconds. What exists against what was planned:

| Layer | Planned | Built |
|---|---|---|
| `wire/` codecs | round-trip property tests; golden vectors from a captured session | round-trip tests ✓; **no captured session** (§8.7) |
| FEC | differential against a compiled `nanors` | ✓ — the oracle is built from `tests/vectors/fec/dump.c` and the output frozen as JSON |
| Pairing | four-phase handshake against a mock client, with negative tests for every out-of-order and replayed transition | ✓ — each of the three CVEs has a named test |
| RTSP | recorded Moonlight transcripts replayed | the full documented sequence is replayed against the state machine; the transcripts are ours, not captured |
| Packetiser | feed Annex-B, reassemble with a port of the client's depacketiser, assert byte equality | ✓ — including shard loss recovered from parity, which is the `FEC_VALIDATION_MODE` invariant run locally |
| Backends | `Xvnc` and `Xspice` in CI, plus minimal mocks as the opposite pole | both poles ✓ for RFB — `Xvnc` is spawned by the test and skipped with a note when absent. No SPICE, because there is no SPICE backend |
| Input | exhaustive VK → scancode table tests | ✓ — and VK → keysym, and both paths through the RFB encoder |
| Parsers | `cargo-fuzz` over five targets | targets written ✓; no corpus, no nightly run yet |
| End-to-end | headless Moonlight client, assert on the elementary stream | ✓ — but with a client of our own rather than `moonlight-embedded`: pair, launch, encrypted RTSP, decrypt, reassemble, decode H.264. Run twice: against the colour-bar generator, reading the frame counter off the decoded picture, and against a real `Xvnc` desktop, checking the pixels are the colour it was painted |

**See `docs/testing.md` for the full strategy** — test tiers, the three
`moonlight-common-c` debug flags that turn the reference client into an oracle,
the two-pole RFB approach (`Xvnc` plus a deliberately minimal mock), the Xspice
flags that force each SPICE image codec, and loss injection with `tc netem`.

The highest-value artefact early on is a **captured Sunshine ↔ Moonlight
session** (pcap plus the client-generated `rikey`) to use as golden data.
Capture it before writing the packetiser, not after.

---

## 8. Decisions, and what is still open

> The open items below are written up as actionable work in
> [`docs/roadmap.md`](docs/roadmap.md) — why, what exactly, where it plugs in,
> and the tests that finish it. This table is the summary.

| # | Decision | Outcome |
|---|---|---|
| 1 | `vnc-rs` vs. a direct RFB implementation | **Direct.** The three things a bridge needs are the three things client crates hide. |
| 2 | Encoder default | **OpenH264.** The lightest encoder to build — cc and nothing else. (It was chosen for its BSD-2 licence; that stopped mattering when the project became GPL-3.0-or-later, and the choice stands on build weight.) It emits profile_idc 100 (High), which settles the question flagged in §4. |
| 3 | HEVC and AV1 | **H.264 only.** `ServerCodecModeSupport` advertises `SCM_H264`, and DESCRIBE omits the two markers a client reads as HEVC and AV1. |
| 4 | Audio beyond Opus silence | **Still silence.** RFB has no audio; the SPICE repacketise path is unbuilt. |
| 5 | `rusty_enet` vs. reimplementing ENet | **Still open.** `rusty_enet` is in use, contained by a one-peer limit, a connect-data check and a GCM-authenticated message layer. No audit has happened. |
| 6 | SPICE image decoders: port, FFI, or drop | **Still open**, and so is the backend. `backend.kind = "spice"` reports it as unimplemented. |

Two more that the implementation raised:

7. **A captured Sunshine ↔ Moonlight session.** `docs/testing.md` §2.4 calls it
   the highest-value artefact and says to capture it *before* writing the
   packetiser. That did not happen, and it is the gap that would catch a field
   or endianness error both of our ends make consistently.
8. **The management socket.** `solstice pair` runs in a different process from
   the daemon, so opening a pairing window needs IPC that does not exist. The
   window, lockout and source-address policy are implemented and tested; only
   the socket is missing.
