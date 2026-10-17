# The Rust project layout

**This describes what is built.** It started as a proposal derived from the
protocol research in `docs/` — in particular the backend abstraction sketched
in `docs/bridging-design.md` §6 — and the structure survived contact with the
implementation almost unchanged. Where it did not, the deviation is marked
**▲** and explained; `docs/implementation-notes.md` has the reasoning.

About 52 000 lines of Rust across ten crates, roughly half of it tests.

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
│   ├── solstice-audio/           # [lib] ▲ backend audio → the client's Opus stream
│   └── solstice-input/           # [lib] VK → scancode / keysym tables. Pure data.
├── fuzz/                         # cargo-fuzz targets, its own workspace
│   ├── seeds/                    # ▲ committed seed inputs, from the captured session
│   └── fuzz_targets/
│       ├── rtsp_message.rs
│       ├── sdp_announce.rs
│       ├── input_batch.rs
│       ├── control_envelope.rs
│       ├── enet_host.rs          # ▲ the ENet host, before and after the handshake
│       ├── audio_bridge.rs       # ▲ backend audio frames through the Opus bridge
│       └── rfb_rect.rs
├── tests/
│   ├── guest/                    # the QEMU test guest: both backends, one image
│   ├── vectors/fec/              # nanors oracle (dump.c), its checker, frozen JSON
│   ├── vectors/capture/          # a real Moonlight session, decrypted and frozen
│   └── tools/
│       ├── capture-session.sh    # captures one, unprivileged; see roadmap §4
│       ├── control-loss.sh       # the real client with loss on the control port
│       ├── fuzz.sh               # builds every fuzz target on stable and runs it
│       ├── gen_fuzz_seeds.py     # seeds four targets from the captured session
│       ├── gen_capture_vectors.py# decrypts it and checks it against the client
│       ├── gen_fec_vectors.py    # runs the oracle, freezes the vectors
│       ├── gen_spice_vectors.py  # the same, for the SPICE image codecs
│       └── mlc-probe/            # the real Moonlight client, headless and asserting
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
| A captured real-Moonlight session, replayed | `crates/solstice-gamestream/tests/capture_vectors.rs` |
| The ENet host vs. upstream ENet, over a lossy simulated network | `crates/solstice-gamestream/tests/enet_interop.rs` |
| RFB client vs. the minimal mock server | `crates/solstice-vnc/tests/mock_server.rs` |
| RFB client vs. QEMU's RFB server | `crates/solstice-vnc/tests/real_server.rs` |
| SPICE client vs. a live `spice-server` | `crates/solstice-spice/tests/real_server.rs` |
| The whole stack, end to end, twice | `crates/solstice/tests/end_to_end.rs` |
| `solstice pair` / `revoke` as a second process against a running daemon | `crates/solstice/tests/management.rs` |
| The host vs. the **real** Moonlight client | `crates/solstice/tests/real_moonlight.rs` |

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
├── cli.rs            # clap: run, pair, status, list-clients, revoke
├── management.rs     # ▲ the control socket those subcommands talk to the daemon over
├── config.rs         # serde + toml; see §5
├── supervisor.rs     # session lifecycle, resource ceilings, shutdown
├── pipeline.rs       # ▲ the frame loop: framebuffer → convert → encode → packetise
├── testpattern.rs    # ▲ the colour-bar backend (and a tone), for milestone 1 and the tests
├── audio.rs          # ▲ the audio sender: one packet per negotiated duration
├── tls.rs            # ▲ the mutual-TLS listener's client-certificate policy
├── backend_factory.rs# config → Arc<dyn Backend>, where the feature flags land
└── net/
    ├── nvhttp.rs     # the two HTTP listeners
    ├── rtsp.rs       # TCP 48010, plaintext and GCM-wrapped
    ├── media.rs      # UDP peer binding and paced sending
    └── control.rs    # the socket and thread around the ENet host
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
│   ├── enet.rs           # ▲ ENet's datagram header and twelve commands
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
│   ├── control.rs        # GCM envelope, replay window, message dispatch
│   ├── enet.rs           # ▲ the ENet host: Moonlight's subset, sans-I/O
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
├── cursor.rs         # the Cursor pseudo-encoding, drawn where the client points
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

▲ `encodings/` has Raw, CopyRect, RRE, Hextile, ZRLE and Tight. Tight is
**lossless-only** — fill, copy, palette and gradient — and no JPEG quality
level is advertised, so a conforming server sends no JPEG; one that does gets
an error rather than a guess (`docs/roadmap.md` §1).

▲ `mock.rs` is the deliberately minimal recording server from
`docs/testing.md` §3.2: Raw only unless Tight is asked for, no flow control,
no -258, and it records
every client message so input is asserted on exactly rather than observed on a
live desktop.

### `solstice-spice-codec` — SPICE's image codecs

```
src/
├── lib.rs            # Error, Image, PixelFormat, Palette, Limits
├── bits.rs           # QUIC's little-endian-word, MSB-first bit reader
├── quic.rs           # SFALIC derivative: prediction, Golomb model, run mode
├── quic_tables.rs    # the 256-entry schedule table, part of the format
├── lz.rs             # FastLZ derivative counting in pixels, eleven layouts
└── glz.rs            # the same, with matches into earlier images + the window
```

▲ **Its own crate, not part of `solstice-spice`.** The three codecs are pure
functions over bytes with no dependency on the SPICE wire format at all, and
keeping them separate is what makes them fuzzable and testable in isolation —
which for a from-scratch port of somebody else's codec is the whole game. It
also means a SPICE backend is not a prerequisite for the thing that was
supposed to gate it.

No dependencies but `thiserror`, and `#![forbid(unsafe_code)]`.
`docs/roadmap.md` §2.2 explains why this is a port rather than an FFI binding
to `spice-common`, and what the port does that the C does not. The
differential vectors that justify it live in `tests/vectors/spice/`.

JPEG, LZ4 and ZLIB are deliberately absent: they have Rust crates.

### `solstice-spice` — SPICE backend (optional)

```
src/
├── lib.rs
├── wire.rs           # bounds-checked little-endian; the 32-bit member offsets
├── error.rs
├── protocol.rs       # constants, transcribed from the canonical headers
├── link.rs           # SpiceLinkHeader/Mess/Reply, caps, RSA-OAEP ticket
├── channel.rs        # mini/full headers, sub-messages, the SET_ACK window
├── main_channel.rs   # session setup, mouse mode, the vdagent tunnel
├── agent.rs          # MONITORS_CONFIG, capabilities, by-demand clipboard, tokens
├── display/
│   ├── mod.rs        # the owning task: surfaces → framebuffer, damage, cursor
│   ├── types.rs      # the structures spice.proto describes
│   ├── image.rs      # SpiceImage descriptors, palettes, the pixmap cache
│   ├── surface.rs    # the surface set
│   ├── raster.rs     # ROPs, clipping, masks, brushes, sampling, glyphs
│   ├── commands.rs   # one draw command, parsed and executed
│   └── stream.rs     # video streams
├── cursor.rs         # cursor shapes, composited by the display task
├── inputs.rs         # scancodes, pointer, motion flow control
├── playback.rs       # guest audio, handed on as the server sent it
├── backend.rs        # dialling every channel; Backend and Session
└── mock.rs           # a deliberately minimal server, for the negative cases
```

Gated behind `--features spice`, off by default — not because it is
unfinished, but because it pulls a dependency tree an RFB-only build has no
use for: the image codecs, a JPEG decoder, LZ4 and zlib.

▲ **The display and cursor channels share one owner.** They arrive on
separate sockets, but a single task holds the surfaces, the cursor and the
framebuffer, with the cursor channel's task forwarding updates into the same
queue. The alternative — a mutex around the framebuffer — needs a third
full-screen buffer to hold the pixels under the pointer, because moving it
has to repaint what was beneath. With one owner that is just publishing the
union of the old and new cursor rectangles out of the primary surface.

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

### `solstice-audio` — audio path

▲ Not in the original layout, which had `opus` in `solstice-gamestream` for
silence. Silence turned out not to need a codec, and real audio needed
rather more than one: a decoder, an encoder, a remix and a jitter buffer.
None of it is GameStream protocol, so it is its own crate, and the daemon
maps the negotiated layout onto it.

```
src/
├── lib.rs
├── bridge.rs         # AudioBridge: pass-through or transcode, prebuffer, one packet per tick
├── codec.rs          # libopus: multistream encoder, plain decoder, a client-side decoder for tests
├── mix.rs            # channel count changes; stereo lands in FL/FR
├── toc.rs            # packet duration from the TOC byte, for the pass-through decision
└── tone.rs           # a sine and a Goertzel purity check, for the tests in other crates
```

The layouts themselves — what DESCRIBE advertises and what the client
decodes with — are GameStream knowledge and live in
`solstice-gamestream/src/stream/opus_layout.rs`.

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
            \        solstice-audio  /              /   \
             `------ solstice-backend -------------'     |
                            |                   solstice-spice-codec
                     solstice-input
```

`solstice-audio` hangs off the binary like the encoder does, and knows
nothing of GameStream: the daemon translates the negotiated layout for it.

No cycles; neither backend is reachable from `solstice-gamestream`.
`solstice-spice-codec` is a leaf — it depends on nothing in the workspace,
which is what lets it be fuzzed and tested without a SPICE backend existing.

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
| `quick-xml` | 0.42 | NVHTTP XML responses |
| `hyper` / `axum` | 1.12 / 0.8 | the HTTP listeners |
| `socket2` | 0.6 | UDP socket options, DSCP, batched send |

> ▲ There is no ENet crate. The plan was `rusty_enet`, a C-to-Rust
> transpilation of ENet 1.3.18 whose own README says it "couldn't be much
> further from ready for serious use", on the **pre-authentication** UDP path
> (`docs/security.md` §2.4). It shipped, contained, until a real client had
> shown which subset of ENet Moonlight uses; that subset is now
> `stream/enet.rs`, and `rusty_enet` survives only as a dev-dependency, as the
> independent ENet the host is tested against (`docs/roadmap.md` §7).

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

### `solstice-audio`

| Crate | Version | Use | Licence note |
|---|---|---|---|
| `opusic-c` | 1.6 | libopus 1.6.1, vendored: multistream encode, decode | BSD-3 |

▲ Not `opus` 0.4: it binds only single-stream Opus, and a surround client
decodes multistream. The pure-Rust ports were passed over because the
decoder reads bytes a SPICE server chose, and libopus is the implementation
with a decade of fuzzing behind it. The cost is that **`cmake` is back as a
build requirement** — `opusic-sys` builds the vendored source with it — for
any build with the `audio` feature, which is on by default. An RFB-only
build without it keeps the old canned silence.

### `solstice-vnc`

| Crate | Version | Use |
|---|---|---|
| `vnc-rs` | 0.6 | candidate RFB client; evaluate vs. implementing directly |
| `flate2` | 1.1 | zlib for Tight / ZRLE / zlibhex |
| `turbojpeg` | 1.5 | Tight's JPEG sub-encoding — **not taken**: Tight is lossless-only |
| `des` | — | only if VNC Authentication is supported at all |

### `solstice-spice-codec`

| Crate | Version | Use |
|---|---|---|
| `thiserror` | 2 | the error type, and nothing else |

▲ That is the whole list, and deliberately: a decoder sitting directly on
attacker-controlled bytes is the last place to want a supply chain.

### `solstice-spice` (optional)

| Crate | Version | Use |
|---|---|---|
| `solstice-spice-codec` | — | QUIC, LZ and GLZ |
| `rsa`, `sha1` | 0.9, 0.10 | the RSA-OAEP/MGF1-SHA-1 ticket |
| `rustls`, `tokio-rustls`, `webpki-roots`, `rustls-pemfile` | — | TLS on every channel, with the certificate verified |
| `zune-jpeg` | 0.4 | the JPEG and JPEG-alpha descriptors, and MJPEG streams |
| `lz4_flex` | 0.11 | the LZ4 descriptor, in its external-dictionary mode |
| `flate2` | 1 | the zlib-over-GLZ descriptor |

▲ `spice-client` 0.2 was evaluated and not used; `docs/spice-protocol.md`
§8 has the reasoning.

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
default  = ["vnc", "openh264", "audio"]
vnc      = ["dep:solstice-vnc"]
openh264 = ["solstice-video/openh264"]
# SPICE is excludable along with its whole dependency tree.
spice    = ["dep:solstice-spice", "dep:solstice-spice-codec", "audio"]
# ▲ The Opus codec. Without it: canned stereo silence, backend audio dropped.
audio    = ["dep:solstice-audio"]
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
pairing_window     = "60s"      # opened only by `solstice pair`; the PIN is
max_pair_attempts  = 3          # 4 digits, so the window and lockout are the control
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
# host     = "127.0.0.1"
# port     = 5901              # the server's *TLS* port, configured separately
# security = "tls"             # refuse "plain" off-loopback
# ca_file  = "/etc/solstice/spice-ca.pem"
# audio    = true
```

---

## 7. Testing

381 tests, about 15 seconds. What exists against what was planned:

| Layer | Planned | Built |
|---|---|---|
| `wire/` codecs | round-trip property tests; golden vectors from a captured session | ✓ — a real `moonlight-common-c` session, captured against this host and replayed (§8.7). The round-trip tests had agreed with a wrong scroll layout; the capture did not |
| FEC | differential against a compiled `nanors` | ✓ — the oracle is built from `tests/vectors/fec/dump.c` and the output frozen as JSON |
| Pairing | four-phase handshake against a mock client, with negative tests for every out-of-order and replayed transition | ✓ — each of the three CVEs has a named test |
| RTSP | recorded Moonlight transcripts replayed | ✓ — the real client's encrypted transcript is replayed against the state machine, and every response must match byte for byte |
| Packetiser | feed Annex-B, reassemble with a port of the client's depacketiser, assert byte equality | ✓ — including shard loss recovered from parity, which is the `FEC_VALIDATION_MODE` invariant run locally |
| Backends | `Xvnc` and `Xspice` in CI, plus minimal mocks as the opposite pole | both poles ✓ for both backends. `real_server.rs` drives a live `Xspice` across every image codec, MJPEG streams and input; it found two bugs the mock could not (`docs/roadmap.md` §2.6). What `Xspice` cannot reach is a real `spice-vdagent` and a QXL guest driver — §2.7 |
| Input | exhaustive VK → scancode table tests | ✓ — and VK → keysym, and both paths through the RFB encoder |
| Parsers | `cargo-fuzz` over ten targets | targets written ✓; five seeded from the captured session and all run by hand with `tests/tools/fuzz.sh` on stable, never scheduled. Four of them have found real bugs in short local runs: a 23-byte QUIC header asking for a 151 MiB image (which is why `Limits` exists), an LZ width whose stride overflowed a `u32`, a `COPY_BITS` asking for a 174 GB allocation on a 64 × 48 surface, a zero-stride stencil mask that indexed an empty row, and two blits whose source position overflowed, once in the fixed-point scaling and once before widening. All six have regression tests |
| SPICE image codecs | differential against the real C encoders | ✓ — 278 vectors from `spice-common` (QUIC, LZ) and `spice-server` (GLZ), frozen by `tests/vectors/spice/` |
| End-to-end | headless Moonlight client, assert on the elementary stream | ✓ — but with a client of our own rather than `moonlight-embedded`: pair, launch, encrypted RTSP, decrypt, reassemble, decode H.264. Run twice: against the colour-bar generator, reading the frame counter off the decoded picture, and against a real `Xvnc` desktop, checking the pixels are the colour it was painted |

**See `docs/testing.md` for the full strategy** — test tiers, the three
`moonlight-common-c` debug flags that turn the reference client into an oracle,
the two-pole RFB approach (`Xvnc` plus a deliberately minimal mock), the Xspice
flags that force each SPICE image codec, and loss injection with `tc netem`.

The highest-value artefact early on was meant to be a **captured Sunshine ↔
Moonlight session** (pcap plus the client-generated `rikey`) to use as golden
data, captured before the packetiser was written. It came last instead, and
with Solstice as the host. It still found two defects (`docs/roadmap.md` §4).

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
| 4 | Audio beyond Opus silence | **Wired.** SPICE's 10 ms stereo Opus goes to the client untouched when it asked for 10 ms, and through libopus to the client's own layout and duration otherwise, including 5.1 and 7.1, which DESCRIBE now advertises. RFB, which has no audio, gets silence encoded in the negotiated layout. A real guest's tone has been heard by the real client both ways (`docs/roadmap.md` §2.7). |
| 5 | `rusty_enet` vs. reimplementing ENet | **Reimplemented — the subset.** Once a real client had been captured, what Moonlight uses was a short list: connect, acknowledge, ping, reliable/unreliable/unsequenced sends, bandwidth limit, disconnect, and never a fragment. `stream/enet.rs` is that list, sans-I/O, bounded, and stricter than ENet before authentication. It is held against upstream ENet (via `rusty_enet`, now test-only) under simulated loss, against the captured session byte for byte, and against the real client with netem on the port (`docs/roadmap.md` §7). |
| 6 | SPICE image decoders: port, FFI, or drop | **Port, and the backend above them is now written too.** `solstice-spice-codec` has QUIC, LZ and GLZ in pure Rust, verified against the real C encoders; `solstice-spice` has the channels, the rasteriser, the agent and the audio. `backend.kind = "spice"` builds a working backend, and a real QEMU guest has answered it — `docs/roadmap.md` §2.6. |

Two more that the implementation raised:

7. **A captured Sunshine ↔ Moonlight session.** `docs/testing.md` §2.4 calls it
   the highest-value artefact and says to capture it *before* writing the
   packetiser. That did not happen. The probe (`tests/tools/mlc-probe/`) found
   eight consistent-at-both-ends errors first (`docs/roadmap.md` §3). Then a
   session between the probe and this host was captured, decrypted and frozen
   (`tests/vectors/capture/`). It runs in CI without a C toolchain, and found
   two more: a frame 0 the client never decodes, and a scroll layout with a
   phantom byte (`docs/roadmap.md` §4). Sunshine is still not at the host
   end; what that would add is a host-side oracle, not conformance.
8. **The management socket.** `solstice pair` runs in a different process from
   the daemon, so opening a pairing window needed IPC. It is a Unix socket at
   `$state_dir/control.sock`, mode 0600 and peer-credential checked, carrying
   `pair`, `status`, `list-clients` and `revoke` as one line in, lines out --
   not HTTP, for the reason `docs/security.md` §3.5 gives
   (`docs/roadmap.md` §5).
