# Roadmap

The work that is not done, in enough detail to start on. Each item says **why**,
**what exactly**, **where it plugs in**, **how it is finished** (the tests that
must exist, since in this codebase a feature arrives with its tests or not at
all), and **what is already known to be hard**.

Status prose lives in three other places and will drift — `README.md`
(§Not implemented), `PROJECT-LAYOUT.md` §8 and
`docs/implementation-notes.md` §4. **This file is the one to work from**; the
others link here.

Sizes are rough and assume familiarity with the codebase, not with the
protocols.

---

## Order

The two the next session is most likely to want are §1 and §2. They are
independent and §1 is much smaller, which makes it the better warm-up if the
codebase is unfamiliar.

| | Item | Size | Blocked on |
|---|---|---|---|
| 1 | [Tight encoding](#1-tight-encoding-rfb) | ~1 week | nothing |
| 2 | [SPICE backend](#2-spice-backend) | 1–3 months | a codec decision (§2.2) |
| 3 | [Validate against real Moonlight](#3-validate-against-real-moonlight) | days | nothing — **do this before 1 or 2** |
| 4 | [Captured golden vectors](#4-captured-sunshine--moonlight-vectors) | days | §3 |
| 5 | [`solstice pair` management socket](#5-solstice-pair-and-a-management-socket) | ~2 days | nothing |
| 6 | [The still-frame encode cost](#6-the-still-frame-encode-cost) | ~2 days | nothing |
| 7 | [ENet: audit or reimplement](#7-enet-audit-or-reimplement) | 1–3 weeks | §3 |
| 8 | [Smaller items](#8-smaller-items) | varies | |

§3 is listed third but should probably go first in wall-clock terms: it is
cheap, and everything else is built on the assumption that the host half is
correct against a client that has never actually connected to it.

---

## 1. Tight encoding (RFB)

### Why

Not for performance. `docs/implementation-notes.md` §3 measures the RFB
decoders at ~14% of a core against an H.264 encoder at 36–83%, so Tight cannot
move the number that matters. The honest reasons to want it are:

- **Compatibility.** Tight is what TigerVNC, TurboVNC and libvncserver prefer.
  Today Solstice negotiates them all down to ZRLE, which works, but it means
  every server runs a code path it uses less often than its default.
- **Bandwidth off-loopback.** `docs/security.md` §6.8 puts the backend on
  loopback or an SSH tunnel, where 13 Mbit/s is free. If that constraint is
  ever relaxed — a VNC host across a LAN — Tight's palette and fill
  sub-encodings beat ZRLE on typical desktop content.
- **It is the last common encoding missing**, and the decoders are the one part
  of the RFB client that is genuinely finished otherwise.

### What exactly

A `tight` module decoding, at minimum:

- the **compression-control byte**: four zlib-stream reset bits plus a
  compression-type field;
- **fill** — a single colour for the whole rectangle (very common, very cheap);
- **basic**, with its filter-id: *copy*, *palette* (1-bit and 8-bit indexed)
  and *gradient*;
- **four independent zlib streams**, selected per rectangle and resettable
  individually. This is the detail that makes Tight stateful in a *different*
  way from ZRLE, which has exactly one stream — see the gotcha below;
- **compact length encoding** (1–3 bytes) for compressed payload sizes.

> The byte layout above is from general knowledge of the encoding, **not** from
> a source reading, which is not how the rest of this project's protocol detail
> was produced. **Task zero is to read `rfbproto.rst` §Tight Encoding and write
> the layout into `docs/rfb-vnc-protocol.md` §5 with line references**, the way
> §2 and §3 of that document were done. Everything else here assumes that has
> happened.

### JPEG: don't

Tight's headline win is its JPEG sub-encoding, and for this architecture it is
a regression. Solstice re-encodes everything to H.264 afterwards, so a JPEG hop
means double-lossy compression, and `docs/testing.md` §8 names exactly that
failure — *"the text looks smeary at 10 Mbit"* — as what desktop remoting is
judged on.

Implement Tight **lossless-only**, and do not advertise the JPEG quality-level
pseudo-encodings (−23..−32). The working assumption is that a server will not
send JPEG to a client that never asked for a quality level; **verify that in
TigerVNC's `TightEncoder` before relying on it**, and if it is wrong, the
decoder needs a JPEG path after all (pure-Rust `zune-jpeg` rather than
`turbojpeg`, to stay off a C dependency — see `docs/security.md` §5.5).

### Where it plugs in

```
crates/solstice-vnc/src/encodings/tight.rs      new
crates/solstice-vnc/src/encodings/mod.rs        declare it; drop the "not implemented" note
crates/solstice-vnc/src/session.rs              UpdateLoop::framebuffer_update, add the arm
crates/solstice-vnc/src/session.rs:27 ENCODINGS add encoding::TIGHT — see the invariant below
crates/solstice-vnc/src/protocol.rs             add TIGHT = 7
crates/solstice-vnc/src/mock.rs                 teach the mock to emit each sub-encoding
```

The ZRLE decoder is the closest model: `zrle.rs` already separates the zlib
stream (owned by the session, passed in) from the tile decoding (a pure
function over an inflated buffer, which is what makes it testable and
fuzzable). Tight should follow that split, with four streams instead of one.

> **Invariant: do not add `encoding::TIGHT` to `ENCODINGS` until it decodes.**
> Advertising an encoding this build cannot decode converts a missing feature
> into a corrupt framebuffer. `set_encodings_lists_what_we_can_actually_decode`
> (`session.rs`) asserts Tight is absent today; that assertion flips when, and
> only when, the decoder lands.

### Known gotchas

- **Four zlib streams, not one.** The reset bits are per-stream, and a server
  may reset one mid-session. Getting this wrong desynchronises the stream and
  the symptom is not an error — it is a picture that slowly turns to garbage.
  The ZRLE continuity test (`the_zlib_stream_is_continuous_across_rectangles`)
  is the model for the regression test, times four.
- **Decompression bombs.** `zrle.rs` caps inflation at 64 MB per rectangle
  (`MAX_INFLATED`) because the backend may be a VM the user does not control
  (`docs/security.md` §5.4). Tight needs the same cap.
- **Fill rectangles carry no length.** A single pixel, no compression, no
  stream involvement — easy to get wrong by routing it through the zlib path.

### Done when

- Unit tests per sub-encoding — fill, copy, palette (both widths), gradient —
  in the style of `zrle.rs`'s tests.
- A four-stream continuity test, and a reset-mid-session test.
- The mock server (`mock.rs`) can emit Tight, so `mock_server.rs` covers it.
- `real_server.rs` gains a case that offers **only** Tight to `Xvnc`, which is
  the cleanest way to get deterministic per-encoding coverage from one server
  (`docs/testing.md` §3.1).
- `encoding_bench.rs` gains a Tight row, so the performance claim in
  `docs/implementation-notes.md` §3 is settled with a measurement rather than
  an argument.
- The `rfb_rect` fuzz target reaches the Tight decoder.

---

## 2. SPICE backend

### Why

It is the native console protocol for QEMU/KVM, and it brings three things RFB
cannot: **audio**, **agent-driven resize** (so Moonlight's requested mode is
matched exactly instead of letterboxed), and **client-mode absolute mouse**.
For bridging a VM it is the right protocol; `docs/spice-protocol.md` §8 is the
full analysis.

### 2.1 What already exists

Not starting from zero. The following need no change:

- the backend seam (`solstice-backend`) — `Session` is a handle, not a socket,
  so SPICE's many-connections-per-session shape fits behind it unchanged. The
  warning in `docs/spice-protocol.md` §8.1 is about a naively-shaped trait;
  this one is not;
- **input**, entirely: `SPICE_MSGC_INPUTS_KEY_DOWN` carries PC AT scancodes,
  the same representation as RFB's pseudo-encoding −258, so `solstice-input`'s
  VK→scancode table serves both backends with no new code;
- the whole GameStream host half, encoder, frame clock and pipeline;
- the config and factory plumbing — `backend.kind = "spice"` parses today and
  returns `FactoryError::NotImplemented("spice")`
  (`crates/solstice/src/backend_factory.rs`), and the `spice` Cargo feature
  exists in `crates/solstice/Cargo.toml` so the dependency tree stays
  excludable.

### 2.2 The decision to make first: the image codecs

Everything else is ordinary work. This is the gate, and it should be settled
before any code is written.

`DRAW_*` messages carry images compressed with **QUIC**, **LZ**, **GLZ**,
**JPEG**, **LZ4**, **ZLIB-over-GLZ** or raw. The problem
(`docs/spice-protocol.md` §5.1):

- **QUIC and GLZ have no Rust implementation**, and both are on the default
  path: QEMU's `-spice` defaults to `image-compression=auto_glz`, which picks
  between GLZ and QUIC per image. Neither can be skipped for real use.
- **GLZ is stateful across images** — a session-long history window — so a
  message cannot be decoded in isolation, and the bugs live in window
  management. `docs/testing.md` §4 is explicit that this needs *long* sessions
  to test, not single frames.
- `PREFERRED_COMPRESSION` biases the server; it cannot forbid anything.

Three options:

| Option | Cost | Risk |
|---|---|---|
| **FFI to `spice-common`** | days for bindings | Puts C back in the data path for attacker-influenced input. `docs/security.md` §5.5 wants that boundary thin, validated before crossing, fuzzed, and possibly in a separate process. |
| **Port QUIC + GLZ to Rust** | weeks to months | A research project. GLZ's history window is the hard part. |
| **Constrain the server and fall back** | days | Only works where the operator controls the QEMU command line. Useless against an appliance. |

Recommendation: **FFI first, behind the thin boundary `security.md` describes,
with a fuzz target on the decode entry point from day one.** A port can replace
it later without changing the backend above it.

### 2.3 Staged plan

Each milestone is independently testable. `docs/testing.md` §4 is the test
plan; `Xspice` links the same `spice-server` QEMU does, so no VM is needed.

**M1 — link and session.** `SpiceLinkHeader/Mess/Reply`, capability
negotiation, the RSA-OAEP/MGF1-SHA-1 ticket against the per-connection
1024-bit key, and TLS on every channel (`docs/security.md` §4.2 requires it).
Then `MAIN_INIT` (which allocates the `connection_id` every other channel must
present), `CHANNELS_LIST`, and the framing: mini vs full header, per-channel
serials, and **`SET_ACK` windows, which are not optional — the server stalls
without them**.
*Done when:* a mock SPICE server (`docs/testing.md` §4.1) and `Xspice
--disable-ticketing` both link, and the negative cases are covered — truncated
`SpiceLinkMess`, bad magic, wrong `connection_id` on a secondary channel,
ack-window violation, a `SpiceDataHeader` whose `size` overruns.

**M2 — inputs and cursor.** Small. Reuses the scancode table. Needs
`MOUSE_MOTION_ACK` flow control (at most 4 unacknowledged bunches,
`protocol.h:113`).
*Done when:* the table-driven input tests from `mock_server.rs` are mirrored
against the SPICE mock.

**M3 — display, raw images only.** Surfaces, `SURFACE_CREATE/DESTROY`, the
`DRAW_*` set, `COPY_BITS`, invalidation, palettes — a 2D rasteriser with
clipping, ROPs, brushes, masks and text glyphs. Run against
`Xspice --image-compression off --streaming-video off`, where images arrive
uncompressed and **no codec work is needed at all**.
*Done when:* an end-to-end test in the shape of
`a_client_receives_the_pixels_of_a_real_vnc_desktop` passes against `Xspice`.
**This is a working backend but not yet a usable one** — a real QEMU guest
still sends GLZ.

**M4 — image codecs**, per §2.2, one `--image-compression` flag at a time:
`lz`, `lz4`, `quic`, `glz`, then `auto_glz`. GLZ last, and with a soak test,
because its window is the whole point and single frames prove nothing.

**M5 — video streams.** `STREAM_CREATE/DATA/CLIP/DESTROY/DATA_SIZED`: clipped
sub-rectangles the server classified as video, composited over the draw output,
carrying MJPEG/VP8/H264/VP9/H265. Turn `--streaming-video all` on early enough
to discover that naive compositing breaks (`docs/testing.md` §4).
**Do not** try to forward SPICE's H.264 straight to Moonlight —
`docs/spice-protocol.md` §5.2 explains why it cannot work: partial-screen,
destroyable at any moment, no keyframe on demand.

**M6 — the agent.** `MONITORS_CONFIG` to match Moonlight's requested mode,
client-mode absolute mouse, clipboard. Test with `--vdagent` **on and off** —
all three degrade when it is absent, and without it absolute coordinates must
be converted to relative deltas with the pointer drift every SPICE client
accepts.

**M7 — audio.** `PLAYBACK` carries Opus, which GameStream also uses, so this
may **repacketise without transcoding** — the one place SPICE is cheaper than
RFB. Confirm the frame duration and channel layout line up with
`x-nv-aqos.packetDuration` before relying on it (`docs/spice-protocol.md` §7).

### 2.4 Known gotchas

- All integers are **little-endian** — the opposite of RFB and of GameStream's
  RTP headers. Three conventions in one process.
- Message type numbers are **per-channel namespaces**; 1–99 are the common base
  set and channel-specific types start at 101.
- `GL_SCANOUT_UNIX` passes a dmabuf FD and is local-only by construction. Do
  not advertise the capability.
- `Xspice` does **not** cover QXL guest-driver behaviour: a real VM's driver
  emits a different mix of draw commands. Worth one manual QEMU run before
  release, not a CI job (`docs/testing.md` §4.2).
- `spice-client` (0.2.0) exists on crates.io but is a component of
  `quickemu-manager` with very little production exposure. Read it before
  depending on it; it is unlikely to have the image decoders.

---

## 3. Validate against real Moonlight

**Do this first.** It is cheap and everything else assumes the host half is
correct.

The end-to-end tests use a client written from the same research as the server,
so a wrong assumption made at *both* ends passes. `moonlight-embedded
-platform fake` is a headless client sharing `moonlight-common-c` with every
real Moonlight port (`docs/testing.md` §2.1), and `-pin 1234` makes pairing
scriptable.

Most likely to break, in order:

1. **The ENet control channel** — `rusty_enet` has never met a real peer, and
   input rides on it.
2. **The encrypted-RTSP IV byte order** — written little-endian by inference
   from the control-stream construction, never verified
   (`docs/implementation-notes.md` §4).
3. **`NV_KEYBOARD_PACKET.keyCode` endianness** — read from the *absence* of a
   byte-swap macro rather than from a capture.

Build the probe client with the three debug flags `docs/testing.md` §2.2
describes — `FEC_VALIDATION_MODE` especially, which turns the reference client
into a continuously-asserting FEC oracle — and keep it in
`tests/tools/mlc-probe/`.

---

## 4. Captured Sunshine ↔ Moonlight vectors

`docs/testing.md` §2.4 calls this *"the highest-value artefact early on"* and
says to capture it **before** writing the packetiser. That did not happen. It
is the gap that catches a field-offset or endianness error both of our ends
make consistently — i.e. exactly the three risks in §3.

Since the *client* generates `rikey`, an instrumented probe can log the session
key and decrypt the control stream and encrypted RTSP offline. Land the result
in `tests/vectors/capture/` with the same freeze-it-as-JSON treatment the FEC
vectors got, so CI needs neither a network nor Sunshine.

---

## 5. `solstice pair` and a management socket

The pairing window, attempt lockout and source-address restriction are
implemented and tested inside the daemon. What is missing is only the IPC:
`solstice pair` runs in a *different process*, so today it reports that rather
than opening a window against its own throwaway state
(`crates/solstice/src/main.rs`).

A Unix socket at `$state_dir/control.sock`, mode 0600, carrying a handful of
commands: `pair --pin --window`, `list-clients`, `revoke`, `status`.

**Not** an HTTP API and **not** a web UI: `docs/security.md` §3.5 is blunt that
Sunshine's worst CVEs — CSRF to command injection as Administrator,
clickjacking — are in its config UI rather than its protocol. A Unix socket
with filesystem permissions needs no auth layer of its own, which is the point.

`contrib/solstice.service` already restricts `RestrictAddressFamilies` to
`AF_INET AF_INET6 AF_UNIX`, so the socket is allowed there.

---

## 6. The still-frame encode cost

The benchmark in `docs/implementation-notes.md` §3 found this and it is the
largest optimisation available: **9.5 ms and 57% of a core at 1080p60 to
produce 13 bytes** for an unchanged frame. A desktop is mostly still and the
synthetic frame clock emits these constantly, so it is the steady-state cost of
an idle session.

Worth trying, in order of likely payoff:

- OpenH264 encoder settings — the build logs already warn that
  `bEnableFrameSkip = 0` disables rate control and that scene-change detection
  is off; neither was tuned with a measurement in hand.
- Dropping to a lower tick rate while the screen is unchanged, within whatever
  Moonlight's watchdog tolerates (`ML_ERROR_NO_VIDEO_TRAFFIC`,
  `Limelight.h:419-424`) — the clock already knows a frame is a duplicate
  (`Tick::is_duplicate`).
- Caching an encoded still frame and re-sending it. **Verify this is legal**
  before building it: the reference and frame numbering have to stay
  consistent or the client's decoder drifts.

Measure with `encode_cost.rs`, which exists for this.

---

## 7. ENet: audit or reimplement

`rusty_enet` is a C-to-Rust transpilation whose own README says it *"couldn't
be much further from ready for serious use"*, and it sits on the
**pre-authentication** UDP path. GHSA-c428-87f8-rrv5 is an unauthenticated DoS
via a short ENet control packet in exactly this position.

What contains it today (`crates/solstice/src/net/control.rs`): a one-peer
limit, a refusal of any peer whose connect data does not match the launch
session, and a message layer that authenticates with AES-GCM before a byte
reaches the input parser. That reduces blast radius; it does not remove a
pre-auth state machine with fragment reassembly and retransmission timers.

`docs/security.md` §2.4 asks for an audit, fuzzing, and readiness to implement
the subset Moonlight actually uses. §3 should come first — knowing which ENet
features a real client exercises is what makes "the subset" a finite thing.

---

## 8. Smaller items

- **Fuzzing in CI.** Five targets exist and run clean for a minute each; there
  is no seed corpus, no persistent corpus, and no nightly job
  (`docs/testing.md` §6 describes the tier).
- **More RFB servers.** `docs/testing.md` §3.3 lists exactly what dropping
  `wayvnc`, `x11vnc`, TurboVNC and QEMU's `-vnc` costs. x11vnc is the
  interesting one: libvncserver implements QEMU extended key events in its
  *client* only, so it is a real server exercising the keysym fallback.
- **HEVC and AV1.** `ServerCodecModeSupport` advertises `SCM_H264` only and
  DESCRIBE omits the two markers a client reads as HEVC and AV1
  (`docs/moonlight-sunshine-protocol.md` §2.2). Both would need encoder support
  first.
- **Hardware encoders.** The `VideoEncoder` trait is the seam. VAAPI and NVENC
  arrive behind an `ffmpeg` feature. Licence-compatible, since Solstice is
  GPL-3.0-or-later, but `deny.toml` bans `ffmpeg-sys-next` and `x264` on
  dependency-weight grounds: lifting the ban should happen with the feature,
  not before it. Not testable in hosted CI (no GPU).
- **mDNS** (`_nvstream._tcp`). Moonlight accepts a typed-in host, so this is
  convenience.
- **Controllers, touch, pen.** Neither backend protocol has any notion of them.
  They are dropped and *counted* today (`DroppedInput` in
  `crates/solstice-gamestream/src/input.rs`). Synthesising keyboard and mouse
  from a gamepad is the only route, and it is a product decision, not a
  protocol one.
- **UPnP / NAT-PMP.** `docs/security.md` §5.6: **do not implement this.**
  Automatically making a service internet-reachable is the operator's decision.
