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

Both halves of this project now have the same shape of gap, and it is not a
missing feature: **neither has met the real thing.** The GameStream host has
never been connected to by a real Moonlight, and the SPICE backend has never
been answered by a real `spice-server`. Everything else on this list is worth
less than closing those two, and both are cheap.

| | Item | Size | Blocked on |
|---|---|---|---|
| 1 | [Tight encoding](#1-tight-encoding-rfb) | ~1 week | nothing |
| 2 | [SPICE backend](#2-spice-backend) | **implemented**; validation outstanding (§2.6) | nothing — `apt install xserver-xspice` |
| 3 | [Validate against real Moonlight](#3-validate-against-real-moonlight) | days | nothing — **do this before 1** |
| 4 | [Captured golden vectors](#4-captured-sunshine--moonlight-vectors) | days | §3 |
| 5 | [`solstice pair` management socket](#5-solstice-pair-and-a-management-socket) | ~2 days | nothing |
| 6 | [The still-frame encode cost](#6-the-still-frame-encode-cost) | ~2 days | nothing |
| 7 | [ENet: audit or reimplement](#7-enet-audit-or-reimplement) | 1–3 weeks | §3 |
| 8 | [Smaller items](#8-smaller-items) | varies | |

§3 is listed third but should go first in wall-clock terms, alongside §2.6:
they are the two places where a wrong assumption made consistently at both
ends of a test currently passes.

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

**Implemented.** `crates/solstice-spice`, behind the `spice` Cargo feature.
`backend.kind = "spice"` builds a working backend rather than reporting
itself unimplemented. What is left is validation against a real server and
the handful of deliberate gaps in §2.5 — not milestones.

### Why it was worth it

It is the native console protocol for QEMU/KVM, and it brings three things
RFB cannot: **audio**, **agent-driven resize** (so Moonlight's requested mode
is matched exactly instead of letterboxed), and **client-mode absolute
mouse**. `docs/spice-protocol.md` §8 is the full analysis.

### 2.1 What it is

| | |
|---|---|
| `wire.rs` | bounds-checked little-endian reading, and the 32-bit offsets SPICE uses instead of inline structures |
| `link.rs` | the per-channel handshake and the RSA-OAEP/MGF1-SHA-1 ticket |
| `channel.rs` | mini and full message headers, sub-message lists, `PING`/`NOTIFY`/`DISCONNECTING`, and the `SET_ACK` window |
| `main_channel.rs` | `MAIN_INIT`, `CHANNELS_LIST`, mouse mode, the agent tunnel |
| `agent.rs` | `spice-vdagent`: `MONITORS_CONFIG` resize, capability exchange, clipboard, token flow control |
| `display/` | surfaces, the `DRAW_*` set, `COPY_BITS`, six image types, video streams, and the framebuffer the encoder reads |
| `cursor.rs` | five of SPICE's seven cursor types, composited into the framebuffer |
| `inputs.rs` | scancodes and pointer messages, with `MOUSE_MOTION_ACK` flow control |
| `playback.rs` | guest audio; Opus is passed through rather than transcoded |
| `backend.rs` | dialling every channel, and the `Backend`/`Session` implementation |
| `mock.rs` | a deliberately minimal server that mints a real RSA key and decrypts a real ticket |

Nothing in the backend seam had to change. `Session` is a handle rather than
a socket, so SPICE's many-connections-per-session shape fits behind it
unchanged — the warning in `docs/spice-protocol.md` §8.1 is about a naively
shaped trait, and this was not one.

Input needed no new table either: `SPICE_MSGC_INPUTS_KEY_DOWN` carries PC AT
scancodes, the same representation as RFB's pseudo-encoding −258, so
`solstice-input`'s VK→scancode table serves both backends. The one wrinkle is
packing: `spice_make_scancode` byte-swaps an extended key so the
little-endian `u32` reads `E0` then the code, which is the raw PS/2 byte
sequence.

### 2.2 The image codecs — settled, ported, and wired

This section used to say the decision had to be made before any code was
written, and recommended FFI to `spice-common`. **The port was done
instead**, as `crates/solstice-spice-codec`: QUIC, LZ and GLZ, pure Rust,
inside `#![forbid(unsafe_code)]`.

The table that recommended FFI costed a port at "weeks to months — a research
project", and that was wrong in a specific way worth recording. The research
*is* the expensive part of this kind of work, and it had already been done:
`docs/spice-protocol.md` §5.1 had located the three codecs, established that
GLZ's history window is the hard part, and named the files. What remained was
a mechanical translation of about 2,400 lines of macro-heavy C, which is a
different and much smaller job.

Why the port rather than the FFI, given the recommendation:

- **The C decoders are where the bounds checks are not.** `spice-common`
  guards its back-references and run lengths with `spice_assert` and
  `spice_extra_assert`, which compile out in release builds. On a release
  build an LZ stream whose first instruction is a back-reference reads before
  the start of its own buffer; a GLZ match longer than the image it refers to
  reads past the end of that one. `docs/security.md` §5.5 wants the C boundary
  thin, validated and fuzzed — but the thing most worth validating was inside
  the boundary.
- **`security.md` §5.5's alternative was a separate process.** That is a real
  cost in a bridge that has to composite every draw command into a
  framebuffer at frame rate.
- **The correctness risk a port carries is answerable.** It is answered by
  `tests/vectors/spice/`: 278 differential vectors generated by linking the
  actual C encoders — `spice-common` for QUIC and LZ, `spice-server` for GLZ —
  and asserting the Rust decoder reproduces the C decoder's pixels.

Three things the port does that the C does not, all of them the point:

1. **Bounds-checks every offset and length**, rather than asserting them away
   in release builds.
2. **Caps the window.** `GlzWindow` drops its oldest images past
   `Limits::glz_window_bytes` and reports `Error::GlzWindowMiss` if a later
   match wants one back.
3. **Caps the image.** `Limits::max_pixels` defaults to just past 8K, and the
   display channel now **does** lower it to the surface being drawn into —
   `display/commands.rs` passes `width * height` of the destination into every
   decode, which is what the codec crate's documentation asked a caller to do.

The schemes that already had Rust crates are in `display/image.rs` rather than
the codec crate: raw bitmaps in all eleven `SpiceBitmapFmt` layouts, JPEG
(`zune-jpeg`), JPEG-with-LZ-alpha, LZ4 (`lz4_flex`) and zlib-over-GLZ
(`flate2`). LZ4 is the awkward one: SPICE frames it as big-endian
length-prefixed **linked** blocks, so each block may match into the output of
the ones before it, which is the external-dictionary mode of the block format.

### 2.3 What the staged plan turned into

The plan was M1–M7. All seven landed; what each one actually cost is worth
recording, because the estimates were not evenly wrong.

**M1 — link and session.** As described. The two details that are easy to get
wrong and are not in the headers: the auth-mechanism word is conditional on
the server advertising `PROTOCOL_AUTH_SELECTION`, and the password is
encrypted **with its NUL terminator**, so an empty password is one zero byte
rather than none. Both come from `spice-gtk`'s `spice-channel.c`.

**M2 — inputs and cursor.** Small, as predicted. `MOUSE_MOTION_ACK` allows
`SPICE_INPUT_MOTION_ACK_BUNCH * 2` outstanding messages and releases four per
ack; past the window motion is *accumulated* rather than dropped, so the
pointer ends up in the right place however long the stall lasted.

**M3 — display, raw images only.** The big one, as predicted. The rasteriser
is `display/raster.rs`: the sixteen binary raster operations, the 256-entry
ternary ones, clip regions, stencil masks, solid and pattern brushes, scaled
blits with nearest and bilinear sampling, hairline strokes with flattened
Béziers, and 1-, 4- and 8-bit raster glyphs. Two mappings had to be
transcribed rather than derived — `ropd_descriptor_to_rop`
(`canvas_base.c:152-306`) and the ROP3 truth-table convention, which
`rop3.c`'s own self-test pins by evaluating each formula with
`d = 0xAA, s = 0xCC, p = 0xF0`.

**M4 — image codecs.** Wiring, as predicted; see §2.2.

**M5 — video streams.** Smaller than expected, because the answer turned out
to be "advertise one codec". A stream is decoded only to be composited and
re-encoded, so the decoder is pure overhead and the cheapest correct one wins:
MJPEG, which already had a decoder in the tree for SPICE's own JPEG images.
A server that opens a stream in anything else is told so with the
`STREAM_REPORT` the protocol defines for it — `num_frames = 0` with
`num_drops = 0xffffffff` — and falls back to draw commands.

**M6 — the agent.** `MONITORS_CONFIG`, capability exchange, and the clipboard
messages. `request_resize` returns `false` when there is no agent, which is
the same best-effort contract the RFB backend's `ExtendedDesktopSize` has.

**M7 — audio.** Opus packets are forwarded as `AudioFormat::Opus` rather than
decoded, which is the repacketise-not-transcode path §7 of the protocol notes
hoped for. Whether the *pipeline* can actually repacketise them still depends
on the frame duration lining up with `x-nv-aqos.packetDuration`, which is a
question for the pipeline and is not yet answered.

### 2.4 How it is tested

- **206 unit and mock tests** in the crate, plus the 88 in
  `solstice-spice-codec`.
- **A mock server** (`mock.rs`, `tests/mock_server.rs`) that mints a real
  1024-bit RSA key and decrypts a real ticket, so the OAEP path is exercised
  rather than stubbed. It covers the negative cases `docs/testing.md` §4.1
  names: a wrong password, a link error, `NEED_SECURED`, a server with no
  display channel, a `SpiceDataHeader` whose `size` overruns, and both header
  framings.
- **Two fuzz targets**, `spice_draw` and `spice_message`. They have already
  paid for themselves: `spice_draw` found a `COPY_BITS` whose destination
  rectangle asked for a 174 GB allocation on a 64 × 48 surface, and a
  zero-stride stencil mask that indexed an empty row. Both have named
  regression tests.
- **`tests/real_server.rs`** drives `Xspice` with `--image-compression` forced
  to `off`, `quic`, `lz`, `lz4` and `glz` in turn, plus
  `--streaming-video all`. It skips with a printed note when `Xspice` is not
  installed.

### 2.5 What is deliberately not implemented

Each of these is a decision, not an oversight.

- **`DRAW_COMPOSITE`.** The `COMPOSITE` capability is not advertised, so a
  conforming server will not send it; one that does gets an error rather than
  a guess. It is Porter-Duff with transforms and is the one draw command with
  no simple reading.
- **GL scanout.** `GL_SCANOUT_UNIX` and `GL_SCANOUT2_UNIX` pass a dmabuf file
  descriptor and are local-only by construction. The capability is not
  advertised and the messages are refused.
- **`COLOR8` and `COLOR24` cursors.** `spice-gtk` does not decode them either
  (`channel-cursor.c:302-305` falls through to "unimplemented cursor type"),
  which is good evidence no server emits them.
- **Stroke styling.** Dashes and line widths are parsed and ignored; every
  stroke is a hairline. A stroke one pixel off is a smaller error than a
  stroke that is missing.
- **Migration.** There is nowhere to migrate a Moonlight session to.
- **Horizontal scroll.** SPICE's button numbering has no horizontal wheel —
  `SIDE` and `EXTRA` are the two thumb buttons, not tilt.
- **Text events.** A scancode channel cannot express a code point the US
  layout has no key for, so `InputEvent::Text` is dropped rather than
  synthesised into the wrong keystrokes.
- **The clipboard has no sink.** The agent's clipboard messages are
  implemented and a guest offer surfaces as a `MainOutcome`, but the backend
  seam has nowhere to put it: GameStream has no clipboard channel. The
  plumbing is there for when something wants it.

### 2.6 The remaining risk, stated plainly

**No SPICE server has ever answered this code.** `Xspice` is not installed on
the machine it was written on, so `tests/real_server.rs` has only ever
skipped. Everything above is verified against the *specification* — the
`spice.proto` message layouts, the C's own raster-operation mapping, the
reference client's behaviour where the wire format does not determine it —
and against a mock written from the same reading. A wrong assumption made in
both places passes.

This is the same risk §3 names for the GameStream half, and it has the same
answer: run it against the real thing. In order of value:

1. **`apt install xserver-xspice` and run `tests/real_server.rs`.** Minutes of
   work, and it is the single highest-value thing left on this item.
2. **A manual QEMU run with a real QXL guest driver.** `Xspice` shares
   `spice-server` with QEMU so the protocol is the same code, but the *mix* of
   draw commands a real guest driver emits is not
   (`docs/testing.md` §4.2). Worth one run before a release, not a CI job.
3. **A GLZ soak.** The vectors replay a window of eight images; a real session
   churns thousands, and window management is exactly what frozen vectors
   cannot exercise. `glz_survives_enough_window_churn_to_evict` is the short
   version; the long one is a nightly job.

Two smaller unknowns, both of which need a server to answer:

- **Nothing is tuned.** The rasteriser's inner loops are per-pixel closures
  and the codec row loops are a direct translation. Whether that costs
  anything measurable against compositing and H.264 encoding is unknown
  because it has not been measured — and it should be measured against a real
  frame rather than guessed at.
- **GLZ out-of-order images are refused, not awaited.** `spice-gtk` blocks on
  a coroutine when a match refers to an image that has not arrived. With one
  display channel the case does not arise, because one channel delivers in
  order. A multi-monitor guest with several display channels would need the
  window shared and the wait reinstated.

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
