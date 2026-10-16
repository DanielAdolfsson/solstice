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

Both halves of this project have now been held against a real peer, and both
exercises paid for themselves on the first day: the SPICE backend against a
real `spice-server` (§2.6, two bugs) and the GameStream host against a real
`moonlight-common-c` (§3, **eight**). Neither set was reachable from a mock,
because a mock written from the same research agrees with the same mistakes.

§1, Tight, is now done too, and validated the same way: offered alone to
QEMU's RFB server, it reproduces QEMU's own screendump pixel for pixel.

What is left is ordinary work. §4 is the next one worth doing, and it is worth
less than it was: the probe now covers what the captured vectors were meant to
catch, so the case for them is regression-pinning in CI without a C toolchain
rather than discovery.

| | Item | Size | Blocked on |
|---|---|---|---|
| 1 | [Tight encoding](#1-tight-encoding-rfb) | **done** — lossless, advertised first, and exact against a real QEMU server; what is left is in §1 | nothing |
| 2 | [SPICE backend](#2-spice-backend) | **implemented and validated against a real QEMU guest**, agent and clipboard included (§2.6); what is left is in §2.7 | nothing |
| 3 | [Validate against real Moonlight](#3-validate-against-real-moonlight) | **done** — a real `moonlight-common-c` client streams from this host; the eight defects it found are in §3 | nothing |
| 4 | [Captured golden vectors](#4-captured-sunshine--moonlight-vectors) | days | nothing |
| 5 | [`solstice pair` management socket](#5-solstice-pair-and-a-management-socket) | ~2 days | nothing |
| 6 | [The still-frame encode cost](#6-the-still-frame-encode-cost) | ~2 days | nothing |
| 7 | [ENet: audit or reimplement](#7-enet-audit-or-reimplement) | 1–3 weeks | nothing |
| 8 | [Smaller items](#8-smaller-items) | varies | |

§4 is next. With §3 done, the place where a wrong assumption made consistently
at both ends still passes is CI, which has no `mlc-probe` in it.

---

## 1. Tight encoding (RFB)

**Done.** `crates/solstice-vnc/src/encodings/tight.rs` decodes fill and basic
compression with the copy, palette (both widths) and gradient filters, over
four independently resettable zlib streams. It is advertised first in
`ENCODINGS`, ahead of ZRLE, and **lossless-only**: no JPEG quality level is
advertised, and a JPEG rectangle is a protocol error. The byte layout,
with line references, is `docs/rfb-vnc-protocol.md` §5.1.

### Why it was worth doing

Not for performance, and the measurement agrees (below). The reasons were
**compatibility** — Tight is what TigerVNC, TurboVNC and libvncserver prefer,
and negotiating them all down to ZRLE ran every server on a path it uses less
often — and **bandwidth off-loopback**, should `docs/security.md` §6.8's
loopback-or-tunnel constraint ever be relaxed.

### The JPEG question, settled from source

The plan said to verify, not assume, that a server sends no JPEG to a client
that never asked for a quality level. Both servers were read:

- **TigerVNC**: `TightJPEGEncoder::isSupported` is false unless the client sent
  a quality level, a fine quality level or a subsampling level.
- **QEMU**: every client starts at `tight.quality = -1`, *"lossless by
  default"*, and the JPEG path is gated on it. Its gradient filter is further
  gated on the display's `lossy` option, so a default QEMU never sends one.

So no JPEG decoder was needed, and no `zune-jpeg` dependency was taken.
`set_encodings_lists_what_we_can_actually_decode` now asserts that no quality
level (−23..−32) and no Tight PNG (−260) is ever listed.

### How it is tested

- **Unit tests** in `tight.rs` per sub-encoding: fill (including that it is
  one TPIXEL and nothing else, and is exempt from the 2048 width limit), copy
  with and without a filter id, both palette widths with padded rows, the
  gradient filter by hand and by round trip, at 888 and 565, and the
  under-12-bytes raw path, including that it leaves the stream alone.
- **Four-stream continuity** (`four_streams_stay_continuous_independently`),
  a **reset mid-session** carried on a fill that must restart only the named
  stream, and the negative: a missed reset is an error, not garbage.
- **Decompression bombs**: a chunk is inflated with its rectangle's exact size
  as the cap, so a bomb is stopped at a few kilobytes rather than at 64 MB,
  and a chunk that inflates short is refused as well.
- **The mock** emits Tight on request (`MockConfig::offer_tight`), choosing
  the sub-encoding by colour count the way real encoders do and spreading
  rectangles across all four streams as QEMU does. `mock_server.rs` round-
  trips every sub-encoding exactly, twice, with a full stream reset between.
- **A real server**: `real_server.rs` offers QEMU **only** Tight and requires
  the decoded framebuffer to equal QEMU's screendump exactly. QEMU used fill,
  copy and both palette widths on three of the four streams to draw it.
  Breaking the TPIXEL byte order makes 463 344 of 480 000 pixels differ.
- **Fuzzing**: `rfb_rect` reaches `tight::decode` from the wire and
  `tight::decode_pixels` directly; 5.3 million runs, clean.

### Measured

`encoding_bench.rs` has a Tight row. Two runs on this machine, against the
QEMU guest under TCG rather than KVM (the user running them was not in the
`kvm` group), so the absolute numbers are not comparable with the `Xvnc` table
in `docs/implementation-notes.md` §3 -- only the rows with each other:

```
encoding                     MB/s   updates     CPU %   MPixel/s  bytes/pixel
ZRLE                         0.74       188      12.0      21.89        0.034
Tight                        0.63       158       8.8      18.33        0.034
ZRLE                         0.75       183      11.8      21.80        0.034
Tight                        0.69       174       9.8      20.72        0.033
```

Same bytes per pixel. Tight costs this client about 13% less CPU per pixel
(0.47–0.48% of a core per MPixel/s against ZRLE's 0.54–0.55). Throughput was
slightly lower; the likeliest cause is QEMU's side, which defaults Tight to
compression level 9 and was itself running under TCG, but that has not been
isolated. Neither moves the number
that matters, the H.264 encoder at 36–83% of a core.

### What is left

- **No TigerVNC or libvncserver Tight server has been tested against.** QEMU
  is the only real Tight encoder that has met this decoder, and it never sends
  the gradient filter. The gradient path is covered by unit and mock tests
  only — an implementation of our own reading, which is exactly the class of
  risk §3 warns about. libvncserver's encoder (`x11vnc`) has a gradient path
  and is the obvious second server; whether it can be made to take that path
  without a quality level has not been checked.
- **Basic compression without zlib** (`1010`, `1110`) needs its own
  pseudo-encoding and is not advertised; it would only help on loopback, where
  the zlib cost is already a small fraction of the encoder's.
- **No compression-level pseudo-encoding** (−256..−247) is sent. QEMU's level-9
  default costs the server CPU for bytes that cross loopback; asking for a
  lower level is a one-line change worth measuring on a real deployment.

---

## 2. SPICE backend

**Implemented and working against a real server.** `crates/solstice-spice`,
behind the `spice` Cargo feature. `backend.kind = "spice"` builds a working
backend, and `tests/real_server.rs` drives it against a live `spice-server`
inside a booted QEMU guest — across every image codec, video streams, input,
and a real `spice-vdagent` (§2.6) — resize, absolute mouse and the clipboard.
What is left is the QXL draw-command assertions and audio (§2.7), plus the
deliberate omissions in §2.5.

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
| `agent.rs` | `spice-vdagent`: `MONITORS_CONFIG` resize, capability exchange, the by-demand clipboard, token flow control |
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

**M6 — the agent.** `MONITORS_CONFIG`, capability exchange, and the clipboard.
`request_resize` returns `false` when there is no agent, which is the same
best-effort contract the RFB backend's `ExtendedDesktopSize` has, and every
clipboard call on the session reads the same way.

The clipboard was finished afterwards, and the two things that mattered were
both found by pointing a real `spice-vdagent` at it rather than by reading:

- **the capability gate.** `vdagentd`'s `send_capabilities` sets
  `CLIPBOARD_BY_DEMAND` and never the bare `CLIPBOARD` bit, so a gate wanting
  both — which is what the first draft had — refuses every guest in
  existence. `spice-gtk` gates on the single bit too.
- **`VD_AGENT_MAX_CLIPBOARD`.** Without it the 1 MiB ceiling on a
  reassembled agent message is enforced only on arrival, and arriving past it
  ends the main channel, because the reassembler cannot walk past a message
  it refused to buffer. Declaring the ceiling moves the enforcement into the
  guest, where an oversized selection is simply never sent. The guest's log
  answers with `Set max clipboard: 1048572`.

`CLIPBOARD_SELECTION` is deliberately **not** announced, and that is what
keeps the framing simple: with it, every clipboard message grows a four-byte
`VDAgentClipboardSelection` in front of its type, and `spice-vdagent` decides
whether to write that prefix from the *client's* announcement rather than its
own. Leaving it out keeps both directions unprefixed and the selection at
X11's `CLIPBOARD`, which is the one a paste uses; `PRIMARY` is middle-click,
which no GameStream client can ask for. Both real-server tests confirm the
unprefixed framing in the direction they drive.

**M7 — audio.** Opus packets are forwarded as `AudioFormat::Opus` rather than
decoded, which is the repacketise-not-transcode path §7 of the protocol notes
hoped for. Whether the pipeline can pass them straight through is now
answered, by measurement against a real guest: `spice-server` sends 10 ms
stereo packets and Moonlight asks for 5 ms unless the client is slow or the
stream is thin, so in the common case it cannot (§2.7).

### 2.4 How it is tested

- **235 unit and mock tests** in the crate, plus the 88 in
  `solstice-spice-codec`.
- **A mock server** (`mock.rs`, `tests/mock_server.rs`) that mints a real
  1024-bit RSA key and decrypts a real ticket, so the OAEP path is exercised
  rather than stubbed. Its guest agent announces `vdagentd.c`'s capability
  set rather than this client's, so the two can disagree — see §2.6 for the
  bug that cost. It covers the negative cases `docs/testing.md` §4.2
  names: a wrong password, a link error, `NEED_SECURED`, a server with no
  display channel, a `SpiceDataHeader` whose `size` overruns, and both header
  framings.
- **Two fuzz targets**, `spice_draw` and `spice_message`. They have already
  paid for themselves: `spice_draw` found a `COPY_BITS` whose destination
  rectangle asked for a 174 GB allocation on a 64 × 48 surface, and a
  zero-stride stencil mask that indexed an empty row. Both have named
  regression tests.
- **`tests/real_server.rs`** drives a live `spice-server` in a QEMU guest:
  every image codec, video streams, input against an `xev` oracle, and both
  the agent-granted resize and the refusal without one. §2.6 is the account
  of what it covers and what it found. It skips with a printed note when
  QEMU or the guest image is absent.

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
- **The clipboard has no sink *in the seam*.** The exchange itself is
  finished and validated (§2.6): `SpiceSession` can offer, request, send and
  decline a payload, and a guest's own grabs, requests and releases arrive on
  `subscribe_clipboard()`. What is deliberately absent is a route from there
  to Moonlight, because GameStream has no clipboard channel to carry one —
  so the API is SPICE's own rather than a method on
  `solstice_backend::Session`, and `BackendEvent` stays `Copy` and
  clipboard-free. Anything embedding `SpiceSession` can drive it; the
  real-server tests are the first thing that does.

### 2.6 Validated against a real server

**A real QEMU guest has answered it.** `crates/solstice-spice/tests/real_server.rs`
runs thirteen tests against a live `spice-server` inside a booted guest, and
they pass. This was `Xspice` first, which links the same library and covered
the protocol well; the guest was what it took to reach everything *above* the
protocol, because the packaged `Xspice` launcher cannot start a
`spice-vdagent` at all. What it covers:

| | |
|---|---|
| Link and session | the handshake, the RSA-OAEP ticket, capability negotiation, `MAIN_INIT`, `CHANNELS_LIST`, four channels, the ack window |
| Display | surfaces, draw commands, incremental updates, every pixel of a repaint; lines, glyphs and an XOR stipple through the real QXL driver, each held against QEMU's own screendump pixel for pixel |
| Image codecs | `off`, `quic`, `lz`, `glz`, `auto_glz`, each forced with `image-compression=`, and **counted**: each test asserts that the images it decoded after its repaint were of the forced kind, and that the screen equals QEMU's screendump |
| GLZ over a long session | the soak in §2.7, on demand rather than per merge |
| Video streams | `streaming-video=all`, MJPEG negotiated by `PREFERRED_VIDEO_CODEC_TYPE`, decoded and composited into a clipped sub-rectangle |
| Input | pointer and keyboard reaching the guest, verified with `xev -root` as the oracle |
| Mouse mode | client mode granted and in force **by a real `spice-vdagent`**; absolute positions land where they were sent |
| The agent | `MONITORS_CONFIG` resize granted, applied by the guest, and the new geometry tracked back by the client (virtio-gpu; see `testing.md` §4.1) |
| The clipboard | both directions through a real `spice-vdagent`: a guest `xclip` copy offered, requested and delivered byte for byte, and this client's offer requested by the guest, answered, pasted by `xclip -o`, then withdrawn so the paste stops finding an owner |
| Audio | a tone from `speaker-test` arriving as Opus, 48 kHz stereo, every packet 10 ms by its TOC byte |

Every test connects to a **black** screen, repaints it **while connected**,
and asserts the pixels. That shape matters: a client that only ever sees the
screen as it was at connect time can be completely broken for incremental
updates and still pass, which is the mistake the first draft of that file
made.

#### Two bugs it found that the mock could not

Both were in the join between the pieces rather than in any one of them,
which is exactly what a real peer is for.

1. **The mouse mode in `MAIN_INIT` was being thrown away.** A real
   `spice-server` reports client mouse mode in `MAIN_INIT` itself; the mock
   granted it in a later `MAIN_MOUSE_MODE`. `MAIN_INIT` is consumed by the
   setup loop inside `connect`, so the mode never reached the input state and
   the session stayed in server mode -- sending relative deltas, which a
   tablet-only server drops on the floor. The pointer did not move at all.
2. **`connect` returned before the primary surface arrived**, so the first
   caller of `dimensions()` got `0x0`. RFB has no equivalent problem because
   `ServerInit` carries the size in the handshake; SPICE sends it as an
   ordinary message on another socket.

Both have regression tests in `tests/mock_server.rs`, written so the mock now
reproduces the real server's behaviour rather than its own.

Finishing the clipboard added a third, of exactly the same kind. The
capability gate was written as "the guest announced `CLIPBOARD` **and**
`CLIPBOARD_BY_DEMAND`", which is what the header's naming suggests. A real
`vdagentd` sets only `BY_DEMAND`, so the gate refused every guest there is,
and the first run against the guest said so immediately.

The mock had agreed with it, and for the structural reason this file keeps
warning about: it announced the guest's capabilities by calling *this
client's* own `announce_capabilities`, so it could never disagree about one.
It now announces `vdagentd.c`'s set instead — `BY_DEMAND` without the bare
bit, and `CLIPBOARD_SELECTION`, which this client does not announce. With
that change, reintroducing the bug fails seven mock tests rather than none,
which is the position the mock is supposed to be in.

#### What counting found

The session now reports how many of each draw command it has executed and of
each image encoding it has decoded (`SpiceSession::draw_counts` and
`image_counts`). The point was to close the first item of §2.7. The first run
with the counts in place showed that two of the tests above had been passing
without testing what they were named for, and the investigation that
followed found two client bugs.

1. **The codec sweep exercised no codec.** Every one of the five tests decoded
   exactly one image, an `LZ_RGB`, whatever `image-compression=` it forced.
   That image was the screen QEMU sends on connect. The repaint the test
   asserted on arrives as a `DRAW_FILL`, which carries no image at all. The
   tests now draw glyphs and a stipple after the repaint, which the QXL
   driver sends as bitmaps, compare the screen with QEMU's screendump, and
   assert that the images decoded *after the repaint* are the forced kind.
2. **This client overrode the server's codec.** With the sweep fixed, `off`
   and `quic` still decoded GLZ. `DISPLAY_INIT` was followed by an
   unconditional `PREFERRED_COMPRESSION = AUTO_GLZ`, and `spice-server` does
   not weigh that against its own configuration: it adopts it. So whatever
   an operator gave QEMU, a Solstice session got GLZ. `spice-gtk` sends a
   preference only if its user set one. This client now does the same:
   `SpiceConfig::preferred_compression`, default `None`.
3. **Client mouse mode was asked for once, too early.** It was requested only
   in answer to `MAIN_INIT`, and only if the server already offered it then.
   An agent that attaches later is announced in `MAIN_MOUSE_MODE` instead, and
   the request never followed. That happens with any guest still booting or
   any agent that restarts. The session then stayed in server mode for good,
   sending relative motion that a tablet-only guest drops. Under TCG the
   input test hit this every time. The client now asks again on every
   `MOUSE_MODE` that offers client mode, as `spice-gtk`'s `set_mouse_mode`
   does, and has a unit test for the late case.
4. **`DRAW_STROKE`, `DRAW_TEXT` and `DRAW_ROP3` are not reachable from this
   guest at all.** `solstice-draw stroke|text|rop3` was written to force them
   out of the QXL driver, and the earlier claim that it did had only ever
   been checked against the screendump. Counted, a 64-line stroke arrives as
   about 480 one-pixel `DRAW_FILL`s and the glyphs and the stipple as
   `DRAW_COPY`s. `xf86-video-qxl` accelerates fills, copies, composites and
   uploads, and renders everything else in software first.
   `core_x11_primitives_reach_the_screen_exactly_through_fills_and_copies`
   now asserts what is true, and fails if one of the three ever does appear.

One more was in the test harness rather than the client, and cost the most
time, because it presents as a guest bug. With the counts in place a stroke
took 57 seconds inside the guest and then delivered nothing. `#[tokio::test]`
is single-threaded, and the `Guest` calls block the thread, so the whole
SPICE client was frozen for as long as the guest command ran. A stroke is
more messages than the server's ack window. `spice-server` stopped sending
until it was acked, stopped draining the QXL ring while its pipe was full, and
the X server blocked in `qxl_ring_push`, so the command never returned. After
30 seconds without a pong the server dropped the client and everything came
unstuck at once. Every test in `real_server.rs` is now multi-threaded, and the
module comment says why.

#### Running them

The guest is built once and cached; the tests skip with a printed note when
it or QEMU is absent.

```sh
./tests/guest/build-image.sh
cargo test -p solstice-spice --test real_server -- --test-threads=4
# the GLZ soak, minutes long; SOLSTICE_GLZ_SOAK_ROUNDS lengthens it
cargo test -p solstice-spice --test real_server -- --ignored glz_soak
```

The SPICE tier needs QEMU's SPICE support, which Debian packages separately
as `qemu-system-modules-spice`. Without it every test here skips, because
`-spice` is not recognised.

`docs/testing.md` §4.0 carries the part worth knowing before writing a new
one: QEMU drops guest damage while no display client is attached, so a test
must connect *before* it repaints, and the guest needs its own painter
because `xsetroot -solid` does not survive the process that issued it.

### 2.7 What is still unvalidated

Smaller than it was. Each item says what would close it.

All three agent items are now closed: resize, client-mode absolute mouse and
the clipboard are each validated against a real `spice-vdagent` (§2.6).

- **`DRAW_STROKE`, `DRAW_TEXT` and `DRAW_ROP3` have still never been seen
  from a real server**, and the Linux guest cannot change that (§2.6, item
  4). Their executors and the raster-operation mapping behind them are
  unit-tested only. A Windows guest with the QXL display driver is the source
  to try next. It is not known for certain to emit them either, so check
  with the counts before building on it.
- **Audio is measured, not yet wired.** `spice-server` sends Opus at 48 kHz
  stereo in 10 ms packets. Moonlight asks for 5 ms by default and 10 ms only
  for a slow decoder or a stream under 5 Mbit/s (`SdpGenerator.c`), and it
  sizes its decoder buffer from that. So passing packets through works only
  when the client asked for 10 ms. The default needs a decode and re-encode,
  and so does surround. Meanwhile the supervisor sends Opus silence
  whatever the backend, so none of this reaches a client yet. Wiring it in
  means an Opus decoder and encoder in the tree, and that is the actual
  remaining work.
- **The GLZ soak exists, and nothing runs it on a schedule.**
  `glz_soak_keeps_the_screen_exact_across_thousands_of_images` repaints with
  changing content and compares the screen with QEMU's screendump every
  twenty rounds. It has run clean for 3,000 rounds: 36,000 GLZ images and
  25.6 million fills over 46 minutes, with the screen exact at every check.
  Nothing has yet been found wrong in the GLZ window itself.
- **The soak sometimes stalls, and the cause is not found.** Three of five
  runs, after the runtime fix in §2.6, stalled a few minutes in. Each time a
  guest command hung because its X server was blocked on a full QXL ring.
  The client's runtime was alive (a task printing its counters kept
  printing), but the session received nothing more. QEMU's threads were
  all idle, and the SPICE worker was waiting in its poll loop, which is what
  it does when it is waiting on a client's `ACK` or socket. That points at the
  join between this client's display channel and the server. Candidates
  include an `ACK` dropped by `try_send` on a full queue, or a task parked
  somewhere unexpected. It is not certain the harness is innocent either.
  **Until it is explained, treat it as able to hang a real session.** What
  closes it: a backtrace of the test process at the moment of a stall.
  `gdb -p` works on this box. One capture caught QEMU's side but attached to
  the wrong process for the client.
- **Nothing is tuned.** The rasteriser's inner loops are per-pixel closures.
  A debug build keeps up with a scrolling terminal over MJPEG; nothing
  heavier has been measured, and it should be measured against a real frame
  rather than guessed at.
- **GLZ out-of-order images are refused, not awaited.** `spice-gtk` blocks on
  a coroutine when a match refers to an image that has not arrived. With one
  display channel the case does not arise, because one channel delivers in
  order. A multi-monitor guest with several display channels would need the
  window shared and the wait reinstated.

Two things that are *not* on this list, because they turned out to be
properties of the environment rather than of the backend:

- **QXL cannot be resized by any client here**, Solstice or `remote-viewer`.
  Established by controlled experiment; `docs/testing.md` §4.1 has the
  account, and the agent tests use virtio-gpu for this reason.
- **Fence and ContinuousUpdates have no third-party server** now that the RFB
  tier is QEMU's server, which implements neither. Covered by the mock, which
  is weaker in the specific way §3 warns about, and recorded in
  `docs/testing.md` §3.1.

---

## 3. Validate against real Moonlight

**Done.** `tests/tools/mlc-probe/` is a driver linking the real
`moonlight-common-c` -- the library every Moonlight port shares -- built with
`LC_DEBUG` (which turns on `FEC_VALIDATION_MODE` and the `LC_ASSERT_VT`
checks on host-supplied values) and `LC_DEBUG_RECORD_MODE`.
`crates/solstice/tests/real_moonlight.rs` pairs, launches, hands the session
to the probe, and asserts on what came back: thirty decoded frames, SPS and
PPS where the format says they are, audio unwrapped, the recorded elementary
stream decoded and its barcode counter increasing, and the input the probe
sent arriving at the backend over ENet. Both skip with a printed note when the
probe has not been built.

The probe does the streaming half only. Pairing, `/serverinfo` and `/launch`
are mutual-TLS HTTP that `moonlight-common-c` does not implement -- each port
has its own app layer for that -- so the harness performs them and passes the
negotiated parameters in.

### What it found

Eight defects, in the order they surfaced. Every one of them was invisible to
the end-to-end test, because that test's client was written from the same
notes as the server and agreed with it.

1. **The encrypted-RTSP IV was missing its tag bytes.** `iv[10]` is `'C'` or
   `'H'` for the originator and `iv[11]` is `'R'` for the RTSP stream
   (`RtspConnection.c:122-132`); Solstice zeroed both. The host refused the
   client's first `OPTIONS` with an authentication failure. The byte order --
   risk 2 on the old list below -- turned out to be right; the fixed field
   nobody had looked for was not.
2. **RTSP is one message per TCP connection**, terminated by the host closing
   it (`RtspConnection.c:386-517`). Solstice held one connection open for the
   whole negotiation and kept its state machine on it. Fixed by replying and
   closing, and moving the negotiation state -- stage ordering, streams set
   up, and the encryption sequence number -- to the launch session.
3. **`X-SS-Connect-Data` was never sent.** It is how the client learns the
   ENet connect data; absent, it connects with `0`, and the host refused the
   peer as belonging to no session. Dead at
   `STAGE_CONTROL_STREAM_ESTABLISHMENT`.
4. **The control port was bound after waiting for the video ping.** The client
   establishes ENet *before* starting the video stream that sends the ping
   (`Connection.c:483-497`), so the two sides waited for each other. Our test
   client pinged immediately and never showed it.
5. **`X-SS-Ping-Payload` was never sent**, so the client fell back to the
   4-byte legacy `"PING"` -- which this host refuses on purpose as
   unauthenticated (`docs/security.md` §2.3). The host therefore never learned
   where to send and the client timed out with `ML_ERROR_NO_VIDEO_TRAFFIC`.
   The refusal was right; it was only safe once the payload was actually
   handed out.
6. **The FEC parity covered the wrong bytes.** Caught by
   `FEC_VALIDATION_MODE`: `nvPacket->flags == droppedNvPacket->flags` failed.
   The NV header has to be written *before* the Reed-Solomon encode and only
   the fields Sunshine patches afterwards -- the RTP header, `fecInfo`,
   `multiFecBlocks`, `frameIndex` -- written after it
   (`docs/moonlight-sunshine-protocol.md` §5.4). Solstice zeroed all 32 header
   bytes for the encode, so nothing in the NV header survived recovery.
7. **The declared FEC percentage did not re-derive to the parity count.** When
   `minRequiredFecPackets` bumps the count, the percentage must be recomputed
   as `100*P/D`; Solstice bumped the count and declared the configured
   percentage, so the client built a Reed-Solomon matrix a row short of the
   host's and every recovery was silently wrong. Also caught by the FEC
   oracle.
8. **Audio FEC blocks did not start on a multiple of four.** Solstice reserved
   sequence numbers for its parity shards, giving bases of 0, 6, 12; the
   client requires multiples of four and switches audio FEC off for the whole
   session otherwise (`RtpAudioQueue.c:269-280`). Sunshine's parity packets
   borrow the next two sequence numbers without consuming them.

Two of the three risks named when this item was written are closed by
inspection rather than by a bug:

- **The ENet control channel** (risk 1) works against a real peer, including
  input: the probe sends a fixed script of pointer, button, keyboard and
  scroll events and the test asserts each one reaches the backend.
- **`NV_KEYBOARD_PACKET.keyCode` endianness** (risk 3) is confirmed correct,
  and now from the source rather than from the absence of a macro:
  `InputStream.c:952` writes `LE16(keyCode)`, which is the little-endian read
  Solstice already had.

### What is still not covered

- **No third-party Moonlight *application* has connected.** The probe is the
  shared protocol core, which is the part that matters, but moonlight-qt's
  own HTTP layer, its certificate handling and its platform decoders are not
  exercised. That is the manual tier (`docs/testing.md` §8).
- **Only the encrypted paths.** The probe asks for `ENCFLG_ALL`, so the
  plaintext RTSP and unencrypted video paths still have only our own client.
- **Only H.264 at one geometry**, and only against the colour-bar backend.
- **No loss.** `FEC_VALIDATION_MODE` exercises recovery on every frame, but
  the real network is loopback; §5 of `docs/testing.md` is still the plan for
  injected loss.

## 4. Captured Sunshine ↔ Moonlight vectors

`docs/testing.md` §2.4 calls this *"the highest-value artefact early on"* and
says to capture it **before** writing the packetiser. That did not happen. It
is the gap that catches a field-offset or endianness error both of our ends
make consistently. §3 now catches those too, and caught eight of them — but it
needs a C toolchain, a network to fetch `moonlight-common-c`, and a minute to
build. Frozen vectors are what put the same coverage in CI.

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
the subset Moonlight actually uses. §3 is done, so "the subset" is now a
finite thing that can be read off a real session: `mlc-probe` establishes the
peer, sends input and tears the connection down over it.

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
