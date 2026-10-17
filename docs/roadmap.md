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

§4, the captured vectors, is done as well. It was expected to be
regression-pinning rather than discovery, and found two more defects anyway,
both in places the probe had passed over (§4).

What is left is ordinary work.

| | Item | Size | Blocked on |
|---|---|---|---|
| 1 | [Tight encoding](#1-tight-encoding-rfb) | **done** — lossless, advertised first, and exact against a real QEMU server; what is left is in §1 | nothing |
| 2 | [SPICE backend](#2-spice-backend) | **implemented and validated against a real QEMU guest**, agent, clipboard and audio included (§2.6, §2.8); what is left is in §2.7 | nothing |
| 3 | [Validate against real Moonlight](#3-validate-against-real-moonlight) | **done** — a real `moonlight-common-c` client streams from this host; the eight defects it found are in §3 | nothing |
| 4 | [Captured golden vectors](#4-captured-sunshine--moonlight-vectors) | **done** — a real session, frozen and replayed in CI; the two defects it found are in §4 | nothing |
| 5 | [`solstice pair` management socket](#5-solstice-pair-and-a-management-socket) | **done** — `pair`, `status`, `list-clients` and `revoke` reach the running daemon, and a revocation ends a stream already running; what is left is in §5 | nothing |
| 6 | [The still-frame encode cost](#6-the-still-frame-encode-cost) | **done** — a still screen drops to a keep-alive rate, about 12× cheaper, and a real `moonlight-common-c` sits through it; what is left is in §6 | nothing |
| 7 | [ENet: audit or reimplement](#7-enet-audit-or-reimplement) | **done** — reimplemented: the subset Moonlight uses, stricter than ENet before authentication, and held against upstream ENet under loss, the captured session and the real client; what is left is in §7 | nothing |
| 8 | [Smaller items](#8-smaller-items) | varies | |

§6, the still-frame cost, is done too: an idle 1080p60 session went from 56%
of a core to under 5%. And §7, ENet, the last item on the pre-authentication
path: `rusty_enet` is gone from the daemon, replaced by a few hundred lines of
the subset Moonlight actually uses. What is left is §8 and the "what is left"
lists under each item.

§2's audio is wired as well (§2.8). A tone played in a real guest reaches the
real client, passed through or re-encoded as the client's request requires,
and a 7.1 client, which could not connect before, now can.

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
Guest audio reaches a Moonlight client (§2.8). What is left is the QXL
draw-command assertions (§2.7), plus the deliberate omissions in §2.5.

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
| `playback.rs` | guest audio, handed on in the format the server sent; whether it can go to the client untouched is decided in `solstice-audio` (§2.8) |
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
stream is thin, so in the common case it cannot. §2.8 is what does it.

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
| Audio | a tone from `speaker-test` arriving as Opus, 48 kHz stereo, every packet 10 ms by its TOC byte; and, with the daemon and the real client added, a seamless tone heard in the client's front pair, passed through at 10 ms and re-encoded at 5 ms (§2.8) |

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
- **The GLZ soak exists, and is run by hand.** Nothing schedules it, by
  decision (`docs/testing.md` §6).
  `glz_soak_keeps_the_screen_exact_across_thousands_of_images` repaints with
  changing content and compares the screen with QEMU's screendump every
  twenty rounds. It has run clean for 3,000 rounds: 36,000 GLZ images and
  25.6 million fills over 46 minutes, with the screen exact at every check.
  Nothing has yet been found wrong in the GLZ window itself.
- **The soak stall is explained, and it is not in this client.** Under TCG
  the soak still stalls: 5 of 6 baseline runs, between rounds 299 and 2,639.
  It was traced in three steps.
  - **The client is idle and up to date.** At each stall, every socket queue
    between client and QEMU was empty in both directions, before and after a
    five-second wait. Both runtime workers were parked. Counting on the
    display channel showed 10.6 million messages received and one `ACK` per
    20 sent, none dropped. By `spice-server`'s own rule
    (`red-channel-client.cpp`, `waiting_for_ack`) that leaves it 19 messages
    into a window of 40, so it was not waiting for an `ACK`. A missing
    `ACK`, the leading suspect, is ruled out.
  - **The guest's X server is blocked in its QXL driver.**
    `Guest::stall_report` asks the guest agent, which still answers. Xorg was
    in uninterruptible sleep in `qxl_fence_wait`, under
    `qxl_execbuffer_ioctl` → `qxl_alloc_release_reserved` → TTM eviction. It
    is waiting for the device to release memory before it can submit
    another command. The server has nothing to send because the guest submits
    nothing, and the guest submits nothing because the server has not
    released the memory.
  - **It is the guest kernel's known regression.** The guest runs Linux
    6.18, whose `qxl_fence_wait` is the simplified version upstream reverted
    in April 2024 for exactly this, `[TTM] Buffer eviction failed` under
    load (Debian #1054514). A month later it was reapplied to fix a boot
    hang, with the note that the eviction failures "may obviously" return.
    The client's only lever on what the server holds is the GLZ window it
    declares, and that is not the cause either. Windows of 64, 24 and 1 MiB
    all stalled.

  More QXL memory avoids it. With the device's RAM at 128 MiB, twice QEMU's
  default, two TCG soaks ran all 3,000 rounds clean. A third was clean to
  round 1,259 when a time limit stopped it. With the default, 5 of 6 runs
  stalled. The soak exists to exercise this client's GLZ decoding, not the
  guest kernel's memory handling, so its guest now gets 128 MiB
  (`GuestConfig::qxl_ram_mb`), and every other test keeps the default
  device. **For a real deployment:** a Linux guest on a QXL device can stall
  this way under heavy drawing. The client had nothing outstanding when it
  did, so no client-side change is known to help, and a larger
  `qxl-vga.ram_size_mb` is the mitigation. Only TCG has reproduced it.

  Two things are changed here. The soak's guest calls now print
  `Guest::stall_report` when they time out. The SPICE tests also install a
  log subscriber, warnings on by default, because the client reports a
  failed display by logging and closing it, and without a subscriber that
  looked like a server gone quiet. `SOLSTICE_GUEST_ACCEL=tcg` forces TCG on
  a host with KVM, which is where this reproduces; with KVM a 3,000-round
  soak ran clean in six minutes.
- **A busy server froze the picture.** The display task published damage
  only when its queue went momentarily empty. A server drawing faster than
  the client rasterises never lets it empty. Under KVM, a debug build fell
  that far behind a scrolling terminal, and
  `mjpeg_streams_are_decoded_and_composited_over_the_draw_output` saw no
  updates at all while decoding carried on. Batches are now capped at 8 ms,
  and `a_queue_that_never_empties_still_publishes` fails without the cap.
- **Nothing is tuned, and a debug build shows it.** The rasteriser's inner
  loops are per-pixel closures. Under KVM an unoptimised client fell behind
  a scrolling terminal badly enough to fail the MJPEG test: about 130 ms per
  GLZ image, and 16 updates where the test needs 50. The dev profile now
  optimises `solstice-spice` and `solstice-spice-codec`, as it already did
  the RSA crates. Overflow checks and debug assertions stay on. A release
  build passed with or without that. Tuning should still be measured
  against a real frame rather than guessed at.
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

### 2.8 Audio, wired

**Done.** `crates/solstice-audio` sits between the backend's audio and the
client's stream, and `crates/solstice/src/audio.rs` sends what it makes, one
packet per negotiated duration.

- **Pass-through where it lines up.** `spice-server` sends 10 ms stereo
  Opus. A client that asked for 10 ms stereo gets those packets untouched.
  Every other client gets them decoded and re-encoded with libopus
  (`opusic-c`) in its own layout and duration, at Sunshine's bitrates, CBR,
  `RESTRICTED_LOWDELAY`. Raw S16, which `spice-server` sends when it has no
  Opus, takes the encode half of the same path.
- **Surround is offered, and stereo is upmixed into it.** DESCRIBE used to
  say `surround-params=NONE`, so a 5.1 client fell back to a layout of its
  own and a 7.1 client failed the connection ("No surround parameters
  found"). It now offers all six layouts Sunshine does, normal and high
  quality for 2, 5.1 and 7.1, written so that the client's rotation of the
  normal-quality mapping leaves it with the identity
  (`stream/opus_layout.rs`). The layout follows the client's choice: the
  `Host:` header for stereo, `x-nv-audio.surround.AudioQuality` for
  surround. SPICE's stereo lands in FL and FR and the rest is silent.
- **Silence is encoded, not canned.** The old silence packet is single-stream
  Opus, which no multistream decoder accepts for a surround layout. Silence
  now comes out of the session's own encoder, so it is valid whatever was
  negotiated. That includes RFB, which still has no audio of its own.
- **A small jitter buffer.** The server sends only while the guest plays,
  in 10 ms bursts. Nothing plays until 20 ms are queued, an underrun sends
  silence and refills, and more than 100 ms queued is trimmed back to 20,
  because accumulated latency never drains on its own.

#### How it is tested

| Tier | What |
|---|---|
| Unit (`solstice-audio`) | pass-through and its conditions, two 5 ms packets per SPICE packet with the tone intact, stereo into the front pair of 5.1 and nothing elsewhere, decodable silence for a surround layout, the prebuffer, underrun and trim, mono, partial frames, stale leftovers, unusable frames counted rather than fatal |
| Unit (`solstice-gamestream`) | the DESCRIBE lines run through a transcription of the client's parser, and land on the identity for every layout; the quality flag from the header for stereo and the attribute for surround |
| Real client (`real_moonlight.rs`) | the test pattern's tone through the daemon to `mlc-probe`, once per layout: stereo at 5 ms and at 10 ms, 5.1 and 7.1 each at normal and high quality. The probe reports the decoder the client built from DESCRIBE and dumps every packet it was handed; each is decoded with that decoder, must be the duration the client sized for, and the tone must be in FL and FR and nowhere else |
| Real server and real client | `the_reference_client_hears_a_real_spice_guest` (`--features spice`): a seamless tone played by `aplay` in the QEMU guest, through `spice-server`, the daemon and the probe, at 10 ms (passed through: the server's packets, not the bridge's size) and 5 ms (re-encoded) |
| Fuzzing | `audio_bridge`: arbitrary frames, any format and channel count, through every layout. Clean for three minutes, 192,000 runs. Coverage guides it through the Rust only: libopus is built by CMake without the instrumentation flags |

#### What it found

- **Pass-through never happened against the real server.** The check
  compared the whole eight-entry mapping, and the negotiated stereo layout
  fills the unused entries differently from the codec's own stereo constant.
  Every unit test built its layout from the constant. Only the full chain,
  with the daemon translating the negotiated layout, showed the 10 ms client
  getting re-encoded packets. Fixed, with a regression test built the way the
  daemon builds it.
- **`MissedTickBehavior::Delay` loses audio.** Under load, a tick more than
  5 ms late pushes every later tick back, so the sender fell to about 150
  packets a second against the client's 200. The backend kept real time, the
  queue overflowed, and each trim was an audible jump. It showed as a tone
  whose purity fell to 0.1 in the debug-build end-to-end test, where
  OpenH264 shares the runtime. The sender now uses `Burst`, and makes up a
  late tick at once. The old silence sender had the same flaw, inaudible
  because silence has no phase to break.
- **`speaker-test -c 2` is not a stereo tone.** It plays the channels in
  turn. The guest test writes one period of a 480 Hz sine (exactly 100
  samples at 48 kHz) and loops it into `aplay` instead.

#### What is left

- **moonlight-qt has played it, by ear.** 2026-10-17, the Flatpak build over
  a 220 ms link, at 1080p60 and 15.5 Mbps -- 5 ms packets, so re-encoded --
  heard the guest in stereo, 5.1 and 7.1 (high quality: 6 and 8 uncoupled
  streams). Clean, on the right sides, no audible stutter, and the daemon
  counted no underruns in 100 s of stereo. Each session also logged
  `dropped=119`: about 1.2 s of audio that queued between the SPICE connect
  and the audio task starting, trimmed as the jitter buffer should. Starting
  the task sooner would save decoding it. Nothing measured the latency.
- **Nothing is resampled.** A backend at a rate other than 48 kHz is
  dropped, with one warning per session. `spice-server` sends 48 kHz in both
  modes, so a resampler would be code with no source to test it.
- **Downmixing is naive.** More channels in than out keeps the first ones.
  QEMU's SPICE audio is stereo, so nothing exercises it.
- **The prebuffer is not tuned.** 20 ms absorbs the jitter seen here, and an
  underrun or two per session at 10 ms is normal on a loaded host. It adds
  that much latency; nothing has measured whether a real client would
  rather have less.
- **`cmake` is a build requirement again**, for `opusic-sys`, in any build
  with the `audio` feature, which is on by default (`PROJECT-LAYOUT.md` §4).

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

- **moonlight-qt has connected, by hand, once.** 2026-10-17, the Flatpak
  build over a 220 ms link: it paired, streamed at 1080p60, typed, moved the
  pointer and played audio (§2.8). Its HTTP layer and certificate pinning
  are exercised now, and it found what the probe could not -- pairing that
  holds `getservercert` for the PIN, `/unpair` on a wrong PIN, frame pacing,
  the VK byte -- each fixed with a test. That session is not repeatable in
  CI; it is the manual tier (`docs/testing.md` §8). Android, iOS and tvOS
  have not connected.
- **Only the encrypted paths.** The probe asks for `ENCFLG_ALL`, so the
  plaintext RTSP and unencrypted video paths still have only our own client.
- **Only H.264 at one geometry**, and only against the colour-bar backend.
- **No loss.** `FEC_VALIDATION_MODE` exercises recovery on every frame, but
  the real network is loopback; §5 of `docs/testing.md` is still the plan for
  injected loss.

## 4. Captured Sunshine ↔ Moonlight vectors

**Done**, with the real client at one end and Solstice at the other rather
than Sunshine (below). `tests/tools/capture-session.sh` runs the real-Moonlight
test from §3 inside an unprivileged network namespace (`unshare -rn`) with
`tcpdump` on its loopback, so no root is needed and nothing else on the
machine gets into the capture. The test hands over the session keys, since the
*client* generates `rikey`. `tests/tools/gen_capture_vectors.py` then decrypts
everything offline: RTSP, the ENet control channel, video and audio. It uses
its own pcap, TCP and ENet parsing and Python's `cryptography`, not the
host's crates. Before it freezes anything it checks the result against the
elementary streams `moonlight-common-c` itself recorded.
`tests/vectors/capture/session.json.gz` is the output, and
`crates/solstice-gamestream/tests/capture_vectors.rs` replays it with no
network, no C toolchain and no probe.

The assertions split in two, and `tests/vectors/capture/README.md` says which
is which:

- **What the client sent is ground truth.** The RTSP requests and ANNOUNCE,
  the pings, the ENet connect data and every control message came from the
  reference client. Decoding them is checked against the protocol, so a
  field-offset or endianness error the host makes fails here.
- **What the host sent is pinned.** It is Solstice's own output, but output a
  real client accepted, FEC-validated and recorded. The RTSP responses and
  both packetisers must reproduce it byte for byte from the same inputs.

### What it found

Two defects. The probe had passed over both, because it judged *whether*
things arrived rather than *what* arrived:

1. **Frame 0 is never decoded.** `moonlight-common-c` starts its depacketiser
   at `nextFrameNumber = 1` and silently drops any packet from an earlier
   frame (`VideoDepacketizer.c:65`, `:772`). Solstice numbered from 0, so the
   session's opening IDR was thrown away on every connect. The picture only
   started because the client's own `REQUEST_IDR` produced a second keyframe.
   Found when the reassembled frames did not line up with the client's
   recording; the first IDR on the wire was not in it. The first frame is now
   1 (`video_tx::FIRST_FRAME_INDEX`).
2. **Every scroll was 256 times too large.** `NV_SCROLL_PACKET` is the header
   followed by `scrollAmt1`, `scrollAmt2` and `zero3` (`Input.h:113-118`).
   Solstice skipped a `zero1` byte that is not there, so a one-click scroll of
   120 decoded as `0x7800` = 30720, and a scroll down as −30465. The encoder
   wrote the same phantom byte, so the round-trip tests agreed with it. The
   real-Moonlight test asserted only that *a* scroll arrived, and now asserts
   it is 120.

The rest of the capture matched the protocol. Several things looked wrong at
first and turned out to be the client behaving as designed. Each is now an
assertion with a source citation:

- The ANNOUNCE's packet size is 32 bytes smaller than requested when video is
  encrypted (`SdpGenerator.c:326`).
- The advertised bitrate is 80% of the configured one, the rest being left
  for FEC (`SdpGenerator.c:338`).
- The client wiggles the mouse ±1 on connect (`Connection.c:535`).
- It enables haptics, which Solstice drops and counts.
- It sends the absolute-pointer reference size minus one
  (`InputStream.c:458`).

### Why Solstice and not Sunshine at the host end

`docs/testing.md` §2.4 says to capture against Sunshine. That was weighed and
not done. Sunshine wants a capturable display, an encoder and `uinput`, and
pairing goes through its web API: in a container on a machine with no GPU and
no `/dev/uinput`, that was judged likely to be days of uncertain work, and
it was not attempted. Most of what a Sunshine
capture would add is already here. The client half of the session is
ground truth either way, and the host half has been accepted by the reference
client. What a Sunshine capture would still add is a host-side oracle:
whether Solstice's *choices*, such as FEC geometry, pacing and the order of
SETUP responses, match Sunshine's where the client would tolerate either.
That is differential testing (§2.4's second use), not conformance.

### What is still not covered

- **ENet framing is replayed, one way.** The client's datagrams go through
  the ENet host that replaced `rusty_enet` (§7), which must deliver every
  control message and acknowledge exactly what the old host did. The host's
  side is not replayed byte for byte beyond the `VERIFY_CONNECT`: its later
  datagrams carry the old host's pings and bandwidth limits, which the new one
  does not send.
- **Pairing, `/serverinfo` and `/launch`** are TLS and are not decrypted. The
  probe does not perform them either (§3).
- **One geometry, one codec, no loss**, the same limits as §3: 640×480 H.264
  from the colour-bar backend, on loopback.
- **Regenerating changes every byte.** The keys and session values are minted
  per run, so a new capture is a wholesale replacement of
  `session.json.gz`, not a diff. Regenerate when the wire format changes on
  purpose, and the replay test will say which packets moved.

---

## 5. `solstice pair` and a management socket

**Done.** `crates/solstice/src/management.rs` serves a Unix socket at
`$state_dir/control.sock`, and `pair`, `status`, `list-clients` and `revoke`
are clients of it. The daemon binds it first, before any network port, so a
second daemon on the same state directory fails at once.

**Not** an HTTP API and **not** a web UI: `docs/security.md` §3.5 is blunt that
Sunshine's worst CVEs — CSRF to command injection as Administrator,
clickjacking — are in its config UI rather than its protocol. The socket needs
no auth layer of its own:

- it is mode 0600, in a state directory the unit already makes 0700;
- every connection's peer credentials are checked against the socket's owner
  (or root), so the mode is not the only control and the instant between
  `bind` and `chmod` does not matter;
- a request is one line of at most 256 bytes, read with a five-second timeout.

`contrib/solstice.service` already allows `AF_UNIX`, and the socket lives in its
one writable path.

`solstice pair` **waits for the outcome** of the window it opened and exits
accordingly: 0 when a client has paired, non-zero when the window runs out, the
attempt limit locks pairing out, a malformed request abandons it, or a second
`solstice pair` replaces it. Interrupting it closes the window. That is what a
script driving `moonlight pair -pin` needs (`docs/testing.md` §2.1), and it
means the operator learns a wrong PIN was tried while still at the terminal.
`--window` defaults to `security.pairing_window` and is capped at ten minutes.

`list-clients` and `revoke` fall back to editing `clients.tsv` directly when no
daemon answers — the one moment that is safe.

### How it is tested

`crates/solstice/tests/management.rs` runs the **real binary** as a second
process: it opens a window on a running daemon, a client pairs through it, the
command reports the client and exits 0, and `revoke` then takes effect in the
daemon's memory. Also: an interrupted `pair` closes the window, an unused one
fails the command, and with no daemon the client list is edited directly. The
socket's own lifecycle — mode, refusal of a second daemon, replacement of a
stale socket but not of a regular file, removal on shutdown — is unit-tested in
the module.

### What it found

- **`solstice revoke` did not revoke.** It edited `clients.tsv` from its own
  process; the running daemon kept the client in memory and went on accepting
  it until restarted. `docs/security.md` §3.4 asks for revocation that takes
  effect immediately.
- **`list-clients` printed the same prefix for every client.** It showed the
  first sixteen hex digits of the certificate's *DER*, which is ASN.1 framing
  and lengths — identical across certificates of the same shape — and `revoke`
  took the first match. It now prints a SHA-256 fingerprint, and `revoke`
  refuses a prefix that matches more than one client. The fingerprint is only
  something for the operator to type: a client is still identified by its
  exact DER (`docs/security.md` §3.3).
- **A device name reached the terminal raw.** It comes from the pairing
  request and is attacker-controlled; control characters are now replaced
  before printing.

Telling a successful window from an expired one needed the pairing manager to
remember its result (`PairingManager::paired`): Moonlight reuses its
certificate, so a client re-pairing leaves the store looking unchanged.

### Revocation ends a running stream

`docs/security.md` §3.4 asks for revocation "with existing sessions torn
down", and at first `Host::revoke` only removed the launch record. That
stopped anything new from starting, but a stream already running went on. Now
`Host` carries a signal that changes whenever a session is ended from outside
its stream, by `revoke` or by `/cancel`. Each stream subscribes before it
starts. When its launch record has gone, it sends the client a `TERMINATION`
and stops.

The details came from the reference client, not from Sunshine:

- **On an encrypted stream, the type is `0x0109` with a four-byte big-endian
  HRESULT** (`packetTypesGen7Enc`). The host sends
  `NVST_DISCONN_SERVER_TERMINATED_CLOSED`, `0x80030023`. Once a frame has
  arrived, Moonlight reports it as `ML_ERROR_GRACEFUL_TERMINATION`, so the
  user sees the stream end rather than an error. Before the first frame it
  reports an early termination instead.
- **Moonlight hangs up the moment it reads one.** It calls
  `enet_peer_disconnect_now` without waiting for anything. So the host's own
  `DISCONNECT` must not overtake the `TERMINATION`: the control thread drains
  what it was asked to send before it looks at its stop flag, then lingers
  until the client has acknowledged it. The linger is capped at a second, for
  a client that has already gone.
- **The stream can be up before the host's half of the handshake is.** Video
  starts once the client has seen `VERIFY_CONNECT`. The host counts the peer
  connected only when the client's acknowledgement of it arrives, and under
  loss that can be a retransmission later. A `TERMINATION` asked for in that
  gap is held until the peer connects, inside the same one-second cap, rather
  than refused.
- **`/cancel` ends the stream too.** It is the client quitting the app, and
  Sunshine tears the stream down for it.
- **One stream at a time holds the ports.** Every stream binds the same
  fixed ports, so a client that relaunches straight after a `TERMINATION`
  used to arrive while the old stream was still lingering, and got
  `EADDRINUSE`. A new stream now waits for the previous one to let go, and
  the client retries its `CONNECT` meanwhile.

`security.pairing_enabled` went with it. The window was always the switch,
and the key never did anything. It is still accepted, and warned about, so
that a configuration copied from an older example keeps loading under
`deny_unknown_fields`.

Tested at three levels. `nvhttp` unit tests check that the signal changes on
revoke and on `/cancel`, and only for the client that had a session. Four
tests in `net/control.rs` drive the control thread over a real socket, with
`rusty_enet` as the client:

- a client that hangs up on `TERMINATION`, as Moonlight does, receives it
  before any disconnect;
- a `TERMINATION` asked for before the handshake waits for it;
- a vanished client holds the thread for no longer than the linger;
- stopping with nothing outstanding does not linger at all.

Then `revoking_the_client_ends_its_running_stream` in `real_moonlight.rs`
revokes the reference client mid-stream. `moonlight-common-c` reports a
graceful termination about 200 ms later, and a newly paired client then
streams from the same daemon. `tests/tools/control-loss.sh 40 revoke` runs
the same test with 40% loss on the control port.

**Three things it found**, all older than this change:

- **A daemon could serve one stream in its lifetime.** The audio task was
  spawned detached and looped until a send failed, which on UDP is never. So
  it outlived its stream and kept the audio port bound, and every later
  stream failed to bind with `EADDRINUSE`. Nothing had ever run two streams
  in one process. The media tasks now belong to the stream and end with it.
- **A stream that failed during setup leaked its control thread.** An early
  return, such as a client that never sent its video ping, left the thread's
  stop flag set to run, and the thread held the control port for good. A
  guard now clears the flag on every return.
- **Audio FEC parity was computed over the wrong bytes.** The host's parity
  covered each whole datagram, RTP header included. The client takes a data
  shard to be the payload after the header (`completeFecBlock`:
  `dataPackets[i] + 1`) and rebuilds a recovered packet's header from the
  FEC header. So every parity shard was 12 bytes longer than the block it
  protected. The client reads parity only once a data packet is missing,
  which on loopback is almost never, so every session passed. The first time
  one was lost, a release client switched audio FEC off for the session
  ("Audio block size mismatch"), and the `LC_DEBUG` probe asserted. The
  second client in the revocation test hit it. The captured session (§4)
  had pinned the wrong parity byte for byte, so it was regenerated. The
  replay now also recovers every captured block as the client lays it out,
  a check the old capture fails.

### What is left

- **Under heavy loss, a revocation early in a session can go untold.** At 40%
  loss each way on the control port, the host's half of the ENet handshake
  was sometimes still incomplete two seconds into a stream, because each
  `VERIFY_CONNECT` round trip then succeeds about a third of the time.
  Upstream ENet behaves the same. In 2 of 10 runs the one-second cap ran out
  before the peer connected. The client was disconnected rather than told,
  and stopped about 1.2 s after the revoke with code −1 instead of 0. At 20%
  and 30% loss, 8 of 8 runs each were graceful.
- **The peer-credential refusal is untested**: exercising it needs a second
  uid, which an unprivileged test cannot get.

---

## 6. The still-frame encode cost

**Done.** On a still screen the frame clock drops from the stream's rate to
`video.idle_fps` (default 5) once nothing has changed for half a second
(`IDLE_AFTER`, `crates/solstice-video/src/clock.rs`). Damage or an IDR request
pulls the next frame back to where the full rate would have put it, so a change
never waits on the keep-alive.

The cost it removes: OpenH264 spent **9.5 ms and 57% of a core at 1080p60 to
produce 13 bytes** for every unchanged frame, and the clock emitted sixty a
second.

### What the three candidates came to

The roadmap listed three things to try, in order of likely payoff. Only the
second survived measurement.

- **Encoder settings: no.** A sweep of the unchanged-frame cost at 1080p,
  using the shipping configuration as the baseline:

  | Change | ms/frame | Bytes |
  |---|---|---|
  | none (`ScreenContentRealTime`, bitrate RC, skip off) | 9.5 | 13 |
  | `num_threads(1)` | 9.5 | 13 |
  | scene-change detection on | 9.6 | 13 |
  | frame skip on | 9.5 | 13 |
  | rate control off | 7.1 | 13 |
  | `CameraVideoRealTime` | 3.2 | 15 |
  | camera, background detection and AQ off | 2.0 | 84 |

  The two build-log warnings were not the cause. Frame skip and scene-change
  detection change nothing. What costs is OpenH264 analysing every macroblock
  of a frame it is about to code as all-skip. Camera mode is cheaper because it
  drops the screen-content tools, which are why screen mode is chosen. Turning
  rate control off means no bitrate control. None of these gets near zero.
- **A lower tick rate while still: yes.** This is what shipped. The fear was
  Moonlight's watchdog. Read from source, the watchdog does not apply here:
  `ML_ERROR_NO_VIDEO_TRAFFIC` and `ML_ERROR_NO_VIDEO_FRAME` are checked only
  until the first packet and the first whole frame (`VideoStream.c:146-176`).
  After that the client has no video-silence timeout at all. Its
  connection-quality statistic counts gaps in the *frame index*
  (`ControlStream.c:471-514`), and the packetiser numbers frames contiguously
  whatever the rate. So fewer frames is not loss.
- **Re-sending a cached frame: not legal as it stands.** The 13-byte repeat is
  a *reference* P-slice (NAL header `0x61`, `nal_ref_idc` 3). Consecutive
  repeats differ in exactly the `frame_num` bits. Sending one twice gives two
  consecutive reference frames the same `frame_num`, which H.264 §7.4.3
  forbids. A legal version would be a hand-built *non-reference* all-skip
  slice. That is feasible, since the PPS is CAVLC, but it is unnecessary once
  the clock slows down.

### Why the tail, and why 5

Two things want the frames right after a change at full rate. A decoder that
holds one frame before display shows a change only when the next frame
arrives. And the client notices a lost frame only when a later frame index
turns up. So the clock holds full rate for `IDLE_AFTER` (500 ms) after the
last change before backing off. Typing or a blinking cursor stays inside the
tail and never oscillates.

5 fps is a judgement, not a measurement. `moonlight-common-c` would accept
less. The keep-alive is for the app layers above it, which have not been
tested (below). `idle_fps` at or above the stream rate restores a fixed-rate
stream, so an operator can opt out without a rebuild.

### How it is tested

- **The clock** (`clock.rs`): back-off after the tail and never silence; damage
  and IDR requests during the idle wait go out at the full-rate deadline; full
  rate resumes after a change; an idle rate at or above the stream rate stays
  fixed.
- **The pipeline** (`pipeline.rs`,
  `a_still_screen_backs_off_and_a_change_cuts_the_wait_short`): a session that
  never changes gets the tail, then roughly the keep-alive rate. A damage event
  mid-wait reaches the packet channel in well under a keep-alive interval.
  Fails with the back-off disabled (112 frames where at most 8 are allowed).
- **The real client** (`real_moonlight.rs`,
  `the_reference_client_sits_through_a_still_screen_at_the_idle_rate`): colour
  bars move for a second, freeze for twelve (longer than any timeout in
  `moonlight-common-c`), then move again. The client must not terminate,
  report a poor connection, or ask for a keyframe after start-up. Its longest
  wait between decode units must look like a keep-alive (204 ms measured at
  `idle_fps = 5`). The recording must show the frozen picture, then motion.
  With the back-off disabled it fails on the gap (63 ms: "the host never
  slowed down"). The probe gained `hold=N`, and `maxgap=` and `poor=` in its
  summary, for this.

### Measured

`encode_cost.rs` now has a still-session row per resolution. It drives the real
`FrameClock` over ten seconds of an unchanged screen and encodes every frame
the clock emits:

```
stage                                  ms/frame   frames/s   core % @60
1280x720 still screen, idle_fps 60        4.280       60.1         25.7
1280x720 still screen, idle_fps 5         4.283        7.9          3.4
1920x1080 still screen, idle_fps 60       9.407       60.1         56.5
1920x1080 still screen, idle_fps 5        9.415        7.9          7.4
```

That includes the half-second tail. In steady state the 1080p figure is 5 ×
9.4 ms, **4.7% of a core, down from 56%**.

### What is left

- **No Moonlight *application* is known to have sat through a slowed
  stream.** moonlight-qt has streamed from this host (§3), but nothing
  recorded whether its frame pacer and decoder saw the idle back-off, and
  those are the layers that could plausibly mind a 5 fps idle stream. If one
  does mind, raise `idle_fps`. Do not remove the back-off.
- **A changed frame still costs a whole-frame analysis.** Typing one character
  at 1080p is a full encode of a frame that is 99.9% unchanged. Encoder-side
  region-of-interest or skip hints would be the next lever. OpenH264 exposes
  neither through the crate.
- **The non-reference skip slice** above would make even the keep-alive frames
  nearly free. It is not worth the bitstream-writing risk at 4.7% of a core.

---

## 7. ENet: audit or reimplement

**Done, by reimplementing.** `rusty_enet` was a C-to-Rust transpilation whose
own README says it *"couldn't be much further from ready for serious use"*,
and it sat on the **pre-authentication** UDP path, where GHSA-c428-87f8-rrv5
is an unauthenticated DoS via a short ENet control packet. It is gone from the
daemon. `crates/solstice-gamestream/src/stream/enet.rs` is the subset
Moonlight uses, over the framing in `wire/enet.rs`, and
`crates/solstice/src/net/control.rs` is now only the socket and thread around
it. `rusty_enet` survives as a dev-dependency, as the independent ENet the new
host is tested against.

### Why reimplement rather than audit

§3 and §4 made "the subset" a finite thing to read off. Decoding the captured
session shows everything a real client sends: `CONNECT`, `ACKNOWLEDGE`,
`PING`, reliable sends on channel 0, one `BANDWIDTH_LIMIT`, and `DISCONNECT`.
Its `ControlStream.c` adds unsequenced sends, made only toward a host whose
`appversion` marks it as Sunshine, which this one's does. It never fragments:
every control message is built in a 256-byte buffer (`sendMessageEnet`),
against a 900-byte MTU. An audit would have had to vouch for 3,000 lines of
transpiled C, most of which this host never needs. The rewrite is a few
hundred lines and can be made strict where ENet is generous.

### What it does differently from ENet, on purpose

Wire-compatible, with the same reliability semantics, but before
authentication it is a smaller target. `docs/implementation-notes.md` §2 has
each point with its reasoning:

- **Nothing is answered before the connect data.** `rusty_enet` completed the
  handshake with *any* peer, and only then could the host check the connect
  data and drop it. Now a `CONNECT` with the wrong value gets no reply and
  creates no state. The one reply a right value earns is 48 bytes, against
  the `CONNECT`'s 52, so the port does not amplify.
- **One peer, bound to its address.** Upstream ENet re-learns a peer's
  address from any datagram with its ID and two-bit session, because the check
  is commented out in `protocol.c`.
- **No fragment reassembly, compression or checksum.** Reassembly is the
  largest piece of pre-authentication state in ENet, and it is simply absent.
- **Hard caps** on commands per datagram (32, ENet's own sender limit), held
  out-of-order data (256 commands, 64 KiB), and the host's unacknowledged sends
  (64).
- **The host sends no pings and no bandwidth limits.** A peer is gone after
  ten seconds of silence, or ten seconds with a reliable command of ours
  unacknowledged. That matches Moonlight's own timeout.

### How it is tested

- **Unit:** 7 framing tests in `wire/enet.rs`, including every truncation of
  every command, and 25 in `stream/enet.rs`. Those cover the handshake and
  each refusal, ordering, duplicates, the reorder bounds, fragments, foreign
  addresses and stale sessions, the 32-command cap, retransmission and
  timeouts, plus a seeded mangled-datagram property test that checks the
  bounds hold.
- **Against upstream ENet, under loss:** `tests/enet_interop.rs` runs
  `rusty_enet` as the client over a simulated network with simulated clocks.
  Hundreds of reliable, unreliable and unsequenced messages go each way over
  networks that are clear, reordering, duplicating, 10% lossy and 30% lossy,
  across several seeds. Every reliable message must arrive exactly once and
  in order. The suite also covers a client that vanishes, an idle minute, and
  wrong connect data. It runs in a fraction of a second. Two deliberate
  breakages were checked against it to confirm it catches them: never
  re-acknowledging a duplicate, and delivering out of order.
- **Against the captured session:**
  `the_real_clients_enet_datagrams_replay_through_the_host` feeds the real
  client's 24 datagrams through the new host. All 23 control messages come
  out, nothing is refused, and the acknowledgements match the old host's
  exactly. The `VERIFY_CONNECT` is byte for byte the one the client accepted
  from `rusty_enet`. That capture has since been replaced (§5) by one taken
  against this host.
- **Against the real client:** `real_moonlight.rs` passes unchanged. So does
  `tests/tools/control-loss.sh`, the same test with netem dropping 20%, 30%
  and 40% of datagrams on the control port alone. The test asserts that
  input arrived, and netem's drop counter shows the loss happened.
- **Fuzzing:** a new target, `fuzz/fuzz_targets/enet_host.rs`, drives every
  input into both a fresh host and one already connected. It ran for ten
  minutes, 25.9 million runs, seeded from the captured datagrams. It found nothing,
  and memory stayed flat at 29 MB. `cargo fuzz` is not on the development
  box, so it ran on stable with cargo-fuzz's own instrumentation flags:
  `RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters
  -Cllvm-args=-sanitizer-coverage-pc-table
  -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing
  -Cdebug-assertions -Coverflow-checks" cargo build --release --bin enet_host
  --target x86_64-unknown-linux-gnu` in `fuzz/`. No AddressSanitizer is
  needed: the crate forbids `unsafe`.

### What it found

Nothing in the new code that a test had not caught first. That is the
expected result, since the subset was read off the session it is tested
against. The findings are about the old arrangement:

- **The connect-data check came after the handshake.** It was containment
  that only applied once ENet's whole state machine had run for the stranger.
- **The old host never ended a session.** On teardown it stopped servicing
  ENet and left the client to time out. The new host sends a `DISCONNECT`
  (`the_host_ending_the_session_reaches_the_client`).

### What is left

- **moonlight-qt, once, by hand.** Its control stream ran through this host
  over a 220 ms link (§3): input arrived and the session ended cleanly. Not
  under loss, and not repeatable in CI.
- **A fragmenting client would be cut off.** Not a real client today, by the
  256-byte buffer above. If Moonlight ever builds a larger control message,
  the client retransmits it unacknowledged until it times out. The `fragments`
  counter in the host's stats is where that would show first.
- **Only `TERMINATION` is sent.** Its round trip through `Host::send` is
  checked against the real client (§5). Rumble and HDR mode have no source in
  either backend.
- **At 40% loss the real-client test fails about a third of the time**, on
  this host before §5 as well as after (6 of 10 at the §7 merge). The
  failures are input not arriving within the test's window: the host drops a
  client's data until its half of the handshake completes, which under that
  much loss takes several retransmissions. One baseline run also hit the
  audio FEC defect §5 fixed. 20% and 30% pass.
- **The control-loss script is manual**, like the rest of the loss tier
  (`docs/testing.md` §5, §6).

---

## 8. Smaller items

- **A cursor for the VNC backend.** Moonlight draws no host cursor, and the
  RFB backend neither asks for the Cursor pseudo-encoding (-239) nor draws one,
  so a VNC desktop streams with no pointer at all. The SPICE backend already
  composites one (`crates/solstice-spice/src/cursor.rs`); RFB needs the same,
  drawn at the position Moonlight last sent.
- **The letterbox scaler is nearest-neighbour.** `convert_scaled` takes one
  source pixel per output pixel, which drops a third of the rows of a 1080p
  desktop streamed at 720p -- text loses strokes. It is also slow: a
  4K-to-1080p conversion plus the encode overran the 16.7 ms budget at 60 fps.
  Only reached when the backend will not resize, which both backends now
  normally do; an area-averaging downscale is the fix.
- **Fuzzing: seeded and scripted, run by hand.** Five targets now start
  from real traffic. `tests/tools/gen_fuzz_seeds.py` cuts
  `fuzz/seeds/<target>/` out of the captured session (§4): the RTSP requests,
  the ANNOUNCE body, the input batches, the control messages and the ENet
  datagrams, 66 inputs in all. The control envelopes are re-sealed under the
  target's fixed key; as captured, every one would fail authentication at the
  first check. Before re-sealing, each is sealed again under the session key
  and must reproduce the captured bytes exactly. The seeds start each target
  well ahead of an empty corpus:

  | Target | Coverage at start, empty | Seeded |
  |---|---|---|
  | `rtsp_message` | 10 | 103 |
  | `sdp_announce` | 47 | 146 |
  | `input_batch` | 16 | 118 |
  | `control_envelope` | 34 | 154 |
  | `enet_host` | 196 | 327 |

  `tests/tools/fuzz.sh [seconds] [target…]` builds every target on stable,
  with cargo-fuzz's instrumentation flags, and runs each from its seeds and
  its own growing `fuzz/corpus/<target>/`. `fuzz/corpus` stays ignored, so the
  persistent corpus lives on whichever machine runs it. Its first two full
  runs each found an overflow in `spice_draw` within a minute, both in the
  sampler behind `DRAW_OPAQUE` and `DRAW_COPY`, and both from `i32` geometry
  at the extremes. The fixed-point `dx * src_w * 256` overflowed in `i64`,
  and `x - dest.left` overflowed in `i32` before it was widened. Each panics
  in a debug build and wraps in a release one. The arithmetic is now widened
  first, the scaling is done in `i128`, and both inputs are a unit test.
  `spice_draw` then ran clean for five minutes, 8.2 million runs.

  **No scheduled job, by decision.** CI builds, lints and tests on push and
  pull request only (`docs/testing.md` §6). Fuzzing is `fuzz.sh`, run by
  hand when a parser changes.
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
