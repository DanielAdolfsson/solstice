# RFB (VNC) — protocol notes

Research notes, October 2026. Sources:

- RFC 6143, *The Remote Framebuffer Protocol* — the IETF baseline.
- The community-maintained living spec,
  `github.com/rfbproto/rfbproto` (`rfbproto.rst`), which documents the two
  decades of extensions that everyone actually implements. Line references
  below are to that file as of 2026-10-15.

> **Direction.** Solstice is a **client** here: it dials an existing VNC server
> (x11vnc, wayvnc, TigerVNC, QEMU's built-in, libvncserver, …), pulls
> framebuffer updates, and injects input.

---

## 1. Shape of the protocol

One TCP connection (default 5900 + display number), strictly ordered, three
phases:

```
  Handshake    version → security type → auth → SecurityResult → ClientInit → ServerInit
  Steady state client messages and server messages interleave freely
```

RFB is **pull-based and lossless**. The client asks for a region; the server
replies with rectangles that bring that region up to date. There is no frame
clock, no timestamp, and no notion of a continuous stream — a static screen
produces no traffic at all. This is the single most important structural
difference from GameStream and it drives most of `bridging-design.md`.

All integers are big-endian.

---

## 2. Handshake

### 2.1 Version

Server sends 12 ASCII bytes, `RFB 003.008\n`. Client replies with the same
form, naming the highest version it supports. Real-world versions: `003.003`,
`003.007`, `003.008`. Some servers (Apple) announce `003.889`.

### 2.2 Security type

For ≥ 3.7 the server sends a count-prefixed list of `U8` type numbers; the
client picks one and echoes it back. For 3.3 the server unilaterally sends a
`U32`.

Registered types (`rfbproto.rst:367-407`), abridged:

| № | Name | Notes |
|---|---|---|
| 0 | Invalid | followed by a reason string |
| 1 | None | no auth at all |
| 2 | VNC Authentication | DES challenge-response, **broken** — see §2.3 |
| 5 / 6 / 13 | RSA-AES, RSA-AES Unencrypted, RSA-AES Two-step | RealVNC |
| 16 | Tight Security Type | capability negotiation + tunnels |
| 18 | TLS | anonymous TLS wrapper (no auth of the server) |
| 19 | VeNCrypt | the practical way to get real TLS + x509 |
| 20 | SASL | GSSAPI/Kerberos etc. |
| 30 | Diffie-Hellman | Apple |
| 129 / 130 / 133 | RSA-AES-256 variants | RealVNC |

For Solstice the realistic set is **None**, **VNC Authentication**, and
**VeNCrypt** (which itself sub-negotiates: `X509Vnc`, `X509Plain`, `TLSVnc`,
`TLSPlain`, …).

### 2.3 VNC Authentication, and why it is not authentication

From the spec (`rfbproto.rst:471-502`): the server sends a 16-byte challenge;
the client encrypts it with **DES in ECB**, keyed by the password **truncated
to 8 characters**, with each key byte's bit order reversed.

That is a ≤ 56-bit key, with no salt, no server authentication, and no channel
protection. The challenge/response pair is offline-crackable, and everything
after it — framebuffer and keystrokes — is plaintext. Treat it as a speed bump,
never as a security control. See `security.md`.

### 2.4 SecurityResult, ClientInit, ServerInit

`SecurityResult` is a `U32` (0 = OK). `ClientInit` is one byte, the *shared*
flag. `ServerInit` carries the framebuffer geometry, the server's preferred
`PIXEL_FORMAT`, and the desktop name:

```
U16 framebuffer-width
U16 framebuffer-height
PIXEL_FORMAT (16 bytes)
U32 name-length
U8  name[name-length]
```

```
PIXEL_FORMAT {
    U8  bits-per-pixel       8, 16 or 32
    U8  depth
    U8  big-endian-flag
    U8  true-colour-flag
    U16 red-max, green-max, blue-max
    U8  red-shift, green-shift, blue-shift
    U8  padding[3]
}
```

---

## 3. Client → server messages

Mandatory (`rfbproto.rst:1625-1636`):

| № | Message |
|---|---|
| 0 | SetPixelFormat |
| 2 | SetEncodings |
| 3 | FramebufferUpdateRequest |
| 4 | KeyEvent |
| 5 | PointerEvent |
| 6 | ClientCutText |

Optional ones Solstice may want: **150 EnableContinuousUpdates**, **248
ClientFence**, and **255 / submessage 0 — QEMU Extended Key Event**.

### 3.1 FramebufferUpdateRequest

```
U8  3
U8  incremental
U16 x, y, width, height
```

The core loop: request incrementally over the whole screen, consume the
`FramebufferUpdate` that comes back, request again. Exactly **one** request may
be outstanding; pipelining more does not get you more frames, it just confuses
flow control.

### 3.2 KeyEvent

```
U8  4
U8  down-flag
U16 padding
U32 key          ← an X11 keysym
```

Keysyms, not scancodes. `0xff08` BackSpace, `0xff0d` Return, `0xffe1` Shift_L,
and ASCII for the printable range. Auto-repeat is the client's job: send
repeated *down* events, never repeated ups (`rfbproto.rst:1823-1831`).

### 3.3 QEMU Extended Key Event (pseudo-encoding −258, message 255/0)

```
U8  255
U8  0
U16 down-flag
U32 keysym
U32 keycode      ← XT make scancode, 1-byte or 0xe0-prefixed packed into U32
```

Available only if the server advertised the pseudo-encoding. **Strongly
preferred for Solstice**: it sidesteps keymap mismatch entirely, and XT
scancodes are a far shorter hop from Moonlight's Windows virtual-key codes than
X11 keysyms are.

### 3.4 PointerEvent

```
U8  5
U8  button-mask
U16 x-position, y-position
```

Absolute coordinates — which is convenient, since Moonlight's absolute-mouse
packet is also absolute. Button mask bits (`rfbproto.rst:1944-1955`):

| Bit | Button |
|---|---|
| 0 | Left |
| 1 | Middle |
| 2 | Right |
| 3 | Scroll up |
| 4 | Scroll down |
| 5 | Scroll left |
| 6 | Scroll right |
| 7 | Back |

Scrolling is modelled as a press *and release* of buttons 4–7. Note there is
no relative-motion message in base RFB; the `QEMU Pointer Motion Change`
pseudo-encoding (−257) adds one.

---

## 4. Server → client messages

Mandatory (`rfbproto.rst:2705-2714`): **0 FramebufferUpdate**, 1
SetColourMapEntries, 2 Bell, 3 ServerCutText. Optional: 150
EndOfContinuousUpdates, 248 ServerFence.

`FramebufferUpdate` is a count-prefixed list of rectangles:

```
U8  0
U8  padding
U16 number-of-rectangles
  ⟨ U16 x, y, w, h ; S32 encoding-type ; encoding-specific data ⟩ ×N
```

---

## 5. Encodings

True encodings (`rfbproto.rst:3047-3062`):

| № | Encoding | Character |
|---|---|---|
| 0 | Raw | uncompressed pixels; every server supports it |
| 1 | CopyRect | "copy this rect from elsewhere in the framebuffer" |
| 2 / 4 | RRE / CoRRE | rectangle-run encoding, obsolete |
| 5 | Hextile | 16×16 tiles, cheap, widely supported |
| 6 / 8 | zlib / zlibhex | raw-over-zlib |
| 7 | **Tight** | zlib + JPEG + palette + fill; the practical default |
| 16 | **ZRLE** | zlib run-length; the practical default where Tight is absent |
| 21 | JPEG | |
| 50 | Open H.264 | rare, but see §7 |
| −260 | Tight PNG | |

Pseudo-encodings worth requesting (`rfbproto.rst:3066-3098`):

| № | Pseudo-encoding | Why |
|---|---|---|
| −223 | DesktopSize | resolution changes |
| −308 | ExtendedDesktopSize | resolution changes **and** lets the client *request* one |
| −224 | LastRect | update terminator when count is unknown |
| −239 / −314 | Cursor / Cursor With Alpha | render the cursor client-side |
| −257 | QEMU Pointer Motion Change | relative pointer motion |
| −258 | QEMU Extended Key Event | scancode input, see §3.3 |
| −259 | QEMU Audio | a possible audio source |
| −312 / −313 | Fence / ContinuousUpdates | flow control, see §6 |
| −23..−32, −247..−256 | JPEG quality / compression level | quality-vs-bandwidth knobs |

A client declares its full set once via `SetEncodings`; order expresses
preference.

### 5.1 Tight (7)

Read from `rfbproto.rst:3414-3627` on 2026-10-16, and checked against
TigerVNC's `common/rfb/TightDecoder.cxx` and QEMU's `ui/vnc-enc-tight.c` where
the prose leaves room. Implemented in `crates/solstice-vnc/src/encodings/tight.rs`.

**Width.** A Tight rectangle may be at most 2048 pixels wide (`:3417-3421`).
TigerVNC's decoder enforces that for everything *except* fill, because its own
servers before 1.16 sent wider fills; Solstice does the same.

**Compression control** — the first byte of every rectangle (`:3423-3479`):

| Bits | Meaning |
|---|---|
| 0–3 | reset zlib stream *n* before decoding — one bit per stream, independent |
| 7–4 = `0xxx` | **basic**: bits 5–4 pick stream 0–3, bit 6 says a *filter-id* byte follows |
| 7–4 = `1000` | **fill** |
| 7–4 = `1001` | **JPEG** — only if the client advertised a quality level (`:3481-3483`) |
| 7–4 = `1010`, `1110` | **basic without zlib** — only if the client advertised it (`:3485-3486`) |
| anything else | invalid |

The reset bits apply **whatever the compression type**, fill and JPEG included
(`:3617-3621`).

**TPIXEL** (`:3488-3495`): a whole `PIXEL`, except that for 32-bit true colour
with depth 24 and 8-bit channels it is **three bytes, red, green, blue** —
not the byte order of the pixel. TigerVNC's `is888` additionally requires the
shifts to be byte-aligned.

**Fill** (`:3500-3503`): one TPIXEL, no length, no stream.

**JPEG** (`:3505-3533`): a compact length, then a JFIF stream.

**Compact length** (`:3516-3531`): one to three bytes, seven bits at a time,
least significant first; the third byte contributes all eight. 10000 is
`90 4E`.

**Basic** (`:3535-3615`). With bit 6 set, a filter id follows: 0 copy, 1
palette, 2 gradient; with it clear, copy.

- *Copy*: TPIXELs.
- *Palette* (`:3560-3572`): a byte holding size − 1, then that many TPIXELs.
  Two colours or fewer pack **one bit per pixel, most significant bit
  leftmost, each row padded to a byte**; more take a byte per pixel. TigerVNC
  treats a one-colour palette as the 1-bit form too.
- *Gradient* (`:3574-3594`): each component is sent as `V − P`, where
  `P = V[left] + V[above] − V[above-left]` clamped to `0..=max`, and anything
  outside the rectangle counts as zero. Not allowed at 8 bits per pixel. For
  888 the components are the TPIXEL's bytes; otherwise they are the pixel's
  channels in their own range.

Filtered data **shorter than 12 bytes is sent as is**, with no length and
without touching any stream (`:3596-3599`). Otherwise it is a compact length
and that many bytes of zlib data on the selected stream (`:3604-3615`). The
four streams are each continuous for the life of the connection until reset,
and both servers checked sync-flush them per rectangle (QEMU's
`tight_compress_data`, TigerVNC's `ZlibOutStream::flush`, both
`Z_SYNC_FLUSH`), so a rectangle's chunk inflates to exactly its filtered size.

**When a server sends JPEG.** The spec's rule (`:3481-3483`) is what the
servers do. TigerVNC's `TightJPEGEncoder::isSupported` returns false unless
the client sent a quality level, a fine quality level or a subsampling level.
QEMU starts every client at `tight.quality = -1` ("lossless by default",
`ui/vnc.c`) and only takes its JPEG path when that is set. QEMU's gradient
filter also needs the display's `lossy` option. So a client that lists Tight
and no quality pseudo-encoding gets lossless Tight from both.

---

## 6. Flow control: Fence and ContinuousUpdates

`EnableContinuousUpdates` (client message 150, gated on pseudo-encoding −313)
tells the server to push updates for a region without further requests. This
turns RFB from pull to push and removes a round-trip from every frame — close
to essential for a latency-sensitive bridge.

`ClientFence`/`ServerFence` (−312) provide a barrier so the client can tell how
far the server has got, which is how you avoid queueing unbounded updates on a
slow link.

Both are widely implemented (TigerVNC, TurboVNC, libvncserver). Solstice should
request them, and fall back to the request/response loop when absent.

---

## 7. The Open H.264 encoding (№ 50)

If a server offered H.264 rectangles, a bridge could in principle forward them
to Moonlight without a transcode. In practice this is not a plan to build on:
support is rare, the rectangles are per-region rather than whole-frame, there
is no guarantee about IDR cadence, slice layout or parameter sets, and nothing
lets the client *demand* a keyframe. Treat it as a possible future
optimisation, not an architecture.

---

## 8. Consequences for Solstice

1. **There is no video stream to forward.** RFB produces dirty rectangles in a
   pixel format of its choosing. Solstice must composite them into a
   framebuffer and encode that framebuffer to H.264 itself.
2. **There is no frame clock.** Solstice must generate one: run its encoder at
   a fixed rate and feed it the current framebuffer, repeating when nothing
   changed. Sunshine does the same thing for duplicate frames.
3. **Decoding Tight and ZRLE is real work.** Tight in particular is a small
   zoo of sub-encodings (basic/fill/jpeg/png, palette, gradient filters) over
   four resettable zlib streams. *(As it turned out, both were written
   directly — see `PROJECT-LAYOUT.md` — Tight lossless-only, per §5.1.)*
4. **Input maps cleanly.** Absolute pointer → `PointerEvent`; Moonlight VK
   codes → XT scancodes → `QEMU Extended Key Event`, with an X11-keysym
   fallback. Clipboard maps to `ClientCutText`/`ServerCutText`.
5. **There is no audio.** The `QEMU Audio` pseudo-encoding is the only option
   and it is uncommon. Solstice will usually be sending silence to Moonlight.

### Crate options

`vnc-rs` (0.6.0, updated 2026-09-21, ~2.2 M downloads) is an async client-side
RFB implementation and the obvious starting point. The venerable `vnc` crate
(0.4.0) has not been touched since 2016. `rfb2` and `rustvncserver` are
server-side and therefore the wrong half of the protocol.

Worth vendoring-or-forking rather than depending on blindly: a bridge needs
control over the update loop, zero-copy access to the framebuffer, and the
pseudo-encodings in §6, and client crates often hide all three.
