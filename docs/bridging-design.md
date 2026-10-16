# Bridging GameStream to RFB / SPICE

Where the two halves meet, and what is actually difficult. Read
`moonlight-sunshine-protocol.md`, `rfb-vnc-protocol.md` and
`spice-protocol.md` first.

---

## 1. The central mismatch

| | GameStream (toward Moonlight) | RFB / SPICE (toward the server) |
|---|---|---|
| Model | continuous encoded video | dirty rectangles / draw commands |
| Loss | lossy, FEC-protected UDP | lossless over TCP |
| Clock | fixed frame rate, 90 kHz RTP timestamps | none; updates when pixels change |
| Flow | host-paced, bitrate-targeted | client-pulled (or fence-paced) |
| Geometry | client *requests* W×H×fps | server *announces* its size |
| Audio | Opus, mandatory-ish | absent (RFB) / Opus or CELT (SPICE) |
| Keys | Windows VK + extended flag | X11 keysym or XT scancode |
| Pointer | absolute, with reference W/H | absolute (RFB) / mode-dependent (SPICE) |

Only input maps across cleanly. Everything on the video path requires
**decode → composite → re-encode**. That is the project.

```
Moonlight ──UDP/H.264──▶ ┌──────────── Solstice ────────────┐ ──TCP──▶ VNC / SPICE server
          ◀──ENet input── │ gamestream host                  │
                          │   ├ nvhttp + pairing             │
                          │   ├ rtsp                         │
                          │   ├ video packetizer ◀─ encoder ◀┼─ framebuffer ◀─ backend client
                          │   ├ audio packetizer             │
                          │   └ control/input ───────────────┼─▶ input translation
                          └──────────────────────────────────┘
```

---

## 2. The video pipeline

```
backend update ─▶ framebuffer (BGRA) ─▶ colour convert (NV12) ─▶ H.264 encoder
                                                                      │
                     ◀── IDR request (control stream) ◀────────────────┤
                                                                      ▼
                                               Annex-B AU ─▶ frame header ─▶ shard split
                                                          ─▶ [FEC] ─▶ [AES-GCM] ─▶ UDP
```

### 2.1 Synthesising a frame clock

Moonlight asks for a framerate in `x-nv-video[0].maxFPS` and expects frames to
keep arriving. Run a fixed-interval ticker at that rate. On each tick, encode
the current framebuffer whether or not it changed.

Two refinements worth building in early:

- **Damage-aware rate control.** When nothing changed, encode a P-frame
  predicting perfectly from the previous one — a handful of bytes. Sunshine
  does the same for duplicate frames and reuses the rate-control timestamp
  rather than a capture timestamp (`stream.cpp:1744-1751`); do likewise, since
  there is no real capture time.
- **Do not skip frames entirely.** Moonlight's watchdog fires
  `ML_ERROR_NO_VIDEO_TRAFFIC` / `ML_ERROR_NO_VIDEO_FRAME`
  (`Limelight.h:419-424`) if the stream goes quiet.
  *(As it turned out, only before the first frame: both checks stop once one
  has arrived (`VideoStream.c:146-176`). Solstice still never goes silent,
  but slows to a keep-alive rate on a still screen, which cut an idle
  session's encode cost by about 12× — `docs/roadmap.md` §6.)*

### 2.2 Resolution

Moonlight requests W×H; the backend has its own idea. Options, best first:

1. **Ask the backend to resize.** RFB: `ExtendedDesktopSize` (−308) lets the
   client request a size. SPICE: vdagent `VD_AGENT_MONITORS_CONFIG`. Both
   require cooperation that may not be there.
2. **Scale.** Letterbox into the requested geometry. Costs quality and CPU but
   always works.
3. **Re-announce.** The RTSP session is already negotiated at this point, so
   mid-session changes mean tearing the session down. Avoid.

Pick one at session start and stick to it; Moonlight does not handle a
resolution change mid-stream gracefully.

### 2.3 Choosing an encoder

| Option | Crate / binding | Notes |
|---|---|---|
| OpenH264 | `openh264` 0.9.x | pure-ish, permissive, software only, baseline/main — check that High Profile is actually produced, since Moonlight's `VIDEO_FORMAT_H264` says High Profile |
| x264 | `x264` 0.5.0 (stale, 2022) or FFI | best software quality/latency, **GPL** |
| FFmpeg | `ffmpeg-next` 9.x | gives libx264 *and* VAAPI/NVENC/QSV behind one API; heavy dependency |
| VAAPI direct | `cros-codecs`, or raw libva FFI | lowest latency on Intel/AMD, no transcode on CPU |

Recommendation: define a `VideoEncoder` trait, implement `openh264` first
because it has the fewest moving parts and a licence that will not force the
project's hand, and add an `ffmpeg` feature for hardware paths. Licensing is a
real decision here, not a detail — x264 and most FFmpeg builds are GPL, and
that choice propagates to the whole binary.

Encoder settings that matter for this workload:

- zero-latency / no B-frames / no lookahead — any reordering is latency.
- Slice count from `x-nv-video[0].videoEncoderSlicesPerFrame`.
- **IDR on demand.** The control stream carries "request IDR frame"
  (`0x0302`); the encoder must be able to force a keyframe immediately.
- Target bitrate from `x-nv-vqos[0].bw.maximumBitrateKbps`.
- `maxNumReferenceFrames` from the ANNOUNCE; ignore reference-frame
  invalidation entirely in v1 and simply answer every RFI with an IDR.

### 2.4 Packetisation checklist

Per encoded access unit:

1. Prepend `video_short_frame_header_t` (8 B): `headerType = 0x01`,
   `frameType` 2 for IDR else 1, `frame_processing_latency` in 1/10 ms,
   `lastPayloadLen` = real length of the last shard's payload.
2. Split into blocks of `packetSize + MAX_RTP_HEADER_SIZE`, zero-padded, with
   `sizeof(video_packet_raw_t)` reserved at the head of each.
3. Fill `NV_VIDEO_PACKET`: `frameIndex`, `streamPacketIndex = (lowseq+i) << 8`,
   `flags` with SOF on the first and EOF on the last, `multiFecFlags = 0x10`,
   `multiFecBlocks`, `fecInfo`.
4. Fill RTP: `header = 0x90`, `sequenceNumber` = low 16 bits of a wider
   counter, `timestamp` = 90 kHz tick. Leave `packetType` and `ssrc` zero.
5. FEC (§2.5), then optional AES-GCM with the 32-byte prefix.
6. Pace the sends. Sunshine spreads a frame's packets over time rather than
   bursting (`stream.cpp:1680-1690`); a burst will cause loss on real links.

### 2.5 FEC — build it in from the start

The Reed–Solomon must match the client's `nanors` bit for bit, and generic Rust
RS crates do not. That is a reason to implement the right construction, not to
defer: it is a closed-form Cauchy matrix over GF(2⁸) with polynomial 0x11D,
verified byte-exact in `moonlight-sunshine-protocol.md` §5.4 — roughly 50 lines.

Deferring costs more than it saves, because the packetiser's buffer layout is
shaped around FEC. Sunshine's `concat_and_insert` reserves 32 bytes at every
block boundary precisely so shards can be built in place, and `fec::encode`
points into the original payload rather than copying. Write the no-FEC path
first and you will design something simpler, then tear it out.

`fec_percentage = 0` is still legal and is a useful bisection tool when
debugging the packetiser — it makes the client skip parity entirely — but it is
not the shipping configuration.

Audio FEC is a **separate** code: fixed RS(4,2) with Nvidia's hard-coded parity
matrix, not the Cauchy construction. One implementation does not cover both.

Validate against `moonlight-common-c` built with `FEC_VALIDATION_MODE`, which
drops a shard per frame and asserts byte-exact recovery — see `testing.md` §2.2.

---

## 3. Audio

RFB has no audio. SPICE has Opus on the playback channel.

| Backend | Plan |
|---|---|
| None / RFB | Send Opus silence at the negotiated `packetDuration`. Cheap, keeps the client happy, avoids the "no audio stream" edge cases. |
| SPICE with Opus | Repacketise when the client asked for 10 ms stereo, which is what `spice-server` sends; transcode otherwise, which with Moonlight's default of 5 ms is the common case. Measured — see `spice-protocol.md` §7. |
| SPICE with CELT | Decode and re-encode, or fall back to silence. |

Either way the audio path is: Opus packet → RTP(pt 97) → optional AES-CBC →
UDP, plus an RS(4,2) parity pair every four packets.

---

## 4. Input translation

### 4.1 Keyboard

Moonlight sends `NV_KEYBOARD_PACKET`:

```c
struct NV_KEYBOARD_PACKET {
    NV_INPUT_HEADER header;   // size (BE), magic (LE): 0x3 down, 0x4 up
    char  flags;              // SS_KBE_FLAG_NON_NORMALIZED = 0x01
    short keyCode;            // Windows VK code, US English layout
    char  modifiers;          // SHIFT 0x01 CTRL 0x02 ALT 0x04 META 0x08 EXTENDED 0x10
    short zero2;
};
```

Two things make this tractable:

- `MODIFIER_EXTENDED (0x10)` means "this key carries the 0xE0 scancode
  prefix" — stated explicitly in `Limelight.h:698-701`. That is *already* the
  XT scancode distinction.
- Key codes are defined to be interpreted against a **US English layout**, so
  one static table is correct rather than approximate.

So the mapping is:

```
VK code + EXTENDED flag ──▶ XT scancode (with optional 0xE0 prefix)
                              ├─ RFB:   QEMU Extended Key Event (255/0), keycode field
                              └─ SPICE: SPICE_MSGC_INPUTS_KEY_DOWN / _KEY_UP
```

SPICE has **no keysym option at all** — `SPICE_MSGC_INPUTS_KEY_DOWN` carries a
PC AT scancode and that is the only representation available. So the
VK→scancode table is required regardless of what any RFB server supports; on
RFB it is merely also *available*.

#### Why scancodes rather than keysyms

A VK code plus the EXTENDED bit identifies a **physical key position** under a
US-layout assumption. A keysym identifies a **symbol**. Converting one to the
other commits to the US interpretation, which is wrong whenever the remote
desktop uses a different layout:

```
User presses the key labelled Ö on a Swedish keyboard
  (physical position of ';' on a US board)

  client OS → VK_OEM_1   (Moonlight normalises to the US-layout VK)

  scancode path:  VK_OEM_1 → XT 0x27 → server applies ITS layout → ö   ✓
  keysym path:    VK_OEM_1 → XK_semicolon → server types            ;   ✗
```

The scancode path defers interpretation to the remote desktop's own keymap,
which is what the user expects. The keysym path hard-codes the US reading.

Two further problems with keysyms, both well known from VNC practice:

- The server must *own* a keycode that produces the requested keysym. When it
  does not, X servers transiently remap a spare keycode — a racy mechanism that
  every mature VNC server carries elaborate heuristics for.
- Modifier state has to be inferred by the server rather than conveyed. With
  scancodes, Shift is just another scancode and the state is explicit and
  symmetric.

`SS_KBE_FLAG_NON_NORMALIZED` is the inverse signal: the client could *not*
normalise the key to a US scancode and is sending it raw. On that flag the
keysym reading is the appropriate one — pass it through on the keysym path and
treat it with suspicion on the scancode path.

#### Both paths are mandatory

Pseudo-encoding −258 is a registered RFB extension (`rfbproto.rst:3076`), not a
QEMU dependency — the name is historical. But support is not universal, and the
gap is on the server side of a widely deployed family:

| Server | −258 server-side | Verified |
|---|---|---|
| TigerVNC / `Xvnc` / TurboVNC | ✓ | `SConnection.cxx:393`, `SMsgReader::readQEMUMessage` |
| neatvnc / `wayvnc` | ✓ | `rfb-proto.h:73`, `server.c:857` |
| QEMU `-vnc` | ✓ | originator; confirmed by probe — it answers with a −258 pseudo-rectangle, and it is the server the T3 tests use |
| **libvncserver** (and `x11vnc`, built on it) | **✗** | `rfbQemuExtendedKeyEvent` is defined in `include/rfb/rfbproto.h:531` and implemented in `libvncclient` only — nothing in `src/libvncserver/` |

So the keysym table is **not a nice-to-have fallback**; it is the path taken
against a real and common class of server. Build both, negotiate per
connection, and test both (`testing.md` §3.2).

UTF-8 text events (`0x00000017`, ≤ 32 bytes) have no scancode representation.
Map them to keysyms (`0x01000000 | codepoint` is the X11 convention for
Unicode) on RFB, and drop them on SPICE unless the agent clipboard can be
abused for it.

### 4.2 Pointer

```
NV_ABS_MOUSE_MOVE_PACKET { x, y, unused, width, height }   // magic 0x5
```

The packet carries its own reference `width`/`height`, so the conversion is
exact:

```
fb_x = x * fb_width  / width
fb_y = y * fb_height / height
```

Buttons: `BUTTON_LEFT 1, MIDDLE 2, RIGHT 3, X1 4, X2 5`
(`Limelight.h:687-691`), magics `0x8` down / `0x9` up.

| Moonlight | RFB button-mask bit | SPICE |
|---|---|---|
| LEFT | 0 | `SPICE_MOUSE_BUTTON_LEFT` |
| MIDDLE | 1 | MIDDLE |
| RIGHT | 2 | RIGHT |
| X1 | 7 (Back) | — |
| X2 | — | — |

RFB has no press/release messages — it has a *button mask*. Solstice must keep
the current mask as state and send a full `PointerEvent` on every change,
including motion. Scroll (`0x0000000A`) and horizontal scroll
(`0x55000001`) become momentary presses of bits 3–6.

Relative motion (`0x00000007`) only appears when the client has captured the
pointer. On RFB, accumulate it into the absolute position yourself; on SPICE in
server mouse mode it forwards directly.

### 4.3 Controllers, touch, pen

Neither backend has any notion of these. Options: drop them, or synthesise
keyboard/mouse from a gamepad. Drop them in v1 and say so in the README —
quietly swallowing controller input is the kind of thing that generates bug
reports.

### 4.4 Clipboard

Moonlight's protocol has no clipboard. RFB's `ServerCutText` and SPICE's agent
clipboard therefore have nowhere to go. Expose them over Solstice's own
management interface if they are wanted at all.

---

## 5. Latency budget

Every stage adds delay, and the bridge adds a full decode-composite-encode
round that neither protocol has on its own:

```
  backend update arrival      network RTT to the VNC/SPICE server
+ decode + composite          Tight/ZRLE or QUIC/GLZ, CPU-bound
+ frame clock wait            up to 1/fps
+ encode                      1–15 ms depending on encoder and hardware
+ packetise + pace            ~1 ms
+ network to client           RTT
+ client decode + present     client-side
```

The frame-clock wait and the composite are where a careless implementation
loses 50 ms. Mitigations: encode immediately on damage rather than waiting for
the next tick when the previous frame is already out; keep the framebuffer in a
format the encoder wants (NV12) and convert incrementally per damaged rect
rather than converting the whole screen every frame.

---

## 6. Backend abstraction

A trait that fits both backends has to accommodate SPICE's multi-connection,
multi-surface nature without contorting the RFB case:

```
trait Backend {
    async fn connect(cfg) -> Result<Session>;
}

trait Session {
    /// Best-effort: ask the remote desktop to change size. May decline.
    async fn request_resize(&self, w: u32, h: u32) -> Result<bool>;

    /// Damage events and framebuffer handoff. The framebuffer is owned by the
    /// session and borrowed under a lock; the encoder reads damaged rects.
    fn subscribe_damage(&self) -> Receiver<DamageEvent>;
    fn framebuffer(&self) -> &FramebufferHandle;

    /// Input, already translated into a backend-neutral form.
    async fn send_input(&self, ev: InputEvent) -> Result<()>;

    /// Audio, if the backend has any.
    fn audio(&self) -> Option<Receiver<AudioFrame>>;
}
```

`InputEvent` should carry **scancodes**, not keysyms, with an optional keysym
alongside — that keeps the lossy conversion at the edge of the RFB backend
instead of in shared code.

---

## 7. Suggested build order

1. **Skeleton host.** nvhttp + pairing + RTSP, serving a hard-coded colour-bar
   generator through the video packetizer. Getting Moonlight to display *any*
   picture validates the hardest-to-debug half of the system.
2. **Input.** Control stream, ENet, AES-GCM, input decoding — logged, not yet
   forwarded.
3. **VNC backend.** Framebuffer + damage, wired to the encoder. Input
   forwarded.
4. **Audio.** Opus silence, then real audio if the backend has it.
5. **Hardening.** Session limits, rate limits, TLS policy, the items in
   `security.md`.
6. **HEVC/AV1, SPICE** — in whichever order the use case demands. (FEC is
   not on this list: it belongs in step 1, per §2.5.)

Step 1 is the one to not shortcut. Almost every hard bug in this project will
be "Moonlight shows a black screen and says nothing", and a known-good
synthetic source is the only way to bisect it.
