# SPICE — protocol notes

Research notes, October 2026. Sources:

- `spice-protocol` (freedesktop GitLab) @ master — the canonical wire-format
  headers: `spice/protocol.h`, `spice/enums.h`, `spice/vd_agent.h`. Line
  references below are to that tree as of 2026-10-15.
- *Spice remote computing protocol definition v1.0 Draft 1*
  (spice-space.org) — the only prose spec, and it is a ~17-year-old draft.
  Useful for intent, unreliable for detail; the headers win.

> **Direction.** Solstice is a **client** here, as it is for VNC.
>
> **Status.** SPICE is explicitly the *optional* backend. It is substantially
> harder than RFB (see §7) and should be gated behind a Cargo feature.

---

## 1. Shape of the protocol

SPICE is not one connection. It is a set of independently-linked **channels**,
each its own TCP connection to the same server, each carrying typed messages
with a serial number. The guest-side half is split again between the
hypervisor (display, input) and an in-guest **agent** (`spice-vdagent`) reached
by tunnelling agent messages through the main channel.

Channel types (`enums.h:407-421`):

| № | Channel | Relevance to Solstice |
|---|---|---|
| 1 | MAIN | required — session setup, mouse mode, agent tunnel |
| 2 | DISPLAY | required — the picture |
| 3 | INPUTS | required — keyboard and mouse |
| 4 | CURSOR | optional — cursor shape/position |
| 5 | PLAYBACK | optional — guest audio out |
| 6 | RECORD | optional — guest audio in |
| 7 | TUNNEL | obsolete |
| 8 | SMARTCARD | out of scope |
| 9 | USBREDIR | out of scope |
| 10 | PORT | out of scope |
| 11 | WEBDAV | out of scope |

Magic is `"REDQ"`; current version is **2.2** (`protocol.h:37-39`).

All integers are little-endian — the opposite of RFB and of GameStream's RTP
headers.

---

## 2. Link handshake

Per channel, in order (`protocol.h:55-95`):

```
client → SpiceLinkHeader { magic="REDQ", major=2, minor=2, size }
         SpiceLinkMess   { connection_id, channel_type, channel_id,
                           num_common_caps, num_channel_caps, caps_offset }
                         followed by the capability bitmask words

server → SpiceLinkHeader
         SpiceLinkReply  { error, pub_key[162], num_common_caps,
                           num_channel_caps, caps_offset }
                         followed by its capability words

client → [ SpiceLinkAuthMechanism { auth_mechanism } ]   if PROTOCOL_AUTH_SELECTION
         SpiceLinkEncryptedTicket { encrypted_data[128] }

server → U32 link result (SpiceLinkErr)
```

`connection_id` is 0 on the first (main) channel; the server allocates one and
returns it in `SPICE_MSG_MAIN_INIT`, and every subsequent channel must link
with that id.

`SpiceLinkErr` values (`enums.h:37-50`): `OK`, `ERROR`, `INVALID_MAGIC`,
`INVALID_DATA`, `VERSION_MISMATCH`, `NEED_SECURED`, `NEED_UNSECURED`,
`PERMISSION_DENIED`, `BAD_CONNECTION_ID`, `CHANNEL_NOT_AVAILABLE`.

### 2.1 Common capabilities

`protocol.h:61-67`:

```
SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION  0
SPICE_COMMON_CAP_AUTH_SPICE               1
SPICE_COMMON_CAP_AUTH_SASL                2
SPICE_COMMON_CAP_MINI_HEADER              3
```

`MINI_HEADER` matters: it selects which message header is on the wire.

### 2.2 Ticket authentication

The server mints a **1024-bit RSA** key per connection and ships the public key
in `SpiceLinkReply.pub_key` (162 bytes = DER SubjectPublicKeyInfo). The client
encrypts the password — max 60 bytes (`protocol.h:44`) — with **RSA-OAEP,
MGF1-SHA1, empty label** and returns the 128-byte block.

SASL (common cap 2) is the alternative and supports GSSAPI/Kerberos.

Security commentary belongs in `security.md`; the short version is that this
scheme is a password check, not a key exchange, and offers no channel
protection by itself. SPICE's answer to that is a *separate TLS port*.

---

## 3. Message framing

Two forms, selected by `SPICE_COMMON_CAP_MINI_HEADER`
(`protocol.h:93-103`):

```c
struct SpiceDataHeader {      // full
    u64 serial;
    u16 type;
    u32 size;
    u32 sub_list;             // byte offset to a SpiceSubMessageList, or 0
};

struct SpiceMiniDataHeader {  // mini
    u16 type;
    u32 size;
};
```

Message type numbers are **per-channel namespaces**. Types 1–99 are the common
base set (`enums.h:423-433`): `MIGRATE`, `MIGRATE_DATA`, `SET_ACK`, `PING`,
`WAIT_FOR_CHANNELS`, `DISCONNECTING`, `NOTIFY`, `LIST`. Channel-specific types
start at 101.

`SET_ACK` / ack windows are a real flow-control mechanism and must be honoured
or the server will stall.

---

## 4. Main channel

Server → client (`enums.h:445-462`), the ones that matter:

```
SPICE_MSG_MAIN_INIT            103   session id, display channel hints, mouse mode, agent state
SPICE_MSG_MAIN_CHANNELS_LIST   104   which channels exist → what to connect next
SPICE_MSG_MAIN_MOUSE_MODE      105
SPICE_MSG_MAIN_MULTI_MEDIA_TIME 106  the A/V clock
SPICE_MSG_MAIN_AGENT_CONNECTED 107
SPICE_MSG_MAIN_AGENT_DATA      109   tunnelled vdagent traffic
SPICE_MSG_MAIN_AGENT_TOKEN     110   agent flow control
SPICE_MSG_MAIN_NAME / _UUID    113 / 114
```

Client → server (`enums.h:468-483`): `CLIENT_INFO 101`,
`ATTACH_CHANNELS 104`, `MOUSE_MODE_REQUEST 105`, `AGENT_START 106`,
`AGENT_DATA 107`, `AGENT_TOKEN 108`.

### 4.1 Mouse modes

`enums.h:118-121`:

```
SPICE_MOUSE_MODE_SERVER  1    relative motion; the guest draws its own cursor
SPICE_MOUSE_MODE_CLIENT  2    absolute positions; requires the agent
```

**Solstice wants CLIENT mode**, because Moonlight's natural input is absolute.
Client mode is only available when `spice-vdagent` is running in the guest. In
its absence, Solstice must convert absolute Moonlight coordinates into relative
deltas and accept that the pointer will drift — the same compromise every SPICE
client makes.

### 4.2 The agent tunnel

vdagent messages are wrapped in `MAIN_AGENT_DATA` and flow-controlled with
tokens. They provide (`vd_agent.h:78-110`): `MONITORS_CONFIG` (set the guest
resolution — the clean way to match Moonlight's requested mode),
`CLIPBOARD` / `CLIPBOARD_GRAB` / `CLIPBOARD_REQUEST` / `CLIPBOARD_RELEASE`,
and file transfer. Clipboard payload types include `UTF8_TEXT`, `IMAGE_PNG`,
and optionally BMP/TIFF/JPG (`vd_agent.h:281-292`).

---

## 5. Display channel — the hard part

SPICE's display channel is **not a video stream**. It is a 2D rendering command
stream against a set of server-side surfaces, with video streams layered on top
as an optimisation for regions the server has detected as video-like.

Server → client (`enums.h:485-519`):

```
101 MODE                   113..117 (surfaces, palettes, invalidation)
102 MARK                   302 DRAW_FILL
103 RESET                  303 DRAW_OPAQUE
104 COPY_BITS              304 DRAW_COPY
122 STREAM_CREATE          305 DRAW_BLEND
123 STREAM_DATA            306 DRAW_BLACKNESS
124 STREAM_CLIP            307 DRAW_WHITENESS
125 STREAM_DESTROY         308 DRAW_INVERS
126 STREAM_DESTROY_ALL     309 DRAW_ROP3
                           310 DRAW_STROKE
                           311 DRAW_TEXT
                           312 DRAW_TRANSPARENT
                           313 DRAW_ALPHA_BLEND
                           314 SURFACE_CREATE
                           315 SURFACE_DESTROY
                           316 STREAM_DATA_SIZED
                           317 MONITORS_CONFIG
                           318 DRAW_COMPOSITE
                           319 STREAM_ACTIVATE_REPORT
                           320 GL_SCANOUT_UNIX
                           321 GL_DRAW
```

Client → server (`enums.h:521-529`): `DISPLAY_INIT 101`, `STREAM_REPORT 102`,
`PREFERRED_COMPRESSION 103`, `GL_DRAW_DONE 104`,
`PREFERRED_VIDEO_CODEC_TYPE 105`.

### 5.1 Images

`DRAW_*` messages carry `SpiceImage`s whose descriptor selects a compression
scheme: **QUIC** (SPICE's own wavelet-ish codec), **LZ**, **GLZ** (LZ with a
cross-image history window), **JPEG**, **JPEG + LZ alpha**, **ZLIB-over-GLZ**,
**LZ4**, or raw bitmap.

QUIC and GLZ are the problem. Both are SPICE-specific, neither has a Rust
implementation, and GLZ is *stateful across images* — you cannot decode one
message in isolation. Any serious SPICE backend needs `spice-common`'s decoders
or a port of them. A client can bias the server away from them with
`PREFERRED_COMPRESSION`, but cannot forbid them.

### 5.2 Video streams

`STREAM_CREATE` opens a stream with a codec from `enums.h:147-155`:

```
SPICE_VIDEO_CODEC_TYPE_MJPEG 1
SPICE_VIDEO_CODEC_TYPE_VP8   2
SPICE_VIDEO_CODEC_TYPE_H264  3
SPICE_VIDEO_CODEC_TYPE_VP9   4
SPICE_VIDEO_CODEC_TYPE_H265  5
```

`PREFERRED_VIDEO_CODEC_TYPE` lets the client ask for one.

It is tempting to imagine asking for H.264 and forwarding it straight to
Moonlight. **This does not work.** A SPICE stream covers only a clipped
sub-rectangle that the server heuristically classified as video; the rest of
the screen still arrives as draw commands, and the stream can be destroyed and
recreated at any moment. There is no whole-screen H.264 to forward and no way
to request a keyframe on demand. The composite-then-re-encode path is the only
correct one.

### 5.3 GL scanout

`GL_SCANOUT_UNIX` passes a dmabuf FD for local zero-copy rendering. It is
local-only by construction and irrelevant to a network bridge; Solstice should
not advertise the capability.

---

## 6. Inputs channel

Small and pleasant (`enums.h:534-553`):

```
server → SPICE_MSG_INPUTS_INIT            101   initial modifier state
         SPICE_MSG_INPUTS_KEY_MODIFIERS   102
         SPICE_MSG_INPUTS_MOUSE_MOTION_ACK 111

client → SPICE_MSGC_INPUTS_KEY_DOWN       101   PC AT scancode
         SPICE_MSGC_INPUTS_KEY_UP         102
         SPICE_MSGC_INPUTS_KEY_MODIFIERS  103
         SPICE_MSGC_INPUTS_KEY_SCANCODE   104   raw scancode bytes
         SPICE_MSGC_INPUTS_MOUSE_MOTION   111   relative (server mouse mode)
         SPICE_MSGC_INPUTS_MOUSE_POSITION 112   absolute (client mouse mode)
         SPICE_MSGC_INPUTS_MOUSE_PRESS    113
         SPICE_MSGC_INPUTS_MOUSE_RELEASE  114
```

Keys are **PC AT / XT scancodes**, not keysyms. That is good news: it is the
same representation as RFB's QEMU Extended Key Event, so one Moonlight-VK →
scancode table serves both backends.

`MOUSE_MOTION_ACK` is flow control — the client may have at most
`SPICE_INPUT_MOTION_ACK_BUNCH` (4, `protocol.h:113`) unacknowledged motion
bunches outstanding.

---

## 7. Audio

`PLAYBACK` carries guest audio out. Codec capabilities
(`protocol.h:116-121`) are CELT 0.5.1, and — importantly — **Opus**
(`SPICE_PLAYBACK_CAP_OPUS`).

This is a genuine advantage over RFB: GameStream's audio stream is Opus, so a
SPICE Opus playback stream can in principle be **repacketised rather than
transcoded**, provided the channel layout and frame duration line up with what
the client requested in `x-nv-aqos.packetDuration`. Worth confirming
experimentally before relying on it.

---

## 8. Consequences for Solstice

1. **Multi-connection, multi-threaded by nature.** Each channel is its own
   socket with its own ack window. The backend trait must tolerate this; a
   trait shaped around "one socket, one read loop" will not fit SPICE.
2. **Compositing is mandatory and harder than RFB's.** Draw commands,
   multiple surfaces, QUIC/GLZ/LZ4 images, plus overlaid video streams, all
   have to be rendered into one framebuffer before encoding.
3. **The image codecs are the gating item.** QUIC and GLZ have no Rust
   implementations. Realistic paths: FFI to `spice-common`, port the decoders,
   or constrain the server (`PREFERRED_COMPRESSION`) and accept a fallback to
   software rendering when something unsupported arrives.
4. **Input is the easy part**, and shares a scancode table with the VNC
   backend.
5. **The agent is what makes it good.** `MONITORS_CONFIG` to match Moonlight's
   requested resolution, client-mode absolute mouse, and clipboard all require
   `spice-vdagent` in the guest. Degrade gracefully when it is absent.

### Crate options

`spice-client` (0.2.0, updated 2025-10-04, ~5 k downloads) exists and bills
itself as a pure-Rust SPICE client with WASM support, but it is a component of
`quickemu-manager` rather than a general-purpose library and the download count
suggests very little production exposure. Read it before depending on it;
expect to need the image decoders it may not have.

This is the main reason SPICE is scoped as optional and deferred.
