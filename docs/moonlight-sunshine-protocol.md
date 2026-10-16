# The Moonlight / Sunshine (NVIDIA GameStream) protocol

Research notes, October 2026. Everything here was read out of source, not
documentation — there is no authoritative spec. Primary sources:

- `moonlight-stream/moonlight-common-c` @ master — the client core, shared by
  every Moonlight port. Authoritative for what a client *sends and expects*.
- `LizardByte/Sunshine` @ master — the de-facto host implementation.
  Authoritative for what a host *must produce*.

Line references below are to those trees as of 2026-10-15.

> **Direction matters.** Moonlight is the *client*. To let Moonlight connect to
> it, Solstice must implement the **host** side — i.e. it is a Sunshine, not a
> Moonlight. Everything in this document is therefore a list of things Solstice
> has to *serve*.

---

## 1. Transport overview

Sunshine derives every port from one configurable base (`port`, default
`47989`) by adding a fixed offset (`net::map_port`, `src/network.cpp:243`).

| Offset | Default | Proto | Purpose | Source |
|---|---|---|---|---|
| −5 | 47984 | TCP | NVHTTP over TLS, mutual-auth | `nvhttp.h:52` |
| 0  | 47989 | TCP | NVHTTP plaintext (pairing, serverinfo) | `nvhttp.h:47` |
| +1 | 47990 | TCP | Web config UI (HTTPS) — *not* part of the streaming protocol | `confighttp.h:29` |
| +9 | 47998 | UDP | Video | `stream.h:19` |
| +10| 47999 | UDP | Control (ENet) | `stream.h:20` |
| +11| 48000 | UDP | Audio | `stream.h:21` |
| +21| 48010 | TCP | RTSP setup | `rtsp.h:18` |

A session proceeds in four phases:

```
  1. Pairing        HTTP  47989   once per client, PIN-gated, produces mutual TLS trust
  2. Query/Launch   HTTPS 47984   serverinfo / applist / launch, client cert required
  3. RTSP setup     TCP   48010   OPTIONS → DESCRIBE → SETUP ×3 → ANNOUNCE → PLAY
  4. Streaming      UDP   47998 / 47999 / 48000
```

Discovery is mDNS (`_nvstream._tcp`), but Moonlight also accepts a manually
typed host, so Solstice can skip mDNS in v1.

---

## 2. NVHTTP

A quasi-REST API returning XML (`boost::property_tree` XML, so
`<?xml version="1.0" encoding="utf-8"?><root status_code="200">…</root>`).

Endpoints served on **both** HTTP and HTTPS (`nvhttp.cpp:1734-1755`):

| Endpoint | HTTP | HTTPS | Notes |
|---|---|---|---|
| `/serverinfo` | ✓ | ✓ | capability + state advertisement |
| `/pair` | ✓ | ✓ | HTTP = the real pairing flow; HTTPS = `phrase=pairchallenge` only |
| `/applist` | — | ✓ | list of launchable apps |
| `/appasset` | — | ✓ | box art PNG |
| `/launch` | — | ✓ | start a session |
| `/resume` | — | ✓ | re-attach to a running session |
| `/cancel` | — | ✓ | tear down |

HTTPS requires a client certificate (`verify_peer |
verify_fail_if_no_peer_cert | verify_client_once`, `nvhttp.cpp:97`) signed by
nobody — the chain is built from the certs stored at pairing time.

### 2.1 `/serverinfo`

Response fields Moonlight actually reads (`nvhttp.cpp:1265-1310`):

```
hostname                 display name
appversion               e.g. "7.1.431.-1"  ← gates protocol generation, see §4
GfeVersion               e.g. "3.23.0.74"
uniqueid                 host UUID
HttpsPort / ExternalPort echoed port numbers
MaxLumaPixelsHEVC        "1869449984" if HEVC offered, else "0"
mac                      real MAC only over HTTPS; "00:00:00:00:00:00" over HTTP
LocalIP                  must be IPv4; return 127.0.0.1 for v6 peers
ServerCodecModeSupport   SCM_* bitmask, see §2.2
PairStatus               1 if the requesting client cert is paired
currentgame              0, or the running app id
state                    "SUNSHINE_SERVER_FREE" | "SUNSHINE_SERVER_BUSY"
```

`appversion` is load-bearing: `moonlight-common-c` parses it into
`AppVersionQuad` and selects packet-type tables and RTSP stream-id strings from
it (`ControlStream.c:300-340`, `RtspConnection.c:953`). **Solstice must
advertise ≥ 7.1.431 to get the modern, encrypted protocol generation.**

### 2.2 Codec advertisement

`ServerCodecModeSupport` (`Limelight.h:506-522`):

```
SCM_H264            0x00000001
SCM_HEVC            0x00000100
SCM_HEVC_MAIN10     0x00000200
SCM_AV1_MAIN8       0x00010000   Sunshine extension
SCM_AV1_MAIN10      0x00020000   Sunshine extension
SCM_H264_HIGH8_444  0x00040000   Sunshine extension
SCM_HEVC_REXT8_444  0x00080000   Sunshine extension
SCM_HEVC_REXT10_444 0x00100000   Sunshine extension
SCM_AV1_HIGH8_444   0x00200000   Sunshine extension
SCM_AV1_HIGH10_444  0x00400000   Sunshine extension
```

For a desktop-remoting bridge, advertise `SCM_H264` only at first. H.264 High
Profile is universally decodable by Moonlight clients and is the cheapest thing
to encode.

### 2.3 `/launch` and `/resume` query parameters

Parsed in `make_launch_session` (`nvhttp.cpp:487-543`). Required (checked at
`nvhttp.cpp:1395-1401`): `rikey`, `rikeyid`, `localAudioPlayMode`, `appid`.

| Param | Meaning |
|---|---|
| `rikey` | hex, 16 bytes — **the AES-128 session key** for control/audio/video/RTSP |
| `rikeyid` | signed int — big-endian u32 placed in bytes 0..4 of the 16-byte audio IV |
| `mode` | `WxHxFPS` |
| `appid` | app to launch |
| `sops` | "optimize game settings" — ignore |
| `localAudioPlayMode` | 1 = also play audio on the host |
| `surroundAudioInfo` | `(channelMask << 16) \| channelCount`, default 196610 = stereo |
| `surroundParams` | Opus multistream config, ASCII digits |
| `continuousAudio`, `gcmap`, `hdrMode` | feature toggles |
| `uniqueid` | client id |
| `corever` | **≥ 1 ⇒ the client supports encrypted RTSP**; selects `rtspenc://` |

Response carries `<sessionUrl0>` — the RTSP URL the client will dial, with
scheme `rtsp://` or `rtspenc://` (`nvhttp.cpp:1474`, `:1575`).

Two random values are minted here and used later as session identifiers:

- `av_ping_payload` — 8 random bytes, **hex-encoded to 16 ASCII chars**. The
  client echoes this in its UDP ping on the video and audio ports; that is how
  the host learns the client's UDP source address (`nvhttp.cpp:534`,
  `stream.cpp:2348`, `stream.cpp:2385`).
- `control_connect_data` — a u32 sent as ENet `connect data`, used to bind an
  incoming ENet peer to a session (`stream.cpp:~690`).

---

## 3. Pairing

The PIN handshake lives entirely on **plaintext HTTP** and runs as four
sequential `GET /pair?…` calls plus a final HTTPS probe. Sunshine enforces
phase ordering with `sess.last_phase` (`nvhttp.cpp:752-910`) — this ordering
check is itself the subject of CVE-2024-51738, see `security.md`.

Let `K = SHA256(salt ‖ pin_ascii)[0..16]`, used as **AES-128 in ECB mode**
(`crypto.cpp:325-339`, cipher constructed at `nvhttp.cpp:790`).

```
① GET /pair?devicename=…&updateState=1&phrase=getservercert
            &salt=<32 hex chars = 16 bytes>&clientcert=<hex of PEM>

   host:  ← <paired>1</paired><plaincert>hex(server PEM)</plaincert>
   The host now waits for a human to type the PIN into its UI.

② GET /pair?clientchallenge=<hex AES-ECB_K(client_challenge[16])>

   host:  c   = AES-ECB-decrypt_K(clientchallenge)
          h   = SHA256(c ‖ sig(server_cert) ‖ server_secret[16])
          sc  = random[16]                       (server challenge)
       ← <challengeresponse>hex(AES-ECB-encrypt_K(h ‖ sc))</challengeresponse>

③ GET /pair?serverchallengeresp=<hex AES-ECB_K(client_hash)>

   host:  client_hash := AES-ECB-decrypt_K(…)    (stored, verified in ④)
       ← <pairingsecret>hex(server_secret ‖ RSA-SHA256(server_key, server_secret))</pairingsecret>

④ GET /pair?clientpairingsecret=<hex (client_secret[16] ‖ signature)>

   host:  expect = SHA256(sc ‖ sig(client_cert) ‖ client_secret)
          ok = (expect == client_hash) && verify_sha256(client_cert, client_secret, signature)
          if ok: persist client_cert as an authorized device
       ← <paired>1|0</paired>

⑤ GET /pair?phrase=pairchallenge   over HTTPS, presenting the client cert
```

`sig(cert)` here means the raw signature bytes of the X.509 structure
(`crypto::signature`), not a hash of the cert.

Both sides are self-signed; trust is pure TOFU, bootstrapped by the PIN.

---

## 4. RTSP

TCP 48010. The dialect is RTSP-shaped but not RFC 2326 — `moonlight-common-c`
ships its own parser and even notes a *"Hacked CSeq attribute due to RTSP
parser bug"* (`RtspConnection.c:77`). Implement against the observed bytes, not
the RFC.

Sequence (`RtspConnection.c:944-1410`, server side `rtsp.cpp:1289-1293`):

```
OPTIONS   rtsp://<host>:48010
DESCRIBE  rtsp://<host>:48010        → SDP body advertising codecs + Opus config
SETUP     streamid=audio/0/0         → Transport: …;server_port=48000
SETUP     streamid=video/0/0         → Transport: …;server_port=47998
SETUP     streamid=control/13/0      → Transport: …;server_port=47999
ANNOUNCE  streamid=control/13/0      ← client's full stream configuration (SDP)
PLAY      rtsp://<host>:48010
```

Stream-id strings are version-gated: `control/13/0` for appversion ≥ 7.1.431,
`control/1/0` below; `audio/0/0` and `video/0/0` need major ≥ 5
(`RtspConnection.c:953`, `:1176`, `:1253`). The client parses `server_port=`
out of the `Transport` response header (`RtspConnection.c:717-745`) — so the
host *can* relocate its UDP ports per-session if it wants.

`PLAY` is a single request with the target `/` for appversion ≥ 7.1.431, and
*two* requests — `streamid=video` then `streamid=audio` — below it
(`RtspConnection.c:1353-1412`). A host that starts its stream on PLAY needs to
know which it will get.

### 4.0 One connection per message

**Each RTSP message gets its own TCP connection, and the response is
terminated by the host closing it.** `transactRtspMessageTcp`
(`RtspConnection.c:386-517`) calls `connectTcpSocket` at the top and
`closeSocket` at the bottom, and its read loop treats `recv() == 0` as "done
reading" — there is no length prefix and no message-boundary scan.

Two consequences for a host:

- **Reply, then close.** A host that holds the connection open leaves the
  client blocking until `RTSP_RECEIVE_TIMEOUT_SEC` (15 s) and the handshake
  fails at `STAGE_RTSP_HANDSHAKE`.
- **The negotiation state belongs to the launch session, not the socket.**
  The stage ordering that makes `SETUP` legal only after `DESCRIBE`, the count
  of streams set up, and the encryption sequence number all have to survive
  across connections. A per-connection state machine sees seven first
  messages.

### Three headers Sunshine adds to `SETUP`

None are in any RFC and the client silently falls back when they are absent,
which makes each of them an invisible failure:

| Header | On | Read at | Absent ⇒ |
|---|---|---|---|
| `Session: <id>;timeout = 90` | audio | `RtspConnection.c:1214-1231` | the client fails the handshake outright |
| `X-SS-Ping-Payload: <16 ASCII>` | audio, video | `RtspConnection.c:1202-1207`, `:1267-1272` | the client sends the 4-byte legacy `"PING"` instead of the payload from `/launch`, so a host that refuses the legacy form (as `security.md` §2.3 says to) never learns the client's address and sends nothing at all |
| `X-SS-Connect-Data: <u32>` | control | `RtspConnection.c:1309-1316`, `strtoul(…, 0)` | the client connects with ENet connect data `0`, and a host that binds peers to a session by that value refuses it |

### 4.1 Encrypted RTSP (`rtspenc://`)

Selected when the client reported `corever >= 1`. Every RTSP message is wrapped
in a 24-byte header (`rtsp.h:25-70`) and the body is AES-128-GCM under the
`rikey`:

```
struct encrypted_rtsp_header {   // packed, 24 bytes
    u32be typeAndLength;         // 0x80000000 | payload_length
    u32be sequenceNumber;        // → low 4 bytes of the AES IV
    u8    tag[16];               // GCM auth tag
};                               // ciphertext follows
```

The 12-byte IV is **not** just the sequence number
(`RtspConnection.c:122-132`, `:197-206`):

```
iv[0..4]  = sequenceNumber, little-endian   (note: the header field is big-endian)
iv[4..10] = 0
iv[10]    = 'C' client-originated | 'H' host-originated
iv[11]    = 'R' RTSP stream
```

Both tag bytes matter. Each end numbers its own messages from zero, so without
`iv[10]` the two directions would reuse a nonce under one key; without
`iv[11]` the RTSP and control streams would. Get either wrong and nothing
decrypts — the host refuses the client's first `OPTIONS` and the client
refuses the host's first reply. The same `'C'`/`'H'` + stream-letter scheme is
used by the control stream (§7.1) and the video stream (§5.5).

The MSB of `typeAndLength` is how a parser tells encrypted from plaintext.
Sunshine rejects a plaintext message once the session is encrypted
(`rtsp.cpp:166`). The client is equally strict in the other direction: it
rejects a response that is partial *or* has excess data
(`RtspConnection.c:185-194`), so exactly one envelope per connection.

### 4.2 The ANNOUNCE SDP — the real configuration channel

This is where the client states what it wants. Sunshine reads `s=` (client
name) and every `a=<name>:<value>` line (`rtsp.cpp:1023-1160`). Keys that
Solstice must handle; those with a `try_emplace` default in Sunshine are
optional:

```
x-nv-video[0].clientViewportWd / .clientViewportHt    requested resolution
x-nv-video[0].maxFPS                                   requested framerate
x-nv-video[0].clientRefreshRateX100                    display refresh ×100 (optional)
x-nv-video[0].packetSize                               max UDP payload — drives MTU
x-nv-video[0].videoEncoderSlicesPerFrame
x-nv-video[0].maxNumReferenceFrames
x-nv-video[0].encoderCscMode                           (default 0)
x-nv-video[0].dynamicRangeMode                         HDR (default 0)
x-nv-vqos[0].bitStreamFormat                           0=H.264 1=HEVC 2=AV1 (default 0)
x-nv-vqos[0].bw.maximumBitrateKbps
x-nv-vqos[0].fec.minRequiredFecPackets                 (default 0)
x-nv-vqos[0].qosTrafficType                            (default 5)
x-nv-audio.surround.numChannels / .channelMask / .AudioQuality
x-nv-aqos.packetDuration                               ms per Opus packet (default 5)
x-nv-aqos.qosTrafficType                               (default 4)
x-nv-general.useReliableUdp                            **13 ⇒ encrypted control**, else 1
x-nv-general.featureFlags                              bit 0x20 = legacy audio-encryption opt-in
x-ml-general.featureFlags                              Moonlight extensions (default 0)
x-ml-video.configuredBitrateKbps                       (default 0)
x-ss-general.encryptionEnabled                         SS_ENC_* bitmask (default 0)
x-ss-video[0].chromaSamplingType                       0=4:2:0 1=4:4:4 (default 0)
x-ss-video[0].intraRefresh                             (default 0)
```

Quirk worth knowing: for **stereo** audio, "high quality" is signalled by
whether the RTSP `Host:` header is `0.0.0.0` (low) or a real address (high)
(`rtsp.cpp:1163-1172`). Genuinely.

### 4.3 Encryption negotiation

`SS_ENC_*` flags (`Limelight-internal.h:48-50`):

```
SS_ENC_CONTROL_V2  0x01
SS_ENC_VIDEO       0x02
SS_ENC_AUDIO       0x04
```

Sunshine's DESCRIBE advertises what it supports and requests
(`rtsp.cpp:881-892`); the client answers in `x-ss-general.encryptionEnabled`.
Note the default policy: **LAN = `ENCRYPTION_MODE_NEVER`, WAN =
`ENCRYPTION_MODE_OPPORTUNISTIC`** (`config.cpp:826-827`). Control is always
encrypted; video and audio are not, by default, on a LAN. See `security.md`.

---

## 5. Video stream — UDP 47998

### 5.1 Session start

The client sends an `SS_PING` to the video port; the host matches the payload
against `av_ping_payload` to learn the client's source address
(`stream.cpp:2087-2135`).

```
struct SS_PING {               // big-endian
    char payload[16];          // the 16 hex chars from /launch
    u32  sequenceNumber;
};
```

A legacy form with the literal body `"PING"` is accepted unless the client set
`ML_FF_SESSION_ID_V1`.

### 5.2 Packet layout

Built in `videoBroadcastThread` (`stream.cpp:1560-1860`). On the wire, each UDP
datagram is:

```
[ video_packet_enc_prefix (32 B) ]   ← only if SS_ENC_VIDEO
  RTP_PACKET                (12 B)
  reserved                  ( 4 B)
  NV_VIDEO_PACKET           (16 B)
  payload                   (… up to packetSize)
```

```c
struct RTP_PACKET {        // Video.h
    u8    header;          // 0x80 | FLAG_EXTENSION(0x10)  ⇒ 0x90
    u8    packetType;      // left 0 for video
    u16be sequenceNumber;  // low 16 bits of a wider counter
    u32be timestamp;       // 90 kHz clock
    u32   ssrc;            // 0
};

struct NV_VIDEO_PACKET {   // little-endian
    u32 streamPacketIndex; // (lowseq + i) << 8
    u32 frameIndex;
    u8  flags;             // 0x1 CONTAINS_PIC_DATA | 0x2 EOF | 0x4 SOF
    u8  extraFlags;        // 0x1 = LTR frame
    u8  multiFecFlags;     // always 0x10
    u8  multiFecBlocks;    // (blockIndex << 4) | ((blockCount-1) << 6)
    u32 fecInfo;           // (shardIndex << 12) | (dataShards << 22) | (pct << 4)
};
```

Note the width mismatch that has bitten forks: the sequence counter is wider
than 16 bits and only its low 16 bits go in `rtp.sequenceNumber`, while
`streamPacketIndex` carries 24 usable bits (`<< 8`). Get this wrong and the
picture freezes after 65536 packets.

### 5.3 Frame framing

The first data packet of each frame begins with an 8-byte header
(`stream.cpp:101-135`), then the access unit in Annex-B:

```c
struct video_short_frame_header_t {   // 8 bytes, packed
    u8    headerType;                 // 0x01
    u16le frame_processing_latency;   // 1/10 ms, 0 if unknown  (Sunshine ext)
    u8    frameType;                  // 1 P, 2 IDR, 4 intra-refresh, 5 post-RFI
    u16le lastPayloadLen;             // real length of the final packet (AV1 ext)
    u8    unknown[2];
};
```

Frames are split into fixed-size blocks of `packetSize + MAX_RTP_HEADER_SIZE`
and zero-padded; `lastPayloadLen` tells the decoder where the real data stops.

### 5.4 FEC

Reed–Solomon over GF(2^8), up to **4 blocks** per frame (2 bits in
`multiFecBlocks`), max 255 shards per block, so
`data_shards = 255*100 / (100 + fec_pct)`. If a frame needs more than 4 blocks,
Sunshine disables FEC for it entirely (`stream.cpp:1637-1643`).

#### What the parity covers, exactly

Parity is computed over the **whole shard including the NV header**, with some
per-shard header fields patched afterwards. Which fields land on which side of
the encode is not a detail — the client asserts on it.

`stream.cpp:1694-1711` writes these **before** `fec::encode`, so they are in
the parity and a recovered shard gets them back:

> `streamPacketIndex`, `flags` (`CONTAINS_PIC_DATA`/`SOF`/`EOF`),
> `extraFlags`, `multiFecFlags`

`stream.cpp:1745-1759` patches these **after**, over every shard including the
parity ones, so they are *not* recoverable and the client re-derives them from
the rest of the block:

> `rtp.header`, `rtp.sequenceNumber`, `rtp.timestamp`, `fecInfo`,
> `multiFecBlocks`, `frameIndex`

`RtpVideoQueue.c:355-389` is the mirror image: the client overwrites exactly
the second list on a recovered shard and then asserts the first list matches
the original byte for byte. Putting a field on the wrong side fails that
assertion in a debug Moonlight and silently corrupts recovered frames in a
release one.

Two consequences that look like bugs and are not:

- **A parity shard's `flags`, `extraFlags`, `multiFecFlags` and
  `streamPacketIndex` are Reed–Solomon output** — effectively random bytes.
  Nothing patches them afterwards. So `flags & CONTAINS_PIC_DATA` is **not**
  how you tell a parity shard from a data one; the client uses the sequence
  number (`RtpVideoQueue.c:738`), and `fecInfo` carries the same information
  in a field that *is* patched.
- `rtp.packetType`, `rtp.ssrc` and the four reserved bytes are never patched
  at all, so in a parity shard they hold parity too. A host that helpfully
  zeroes them takes those bytes out of the recovery.

The parity count is **never transmitted**. Both sides derive it from `D` and
the percentage with the same expression (`stream.cpp:866`, `RtpVideoQueue.c:712`):

```
P = (D * fec_percentage + 99) / 100        # integer division = ceil
```

An encoder must therefore guarantee that the percentage it writes re-derives to
the parity count it actually used. The client applies **no minimum of its own**
— that expression is the whole of its knowledge. So Sunshine's
`minRequiredFecPackets` path (Moonlight sends `2`) bumps `P` *and recomputes*
`pct = 100*P/D` before writing it into `fecInfo` (`stream.cpp:867-873`); the
round-trip holds because the bump only fires for `D <= 5`, where
`200/D ∈ {200, 100, 66, 50, 40}` all re-derive to 2.

Declaring the configured percentage next to a bumped count is the subtle
version of getting this wrong: the client builds a Reed–Solomon matrix one row
short of the host's, and every recovery from that block is quietly garbage.

#### The matrix is a closed form

`nanors` generates its parity matrix in four lines (`nanors/rs.c:125-129`):

```c
for (int j = 0; j < rs->ps; j++) {
    u8 *row = rs->p + j * rs->ds;
    for (int i = 0; i < rs->ds; i++)
        row[i] = GF2_8_INV[(rs->ps + i) ^ j];
}
```

That is a **Cauchy matrix** — rows indexed from `{0..ps-1}`, columns from
`{ps..ps+ds-1}`. The sets are disjoint, so no term is zero and every square
submatrix is nonsingular, which is the MDS property erasure coding needs. The
field is fixed by `nanors/deps/obl/gf2_8_tables.h:1`: *"these tables were
generated with polynomial: 285"* (0x11D). Encoding is a plain systematic GEMM
(`rs.c:229`).

The complete specification is therefore:

| | |
|---|---|
| Field | GF(2⁸), primitive polynomial 285 (0x11D) |
| Matrix | `P[j][i] = inv((ps + i) XOR j)`, `j∈[0,ps)`, `i∈[0,ds)` |
| Encode | systematic; `parity[j] = Σᵢ P[j][i] · data[i]` |

Verified byte-exact against a compiled `nanors` by an independent
reimplementation — see `tests/vectors/fec/`:

```
ds=1    ps=2   bs=32    matrix=MATCH  parity=MATCH    small-frame case
ds=5    ps=2   bs=64    matrix=MATCH  parity=MATCH    minRequiredFecPackets bump
ds=212  ps=42  bs=96    matrix=MATCH  parity=MATCH    max block at 20%
ds=100  ps=20  bs=1408  matrix=MATCH  parity=MATCH    real blocksize (1392+16)
```

So this is ~50 lines of Rust, not a dependency problem. Generic crates still do
not interoperate — `reed-solomon-erasure` is Vandermonde-based and
`reed-solomon-simd` is FFT-based over GF(2¹⁶) — but that is a reason to
implement the closed form, not a reason to defer.

> **Audio FEC is a different code.** `nanors` for RS(4,2) gives
> `142 244 71 167 / 244 142 167 71`, whereas Sunshine's Nvidia-compatible audio
> matrix is `119 64 56 14 / 199 167 13 108` (`stream.cpp:1872-1878`, hard-coded
> because "the RS parity matrix computed by our RS implementation doesn't match
> the one Nvidia uses"). Unrelated matrices. One implementation does **not**
> cover both.

`fec_percentage = 0` remains legal (`config.cpp:1811`) and is a useful bisection
tool when debugging the packetiser, but it is not the recommended shipping
configuration. Note also that the packetiser's buffer layout is shaped around
FEC — `concat_and_insert` reserves 32 bytes at every block boundary so shards
can be built in place — so retrofitting it later means rewriting that path.

### 5.5 Video encryption

When `SS_ENC_VIDEO` is on, each shard is encrypted in place with AES-128-GCM
and prefixed (`stream.cpp:1762-1781`):

```c
struct video_packet_enc_prefix_t {   // 32 bytes
    u8  iv[12];
    u32 frameNumber;
    u8  tag[16];
};
```

The IV is deterministic per NIST SP 800-38D §8.2.1: a 64-bit little-endian
counter in bytes 0..8, and `iv[11] = 'V'` as the fixed field.

---

## 6. Audio stream — UDP 48000

Opus, in RTP. Same `SS_PING` address-discovery step as video.

```
RTP_PACKET { header = 0x80, packetType = 97, seq = u16be, ts = u32be, ssrc = 0 }
payload: Opus packet, optionally AES-128-CBC/PKCS#7 encrypted
```

`timestamp` advances by `packetDuration` (milliseconds) per packet. The CBC IV
is 16 zero bytes with `BE32(rikeyid + sequenceNumber)` written over bytes 0..4
(`stream.cpp:1899`).

FEC is fixed **RS(4, 2)** — four data shards, two parity
(`RtpAudioQueue.h:11-13`). Parity packets use `packetType = 127` and carry:

```c
struct AUDIO_FEC_HEADER {
    u8    fecShardIndex;
    u8    payloadType;
    u16be baseSequenceNumber;
    u32be baseTimestamp;
    u32   ssrc;
};
```

The parity matrix Sunshine patches in is
`{0x77, 0x40, 0x38, 0x0e, 0xc7, 0xa7, 0x0d, 0x6c}`.

**The sequence number advances once per data packet and never for parity**
(`stream.cpp:1913`). The two parity packets of a block *borrow* the next two
sequence numbers — the block starting at `n` sends data at `n..n+3` and parity
at `n+4` and `n+5` — and the following block then starts at `n+4`, colliding
with them. That is intentional: a parity packet is told apart by
`packetType = 127`, not by its sequence number.

The reason it has to work that way is `RtpAudioQueue.c:269-280`: a block whose
`baseSequenceNumber` is not a multiple of four is rejected, logged as *"Audio
FEC has been disabled due to an incompatibility with your host's old
software!"*, and audio FEC is switched off **for the rest of the session**. A
host that reserves sequence numbers for its parity produces bases of 0, 6, 12,
… and only the first one is ever accepted.

---

## 7. Control stream — UDP 47999 (ENet)

Reliable-UDP via **ENet 1.3.x**. The client supplies `control_connect_data` as
ENet connect data so the host can bind the peer to a session — it learns the
value from `X-SS-Connect-Data` on the control `SETUP` (§4), and uses `0` when
that header is missing. Input events, IDR requests, loss statistics, rumble,
HDR state and termination all ride here.

**The client connects here before it sends a single video ping.**
`STAGE_CONTROL_STREAM_START` runs at `Connection.c:483`, and the ping thread
that tells the host where to send video does not start until
`startVideoStream` at `:497` (`VideoStream.c:382-384`). A host that waits for
the ping before binding its ENet socket deadlocks against every real client:
each side is waiting for the other to go first. Bind the control port first.

(The *audio* ping thread is the exception — it starts before the RTSP
handshake, for GFE 3.22 compatibility: `AudioStream.c:87-95`.)

### 7.1 Framing

Plaintext (legacy) inner header:

```c
struct NVCTL_ENET_PACKET_HEADER_V2 { u16le type; u16le payloadLength; };
```

Encrypted envelope, used whenever `useReliableUdp == 13`
(`ControlStream.c:25-32`, `stream.cpp:245-305`):

```c
struct NVCTL_ENCRYPTED_PACKET_HEADER {
    u16le encryptedHeaderType;  // always 0x0001
    u16le length;               // sizeof(seq) + 16 tag + encrypted body
    u32le seq;                  // → IV
};
// then: u8 tag[16], then AES-128-GCM ciphertext of {V2 header ‖ payload}
```

IV construction (`ControlStream.c:548-580`), 12 bytes:

```
iv[0..4] = seq, little-endian
iv[10]   = 'C'   // 'C' client-originated, 'S' server-originated
iv[11]   = 'C'   // control stream
```

Sunshine drops any unencrypted message on an encrypted stream
(`stream.cpp:746-750`).

### 7.2 Message types (generation 7, encrypted — `ControlStream.c:203-217`)

| Type | Meaning |
|---|---|
| `0x0302` | Request IDR frame |
| `0x0307` | Start B |
| `0x0301` | Invalidate reference frames |
| `0x0201` | Loss stats |
| `0x0204` | Frame stats (unused) |
| `0x0206` | **Input data** |
| `0x010b` | Rumble |
| `0x0109` | Termination (extended) |
| `0x010e` | HDR mode |
| `0x5500` | Rumble triggers (Sunshine ext) |
| `0x5501` | Set motion event (Sunshine ext) |
| `0x5502` | Set RGB LED (Sunshine ext) |
| `0x5503` | Adaptive triggers (Sunshine ext) |

Also carried on this channel, client → host:

- `SS_FRAME_FEC_STATUS` (ptype `0x5502` in the video-feedback sense, big-endian
  fields) — per-frame FEC accounting.
- `SS_LTR_FRAME_ACK` (`0x0350`) and `SS_RFI_REQUEST` (`0x0301`), little-endian.

### 7.3 Input packets

All on `0x0206`, each with a 4-byte little-endian magic (`Input.h`):

| Magic | Packet |
|---|---|
| `0x00000003` / `0x00000004` | Key down / key up |
| `0x00000005` | Absolute mouse move |
| `0x00000007` | Relative mouse move (gen5+) |
| `0x00000008` / `0x00000009` | Mouse button down / up (gen5+) |
| `0x0000000A` | Scroll (gen5+) |
| `0x0000000C` | Multi-controller (gen5+) |
| `0x00000017` | UTF-8 text (max 32 chars) |
| `0x55000001` | Horizontal scroll (Sunshine ext) |
| `0x55000002` | Touch (Sunshine ext) |
| `0x55000003` | Pen (Sunshine ext) |
| `0x55000004`–`0x55000007` | Controller arrival / touch / motion / battery |

Keyboard packets carry **Windows virtual-key codes with a modifier byte**, not
X11 keysyms and not evdev scancodes. The absolute-mouse packet carries a
reference width/height the coordinates are relative to. Both facts matter for
the VNC/SPICE mapping — see `bridging-design.md`.

A `0x0206` message is a *batch*: Sunshine walks the payload and dispatches each
magic-prefixed record in turn.

---

## 8. What a minimal host must do

Ordered by dependency, this is the build list:

1. TLS listener with a self-signed cert, client-cert-required, on 47984.
2. Plaintext HTTP on 47989 for `/serverinfo` and `/pair`.
3. The four-step PIN handshake; persist client certs.
4. `/applist`, `/launch`, `/resume`, `/cancel`.
5. RTSP on 48010, both plaintext and GCM-wrapped, with an SDP DESCRIBE and a
   parser for the ANNOUNCE attribute soup — one message per connection,
   closing after each reply, with the negotiation state kept per session
   (§4.0), and the three `SETUP` headers of §4.
6. UDP ping responder on 47998/48000 to learn the peer address. Bind the ENet
   control port (8) *before* waiting on the video ping, or deadlock (§7).
7. H.264 Annex-B → `NV_VIDEO_PACKET` packetizer on 47998 (FEC off initially).
8. ENet host on 47999, AES-GCM envelope, input-packet decoder.
9. Opus sender on 48000 (can be silence, or omitted if the client tolerates it
   — it generally expects *something*).

Steps 1–6 and 8 are protocol plumbing with no hard problems. Step 7 is where
the real work is, and it is a *video-encoding* problem, not a protocol one.

None of that is the same as being interoperable. Everything in this document
that a host can get wrong *symmetrically* — an IV construction, a FEC field
ordering, a sequence-numbering rule — will pass a test suite built from this
document alone. The only cure is a real client: `tests/tools/mlc-probe/`.
