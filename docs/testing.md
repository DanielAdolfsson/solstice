# Testing and mocking strategy

How to get confidence that Solstice interoperates, and how much of it can run
unattended. Read after `bridging-design.md`.

---

## 0. Three compatibility surfaces, three different problems

| Surface | Our role | Peers in the wild | Shape of the problem |
|---|---|---|---|
| GameStream | **host** | one protocol core (`moonlight-common-c`) shared by every client port | one spec, very picky, fails silently |
| RFB | **client** | a dozen server implementations with wildly different feature subsets | many peers, each supporting a different slice — so test the two extremes, not the middle (§3) |
| SPICE | **client** | effectively just QEMU's `spice-server` | one peer, but a large message surface |

These need different tactics. The GameStream side is about *exactness* against
a single reference. The RFB side is about *range* — a feature-rich server and a
deliberately minimal one. The SPICE side is about reaching the
rarely-exercised corners of one implementation, which its own config flags make
directly reachable.

Note on terminology: there is no "Sunshine client". Solstice **replaces**
Sunshine; the thing that connects to it is **Moonlight**. Sunshine still
matters for testing, but as a *reference host* to diff against — §2.4.

---

## 1. Test tiers

| Tier | What | Trigger | Budget |
|---|---|---|---|
| T0 | Unit + property tests on pure functions | every push | seconds |
| T1 | Golden vectors from captured real traffic | every push | seconds |
| T2 | Mock peers — our own fake client and fake servers | every push | < 1 min |
| T3 | Real implementations, lightweight (Xvnc, Xspice, headless Moonlight) | every push | ~5 min |
| T4 | Server flag sweeps + loss injection | nightly | ~30 min |
| T5 | Fuzzing | nightly / continuous | hours |
| T6 | Manual (GUI clients, subjective quality) | release gate | — |

T0–T3 should gate merges. Everything below is about how to actually build
them.

---

## 2. The GameStream side

### 2.1 `moonlight-embedded` is a headless client

This is the single most useful discovery for automation.
`moonlight-stream/moonlight-embedded` builds a CLI client, and
`-platform fake` selects a null backend — `platform.c:185` and `:252` return
`NULL` callbacks, described as *"Fake (no a/v output)"*. `LiStartConnection`
then substitutes the no-op callbacks from `FakeCallbacks.c`.

So the full protocol runs with no display, no GPU and no decoder:

```sh
# PIN is supplied directly -- no stdout scraping, no interaction
moonlight pair   -pin 1234  127.0.0.1

moonlight stream -platform fake \
                 -app Desktop \
                 -codec h264 -width 1280 -height 720 -fps 60 \
                 -bitrate 10000 -viewonly -quitappafter \
                 127.0.0.1
```

`-pin` is parsed at `config.c:255` and must be in 1–9999 (`main.c:398`), so
both halves of the handshake are scriptable with a fixed PIN. That in turn
means **Solstice's own pairing API must be scriptable too** — a CLI
`solstice pair --pin 1234 --window 60s` rather than a web form. Design for the
test harness.

Because every Moonlight port shares `moonlight-common-c`, exercising
moonlight-embedded covers the *protocol* surface of moonlight-qt, Android and
iOS. What it does not cover is their UI and their platform decoders, which is
what T6 is for.

### 2.2 The three debug build flags

`moonlight-common-c` ships hooks that turn the reference client into a test
oracle. These are compile-time and undocumented outside the source:

| Flag | Effect | Why it matters |
|---|---|---|
| `FEC_VALIDATION_MODE` | Drops one random data shard per frame, recovers it via parity, then asserts the recovered bytes match the original **exactly** and that the header flags are sane (`RtpVideoQueue.c:372-418`) | Validates your Reed–Solomon against the real decoder on **every frame**. This is the FEC oracle. |
| `LC_DEBUG_RECORD_MODE` | Installs pass-through recorder callbacks (`Connection.c:249`) that write the reassembled video and audio elementary streams to files given via `drContext`/`arContext` | Lets you assert on *content*, not just "it connected" |
| `LC_FUZZING` | Disables early-reject paths that would short-circuit a fuzzer (`RtpVideoQueue.c:577`, `VideoStream.c:169`) | Fuzz the depacketiser against your packetiser's output |

A ~150-line C driver linking `moonlight-common-c` with all three gives you a
headless, asserting, recording client. Build it once, keep it in
`tests/tools/mlc-probe/`, and treat it as the primary conformance tool.

`FEC_VALIDATION_MODE` deserves emphasis given the earlier FEC discussion: it
converts "did we get the Cauchy matrix right?" from a question into a
continuously-enforced invariant.

### 2.3 Asserting on the video that actually arrived

`LC_DEBUG_RECORD_MODE` gives you an H.264 elementary stream. Decode it and
compare against what the backend was displaying:

```sh
ffmpeg -i recorded.h264 -vsync 0 frame_%04d.png
```

For comparison, don't use OCR or raw pixel diffs — the encoder is lossy and
the scaler may be involved. Instead **render a binary block barcode** on the
remote desktop: a row of large black/white squares encoding a monotonically
increasing frame counter plus a timestamp. Large flat blocks survive H.264 at
any sane bitrate, decode with a trivial threshold, and give you three things at
once:

- **Correctness** — the counter decodes to the expected value.
- **Frame identity** — you can tell duplicate frames from dropped ones, which
  matters because the synthetic frame clock (`bridging-design.md` §2.1)
  deliberately emits repeats.
- **End-to-end latency** — the embedded timestamp versus arrival time.

For colour correctness, a few full-screen flat fills (pure red, green, blue,
mid-grey) compared within a tolerance will catch the BGRA→NV12 bugs and the
limited-vs-full range mistakes, which are the two colour errors you will
actually make.

### 2.4 Sunshine as the reference host

Two distinct uses.

**Golden capture.** Run Sunshine (the project publishes container images),
point the probe client at it, and capture with `tcpdump`. Since the *client*
generates `rikey`, an instrumented probe can log the session key, letting you
decrypt the control stream and encrypted RTSP offline. That capture becomes the
T1 golden vector set: known-good `/serverinfo` XML, a real RTSP transcript, and
real video packet layouts to diff your packetiser against.

Do this **before** writing the packetiser, not after.

**Differential testing.** Feed the same recorded ANNOUNCE to both Sunshine and
Solstice and compare the DESCRIBE/SETUP responses and the resulting packet
header fields. Discrepancies in `fecInfo`, `multiFecBlocks`, `streamPacketIndex`
or the RTP sequence relationship are exactly the bugs that produce "black
screen, no error".

**Reuse their pairing vectors.** `Sunshine/tests/unit/test_http_pairing.cpp`
runs the four-phase handshake deterministically — hard-coded private key and
certificate, plus an `override_server_challenge` field specifically so the
output is reproducible. Lift those constants into Solstice's pairing tests and
you get a published, known-good oracle for the one piece of the protocol with
three CVEs in its history. The same file also tests the negative paths
(`"Out of order"` at `:521`), which is the behaviour CVE-2024-51738 was about.

### 2.5 A mock Moonlight client, for the things real clients won't do

Real clients never send malformed data, so T2 needs a hostile client of our
own:

- pairing phases out of order, repeated, interleaved between two sessions
- a replayed or brute-forced PIN
- `ANNOUNCE` with missing, duplicated, or absurd attributes
- short ENet packets (the shape of GHSA-c428-87f8-rrv5)
- input batches with length fields that overrun the payload
- invalid UTF-8 in text events (GHSA-6w33-pjh7-p77c)
- a second client connecting mid-session; a client cert that is *similar* but
  not byte-identical to a paired one (CVE-2026-32253)

This is where a reimplementation earns its safety claim. Each of these maps to
a published advisory against Sunshine, so the test names can cite them.

---

## 3. The RFB side — two poles, not a matrix

Solstice is an RFB *client*. It does not care whether the server's pixels came
from X11, Wayland or a VM — the axis that actually matters is **which RFB
implementation** it is talking to, because each supports a different slice of
the encoding and pseudo-encoding space.

(Worth being precise: XWayland is not a substitute for a Wayland VNC server.
XWayland runs X11 *clients* on a Wayland compositor — it is the client side.
`Xvnc` is a self-contained X server and involves neither Wayland nor XWayland.
Dropping `wayvnc` is justified by the implementation-coverage argument below,
not by XWayland.)

Rather than sampling six servers, use two deliberately opposite poles:

| Pole | What | Role |
|---|---|---|
| **TigerVNC `Xvnc`** | feature-rich real server | everything we want to use, present |
| **Mock RFB server** | minimal, pedantic, ours | nothing optional present; strict about ordering |

### 3.1 TigerVNC `Xvnc` — the real server

Self-contained X server with a VNC frontend. No Xvfb, no compositor, no VM.

```sh
Xvnc :1 -geometry 1280x720 -depth 24 -SecurityTypes None -rfbport 5901 &
DISPLAY=:1 ./tests/tools/barcode-pattern &

# VeNCrypt path
Xvnc :1 -SecurityTypes VeNCrypt,X509Vnc -X509Cert cert.pem -X509Key key.pem
```

It covers every axis Solstice actually depends on:

- **Encodings** — Raw, CopyRect, RRE, Hextile, Tight, Tight+JPEG, ZRLE
  (`common/rfb/*Encoder.cxx`). Force each one individually by offering only
  that encoding in `SetEncodings`; that is the cleanest way to get
  deterministic per-encoding coverage from a single server.
- **Security** — None, VncAuth, VeNCrypt/X509, RSA-AES. Assert that Solstice
  *refuses* the first two off-loopback per `security.md` §4.1. A refusal test
  is a security test.
- **Flow control** — Fence (−312) and ContinuousUpdates (−313).
- **Input** — **QEMU Extended Key Event (−258) is supported server-side**.
  `SConnection.cxx:393` advertises it whenever the client requests the
  pseudo-encoding, and `SMsgReader::readQEMUMessage` parses it. This matters:
  scancodes are Solstice's *primary* keyboard path (`bridging-design.md` §4.1),
  and without this we would only ever exercise the keysym fallback against a
  real server.
- **Geometry** — DesktopSize and ExtendedDesktopSize.

### 3.2 Mock RFB server — the opposite pole

A single real server risks coding to *that server's* quirks and shipping a
client that only works with TigerVNC. The cheap guard is not another daemon —
it is a deliberately minimal server of our own:

- Raw encoding only; no Tight, no ZRLE, no CopyRect
- no ContinuousUpdates, no Fence — forces the request/response fallback loop
- no QEMU Extended Key Event — forces the VK→keysym path
- RFB 3.3 and 3.8 handshakes; `None` and `VNC Authentication`
- strict message ordering, and it **records every client message**

That last property is what makes input testable precisely. Instead of observing
a live desktop:

```
inject Moonlight key event (VK_RETURN, EXTENDED)
    → assert mock received QEMU ext key event, keycode 0xE01C, down=1
inject the same with the mock advertising no -258
    → assert mock received KeyEvent, keysym 0xFF8D (KP_Enter)
```

Table-driven over the whole VK→scancode and VK→keysym tables, instant, no X
server. Keep one real-server smoke test (`xev`/`xdotool` observing an `Xvnc`
session) to catch what the mock's own assumptions would hide.

### 3.3 What we are knowingly not testing

An explicit decision, not an oversight. Re-add a server here the first time a
real bug is reported against one.

| Not tested | Unique coverage lost | Why that is acceptable |
|---|---|---|
| `wayvnc` / `neatvnc` | TRLE (15), Open H.264 (50), ExtendedClipboard, ExtMouseButtons | Solstice implements neither TRLE nor encoding 50 (`rfb-vnc-protocol.md` §7 rejects H.264 passthrough as an architecture) |
| `x11vnc` / libvncserver | a second Tight implementation, **and a real server lacking −258** (libvncserver implements QEMU ext key events in `libvncclient` only) | the mock covers the no-−258 keysym path deliberately and more strictly |
| TurboVNC | JPEG subsampling / fine-grained quality pseudo-encodings | quality knobs, not correctness |
| QEMU `-vnc` | QEMU Audio (−259), VNC over unix socket | audio is silence on the RFB backend in v1 |

---

## 4. The SPICE side — Xspice only

QEMU is not needed here either. **Xspice links the same `spice-server` library
QEMU does**, so the display-channel and image-codec behaviour is literally the
same code — and it exposes the same configuration knobs, without a VM, a guest
OS, or nested virtualisation.

From `xf86-video-qxl/scripts/Xspice`:

```
--image-compression  off | auto_glz | auto_lz | quic | glz | lz
--streaming-video    off | all | filter
--video-codecs       encoder:codec;...   (spice:mjpeg default; gstreamer mjpeg/vp8/h264)
--jpeg-wan-compression / --zlib-glz-wan-compression   auto | never | always
--disable-ticketing | --password
--tls-port --x509-dir --x509-cert-file --x509-key-file --dh-file --tls-ciphers
--vdagent            launches spice-vdagent + vdagentd
--numheads           multiple virtual heads
--deferred-fps       rate-limit the dirty-rect stream
--audio-fifo-dir     playback channel fed from PulseAudio module-pipe-sink
```

`--image-compression` offers exactly the choices QEMU's `-spice` does. The
decoders now exist — `crates/solstice-spice-codec`, tested differentially
against the real C encoders (§4.3) — so this is no longer about whether the
codec can be read at all. It is about whether a *server* agrees, which is a
separate question the vectors cannot answer. Force each one rather than hoping
the server's heuristics pick it:

```sh
Xspice --port 5930 --disable-ticketing --image-compression off  --streaming-video off  # baseline
Xspice --port 5930 --disable-ticketing --image-compression quic --streaming-video off
Xspice --port 5930 --disable-ticketing --image-compression glz  --streaming-video off  # stateful
Xspice --port 5930 --disable-ticketing --image-compression auto_glz --streaming-video all
```

Build the SPICE backend against `--image-compression off` first, then add
codecs one flag at a time. GLZ needs *long* sessions, not single frames — its
history window is the whole point and the bugs are in window management, which
is exactly the part frozen vectors cannot exercise: they replay a window of
eight images, and a real session churns thousands.
`--streaming-video all` is the one that breaks naive compositing, because
streams are clipped sub-rectangles layered over the draw commands; turn it on
early enough to find that out cheaply.

`--vdagent` is a genuine bonus: clipboard, `MONITORS_CONFIG` resize and
client-mode absolute mouse are all testable without building a guest image.
Test with it on *and* off — all three degrade when the agent is absent.

### 4.1 Mock SPICE server

Same rationale as §3.2, for the same negative tests: truncated
`SpiceLinkMess`, bad magic, wrong `connection_id` on a secondary channel,
ack-window violations, and a `SpiceDataHeader` whose `size` overruns the
payload.

### 4.2 Known gap

Xspice is the only SPICE server tested. Since it shares `spice-server` with
QEMU this covers the protocol well, but it does **not** cover QXL guest-driver
behaviour — a real VM's driver emits different draw-command mixes than the
Xspice video driver does. Worth one manual QEMU run before a release, not a CI
job.

### 4.3 The image codecs, without a server

`crates/solstice-spice-codec` is a from-scratch port of QUIC, LZ and GLZ, and
nothing about those codecs can be checked by reading the code: QUIC's Golomb
model evolves pseudo-randomly in lockstep with the encoder, and GLZ's
dictionary spans the session. A round-trip against a Rust encoder would only
prove the port is self-consistent with itself.

So the oracle is the C, the same way FEC's is `nanors` (§2.3).
`tests/vectors/spice/dump.c` links `spice-common`'s QUIC and LZ and records
both the compressed bytes **and** the pixels the C decoder makes of them;
`glz-dump.c` links `spice-server`'s GLZ encoder. The 278 cases are frozen as
gzipped JSON so CI needs no C toolchain, no glib and no network —
`tests/vectors/spice/README.md` has the build and the reasoning, including the
one place the expected pixels are derived rather than C-generated.

A GLZ vector is a **window**, not an image: a sequence encoded through one
dictionary, which must be replayed through one decoder in order. One of the
windows uses a dictionary too small to hold its own sequence, so images are
evicted and the release path runs rather than just the lookups.

Two things this deliberately does not do, and the second is the one to
remember:

- It does not test the codecs under a *server's* choices. The images are this
  repository's, not a guest's. §4 and §4.2 are still the real test.
- **It cannot test a long GLZ session.** That is what `--image-compression glz`
  against Xspice is for, and why the staged plan puts GLZ last.

---

## 5. Loss injection — testing FEC for real

`tc netem` makes the recovery paths reachable in CI:

```sh
# 1% loss on the video port, applied to the loopback or the container veth
tc qdisc add dev lo root netem loss 1%
tc qdisc change dev lo root netem loss 5% delay 20ms 5ms
```

Combined with `FEC_VALIDATION_MODE` on the probe client, this is a genuine
end-to-end test of the FEC implementation: the client is dropping a shard per
frame deliberately *and* the network is dropping more, and every recovered byte
is asserted.

Worth asserting at each loss level:

- 0% — baseline, no parity consulted
- 1–5% — recovery succeeds, no IDR requests on the control stream
- 20%+ — frames genuinely lost; assert Solstice responds to the resulting IDR
  request promptly rather than stalling

The third case is the one that catches encoder-integration bugs: a forced
keyframe must actually come out of the encoder on the next frame.

---

## 6. CI shape

One container image: `tigervnc-standalone-server`, `xspice`, `ffmpeg`, the
probe client and the barcode generator. No QEMU, no compositor, no VM — which
is what keeps the image small and the jobs fast.

```
on push:      T0 unit/property                      ~20 s
              T1 golden vectors                     ~10 s
              T2 mock client + mock RFB/SPICE       ~40 s
              T3 Xvnc  + probe client               ~3 min
              T3 Xspice + probe client              ~2 min
nightly:      T4 Xvnc  × encodings × security       ~10 min
              T4 Xspice × image-compression × streaming-video × vdagent  ~10 min
              T4 loss injection sweep               ~10 min
              T5 cargo-fuzz on the seven parsers    ~2 h
```

The nightly tier is now a sweep over *one* server's flags rather than a matrix
of servers, which is both faster and more deterministic — the same binary with
a different flag isolates the variable properly, where swapping servers
confounds it.

The two SPICE codec targets are worth running first when the budget is short.
Both have already paid for themselves in minutes rather than hours:
`spice_quic` found a 23-byte header asking the decoder for a 151 MiB image,
and `spice_lz` found a width whose stride overflowed a `u32` before anything
had a chance to reject it. Both now have named regression tests; neither was
reachable from the differential vectors, because the C encoders do not emit
malformed headers.

Two practical constraints:

- **No nested virtualisation** on most hosted runners. This is a large part of
  why Xvnc and Xspice are the right choices: neither needs KVM, a guest OS, or
  a disk image.
- **No GPU**, so hardware encoder paths (VAAPI/NVENC) cannot be covered in
  hosted CI. Keep them behind feature flags and test them on a self-hosted
  runner or manually at release.

---

## 7. Harness layout

Extending `PROJECT-LAYOUT.md` §1:

```
tests/
├── vectors/
│   ├── fec/                 # nanors differential vectors (see the FEC work)
│   ├── pairing/             # lifted from Sunshine's test_http_pairing.cpp
│   └── capture/             # golden Sunshine↔Moonlight transcripts
├── mocks/
│   ├── moonlight_client/    # hostile client, T2
│   ├── rfb_server/          # recording RFB server, T2
│   └── spice_server/        # recording SPICE server, T2
├── tools/
│   ├── mlc-probe/           # moonlight-common-c + the three debug flags
│   └── barcode-pattern/     # the on-screen test pattern
└── integration/
    ├── vnc_matrix.rs
    ├── spice_matrix.rs
    └── loss_injection.rs
```

---

## 8. What cannot be automated

Be honest about the gaps rather than pretending the matrix is complete:

- **GUI clients.** moonlight-qt, Android, iOS and tvOS share the protocol core
  but not the decoders or the UX. A release gate needs a human with a real
  client.
- **Subjective quality.** PSNR/SSIM catch gross errors, not "the text looks
  smeary at 10 Mbit". Desktop remoting is text-heavy and judged differently
  from game streaming.
- **Real network conditions.** `netem` models loss and delay, not bufferbloat,
  Wi-Fi retry bursts, or carrier-grade NAT.
- **Hardware encoders**, per §6.
- **Long-running stability.** Memory growth, sequence-number and IV-counter
  wrap, GLZ history-window drift over hours. Needs a soak job, not a CI job.
- **Other RFB servers and real QXL guests**, deliberately — see §3.3 and §4.2
  for exactly what that costs and when to revisit.
