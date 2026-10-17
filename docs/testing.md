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
| T3 | Real implementations (one QEMU guest, headless Moonlight) | every push | ~1 min |
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

**The three are not usable together.** `RtpVideoQueue.c:5` defines
`FEC_VALIDATION_MODE` as `LC_DEBUG && !LC_FUZZING`, and `Platform.h:128-132`
compiles `LC_ASSERT_VT` -- the assertions on host-supplied values -- out under
`LC_FUZZING` for the obvious reason. `LC_FUZZING` is for fuzzing the
depacketiser; conformance wants the other two.

This exists and is built: `tests/tools/mlc-probe/`, with `build.sh` to fetch
`moonlight-common-c` at a pinned commit and compile it under `LC_DEBUG` and
`LC_DEBUG_RECORD_MODE`. The harness that drives it is
`crates/solstice/tests/real_moonlight.rs`, which does the pairing and `/launch`
the probe cannot (they are not in `moonlight-common-c`) and then hands over.
Both skip with a printed note when the probe has not been built. That README
is the detail; `docs/roadmap.md` §3 has what the exercise found.

**Audio content** is checked without either flag. The recorder writes the
Opus packets back to back, which cannot be split again, so the probe also
dumps each packet behind a length (`audiopackets=`), and reports the decoder
`moonlight-common-c` configured from DESCRIBE, mapping included. The harness
decodes every packet with exactly that decoder and asks whether the tone the
backend played is in the right channels (`docs/roadmap.md` §2.8).

`FEC_VALIDATION_MODE` deserves emphasis given the earlier FEC discussion: it
converts "did we get the Cauchy matrix right?" from a question into a
continuously-enforced invariant. It is also the single highest-yield assertion
in this project's history -- it is what caught both FEC defects below.

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

**What was built instead** (`docs/roadmap.md` §4): the same capture with
Solstice at the host end rather than Sunshine. `tests/tools/capture-session.sh`
runs `real_moonlight.rs` in an unprivileged network namespace with `tcpdump`
on its loopback. `gen_capture_vectors.py` decrypts the capture independently
and holds it against what the client recorded, then freezes it as
`tests/vectors/capture/session.json.gz`. `capture_vectors.rs` replays it in
CI. The client's half is ground truth and the host's half is pinned. A
Sunshine capture would add a host-side oracle on top, and remains the
differential use below.

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

## 3. The RFB side — one real server and a mock

Solstice is an RFB *client*. It does not care whether the server's pixels came
from X11, Wayland or a VM — the axis that actually matters is **which RFB
implementation** it is talking to, because each supports a different slice of
the encoding and pseudo-encoding space.

This used to be TigerVNC's `Xvnc`, chosen as a deliberately feature-rich pole.
It is now QEMU's own RFB server, running on the same guest the SPICE tests
use (§4). The reason is not that QEMU's server is richer — it is poorer — but
that **one guest serves both backends**, which replaces two X-server launchers
and their separate quirks with a single harness, and buys the SPICE side
things no X server could offer at all.

### 3.1 QEMU's RFB server — what it actually supports

Probed directly rather than assumed, by offering each encoding in isolation
and recording what came back:

| | |
|---|---|
| **Encodings** | Raw, Hextile, zlib, Tight, ZRLE served natively; ZYWRLE answers as ZRLE |
| **Absent** | RRE, CoRRE, ZlibHex — all fall back to Raw |
| **CopyRect** | inconclusive on a static screen, which offers no copy to describe |
| **Pseudo** | ExtendedDesktopSize (−308), LEDState (−261), QEMUAudio (−259), and **QEMU Extended Key Event (−258)** |
| **Absent pseudo** | **Fence (−312) and ContinuousUpdates (−313)** — a ClientFence makes the server close the connection |
| **Security** | configuration, not capability: `None` by default, VncAuth with a password, VeNCrypt with TLS credentials |

−258 is the one that mattered most. Scancodes are Solstice's primary keyboard
path (`bridging-design.md` §4.1), QEMU invented that pseudo-encoding, and
without it the only real-server coverage would be the keysym fallback.

**What the move cost, stated plainly.** `backend.rs`'s continuous-updates path
no longer runs against a third-party server. It is still covered by the mock
below, which offers both and tests the negative — but only against an
implementation of our own reading of the spec, which is exactly the class of
mistake `roadmap.md` §3 warns about. That is a deliberate, recorded trade.

```sh
./tests/guest/build-image.sh
cargo test -p solstice-vnc --test real_server -- --test-threads=4
```

### 3.2 Mock RFB server — the opposite pole

A single real server risks coding to *that server's* quirks and shipping a
client that only works with QEMU's. The cheap guard is not another daemon —
it is a deliberately minimal server of our own:

- Raw encoding only; no ZRLE, no CopyRect. Tight is opt-in
  (`MockConfig::offer_tight`), because no real server can be made to send each
  Tight sub-encoding on demand
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
server. Keep one real-server smoke test (`xev` observing the guest) to catch
what the mock's own assumptions would hide.

### 3.3 What we are knowingly not testing

An explicit decision, not an oversight. Re-add a server here the first time a
real bug is reported against one.

| Not tested | Unique coverage lost | Why that is acceptable |
|---|---|---|
| `wayvnc` / `neatvnc` | TRLE (15), Open H.264 (50), ExtendedClipboard, ExtMouseButtons | Solstice implements neither TRLE nor encoding 50 (`rfb-vnc-protocol.md` §7 rejects H.264 passthrough as an architecture) |
| `x11vnc` / libvncserver | a second Tight implementation, **and a real server lacking −258** (libvncserver implements QEMU ext key events in `libvncclient` only) | the mock covers the no-−258 keysym path deliberately and more strictly |
| TurboVNC | JPEG subsampling / fine-grained quality pseudo-encodings | quality knobs, not correctness |
| TigerVNC `Xvnc` | **Fence (−312) and ContinuousUpdates (−313) against a third-party server**, RRE/CoRRE, RSA-AES | the flow-control paths are covered by the mock; see §3.1 for why this trade was taken, and `roadmap.md` §3 for why it is not free |

---

## 4. The SPICE side — a real QEMU guest

This used to be `Xspice`, which links the same `spice-server` library QEMU
does and could therefore cover the protocol without a VM. It covered it well,
and `-spice` exposes the same knobs its launcher did — `image-compression`,
`streaming-video`, the WAN compression pair — so nothing was given up by
moving:

```
image-compression  off | auto_glz | auto_lz | quic | glz | lz
streaming-video    off | all | filter
jpeg-wan-compression / zlib-glz-wan-compression   auto | never | always
video-codec, playback-compression, agent-mouse, seamless-migration
password-secret | tls-port | x509-* | sasl
```

What `Xspice` could not reach was everything *above* the protocol. Its
packaged launcher cannot start a `spice-vdagent` at all — `--vdagent` requires
`--auto`, and `--auto` crashes — so the agent had no real peer. And its video
driver renders through the frame buffer, so every draw command it ever sent
was a `DRAW_COPY` or a `DRAW_FILL`.

### 4.0 The shape every test must keep

**Connect first, repaint second.** QEMU renders guest damage into its console
surface only while a display client is attached: a repaint performed with
nothing connected is dropped outright, with no error anywhere, and a client
connecting afterwards is served a stale surface. This was already the right
shape for a different reason — a client that only ever sees the screen as it
was at connect time can be completely broken for incremental updates and still
pass — and against QEMU it is also mandatory.

`connect` returning is slightly earlier than the attach, so the tests
re-issue the paint rather than asserting on the race. Waiting for a damage
event instead does *not* work: the server's first update can precede
`subscribe`, and the wait simply hangs.

Two more things the guest had to be taught, each of which fails silently:

- `xsetroot -solid` does not work against this X server. It exits 0, leaves
  `_XSETROOT_ID` unset, and the root reverts to black the moment it exits,
  because the background is only retained for a client that asked to be.
  `tests/guest/draw-helper.c` does, as `RetainTemporary` after killing the
  previous holder: `RetainPermanent` on every call leaked one X client per
  paint, and a soak ran into the server's limit of 256.
- `spice-vdagentd` takes `-x`, not `-X`; it needs the `uinput` module; and it
  needs `/run/spice-vdagentd/` and a machine-id. Miss any one and the daemon
  is simply absent, which looks exactly like a client that failed to
  negotiate.

**Count what arrived, not only what it looks like.** The session exposes
`draw_counts()` and `image_counts()` — how many of each draw command it has
executed and of each image encoding it has decoded. Correct pixels are
consistent with more than one route to them, and twice that hid a test that
was not testing what it was named for: the codec sweep decoded one `LZ_RGB`
image whatever it forced, and `solstice-draw stroke|text|rop3`, written to
force `DRAW_STROKE`, `DRAW_TEXT` and `DRAW_ROP3`, produces fills and copies
because `xf86-video-qxl` accelerates nothing else. `roadmap.md` §2.6 has both.
A new test that claims a code path should assert the count that proves it.

**Never block the runtime the client runs on.** `Guest` calls block the
thread. On a single-threaded runtime that freezes the client while the guest
command runs, and a command that draws more than the server's ack window
deadlocks against it — the X server ends up blocked in `qxl_ring_push` and
the failure looks like a slow guest. `real_server.rs` is multi-threaded *and*
wraps `Guest` so every blocking call goes through `block_in_place`, because a
blocked worker could otherwise still hold the client's next task in its LIFO
slot. Its module comment has the mechanism. The GLZ soak still stalls
intermittently under TCG with both in place. That is the guest's QXL driver
waiting for memory the device has not released, not the client
(`roadmap.md` §2.7). When a guest command times out,
`Guest::stall_report` says where X is blocked.

### 4.1 Which display device, and why it matters

`GuestConfig::display` picks between two, and the choice is not cosmetic.

| | `Qxl` (default) | `VirtioGpu` |
|---|---|---|
| What it is | the device a real SPICE guest has | generic KMS, `modesetting` X driver |
| Image codecs, draw commands, streams | **yes — use this** | not representative |
| Agent resize | **cannot**: no client can resize a QXL guest here, `remote-viewer` included | **yes — use this** |
| `spice-vdagent` output map | falls back to "using output index as display id" | maps the connector properly |

The resize asymmetry was established by controlled experiment, not inferred:
`remote-viewer` against a freshly booted QXL guest also only scales, while
both it and Solstice resize a virtio-gpu guest correctly.

QEMU does not forward a client's `MONITORS_CONFIG` to the agent in either
case — `ui/spice-display.c` registers a `QXLInstance` per console for *every*
display device, so the message is handed to the device rather than the agent.
The device makes the requested mode preferred and fires a hotplug event, and
**userspace is expected to apply it**. On a desktop that is the session's job;
`tests/guest/init` runs a small loop that stands in for one.

### 4.2 Mock SPICE server

Same rationale as §3.2, for the same negative tests: truncated
`SpiceLinkMess`, bad magic, wrong `connection_id` on a secondary channel,
ack-window violations, and a `SpiceDataHeader` whose `size` overruns the
payload.

Built: `crates/solstice-spice/src/mock.rs`, driven by
`tests/mock_server.rs`. It is a *real* link peer rather than a stub — it
mints a 1024-bit RSA key per session, hands over the DER public key, and
decrypts the ticket the client sends back, so the OAEP path is exercised
rather than faked. Which is also why the workspace optimises `rsa` even in
debug builds: unoptimised key generation takes seconds per connection, and a
session opens four of them.

It offers nothing optional, for the same reason the RFB mock does: raw
bitmaps only, no image compression, no streams unless a test pushes one. And
it records every client message, which is what makes input testable precisely
— inject a Moonlight key event at one end, assert on the exact scancode that
came out the other.

One trap it surfaced immediately, worth repeating because it will catch the
next person too: **message numbers are per-channel namespaces.** 101 is
`KEY_DOWN` on the inputs channel, `DISPLAY_INIT` on the display one and
`CLIENT_INFO` on the main one. A recorder that filters by type alone finds
the wrong message.

### 4.3 Known gaps

Smaller than they were. `roadmap.md` §2.7 is the live list; these are the
ones that are properties of *this harness* rather than of the backend.

**QXL cannot resize.** See §4.1 — not a client limitation, and not worth
chasing further, since virtio-gpu serves the agent tests properly.

**The clipboard needs the guest to retry, and the host to keep answering.**
Not a gap any more — both directions run against a real `spice-vdagent` —
but the shape is worth knowing before writing another one. An offer from
this client and an X selection ownership change are not the same event, and
`xclip -o` run before `spice-vdagent` owns the selection exits immediately
with *"target STRING not available"* rather than waiting. So the guest pastes
in a loop, and **every attempt is a real request the client must answer**:
the test answers them from a task rather than with a single call, because a
consumer that answered only the first would hang the guest on the second. A
real consumer carries the same obligation.

**Audio.** The guest gets a sound card with `Spice::audio()` (an
`intel-hda` codec whose output is the playback channel), and `speaker-test`
plays into it. What arrives is Opus, 48 kHz stereo, in **10 ms** packets —
measured, and asserted by `guest_audio_arrives_as_opus_packets_of_one_fixed_duration`.

That test only reads durations, and `speaker-test -c 2` plays the channels in
turn, so it is no use for checking the sound itself.
`the_reference_client_hears_a_real_spice_guest`, in `real_moonlight.rs` and
behind the `spice` feature, writes one period of a 480 Hz sine into the guest
with `printf` (exactly 100 samples at 48 kHz, so it repeats without a seam),
loops it into `aplay`, and checks the real client hears it
(`docs/roadmap.md` §2.8).

**The GLZ soak** is `glz_soak_keeps_the_screen_exact_across_thousands_of_images`,
`#[ignore]`d because it is minutes long under TCG. It repaints with changing
content round after round and holds the screen against QEMU's screendump
every twenty; `SOLSTICE_GLZ_SOAK_ROUNDS` lengthens it.

### 4.4 The image codecs, without a server

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
- **It cannot test a long GLZ session.** That is what `image-compression=glz`
  against the guest is for: the dictionary spans the session and the bugs are
  in window management, which needs thousands of images rather than one.

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

### 5.1 Loss on the control channel

This part exists. The ENet control channel is the host's own subset of ENet
(`docs/roadmap.md` §7), so its retransmission and reordering paths are this
project's to prove. Two tiers do it:

- **In simulation, every push.**
  `crates/solstice-gamestream/tests/enet_interop.rs` holds the host against
  `rusty_enet` -- upstream ENet's C, transpiled, so a second implementation
  rather than a second reading -- over a simulated network that loses,
  duplicates and reorders, with simulated clocks on both ends. Hundreds of
  messages each way at up to 30% loss, a client that vanishes, an idle
  minute, and a client with the wrong connect data. It runs in well under a
  second.
- **Against the real client, by hand.** `tests/tools/control-loss.sh [pct]`
  runs `real_moonlight.rs` in an unprivileged network namespace with netem on
  the control port alone, both directions, and prints netem's drop count as
  proof the loss happened. Video and audio are untouched, so a failure is the
  control channel's. It has passed at 20%, 30% and 40%.

---

## 6. CI shape

One container image for T0–T2: `ffmpeg`, the probe client and the barcode
generator. T3 and above need `qemu-system-x86_64` and the guest image, which
`tests/guest/build-image.sh` produces — unprivileged, no installer, about
four minutes cold.

```
on push:      T0 unit/property                      ~20 s
              T1 golden vectors                     ~10 s
              T2 mock client + mock RFB/SPICE       ~40 s
              T3 both backends against the guest    ~45 s
              T3 the host against real Moonlight    ~5 s
nightly:      T4 image-compression × streaming-video × agent sweeps  ~10 min
              T4 loss injection sweep               ~10 min
              T4 encoding cost measurement          ~1 min
              T5 cargo-fuzz on the eleven targets      ~2 h
```

`mlc-probe` is the cheapest of these by a wide margin and the highest-yield
(§2.2), so it belongs on every push rather than nightly. It needs `gcc`,
`git` and `libssl-dev` in the image, and a cache of its own:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/solstice/mlc
    key: mlc-${{ hashFiles('tests/tools/mlc-probe/manifest.lock',
                           'tests/tools/mlc-probe/probe.c',
                           'tests/tools/mlc-probe/build.sh') }}
- run: ./tests/tools/mlc-probe/build.sh   # a no-op on a cache hit
```

Keying on `manifest.lock` rather than on the pinned commit in `build.sh` is
deliberate: the lock also names the resolved `enet` and `nanors` submodules,
so a rebuild happens when any of the three move.

The guest is one artifact, not a per-test build, so cache it rather than
rebuild it:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/solstice/guest
    key: guest-${{ hashFiles('tests/guest/packages', 'tests/guest/packages.build',
                             'tests/guest/init', 'tests/guest/xorg.conf',
                             'tests/guest/draw-helper.c', 'tests/guest/build-image.sh') }}
- run: ./tests/guest/build-image.sh      # a no-op on a cache hit
```

Not Git LFS. The image is a derived artifact and LFS charges twice for that:
every rebuild adds a ~130 MB blob that stays in history, and every checkout
spends LFS bandwidth. The free tier is 1 GB of each. If cache eviction (7
days unused) becomes a problem, promote the artifact to a GitHub Release or
GHCR keyed by the same hash.

Three practical constraints:

- **Nested virtualisation.** The guest boots in about five seconds with
  `/dev/kvm` and well under a minute without it, under TCG. Either is fine
  nightly; only the first is comfortable on every push. Whether hosted
  runners expose `/dev/kvm` should be checked rather than assumed -- and
  "exposes" means *openable*: a node the user cannot open (not in the `kvm`
  group) used to make `-accel kvm` fail and surface as a QMP timeout. The
  harness now opens the device to decide, and falls back to TCG.
  `SOLSTICE_GUEST_ACCEL=tcg` forces TCG on a host with KVM. The two are not
  interchangeable for every test: a guest that is slow relative to the
  client changes which races can happen, and the GLZ soak's stall
  reproduces only under TCG (`roadmap.md` §2.7).
- **QXL needs QEMU's SPICE module** (`qemu-system-modules-spice` on Debian).
  Without it `-vga qxl` refuses to start, so the RFB tier asks for virtio-gpu
  instead: QEMU's VNC server reads the same console surface either way.
- **Memory.** Each guest wants about 1 GiB, and below that the initramfs
  unpacks *partially* — a guest that boots, starts X and is quietly missing
  binaries. The harness refuses to start one when the machine is short, and
  caps how many run at once based on what is actually free.
- **No GPU**, so hardware encoder paths (VAAPI/NVENC) cannot be covered in
  hosted CI. Keep them behind feature flags and test them on a self-hosted
  runner or manually at release.

---

## 7. Harness layout

Extending `PROJECT-LAYOUT.md` §1:

```
tests/
├── guest/                   # the QEMU guest the T3 tests run against
│   ├── build-image.sh       # unprivileged build; no installer is ever booted
│   ├── packages             # runtime package set, pinned to an Alpine branch
│   ├── packages.build       # toolchain, installed then removed again
│   ├── manifest.lock        # resolved versions; a mismatch means it is stale
│   ├── init                 # PID 1: X, spice-vdagent, qemu-ga, mode watcher
│   ├── xorg.conf            # geometry and driver substituted from the cmdline
│   └── draw-helper.c        # solstice-draw: fill, stroke, text, rop3
├── vectors/
│   ├── fec/                 # nanors differential vectors (see the FEC work)
│   ├── spice/               # QUIC/LZ/GLZ differential vectors
│   └── capture/             # a real Moonlight session, decrypted and frozen (§2.4)
└── tools/
    ├── capture-session.sh   # runs real_moonlight.rs under tcpdump, unprivileged
    ├── control-loss.sh      # runs it with netem on the control port (§5.1)
    ├── gen_capture_vectors.py
    ├── gen_fec_vectors.py
    ├── gen_spice_vectors.py
    └── mlc-probe/           # the real Moonlight client, headless (§2.2)
        ├── build.sh         # fetches moonlight-common-c at a pinned commit
        ├── probe.c          # the driver: connect, record, assert, report
        ├── manifest.lock    # resolved commits, superproject and submodules
        └── README.md

crates/solstice-test-guest/  # boots the guest and drives it; dev-only
```

Neither built artifact is in the repository. The guest image lands in
`~/.cache/solstice/guest` and the probe in `~/.cache/solstice/mlc`; what is
committed in each case is a `manifest.lock`, so a stale build is loud rather
than silent.

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
  The GLZ part has a test to run (§4.3); nothing runs it on a schedule.
- **Other RFB servers and real QXL guests**, deliberately — see §3.3 and §4.2
  for exactly what that costs and when to revisit.
