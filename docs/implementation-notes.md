# What building it settled

The research in the other documents was read out of source at 2026-10-15 and
was largely right. This note records the places where implementation confirmed
a claim that was flagged as uncertain, corrected one that was wrong, or left
something open — so the next person does not have to re-derive it.

Dates and versions here are from the build at 2026-10-15, on `rustc 1.98.1`.

---

## 1. Confirmed

### The FEC construction is exactly as described

`docs/moonlight-sunshine-protocol.md` §5.4 specified the Cauchy closed form
`P[j][i] = inv((ps + i) XOR j)` over GF(2⁸) with polynomial 285, and claimed it
had been verified byte-exact against a compiled `nanors`. That verification was
repeated here against the real C library and frozen into golden vectors:

```
ds=6    ps=3   bs=8     matrix=MATCH  parity=MATCH
ds=1    ps=2   bs=32    matrix=MATCH  parity=MATCH
ds=5    ps=2   bs=64    matrix=MATCH  parity=MATCH
ds=212  ps=42  bs=96    matrix=MATCH  parity=MATCH
ds=235  ps=20  bs=128   matrix=MATCH  parity=MATCH
ds=100  ps=20  bs=1408  matrix=MATCH  parity=MATCH
```

`nanors/rs.c:128` reads `row[i] = GF2_8_INV[(rs->ps + i) ^ j];` and
`deps/obl/gf2_8_tables.h:1` says *"these tables were generated with polynomial:
285"*. Both lines are still there. The implementation is ~120 lines including
the Gauss–Jordan inverse needed for recovery, which is the "roughly 50 lines
plus a GF table" the research predicted plus the decoder it did not count.

The audio matrix really is unrelated: the Cauchy construction for RS(4,2) gives
`142 244 71 167 / 244 142 167 71`, and Nvidia's is
`119 64 56 14 / 199 167 13 108`. One implementation does not cover both, as
`docs/moonlight-sunshine-protocol.md` warned.

### OpenH264 does emit High Profile

`PROJECT-LAYOUT.md` §4 flagged this as *"cheap to test and expensive to
discover late"*: OpenH264's README documents Constrained Baseline only for the
encoder, while Moonlight advertises `VIDEO_FORMAT_H264` as High Profile.

Tested by reading `profile_idc` out of the SPS this build actually produces:
**100**, which is High. The test
(`crates/solstice-video/src/openh264.rs::the_stream_declares_its_profile_in_the_sps`)
asserts the value is one of the three that decode on such a client and prints
which, so a regression is visible rather than silent.

### The buffer layout really is shaped around FEC

`docs/bridging-design.md` §2.5 argued that writing the no-FEC path first means
designing something simpler and then tearing it out. That is accurate. Parity
is computed over the **whole shard including the 32 header bytes, with those
bytes still zero**, and every header — data and parity alike — is written
afterwards. A packetiser built around "header, then payload, then maybe parity"
has the wrong shape and cannot be retrofitted.

### Both keyboard paths are needed

Not a discovery so much as a confirmation that the design pays off: the mock
RFB server advertises no pseudo-encoding -258 and the same `InputEvent`
produces a `KeyEvent` with keysym `0xFF8D` against it and a QEMU extended key
event with keycode `0xE01C` against a server that does. Both are tested from
the same input, which is what `docs/testing.md` §3.2 asked for.

---

## 2. Corrected

### The dependency version table was wrong

`PROJECT-LAYOUT.md` §4 listed versions "as published on crates.io, checked
2026-10-15". Several do not exist. What actually resolves:

| Research said | Actually published |
|---|---|
| `sha2` 0.11 | 0.10 |
| `aes` 0.9 | 0.8 |
| `aes-gcm` 0.11 | 0.10 |
| `cbc` 0.2 | 0.1 |
| `zeroize` 1.9 | 1.8 |
| `x509-parser` 0.18 | 0.18 ✓ |
| `rcgen` 0.14 | 0.14 ✓ |
| `quick-xml` 0.42 | 0.41 |
| `socket2` 0.6 | 0.6 ✓ |
| `openh264` 0.9 | 0.9 ✓ |

The RustCrypto numbers are all one minor version ahead of reality, which is
what a confident guess looks like. Treat the table as a list of *which* crates,
not which versions.

### `ring`, not `aws-lc-rs`

Not addressed by the research, but it decides whether the project builds on a
machine without `cmake`. `rustls` and `rcgen` default to the `aws-lc-rs`
backend, whose `aws-lc-sys` build needs cmake; `ring` needs only a C compiler.
Everything here selects `ring` explicitly. The cost is nothing this project
uses.

### The encoder wants I420, not NV12

`docs/bridging-design.md` §5 says to "keep the framebuffer in a format the
encoder wants (NV12)". NV12 is what *hardware* encoders want. OpenH264 takes
three separate planes, so the pipeline uses I420 and a VAAPI or NVENC backend
would carry its own conversion. Converting to NV12 and then splitting it would
be the worst of both.

### `ring` carries no OpenSSL-licensed code

`deny.toml` originally carried a `[[licenses.clarify]]` entry declaring `ring`
as `MIT AND ISC AND OpenSSL` — a value copied from older cargo-deny examples
rather than read off the crate. It is wrong for `ring` 0.17: its licence files
are ISC for new code, **Apache-2.0** for the BoringSSL-derived parts, and
MIT/Apache for a vendored `once_cell` polyfill. Nothing with an advertising
clause, and no `SSLeay` text anywhere in the tree.

This stopped being pedantry the moment the project became GPL-3.0-or-later: the
old OpenSSL licence is generally considered GPL-incompatible, so a stale
clarification would have made a compatible dependency look like a licence
conflict. The entry is gone; cargo-deny reads the crate's own metadata.

### No web UI, and therefore no `solstice pair` yet

`docs/security.md` §3.5 says not to build a web UI with a session cookie, and
`docs/testing.md` §2.1 says pairing must be scriptable. Both are satisfied by a
CLI — but a CLI subcommand runs in a *different process* from the daemon, so
`solstice pair` needs a management socket that does not exist yet. The pairing
window, the attempt lockout and the source-address restriction are all
implemented and tested inside the daemon; only the IPC to open the window from
outside is missing. The command reports that rather than opening a window
against its own throwaway state.

### The fuzz targets found a bug on their first run

`cargo fuzz run rfb_rect` panicked within seconds on
`crates/solstice-vnc/src/encodings/zrle.rs`: the palette-RLE branch subtracted
128 from a value that was already masked to seven bits, so **every**
palette-RLE tile underflowed. The subencoding byte comes straight off the wire,
which made it reachable from any VNC server — including one the user does not
control, which `docs/security.md` §5.4 identifies as an inbound attack surface.

Worth recording because it is the argument for §9 of that document in
miniature: the bug was in a branch the unit tests covered three other ways, it
survived review, and a fuzzer found it in under ten seconds. The fix came with
three regression tests, one of which simply walks every possible subencoding
byte.

### The real server found the bug the mock could not

`docs/testing.md` §3 argues for two poles — a feature-rich real server and a
deliberately minimal mock — rather than sampling six servers. The second real
bug is the case for that argument.

Against TigerVNC's `Xvnc`, the screen stayed black. The mock passed every test.
The cause: `Xvnc` sends an **ExtendedDesktopSize pseudo-rectangle on every full
update**, not only when the size changes, and the client treated each one as a
resize — reallocating the framebuffer, wiping it black, and asking for another
full update, which came back with another pseudo-rectangle. A livelock at about
110 updates a second, with no error anywhere.

The mock could not have found it: a minimal server has no reason to send that
rectangle at all. The fix is to compare the geometry before acting, and the
regression test now lives beside the mock-based ones
(`a_repeated_size_announcement_is_not_a_resize`). What this cost to find, with
the real server available, was one `tracing::debug!` on the rectangle header.

---

## 3. Measured

Two benchmarks exist, both `#[ignore]`d because they are measurements rather
than assertions. The figures below were taken against a 1280x720 `Xvnc`, which
is no longer the server the tests use; `encoding_bench.rs` now measures the
same cases against the QEMU guest, whose cheaper content generators move the
absolute numbers while leaving their ordering intact. Kept because the shape
is the point, not the digits:

```
encoding                     MB/s   updates     CPU %   MPixel/s  bytes/pixel
Raw                         52.42       364       7.7      22.53        2.327
Hextile                      8.70       367      11.3      22.40        0.388
ZRLE                         1.65       357      13.8      21.41        0.077
ZRLE + CopyRect              1.72       360      14.0      22.02        0.078
what Solstice ships          1.68      1077      13.8      21.74        0.077
```

`cargo test -p solstice-vnc --release --test encoding_bench -- --ignored --nocapture`

And the encode path, which is what those numbers have to be read against:

```
stage                                  ms/frame   frames/s   core % @60 mean bytes
1280x720 BGRA->I420, whole frame          1.533        652          9.2
1280x720 BGRA->I420, 320x200 rect         0.101       9949          0.6
1280x720 convert + H.264, moving          6.087        164         36.2         86
1280x720 H.264, unchanged frame           4.395        228         26.4         13
1920x1080 BGRA->I420, whole frame         3.243        308         19.6
1920x1080 BGRA->I420, 320x200 rect        0.100       9962          0.6
1920x1080 convert + H.264, moving        13.800         72         82.8        111
1920x1080 H.264, unchanged frame          9.511        105         57.0         13
```

`cargo test -p solstice-video --release --test encode_cost -- --ignored --nocapture`

Three things follow.

**The backend decoder is not the bottleneck.** ZRLE costs about 14% of a core
at 720p under the worst desktop content there is; the encoder costs 36% at the
same resolution and 83% at 1080p60. Any work on the RFB decoding side is
optimising the cheap third of the pipeline. Tight, since implemented, bears
that out: about 13% less client CPU per pixel than ZRLE at the same bytes
(`docs/roadmap.md` §1), which is real and does not matter.

**The per-rectangle conversion was worth building.** Converting a 320x200
damage rectangle is 0.1 ms against 3.2 ms for a whole 1080p frame, a 30x
difference, and it is the common case on a desktop. `docs/bridging-design.md`
§5 called this out and it is the one place the advice paid directly.

**An unchanged frame is not cheap, and it should be.** 9.5 ms and 57% of a core
at 1080p60 to produce 13 bytes. The synthetic frame clock emits these
constantly -- a desktop is mostly still -- so this is the largest single
optimisation available, and it is in the encoder's configuration rather than
anywhere in this codebase. Worth investigating before anything else.

---

## 4. Open

> These are *findings* — what is known to be unresolved and why. The plan for
> acting on them is [`docs/roadmap.md`](roadmap.md).

### What a real Moonlight found — and what "assumed, not verified" cost

This section used to open with a worry: the encrypted-RTSP IV was written
little-endian *by inference* from the control-stream construction, with both
ends of the end-to-end test using the same code, so the test would pass either
way. The worry was well placed and aimed slightly wrong. The byte order was
right. What was missing was that the IV has a **fixed field** as well as a
counter — `iv[10]` for the originator and `iv[11]` for the stream
(`RtspConnection.c:122-132`) — which nobody had looked for, because
`docs/moonlight-sunshine-protocol.md` §4.1 did not mention it. A real client
refused the host's first reply and the host refused the client's first
`OPTIONS`.

It was one of eight defects that `tests/tools/mlc-probe/` found on its first
run; the list is in `docs/roadmap.md` §3. The pattern behind all eight is the
same and worth stating plainly, because it is the most expensive lesson in
this project's history: **a test whose client and server were written from the
same notes tests the notes, not the protocol.** Seven of the eight were in
code that had unit tests, an end-to-end test, and a documented source
citation. The eighth — the FEC parity layout — had all of that *and* a
correct description in the protocol document that the implementation did not
follow.

`NV_KEYBOARD_PACKET.keyCode` is the happy counter-example: it was read from
the *absence* of a byte-swap macro and flagged here as weak evidence. It is
correct, and now rests on `InputStream.c:952` writing `LE16(keyCode)`
explicitly.

### `rusty_enet` has not been audited

`docs/security.md` §2.4 asks for an audit, fuzzing, and a readiness to
reimplement the ENet subset Moonlight uses. None of that has happened. What it
has instead is containment: a peer limit of one, a refusal to accept a peer
whose connect data does not match the launch session, and a message layer that
authenticates every packet with AES-GCM before a byte reaches the input parser.
That reduces the blast radius; it does not remove the pre-authentication state
machine.

It does now interoperate: a real `moonlight-common-c` peer connects, carries
input and disconnects cleanly. That is worth something for the audit, which
needs to know which ENet features a real client actually exercises — but it
is evidence about the happy path only, and the advisory in question
(GHSA-c428-87f8-rrv5) is about the unhappy one.

The connect-data check was also, until the probe ran, *unreachable*: the host
minted a random value and never told the client, so the only peer it would
ever have accepted was one that guessed. See `docs/roadmap.md` §3, defect 3.

### Scaling is nearest-neighbour

When the backend declines to resize, the frame is letterboxed with
nearest-neighbour sampling. For a text-heavy desktop that is a defensible
default — a smoothing filter costs CPU to make text less legible — but it has
not been compared against anything.

### The fuzz targets have no corpus and no CI job

Nine targets exist and each runs clean for a minute to a few
(`rtsp_message`, `sdp_announce`, `input_batch`, `control_envelope`,
`rfb_rect`, `spice_quic`, `spice_lz`, `spice_draw`, `spice_message`). That is
a smoke test, not the nightly tier `docs/testing.md` §6 describes. There is no
seed corpus, no persistent corpus, and nothing runs them unattended.

The short runs have not been wasted: four of those targets have each found a
real unbounded allocation or out-of-bounds index in under two minutes, all
four on the SPICE side, all four now with named regression tests. That is a
reasonable argument that the nightly tier would find more.

### What a real SPICE server found, and what it still cannot reach

`crates/solstice-spice` was written against `spice.proto`, the C's own
raster-operation mapping, and the reference client's behaviour — then tested
against a mock written from the same reading. Pointing it at a live `Xspice`
found two bugs within an afternoon, and both were in the *join* between
pieces rather than in any one of them, which is what a real peer is for:

1. **The mouse mode in `MAIN_INIT` was thrown away.** A real server reports
   client mouse mode in `MAIN_INIT` itself; the mock granted it in a later
   `MAIN_MOUSE_MODE`, and `MAIN_INIT` is consumed by the setup loop inside
   `connect`. The session stayed in server mode and sent relative deltas,
   which `Xspice` drops because its only pointer is a tablet. The pointer did
   not move at all.
2. **`connect` returned before the primary surface arrived**, handing the
   first caller of `dimensions()` a `0x0` geometry.

A third of the afternoon went to a bug that was **not** in the client: a
throwaway probe treated two seconds of silence as end-of-session, which
looked exactly like "the server never sends incremental updates". Writing an
independent 80-line Python SPICE client was what settled it — and that is the
general lesson, because the same symptom had three plausible causes on the
client side and one on the server's.

One of the two things `Xspice` could not reach is reachable now: a real
`spice-vdagent` answers in the QEMU guest. The other turned out not to be. The
plan was for `solstice-draw` to provoke `DRAW_ROP3`, `DRAW_STROKE` and
`DRAW_TEXT` through a real QXL driver, but once the session could count the
commands it executed, the count said the Linux driver never sends them:
`xf86-video-qxl` accelerates fills, copies, composites and uploads, and draws
everything else in software. So the raster-operation mapping behind those
three — `ropd_descriptor_to_rop`, transcribed from C that exists nowhere
else — still has only its transcription and a unit test for an oracle. The
ROP3 truth table at least has `rop3.c`'s own self-test constants, reproduced
as a test over all 256 opcodes. A Windows guest is the remaining route.
`docs/roadmap.md` §2.7.

### The whole path is tested, but only against one real server

`crates/solstice/tests/end_to_end.rs` runs the complete chain twice: once
against the colour-bar generator, reading the frame counter off the decoded
picture, and once against a real guest desktop painted a known colour. That
settles the question the research could not — the pieces fit together — but the
VNC half still meets exactly one implementation, and it is now QEMU's rather
than TigerVNC's. `docs/testing.md` §3.3 lists what that costs and when to
revisit it.

### Capture-derived golden vectors came last, and from our own host

`docs/testing.md` §2.4 calls a captured Sunshine ↔ Moonlight session *"the
highest-value artefact early on"* and says to capture it **before** writing the
packetiser. That did not happen: the packetiser was written against the source
reading and verified against a client of our own. The real client came later
(`docs/roadmap.md` §3), and a frozen capture of it later still (§4). The
capture has Solstice at the host end, so the client's half is ground truth and
the host's half is a pin rather than an oracle. Even so, it found a frame
numbering and a scroll layout that every earlier tier had accepted.
