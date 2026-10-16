# A captured Moonlight session

`session.json.gz` is one real streaming session: the reference
`moonlight-common-c` (`tests/tools/mlc-probe`) against this host. It was
captured off the wire, decrypted offline and frozen, so CI can replay a real
client's traffic without a C toolchain, a network or the probe.
`crates/solstice-gamestream/tests/capture_vectors.rs` is the replay.
`docs/roadmap.md` §4 covers why it exists and what it found.

## Capture

```sh
./tests/tools/mlc-probe/build.sh     # once
./tests/tools/capture-session.sh     # rewrites session.json.gz
cargo test -p solstice-gamestream --test capture_vectors
```

`capture-session.sh` runs `crates/solstice/tests/real_moonlight.rs` inside
`unshare -rn`, a private network namespace in which an unprivileged user is
root. `tcpdump` listens on that namespace's loopback, so no root is needed and
no other traffic gets in. The test writes a sidecar only once every one of its
own assertions has passed, so a broken session never becomes a vector. The
sidecar holds the session keys (the client generates `rikey`), the ports, the
host settings and the client's recordings.

`tests/tools/gen_capture_vectors.py` then does the following, using its own
pcap, TCP and ENet parsing and Python's `cryptography`, and none of the
host's code:

1. Reassembles the RTSP connections (one message each way per connection)
   and opens every GCM envelope.
2. Reads the session ID, ping payload and connect data out of the SETUP
   responses. It checks that the pings carry that payload, and that the
   client's ENet `CONNECT` carries that connect data.
3. Splits each ENet datagram into commands and opens every control message
   inside.
4. Decrypts every video shard, groups shards into frames by FEC block,
   reassembles each frame, and requires the result to equal what the client
   recorded. The comparison is byte for byte, including the zero padding the
   client hands its H.264 decoder.
5. Decrypts every audio packet and requires the Opus to equal what the client
   recorded.

Nothing is written unless all of that holds. Every GCM tag verifies, so a
plaintext in the file is the plaintext.

## What the replay asserts

The file holds two kinds of bytes, and the tests treat them differently.

**The client's bytes are ground truth.** These are the RTSP requests and the
ANNOUNCE, the pings, the ENet connect data and every control message. They
came out of the reference client, so a host that misreads them is wrong. They
are decrypted with the host's own crypto, parsed with its parsers, and held
against what the probe was told to send, with a source citation wherever the
client changes it on the way.

**The host's bytes are pinned.** These are the RTSP responses and the video
and audio datagrams. They are Solstice's output, but output the reference
client accepted: with `LC_DEBUG` on, every frame was FEC-validated and
decoded. The replay feeds the same inputs through `RtspServer`,
`VideoPacketizer` and `AudioPacketizer` and requires identical bytes. A
change to the wire format therefore fails here first, showing which packet
moved. If the change is intentional, recapture.

## Layout

| Key | Contents |
|---|---|
| `session` | `rikey`, `rikey_id`, geometry, ports, host settings, and the session ID, ping payload and connect data as SETUP handed them out |
| `rtsp[]` | each exchange: client and host envelope on the wire, sequence numbers, plaintext request and response |
| `pings` | the client's video and audio ping datagrams |
| `control` | ENet datagrams both ways (raw, for §7 and fuzz seeds), and every control message decrypted: wire, sequence, type, payload |
| `video` | each complete frame: index, RTP timestamp, frame type, latency field, the access unit, the padded length, and every shard's wire bytes, plaintext and header fields. `recorded_frames` and `recording_sha256` pin what the client recorded |
| `audio` | each packet of each complete FEC block: wire bytes, sequence, and the decrypted Opus on data packets |

Bytes are lowercase hex. The gzip carries no timestamp, so recompressing the
same capture gives the same file. A *new* capture changes every byte,
because the keys and session values are minted per run.
