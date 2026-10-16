#!/usr/bin/env python3
"""Freeze a captured Moonlight session into golden vectors.

`tests/tools/capture-session.sh` runs the real-Moonlight test under tcpdump and
leaves a directory holding the pcap, the session keys (`session.json`) and the
elementary streams the client recorded.  This script decrypts the capture and
writes `tests/vectors/capture/session.json.gz`, so CI can replay a real
session without a C toolchain, a network or a probe (`docs/roadmap.md` §4).

It is deliberately independent of Solstice: the pcap parser, the TCP
reassembly, the ENet framing and every decryption below are written from the
protocol, not from the Rust, and use Python's `cryptography` rather than the
crates the host uses.  Every GCM tag has to verify, so a plaintext produced
here is the plaintext -- and the reassembled video and audio are then held
against what `moonlight-common-c` itself recorded, which is the real client's
view of the same bytes.  Nothing is written unless all of that agrees.

Usage:
    python3 -I tests/tools/gen_capture_vectors.py <capture-dir> [outdir]
"""
import gzip
import hashlib
import json
import os
import struct
import sys

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def fail(message):
    sys.exit(f"gen_capture_vectors: {message}")


# --- pcap ---------------------------------------------------------------------

def read_pcap(path):
    """Yield (proto, src_port, dst_port, payload, tcp) for each IPv4 packet."""
    with open(path, "rb") as f:
        data = f.read()
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        fail(f"{path}: not a microsecond pcap (magic {magic:#x})")
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if linktype != 1:
        fail(f"{path}: link type {linktype}, expected Ethernet")
    offset = 24
    while offset < len(data):
        _, _, incl, orig = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        frame = data[offset:offset + incl]
        offset += incl
        if incl != orig:
            fail("a packet was truncated by the snapshot length")
        if struct.unpack_from(">H", frame, 12)[0] != 0x0800:
            continue
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack_from(">H", ip, 2)[0]
        proto = ip[9]
        body = ip[ihl:total]
        if proto == 17:
            sport, dport, length = struct.unpack_from(">HHH", body, 0)
            yield "udp", sport, dport, body[8:length], None
        elif proto == 6:
            sport, dport, seq = struct.unpack_from(">HHI", body, 0)
            data_offset = (body[12] >> 4) * 4
            flags = body[13]
            yield "tcp", sport, dport, body[data_offset:], (seq, flags)


def reassemble_tcp(segments):
    """One direction of a TCP connection: (seq, flags, payload) in capture order."""
    syn = [s for s in segments if s[1] & 0x02]
    if not syn:
        fail("a TCP direction without a SYN; the capture started too late")
    base = syn[0][0] + 1
    out = bytearray()
    for seq, _, payload in segments:
        if not payload:
            continue
        at = (seq - base) & 0xFFFFFFFF
        if at > len(out):
            fail("a hole in a TCP stream")
        out[at:at + len(payload)] = payload
    return bytes(out)


# --- crypto -------------------------------------------------------------------

def gcm_open(key, iv, ciphertext, tag):
    return AESGCM(key).decrypt(iv, ciphertext + tag, None)


def tagged_iv(sequence, origin, stream):
    """The RTSP and control IV: LE32 sequence, origin byte, stream byte."""
    iv = bytearray(12)
    iv[0:4] = struct.pack("<I", sequence)
    iv[10] = ord(origin)
    iv[11] = ord(stream)
    return bytes(iv)


def open_rtsp(key, buf, origin):
    """Exactly one encrypted RTSP message, which is all a connection carries."""
    type_and_length, sequence = struct.unpack_from(">II", buf, 0)
    if not type_and_length & 0x80000000:
        fail("a plaintext RTSP message on an encrypted session")
    length = type_and_length & 0x7FFFFFFF
    if len(buf) != 24 + length:
        fail(f"an RTSP connection carried {len(buf)} bytes for a {length}-byte message")
    tag = buf[8:24]
    plaintext = gcm_open(key, tagged_iv(sequence, origin, "R"), buf[24:], tag)
    return sequence, plaintext


def open_control(key, packet, origin):
    header_type, length, sequence = struct.unpack_from("<HHI", packet, 0)
    if header_type != 0x0001:
        fail(f"control header type {header_type:#x}")
    tag = packet[8:24]
    ciphertext = packet[24:24 + length - 20]
    if len(ciphertext) != length - 20:
        fail("a truncated control message")
    plaintext = gcm_open(key, tagged_iv(sequence, origin, "C"), ciphertext, tag)
    msg_type, msg_len = struct.unpack_from("<HH", plaintext, 0)
    if msg_len != len(plaintext) - 4:
        fail(f"control message {msg_type:#06x} claims {msg_len} bytes of {len(plaintext) - 4}")
    return sequence, msg_type, plaintext[4:]


def open_audio(key, rikey_id, sequence, ciphertext):
    value = (rikey_id + sequence) & 0xFFFFFFFF
    iv = struct.pack(">I", value) + bytes(12)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# --- ENet ---------------------------------------------------------------------

ENET_SIZES = {
    1: 8,    # ACKNOWLEDGE
    2: 48,   # CONNECT
    3: 44,   # VERIFY_CONNECT
    4: 8,    # DISCONNECT
    5: 4,    # PING
    6: 6,    # SEND_RELIABLE
    7: 8,    # SEND_UNRELIABLE
    8: 24,   # SEND_FRAGMENT
    9: 8,    # SEND_UNSEQUENCED
    10: 12,  # BANDWIDTH_LIMIT
    11: 16,  # THROTTLE_CONFIGURE
    12: 24,  # SEND_UNRELIABLE_FRAGMENT
}


def enet_commands(datagram):
    """Split one ENet datagram into (command, channel, rsn, body, data).

    Stock ENet framing (`enet/protocol.h`): no checksum and no compression,
    which is how moonlight-common-c creates its host.  Multi-byte fields are
    big-endian.
    """
    peer_id = struct.unpack_from(">H", datagram, 0)[0]
    if peer_id & 0x4000:
        fail("a compressed ENet datagram")
    offset = 4 if peer_id & 0x8000 else 2
    while offset < len(datagram):
        command, channel, rsn = struct.unpack_from(">BBH", datagram, offset)
        kind = command & 0x0F
        size = ENET_SIZES.get(kind)
        if size is None:
            fail(f"unknown ENet command {kind}")
        body = datagram[offset:offset + size]
        data = b""
        if kind == 6:
            data_len = struct.unpack_from(">H", body, 4)[0]
        elif kind in (7, 9):
            data_len = struct.unpack_from(">H", body, 6)[0]
        elif kind in (8, 12):
            fail("a fragmented ENet message; the control messages here are all small")
        else:
            data_len = 0
        data = datagram[offset + size:offset + size + data_len]
        yield kind, channel, rsn, body, data
        offset += size + data_len


# --- the session --------------------------------------------------------------

def rtsp_header(text, name):
    for line in text.split("\r\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            if key.strip().lower() == name.lower():
                return value.strip()
    return None


def main():
    if len(sys.argv) not in (2, 3):
        fail("usage: gen_capture_vectors.py <capture-dir> [outdir]")
    capture = sys.argv[1]
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    outdir = sys.argv[2] if len(sys.argv) == 3 else os.path.join(root, "tests/vectors/capture")

    with open(os.path.join(capture, "session.json")) as f:
        session = json.load(f)
    key = bytes.fromhex(session["rikey"])
    rikey_id = session["rikey_id"]
    ports = session["ports"]

    tcp = {}
    udp = []
    for proto, sport, dport, payload, extra in read_pcap(os.path.join(capture, "session.pcap")):
        if proto == "udp":
            udp.append((sport, dport, payload))
        elif ports["rtsp"] in (sport, dport):
            client_port = sport if dport == ports["rtsp"] else dport
            conn = tcp.setdefault(client_port, {"order": len(tcp), "client": [], "host": []})
            side = "client" if dport == ports["rtsp"] else "host"
            conn[side].append((extra[0], extra[1], payload))

    # --- RTSP: one message each way per connection, in connection order -----
    rtsp = []
    for conn in sorted(tcp.values(), key=lambda c: c["order"]):
        client_wire = reassemble_tcp(conn["client"])
        host_wire = reassemble_tcp(conn["host"])
        if not client_wire:
            continue
        client_seq, request = open_rtsp(key, client_wire, "C")
        host_seq, response = open_rtsp(key, host_wire, "H")
        rtsp.append({
            "client_sequence": client_seq,
            "client_wire": client_wire.hex(),
            "request": request.decode(),
            "host_sequence": host_seq,
            "host_wire": host_wire.hex(),
            "response": response.decode(),
        })
    methods = [r["request"].split(" ", 1)[0] for r in rtsp]
    if "PLAY" not in methods:
        fail(f"the RTSP transcript never reached PLAY: {methods}")

    session_id = ping_payload = connect_data = None
    for r in rtsp:
        if " streamid=audio" in r["request"].split("\r\n", 1)[0]:
            session_id = rtsp_header(r["response"], "Session").split(";", 1)[0]
        ping_payload = ping_payload or rtsp_header(r["response"], "X-SS-Ping-Payload")
        connect_data = connect_data or rtsp_header(r["response"], "X-SS-Connect-Data")
    if None in (session_id, ping_payload, connect_data):
        fail("the SETUP responses did not carry the session parameters")

    # --- pings --------------------------------------------------------------
    pings = {
        "video": [p.hex() for s, d, p in udp if d == ports["video"]],
        "audio": [p.hex() for s, d, p in udp if d == ports["audio"]],
    }
    for name, datagrams in pings.items():
        if not datagrams:
            fail(f"no {name} ping in the capture")
        for hexed in datagrams:
            raw = bytes.fromhex(hexed)
            if raw[:16].decode() != ping_payload:
                fail(f"a {name} ping carried {raw[:16]!r}, not the payload SETUP handed out")

    # --- control ------------------------------------------------------------
    control = {"client_datagrams": [], "host_datagrams": [], "client": [], "host": []}
    enet_connect_data = None
    seen = set()
    for sport, dport, payload in udp:
        if ports["control"] not in (sport, dport):
            continue
        side = "client" if dport == ports["control"] else "host"
        origin = "C" if side == "client" else "H"
        control[f"{side}_datagrams"].append(payload.hex())
        for kind, channel, rsn, body, data in enet_commands(payload):
            if kind == 2:
                enet_connect_data = struct.unpack_from(">I", body, 44)[0]
            if not data:
                continue
            # A reliable command can be retransmitted; the message is the
            # first copy.
            if kind == 6:
                if (side, channel, rsn) in seen:
                    continue
                seen.add((side, channel, rsn))
            sequence, msg_type, plaintext = open_control(key, data, origin)
            control[side].append({
                "wire": data.hex(),
                "sequence": sequence,
                "type": msg_type,
                "payload": plaintext.hex(),
            })
    if enet_connect_data is None:
        fail("no ENet CONNECT in the capture")
    if str(enet_connect_data) != connect_data:
        fail(f"the client connected with {enet_connect_data}, not {connect_data}")
    control["connect_data"] = enet_connect_data

    # --- video --------------------------------------------------------------
    video_packets = []
    for sport, dport, payload in udp:
        if sport != ports["video"]:
            continue
        iv, frame_number, tag = payload[:12], struct.unpack_from("<I", payload, 12)[0], payload[16:32]
        plaintext = gcm_open(key, iv, payload[32:], tag)
        sequence, timestamp = struct.unpack_from(">HI", plaintext, 2)
        spi, frame_index, flags, extra, mff, mfb, fec_info = struct.unpack_from(
            "<IIBBBBI", plaintext, 16)
        if frame_index != frame_number:
            fail(f"frame {frame_index} sent under encryption prefix frame {frame_number}")
        video_packets.append({
            "wire": payload,
            "plaintext": plaintext,
            "sequence": sequence,
            "timestamp": timestamp,
            "frame_index": frame_index,
            "stream_packet_index": spi,
            "flags": flags,
            "multi_fec_blocks": mfb,
            "fec_info": fec_info,
        })
    for i, p in enumerate(video_packets):
        if p["sequence"] != i & 0xFFFF:
            fail(f"video packet {i} has sequence {p['sequence']}; the capture has a hole")

    payload_blocksize = len(video_packets[0]["plaintext"]) - 32
    frames = []
    index = 0
    while index < len(video_packets):
        frame_index = video_packets[index]["frame_index"]
        block_count = ((video_packets[index]["multi_fec_blocks"] >> 6) & 3) + 1
        packets = []
        complete = True
        for _ in range(block_count):
            if index >= len(video_packets):
                complete = False
                break
            fec_info = video_packets[index]["fec_info"]
            data_shards = (fec_info >> 22) & 0x3FF
            percentage = (fec_info >> 4) & 0xFF
            # The client's derivation, which is the only one that matters
            # (`RtpVideoQueue.c:708`).
            parity = (data_shards * percentage + 99) // 100
            block = video_packets[index:index + data_shards + parity]
            if len(block) < data_shards + parity:
                complete = False
                break
            packets.extend(block)
            index += data_shards + parity
        if not complete:
            break
        if any(p["frame_index"] != frame_index for p in packets):
            fail(f"frame {frame_index} interleaved with another")
        data = []
        for p in packets:
            shard, data_shards, _ = ((p["fec_info"] >> 12) & 0x3FF,
                                     (p["fec_info"] >> 22) & 0x3FF, 0)
            if shard < data_shards:
                data.append(p["plaintext"][32:])
        joined = b"".join(data)
        header_type, latency, frame_type, last_len = struct.unpack_from("<BHBH", joined, 0)
        if header_type != 0x01:
            fail(f"frame {frame_index} header type {header_type:#x}")
        end = (len(data) - 1) * payload_blocksize + last_len
        if any(joined[end:]):
            fail(f"frame {frame_index} has data past its declared last payload length")
        frames.append({
            "frame_index": frame_index,
            "timestamp": packets[0]["timestamp"],
            "frame_type": frame_type,
            "latency": latency,
            "access_unit": joined[8:end].hex(),
            # What the client hands its decoder: for H.264 it keeps the FEC
            # zero padding, which an Annex B parser ignores
            # (`VideoDepacketizer.c:906-911`).
            "padded_length": len(joined) - 8,
            "packets": [{
                "wire": p["wire"].hex(),
                "plaintext": p["plaintext"].hex(),
                "sequence": p["sequence"],
                "stream_packet_index": p["stream_packet_index"],
                "flags": p["flags"],
                "multi_fec_blocks": p["multi_fec_blocks"],
                "fec_info": p["fec_info"],
            } for p in packets],
        })
    # The client starts at frame 1 and drops anything earlier
    # (`VideoDepacketizer.c:65`, `:772`).
    for i, frame in enumerate(frames):
        if frame["frame_index"] != i + 1:
            fail(f"frame {i + 1} is numbered {frame['frame_index']}")

    with open(os.path.join(capture, "recorded.h264"), "rb") as f:
        recorded = f.read()
    stream = b""
    recorded_frames = 0
    for frame in frames:
        if len(stream) >= len(recorded):
            break
        au = bytes.fromhex(frame["access_unit"])
        stream += au + bytes(frame["padded_length"] - len(au))
        recorded_frames += 1
    if stream != recorded:
        at = next((i for i, (a, b) in enumerate(zip(stream, recorded)) if a != b),
                  min(len(stream), len(recorded)))
        fail(f"the reassembled frames are not what moonlight-common-c recorded: "
             f"{len(stream)} bytes over {recorded_frames} frames against {len(recorded)}, "
             f"first difference at byte {at}")

    # --- audio --------------------------------------------------------------
    audio_data, audio_fec = [], []
    for sport, dport, payload in udp:
        if sport != ports["audio"]:
            continue
        payload_type = payload[1] & 0x7F
        sequence, timestamp = struct.unpack_from(">HI", payload, 2)
        if payload_type == 97:
            audio_data.append((sequence, timestamp, payload))
        elif payload_type == 127:
            audio_fec.append((sequence, timestamp, payload))
        else:
            fail(f"audio payload type {payload_type}")
    for i, (sequence, _, _) in enumerate(audio_data):
        if sequence != i:
            fail(f"audio packet {i} has sequence {sequence}; the capture has a hole")
    blocks = min(len(audio_data) // 4, len(audio_fec) // 2)
    audio = []
    for b in range(blocks):
        for sequence, timestamp, payload in audio_data[b * 4:b * 4 + 4]:
            audio.append({
                "wire": payload.hex(),
                "opus": open_audio(key, rikey_id, sequence, payload[12:]).hex(),
                "sequence": sequence,
                "timestamp": timestamp,
            })
        for sequence, timestamp, payload in audio_fec[b * 2:b * 2 + 2]:
            base = struct.unpack_from(">H", payload, 14)[0]
            if base != b * 4:
                fail(f"audio parity for base {base} where block {b} was expected")
            audio.append({"wire": payload.hex(), "sequence": sequence, "timestamp": timestamp})

    with open(os.path.join(capture, "recorded.opus"), "rb") as f:
        recorded_audio = f.read()
    opus = b""
    recorded_audio_packets = 0
    for p in audio:
        if len(opus) >= len(recorded_audio):
            break
        if "opus" in p:
            opus += bytes.fromhex(p["opus"])
            recorded_audio_packets += 1
    if opus != recorded_audio:
        fail("the decrypted audio is not what moonlight-common-c recorded")

    vectors = {
        "source": "a real moonlight-common-c (tests/tools/mlc-probe) streaming from Solstice, "
                  "captured by tests/tools/capture-session.sh",
        "session": {
            "rikey": session["rikey"],
            "rikey_id": rikey_id,
            "width": session["width"],
            "height": session["height"],
            "fps": session["fps"],
            "ports": ports,
            "host": session["host"],
            "session_id": session_id,
            "ping_payload": ping_payload,
            "connect_data": int(connect_data),
        },
        "rtsp": rtsp,
        "pings": pings,
        "control": control,
        "video": {
            "payload_blocksize": payload_blocksize,
            "recorded_frames": recorded_frames,
            "recording_sha256": hashlib.sha256(recorded).hexdigest(),
            "frames": frames,
        },
        "audio": {
            "recorded_packets": recorded_audio_packets,
            "packets": audio,
        },
    }

    os.makedirs(outdir, exist_ok=True)
    out = os.path.join(outdir, "session.json.gz")
    # mtime=0 and no filename, so the same capture gives the same bytes.
    with open(out, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as f:
            f.write(json.dumps(vectors, indent=1, sort_keys=True).encode())

    print(f"rtsp      {len(rtsp)} exchanges: {' '.join(methods)}")
    print(f"control   {len(control['client'])} client / {len(control['host'])} host messages, "
          f"{len(control['client_datagrams'])}+{len(control['host_datagrams'])} ENet datagrams")
    print(f"video     {len(frames)} frames, {sum(len(f['packets']) for f in frames)} packets; "
          f"the first {recorded_frames} match the client's recording")
    print(f"audio     {blocks} FEC blocks; the first {recorded_audio_packets} packets "
          f"match the client's recording")
    print(f"wrote {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
