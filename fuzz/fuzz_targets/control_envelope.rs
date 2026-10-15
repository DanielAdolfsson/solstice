//! The ENet control envelope -- the shape of GHSA-c428-87f8-rrv5, an
//! unauthenticated denial of service via a short control packet.
#![no_main]
use libfuzzer_sys::fuzz_target;
use solstice_gamestream::stream::control::ControlCodec;
use solstice_gamestream::wire::control::EncryptedPacket;

fuzz_target!(|data: &[u8]| {
    let _ = EncryptedPacket::parse(data);
    // And through the authenticated path: nothing may reach the input parser
    // without a valid GCM tag.
    let mut codec = ControlCodec::new(Some(&[0x33; 16]));
    let _ = codec.decode(data);
});
