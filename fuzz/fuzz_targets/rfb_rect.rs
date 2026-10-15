//! RFB rectangle decoders, which run on data from the backend. A VM the user
//! does not fully control is an inbound attack surface
//! (`docs/security.md` §5.4).
#![no_main]
use libfuzzer_sys::fuzz_target;
use solstice_backend::{Framebuffer, Rect};
use solstice_vnc::encodings::{hextile, raw, rre, zrle};
use solstice_vnc::pixel::PixelFormat;

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let format = PixelFormat::BGRA;
    let rect = Rect { x: 0, y: 0, width: 32, height: 32 };
    runtime.block_on(async {
        let mut fb = Framebuffer::new(64, 64);
        let _ = raw::decode(&mut std::io::Cursor::new(data), &format, rect, &mut fb).await;
        let mut fb = Framebuffer::new(64, 64);
        let _ = rre::decode(&mut std::io::Cursor::new(data), &format, rect, &mut fb).await;
        let mut fb = Framebuffer::new(64, 64);
        let _ = hextile::decode(&mut std::io::Cursor::new(data), &format, rect, &mut fb).await;
        // The tile stream, without the zlib layer, so the fuzzer reaches the
        // RLE and palette paths directly rather than spending its budget
        // producing valid deflate.
        let mut fb = Framebuffer::new(64, 64);
        let _ = zrle::decode_tiles(&format, rect, &mut fb, data);
    });
});
