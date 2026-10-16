//! RFB rectangle decoders, which run on data from the backend. A VM the user
//! does not fully control is an inbound attack surface
//! (`docs/security.md` §5.4).
#![no_main]
use libfuzzer_sys::fuzz_target;
use solstice_backend::{Framebuffer, Rect};
use solstice_vnc::encodings::tight::{self, Filter, TightStreams};
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

        // Tight from the wire, with four fresh streams: the control byte,
        // fill, the filter id, the palette and the uncompressed short-data
        // path are all reachable without valid deflate.
        let mut fb = Framebuffer::new(64, 64);
        let _ = tight::decode(
            &mut std::io::Cursor::new(data),
            &format,
            rect,
            &mut fb,
            &mut TightStreams::new(),
        )
        .await;
        // And Tight's filters over already-inflated data, the way ZRLE's tiles
        // are fuzzed above. The first byte picks the filter and the width; the
        // height is whatever the rest fills, so the length check passes and
        // the fuzzer's budget goes on the pixel loops.
        if let Some((&pick, rest)) = data.split_first() {
            let filter = match pick & 3 {
                0 => Filter::Copy,
                1 => Filter::Gradient,
                2 => Filter::Palette(vec![[1, 2, 3, 255], [4, 5, 6, 255]]),
                _ => Filter::Palette(vec![[7, 8, 9, 255]; 3 + (pick >> 2) as usize * 4]),
            };
            let width = 1 + (pick >> 2) as u32 % 64;
            let row = tight::data_size(&format, Rect { x: 0, y: 0, width, height: 1 }, &filter);
            let height = (rest.len() / row).min(64) as u32;
            let rect = Rect { x: 0, y: 0, width, height };
            let mut fb = Framebuffer::new(64, 64);
            let _ = tight::decode_pixels(&format, rect, &mut fb, &filter, &rest[..row * height as usize]);
        }
    });
});
