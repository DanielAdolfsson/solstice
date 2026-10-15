/* Dump QUIC and LZ vectors from the real spice-common encoders.
 *
 * Links `common/quic.c` and `common/lz.c` from spice-common unmodified and
 * prints, for a set of deterministic test images, the compressed bytes and
 * the pixels the C *decoder* produces from them. The Rust port has to agree
 * with both halves: the bytes prove it reads the same format, the pixels
 * prove it reconstructs the same image.
 *
 * See README.md for how to build and run this.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/quic.h"
#include "common/lz.h"

#define MAX_BYTES (64 * 1024 * 1024)

/* ---- the usr contexts both encoders need ---------------------------- */

typedef struct {
    QuicUsrContext usr;
    uint32_t *buf;
    unsigned int words;
} QuicCtx;

typedef struct {
    LzUsrContext usr;
    uint8_t *buf;
    unsigned int bytes;
} LzCtx;

static void die(const char *fmt, va_list ap)
{
    vfprintf(stderr, fmt, ap);
    exit(1);
}

static void q_error(QuicUsrContext *u, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); die(fmt, ap);
}
static void q_warn(QuicUsrContext *u, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); die(fmt, ap);
}
static void q_info(QuicUsrContext *u, const char *fmt, ...) { (void)u; (void)fmt; }
static void *q_malloc(QuicUsrContext *u, int size) { (void)u; return malloc(size); }
static void q_free(QuicUsrContext *u, void *p) { (void)u; free(p); }

/* Both codecs get their whole buffer up front as an argument, so "more
 * space" means the buffer was too small -- fail loudly. The LZ decoder also
 * calls this to confirm it consumed every byte, and reads a zero as "there is
 * no more", which is what makes `is_io_to_decode_end` pass. */
static int q_more_space(QuicUsrContext *u, uint32_t **io_ptr, int rows)
{
    (void)u; (void)io_ptr; (void)rows;
    return 0;
}
static int q_more_lines(QuicUsrContext *u, uint8_t **lines)
{
    (void)u; (void)lines;
    fprintf(stderr, "more_lines called: the image should have been passed whole\n");
    exit(1);
}

static void l_error(LzUsrContext *u, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); die(fmt, ap);
}
static void l_warn(LzUsrContext *u, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); die(fmt, ap);
}
static void l_info(LzUsrContext *u, const char *fmt, ...) { (void)u; (void)fmt; }
static void *l_malloc(LzUsrContext *u, int size) { (void)u; return malloc(size); }
static void l_free(LzUsrContext *u, void *p) { (void)u; free(p); }
static int l_more_space(LzUsrContext *u, uint8_t **io_ptr)
{
    (void)u; (void)io_ptr;
    return 0;
}
static int l_more_lines(LzUsrContext *u, uint8_t **lines)
{
    (void)u; (void)lines;
    fprintf(stderr, "more_lines called: the image should have been passed whole\n");
    exit(1);
}

/* ---- deterministic test images -------------------------------------- */

/* A 32-bit xorshift, so the generator is reproducible without depending on
 * any libc's rand(). The Rust side does not need to reproduce these: the
 * expected pixels are dumped alongside the compressed bytes. */
static uint32_t rng_state;
static uint32_t rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

/* Fill `bytes_per_pixel`-wide pixels with one of several patterns, each
 * chosen to exercise a different part of the codec. */
static void fill(uint8_t *buf, int w, int h, int bpp, const char *pattern)
{
    int x, y, c;
    rng_state = 0x1234567u;
    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            uint8_t *p = buf + (y * w + x) * bpp;
            for (c = 0; c < bpp; c++) {
                int v;
                if (!strcmp(pattern, "flat")) {
                    /* Long identical runs: drives QUIC's run mode and LZ's
                     * self-overlapping matches. */
                    v = 0x40 + c * 0x10;
                } else if (!strcmp(pattern, "gradient")) {
                    /* Smooth, so prediction residuals stay near zero and the
                     * model settles on a short code. */
                    v = (x * 3 + y * 5 + c * 7) & 0xff;
                } else if (!strcmp(pattern, "noise")) {
                    /* Incompressible: forces the escape codewords and LZ's
                     * literal runs. */
                    v = rng() & 0xff;
                } else if (!strcmp(pattern, "bands")) {
                    /* Repeats every 16 rows, which is what a cross-image or
                     * long-distance match looks for. */
                    v = ((y / 16) * 37 + c * 11) & 0xff;
                } else if (!strcmp(pattern, "farmatch")) {
                    /* The first half is a long-period LCG so LZ can find no
                     * short match inside it; the second half repeats it
                     * exactly. The only match available is one of half the
                     * image, which at this size is past LZ's 8191-pixel
                     * short distance and so reaches the 16-bit escape --
                     * the one branch no natural image got near. */
                    int half = (w * h) / 2;
                    int i = y * w + x;
                    uint32_t k = (uint32_t)((i < half ? i : i - half) + 1);
                    k *= 2654435761u;
                    k ^= k >> 15;
                    v = (int)((k >> (c * 8)) & 0xff);
                } else if (!strcmp(pattern, "longperiod")) {
                    /* Repeats every 72 rows. At the large size that is 9360
                     * pixels, past LZ's 8191-pixel short distance, so the
                     * 16-bit far-distance escape is reached. */
                    v = (((y % 72) * 13 + (x % 5) * 59 + c * 11) ^ (y / 72)) & 0xff;
                } else { /* "edges" */
                    /* Hard vertical edges next to flat areas: the mix that
                     * makes the model switch codes often. */
                    v = ((x / 7) & 1) ? 0xf0 : 0x08;
                    v = (v + c * 3) & 0xff;
                }
                p[c] = (uint8_t)v;
            }
        }
    }
}

static void print_hex(const char *key, const uint8_t *data, size_t len)
{
    size_t i;
    printf("  \"%s\": \"", key);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\"");
}

static int first_case = 1;

static void begin_case(const char *codec, const char *name, const char *type,
                       int w, int h)
{
    if (!first_case) {
        printf(",\n");
    }
    first_case = 0;
    printf(" {\n");
    printf("  \"codec\": \"%s\",\n", codec);
    printf("  \"name\": \"%s\",\n", name);
    printf("  \"image_type\": \"%s\",\n", type);
    printf("  \"width\": %d,\n", w);
    printf("  \"height\": %d,\n", h);
}

/* ---- QUIC ------------------------------------------------------------ */

static void quic_case(QuicContext *quic, QuicCtx *ctx, const char *name,
                      QuicImageType type, int w, int h, const char *pattern)
{
    int src_bpp = (type == QUIC_IMAGE_TYPE_GRAY) ? 1
                : (type == QUIC_IMAGE_TYPE_RGB16) ? 2
                : (type == QUIC_IMAGE_TYPE_RGB24) ? 3 : 4;
    int out_bpp = (type == QUIC_IMAGE_TYPE_GRAY) ? 1 : 4;
    QuicImageType out_type = (type == QUIC_IMAGE_TYPE_GRAY) ? QUIC_IMAGE_TYPE_GRAY
                           : (type == QUIC_IMAGE_TYPE_RGBA) ? QUIC_IMAGE_TYPE_RGBA
                           : QUIC_IMAGE_TYPE_RGB32;
    uint8_t *src = malloc((size_t)w * h * src_bpp);
    uint8_t *out = calloc((size_t)w * h, out_bpp);
    int words, dec_w, dec_h;
    QuicImageType dec_type;
    const char *type_name;

    fill(src, w, h, src_bpp, pattern);
    if (type == QUIC_IMAGE_TYPE_RGB16) {
        /* The top bit of a 16-bit pixel is unused; the encoder ignores it and
         * the decoder writes zero, so clear it in the source too or the
         * round-trip comparison is meaningless. */
        int i;
        for (i = 0; i < w * h; i++) {
            src[i * 2 + 1] &= 0x7f;
        }
    }

    words = quic_encode(quic, type, w, h, src, h, w * src_bpp, ctx->buf, ctx->words);
    if (words <= 0) {
        fprintf(stderr, "quic_encode failed\n");
        exit(1);
    }

    if (quic_decode_begin(quic, ctx->buf, words, &dec_type, &dec_w, &dec_h) != QUIC_OK) {
        fprintf(stderr, "quic_decode_begin failed\n");
        exit(1);
    }
    if (dec_type != type || dec_w != w || dec_h != h) {
        fprintf(stderr, "quic header round-trip mismatch\n");
        exit(1);
    }
    if (quic_decode(quic, out_type, out, w * out_bpp) != QUIC_OK) {
        fprintf(stderr, "quic_decode failed\n");
        exit(1);
    }

    switch (type) {
    case QUIC_IMAGE_TYPE_GRAY:  type_name = "gray";  break;
    case QUIC_IMAGE_TYPE_RGB16: type_name = "rgb16"; break;
    case QUIC_IMAGE_TYPE_RGB24: type_name = "rgb24"; break;
    case QUIC_IMAGE_TYPE_RGB32: type_name = "rgb32"; break;
    default:                    type_name = "rgba";  break;
    }

    begin_case("quic", name, type_name, w, h);
    printf("  \"pattern\": \"%s\",\n", pattern);
    print_hex("compressed", (const uint8_t *)ctx->buf, (size_t)words * 4);
    printf(",\n");
    print_hex("decoded", out, (size_t)w * h * out_bpp);
    printf("\n }");

    free(src);
    free(out);
}

/* ---- LZ -------------------------------------------------------------- */

static void lz_case(LzContext *lz, LzCtx *ctx, const char *name,
                    LzImageType type, int w, int h, const char *pattern,
                    int top_down)
{
    int src_bpp = (type == LZ_IMAGE_TYPE_RGB16) ? 2
                : (type == LZ_IMAGE_TYPE_RGB24) ? 3
                : (type == LZ_IMAGE_TYPE_A8) ? 1 : 4;
    int out_bpp = (type == LZ_IMAGE_TYPE_A8) ? 1 : 4;
    LzImageType out_type = type;
    uint8_t *src = malloc((size_t)w * h * src_bpp);
    uint8_t *out = calloc((size_t)w * h, out_bpp);
    int bytes, dec_w, dec_h, dec_px, dec_td;
    LzImageType dec_type;
    const char *type_name;

    /* The Rust crate always produces BGRA, so ask the C for the same
     * conversion rather than for the source layout. */
    if (type == LZ_IMAGE_TYPE_RGB24 || type == LZ_IMAGE_TYPE_RGB16) {
        out_type = LZ_IMAGE_TYPE_RGB32;
    }

    fill(src, w, h, src_bpp, pattern);
    if (type == LZ_IMAGE_TYPE_RGB16) {
        int i;
        for (i = 0; i < w * h; i++) {
            src[i * 2 + 1] &= 0x7f;
        }
    }

    bytes = lz_encode(lz, type, w, h, top_down, src, h, w * src_bpp,
                      ctx->buf, ctx->bytes);
    if (bytes <= 0) {
        fprintf(stderr, "lz_encode failed\n");
        exit(1);
    }

    lz_decode_begin(lz, ctx->buf, bytes, &dec_type, &dec_w, &dec_h, &dec_px,
                    &dec_td, NULL);
    if (dec_type != type || dec_w != w || dec_h != h) {
        fprintf(stderr, "lz header round-trip mismatch\n");
        exit(1);
    }
    lz_decode(lz, out_type, out);

    switch (type) {
    case LZ_IMAGE_TYPE_RGB16: type_name = "rgb16"; break;
    case LZ_IMAGE_TYPE_RGB24: type_name = "rgb24"; break;
    case LZ_IMAGE_TYPE_RGB32: type_name = "rgb32"; break;
    case LZ_IMAGE_TYPE_RGBA:  type_name = "rgba";  break;
    case LZ_IMAGE_TYPE_XXXA:  type_name = "xxxa";  break;
    default:                  type_name = "a8";    break;
    }

    begin_case("lz", name, type_name, w, h);
    printf("  \"pattern\": \"%s\",\n", pattern);
    printf("  \"top_down\": %s,\n", top_down ? "true" : "false");
    print_hex("compressed", ctx->buf, (size_t)bytes);
    printf(",\n");
    print_hex("decoded", out, (size_t)w * h * out_bpp);
    printf("\n }");

    free(src);
    free(out);
}


/* Emit every image type against every pattern at every size given. */
static void emit_block(QuicContext *quic, QuicCtx *qctx, LzContext *lz, LzCtx *lctx,
                       const int sizes[][2], size_t n_sizes,
                       const char *const *patterns, size_t n_patterns)
{
    static const QuicImageType qtypes[] = {
        QUIC_IMAGE_TYPE_GRAY, QUIC_IMAGE_TYPE_RGB16, QUIC_IMAGE_TYPE_RGB24,
        QUIC_IMAGE_TYPE_RGB32, QUIC_IMAGE_TYPE_RGBA
    };
    static const char *qnames[] = {"gray", "rgb16", "rgb24", "rgb32", "rgba"};
    static const LzImageType ltypes[] = {
        LZ_IMAGE_TYPE_RGB16, LZ_IMAGE_TYPE_RGB24, LZ_IMAGE_TYPE_RGB32,
        LZ_IMAGE_TYPE_RGBA, LZ_IMAGE_TYPE_XXXA, LZ_IMAGE_TYPE_A8
    };
    static const char *lnames[] = {"rgb16", "rgb24", "rgb32", "rgba", "xxxa", "a8"};
    char name[128];
    size_t s, p, t;

    for (s = 0; s < n_sizes; s++) {
        for (p = 0; p < n_patterns; p++) {
            int w = sizes[s][0], h = sizes[s][1];

            for (t = 0; t < sizeof(qtypes) / sizeof(qtypes[0]); t++) {
                snprintf(name, sizeof(name), "quic-%s-%s-%dx%d", qnames[t],
                         patterns[p], w, h);
                quic_case(quic, qctx, name, qtypes[t], w, h, patterns[p]);
            }
            for (t = 0; t < sizeof(ltypes) / sizeof(ltypes[0]); t++) {
                snprintf(name, sizeof(name), "lz-%s-%s-%dx%d", lnames[t],
                         patterns[p], w, h);
                lz_case(lz, lctx, name, ltypes[t], w, h, patterns[p],
                        (int)((s + p + t) % 2));
            }
        }
    }
}

int main(void)
{
    QuicCtx qctx;
    LzCtx lctx;
    QuicContext *quic;
    LzContext *lz;
    static const char *patterns[] = {"flat", "gradient", "noise", "bands", "edges"};

    memset(&qctx, 0, sizeof(qctx));
    qctx.usr.error = q_error;
    qctx.usr.warn = q_warn;
    qctx.usr.info = q_info;
    qctx.usr.malloc = q_malloc;
    qctx.usr.free = q_free;
    qctx.usr.more_space = q_more_space;
    qctx.usr.more_lines = q_more_lines;
    qctx.words = MAX_BYTES / 4;
    qctx.buf = malloc(MAX_BYTES);

    memset(&lctx, 0, sizeof(lctx));
    lctx.usr.error = l_error;
    lctx.usr.warn = l_warn;
    lctx.usr.info = l_info;
    lctx.usr.malloc = l_malloc;
    lctx.usr.free = l_free;
    lctx.usr.more_space = l_more_space;
    lctx.usr.more_lines = l_more_lines;
    lctx.bytes = MAX_BYTES;
    lctx.buf = malloc(MAX_BYTES);

    quic = quic_create(&qctx.usr);
    lz = lz_create(&lctx.usr);
    if (!quic || !lz) {
        fprintf(stderr, "create failed\n");
        return 1;
    }

    printf("[\n");

    {
        /* Every type against every pattern at small sizes, where the whole
         * file stays cheap: 1x1 and 3x2 catch the row-0 and first-pixel
         * special cases, 17x5 is wide enough for a real match and a run. */
        static const int small[][2] = {{1, 1}, {3, 2}, {17, 5}};
        /* Two structured patterns at 64x64 (4096 px) and 130x100 (13000 px).
         * The large size is what crosses QUIC's 2048-symbol wait-mask step
         * more than once and gives LZ distances past 8191. Noise is left out
         * above 17x5 deliberately: it compresses to nothing, so it would be
         * most of the file for none of the coverage. */
        static const int medium[][2] = {{64, 64}};
        static const char *medium_patterns[] = {"gradient", "edges"};
        static const int large[][2] = {{130, 100}};
        static const char *large_patterns[] = {"bands", "longperiod"};

        emit_block(quic, &qctx, lz, &lctx, small, 3, patterns, 5);
        emit_block(quic, &qctx, lz, &lctx, medium, 1, medium_patterns, 2);
        emit_block(quic, &qctx, lz, &lctx, large, 1, large_patterns, 2);

        /* One very wide image whose second half repeats its first, which is
         * the only way to make the C encoder emit a distance past 8191.
         * LZ only: the point is the distance encoding, and paying for five
         * more QUIC images of incompressible noise would buy nothing. */
        lz_case(lz, &lctx, "lz-rgb32-farmatch-20000x1", LZ_IMAGE_TYPE_RGB32,
                20000, 1, "farmatch", 1);
        lz_case(lz, &lctx, "lz-a8-farmatch-20000x1", LZ_IMAGE_TYPE_A8,
                20000, 1, "farmatch", 1);
    }

    printf("\n]\n");

    quic_destroy(quic);
    lz_destroy(lz);
    return 0;
}
