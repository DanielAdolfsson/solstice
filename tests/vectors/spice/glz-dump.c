/* Dump GLZ vectors from the real spice-server encoder.
 *
 * GLZ cannot be tested one image at a time: a match may reach back into an
 * image sent earlier in the session, so a vector is a *window* -- a sequence
 * of images encoded through one dictionary, which has to be decoded through
 * one decoder in the same order. Each window here is a base image followed by
 * scrolled and patched variants of it, which is what gives the encoder long
 * cross-image matches to find.
 *
 * Expected pixels are the source image, converted to BGRA. GLZ is lossless,
 * so a correct decoder reproduces its input exactly, and that is a complete
 * test of the control encoding and the window arithmetic. For every type the
 * C `lz_decode` supports, the conversion itself is cross-checked here against
 * the C by encoding the same source with LZ and decoding it -- so the
 * expected buffer is not this program's opinion. The palette types are the
 * exception; see README.md.
 *
 * See README.md for how to build and run this.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "glz-encoder.h"
#include "glz-encoder-dict.h"
#include "common/lz.h"

#define MAX_BYTES (32 * 1024 * 1024)

static uint8_t *io_buf;
static uint8_t *lz_io_buf;

/* ---- encoder callbacks ---------------------------------------------- */

static void g_error_cb(GlzEncoderUsrContext *u, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); exit(1);
}
static void g_warn_cb(GlzEncoderUsrContext *u, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); exit(1);
}
static void g_info_cb(GlzEncoderUsrContext *u, const char *fmt, ...) { (void)u; (void)fmt; }
static void *g_malloc_cb(GlzEncoderUsrContext *u, size_t size) { (void)u; return malloc(size); }
static void g_free_cb(GlzEncoderUsrContext *u, void *p) { (void)u; free(p); }
static int g_more_lines(GlzEncoderUsrContext *u, uint8_t **lines)
{
    (void)u; (void)lines;
    fprintf(stderr, "glz more_lines: the image should have been passed whole\n");
    exit(1);
}
static int g_more_space(GlzEncoderUsrContext *u, uint8_t **io_ptr)
{
    (void)u; (void)io_ptr;
    fprintf(stderr, "glz more_space: buffer too small\n");
    exit(1);
}
/* Called when the dictionary drops an image. Nothing to free: the sources
 * outlive the encoder. */
static void g_free_image(GlzEncoderUsrContext *u, GlzUsrImageContext *image)
{
    (void)u; (void)image;
}

static GlzEncoderUsrContext glz_usr;

/* ---- LZ, used only to certify the expected buffers ------------------- */

typedef struct { LzUsrContext usr; } LzCtx;

static void l_error(LzUsrContext *u, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); exit(1);
}
static void l_warn(LzUsrContext *u, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); exit(1);
}
static void l_info(LzUsrContext *u, const char *fmt, ...) { (void)u; (void)fmt; }
static void *l_malloc(LzUsrContext *u, int size) { (void)u; return malloc(size); }
static void l_free(LzUsrContext *u, void *p) { (void)u; free(p); }
static int l_more_space(LzUsrContext *u, uint8_t **io_ptr) { (void)u; (void)io_ptr; return 0; }
static int l_more_lines(LzUsrContext *u, uint8_t **lines)
{
    (void)u; (void)lines; exit(1);
}

static LzCtx lz_ctx;
static LzContext *lz;

static const char *type_name(LzImageType t);

/* ---- the palette every indexed window uses --------------------------- */

#define PALETTE_ENTS 256
static uint32_t palette_ents[PALETTE_ENTS];
static uint8_t palette_mem[sizeof(SpicePalette) + PALETTE_ENTS * sizeof(uint32_t)];

static SpicePalette *make_palette(void)
{
    SpicePalette *plt = (SpicePalette *)palette_mem;
    int i;
    for (i = 0; i < PALETTE_ENTS; i++) {
        /* An arbitrary but non-degenerate ramp, so a wrong index shows up as
         * a wrong colour rather than a near-miss. */
        palette_ents[i] = ((uint32_t)(i * 7 & 0xff) << 16)
                        | ((uint32_t)(i * 13 & 0xff) << 8)
                        | (uint32_t)(i * 29 & 0xff);
        plt->ents[i] = palette_ents[i];
    }
    plt->unique = 1;
    plt->num_ents = PALETTE_ENTS;
    return plt;
}

/* ---- source images --------------------------------------------------- */

static int bytes_per_pixel(LzImageType type)
{
    switch (type) {
    case LZ_IMAGE_TYPE_RGB16: return 2;
    case LZ_IMAGE_TYPE_RGB24: return 3;
    case LZ_IMAGE_TYPE_RGB32:
    case LZ_IMAGE_TYPE_RGBA:  return 4;
    default:                  return 1; /* palette: one index per byte-unit */
    }
}

static int pixels_per_byte(LzImageType type)
{
    switch (type) {
    case LZ_IMAGE_TYPE_PLT1_LE:
    case LZ_IMAGE_TYPE_PLT1_BE: return 8;
    case LZ_IMAGE_TYPE_PLT4_LE:
    case LZ_IMAGE_TYPE_PLT4_BE: return 2;
    default:                    return 1;
    }
}

static int is_plt(LzImageType type)
{
    return type >= LZ_IMAGE_TYPE_PLT1_LE && type <= LZ_IMAGE_TYPE_PLT8;
}

/* Build frame `n` of a window: a base pattern scrolled up by `n` rows with a
 * moving block painted over it, so consecutive frames share long runs. */
static void make_frame(uint8_t *buf, int stride, int w, int h, LzImageType type, int n)
{
    int x, y, c;
    int bpp = is_plt(type) ? 1 : bytes_per_pixel(type);
    int units = is_plt(type) ? stride : w;

    for (y = 0; y < h; y++) {
        for (x = 0; x < units; x++) {
            uint8_t *p = buf + (size_t)y * stride + (size_t)x * bpp;
            int sy = (y + n * 7) % h;
            for (c = 0; c < bpp; c++) {
                int v = ((sy / 5) * 23 + (x / 3) * 11 + c * 41) & 0xff;
                /* A block that moves with n, so not everything matches. */
                if (y >= n * 3 % h && y < (n * 3 % h) + 6 && x >= 4 && x < 20) {
                    v = (n * 37 + x * 5 + c) & 0xff;
                }
                p[c] = (uint8_t)v;
            }
        }
    }
    if (type == LZ_IMAGE_TYPE_RGB16) {
        for (y = 0; y < h; y++) {
            for (x = 0; x < w; x++) {
                buf[(size_t)y * stride + x * 2 + 1] &= 0x7f;
            }
        }
    }
}

/* ---- the expected BGRA buffer ---------------------------------------- */

/* Mirrors the COPY_COMP_PIXEL macros in `lz_decompress_tmpl.c`, which GLZ
 * shares verbatim. Certified against the C decoder below for every type the
 * C `lz_decode` accepts. */
static void expand(uint8_t *out, const uint8_t *src, int stride, int w, int h,
                   LzImageType type, const SpicePalette *plt)
{
    int x, y;
    size_t at = 0;
    int ppb = pixels_per_byte(type);
    int units = is_plt(type) ? stride : w;

    for (y = 0; y < h; y++) {
        for (x = 0; x < units; x++) {
            const uint8_t *p = src + (size_t)y * stride + (size_t)x * (is_plt(type) ? 1 : bytes_per_pixel(type));
            if (type == LZ_IMAGE_TYPE_RGB16) {
                uint8_t hi = p[1], lo = p[0];
                uint8_t g = ((hi << 6) | (lo >> 2)) & ~0x07;
                g |= g >> 5;
                out[at * 4 + 0] = (lo << 3) | ((lo >> 2) & 0x07);
                out[at * 4 + 1] = g;
                out[at * 4 + 2] = ((hi << 1) & ~0x07) | ((hi >> 4) & 0x07);
                out[at * 4 + 3] = 0;
                at++;
            } else if (type == LZ_IMAGE_TYPE_RGB24) {
                out[at * 4 + 0] = p[0];
                out[at * 4 + 1] = p[1];
                out[at * 4 + 2] = p[2];
                out[at * 4 + 3] = 0;
                at++;
            } else if (type == LZ_IMAGE_TYPE_RGB32) {
                out[at * 4 + 0] = p[0];
                out[at * 4 + 1] = p[1];
                out[at * 4 + 2] = p[2];
                out[at * 4 + 3] = 0;
                at++;
            } else if (type == LZ_IMAGE_TYPE_RGBA) {
                out[at * 4 + 0] = p[0];
                out[at * 4 + 1] = p[1];
                out[at * 4 + 2] = p[2];
                out[at * 4 + 3] = p[3];
                at++;
            } else { /* palette */
                int i;
                for (i = 0; i < ppb; i++) {
                    uint32_t rgb;
                    int idx;
                    switch (type) {
                    case LZ_IMAGE_TYPE_PLT8:    idx = p[0]; break;
                    case LZ_IMAGE_TYPE_PLT4_BE: idx = i == 0 ? (p[0] >> 4) : (p[0] & 0x0f); break;
                    case LZ_IMAGE_TYPE_PLT4_LE: idx = i == 0 ? (p[0] & 0x0f) : (p[0] >> 4); break;
                    case LZ_IMAGE_TYPE_PLT1_BE: idx = (p[0] >> (7 - i)) & 1; break;
                    default:                    idx = (p[0] >> i) & 1; break;
                    }
                    rgb = plt->ents[idx];
                    out[at * 4 + 0] = (uint8_t)rgb;
                    out[at * 4 + 1] = (uint8_t)(rgb >> 8);
                    out[at * 4 + 2] = (uint8_t)(rgb >> 16);
                    out[at * 4 + 3] = 0;
                    at++;
                }
            }
        }
    }
}

/* Encode `src` with LZ and decode it with the C decoder, asserting the result
 * is `want`. This is what makes `expand` trustworthy rather than merely
 * plausible. */
static void certify(const uint8_t *src, const uint8_t *want, int stride, int w, int h,
                    LzImageType type)
{
    uint8_t *got;
    int bytes, dw, dh, dpx, dtd;
    LzImageType dtype;
    size_t pixels = (size_t)w * h;

    if (is_plt(type)) {
        return; /* the C lz_decode refuses palette output; see README.md */
    }

    got = calloc(pixels, 4);
    bytes = lz_encode(lz, type, w, h, 1, (uint8_t *)src, h, stride,
                      lz_io_buf, MAX_BYTES);
    if (bytes <= 0) {
        fprintf(stderr, "certify: lz_encode failed\n");
        exit(1);
    }
    lz_decode_begin(lz, lz_io_buf, bytes, &dtype, &dw, &dh, &dpx, &dtd, NULL);
    lz_decode(lz,
              (type == LZ_IMAGE_TYPE_RGB24 || type == LZ_IMAGE_TYPE_RGB16)
                  ? LZ_IMAGE_TYPE_RGB32 : type,
              got);

    if (memcmp(got, want, pixels * 4) != 0) {
        size_t i;
        for (i = 0; i < pixels * 4; i++) {
            if (got[i] != want[i]) {
                break;
            }
        }
        fprintf(stderr, "certify: type %s %dx%d: byte %zu (pixel %zu, chan %zu): "
                        "C gives %02x, expand gives %02x\n",
                type_name(type), w, h, i, i / 4, i % 4, got[i], want[i]);
        exit(1);
    }
    free(got);
}

/* ---- output ---------------------------------------------------------- */

static int first_case = 1;

static void print_hex(const char *key, const uint8_t *data, size_t len)
{
    size_t i;
    printf("  \"%s\": \"", key);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\"");
}

static uint64_t read_be64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

static const char *type_name(LzImageType t)
{
    switch (t) {
    case LZ_IMAGE_TYPE_PLT1_LE: return "plt1_le";
    case LZ_IMAGE_TYPE_PLT1_BE: return "plt1_be";
    case LZ_IMAGE_TYPE_PLT4_LE: return "plt4_le";
    case LZ_IMAGE_TYPE_PLT4_BE: return "plt4_be";
    case LZ_IMAGE_TYPE_PLT8:    return "plt8";
    case LZ_IMAGE_TYPE_RGB16:   return "rgb16";
    case LZ_IMAGE_TYPE_RGB24:   return "rgb24";
    case LZ_IMAGE_TYPE_RGB32:   return "rgb32";
    default:                    return "rgba";
    }
}

/* Encode one window: `frames` images through one dictionary. */
static void window(const char *name, LzImageType type, int w, int h, int frames,
                   uint32_t dict_pixels)
{
    GlzEncDictContext *dict;
    GlzEncoderContext *enc;
    SpicePalette *plt = make_palette();
    int ppb = pixels_per_byte(type);
    int stride = is_plt(type) ? (w + ppb - 1) / ppb : w * bytes_per_pixel(type);
    size_t gross = is_plt(type) ? (size_t)stride * ppb * h : (size_t)w * h;
    uint8_t **sources = calloc(frames, sizeof(uint8_t *));
    int n;

    dict = glz_enc_dictionary_create(dict_pixels, 1, &glz_usr);
    enc = glz_encoder_create(0, dict, &glz_usr);
    if (!dict || !enc) {
        fprintf(stderr, "glz create failed\n");
        exit(1);
    }

    for (n = 0; n < frames; n++) {
        GlzEncDictImageContext *dict_ctx = NULL;
        uint8_t *src = malloc((size_t)stride * h);
        uint8_t *want = calloc(gross, 4);
        int bytes;
        uint64_t id;

        sources[n] = src;
        make_frame(src, stride, w, h, type, n);
        expand(want, src, stride, w, h, type, plt);
        certify(src, want, stride, w, h, type);

        bytes = glz_encode(enc, type, w, h, 1 /* top_down */, src, h, stride,
                           io_buf, MAX_BYTES, (GlzUsrImageContext *)src, &dict_ctx);
        if (bytes <= 0) {
            fprintf(stderr, "glz_encode failed\n");
            exit(1);
        }

        /* magic(4) version(4) type(1) width(4) height(4) stride(4) -> id */
        id = read_be64(io_buf + 21);

        if (!first_case) {
            printf(",\n");
        }
        first_case = 0;
        printf(" {\n");
        printf("  \"codec\": \"glz\",\n");
        printf("  \"window\": \"%s\",\n", name);
        printf("  \"name\": \"%s-%d\",\n", name, n);
        printf("  \"image_type\": \"%s\",\n", type_name(type));
        printf("  \"width\": %d,\n", w);
        printf("  \"height\": %d,\n", h);
        printf("  \"pattern\": \"scroll\",\n");
        printf("  \"top_down\": true,\n");
        printf("  \"id\": %llu,\n", (unsigned long long)id);
        if (is_plt(type)) {
            int i;
            printf("  \"palette\": [");
            for (i = 0; i < PALETTE_ENTS; i++) {
                printf("%s%u", i ? "," : "", palette_ents[i]);
            }
            printf("],\n");
        }
        print_hex("compressed", io_buf, (size_t)bytes);
        printf(",\n");
        /* Only the first `width` pixels of each row survive cropping, which
         * is what the Rust decoder returns. */
        {
            uint8_t *cropped = malloc((size_t)w * h * 4);
            int y;
            int row_pixels = is_plt(type) ? stride * ppb : w;
            for (y = 0; y < h; y++) {
                memcpy(cropped + (size_t)y * w * 4,
                       want + (size_t)y * row_pixels * 4, (size_t)w * 4);
            }
            print_hex("decoded", cropped, (size_t)w * h * 4);
            free(cropped);
        }
        printf("\n }");
        free(want);
    }

    glz_encoder_destroy(enc);
    glz_enc_dictionary_destroy(dict, &glz_usr);
    for (n = 0; n < frames; n++) {
        free(sources[n]);
    }
    free(sources);
}

int main(void)
{
    io_buf = malloc(MAX_BYTES);
    lz_io_buf = malloc(MAX_BYTES);

    glz_usr.error = g_error_cb;
    glz_usr.warn = g_warn_cb;
    glz_usr.info = g_info_cb;
    glz_usr.malloc = g_malloc_cb;
    glz_usr.free = g_free_cb;
    glz_usr.more_lines = g_more_lines;
    glz_usr.more_space = g_more_space;
    glz_usr.free_image = g_free_image;

    memset(&lz_ctx, 0, sizeof(lz_ctx));
    lz_ctx.usr.error = l_error;
    lz_ctx.usr.warn = l_warn;
    lz_ctx.usr.info = l_info;
    lz_ctx.usr.malloc = l_malloc;
    lz_ctx.usr.free = l_free;
    lz_ctx.usr.more_space = l_more_space;
    lz_ctx.usr.more_lines = l_more_lines;
    lz = lz_create(&lz_ctx.usr);

    printf("[\n");

    /* A roomy dictionary: every frame stays in the window, so matches reach
     * back as far as the encoder likes. */
    window("rgb32-scroll", LZ_IMAGE_TYPE_RGB32, 120, 80, 8, 1 << 20);
    window("rgb24-scroll", LZ_IMAGE_TYPE_RGB24, 97, 61, 6, 1 << 20);
    window("rgb16-scroll", LZ_IMAGE_TYPE_RGB16, 100, 70, 6, 1 << 20);
    window("rgba-scroll", LZ_IMAGE_TYPE_RGBA, 80, 50, 6, 1 << 20);
    window("plt8-scroll", LZ_IMAGE_TYPE_PLT8, 96, 48, 5, 1 << 20);
    window("plt4le-scroll", LZ_IMAGE_TYPE_PLT4_LE, 94, 40, 5, 1 << 20);
    window("plt4be-scroll", LZ_IMAGE_TYPE_PLT4_BE, 94, 40, 5, 1 << 20);
    window("plt1le-scroll", LZ_IMAGE_TYPE_PLT1_LE, 93, 32, 5, 1 << 20);
    window("plt1be-scroll", LZ_IMAGE_TYPE_PLT1_BE, 93, 32, 5, 1 << 20);

    /* A dictionary too small to hold the whole sequence, so images are
     * evicted and `win_head_dist` stops being zero. This is the case that
     * exercises the window's release path rather than just its lookups. */
    window("rgb32-evicting", LZ_IMAGE_TYPE_RGB32, 120, 80, 10, 20000);

    /* Tall and narrow, so a cross-image match can start at a large pixel
     * offset and reach the three- and four-byte offset encodings. */
    window("rgb32-tall", LZ_IMAGE_TYPE_RGB32, 40, 400, 6, 1 << 20);

    printf("\n]\n");

    lz_destroy(lz);
    return 0;
}
