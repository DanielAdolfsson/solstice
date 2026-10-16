/*
 * solstice-draw -- paint the guest's root window from the test harness.
 *
 * Two jobs.
 *
 * 1. `fill` is how every test paints a known colour. It exists instead of
 *    `xsetroot -solid` because of XSetCloseDownMode in finish_retained, which xsetroot
 *    does not reliably apply on this X server: without it the server frees
 *    the client's state on disconnect and the root reverts to black the
 *    instant the painting process exits, so the assertion that follows reads
 *    stale pixels and the test fails for a reason that has nothing to do
 *    with Solstice.
 *
 * 2. `stroke`, `text` and `rop3` drive the core-X11 primitives. They were
 *    written to force SPICE_MSG_DISPLAY_DRAW_STROKE, _DRAW_TEXT and
 *    _DRAW_ROP3 out of the QXL driver, and they do not: xf86-video-qxl
 *    accelerates only fills, copies, composites and uploads, so a line
 *    arrives as one DRAW_FILL per span and glyphs and the XOR stipple as
 *    DRAW_COPYs of the software-rendered result (docs/roadmap.md 2.7). They
 *    stay because that output is still a demanding thing to reproduce
 *    exactly, and the real-server tests hold it against QEMU's screendump.
 *    Deliberate and targeted -- x11perf would be a scattergun, and is not
 *    packaged for Alpine in any case.
 *
 * Built into the image by build-image.sh, in the guest's own toolchain.
 */
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static Display *dpy;
static Window   root;
static int      W, H;

/*
 * Retain this client's server-side state past exit, as fill needs; see the
 * comment above. RetainTemporary rather than RetainPermanent, and the
 * previous holder killed first, which is xsetroot's own arrangement: each
 * retained client counts against the X server's limit of 256 for good, so a
 * soak that painted a few hundred times ran out of clients and every later
 * XOpenDisplay failed with "Maximum number of clients reached".
 */
static void finish_retained(void)
{
    XKillClient(dpy, AllTemporary);
    XSetCloseDownMode(dpy, RetainTemporary);
    XSync(dpy, False);
    XCloseDisplay(dpy);
}

/* The other primitives leave pixels behind, not state: nothing to retain. */
static void finish(void)
{
    XSync(dpy, False);
    XCloseDisplay(dpy);
}

static int usage(void)
{
    fputs("usage: solstice-draw fill RRGGBB\n"
          "                     stroke [count]\n"
          "                     text [string]\n"
          "                     rop3 [count]\n", stderr);
    return 2;
}

int main(int argc, char **argv)
{
    if (argc < 2) return usage();

    /* guest-exec hands us no environment, so DISPLAY is normally unset;
       the guest only ever runs one X server and it is always :0. */
    const char *disp = getenv("DISPLAY");
    if (!disp || !*disp) disp = ":0";

    if (!(dpy = XOpenDisplay(disp))) {
        fprintf(stderr, "solstice-draw: cannot open display %s\n", disp);
        return 1;
    }
    int screen = DefaultScreen(dpy);
    root = RootWindow(dpy, screen);

    XWindowAttributes attr;
    XGetWindowAttributes(dpy, root, &attr);
    W = attr.width;
    H = attr.height;

    if (!strcmp(argv[1], "fill")) {
        if (argc < 3) return usage();
        unsigned long c = strtoul(argv[2], NULL, 16);
        XSetWindowBackground(dpy, root, c);
        XClearWindow(dpy, root);
        finish_retained();
        return 0;
    }

    GC gc = XCreateGC(dpy, root, 0, NULL);

    if (!strcmp(argv[1], "stroke")) {
        /* Thin diagonal lines: the driver's line path, not a filled rect. */
        int n = argc > 2 ? atoi(argv[2]) : 64;
        XSetLineAttributes(dpy, gc, 1, LineSolid, CapButt, JoinMiter);
        for (int i = 0; i < n; i++) {
            XSetForeground(dpy, gc, 0x00ff00u + (unsigned)i * 37u);
            XDrawLine(dpy, root, gc, 0, i * H / n, W - 1, H - 1 - i * H / n);
        }
    } else if (!strcmp(argv[1], "text")) {
        /* A *core* bitmap font, so this becomes DRAW_TEXT rather than a
           client-side-rendered glyph blit through RENDER. font-misc-misc
           supplies "fixed". */
        const char *msg = argc > 2 ? argv[2] : "solstice draw text";
        XFontStruct *fs = XLoadQueryFont(dpy, "fixed");
        if (!fs) { fputs("solstice-draw: no \"fixed\" core font\n", stderr); return 1; }
        XSetFont(dpy, gc, fs->fid);
        XSetForeground(dpy, gc, 0xffffffu);
        XSetBackground(dpy, gc, 0x000000u);
        for (int y = 20; y < H - 10; y += 40)
            XDrawImageString(dpy, root, gc, 20, y, msg, (int)strlen(msg));
    } else if (!strcmp(argv[1], "rop3")) {
        /* A non-GXcopy raster op against a stipple is what the QXL driver
           cannot express as a plain copy or fill, so it has to emit ROP3. */
        int n = argc > 2 ? atoi(argv[2]) : 16;
        static const char bits[] = { 0x05, 0x0a, 0x05, 0x0a, 0x05, 0x0a, 0x05, 0x0a };
        Pixmap stip = XCreateBitmapFromData(dpy, root, bits, 8, 8);
        XSetStipple(dpy, gc, stip);
        XSetFillStyle(dpy, gc, FillStippled);
        XSetFunction(dpy, gc, GXxor);
        for (int i = 0; i < n; i++) {
            XSetForeground(dpy, gc, 0x00336699u * (unsigned)(i + 1));
            XFillRectangle(dpy, root, gc, i * 8, i * 8, W - i * 16, H - i * 16);
        }
        XSetFunction(dpy, gc, GXcopy);
        XFreePixmap(dpy, stip);
    } else {
        return usage();
    }

    XFreeGC(dpy, gc);
    finish();
    return 0;
}
