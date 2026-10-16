/*
 * mlc-probe -- the reference Moonlight client, driven headlessly, asserting.
 *
 * This is the conformance tool `docs/testing.md` §2.2 asks for: a driver that
 * links the real `moonlight-common-c` so that Solstice's host half is judged
 * by the code every Moonlight port actually runs, rather than by a client
 * written from the same notes as the server.
 *
 * It does the streaming half only. Pairing, `/serverinfo` and `/launch` are
 * mutual-TLS HTTP that moonlight-common-c does not implement -- those live in
 * each port's own app layer -- so the Rust harness
 * (`crates/solstice/tests/real_moonlight.rs`) performs them and hands the
 * negotiated parameters here. What this binary exercises is everything after
 * the launch: the encrypted RTSP handshake, the ENet control channel, the UDP
 * media binding, the video packetiser, the FEC geometry and the input path.
 *
 * Built with `LC_DEBUG` (which turns on FEC_VALIDATION_MODE and the LC_ASSERT
 * family) and `LC_DEBUG_RECORD_MODE` (pass-through recorder callbacks). See
 * `build.sh`, which is the only supported way to compile this.
 *
 * Output: a `PROBE ` prefixed line per interesting event on stdout, parsed by
 * the harness. Everything moonlight-common-c logs goes to stderr untouched,
 * because when this fails the log is the whole diagnosis.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <Limelight.h>

/* --------------------------------------------------------------- state -- */

static struct {
    unsigned int frames;         /* decode units handed to the renderer   */
    unsigned int idr_frames;     /* of those, key frames                  */
    unsigned long long bytes;    /* total elementary stream bytes         */
    unsigned int audio_samples;  /* Opus packets handed to the renderer   */
    unsigned int last_frame;     /* most recent frame number              */
    bool saw_sps, saw_pps;       /* codec configuration NALUs seen        */
    int video_format;            /* what setup() was told to decode       */
    int video_width, video_height, video_rate;
    int audio_channels, audio_rate, audio_frame_samples;
    bool started;                /* connectionStarted fired               */
    int terminated;              /* connectionTerminated errorCode, or 1  */
    bool was_terminated;
    int failed_stage, failed_code;
} probe;

static void emit(const char* format, ...) {
    va_list args;
    va_start(args, format);
    fputs("PROBE ", stdout);
    vprintf(format, args);
    fputc('\n', stdout);
    fflush(stdout);
    va_end(args);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* ----------------------------------------------------------- callbacks -- */

static int dr_setup(int videoFormat, int width, int height, int redrawRate,
                    void* context, int drFlags) {
    (void)context; (void)drFlags;
    probe.video_format = videoFormat;
    probe.video_width = width;
    probe.video_height = height;
    probe.video_rate = redrawRate;
    emit("video-setup format=0x%x width=%d height=%d rate=%d",
         videoFormat, width, height, redrawRate);
    return 0;
}

static void dr_start(void) { emit("video-start"); }
static void dr_stop(void) { emit("video-stop"); }
static void dr_cleanup(void) { emit("video-cleanup"); }

/*
 * The decode unit arrives reassembled, FEC-recovered and in Annex B order.
 * Reaching this callback at all means the packetiser, the FEC geometry and
 * the frame assembly agreed with the reference implementation; the recorder
 * callbacks installed by LC_DEBUG_RECORD_MODE have already written the bytes
 * out by the time we are called.
 */
static int dr_submit(PDECODE_UNIT du) {
    PLENTRY entry;

    probe.frames++;
    probe.last_frame = (unsigned int)du->frameNumber;
    probe.bytes += (unsigned long long)du->fullLength;
    if (du->frameType == FRAME_TYPE_IDR) {
        probe.idr_frames++;
    }

    for (entry = du->bufferList; entry != NULL; entry = entry->next) {
        if (entry->bufferType == BUFFER_TYPE_SPS) probe.saw_sps = true;
        if (entry->bufferType == BUFFER_TYPE_PPS) probe.saw_pps = true;
    }

    /* One line per frame is too much for a 60fps stream; sample it. */
    if (probe.frames <= 4 || probe.frames % 30 == 0) {
        emit("frame n=%u number=%d type=%s length=%d",
             probe.frames, du->frameNumber,
             du->frameType == FRAME_TYPE_IDR ? "idr" : "p", du->fullLength);
    }
    return DR_OK;
}

static int ar_init(int audioConfiguration, const POPUS_MULTISTREAM_CONFIGURATION opusConfig,
                   void* context, int arFlags) {
    (void)audioConfiguration; (void)context; (void)arFlags;
    probe.audio_channels = opusConfig->channelCount;
    probe.audio_rate = opusConfig->sampleRate;
    probe.audio_frame_samples = opusConfig->samplesPerFrame;
    emit("audio-setup channels=%d rate=%d streams=%d coupled=%d samples=%d",
         opusConfig->channelCount, opusConfig->sampleRate, opusConfig->streams,
         opusConfig->coupledStreams, opusConfig->samplesPerFrame);
    return 0;
}

static void ar_start(void) { emit("audio-start"); }
static void ar_stop(void) { emit("audio-stop"); }
static void ar_cleanup(void) { emit("audio-cleanup"); }

static void ar_sample(char* data, int length) {
    (void)data;
    probe.audio_samples++;
    if (probe.audio_samples <= 2 || probe.audio_samples % 100 == 0) {
        emit("audio n=%u length=%d", probe.audio_samples, length);
    }
}

static void cl_stage_starting(int stage) {
    emit("stage-starting %d %s", stage, LiGetStageName(stage));
}

static void cl_stage_complete(int stage) {
    emit("stage-complete %d %s", stage, LiGetStageName(stage));
}

static void cl_stage_failed(int stage, int errorCode) {
    probe.failed_stage = stage;
    probe.failed_code = errorCode;
    emit("stage-failed %d %s code=%d", stage, LiGetStageName(stage), errorCode);
}

static void cl_connection_started(void) {
    probe.started = true;
    emit("connected");
}

static void cl_connection_terminated(int errorCode) {
    probe.was_terminated = true;
    probe.terminated = errorCode;
    emit("terminated code=%d", errorCode);
}

static void cl_log(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    fflush(stderr);
    va_end(args);
}

static void cl_connection_status(int status) {
    emit("status %s", status == CONN_STATUS_POOR ? "poor" : "okay");
}

/* ------------------------------------------------------------ argument -- */

static const char* arg_value(int argc, char** argv, const char* name, const char* fallback) {
    int i;
    size_t len = strlen(name);
    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], name, len) == 0 && argv[i][len] == '=') {
            return argv[i] + len + 1;
        }
    }
    return fallback;
}

static int arg_int(int argc, char** argv, const char* name, int fallback) {
    const char* value = arg_value(argc, argv, name, NULL);
    return value != NULL ? (int)strtol(value, NULL, 0) : fallback;
}

/* Parse exactly `len` bytes of hex into `out`, returning false on anything else. */
static bool parse_hex(const char* hex, unsigned char* out, size_t len) {
    size_t i;
    if (hex == NULL || strlen(hex) != len * 2) {
        return false;
    }
    for (i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return false;
        }
        out[i] = (unsigned char)byte;
    }
    return true;
}

static void usage(void) {
    fputs(
        "usage: mlc-probe address=HOST rtspurl=URL rikey=HEX32 rikeyid=N [options]\n"
        "\n"
        "  appversion=STR     /serverinfo <appversion>   (default 7.1.431.-1)\n"
        "  gfeversion=STR     /serverinfo <GfeVersion>\n"
        "  codecsupport=N     ServerCodecModeSupport bitmask (default 1, H.264)\n"
        "  width= height= fps= bitrate=   stream configuration\n"
        "  packetsize=N       video packet size (default 1024)\n"
        "  frames=N           stop once N decode units have arrived (default 60)\n"
        "  timeout=N          give up after N seconds (default 30)\n"
        "  video=PATH         write the H.264 elementary stream here\n"
        "  audio=PATH         write the Opus stream here\n"
        "  input=0|1          send input events once connected (default 1)\n",
        stderr);
}

/* ---------------------------------------------------------------- main -- */

int main(int argc, char** argv) {
    STREAM_CONFIGURATION stream;
    SERVER_INFORMATION server;
    CONNECTION_LISTENER_CALLBACKS listener;
    DECODER_RENDERER_CALLBACKS video;
    AUDIO_RENDERER_CALLBACKS audio;
    const char* address;
    const char* rtsp_url;
    const char* video_path;
    const char* audio_path;
    unsigned char rikey[16];
    int want_frames, timeout_s, send_input;
    uint64_t deadline;
    int rc;

    setvbuf(stdout, NULL, _IOLBF, 0);

    address = arg_value(argc, argv, "address", NULL);
    rtsp_url = arg_value(argc, argv, "rtspurl", NULL);
    if (address == NULL || rtsp_url == NULL ||
        !parse_hex(arg_value(argc, argv, "rikey", NULL), rikey, sizeof(rikey))) {
        usage();
        return 2;
    }

    want_frames = arg_int(argc, argv, "frames", 60);
    timeout_s = arg_int(argc, argv, "timeout", 30);
    send_input = arg_int(argc, argv, "input", 1);
    video_path = arg_value(argc, argv, "video", NULL);
    audio_path = arg_value(argc, argv, "audio", NULL);

    LiInitializeStreamConfiguration(&stream);
    stream.width = arg_int(argc, argv, "width", 1280);
    stream.height = arg_int(argc, argv, "height", 720);
    stream.fps = arg_int(argc, argv, "fps", 60);
    stream.bitrate = arg_int(argc, argv, "bitrate", 10000);
    stream.packetSize = arg_int(argc, argv, "packetsize", 1024);
    /* LOCAL rather than AUTO: AUTO would cap packetSize for a non-RFC1918
       address, which would silently change what the host is being asked for. */
    stream.streamingRemotely = STREAM_CFG_LOCAL;
    stream.audioConfiguration = AUDIO_CONFIGURATION_STEREO;
    stream.supportedVideoFormats = VIDEO_FORMAT_H264;
    stream.colorSpace = COLORSPACE_REC_601;
    stream.colorRange = COLOR_RANGE_LIMITED;
    /* Everything the host is willing to encrypt, so the encrypted paths are
       the ones under test rather than a fallback. */
    stream.encryptionFlags = ENCFLG_ALL;
    memcpy(stream.remoteInputAesKey, rikey, sizeof(rikey));
    /* Moonlight derives the input IV from rikeyid the same way the host does:
       the big-endian rikeyid in the first four bytes, zeroes after. */
    memset(stream.remoteInputAesIv, 0, sizeof(stream.remoteInputAesIv));
    {
        int rikey_id = arg_int(argc, argv, "rikeyid", 0);
        stream.remoteInputAesIv[0] = (char)(rikey_id >> 24);
        stream.remoteInputAesIv[1] = (char)(rikey_id >> 16);
        stream.remoteInputAesIv[2] = (char)(rikey_id >> 8);
        stream.remoteInputAesIv[3] = (char)(rikey_id >> 0);
    }

    LiInitializeServerInformation(&server);
    server.address = address;
    server.serverInfoAppVersion = arg_value(argc, argv, "appversion", "7.1.431.-1");
    server.serverInfoGfeVersion = arg_value(argc, argv, "gfeversion", NULL);
    server.rtspSessionUrl = rtsp_url;
    server.serverCodecModeSupport = arg_int(argc, argv, "codecsupport", SCM_H264);

    LiInitializeVideoCallbacks(&video);
    video.setup = dr_setup;
    video.start = dr_start;
    video.stop = dr_stop;
    video.cleanup = dr_cleanup;
    video.submitDecodeUnit = dr_submit;
    /* No slicing and no reference-frame invalidation: this probe is judging
       the host's default path, not negotiating its way off it. */
    video.capabilities = CAPABILITY_DIRECT_SUBMIT;

    LiInitializeAudioCallbacks(&audio);
    audio.init = ar_init;
    audio.start = ar_start;
    audio.stop = ar_stop;
    audio.cleanup = ar_cleanup;
    audio.decodeAndPlaySample = ar_sample;
    audio.capabilities = CAPABILITY_DIRECT_SUBMIT;

    LiInitializeConnectionCallbacks(&listener);
    listener.stageStarting = cl_stage_starting;
    listener.stageComplete = cl_stage_complete;
    listener.stageFailed = cl_stage_failed;
    listener.connectionStarted = cl_connection_started;
    listener.connectionTerminated = cl_connection_terminated;
    listener.logMessage = cl_log;
    listener.connectionStatusUpdate = cl_connection_status;

    emit("starting address=%s rtsp=%s %dx%d@%d bitrate=%d",
         address, rtsp_url, stream.width, stream.height, stream.fps, stream.bitrate);

    /* With LC_DEBUG_RECORD_MODE the contexts are the recorder's file paths. */
    rc = LiStartConnection(&server, &stream, &listener, &video, &audio,
                           (void*)video_path, 0, (void*)audio_path, 0);
    if (rc != 0) {
        emit("start-failed rc=%d stage=%d code=%d", rc, probe.failed_stage, probe.failed_code);
        emit("result ok=0");
        return 1;
    }

    deadline = now_ms() + (uint64_t)timeout_s * 1000;
    while (probe.frames < (unsigned int)want_frames && !probe.was_terminated) {
        struct timespec nap = { 0, 20 * 1000 * 1000 };
        if (now_ms() >= deadline) {
            emit("timeout frames=%u", probe.frames);
            break;
        }
        nanosleep(&nap, NULL);

        /* Input rides the ENet control channel, which is the piece with no
           other real-peer coverage. Send a fixed script once the stream is
           up so the host side can assert on exactly what arrived. */
        if (send_input && probe.frames >= 2 && send_input != 2) {
            send_input = 2;
            LiSendMouseMoveEvent(40, 30);
            LiSendMousePositionEvent(100, 50, (short)stream.width, (short)stream.height);
            LiSendMouseButtonEvent(BUTTON_ACTION_PRESS, BUTTON_LEFT);
            LiSendMouseButtonEvent(BUTTON_ACTION_RELEASE, BUTTON_LEFT);
            LiSendKeyboardEvent(0x41 /* VK_A */, KEY_ACTION_DOWN, 0);
            LiSendKeyboardEvent(0x41 /* VK_A */, KEY_ACTION_UP, 0);
            LiSendScrollEvent(1);
            emit("input-sent");
        }
    }

    {
        uint32_t rtt = 0, variance = 0;
        if (LiGetEstimatedRttInfo(&rtt, &variance)) {
            emit("rtt ms=%u variance=%u", rtt, variance);
        }
    }

    emit("stopping");
    LiStopConnection();

    emit("summary frames=%u idr=%u bytes=%llu audio=%u sps=%d pps=%d last=%u terminated=%d",
         probe.frames, probe.idr_frames, probe.bytes, probe.audio_samples,
         (int)probe.saw_sps, (int)probe.saw_pps, probe.last_frame,
         probe.was_terminated ? probe.terminated : 0);

    /*
     * The bar for success. A client that connected but decoded nothing is the
     * exact failure this tool exists to catch, so frames are part of it.
     */
    if (!probe.started || probe.frames < (unsigned int)want_frames) {
        emit("result ok=0");
        return 1;
    }
    emit("result ok=1");
    return 0;
}
