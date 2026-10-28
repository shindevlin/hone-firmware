/*
 * hone_srv.c — HONE sensor service (firmware-resident, starts at boot)
 *
 * HONE is the only owner of the Flipper's sensors. This service runs on its own
 * thread with its own stack and rotates through the sensors in timed slots.
 * Each slot: power the sensor up, capture for a window, power it fully down,
 * THEN sign and queue. A radio is never held while signing, and only one
 * sensor is ever powered at a time. No timer callbacks do work.
 *
 * Maintenance mode: if /ext/apps_data/hone/maintenance exists, the service
 * idles and touches no sensor until the file is removed.
 *
 * Shin Devlin — honemesh.network
 */
#include "hone_frame.h"
#include "hone_scheduler.h"
#include "crypto/ed25519.h"

#include <furi.h>
#include <furi_hal_subghz.h>
#include <furi_hal_power.h>
#include <storage/storage.h>
#include <string.h>

#define TAG "HoneSrv"
#define HONE_FW_VERSION "2.0.0"

#define HONE_DIR         EXT_PATH("apps_data/hone")
#define HONE_KEY_PATH    HONE_DIR "/identity.key"
#define HONE_PUB_PATH    HONE_DIR "/identity.pub"
#define HONE_CTR_PATH    HONE_DIR "/counter.bin"
#define HONE_ANCHOR_PATH HONE_DIR "/anchor.bin"
#define HONE_QUEUE_PATH  HONE_DIR "/queue.bin"
#define HONE_QUEUE_OLD   HONE_DIR "/queue.old"
#define HONE_MAINT_PATH  HONE_DIR "/maintenance"

#define HONE_CTR_RESERVE  1000u          /* counter block persisted ahead */
#define HONE_QUEUE_MAX    (1024u * 1024u) /* rotate queue at 1 MB */
#define HONE_SLOT_MS      2000u          /* capture window per slot */
#define HONE_RSSI_GAP_MS  50u            /* RSSI sample spacing inside window */

/* Sub-GHz observation frequencies, one per Sub-GHz slot in rotation.
 * Receive only, so region does not apply (region limits TX, checked at TX). */
static const uint32_t hone_subghz_freqs[] = {433920000UL, 315000000UL, 915000000UL, 868350000UL};

typedef struct {
    Storage* storage;
    uint8_t pk[32];
    uint8_t sk[64];
    uint32_t counter;      /* next counter value to use */
    uint32_t counter_ceil; /* persisted reservation ceiling */
    uint8_t anchor[HONE_ANCHOR_LEN];
    uint32_t total_frames;
    HoneScheduler sched;
    uint8_t frame[HONE_FRAME_MAX];
} HoneSrv;

/* ─── storage helpers ───────────────────────────────────────────────────── */

static bool read_file(Storage* st, const char* path, void* buf, size_t len) {
    File* f = storage_file_alloc(st);
    bool ok = storage_file_open(f, path, FSAM_READ, FSOM_OPEN_EXISTING) &&
              storage_file_read(f, buf, len) == len;
    storage_file_close(f);
    storage_file_free(f);
    return ok;
}

static bool write_file(Storage* st, const char* path, const void* buf, size_t len) {
    File* f = storage_file_alloc(st);
    bool ok = storage_file_open(f, path, FSAM_WRITE, FSOM_CREATE_ALWAYS) &&
              storage_file_write(f, buf, len) == len;
    storage_file_close(f);
    storage_file_free(f);
    return ok;
}

static void identity_load_or_create(HoneSrv* s) {
    if(read_file(s->storage, HONE_KEY_PATH, s->sk, 64) &&
       read_file(s->storage, HONE_PUB_PATH, s->pk, 32)) {
        return;
    }
    FURI_LOG_I(TAG, "no identity, generating ed25519 keypair");
    hone_ed25519_keypair(s->pk, s->sk);
    write_file(s->storage, HONE_KEY_PATH, s->sk, 64);
    write_file(s->storage, HONE_PUB_PATH, s->pk, 32);
}

/* Counter: persist a ceiling ahead of use so a crash/reboot can only skip
 * values, never reuse one. */
static void counter_load(HoneSrv* s) {
    uint32_t stored = 0;
    read_file(s->storage, HONE_CTR_PATH, &stored, sizeof(stored));
    s->counter = stored;
    s->counter_ceil = stored + HONE_CTR_RESERVE;
    write_file(s->storage, HONE_CTR_PATH, &s->counter_ceil, sizeof(s->counter_ceil));
}

static uint32_t counter_next(HoneSrv* s) {
    if(s->counter >= s->counter_ceil) {
        s->counter_ceil = s->counter + HONE_CTR_RESERVE;
        write_file(s->storage, HONE_CTR_PATH, &s->counter_ceil, sizeof(s->counter_ceil));
    }
    return s->counter++;
}

static void queue_append(HoneSrv* s, const uint8_t* frame, size_t len) {
    FileInfo fi;
    if(storage_common_stat(s->storage, HONE_QUEUE_PATH, &fi) == FSE_OK &&
       fi.size > HONE_QUEUE_MAX) {
        storage_common_remove(s->storage, HONE_QUEUE_OLD);
        storage_common_rename(s->storage, HONE_QUEUE_PATH, HONE_QUEUE_OLD);
    }
    File* f = storage_file_alloc(s->storage);
    if(storage_file_open(f, HONE_QUEUE_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
        uint8_t l = (uint8_t)len; /* frames are <= 128 bytes */
        storage_file_write(f, &l, 1);
        storage_file_write(f, frame, len);
    }
    storage_file_close(f);
    storage_file_free(f);
}

/* ─── sensors: each one acquires and fully releases its hardware ───────── */

static bool capture_subghz(HoneBodySubGhz* out) {
    static size_t next = 0;
    uint32_t freq = hone_subghz_freqs[next++ % COUNT_OF(hone_subghz_freqs)];
    if(!furi_hal_subghz_is_frequency_valid(freq)) return false;

    furi_hal_subghz_reset();
    furi_hal_subghz_idle();
    furi_hal_subghz_set_frequency_and_path(freq);
    furi_hal_subghz_flush_rx();
    furi_hal_subghz_rx();
    furi_delay_ms(3);

    float peak = -200.0f, sum = 0.0f;
    uint16_t n = 0;
    uint32_t start = furi_get_tick();
    while(furi_get_tick() - start < furi_ms_to_ticks(HONE_SLOT_MS)) {
        float r = furi_hal_subghz_get_rssi();
        if(r > peak) peak = r;
        sum += r;
        n++;
        furi_delay_ms(HONE_RSSI_GAP_MS);
    }

    furi_hal_subghz_idle();
    furi_hal_subghz_sleep(); /* fully released before any signing */

    if(!n) return false;
    out->freq_hz = freq;
    out->rssi_peak_dbm = (int8_t)CLAMP(peak, 0.0f, -128.0f);
    out->rssi_avg_dbm = (int8_t)CLAMP(sum / n, 0.0f, -128.0f);
    out->samples = n;
    return true;
}

static void emit(HoneSrv* s, HoneMsgType type, const void* body, uint8_t body_len) {
    size_t len = hone_frame_build(
        s->frame, type, body, body_len, s->pk, s->sk, counter_next(s), s->anchor);
    if(!len) return;
    queue_append(s, s->frame, len);
    s->total_frames++;
}

/* Run one slot. Returns true if the sensor produced a reading. */
static bool run_slot(HoneSrv* s, HoneSensorKind k) {
    switch(k) {
    case HoneSensorSubGhz: {
        HoneBodySubGhz b;
        if(!capture_subghz(&b)) return false;
        emit(s, HoneMsgSubGhz, &b, sizeof(b));
        FURI_LOG_I(TAG, "subghz %lu peak %d avg %d", b.freq_hz, b.rssi_peak_dbm, b.rssi_avg_dbm);
        return true;
    }
    case HoneSensorHeartbeat: {
        HoneBodyHeartbeat b = {
            .battery_pct = furi_hal_power_get_pct(),
            .uptime_s = furi_get_tick() / furi_kernel_get_tick_frequency(),
            .total_frames = s->total_frames,
        };
        strncpy(b.fw, HONE_FW_VERSION, sizeof(b.fw));
        emit(s, HoneMsgHeartbeat, &b, sizeof(b));
        FURI_LOG_I(TAG, "heartbeat batt %u frames %lu", b.battery_pct, b.total_frames);
        return true;
    }
    case HoneSensorNfc:
    case HoneSensorRfid:
    case HoneSensorIButton:
    default:
        /* Not wired yet: report barren so the scheduler backs off. */
        return false;
    }
}

/* ─── service entry ─────────────────────────────────────────────────────── */

int32_t hone_srv(void* p) {
    UNUSED(p);
    HoneSrv* s = malloc(sizeof(HoneSrv));
    memset(s, 0, sizeof(HoneSrv));
    s->storage = furi_record_open(RECORD_STORAGE);

    /* Wait for the SD card: identity, counter and queue all live there. */
    while(storage_sd_status(s->storage) != FSE_OK) {
        furi_delay_ms(1000);
    }
    storage_simply_mkdir(s->storage, HONE_DIR);

    identity_load_or_create(s);
    counter_load(s);
    read_file(s->storage, HONE_ANCHOR_PATH, s->anchor, HONE_ANCHOR_LEN);
    hone_sched_init(&s->sched);
    FURI_LOG_I(TAG, "started, counter %lu", s->counter);

    while(1) {
        if(storage_file_exists(s->storage, HONE_MAINT_PATH)) {
            furi_delay_ms(5000);
            continue;
        }
        hone_sched_set_battery(&s->sched, furi_hal_power_get_pct());
        HoneSensorKind k = hone_sched_next(&s->sched);
        hone_sched_report(&s->sched, k, run_slot(s, k));
        furi_delay_ms(hone_sched_cycle_delay_ms(&s->sched));
    }
    return 0;
}
