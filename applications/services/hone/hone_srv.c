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
#include <furi_hal_adc.h>
#include <storage/storage.h>
#include <string.h>

#include <nfc/nfc.h>
#include <nfc/nfc_scanner.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller_sync.h>
#include <lfrfid/lfrfid_worker.h>
#include <lfrfid/protocols/lfrfid_protocols.h>
#include <toolbox/protocols/protocol_dict.h>
#include <ibutton/ibutton_worker.h>
#include <ibutton/ibutton_protocols.h>
#include <infrared_worker.h>
#include <mbedtls/sha256.h>

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

/* ─── tag sensors: wait on a library callback for up to one slot window ─── */

typedef struct {
    FuriSemaphore* done;
    volatile bool hit;
    uint32_t id;            /* protocol id (RFID/NFC) */
    HoneBodyIr ir;
} HoneWait;

static bool wait_slot(HoneWait* w) {
    return furi_semaphore_acquire(w->done, furi_ms_to_ticks(HONE_SLOT_MS)) == FuriStatusOk;
}

static void signal_once(HoneWait* w) {
    if(!w->hit) {
        w->hit = true;
        furi_semaphore_release(w->done);
    }
}

/* id_hash = sha256(pk || "hone-tag" || type || protocol || raw)[0..16] */
static void tag_hash(
    const HoneSrv* s,
    uint8_t type,
    uint8_t protocol,
    const uint8_t* raw,
    size_t len,
    uint8_t out[16]) {
    mbedtls_sha256_context c;
    uint8_t d[32];
    mbedtls_sha256_init(&c);
    mbedtls_sha256_starts(&c, 0);
    mbedtls_sha256_update(&c, s->pk, 32);
    mbedtls_sha256_update(&c, (const uint8_t*)"hone-tag", 8);
    mbedtls_sha256_update(&c, &type, 1);
    mbedtls_sha256_update(&c, &protocol, 1);
    mbedtls_sha256_update(&c, raw, len);
    mbedtls_sha256_finish(&c, d);
    mbedtls_sha256_free(&c);
    memcpy(out, d, 16);
}

static void nfc_scan_cb(NfcScannerEvent event, void* ctx) {
    HoneWait* w = ctx;
    if(event.type == NfcScannerEventTypeDetected && event.data.protocol_num > 0) {
        w->id = event.data.protocols[0];
        signal_once(w);
    }
}

static bool capture_nfc(HoneSrv* s, HoneBodyTag* out) {
    HoneWait w = {.done = furi_semaphore_alloc(1, 0)};
    Nfc* nfc = nfc_alloc();
    NfcScanner* sc = nfc_scanner_alloc(nfc);
    nfc_scanner_start(sc, nfc_scan_cb, &w);
    bool got = wait_slot(&w);
    nfc_scanner_stop(sc);
    nfc_scanner_free(sc);

    if(got) {
        memset(out, 0, sizeof(*out));
        out->protocol = (uint8_t)w.id;
        /* UID for the ISO14443-3A family (MIFARE, NTAG, most bank/transit cards). */
        if(w.id == NfcProtocolIso14443_3a || nfc_protocol_has_parent(w.id, NfcProtocolIso14443_3a)) {
            Iso14443_3aData d = {0};
            if(iso14443_3a_poller_sync_read(nfc, &d) == Iso14443_3aErrorNone && d.uid_len) {
                out->id_len = d.uid_len;
                tag_hash(s, HoneMsgNfc, out->protocol, d.uid, d.uid_len, out->id_hash);
                out->extra[0] = d.atqa[0];
                out->extra[1] = d.atqa[1];
                out->extra[2] = d.sak;
            }
        }
    }
    nfc_free(nfc); /* releases the NFC chip */
    furi_semaphore_free(w.done);
    return got;
}

static void rfid_cb(LFRFIDWorkerReadResult result, ProtocolId protocol, void* ctx) {
    HoneWait* w = ctx;
    if(result == LFRFIDWorkerReadDone) {
        w->id = protocol;
        signal_once(w);
    }
}

static bool capture_rfid(HoneSrv* s, HoneBodyTag* out) {
    HoneWait w = {.done = furi_semaphore_alloc(1, 0)};
    ProtocolDict* dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
    LFRFIDWorker* worker = lfrfid_worker_alloc(dict);
    lfrfid_worker_start_thread(worker);
    lfrfid_worker_read_start(worker, LFRFIDWorkerReadTypeAuto, rfid_cb, &w);
    bool got = wait_slot(&w);
    lfrfid_worker_stop(worker);
    lfrfid_worker_stop_thread(worker);

    if(got) {
        uint8_t raw[32];
        size_t n = protocol_dict_get_data_size(dict, w.id);
        if(n > sizeof(raw)) n = sizeof(raw);
        protocol_dict_get_data(dict, w.id, raw, n);
        memset(out, 0, sizeof(*out));
        out->protocol = (uint8_t)w.id;
        out->id_len = (uint8_t)n;
        tag_hash(s, HoneMsgRfid, out->protocol, raw, n, out->id_hash);
    }
    lfrfid_worker_free(worker);
    protocol_dict_free(dict);
    furi_semaphore_free(w.done);
    return got;
}

static void ibutton_cb(void* ctx) {
    signal_once(ctx);
}

static bool capture_ibutton(HoneSrv* s, HoneBodyTag* out) {
    HoneWait w = {.done = furi_semaphore_alloc(1, 0)};
    iButtonProtocols* protocols = ibutton_protocols_alloc();
    iButtonKey* key = ibutton_key_alloc(ibutton_protocols_get_max_data_size(protocols));
    iButtonWorker* worker = ibutton_worker_alloc(protocols);
    ibutton_worker_start_thread(worker);
    ibutton_worker_read_set_callback(worker, ibutton_cb, &w);
    ibutton_worker_read_start(worker, key);
    bool got = wait_slot(&w);
    ibutton_worker_stop(worker);
    ibutton_worker_stop_thread(worker);

    if(got) {
        iButtonEditableData ed;
        ibutton_protocols_get_editable_data(protocols, key, &ed);
        memset(out, 0, sizeof(*out));
        out->protocol = (uint8_t)ibutton_key_get_protocol_id(key);
        out->id_len = (uint8_t)MIN(ed.size, 255u);
        tag_hash(s, HoneMsgIButton, out->protocol, ed.ptr, ed.size, out->id_hash);
    }
    ibutton_worker_free(worker);
    ibutton_key_free(key);
    ibutton_protocols_free(protocols);
    furi_semaphore_free(w.done);
    return got;
}

static void ir_cb(void* ctx, InfraredWorkerSignal* sig) {
    HoneWait* w = ctx;
    if(w->hit) return;
    memset(&w->ir, 0, sizeof(w->ir));
    if(infrared_worker_signal_is_decoded(sig)) {
        const InfraredMessage* m = infrared_worker_get_decoded_signal(sig);
        w->ir.protocol = (int8_t)m->protocol;
        w->ir.address = m->address;
        w->ir.command = m->command;
        w->ir.repeat = m->repeat;
    } else {
        const uint32_t* t;
        size_t n;
        infrared_worker_get_raw_signal(sig, &t, &n);
        w->ir.protocol = -1;
        w->ir.raw_timings = (uint16_t)MIN(n, 0xFFFFu);
    }
    signal_once(w);
}

static bool capture_ir(HoneBodyIr* out) {
    HoneWait w = {.done = furi_semaphore_alloc(1, 0)};
    InfraredWorker* worker = infrared_worker_alloc();
    infrared_worker_rx_enable_signal_decoding(worker, true);
    infrared_worker_rx_enable_blink_on_receiving(worker, false);
    infrared_worker_rx_set_received_signal_callback(worker, ir_cb, &w);
    infrared_worker_rx_start(worker);
    bool got = wait_slot(&w);
    infrared_worker_rx_stop(worker);
    infrared_worker_free(worker);
    if(got) *out = w.ir;
    furi_semaphore_free(w.done);
    return got;
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
            .battery_mv = (uint16_t)(furi_hal_power_get_battery_voltage(FuriHalPowerICFuelGauge) * 1000),
            .battery_ma = (int16_t)(furi_hal_power_get_battery_current(FuriHalPowerICFuelGauge) * 1000),
            .battery_c = (int8_t)furi_hal_power_get_battery_temperature(FuriHalPowerICFuelGauge),
        };
        strncpy(b.fw, HONE_FW_VERSION, sizeof(b.fw));
        FuriHalAdcHandle* adc = furi_hal_adc_acquire();
        furi_hal_adc_configure(adc);
        b.mcu_c10 = (int16_t)(furi_hal_adc_convert_temp(
                                  adc, furi_hal_adc_read(adc, FuriHalAdcChannelTEMPSENSOR)) * 10);
        furi_hal_adc_release(adc);
        emit(s, HoneMsgHeartbeat, &b, sizeof(b));
        FURI_LOG_I(TAG, "heartbeat batt %u frames %lu", b.battery_pct, b.total_frames);
        return true;
    }
    case HoneSensorNfc:
    case HoneSensorRfid:
    case HoneSensorIButton: {
        HoneBodyTag b;
        bool got = k == HoneSensorNfc  ? capture_nfc(s, &b) :
                   k == HoneSensorRfid ? capture_rfid(s, &b) :
                                         capture_ibutton(s, &b);
        if(!got) return false;
        HoneMsgType t = k == HoneSensorNfc ? HoneMsgNfc : k == HoneSensorRfid ? HoneMsgRfid : HoneMsgIButton;
        emit(s, t, &b, sizeof(b));
        FURI_LOG_I(TAG, "tag type %d proto %u idlen %u", t, b.protocol, b.id_len);
        return true;
    }
    case HoneSensorIr: {
        HoneBodyIr b;
        if(!capture_ir(&b)) return false;
        emit(s, HoneMsgIr, &b, sizeof(b));
        FURI_LOG_I(TAG, "ir proto %d addr %lx cmd %lx", b.protocol, b.address, b.command);
        return true;
    }
    default:
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
