/*
 * hone_srv.c — HONE sensor service (firmware-resident, starts at boot)
 *
 * HONE is the only owner of the Flipper's sensors. Three lanes, each its own
 * thread and stack:
 *   - Sub-GHz lane: continuous RSSI windows (SPI only, no timers)
 *   - Wi-Fi lane: dev board scans (separate MCU on USART), once a minute on
 *     battery and on USB: one AP scan + ~15 s probe listening (body v2)
 *   - BLE lane: passive scan window every minute (needs the full radio stack):
 *     crowd count as day-keyed oids, and sightings of other HONE devices
 *   - announce lane: signed HA announce + HC batch commits, and the rotating
 *     window-key advert ('hK') on its own addresses, rotating at UTC quarter-hours
 *   - tag lane (service thread): rotates NFC (+IR), iButton (+IR), RFID, IR,
 *     heartbeat. NFC and iButton both need TIM1 and RFID needs TIM1+TIM2, so
 *     only one of them runs at a time; IR receive (TIM2 only) rides along
 *     with NFC and iButton.
 * Signing + queueing is serialised by one mutex.
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
#include <furi_hal_rtc.h>
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
#include <furi_hal_serial.h>
#include <furi_hal_serial_control.h>
#include <expansion/expansion.h>
#include <furi_hal_bt.h>
#include <furi_hal_version.h>
#include <bt/bt_service/bt.h>
#include <gap_observer.h>
#include <furi_hal_random.h>
#include <furi_hal_crypto.h>
#include <datetime/datetime.h>
#include "crypto/tweetnacl.h"
#include "hone_status.h"
#include "hone_census.h"
#include <lib/subghz/receiver.h>
#include <toolbox/level_duration.h>
#include <lib/subghz/environment.h>
#include <lib/subghz/protocols/protocol_items.h>
#include <lib/subghz/devices/cc1101_configs.h>
#include <furi_hal_nfc.h>
#include <furi_hal_rfid.h>
#include <notification/notification_messages.h>
#include <loader/loader.h>
#include <gui/gui.h>
#include <stm32wbxx_ll_rcc.h>
#include <stdlib.h>

#define TAG "HoneSrv"
#define HONE_FW_VERSION "2.2.0"

#define HONE_DIR         EXT_PATH("apps_data/hone")
#define HONE_KEY_PATH    HONE_DIR "/identity.key"
#define HONE_PUB_PATH    HONE_DIR "/identity.pub"
#define HONE_CTR_PATH    HONE_DIR "/counter.bin"
#define HONE_ANCHOR_PATH HONE_DIR "/anchor.bin"
#define HONE_QUEUE_PATH  HONE_DIR "/queue.bin"
#define HONE_ARCHIVE_DIR HONE_DIR "/archive" /* rotated queues, never deleted */
#define HONE_MAINT_PATH  HONE_DIR "/maintenance"
#define HONE_OWNER_PATH  HONE_DIR "/owner.txt" /* chain account name, set at claim */
#define HONE_COMMIT_PATH HONE_DIR "/commits.bin" /* every signed batch commit, appended */
#define HONE_COMMIT_TIME HONE_DIR "/commits.time" /* u32 RTC per commits.bin record, same order */
/* Rotating-id seed (spec 1a). The owner's phone provisions it at claim time
 * (id_seed = HKDF(hide, "hone-id-seed" || device pubkey)), over USB or BLE RPC
 * storage write, as either
 *   id_seed.sealed  92 bytes: FindMy.provisionBlob = ECIES to the X25519 form of
 *                   this device's ed25519 key (epk 32 | nonce 12 | AES-GCM ct 32 + tag 16,
 *                   info "hone-seed-provision-v1"), preferred: the SD never holds it in clear
 *   id_seed         32 raw bytes (bench / USB)
 * Never logged or sent. Neither file = no id advert. Deleting it stops the advert. */
#define HONE_SEED_PATH   HONE_DIR "/id_seed"
#define HONE_SEALED_PATH HONE_DIR "/id_seed.sealed"
#define HONE_PROVISION_INFO "hone-seed-provision-v1"
/* The Flipper RTC keeps LOCAL time. Offset of local time from UTC, in minutes,
 * as text (e.g. "-360"). Missing file = HONE_UTC_OFFSET_DEFAULT. */
#define HONE_TZ_PATH     HONE_DIR "/utc_offset_min"
#define HONE_BOOT_LOG    HONE_DIR "/boot.log"  /* one line per boot: time, reset cause, downtime */
#define HONE_ALIVE_PATH  HONE_DIR "/alive.bin" /* u32 RTC, refreshed every minute */
/* capture log (v3 chain). chain.bin = HoneChainState, rewritten every
 * HONE_CHAIN_SAVE_EVERY frames and at each rotation; on boot the tail of
 * queue.bin after .offset is replayed, so the head is never lost.
 * heads.bin  = every signed chain head the Flipper broadcast (HoneHeadRec).
 * ack.bin    = u32 seq, written by a HONE phone once it has verified and stored
 *              every frame up to seq. Only archives fully <= ack may ever be
 *              deleted, and only when the SD runs low. */
#define HONE_CHAIN_PATH  HONE_DIR "/chain.bin"
#define HONE_HEADS_PATH  HONE_DIR "/heads.bin"
#define HONE_ACK_PATH    HONE_DIR "/ack.bin"
#define HONE_CHAIN_MAGIC 0x31484348u /* "HCH1" */
#define HONE_CHAIN_SAVE_EVERY 32u
#define HONE_SD_LOW_MB   128u /* below: delete the oldest delivered archive */
#define HONE_SD_ECON_MB  32u  /* below, nothing deletable: economy mode */
#define HONE_UTC_OFFSET_DEFAULT (-360) /* America/El_Salvador, UTC-6, no DST */

/* ─── batch commits ───────────────────────────────────────────────────────
 * Readings are grouped per enrolled sensor id (flipper-<devid>-<group>). Every
 * minute (or 60 readings) a group's frames are summed into batch_hash =
 * sha256(frame || frame || ...), and the Flipper signs the chain's
 * SENSOR_DATA_COMMIT canonical message with its own key. The signed commit is
 * broadcast over BLE ('HC'), so any HONE phone in range can submit it to the
 * chain from anywhere; the frames themselves stay in queue.bin as the evidence
 * batch_hash commits to. */
#define HONE_GROUPS        6
#define HONE_BATCH_MS      60000u
#define HONE_BATCH_MAX     60u
#define HONE_COMMIT_LEN    (8 + 1 + 2 + 32 + 64) /* devid, group, count, hash, sig */
#define HONE_COMMIT_SLOTS  8
#define HONE_COMMIT_TTL_MS (15u * 60u * 1000u)   /* re-broadcast each commit for 15 min */
/* Group index = commits.bin group byte = sensor id flipper-<devid>-<name>.
 * Append only: indices are on chain. */
static const char* const hone_group_name[HONE_GROUPS] =
    {"subghz", "wifi", "tags", "ir", "blecrowd", "sightings"};
static const char* const hone_group_type[HONE_GROUPS] =
    {"continuous", "continuous", "event", "event", "continuous", "event"};

typedef struct {
    mbedtls_sha256_context h;
    uint16_t count;
    uint32_t started;
} HoneBatch;

typedef struct {
    uint8_t data[HONE_COMMIT_LEN];
    uint32_t made; /* tick; 0 = empty slot */
    uint8_t seq;
} HoneCommit;

#define HONE_CTR_RESERVE  1000u          /* counter block persisted ahead */
#define HONE_QUEUE_MAX    (4u * 1024u * 1024u) /* rotate queue.bin into archive/ at 4 MB */
#define HONE_SLOT_MS      2000u          /* capture window per slot */
#define HONE_RSSI_GAP_MS  50u            /* RSSI sample spacing inside window */

/* Sub-GHz observation frequencies, one per Sub-GHz slot in rotation.
 * Receive only, so region does not apply (region limits TX, checked at TX). */
static const uint32_t hone_subghz_freqs[] = {433920000UL, 315000000UL, 915000000UL, 868350000UL};

typedef enum {
    HoneLaneTag,
    HoneLaneSubGhz,
    HoneLaneWifi,
    HoneLaneBle,
    HoneLaneAnnounce,
    HoneLaneCount,
} HoneLane;

struct HoneStatusRecord {
    FuriMutex* lock;
    HoneStatus st;
    volatile bool ui_open;
    volatile bool want_reprobe; /* screen opened: maybe a board was just plugged in */
};

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
    FuriMutex* emit_lock;   /* counter, frame buffer, queue file */
    volatile bool paused;   /* maintenance mode, refreshed by the tag lane */
    volatile bool ext_power;        /* last VBUS reading, taken with 5 V out off */
    volatile uint32_t wifi_ok_tick; /* last time the dev board answered */
    char owner[16];                 /* from owner.txt, NUL-padded */
    HoneBatch batch[HONE_GROUPS];   /* guarded by emit_lock */
    HoneCommit commits[HONE_COMMIT_SLOTS];
    uint8_t commit_next;
    uint8_t commit_seq;
    /* time */
    volatile int32_t utc_offset_min;
    /* rotating id (spec 1a). Seed guarded by seed_lock; never logged. */
    FuriMutex* seed_lock;
    uint8_t id_seed[32];
    volatile bool seed_ok;
    volatile uint32_t seed_gen; /* bumps on every seed change */
    /* per-day oid key (spec 1b): RAM only, replaced at UTC midnight */
    FuriMutex* kday_lock;
    uint8_t k_day[32];
    uint32_t k_day_day; /* floor(utc / 86400) it belongs to; 0 = unset */
    volatile bool observer_ok;
    volatile bool beacon_hold; /* BLE lane asks the announce lane to free the radio slot */
    volatile bool beacon_held;
    /* Another app is starting or running: every lane releases its hardware
     * (radios, timers, USART, 5 V, BLE stack calls) until the loader says it
     * stopped. Set from the loader's pubsub, which waits for busy[] to clear. */
    volatile bool app_hold;
    volatile uint32_t hold_tick;
    volatile bool busy[HoneLaneCount];
    FuriMutex* otg_lock; /* Wi-Fi board power vs the iButton reader's 5 V request */
    /* TIM2 is shared by Sub-GHz async RX (decoding), IR and 125 kHz RFID:
     * the tag lane holds it for its slots, the Sub-GHz lane only tries. */
    FuriMutex* tim_lock;
    HoneStatusRecord rec;
    /* capture log chain (guarded by emit_lock) */
    uint8_t chain_head[32]; /* sha256 of the newest queued frame */
    uint32_t chain_seq;     /* its counter */
    uint32_t queue_first;   /* counter of the first frame in queue.bin */
    uint32_t chain_unsaved;
    volatile bool economy;  /* SD nearly full of undelivered data */
    /* where are we: fingerprint of the strongest Wi-Fi APs (oids), 0 = unknown */
    volatile uint32_t loc_fp;
    /* Wi-Fi dev board: seen at the last probe; re-probe request (USB power came,
     * or the Hone screen was opened) */
    volatile bool wifi_board;
    volatile bool wifi_reprobe;
    /* main loop launches the Hone screen for an alert */
    volatile bool want_screen;
    NotificationApp* notif;
} HoneSrv;

/* chain.bin */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t seq;         /* counter of the newest frame folded into head */
    uint32_t queue_first; /* counter of the first frame in queue.bin */
    uint32_t offset;      /* queue.bin size when saved */
    uint8_t head[32];
} HoneChainState;

/* heads.bin record; the 'HH' beacon carries devid | seq | rtc | head16 | sig */
typedef struct __attribute__((packed)) {
    uint32_t seq;
    uint32_t rtc;
    uint8_t head[16];
    uint8_t sig[64]; /* ed25519 over "HH1" | devid8 | seq | rtc | head16 */
} HoneHeadRec;

_Static_assert(sizeof(HoneBodyBleCrowd) == 29, "crowd body");
_Static_assert(sizeof(HoneSighting) == 20, "sighting entry");
_Static_assert(sizeof(HoneBodySighting) <= HONE_MAX_BODY, "sighting body");
_Static_assert(sizeof(HoneBodyWifi2) == 102 && sizeof(HoneBodyWifi2) <= HONE_MAX_BODY, "wifi2 body");

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

static void hex_into(char* out, const uint8_t* in, size_t n) {
    static const char hx[] = "0123456789abcdef";
    for(size_t i = 0; i < n; i++) {
        out[2 * i] = hx[in[i] >> 4];
        out[2 * i + 1] = hx[in[i] & 15];
    }
    out[2 * n] = 0;
}

/* ─── time, HMAC, keys ─────────────────────────────────────────────────── */

static uint32_t utc_now(const HoneSrv* s) {
    int64_t t = (int64_t)furi_hal_rtc_get_timestamp() - (int64_t)s->utc_offset_min * 60;
    return t > 0 ? (uint32_t)t : 0;
}

static void tz_load(HoneSrv* s) {
    char buf[12] = {0};
    File* f = storage_file_alloc(s->storage);
    int32_t off = HONE_UTC_OFFSET_DEFAULT;
    if(storage_file_open(f, HONE_TZ_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        size_t n = storage_file_read(f, buf, sizeof(buf) - 1);
        buf[n] = 0;
        char* end;
        long v = strtol(buf, &end, 10);
        if(end != buf && v >= -14 * 60 && v <= 14 * 60) off = (int32_t)v;
    }
    storage_file_close(f);
    storage_file_free(f);
    if(off != s->utc_offset_min) {
        s->utc_offset_min = off;
        FURI_LOG_I(TAG, "utc offset %ld min", (long)off);
    }
}

static void hmac_sha256(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* a,
    size_t a_len,
    const uint8_t* b,
    size_t b_len,
    uint8_t out[32]) {
    uint8_t k[64] = {0}, pad[64], inner[32];
    mbedtls_sha256_context c;
    if(key_len > 64) {
        mbedtls_sha256(key, key_len, k, 0);
    } else {
        memcpy(k, key, key_len);
    }
    for(int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    mbedtls_sha256_init(&c);
    mbedtls_sha256_starts(&c, 0);
    mbedtls_sha256_update(&c, pad, 64);
    if(a_len) mbedtls_sha256_update(&c, a, a_len);
    if(b_len) mbedtls_sha256_update(&c, b, b_len);
    mbedtls_sha256_finish(&c, inner);
    for(int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    mbedtls_sha256_starts(&c, 0);
    mbedtls_sha256_update(&c, pad, 64);
    mbedtls_sha256_update(&c, inner, 32);
    mbedtls_sha256_finish(&c, out);
    mbedtls_sha256_free(&c);
    memset(k, 0, sizeof(k));
    memset(pad, 0, sizeof(pad));
    memset(inner, 0, sizeof(inner));
}

/* RFC 5869 HKDF-SHA256, empty salt = 32 zero bytes (same as Android IdKeys.hkdf). */
static void hkdf_sha256(
    const uint8_t* ikm,
    size_t ikm_len,
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* info_a,
    size_t a_len,
    const uint8_t* info_b,
    size_t b_len,
    uint8_t* out,
    size_t out_len) {
    static const uint8_t zero[32] = {0};
    uint8_t prk[32], t[32 + 64 + 1], blk[32];
    if(!salt_len) {
        salt = zero;
        salt_len = 32;
    }
    hmac_sha256(salt, salt_len, ikm, ikm_len, NULL, 0, prk);
    size_t pos = 0, tl = 0;
    for(uint8_t i = 1; pos < out_len; i++) {
        /* T(i) = HMAC(prk, T(i-1) || info || i); info here is at most 64 bytes */
        size_t n = tl;
        memcpy(t + n, info_a, a_len);
        n += a_len;
        if(b_len) memcpy(t + n, info_b, b_len);
        n += b_len;
        t[n++] = i;
        hmac_sha256(prk, 32, t, n, NULL, 0, blk);
        size_t c = MIN((size_t)32, out_len - pos);
        memcpy(out + pos, blk, c);
        pos += c;
        memcpy(t, blk, 32);
        tl = 32;
    }
    memset(prk, 0, sizeof(prk));
    memset(t, 0, sizeof(t));
    memset(blk, 0, sizeof(blk));
}

/* Open FindMy.provisionBlob: X25519 with this device's key (SHA-512(ed seed)[0..32]),
 * key = HKDF(shared, salt = epk || pk_x, "hone-seed-provision-v1"), AES-256-GCM. */
static bool seed_unseal(const HoneSrv* s, const uint8_t blob[92], uint8_t seed[32]) {
    uint8_t h[64], skx[32], pkx[32], shared[32], salt[64], key[32];
    crypto_hash_sha512(h, s->sk, 32); /* TweetNaCl sk = seed(32) || pk(32) */
    memcpy(skx, h, 32);
    crypto_scalarmult_base(pkx, skx);
    crypto_scalarmult(shared, skx, blob);
    memcpy(salt, blob, 32);
    memcpy(salt + 32, pkx, 32);
    hkdf_sha256(
        shared, 32, salt, 64, (const uint8_t*)HONE_PROVISION_INFO,
        strlen(HONE_PROVISION_INFO), NULL, 0, key, 32);
    bool ok = furi_hal_crypto_gcm_decrypt_and_verify(
                  key, blob + 32, NULL, 0, blob + 44, seed, 32, blob + 76) ==
              FuriHalCryptoGCMStateOk;
    memset(h, 0, sizeof(h));
    memset(skx, 0, sizeof(skx));
    memset(shared, 0, sizeof(shared));
    memset(key, 0, sizeof(key));
    if(!ok) memset(seed, 0, 32);
    return ok;
}

/* Load or drop the id seed. Called every few seconds; touches RAM only on change. */
static void seed_load(HoneSrv* s) {
    uint8_t buf[32], blob[92];
    bool ok = false;
    FileInfo fi;
    if(storage_common_stat(s->storage, HONE_SEALED_PATH, &fi) == FSE_OK && fi.size == 92 &&
       read_file(s->storage, HONE_SEALED_PATH, blob, 92)) {
        /* unseal only when the blob changed: X25519 twice costs a moment */
        static uint8_t last_blob_hash[32];
        static bool last_ok;
        uint8_t bh[32];
        mbedtls_sha256(blob, 92, bh, 0);
        bool same = memcmp(bh, last_blob_hash, 32) == 0;
        if(same && last_ok && s->seed_ok) return; /* same blob, seed already in RAM */
        if(!same) {
            ok = seed_unseal(s, blob, buf);
            if(!ok) FURI_LOG_W(TAG, "id: sealed seed does not open with this device key");
            memcpy(last_blob_hash, bh, 32);
            last_ok = ok;
        }
    }
    if(!ok && storage_common_stat(s->storage, HONE_SEED_PATH, &fi) == FSE_OK && fi.size == 32)
        ok = read_file(s->storage, HONE_SEED_PATH, buf, 32);
    furi_check(furi_mutex_acquire(s->seed_lock, FuriWaitForever) == FuriStatusOk);
    if(ok != s->seed_ok || (ok && memcmp(buf, s->id_seed, 32) != 0)) {
        if(ok) {
            memcpy(s->id_seed, buf, 32);
        } else {
            memset(s->id_seed, 0, 32);
        }
        s->seed_ok = ok;
        s->seed_gen++;
        FURI_LOG_I(TAG, ok ? "id: seed provisioned" : "id: no seed, id advert off");
    }
    furi_mutex_release(s->seed_lock);
    memset(buf, 0, sizeof(buf));
}

/* Window key (Android IdKeys.kt, spec 1a, Find My model):
 *   period  = UTC calendar month of the window start, year*12 + (month-1)
 *   share_k = HKDF(id_seed, "hone-share" || period_be32)
 *   sk_w    = HKDF(share_k, "hone-pkw" || window_be64), pk_w = X25519(sk_w, 9)
 *   tag     = HKDF(share_k, "hone-tag" || window_be64)[0..2]
 * plus, Flipper only, the two advert addresses for the window:
 *   HKDF(share_k, "hone-adr" || window_be64)[0..12], each 6 bytes as a random
 *   static address, so the addresses change at the same instant as pk_w. */
typedef struct {
    uint32_t window;
    uint32_t seed_gen;
    bool valid;
    uint8_t pk[32];
    uint8_t tag[2];
    uint8_t addr[2][6];
} HoneWindowKey;

static bool window_key(HoneSrv* s, uint32_t window, HoneWindowKey* k) {
    if(k->valid && k->window == window && k->seed_gen == s->seed_gen) return true;
    DateTime dt;
    datetime_timestamp_to_datetime(window * HONE_WINDOW_S, &dt);
    uint32_t period = (uint32_t)dt.year * 12u + (dt.month - 1u);
    uint8_t p_be[4] = {period >> 24, period >> 16, period >> 8, period};
    uint8_t w_be[8] = {0, 0, 0, 0, window >> 24, window >> 16, window >> 8, window};
    uint8_t share[32], sk[32], adr[12];

    furi_check(furi_mutex_acquire(s->seed_lock, FuriWaitForever) == FuriStatusOk);
    bool ok = s->seed_ok;
    uint32_t gen = s->seed_gen;
    if(ok)
        hkdf_sha256(s->id_seed, 32, NULL, 0, (const uint8_t*)"hone-share", 10, p_be, 4, share, 32);
    furi_mutex_release(s->seed_lock);
    if(!ok) {
        k->valid = false;
        return false;
    }
    hkdf_sha256(share, 32, NULL, 0, (const uint8_t*)"hone-pkw", 8, w_be, 8, sk, 32);
    crypto_scalarmult_base(k->pk, sk);
    hkdf_sha256(share, 32, NULL, 0, (const uint8_t*)"hone-tag", 8, w_be, 8, k->tag, 2);
    hkdf_sha256(share, 32, NULL, 0, (const uint8_t*)"hone-adr", 8, w_be, 8, adr, 12);
    for(int i = 0; i < 2; i++) {
        memcpy(k->addr[i], adr + 6 * i, 6);
        k->addr[i][5] |= 0xC0; /* random static: two top bits set (LSB first) */
    }
    k->window = window;
    k->seed_gen = gen;
    k->valid = true;
    memset(share, 0, sizeof(share));
    memset(sk, 0, sizeof(sk));
    return true;
}

/* K_day: fresh random key per UTC day, RAM only. Copies the current key out. */
static void k_day_get(HoneSrv* s, uint8_t out[32], uint32_t* day_out) {
    uint32_t day = utc_now(s) / 86400u;
    furi_check(furi_mutex_acquire(s->kday_lock, FuriWaitForever) == FuriStatusOk);
    if(day != s->k_day_day) {
        furi_hal_random_fill_buf(s->k_day, sizeof(s->k_day));
        s->k_day_day = day;
    }
    memcpy(out, s->k_day, 32);
    if(day_out) *day_out = day;
    furi_mutex_release(s->kday_lock);
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

static void owner_load(HoneSrv* s) {
    char buf[32] = {0};
    File* f = storage_file_alloc(s->storage);
    size_t n = 0;
    if(storage_file_open(f, HONE_OWNER_PATH, FSAM_READ, FSOM_OPEN_EXISTING))
        n = storage_file_read(f, buf, sizeof(buf) - 1);
    storage_file_close(f);
    storage_file_free(f);
    char next[sizeof(s->owner)] = {0};
    for(size_t i = 0, j = 0; i < n && j < sizeof(next); i++) {
        char c = buf[i];
        if(c == '\n' || c == '\r' || c == ' ') break;
        next[j++] = c;
    }
    /* only touch the shared copy on change, so the announce lane never
     * catches it half-written in the normal case */
    if(memcmp(next, s->owner, sizeof(next)) != 0) memcpy(s->owner, next, sizeof(next));
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

/* ─── sharing the hardware with other apps ────────────────────────────────
 * HoneSrv runs under every app. Before the loader starts one (the Hone screen
 * excepted) every lane parks: it finishes or cuts its slot short, powers its
 * sensor down and stops calling into the BLE stack, so the app (or a BT
 * profile change, Bluetooth settings, SD unmount...) never meets a half-held
 * radio. A lane marks itself busy BEFORE it checks the hold, so the loader
 * callback cannot miss a lane that is just starting a slot. */

static bool hone_should_yield(const HoneSrv* s) {
    return s->paused || (s->app_hold && !s->rec.ui_open);
}

/* true = go ahead, lane is now busy; false = parked, try again later */
static bool lane_enter(HoneSrv* s, HoneLane lane) {
    s->busy[lane] = true;
    if(hone_should_yield(s)) {
        s->busy[lane] = false;
        return false;
    }
    return true;
}

static void lane_leave(HoneSrv* s, HoneLane lane) {
    s->busy[lane] = false;
}

#define ST_LOCK(s)   furi_check(furi_mutex_acquire((s)->rec.lock, FuriWaitForever) == FuriStatusOk)
#define ST_UNLOCK(s) furi_mutex_release((s)->rec.lock)

void hone_status_get(HoneStatusRecord* rec, HoneStatus* out) {
    furi_check(rec && out);
    furi_check(furi_mutex_acquire(rec->lock, FuriWaitForever) == FuriStatusOk);
    *out = rec->st;
    furi_mutex_release(rec->lock);
}

void hone_status_ui_open(HoneStatusRecord* rec, bool open) {
    furi_check(rec);
    rec->ui_open = open;
    if(open) rec->want_reprobe = true;
}

static void status_tag_lane(HoneSrv* s, const char* name) {
    ST_LOCK(s);
    strlcpy(s->rec.st.tag_lane, name, sizeof(s->rec.st.tag_lane));
    ST_UNLOCK(s);
}

/* A new find for the Hone screen (and the kiskadee's "found" mood). */
static void find_push(HoneSrv* s, const char* text) {
    ST_LOCK(s);
    HoneStatus* st = &s->rec.st;
    memmove(st->finds[1], st->finds[0], sizeof(st->finds[0]) * (HONE_FINDS - 1));
    memmove(&st->find_tick[1], &st->find_tick[0], sizeof(st->find_tick[0]) * (HONE_FINDS - 1));
    strlcpy(st->finds[0], text, sizeof(st->finds[0]));
    st->find_tick[0] = furi_get_tick();
    st->find_seq++;
    ST_UNLOCK(s);
    FURI_LOG_I(TAG, "find: %s", text);
}

/* Something the owner should see now: buzz, blink, and bring up the screen. */
static void alert_raise(HoneSrv* s, const char* l1, const char* l2) {
    ST_LOCK(s);
    strlcpy(s->rec.st.alert[0], l1, sizeof(s->rec.st.alert[0]));
    strlcpy(s->rec.st.alert[1], l2, sizeof(s->rec.st.alert[1]));
    s->rec.st.alert_seq++;
    s->rec.st.alert_tick = furi_get_tick();
    ST_UNLOCK(s);
    FURI_LOG_W(TAG, "ALERT %s / %s", l1, l2);
    if(s->notif) notification_message(s->notif, &sequence_error);
    s->want_screen = true;
}

static void loader_event_cb(const void* message, void* context) {
    const LoaderEvent* e = message;
    HoneSrv* s = context;
    if(e->type == LoaderEventTypeApplicationBeforeLoad) {
        s->hold_tick = furi_get_tick();
        s->app_hold = true;
        /* Wait for the lanes to let go (a slot is at most ~2 s; long Wi-Fi and
         * BLE windows check the hold and cut short). */
        for(int i = 0; i < 40; i++) {
            bool any = false;
            for(int l = 0; l < HoneLaneCount; l++) any |= s->busy[l];
            if(!any) break;
            furi_delay_ms(100);
        }
    } else if(
        e->type == LoaderEventTypeApplicationStopped ||
        e->type == LoaderEventTypeApplicationLoadFailed) {
        s->rec.ui_open = false;
        s->app_hold = false;
    }
}

/* ─── boot record: why did we restart? ───────────────────────────────────
 * Reads the reset flags and the crash message the previous run left in the
 * RTC, appends one line to boot.log, and keeps it for the Hone screen. The
 * reset flags are cleared afterwards so the next boot reads only its own. */
static void boot_record(HoneSrv* s) {
    char reason[40];
    const char* fault = (const char*)furi_hal_rtc_get_fault_data();
    uint32_t csr = RCC->CSR;
    if(fault) {
        /* furi_crash stores a pointer to a message in flash */
        snprintf(reason, sizeof(reason), "crash: %s", fault);
    } else if(csr & (RCC_CSR_IWDGRSTF | RCC_CSR_WWDGRSTF)) {
        strlcpy(reason, "watchdog reset", sizeof(reason));
    } else if(csr & RCC_CSR_LPWRRSTF) {
        strlcpy(reason, "low-power reset", sizeof(reason));
    } else if(csr & RCC_CSR_SFTRSTF) {
        strlcpy(reason, "software reboot (no crash)", sizeof(reason));
    } else if(csr & RCC_CSR_BORRSTF) {
        strlcpy(reason, "power on / brownout", sizeof(reason));
    } else if(csr & RCC_CSR_PINRSTF) {
        strlcpy(reason, "reset button", sizeof(reason));
    } else {
        strlcpy(reason, "unknown", sizeof(reason));
    }
    for(char* p = reason; *p; p++)
        if(*p == '\n' || *p == '\r') *p = ' ';
    LL_RCC_ClearResetFlags();

    uint32_t now = furi_hal_rtc_get_timestamp();
    uint32_t alive = 0, down = 0;
    if(read_file(s->storage, HONE_ALIVE_PATH, &alive, sizeof(alive)) && alive && now >= alive)
        down = now - alive;

    char line[112];
    DateTime dt;
    datetime_timestamp_to_datetime(now, &dt);
    int n = snprintf(
        line, sizeof(line), "%04u-%02u-%02u %02u:%02u:%02u csr=%08lx down=%lus %s\n", dt.year,
        dt.month, dt.day, dt.hour, dt.minute, dt.second, (unsigned long)csr, (unsigned long)down,
        reason);
    File* f = storage_file_alloc(s->storage);
    if(n > 0 && storage_file_open(f, HONE_BOOT_LOG, FSAM_WRITE, FSOM_OPEN_APPEND))
        storage_file_write(f, line, (size_t)MIN(n, (int)sizeof(line) - 1));
    storage_file_close(f);
    storage_file_free(f);
    FURI_LOG_W(TAG, "boot: %s", line);

    ST_LOCK(s);
    strlcpy(s->rec.st.boot_reason, reason, sizeof(s->rec.st.boot_reason));
    s->rec.st.boot_rtc = now;
    s->rec.st.down_s = down;
    ST_UNLOCK(s);
}

static void alive_touch(HoneSrv* s) {
    uint32_t now = furi_hal_rtc_get_timestamp();
    write_file(s->storage, HONE_ALIVE_PATH, &now, sizeof(now));
}

/* ─── desktop status-bar icon: a tiny kiskadee head ──────────────────────
 * black crown, white brow, black mask with the eye, heavy beak, white throat.
 * Eye shut while HONE is paused or yielding to another app. */

static const uint8_t statusbar_head[8][9] = {
    {0, 0, 1, 1, 1, 1, 0, 0, 0},
    {0, 1, 1, 1, 1, 1, 1, 0, 0},
    {1, 0, 0, 0, 0, 0, 0, 1, 0},
    {1, 1, 1, 1, 0, 1, 1, 1, 1},
    {1, 1, 1, 1, 1, 1, 1, 1, 0},
    {1, 0, 0, 0, 0, 0, 0, 1, 0},
    {0, 1, 0, 0, 0, 0, 1, 0, 0},
    {0, 0, 1, 1, 1, 1, 0, 0, 0},
};

static void statusbar_draw(Canvas* canvas, void* ctx) {
    HoneSrv* s = ctx;
    bool shut = hone_should_yield(s);
    for(int y = 0; y < 8; y++)
        for(int x = 0; x < 9; x++)
            if(statusbar_head[y][x] || (shut && y == 3 && x == 4))
                canvas_draw_dot(canvas, x, y);
}

/* ─── capture log: hash chain over queue.bin ──────────────────────────────
 * Every queued frame is v3 and carries prev = sha256(previous frame)[0..16];
 * chain_head is sha256 of the newest one. Called with emit_lock held. */

static void chain_save(HoneSrv* s, uint32_t offset) {
    HoneChainState c = {
        .magic = HONE_CHAIN_MAGIC,
        .seq = s->chain_seq,
        .queue_first = s->queue_first,
        .offset = offset,
    };
    memcpy(c.head, s->chain_head, 32);
    write_file(s->storage, HONE_CHAIN_PATH, &c, sizeof(c));
    s->chain_unsaved = 0;
}

/* Fold frames from queue.bin (starting at offset) into the head. */
static void chain_replay(HoneSrv* s, uint32_t offset) {
    File* f = storage_file_alloc(s->storage);
    uint8_t* buf = malloc(256);
    if(storage_file_open(f, HONE_QUEUE_PATH, FSAM_READ, FSOM_OPEN_EXISTING) &&
       storage_file_seek(f, offset, true)) {
        uint8_t l;
        while(storage_file_read(f, &l, 1) == 1 && l >= sizeof(HoneV2Header) &&
              storage_file_read(f, buf, l) == l) {
            mbedtls_sha256(buf, l, s->chain_head, 0);
            s->chain_seq = ((const HoneV2Header*)buf)->counter;
            if(!s->queue_first) s->queue_first = s->chain_seq;
        }
    }
    storage_file_close(f);
    storage_file_free(f);
    free(buf);
}

/* Boot: chain.bin + the queue tail after it. First boot with v3: the whole
 * queue.bin (<= 4 MB) once, so the first v3 frame links to the last v2 one. */
static void chain_load(HoneSrv* s) {
    HoneChainState c;
    if(read_file(s->storage, HONE_CHAIN_PATH, &c, sizeof(c)) && c.magic == HONE_CHAIN_MAGIC) {
        memcpy(s->chain_head, c.head, 32);
        s->chain_seq = c.seq;
        s->queue_first = c.queue_first;
        chain_replay(s, c.offset);
    } else {
        memset(s->chain_head, 0, 32);
        s->chain_seq = 0;
        s->queue_first = 0;
        chain_replay(s, 0);
    }
    FileInfo fi;
    uint32_t size = storage_common_stat(s->storage, HONE_QUEUE_PATH, &fi) == FSE_OK ? fi.size : 0;
    chain_save(s, size);
    FURI_LOG_I(TAG, "chain seq %lu, queue from %lu", s->chain_seq, s->queue_first);
}

static void queue_append(HoneSrv* s, const uint8_t* frame, size_t len, uint32_t seq) {
    FileInfo fi;
    if(storage_common_stat(s->storage, HONE_QUEUE_PATH, &fi) == FSE_OK &&
       fi.size > HONE_QUEUE_MAX) {
        /* Rotate. The name carries the seq range, so a delivered archive can be
         * found without opening it. Archives are only ever deleted once a phone
         * has acknowledged everything in them, and only when the SD runs low. */
        char path[80];
        storage_common_mkdir(s->storage, HONE_ARCHIVE_DIR);
        snprintf(
            path, sizeof(path), HONE_ARCHIVE_DIR "/q-%lu-%lu-%lu.bin",
            (unsigned long)furi_hal_rtc_get_timestamp(), (unsigned long)s->queue_first,
            (unsigned long)s->chain_seq);
        if(storage_common_rename(s->storage, HONE_QUEUE_PATH, path) == FSE_OK) {
            s->queue_first = seq;
            chain_save(s, 0);
        }
    }
    File* f = storage_file_alloc(s->storage);
    uint32_t size = 0;
    if(storage_file_open(f, HONE_QUEUE_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
        uint8_t l = (uint8_t)len; /* frames are <= 240 bytes */
        storage_file_write(f, &l, 1);
        storage_file_write(f, frame, len);
        size = (uint32_t)storage_file_size(f);
    }
    storage_file_close(f);
    storage_file_free(f);
    mbedtls_sha256(frame, len, s->chain_head, 0);
    s->chain_seq = seq;
    if(!s->queue_first) s->queue_first = seq;
    if(++s->chain_unsaved >= HONE_CHAIN_SAVE_EVERY) chain_save(s, size);
}

/* ─── SD space: never drop undelivered data ───────────────────────────────
 * Below HONE_SD_LOW_MB free, delete the oldest archive whose last seq a phone
 * has acknowledged (ack.bin). Archives from before the v3 log (no seq range in
 * the name) are never deleted. If nothing can be deleted and space keeps
 * falling, economy mode: continuous Sub-GHz RSSI frames are thinned 1 in 4;
 * every event (gadget, jam, tag, tracker...) is still logged. */
static void sd_manage(HoneSrv* s) {
    uint64_t total = 0, free_b = 0;
    if(storage_common_fs_info(s->storage, STORAGE_EXT_PATH_PREFIX, &total, &free_b) != FSE_OK)
        return;
    uint32_t free_mb = (uint32_t)(free_b / (1024u * 1024u));
    uint32_t ack = 0;
    read_file(s->storage, HONE_ACK_PATH, &ack, sizeof(ack));

    if(free_mb < HONE_SD_LOW_MB) {
        File* d = storage_file_alloc(s->storage);
        char name[64], best[64] = {0};
        unsigned long best_last = 0xFFFFFFFFul;
        FileInfo fi;
        if(storage_dir_open(d, HONE_ARCHIVE_DIR)) {
            while(storage_dir_read(d, &fi, name, sizeof(name))) {
                unsigned long rtc, first, last;
                if(sscanf(name, "q-%lu-%lu-%lu.bin", &rtc, &first, &last) == 3 && last <= ack &&
                   last < best_last) {
                    best_last = last;
                    strlcpy(best, name, sizeof(best));
                }
            }
        }
        storage_dir_close(d);
        storage_file_free(d);
        if(best[0]) {
            char path[96];
            snprintf(path, sizeof(path), HONE_ARCHIVE_DIR "/%s", best);
            if(storage_common_remove(s->storage, path) == FSE_OK)
                FURI_LOG_W(TAG, "sd low (%lu MB): removed delivered %s", free_mb, best);
        }
    }
    bool econ = free_mb < HONE_SD_ECON_MB;
    if(econ && !s->economy) find_push(s, "SD almost full: sync a phone");
    s->economy = econ;
    ST_LOCK(s);
    s->rec.st.sd_free_mb = free_mb;
    s->rec.st.sd_economy = econ;
    s->rec.st.acked_seq = ack;
    ST_UNLOCK(s);
}

/* ─── sensors: each one acquires and fully releases its hardware ───────── */

/* ─── Sub-GHz: RSSI windows + gadget census + jamming ─────────────────────
 * Each window listens HONE_SLOT_MS on one band. On the OOK bands (433.92, 315,
 * 868.35) the window also runs the firmware's own Sub-GHz decoders through
 * async RX, when TIM2 is free and the heap allows. A decoded packet yields
 * only: decoder name (brand/protocol family), static vs dynamic (fixed vs
 * rolling code) and the decoder's 1-byte data hash, which never leaves RAM
 * except as a daily-keyed HMAC token. No code, key or payload is kept. */

#define HONE_GADGET_PER_WIN 8
#define HONE_GADGET_RECENT  16
#define HONE_GADGET_QUIET_MS (10u * 60u * 1000u) /* same device: one frame per 10 min */
#define HONE_DECODE_MIN_HEAP (24u * 1024u)       /* largest free block needed to decode */

typedef struct {
    const SubGhzProtocol* proto;
    uint8_t hash;
    uint8_t count;
} HoneHeard;

typedef struct {
    HoneHeard heard[HONE_GADGET_PER_WIN];
    uint8_t n;
    uint32_t acc;      /* ISR: glitch filter accumulator */
} HoneDecodeWin;

static FuriStreamBuffer* volatile sg_stream;

static void sg_capture_cb(bool level, uint32_t duration, void* ctx) {
    HoneDecodeWin* w = ctx;
    if(duration < 30) { /* glitch: fold into the next pulse */
        w->acc += duration;
        return;
    }
    LevelDuration ld = level_duration_make(level, duration + w->acc);
    w->acc = 0;
    if(sg_stream) furi_stream_buffer_send(sg_stream, &ld, sizeof(ld), 0);
}

static void sg_decoded_cb(SubGhzReceiver* r, SubGhzProtocolDecoderBase* d, void* ctx) {
    UNUSED(r);
    HoneDecodeWin* w = ctx;
    uint8_t h = subghz_protocol_decoder_base_get_hash_data(d);
    for(uint8_t i = 0; i < w->n; i++) {
        if(w->heard[i].proto == d->protocol && w->heard[i].hash == h) {
            if(w->heard[i].count < 255) w->heard[i].count++;
            return;
        }
    }
    if(w->n < HONE_GADGET_PER_WIN) w->heard[w->n++] = (HoneHeard){d->protocol, h, 1};
}

static bool band_is_ook(uint32_t f) {
    return f == 433920000UL || f == 315000000UL || f == 868350000UL;
}

/* One window. *band = index into hone_subghz_freqs; win->n > 0 if decoded. */
static bool capture_subghz(HoneSrv* s, HoneBodySubGhz* out, uint8_t* band, HoneDecodeWin* win) {
    static size_t next = 0;
    *band = (uint8_t)(next++ % COUNT_OF(hone_subghz_freqs));
    uint32_t freq = hone_subghz_freqs[*band];
    memset(win, 0, sizeof(*win));
    if(!furi_hal_subghz_is_frequency_valid(freq)) return false;

    SubGhzEnvironment* env = NULL;
    SubGhzReceiver* rx = NULL;
    FuriStreamBuffer* sb = NULL;
    bool decode = band_is_ook(freq) && memmgr_heap_get_max_free_block() >= HONE_DECODE_MIN_HEAP &&
                  furi_mutex_acquire(s->tim_lock, 0) == FuriStatusOk;
    if(decode) {
        env = subghz_environment_alloc();
        subghz_environment_set_protocol_registry(env, &subghz_protocol_registry);
        rx = subghz_receiver_alloc_init(env);
        subghz_receiver_set_filter(rx, SubGhzProtocolFlag_Decodable);
        subghz_receiver_set_rx_callback(rx, sg_decoded_cb, win);
        sb = furi_stream_buffer_alloc(512 * sizeof(LevelDuration), sizeof(LevelDuration));
    }

    furi_hal_subghz_reset();
    furi_hal_subghz_idle();
    if(decode) furi_hal_subghz_load_custom_preset(subghz_device_cc1101_preset_ook_650khz_async_regs);
    furi_hal_subghz_set_frequency_and_path(freq);
    furi_hal_subghz_flush_rx();
    furi_hal_subghz_rx();
    if(decode) {
        sg_stream = sb;
        furi_hal_subghz_start_async_rx(sg_capture_cb, win);
    }
    furi_delay_ms(3);

    float peak = -200.0f, sum = 0.0f;
    uint16_t n = 0;
    uint32_t start = furi_get_tick(), last_rssi = 0;
    while(furi_get_tick() - start < furi_ms_to_ticks(HONE_SLOT_MS) && !hone_should_yield(s)) {
        if(decode) {
            LevelDuration ld;
            while(furi_stream_buffer_receive(sb, &ld, sizeof(ld), 0) == sizeof(ld))
                subghz_receiver_decode(
                    rx, level_duration_get_level(ld), level_duration_get_duration(ld));
        }
        if(!last_rssi || furi_get_tick() - last_rssi >= furi_ms_to_ticks(HONE_RSSI_GAP_MS)) {
            last_rssi = furi_get_tick();
            float r = furi_hal_subghz_get_rssi();
            if(r > peak) peak = r;
            sum += r;
            n++;
        }
        furi_delay_ms(decode ? 10 : HONE_RSSI_GAP_MS);
    }

    if(decode) {
        furi_hal_subghz_stop_async_rx();
        sg_stream = NULL;
    }
    furi_hal_subghz_idle();
    furi_hal_subghz_sleep(); /* fully released before any signing */
    if(decode) {
        furi_mutex_release(s->tim_lock);
        subghz_receiver_free(rx);
        subghz_environment_free(env);
        furi_stream_buffer_free(sb);
    }

    if(!n || hone_should_yield(s)) {
        win->n = 0;
        return false; /* cut short: not a full window */
    }
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
    /* The iButton reader asks the power service for 5 V. That same 5 V feeds
     * the Wi-Fi board: never switch it under a running Wi-Fi scan. */
    if(furi_mutex_acquire(s->otg_lock, 0) != FuriStatusOk) return false;
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
    furi_mutex_release(s->otg_lock);
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

/* IR running alongside an NFC or iButton window (IR RX uses TIM2 only). */
typedef struct {
    InfraredWorker* worker;
    HoneWait w;
} HoneIrRun;

static void ir_begin(HoneIrRun* r) {
    r->w = (HoneWait){.done = furi_semaphore_alloc(1, 0)};
    r->worker = infrared_worker_alloc();
    infrared_worker_rx_enable_signal_decoding(r->worker, true);
    infrared_worker_rx_enable_blink_on_receiving(r->worker, false);
    infrared_worker_rx_set_received_signal_callback(r->worker, ir_cb, &r->w);
    infrared_worker_rx_start(r->worker);
}

static bool ir_end(HoneIrRun* r, HoneBodyIr* out) {
    infrared_worker_rx_stop(r->worker);
    infrared_worker_free(r->worker);
    bool got = r->w.hit;
    if(got) *out = r->w.ir;
    furi_semaphore_free(r->w.done);
    return got;
}

/* ─── Wi-Fi dev board (hone-esp on ESP32-S2, USART pins 13/14) ─────────── */

#define HONE_WIFI_BAUD    230400
#define HONE_WIFI_BOOT_MS 4000
#define HONE_WIFI_SCAN_MS 10000  /* v1 SCAN reply timeout */
#define HONE_WIFI_LISTEN_MS 15000 /* v2: continuous probe listening, ch 1/6/11 */
#define HONE_WIFI2_SCAN_MS (HONE_WIFI_LISTEN_MS + 15000) /* v2 reply timeout */
#define HONE_WIFI_EVERY_MS 60000 /* one scan a minute, battery and USB alike (spec 2b) */
#define HONE_EXT_POWER_V   4.5f  /* VBUS above this = USB/external power (announce flag) */

static void wifi_rx_cb(FuriHalSerialHandle* h, FuriHalSerialRxEvent ev, void* ctx) {
    if(ev & FuriHalSerialRxEventData) {
        uint8_t b = furi_hal_serial_async_rx(h);
        furi_stream_buffer_send(ctx, &b, 1, 0);
    }
}

static bool wifi_readline(FuriStreamBuffer* sb, char* buf, size_t cap, uint32_t timeout_ms) {
    size_t n = 0;
    uint32_t start = furi_get_tick();
    while(furi_get_tick() - start < furi_ms_to_ticks(timeout_ms)) {
        uint8_t c;
        if(furi_stream_buffer_receive(sb, &c, 1, furi_ms_to_ticks(50)) != 1) continue;
        if(c == '\r') continue;
        if(c == '\n') {
            if(n) {
                buf[n] = 0;
                return true;
            }
            continue;
        }
        if(n < cap - 1) buf[n++] = (char)c;
    }
    return false;
}

static int kv_int(const char* line, const char* key) {
    const char* p = strstr(line, key);
    return p ? atoi(p + strlen(key)) : 0;
}

static int hexval(char c) {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 :
           c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

/* "WIFI2 aps=N la=L best=R ch=c1,...,c13 probes=P uniq=U listen=S top=oid:rssi:ch,... ms=T" */
/* hone-esp >= 0.3 adds to the WIFI2 line:
 *   sec=open,wep,wpa,wpa2,wpa3,ent,wps   networks by security type
 *   pso=<8hex>,...                        up to 32 probe senders as 4-byte keyed
 *                                         oids (daily key; never a MAC)
 *   cu=f1,f6,f11                          frames/s heard on channels 1, 6, 11
 *   deauth=N                              deauth + disassoc frames heard
 * Parsed into these (Wi-Fi lane only). */
#define HONE_PSO_MAX 32
static struct {
    bool sec_ok, crowd_ok;
    HoneBodyWifiSec sec;
    uint32_t pso[HONE_PSO_MAX];
    uint8_t pso_n;
    uint16_t cu[3];
    uint16_t deauth;
} wx;

static void csv_u16(const char* p, uint16_t* out, int n) {
    for(int i = 0; i < n && *p && *p != ' '; i++) {
        out[i] = (uint16_t)MIN(atoi(p), 0xFFFF);
        while(*p && *p != ',' && *p != ' ') p++;
        if(*p == ',') p++;
    }
}

static void wifi_extra_parse(const char* line) {
    memset(&wx, 0, sizeof(wx));
    const char* p = strstr(line, " sec=");
    if(p) {
        uint16_t v[7] = {0};
        csv_u16(p + 5, v, 7);
        wx.sec = (HoneBodyWifiSec){
            .ver = 1,
            .open = (uint8_t)MIN(v[0], 255),
            .wep = (uint8_t)MIN(v[1], 255),
            .wpa = (uint8_t)MIN(v[2], 255),
            .wpa2 = (uint8_t)MIN(v[3], 255),
            .wpa3 = (uint8_t)MIN(v[4], 255),
            .ent = (uint8_t)MIN(v[5], 255),
            .wps = (uint8_t)MIN(v[6], 255),
        };
        wx.sec_ok = true;
    }
    p = strstr(line, " pso=");
    if(p) {
        wx.crowd_ok = true;
        p += 5;
        while(wx.pso_n < HONE_PSO_MAX && *p && *p != ' ' && *p != '-') {
            uint32_t v = 0;
            int i = 0;
            for(; i < 8; i++) {
                int h = hexval(p[i]);
                if(h < 0) break;
                v = v << 4 | (uint32_t)h;
            }
            if(i != 8) break;
            wx.pso[wx.pso_n++] = v;
            p += 8;
            if(*p == ',') p++;
        }
    }
    p = strstr(line, " cu=");
    if(p) csv_u16(p + 4, wx.cu, 3);
    int d = kv_int(line, " deauth=");
    wx.deauth = (uint16_t)MIN(d < 0 ? 0 : d, 0xFFFF);
}

static bool wifi2_parse(const char* line, HoneBodyWifi2* out) {
    if(strncmp(line, "WIFI2 ", 6) != 0) return false;
    memset(out, 0, sizeof(*out));
    out->ver = 2;
    out->aps = (uint8_t)MIN(kv_int(line, " aps="), 255);
    out->la_aps = (uint8_t)MIN(kv_int(line, " la="), 255);
    out->best_rssi = (int8_t)kv_int(line, " best=");
    out->probes = (uint16_t)MIN(kv_int(line, " probes="), 0xFFFF);
    out->probe_senders = (uint8_t)MIN(kv_int(line, " uniq="), 255);
    out->listen_s = (uint8_t)MIN(kv_int(line, " listen="), 255);
    const char* p = strstr(line, " ch=");
    if(p) {
        p += 4;
        for(int i = 0; i < 13 && *p && *p != ' '; i++) {
            out->ch[i] = (uint8_t)MIN(atoi(p), 255);
            while(*p && *p != ',' && *p != ' ') p++;
            if(*p == ',') p++;
        }
    }
    p = strstr(line, " top=");
    if(p) {
        p += 5;
        while(out->n_top < HONE_WIFI_TOP && *p && *p != ' ' && *p != '-') {
            HoneWifiAp* ap = &out->top[out->n_top];
            int i = 0;
            for(; i < HONE_OID_LEN; i++) {
                int hi = hexval(p[0]), lo = hi < 0 ? -1 : hexval(p[1]);
                if(lo < 0) break;
                ap->oid[i] = (uint8_t)(hi << 4 | lo);
                p += 2;
            }
            if(i != HONE_OID_LEN || *p != ':') break;
            ap->rssi = (int8_t)atoi(++p);
            while(*p && *p != ':' && *p != ' ') p++;
            if(*p != ':') break;
            ap->channel = (uint8_t)atoi(++p);
            while(*p && *p != ',' && *p != ' ') p++;
            out->n_top++;
            if(*p == ',') p++;
        }
    }
    wifi_extra_parse(line);
    return true;
}

static bool wifi_parse(const char* line, HoneBodyWifi* out) {
    if(strncmp(line, "WIFI ", 5) != 0) return false;
    memset(out, 0, sizeof(*out));
    out->aps = (uint8_t)MIN(kv_int(line, "aps="), 255);
    out->best_rssi = (int8_t)kv_int(line, "best=");
    out->probes = (uint16_t)MIN(kv_int(line, "probes="), 0xFFFF);
    out->uniq = (uint8_t)MIN(kv_int(line, "uniq="), 255);
    const char* p = strstr(line, "ch=");
    if(p) {
        p += 3;
        for(int i = 0; i < 13 && *p && *p != ' '; i++) {
            out->ch[i] = (uint8_t)MIN(atoi(p), 255);
            while(*p && *p != ',' && *p != ' ') p++;
            if(*p == ',') p++;
        }
    }
    return true;
}

/* One dev board session. hone-esp >= 0.2 gets the day's oid subkey and a SCAN2
 * (body v2, *v2 = true); an older board falls back to the v1 SCAN. */
static bool capture_wifi(HoneSrv* s, HoneBodyWifi* v1, HoneBodyWifi2* v2, bool* is_v2) {
    furi_check(furi_mutex_acquire(s->otg_lock, FuriWaitForever) == FuriStatusOk);
    bool otg_was_on = furi_hal_power_is_otg_enabled();
    if(!otg_was_on) furi_hal_power_enable_otg();
    FuriHalSerialHandle* h = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if(!h) {
        if(!otg_was_on) furi_hal_power_disable_otg();
        furi_mutex_release(s->otg_lock);
        return false;
    }
    FuriStreamBuffer* sb = furi_stream_buffer_alloc(1024, 1);
    furi_hal_serial_init(h, HONE_WIFI_BAUD);
    furi_hal_serial_async_rx_start(h, wifi_rx_cb, sb, false);

    char* line = malloc(800); /* WIFI2 with sec/pso/cu fields runs to ~650 chars */
    bool alive = false, got = false, new_board = false;
    *is_v2 = false;
    uint32_t start = furi_get_tick();
    while(!alive && furi_get_tick() - start < furi_ms_to_ticks(HONE_WIFI_BOOT_MS) &&
          !hone_should_yield(s)) {
        furi_hal_serial_tx(h, (const uint8_t*)"PING\n", 5);
        while(wifi_readline(sb, line, 800, 500)) {
            if(strncmp(line, "PONG", 4) == 0) {
                alive = true;
                /* "PONG hone-esp 0.1.0": 0.1.x only speaks v1 */
                const char* v = strstr(line, "hone-esp ");
                new_board = v && strncmp(v + 9, "0.1.", 4) != 0;
                break;
            }
        }
    }
    if(alive && new_board) {
        /* subkey = HMAC(K_day, "hone-wifi"): the board never holds K_day itself */
        uint8_t k[32], sub[32];
        char cmd[4 + 64 + 2];
        k_day_get(s, k, NULL);
        hmac_sha256(k, 32, (const uint8_t*)"hone-wifi", 9, NULL, 0, sub);
        memcpy(cmd, "KEY ", 4);
        hex_into(cmd + 4, sub, 32);
        cmd[68] = '\n';
        furi_hal_serial_tx(h, (const uint8_t*)cmd, 69);
        memset(k, 0, sizeof(k));
        memset(sub, 0, sizeof(sub));
        memset(cmd, 0, sizeof(cmd));
        bool keyed = false;
        start = furi_get_tick();
        while(!keyed && furi_get_tick() - start < furi_ms_to_ticks(1000)) {
            if(wifi_readline(sb, line, 800, 200)) keyed = strncmp(line, "OK key", 6) == 0;
        }
        if(keyed) {
            char sc[24];
            int n = snprintf(sc, sizeof(sc), "SCAN2 %u\n", (unsigned)HONE_WIFI_LISTEN_MS);
            furi_hal_serial_tx(h, (const uint8_t*)sc, n);
            start = furi_get_tick();
            while(!got && furi_get_tick() - start < furi_ms_to_ticks(HONE_WIFI2_SCAN_MS) &&
          !hone_should_yield(s)) {
                if(wifi_readline(sb, line, 800, 500)) got = wifi2_parse(line, v2);
            }
            *is_v2 = got;
        }
    }
    if(alive && !new_board) {
        furi_hal_serial_tx(h, (const uint8_t*)"SCAN\n", 5);
        start = furi_get_tick();
        while(!got && furi_get_tick() - start < furi_ms_to_ticks(HONE_WIFI_SCAN_MS) &&
          !hone_should_yield(s)) {
            if(wifi_readline(sb, line, 800, 500)) got = wifi_parse(line, v1);
        }
    }
    free(line);
    s->wifi_board = alive;

    furi_hal_serial_async_rx_stop(h);
    furi_hal_serial_deinit(h);
    furi_hal_serial_control_release(h);
    furi_stream_buffer_free(sb);
    if(!otg_was_on) furi_hal_power_disable_otg(); /* board fully off between slots */
    furi_mutex_release(s->otg_lock);
    return got;
}

static int group_of(HoneMsgType t) {
    switch(t) {
    case HoneMsgSubGhz: return 0;
    case HoneMsgWifi:
    case HoneMsgWifi2: return 1;
    case HoneMsgRfid:
    case HoneMsgNfc:
    case HoneMsgIButton: return 2;
    case HoneMsgIr: return 3;
    case HoneMsgBleCrowd: return 4;
    case HoneMsgSighting: return 5;
    /* new census frames ride in the existing on-chain sensor groups */
    case HoneMsgGadget:
    case HoneMsgJam: return 0;
    case HoneMsgWifiSec:
    case HoneMsgWifiCrowd: return 1;
    case HoneMsgReader: return 2;
    case HoneMsgBleThreat: return 4;
    default: return -1;
    }
}

static void emit(HoneSrv* s, HoneMsgType type, const void* body, uint8_t body_len) {
    furi_check(furi_mutex_acquire(s->emit_lock, FuriWaitForever) == FuriStatusOk);
    uint32_t seq = counter_next(s);
    size_t len = hone_frame_build(
        s->frame, type, body, body_len, s->pk, s->sk, seq, s->anchor, s->chain_head);
    if(len) {
        queue_append(s, s->frame, len, seq);
        s->total_frames++;
        ST_LOCK(s);
        s->rec.st.frames = s->total_frames;
        s->rec.st.counter = s->counter;
        s->rec.st.chain_seq = s->chain_seq;
        ST_UNLOCK(s);
        int g = group_of(type);
        if(g >= 0) {
            HoneBatch* b = &s->batch[g];
            if(b->count == 0) {
                mbedtls_sha256_init(&b->h);
                mbedtls_sha256_starts(&b->h, 0);
                b->started = furi_get_tick();
            }
            mbedtls_sha256_update(&b->h, s->frame, len);
            b->count++;
        }
    }
    furi_mutex_release(s->emit_lock);
}

/* Close any batch that is due: sign the chain's SENSOR_DATA_COMMIT canonical
 * message (compact JSON, fixed key order — must match hone-node tx.rs) and keep
 * the signed commit for broadcast. Called from the announce lane. */
static void batches_flush(HoneSrv* s) {
    if(!s->owner[0]) return; /* not claimed: nobody to commit for */
    for(int g = 0; g < HONE_GROUPS; g++) {
        uint8_t hash[32];
        uint16_t count;
        furi_check(furi_mutex_acquire(s->emit_lock, FuriWaitForever) == FuriStatusOk);
        HoneBatch* b = &s->batch[g];
        bool due = b->count > 0 &&
                   (b->count >= HONE_BATCH_MAX ||
                    furi_get_tick() - b->started >= furi_ms_to_ticks(HONE_BATCH_MS));
        if(due) {
            mbedtls_sha256_finish(&b->h, hash);
            mbedtls_sha256_free(&b->h);
            count = b->count;
            b->count = 0;
        }
        furi_mutex_release(s->emit_lock);
        if(!due) continue;

        char dev[17], hash_hex[65], owner[17] = {0};
        hex_into(dev, s->pk, 8);
        hex_into(hash_hex, hash, 32);
        memcpy(owner, s->owner, 16);
        char msg[384];
        int n = snprintf(
            msg, sizeof(msg),
            "{\"chain_id\":\"hone\",\"type\":\"SENSOR_DATA_COMMIT\","
            "\"sensor_id\":\"flipper-%s-%s\",\"owner\":\"%s\",\"batch_hash\":\"%s\","
            "\"reading_count\":%u,\"sensor_type\":\"%s\",\"signed_by\":\"%s\"}",
            dev, hone_group_name[g], owner, hash_hex, (unsigned)count, hone_group_type[g], owner);
        if(n <= 0 || n >= (int)sizeof(msg)) continue;

        HoneCommit* c = &s->commits[s->commit_next];
        s->commit_next = (s->commit_next + 1) % HONE_COMMIT_SLOTS;
        memcpy(c->data, s->pk, 8);
        c->data[8] = (uint8_t)g;
        c->data[9] = (uint8_t)(count & 0xFF);
        c->data[10] = (uint8_t)(count >> 8);
        memcpy(c->data + 11, hash, 32);
        hone_ed25519_sign(c->data + 43, (const uint8_t*)msg, (size_t)n, s->sk);
        c->seq = ++s->commit_seq;
        c->made = furi_get_tick() ? furi_get_tick() : 1;

        File* f = storage_file_alloc(s->storage);
        if(storage_file_open(f, HONE_COMMIT_PATH, FSAM_WRITE, FSOM_OPEN_APPEND))
            storage_file_write(f, c->data, HONE_COMMIT_LEN);
        storage_file_close(f);
        uint32_t now = furi_hal_rtc_get_timestamp();
        if(storage_file_open(f, HONE_COMMIT_TIME, FSAM_WRITE, FSOM_OPEN_APPEND))
            storage_file_write(f, &now, sizeof(now));
        storage_file_close(f);
        storage_file_free(f);
        ST_LOCK(s);
        s->rec.st.commits++;
        ST_UNLOCK(s);
        FURI_LOG_I(TAG, "commit %s x%u", hone_group_name[g], (unsigned)count);
    }
}

static void ir_status(HoneSrv* s, const HoneBodyIr* b) {
    ST_LOCK(s);
    if(b->protocol < 0)
        snprintf(s->rec.st.last_tag, sizeof(s->rec.st.last_tag), "IR raw %u", b->raw_timings);
    else
        snprintf(
            s->rec.st.last_tag, sizeof(s->rec.st.last_tag), "IR p%d %lx/%lx", b->protocol,
            (unsigned long)b->address, (unsigned long)b->command);
    s->rec.st.last_tag_tick = furi_get_tick();
    ST_UNLOCK(s);
}

/* A reader field: one frame per kind per 10 min while it stays around. */
static bool reader_found(HoneSrv* s, uint8_t kind, uint32_t freq) {
    static uint32_t last[3];
    if(last[kind] && furi_get_tick() - last[kind] < furi_ms_to_ticks(10u * 60u * 1000u))
        return true;
    last[kind] = furi_get_tick() ? furi_get_tick() : 1;
    HoneBodyReader b = {.ver = 1, .kind = kind, .freq_hz = freq};
    emit(s, HoneMsgReader, &b, sizeof(b));
    char t[48];
    if(kind == HONE_READER_125K)
        snprintf(t, sizeof(t), "125kHz reader %lu.%luk legacy", freq / 1000, freq / 100 % 10);
    else
        snprintf(t, sizeof(t), "NFC 13.56MHz reader nearby");
    find_push(s, t);
    ST_LOCK(s);
    s->rec.st.readers++;
    ST_UNLOCK(s);
    return true;
}

/* Run one slot. Returns true if the sensor produced a reading. */
static bool run_slot(HoneSrv* s, HoneSensorKind k) {
    switch(k) {
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
        alive_touch(s); /* next boot can tell an instant reset from a power loss */
        ST_LOCK(s);
        s->rec.st.battery_pct = b.battery_pct;
        s->rec.st.ext_power = s->ext_power;
        ST_UNLOCK(s);
        FURI_LOG_I(TAG, "heartbeat batt %u frames %lu", b.battery_pct, b.total_frames);
        return true;
    }
    case HoneSensorNfc:
    case HoneSensorRfid:
    case HoneSensorIButton: {
        /* RFID needs TIM2 too, so IR only rides along with NFC and iButton. */
        bool with_ir = k != HoneSensorRfid;
        HoneIrRun ir;
        if(with_ir) ir_begin(&ir);
        HoneBodyTag b;
        bool got = k == HoneSensorNfc  ? capture_nfc(s, &b) :
                   k == HoneSensorRfid ? capture_rfid(s, &b) :
                                         capture_ibutton(s, &b);
        if(with_ir) {
            HoneBodyIr irb;
            if(ir_end(&ir, &irb)) {
                emit(s, HoneMsgIr, &irb, sizeof(irb));
                ir_status(s, &irb);
                FURI_LOG_I(TAG, "ir proto %d addr %lx cmd %lx", irb.protocol, irb.address, irb.command);
            }
        }
        if(!got) return false;
        HoneMsgType t = k == HoneSensorNfc ? HoneMsgNfc : k == HoneSensorRfid ? HoneMsgRfid : HoneMsgIButton;
        emit(s, t, &b, sizeof(b));
        ST_LOCK(s);
        snprintf(
            s->rec.st.last_tag, sizeof(s->rec.st.last_tag), "%s proto %u",
            t == HoneMsgNfc ? "NFC" : t == HoneMsgRfid ? "RFID" : "iButton", b.protocol);
        s->rec.st.last_tag_tick = furi_get_tick();
        ST_UNLOCK(s);
        FURI_LOG_I(TAG, "tag type %d proto %u idlen %u", t, b.protocol, b.id_len);
        return true;
    }
    case HoneSensorIr: {
        HoneBodyIr b;
        if(!capture_ir(&b)) return false;
        emit(s, HoneMsgIr, &b, sizeof(b));
        ir_status(s, &b);
        FURI_LOG_I(TAG, "ir proto %d addr %lx cmd %lx", b.protocol, b.address, b.command);
        return true;
    }
    case HoneSensorReader: {
        /* Card-reader census: is a reader's field around us? Field presence
         * only: we never answer it, emulate a card or read anything. */
        bool any = false;
        if(furi_hal_nfc_acquire() == FuriHalNfcErrorNone) {
            furi_hal_nfc_low_power_mode_stop();
            furi_hal_nfc_field_detect_start();
            bool hf = false;
            for(int i = 0; i < 10 && !hf && !hone_should_yield(s); i++) {
                furi_delay_ms(100);
                hf = furi_hal_nfc_field_is_present();
            }
            furi_hal_nfc_field_detect_stop();
            furi_hal_nfc_low_power_mode_start();
            furi_hal_nfc_release();
            if(hf) any |= reader_found(s, HONE_READER_NFC, 0);
        }
        furi_hal_rfid_field_detect_start();
        uint32_t f = 0;
        bool lf = false;
        for(int i = 0; i < 10 && !lf && !hone_should_yield(s); i++) {
            furi_delay_ms(100);
            lf = furi_hal_rfid_field_is_present(&f);
        }
        furi_hal_rfid_field_detect_stop();
        if(lf) any |= reader_found(s, HONE_READER_125K, f);
        return any;
    }
    default:
        return false;
    }
}

/* Turn a window's decodes into census frames: one per device per 10 min. */
static void gadgets_emit(HoneSrv* s, const HoneDecodeWin* win, const HoneBodySubGhz* sg) {
    static struct {
        uint32_t token;
        uint32_t tick;
    } recent[HONE_GADGET_RECENT];
    static uint8_t recent_next;
    uint8_t kd[32];
    for(uint8_t i = 0; i < win->n; i++) {
        const SubGhzProtocol* p = win->heard[i].proto;
        HoneBodyGadget g = {
            .ver = 1,
            .category = (uint8_t)hone_gadget_category(p->name),
            .sec_class = (uint8_t)hone_gadget_security((int)p->type),
            .freq_hz = sg->freq_hz,
            .rssi_dbm = sg->rssi_peak_dbm,
            .count = win->heard[i].count,
        };
        strncpy(g.protocol, p->name, sizeof(g.protocol));
        /* token = HMAC(K_day, "hone-sg" || name || hash)[0..4]: links the same
         * device within a day, nothing else; K_day never leaves RAM */
        uint8_t mac[32], msg[1 + sizeof(g.protocol)];
        memcpy(msg, g.protocol, sizeof(g.protocol));
        msg[sizeof(g.protocol)] = win->heard[i].hash;
        k_day_get(s, kd, NULL);
        hmac_sha256(kd, 32, (const uint8_t*)"hone-sg", 7, msg, sizeof(msg), mac);
        memcpy(g.token, mac, 4);
        uint32_t tok;
        memcpy(&tok, mac, 4);
        bool fresh = true;
        for(uint8_t k = 0; k < HONE_GADGET_RECENT; k++)
            if(recent[k].tick && recent[k].token == tok &&
               furi_get_tick() - recent[k].tick < furi_ms_to_ticks(HONE_GADGET_QUIET_MS))
                fresh = false;
        if(!fresh) continue;
        recent[recent_next].token = tok;
        recent[recent_next].tick = furi_get_tick() ? furi_get_tick() : 1;
        recent_next = (recent_next + 1) % HONE_GADGET_RECENT;

        emit(s, HoneMsgGadget, &g, sizeof(g));
        char t[30];
        snprintf(
            t, sizeof(t), "%.10s %s %s", p->name,
            hone_gadget_category_name((HoneGadgetCategory)g.category),
            hone_sec_class_name((HoneSecClass)g.sec_class));
        find_push(s, t);
        ST_LOCK(s);
        s->rec.st.gadgets++;
        if(g.sec_class == HoneSecFixed) s->rec.st.gadgets_fixed++;
        ST_UNLOCK(s);
    }
    memset(kd, 0, sizeof(kd));
}

static void jam_note(HoneSrv* s, uint8_t band, const HoneBodySubGhz* sg) {
    static HoneJam jam = {.round_max = -128};
    static uint32_t started_rtc, started_tick;
    HoneJamEvent ev = hone_jam_feed(&jam, band, sg->rssi_avg_dbm, sg->rssi_peak_dbm);
    if(ev == HoneJamNone) return;
    HoneBodyJam b = {.ver = 1, .bands = jam.bands, .max_avg_dbm = jam.max_avg};
    char l2[26];
    if(ev == HoneJamStarted) {
        started_rtc = furi_hal_rtc_get_timestamp();
        started_tick = furi_get_tick();
        b.flags = HONE_JAM_START;
        b.started = started_rtc;
        snprintf(l2, sizeof(l2), "%d dBm on %d bands", jam.max_avg, __builtin_popcount(jam.bands));
        alert_raise(s, "Sub-GHz JAMMING?", l2);
        find_push(s, "Sub-GHz jamming started");
    } else {
        b.flags = HONE_JAM_END;
        b.started = started_rtc;
        uint32_t d = (furi_get_tick() - started_tick) / furi_kernel_get_tick_frequency();
        b.duration_s = (uint16_t)MIN(d, 0xFFFFu);
        snprintf(l2, sizeof(l2), "jamming ended, %lus", (unsigned long)d);
        find_push(s, l2);
    }
    emit(s, HoneMsgJam, &b, sizeof(b));
    ST_LOCK(s);
    s->rec.st.jamming = jam.jamming;
    ST_UNLOCK(s);
}

/* ─── lanes ─────────────────────────────────────────────────────────────── */

#define HONE_LANE_STACK      (6 * 1024) /* ed25519 sign needs ~3 KB */
#define HONE_WIFI_RETRY_MS   15000      /* no board answering: try again later */

static int32_t subghz_lane(void* ctx) {
    HoneSrv* s = ctx;
    while(1) {
        if(!lane_enter(s, HoneLaneSubGhz)) {
            furi_delay_ms(1000);
            continue;
        }
        HoneBodySubGhz b;
        HoneDecodeWin win;
        uint8_t band;
        static uint8_t thin;
        bool got = capture_subghz(s, &b, &band, &win);
        lane_leave(s, HoneLaneSubGhz); /* radio is asleep again */
        if(got) {
            /* economy (SD full of undelivered data): keep 1 in 4 RSSI frames */
            if(!s->economy || (thin++ & 3) == 0) emit(s, HoneMsgSubGhz, &b, sizeof(b));
            gadgets_emit(s, &win, &b);
            jam_note(s, band, &b);
            ST_LOCK(s);
            s->rec.st.subghz_freq = b.freq_hz;
            s->rec.st.subghz_peak = b.rssi_peak_dbm;
            s->rec.st.subghz_avg = b.rssi_avg_dbm;
            s->rec.st.subghz_tick = furi_get_tick();
            ST_UNLOCK(s);
            FURI_LOG_D(TAG, "subghz %lu peak %d avg %d", b.freq_hz, b.rssi_peak_dbm, b.rssi_avg_dbm);
        } else {
            furi_delay_ms(1000);
        }
    }
    return 0;
}

/* Wi-Fi presence: probe senders per window (keyed oids, counted only),
 * channel load and deauth bursts. RAM only; sets reset with the window/day. */
#define HONE_WCROWD_WIN 256u
#define HONE_WCROWD_DAY 512u
#define HONE_DEAUTH_ATTACK 30u /* deauth+disassoc frames in one ~15 s listen */

typedef struct {
    uint32_t window, day;
    uint32_t* win;
    uint16_t win_n;
    uint16_t returning;
    uint32_t* today;
    uint16_t today_n;
} HoneWifiCrowd;

static bool set32_has(const uint32_t* set, uint16_t n, uint32_t v) {
    for(uint16_t i = 0; i < n; i++)
        if(set[i] == v) return true;
    return false;
}

static void wifi_crowd_note(HoneSrv* s, HoneWifiCrowd* c) {
    uint32_t utc = utc_now(s);
    uint32_t window = utc / HONE_WINDOW_S, day = utc / 86400u;
    if(!c->win) {
        c->win = malloc(HONE_WCROWD_WIN * sizeof(uint32_t));
        c->today = malloc(HONE_WCROWD_DAY * sizeof(uint32_t));
    }
    if(day != c->day) {
        c->day = day;
        c->today_n = 0; /* the board's oid key rotates with K_day */
    }
    if(window != c->window) {
        for(uint16_t i = 0; i < c->win_n && c->today_n < HONE_WCROWD_DAY; i++)
            if(!set32_has(c->today, c->today_n, c->win[i])) c->today[c->today_n++] = c->win[i];
        c->window = window;
        c->win_n = 0;
        c->returning = 0;
    }
    for(uint8_t i = 0; i < wx.pso_n; i++) {
        if(set32_has(c->win, c->win_n, wx.pso[i]) || c->win_n >= HONE_WCROWD_WIN) continue;
        c->win[c->win_n++] = wx.pso[i];
        if(set32_has(c->today, c->today_n, wx.pso[i])) c->returning++;
    }
    HoneBodyWifiCrowd b = {
        .ver = 1,
        .window = window,
        .scan_devices = wx.pso_n,
        .win_devices = c->win_n,
        .returning = c->returning,
        .deauth = wx.deauth,
        .flags = wx.deauth >= HONE_DEAUTH_ATTACK ? HONE_WIFI_ATTACK : 0,
    };
    memcpy(b.cu, wx.cu, sizeof(b.cu));
    emit(s, HoneMsgWifiCrowd, &b, sizeof(b));
    static uint32_t attack_tick;
    if((b.flags & HONE_WIFI_ATTACK) &&
       (!attack_tick || furi_get_tick() - attack_tick > furi_ms_to_ticks(10u * 60u * 1000u))) {
        attack_tick = furi_get_tick() ? furi_get_tick() : 1;
        char l2[48];
        snprintf(l2, sizeof(l2), "%u deauth frames / scan", wx.deauth);
        alert_raise(s, "Wi-Fi deauth attack?", l2);
        find_push(s, l2);
    }
}

/* Remember where we are: a new "place" when the strongest APs share nothing
 * with the last ones (tracker detection uses it; nothing is sent). */
static void place_note(HoneSrv* s, const HoneBodyWifi2* b2) {
    static uint32_t set[3];
    static uint32_t place;
    uint32_t now[3] = {0};
    uint8_t n = MIN(b2->n_top, 3);
    if(!n) return;
    bool overlap = false;
    for(uint8_t i = 0; i < n; i++) {
        memcpy(&now[i], b2->top[i].oid, 4);
        for(int k = 0; k < 3; k++) overlap |= set[k] && set[k] == now[i];
    }
    if(!place || !overlap) place++;
    memcpy(set, now, sizeof(set));
    s->loc_fp = place;
}

static void wifi_sec_note(HoneSrv* s) {
    static HoneBodyWifiSec last;
    emit(s, HoneMsgWifiSec, &wx.sec, sizeof(wx.sec));
    if(wx.sec.open > last.open || wx.sec.wep > last.wep) {
        char t[48];
        snprintf(
            t, sizeof(t), "Wi-Fi: %u open, %u WEP, %u WPS", wx.sec.open, wx.sec.wep, wx.sec.wps);
        find_push(s, t);
    }
    last = wx.sec;
    ST_LOCK(s);
    s->rec.st.wifi_sec_ok = true;
    s->rec.st.wifi_open = wx.sec.open;
    s->rec.st.wifi_wep = wx.sec.wep;
    s->rec.st.wifi_wpa = wx.sec.wpa;
    s->rec.st.wifi_wpa2 = wx.sec.wpa2;
    s->rec.st.wifi_wpa3 = wx.sec.wpa3;
    s->rec.st.wifi_ent = wx.sec.ent;
    s->rec.st.wifi_wps = wx.sec.wps;
    ST_UNLOCK(s);
}

/* Board presence. On USB power the board's 5 V comes from VBUS, so probing is
 * free: every minute. On battery an absent board is probed only at boot, when
 * USB power arrives, or when the Hone screen opens (someone just plugged it
 * in): no 5 V toggling for a board that is not there. */
static int32_t wifi_lane(void* ctx) {
    HoneSrv* s = ctx;
    uint32_t last = 0;
    bool was_ext = false;
    HoneWifiCrowd crowd = {0};
    while(1) {
        if(hone_should_yield(s)) {
            furi_delay_ms(1000);
            continue;
        }
        /* Read VBUS while our 5 V output is off, so it reflects real external power. */
        if(!furi_hal_power_is_otg_enabled())
            s->ext_power = furi_hal_power_get_usb_voltage() > HONE_EXT_POWER_V;
        if(s->ext_power && !was_ext) s->wifi_reprobe = true;
        if(s->rec.want_reprobe) {
            s->rec.want_reprobe = false;
            if(!s->wifi_board) s->wifi_reprobe = true;
        }
        was_ext = s->ext_power;
        bool due = !last ||
                   ((s->wifi_board || s->ext_power) &&
                    furi_get_tick() - last >= furi_ms_to_ticks(HONE_WIFI_EVERY_MS)) ||
                   s->wifi_reprobe;
        if(!due) {
            furi_delay_ms(1000);
            continue;
        }
        if(!lane_enter(s, HoneLaneWifi)) continue;
        s->wifi_reprobe = false;
        last = furi_get_tick();
        HoneBodyWifi b;
        HoneBodyWifi2 b2;
        bool v2;
        bool had = s->wifi_board;
        bool got = capture_wifi(s, &b, &b2, &v2);
        lane_leave(s, HoneLaneWifi); /* USART released, 5 V back as it was */
        if(s->wifi_board != had)
            find_push(s, s->wifi_board ? "Wi-Fi board attached" : "Wi-Fi board gone");
        if(got) {
            s->wifi_ok_tick = furi_get_tick();
            ST_LOCK(s);
            s->rec.st.wifi_aps = v2 ? b2.aps : b.aps;
            s->rec.st.wifi_probes = v2 ? b2.probes : b.probes;
            s->rec.st.wifi_tick = s->wifi_ok_tick;
            ST_UNLOCK(s);
            if(v2) {
                emit(s, HoneMsgWifi2, &b2, (uint8_t)(offsetof(HoneBodyWifi2, top) + b2.n_top * sizeof(HoneWifiAp)));
                FURI_LOG_I(
                    TAG, "wifi2 aps %u la %u top %u probes %u senders %u",
                    b2.aps, b2.la_aps, b2.n_top, b2.probes, b2.probe_senders);
                place_note(s, &b2);
                if(wx.sec_ok) wifi_sec_note(s);
                if(wx.crowd_ok) wifi_crowd_note(s, &crowd);
            } else {
                emit(s, HoneMsgWifi, &b, sizeof(b));
                FURI_LOG_I(TAG, "wifi aps %u best %d probes %u", b.aps, b.best_rssi, b.probes);
            }
        }
    }
    return 0;
}

/* ─── BLE lane: passive observer (spec 1b, 2a crowd, 1a sightings) ───────
 * Every HONE_BLE_EVERY_MS: a passive scan of HONE_BLE_SCAN_MS with duplicate
 * filtering (each advertiser reported about once per scan). Reports are copied
 * off the BLE event thread through a queue; addresses are turned into day-keyed
 * oids at once and never stored or sent. Needs the full radio stack; with the
 * light stack the lane only reports HONE_CROWD_NO_OBSERVER once per window. */

#define HONE_BLE_EVERY_MS     60000u
#define HONE_BLE_SCAN_MS      8000u
#define HONE_BLE_INTERVAL_MS  100u
#define HONE_BLE_WINDOW_MS    50u  /* 50 % duty inside the scan: leaves airtime for the adverts */
#define HONE_BLE_SCAN_SET     160u /* distinct advertisers per scan */
#define HONE_BLE_WIN_SET      384u /* distinct advertisers per window */
#define HONE_BLE_DAY_SET      768u /* 4-byte fingerprints of earlier windows today */
#define HONE_BLE_SIGHT_MAX    20u

typedef struct {
    HoneSrv* s;
    FuriMessageQueue* q;
    uint32_t dropped;
    /* current window */
    uint32_t window;
    uint64_t* win_set;
    uint16_t win_n;
    uint16_t win_returning;
    uint8_t scans;
    HoneSighting sight[HONE_BLE_SIGHT_MAX];
    uint8_t sight_n;
    /* 'hK' legacy halves waiting for their other half, joined by (win8, tag) */
    struct {
        uint8_t win8, tag[2], have;
        int8_t rssi;
        uint8_t pk[32];
    } half[8];
    uint8_t half_next;
    /* today */
    uint32_t day;
    uint32_t* day_fp;
    uint16_t day_n;
    /* current scan */
    uint64_t* scan_set;
    uint16_t scan_n;
    HoneBodyBleCrowd crowd;
    /* tracker tags (Find My, Tile, SmartTag, Chipolo, Google): RAM only; the
     * key is the day-keyed oid, so the table is meaningless after midnight */
    struct {
        uint32_t tok;
        uint32_t first, last; /* ticks */
        uint32_t win_last;    /* last window it was heard in */
        uint32_t place[2];    /* distinct places (Wi-Fi fingerprints) it was heard at */
        uint8_t kind, wins, nplace;
        bool alerted;
    } trk[24];
    uint8_t trk_n;
    uint8_t win_trk[HoneTrackerKinds];
    uint8_t win_following;
    uint8_t win_skim;
    uint32_t skim_tick;
} HoneBle;

#define HONE_FOLLOW_WINDOWS 3                    /* heard in 3+ quarter-hours */
#define HONE_FOLLOW_SPAN_MS (45u * 60u * 1000u)  /* over 45+ minutes */
#define HONE_FOLLOW_SPAN_NOWIFI_MS (90u * 60u * 1000u)

static void tracker_seen(HoneBle* b, HoneTrackerKind k, uint32_t tok) {
    uint32_t now = furi_get_tick();
    uint32_t place = b->s->loc_fp;
    int e = -1, oldest = 0;
    for(int i = 0; i < b->trk_n; i++) {
        if(b->trk[i].tok == tok && b->trk[i].kind == k) e = i;
        if(b->trk[i].last < b->trk[oldest].last) oldest = i;
    }
    if(e < 0) {
        e = (size_t)b->trk_n < COUNT_OF(b->trk) ? b->trk_n++ : oldest;
        memset(&b->trk[e], 0, sizeof(b->trk[e]));
        b->trk[e].tok = tok;
        b->trk[e].kind = (uint8_t)k;
        b->trk[e].first = now;
        ST_LOCK(b->s);
        b->s->rec.st.trackers++;
        ST_UNLOCK(b->s);
    }
    typeof(b->trk[0])* t = &b->trk[e];
    t->last = now;
    if(t->win_last != b->window) {
        t->win_last = b->window;
        if(t->wins < 255) t->wins++;
        if(b->win_trk[k] < 255) b->win_trk[k]++;
    }
    if(place && t->nplace < 2 && (t->nplace == 0 || t->place[0] != place))
        t->place[t->nplace++] = place;
    uint32_t span = now - t->first;
    bool follows = t->wins >= HONE_FOLLOW_WINDOWS &&
                   ((span >= furi_ms_to_ticks(HONE_FOLLOW_SPAN_MS) && t->nplace >= 2) ||
                    (!place && span >= furi_ms_to_ticks(HONE_FOLLOW_SPAN_NOWIFI_MS)));
    if(follows && !t->alerted) {
        t->alerted = true;
        if(b->win_following < 255) b->win_following++;
        char l2[26];
        snprintf(
            l2, sizeof(l2), "%s %ux, %lu min", hone_tracker_name(k), t->wins,
            (unsigned long)(span / furi_kernel_get_tick_frequency() / 60));
        alert_raise(b->s, "Tracker following you?", l2);
        find_push(b->s, l2);
        ST_LOCK(b->s);
        b->s->rec.st.following++;
        ST_UNLOCK(b->s);
    }
}

/* Trackers and skimmer-module names in one advertising report. */
static void ble_threats(HoneBle* b, const GapObserverReport* r, uint64_t oid) {
    HoneTrackerKind k = hone_ble_tracker_kind(r->data, r->data_len);
    if(k < HoneTrackerKinds) tracker_seen(b, k, (uint32_t)(oid >> 32));
    char name[16];
    if(hone_ble_skimmer_name(r->data, r->data_len, name, sizeof(name))) {
        if(b->win_skim < 255) b->win_skim++;
        /* close (a pump's card reader is an arm's length away) and not
         * repeated more than every 10 min */
        if(r->rssi != 127 && r->rssi >= -75 &&
           (!b->skim_tick ||
            furi_get_tick() - b->skim_tick > furi_ms_to_ticks(10u * 60u * 1000u))) {
            b->skim_tick = furi_get_tick() ? furi_get_tick() : 1;
            char l2[26];
            snprintf(l2, sizeof(l2), "\"%.10s\" %d dBm", name, r->rssi);
            alert_raise(b->s, "Skimmer module nearby?", l2);
            find_push(b->s, l2);
        }
    }
}

static void ble_report_cb(const GapObserverReport* r, void* ctx) {
    HoneBle* b = ctx;
    if(furi_message_queue_put(b->q, r, 0) != FuriStatusOk) b->dropped++;
}

static bool set64_add(uint64_t* set, uint16_t* n, uint16_t cap, uint64_t v) {
    for(uint16_t i = 0; i < *n; i++)
        if(set[i] == v) return false;
    if(*n < cap) set[(*n)++] = v;
    return true;
}

static bool fp_has(const uint32_t* set, uint16_t n, uint32_t v) {
    for(uint16_t i = 0; i < n; i++)
        if(set[i] == v) return true;
    return false;
}

static void sight_note(HoneBle* b, uint8_t kind, uint8_t win8, const uint8_t* id, size_t id_len, int8_t rssi) {
    for(uint8_t i = 0; i < b->sight_n; i++) {
        HoneSighting* e = &b->sight[i];
        if(e->kind == kind && memcmp(e->id, id, id_len) == 0) {
            if(rssi > e->rssi_max) e->rssi_max = rssi;
            if(e->hits < 255) e->hits++;
            return;
        }
    }
    if(b->sight_n >= HONE_BLE_SIGHT_MAX) return;
    HoneSighting* e = &b->sight[b->sight_n++];
    memset(e, 0, sizeof(*e));
    e->kind = kind;
    e->win8 = win8;
    e->rssi_max = rssi;
    e->hits = 1;
    memcpy(e->id, id, id_len);
}

static void ble_half(HoneBle* b, const uint8_t* m, int8_t rssi) {
    /* m: 'h' 'K' 02 win8 frag tag[2] pk16 */
    uint8_t idx = m[4] >> 4, win8 = m[3];
    for(uint8_t i = 0; i < COUNT_OF(b->half); i++) {
        if(b->half[i].have && b->half[i].win8 == win8 && memcmp(b->half[i].tag, m + 5, 2) == 0) {
            memcpy(b->half[i].pk + 16 * idx, m + 7, 16);
            b->half[i].have |= 1 << idx;
            if(rssi > b->half[i].rssi) b->half[i].rssi = rssi;
            if(b->half[i].have == 3) {
                uint8_t lid[32];
                mbedtls_sha256(b->half[i].pk, 32, lid, 0);
                sight_note(b, HoneSightLookup, win8, lid, 16, b->half[i].rssi);
                b->half[i].have = 0;
            }
            return;
        }
    }
    uint8_t i = b->half_next++ % COUNT_OF(b->half);
    b->half[i].win8 = win8;
    memcpy(b->half[i].tag, m + 5, 2);
    memset(b->half[i].pk, 0, 32);
    memcpy(b->half[i].pk + 16 * idx, m + 7, 16);
    b->half[i].have = 1 << idx;
    b->half[i].rssi = rssi;
}

/* HONE adverts inside one report (manufacturer data, company 0xFFFF):
 *   'h' 'K' 02 win8 frag tag[2] pk  window key (Android IdAdvertiser, this firmware):
 *                                   lookup id = sha256(pk_w)[0..16]. Legacy halves
 *                                   (frag 0x02/0x12) are joined; extended (0x01) is
 *                                   not received by this stack.
 *   'h' 'R' 0x01 win8 rid[16]       older rid advert (Android SIGHTINGS.md v1)
 *   'H' 'A' seq idx|total frame...  Flipper announce; fragment 0 carries the header
 *                                   (magic 2, type 1, len 1, device_id 8) */
static void ble_hone_parse(HoneBle* b, const GapObserverReport* r) {
    const uint8_t* d = r->data;
    size_t n = r->data_len;
    for(size_t off = 0; off + 1 < n;) {
        uint8_t l = d[off];
        if(!l || off + 1 + l > n) break;
        const uint8_t* ad = d + off + 1; /* ad[0] = type */
        if(ad[0] == 0xFF && l >= 5 && ad[1] == 0xFF && ad[2] == 0xFF) {
            const uint8_t* m = ad + 3;
            size_t ml = l - 3;
            if(ml >= 23 && m[0] == 'h' && m[1] == 'K' && m[2] == 0x02 &&
               (m[4] & 0x0F) == 2 && (m[4] >> 4) < 2) {
                ble_half(b, m, r->rssi);
            } else if(ml >= 39 && m[0] == 'h' && m[1] == 'K' && m[2] == 0x02 && m[4] == 0x01) {
                uint8_t lid[32];
                mbedtls_sha256(m + 7, 32, lid, 0);
                sight_note(b, HoneSightLookup, m[3], lid, 16, r->rssi);
            } else if(ml >= 20 && m[0] == 'h' && m[1] == 'R' && m[2] == 0x01) {
                sight_note(b, HoneSightRid, m[3], m + 4, 16, r->rssi);
            } else if(ml >= 4 + 12 && m[0] == 'H' && m[1] == 'A' && (m[3] >> 4) == 0 &&
                      m[4] == HONE_V2_MAGIC0 && m[5] == HONE_V2_MAGIC1) {
                sight_note(b, HoneSightFlipper, 0, m + 8, HONE_DEVICE_ID_LEN, r->rssi);
            }
        }
        off += 1 + l;
    }
}

static void ble_take(HoneBle* b, const GapObserverReport* r, const uint8_t k_day[32]) {
    b->crowd.reports++;
    /* oid over the 6 address bytes only (spec 1b: HMAC(K_day, mac)) */
    uint8_t d[32];
    hmac_sha256(k_day, 32, r->addr, 6, NULL, 0, d);
    uint64_t oid;
    memcpy(&oid, d, sizeof(oid));
    memset(d, 0, sizeof(d));
    ble_hone_parse(b, r);
    if(!set64_add(b->scan_set, &b->scan_n, HONE_BLE_SCAN_SET, oid)) return; /* scan response etc. */
    ble_threats(b, r, oid);
    if(r->addr_type & 1) b->crowd.random_addr++;
    if(r->rssi != 127) {
        int8_t v = r->rssi;
        int bin = v < -90 ? 0 : v < -80 ? 1 : v < -70 ? 2 : v < -60 ? 3 : v < -50 ? 4 : v < -40 ? 5 : 6;
        if(b->crowd.rssi_hist[bin] < 255) b->crowd.rssi_hist[bin]++;
        if(b->crowd.rssi_max == 0 || v > b->crowd.rssi_max) b->crowd.rssi_max = v;
    }
    if(set64_add(b->win_set, &b->win_n, HONE_BLE_WIN_SET, oid)) {
        if(fp_has(b->day_fp, b->day_n, (uint32_t)oid)) b->win_returning++;
    }
}

static uint8_t sight_count(const HoneBle* b, uint8_t kind) {
    uint8_t n = 0;
    for(uint8_t i = 0; i < b->sight_n; i++)
        if(b->sight[i].kind == kind) n++;
    return n;
}

static void ble_emit_crowd(HoneBle* b, uint8_t flags) {
    HoneBodyBleCrowd* c = &b->crowd;
    c->ver = 1;
    c->flags |= flags;
    c->window = b->window;
    c->seen = b->scan_n;
    c->win_distinct = b->win_n;
    c->win_returning = b->win_returning;
    c->hone_rids = sight_count(b, HoneSightRid) + sight_count(b, HoneSightLookup);
    c->hone_flippers = sight_count(b, HoneSightFlipper);
    c->scans = b->scans;
    emit(b->s, HoneMsgBleCrowd, c, sizeof(*c));
    FURI_LOG_I(
        TAG, "ble w%lu scan %u win %u ret %u rids %u flippers %u%s",
        c->window, c->seen, c->win_distinct, c->win_returning, c->hone_rids, c->hone_flippers,
        (c->flags & HONE_CROWD_FINAL) ? " final" : "");
}

/* Close the window: final crowd frame, sightings frames, fold the window's
 * oids into today's fingerprints. */
static void ble_close_window(HoneBle* b, uint32_t day) {
    if(b->window && (b->scans || (b->crowd.flags & HONE_CROWD_NO_OBSERVER))) {
        memset(&b->crowd, 0, sizeof(b->crowd));
        b->crowd.flags = b->s->observer_ok ? 0 : HONE_CROWD_NO_OBSERVER;
        b->scan_n = 0;
        ble_emit_crowd(b, HONE_CROWD_FINAL);
        for(uint8_t i = 0; i < b->sight_n; i += HONE_SIGHTINGS_PER_FRAME) {
            HoneBodySighting f = {.ver = 1, .window = b->window};
            f.n = (uint8_t)MIN((unsigned)HONE_SIGHTINGS_PER_FRAME, (unsigned)(b->sight_n - i));
            memcpy(f.s, b->sight + i, f.n * sizeof(HoneSighting));
            emit(b->s, HoneMsgSighting, &f, (uint8_t)(offsetof(HoneBodySighting, s) + f.n * sizeof(HoneSighting)));
        }
        if(b->sight_n) FURI_LOG_I(TAG, "sightings w%lu: %u", b->window, b->sight_n);
    }
    /* trackers / skimmer names this window: counts only */
    bool threats = b->win_following || b->win_skim;
    for(int k = 0; k < HoneTrackerKinds; k++) threats |= b->win_trk[k] != 0;
    if(b->window && threats) {
        HoneBodyBleThreat t = {
            .ver = 1,
            .window = b->window,
            .following = b->win_following,
            .skimmer_names = b->win_skim,
        };
        memcpy(t.trackers, b->win_trk, sizeof(t.trackers));
        emit(b->s, HoneMsgBleThreat, &t, sizeof(t));
    }
    memset(b->win_trk, 0, sizeof(b->win_trk));
    b->win_following = 0;
    b->win_skim = 0;
    if(day != b->day) {
        b->day = day;
        b->day_n = 0; /* new K_day: yesterday's oids mean nothing now */
        b->trk_n = 0; /* tracker tokens are day-keyed too */
    } else {
        for(uint16_t i = 0; i < b->win_n && b->day_n < HONE_BLE_DAY_SET; i++) {
            uint32_t fp = (uint32_t)b->win_set[i];
            if(!fp_has(b->day_fp, b->day_n, fp)) b->day_fp[b->day_n++] = fp;
        }
    }
    b->win_n = 0;
    b->win_returning = 0;
    b->scans = 0;
    b->sight_n = 0;
    memset(b->half, 0, sizeof(b->half));
    memset(&b->crowd, 0, sizeof(b->crowd));
}

static int32_t ble_lane(void* ctx) {
    HoneSrv* s = ctx;
    furi_record_open(RECORD_BT); /* blocks until the BT service is up */
    furi_record_close(RECORD_BT);

    HoneBle* b = malloc(sizeof(HoneBle));
    memset(b, 0, sizeof(*b));
    b->s = s;
    b->q = furi_message_queue_alloc(48, sizeof(GapObserverReport));
    b->scan_set = malloc(HONE_BLE_SCAN_SET * sizeof(uint64_t));
    b->win_set = malloc(HONE_BLE_WIN_SET * sizeof(uint64_t));
    b->day_fp = malloc(HONE_BLE_DAY_SET * sizeof(uint32_t));
    uint8_t k_day[32];
    uint32_t last_scan = 0;
    bool warned = false;

    while(1) {
        if(hone_should_yield(s)) {
            furi_delay_ms(1000);
            continue;
        }
        uint32_t day;
        k_day_get(s, k_day, &day);
        uint32_t window = utc_now(s) / HONE_WINDOW_S;
        if(window != b->window) {
            ble_close_window(b, day);
            b->window = window;
        }
        if(last_scan && furi_get_tick() - last_scan < furi_ms_to_ticks(HONE_BLE_EVERY_MS)) {
            furi_delay_ms(500);
            continue;
        }
        if(!lane_enter(s, HoneLaneBle)) continue;
        last_scan = furi_get_tick();

        s->observer_ok = gap_observer_supported();
        if(!s->observer_ok) {
            lane_leave(s, HoneLaneBle);
            if(!warned) FURI_LOG_W(TAG, "ble: radio stack cannot scan (light stack?)");
            warned = true;
            b->crowd.flags |= HONE_CROWD_NO_OBSERVER;
            continue;
        }
        warned = false;
        memset(&b->crowd, 0, sizeof(b->crowd));
        b->scan_n = 0;
        b->dropped = 0;
        furi_message_queue_reset(b->q);
        bool held = false;
        if(!gap_observer_start(HONE_BLE_INTERVAL_MS, HONE_BLE_WINDOW_MS, ble_report_cb, b)) {
            /* No free radio slot (e.g. a phone connected): borrow the extra
             * beacon's slot for this scan. */
            s->beacon_hold = true;
            for(int i = 0; i < 60 && !s->beacon_held; i++) furi_delay_ms(100);
            held = true;
            if(!s->beacon_held ||
               !gap_observer_start(HONE_BLE_INTERVAL_MS, HONE_BLE_WINDOW_MS, ble_report_cb, b)) {
                s->beacon_hold = false;
                lane_leave(s, HoneLaneBle);
                FURI_LOG_W(TAG, "ble: scan start refused");
                continue;
            }
        }
        uint32_t t0 = furi_get_tick();
        GapObserverReport r;
        while(furi_get_tick() - t0 < furi_ms_to_ticks(HONE_BLE_SCAN_MS) && !hone_should_yield(s)) {
            if(furi_message_queue_get(b->q, &r, furi_ms_to_ticks(100)) == FuriStatusOk)
                ble_take(b, &r, k_day);
        }
        gap_observer_stop();
        if(held) s->beacon_hold = false;
        lane_leave(s, HoneLaneBle); /* no more stack calls from this lane */
        uint32_t scan_ms = (furi_get_tick() - t0) * 1000 / furi_kernel_get_tick_frequency();
        while(furi_message_queue_get(b->q, &r, 0) == FuriStatusOk) ble_take(b, &r, k_day);
        b->crowd.scan_ms = (uint16_t)MIN(scan_ms, 0xFFFFu);
        if(b->scans < 255) b->scans++;
        if(b->dropped) FURI_LOG_D(TAG, "ble: %lu reports dropped", b->dropped);
        ble_emit_crowd(b, 0);
        ST_LOCK(s);
        s->rec.st.observer_ok = s->observer_ok;
        s->rec.st.ble_seen = b->crowd.seen;
        s->rec.st.ble_window = b->crowd.win_distinct;
        s->rec.st.ble_tick = furi_get_tick();
        ST_UNLOCK(s);
    }
    return 0;
}

/* ─── announce lane: signed BLE broadcast any HONE device can verify ───── */

#define HONE_ANNOUNCE_EVERY_MS 30000 /* re-sign with fresh counter/state */
#define HONE_FRAG_MS           200   /* one fragment per beacon update */
#define HONE_FRAG_DATA         23    /* 31-byte advert minus 8 header bytes */
#define HONE_BEACON_COMPANY    0xFFFF /* BT SIG "testing" ID until HONE has its own */

/* Advert (31 B): [len][0xFF][company lo][company hi]['H']['A'][seq][idx<<4 | total][data <= 23]
 * Receivers collect idx 0..total-1 with the same seq, concatenate, verify the
 * ed25519 signature with the pubkey inside the body, then look the key up on chain. */
static size_t build_announce(HoneSrv* s, uint8_t* out) {
    HoneBodyAnnounce b = {
        .caps = HONE_CAP_SUBGHZ | HONE_CAP_NFC | HONE_CAP_RFID | HONE_CAP_IBUTTON | HONE_CAP_IR,
        .battery_pct = furi_hal_power_get_pct(),
    };
    memcpy(b.pubkey, s->pk, 32);
    memcpy(b.owner, s->owner, sizeof(b.owner));
    if(s->wifi_board) b.caps |= HONE_CAP_WIFI; /* board attached (last probe) */
    b.caps |= HONE_CAP_BLE | HONE_CAP_READERS;
    if(s->observer_ok) b.caps |= HONE_CAP_BLE_OBS;
    if(s->seed_ok) b.caps |= HONE_CAP_RID;
    if(s->ext_power) b.flags |= HONE_FLAG_EXT_POWER;
    if(s->paused) b.flags |= HONE_FLAG_PAUSED;

    furi_check(furi_mutex_acquire(s->emit_lock, FuriWaitForever) == FuriStatusOk);
    b.last_counter = s->counter ? s->counter - 1 : 0;
    size_t len = hone_frame_build(
        out, HoneMsgAnnounce, &b, sizeof(b), s->pk, s->sk, counter_next(s), s->anchor, NULL);
    furi_mutex_release(s->emit_lock);
    return len;
}

/* Advert (31 B): [len][0xFF][company lo][company hi]['H'][kind][seq][idx<<4 | total][data <= 23]
 * kind 'A' = signed announce frame, 'C' = signed batch commit. */
static void send_fragments(
    const HoneSrv* s,
    uint8_t* adv, char kind, uint8_t seq, const uint8_t* data, size_t len, bool* started) {
    uint8_t total = (uint8_t)((len + HONE_FRAG_DATA - 1) / HONE_FRAG_DATA);
    for(uint8_t i = 0; i < total && !hone_should_yield(s); i++) {
        size_t off = (size_t)i * HONE_FRAG_DATA;
        size_t n = MIN((size_t)HONE_FRAG_DATA, len - off);
        adv[0] = (uint8_t)(7 + n);
        adv[1] = 0xFF;
        adv[2] = HONE_BEACON_COMPANY & 0xFF;
        adv[3] = HONE_BEACON_COMPANY >> 8;
        adv[4] = 'H';
        adv[5] = (uint8_t)kind;
        adv[6] = seq;
        adv[7] = (uint8_t)((i << 4) | total);
        memcpy(adv + 8, data + off, n);
        furi_hal_bt_extra_beacon_set_data(adv, (uint8_t)(8 + n));
        if(!*started) *started = furi_hal_bt_extra_beacon_start();
        furi_delay_ms(HONE_FRAG_MS);
    }
}

/* ─── rotating id advert (spec 1a) ────────────────────────────────────────
 * The beacon is time-shared: HA fragments + one HC commit on the fixed HONE
 * address, then the window key advert. pk_w and both advert addresses are
 * derived from (seed, window) at the start of every slot and the slot is cut at
 * the quarter-hour, so key and address change together at the boundary.
 * Format = Android IdAdvertiser legacy fallback, two adverts joined by (win8, tag):
 *   [0x1A][0xFF][0xFF 0xFF]['h']['K'][0x02][win8][0x02 | 0x12][tag 2][pk_w 16 of 32]
 * Each half goes out on its own address (one per half, like Android's two sets),
 * so observers that filter duplicates per address still get both. */
#define HONE_ID_HALF_MS 800u

static void id_slot(HoneSrv* s, HoneWindowKey* key, const GapExtraBeaconConfig* home, bool* started) {
    uint32_t utc = utc_now(s);
    uint32_t window = utc / HONE_WINDOW_S;
    if(!window_key(s, window, key)) return;
    uint32_t left_ms = (HONE_WINDOW_S - utc % HONE_WINDOW_S) * 1000u;
    if(*started) furi_hal_bt_extra_beacon_stop();
    *started = false;
    for(uint8_t half = 0; half < 2 && left_ms && !hone_should_yield(s); half++) {
        GapExtraBeaconConfig cfg = *home;
        cfg.address_type = GapAddressTypeRandom;
        memcpy(cfg.address, key->addr[half], 6);
        uint8_t adv[27] = {
            0x1A, 0xFF, 0xFF, 0xFF, 'h', 'K', 0x02, (uint8_t)(window & 0xFF),
            (uint8_t)((half << 4) | 2), key->tag[0], key->tag[1]};
        memcpy(adv + 11, key->pk + 16 * half, 16);
        uint32_t hold = MIN(HONE_ID_HALF_MS, left_ms);
        if(furi_hal_bt_extra_beacon_set_config(&cfg) &&
           furi_hal_bt_extra_beacon_set_data(adv, sizeof(adv)) && furi_hal_bt_extra_beacon_start()) {
            furi_delay_ms(hold);
            furi_hal_bt_extra_beacon_stop();
        }
        left_ms -= hold;
    }
    /* back to the HONE address; send_fragments restarts the beacon */
    furi_hal_bt_extra_beacon_set_config(home);
}

/* Signed chain head ('HH' beacon, 96 bytes): devid8 | seq | rtc | head16 | sig,
 * sig = ed25519 over "HH1" | devid8 | seq | rtc | head16. A phone that later
 * gets the frames recomputes the chain and checks it ends in this head; the
 * head is out in the air (and in heads.bin) from the moment it was signed, so
 * frames cannot be backdated or swapped after the fact. Re-signs only when the
 * log has moved; otherwise keeps the last one (returns its length). */
static size_t build_head(HoneSrv* s, uint8_t* out, size_t have) {
    static uint32_t signed_seq;
    uint8_t head[16];
    furi_check(furi_mutex_acquire(s->emit_lock, FuriWaitForever) == FuriStatusOk);
    uint32_t seq = s->chain_seq;
    memcpy(head, s->chain_head, 16);
    furi_mutex_release(s->emit_lock);
    if(!seq || (have && seq == signed_seq)) return have;
    uint32_t rtc = furi_hal_rtc_get_timestamp();
    uint8_t msg[3 + 8 + 4 + 4 + 16];
    memcpy(msg, "HH1", 3);
    memcpy(msg + 3, s->pk, 8);
    memcpy(msg + 11, &seq, 4);
    memcpy(msg + 15, &rtc, 4);
    memcpy(msg + 19, head, 16);
    memcpy(out, msg + 3, 32);
    hone_ed25519_sign(out + 32, msg, sizeof(msg), s->sk);
    signed_seq = seq;
    HoneHeadRec r = {.seq = seq, .rtc = rtc};
    memcpy(r.head, head, 16);
    memcpy(r.sig, out + 32, 64);
    File* f = storage_file_alloc(s->storage);
    if(storage_file_open(f, HONE_HEADS_PATH, FSAM_WRITE, FSOM_OPEN_APPEND))
        storage_file_write(f, &r, sizeof(r));
    storage_file_close(f);
    storage_file_free(f);
    return 96;
}
static int32_t announce_lane(void* ctx) {
    HoneSrv* s = ctx;
    furi_record_open(RECORD_BT); /* blocks until the BT service is up */
    furi_record_close(RECORD_BT);

    GapExtraBeaconConfig cfg = {
        .min_adv_interval_ms = 100,
        .max_adv_interval_ms = 150,
        .adv_channel_map = GapAdvChannelMapAll,
        .adv_power_level = GapAdvPowerLevel_0dBm,
        .address_type = GapAddressTypePublic,
    };
    memcpy(cfg.address, furi_hal_version_get_ble_mac(), sizeof(cfg.address));
    cfg.address[0] ^= 0xFF; /* distinct from the main advertising address */
    cfg.address[3] ^= 0xFF;
    if(!furi_hal_bt_extra_beacon_set_config(&cfg)) {
        FURI_LOG_E(TAG, "announce: beacon config refused");
        return 0;
    }

    uint8_t frame[HONE_FRAME_MAX];
    uint8_t adv[31];
    size_t len = 0;
    uint32_t built = 0;
    uint8_t seq = 0;
    uint8_t rr = 0;
    bool started = false;
    HoneWindowKey idkey = {0};
    uint8_t hh[8 + 4 + 4 + 16 + 64]; /* devid | seq | rtc | head16 | sig */
    size_t hh_len = 0;
    uint32_t hh_tick = 0;
    while(1) {
        if(s->beacon_hold) {
            if(started) furi_hal_bt_extra_beacon_stop();
            started = false;
            s->beacon_held = true;
            while(s->beacon_hold) furi_delay_ms(100);
            s->beacon_held = false;
            continue;
        }
        if(!lane_enter(s, HoneLaneAnnounce)) {
            /* parked; never touch the stack while another app may be
             * restarting it (the beacon was stopped when we parked) */
            if(started && !s->app_hold) furi_hal_bt_extra_beacon_stop();
            if(!s->app_hold) started = false;
            furi_delay_ms(500);
            continue;
        }
        if(!len || furi_get_tick() - built > furi_ms_to_ticks(HONE_ANNOUNCE_EVERY_MS)) {
            len = build_announce(s, frame);
            built = furi_get_tick();
            seq++;
        }
        send_fragments(s, adv, 'A', seq, frame, len, &started);
        /* signed chain head ('HH'), re-signed when the log moved (<= every 30 s) */
        if(!hh_len || furi_get_tick() - hh_tick > furi_ms_to_ticks(HONE_ANNOUNCE_EVERY_MS)) {
            hh_tick = furi_get_tick();
            hh_len = build_head(s, hh, hh_len);
        }
        if(hh_len) send_fragments(s, adv, 'H', hh[8], hh, hh_len, &started);
        batches_flush(s);
        /* One commit per cycle, round-robin, so the announce (which receivers need
         * first) keeps most of the airtime. */
        for(int tries = 0; tries < HONE_COMMIT_SLOTS; tries++) {
            HoneCommit* c = &s->commits[rr];
            rr = (rr + 1) % HONE_COMMIT_SLOTS;
            if(!c->made) continue;
            if(furi_get_tick() - c->made > furi_ms_to_ticks(HONE_COMMIT_TTL_MS)) {
                c->made = 0;
                continue;
            }
            send_fragments(s, adv, 'C', c->seq, c->data, HONE_COMMIT_LEN, &started);
            break;
        }
        if(s->seed_ok) id_slot(s, &idkey, &cfg, &started);
        if(hone_should_yield(s) && started) {
            furi_hal_bt_extra_beacon_stop();
            started = false;
        }
        lane_leave(s, HoneLaneAnnounce);
        ST_LOCK(s);
        s->rec.st.beacon_on = started;
        s->rec.st.id_advert = s->seed_ok;
        s->rec.st.announce_seq = seq;
        s->rec.st.announce_tick = built;
        ST_UNLOCK(s);
    }
    return 0;
}

static void lane_start(const char* name, FuriThreadCallback cb, HoneSrv* s) {
    FuriThread* t = furi_thread_alloc_ex(name, HONE_LANE_STACK, cb, s);
    furi_thread_start(t); /* lanes run for the life of the firmware */
}

/* ─── service entry ─────────────────────────────────────────────────────── */

int32_t hone_srv(void* p) {
    UNUSED(p);
    HoneSrv* s = malloc(sizeof(HoneSrv));
    memset(s, 0, sizeof(HoneSrv));
    s->rec.lock = furi_mutex_alloc(FuriMutexTypeNormal);
    s->otg_lock = furi_mutex_alloc(FuriMutexTypeNormal);
    s->tim_lock = furi_mutex_alloc(FuriMutexTypeNormal);
    strlcpy(s->rec.st.fw, HONE_FW_VERSION, sizeof(s->rec.st.fw));
    strlcpy(s->rec.st.boot_reason, "(waiting for SD card)", sizeof(s->rec.st.boot_reason));
    furi_record_create(RECORD_HONE, &s->rec);
    s->storage = furi_record_open(RECORD_STORAGE);

    /* kiskadee head in the desktop status bar: eye shut = paused/yielding */
    ViewPort* icon = view_port_alloc();
    view_port_set_width(icon, 9);
    view_port_draw_callback_set(icon, statusbar_draw, s);
    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, icon, GuiLayerStatusBarLeft);
    furi_record_close(RECORD_GUI);

    /* Wait for the SD card: identity, counter and queue all live there. */
    while(storage_sd_status(s->storage) != FSE_OK) {
        furi_delay_ms(1000);
    }
    storage_simply_mkdir(s->storage, HONE_DIR);
    boot_record(s);

    identity_load_or_create(s);
    counter_load(s);
    chain_load(s); /* before any lane can emit */
    read_file(s->storage, HONE_ANCHOR_PATH, s->anchor, HONE_ANCHOR_LEN);
    owner_load(s);
    s->seed_lock = furi_mutex_alloc(FuriMutexTypeNormal);
    s->kday_lock = furi_mutex_alloc(FuriMutexTypeNormal);
    s->utc_offset_min = HONE_UTC_OFFSET_DEFAULT;
    tz_load(s);
    seed_load(s);
    hone_sched_init(&s->sched);
    hone_sched_set_enabled(&s->sched, HoneSensorSubGhz, false); /* own lane */
    hone_sched_set_enabled(&s->sched, HoneSensorWifi, false);   /* own lane */
    s->emit_lock = furi_mutex_alloc(FuriMutexTypeNormal);

    /* The Wi-Fi dev board sits on USART; stop the expansion-module listener
     * from claiming that port. */
    Expansion* expansion = furi_record_open(RECORD_EXPANSION);
    expansion_disable(expansion);
    furi_record_close(RECORD_EXPANSION);
    s->paused = storage_file_exists(s->storage, HONE_MAINT_PATH);
    FURI_LOG_I(TAG, "started, counter %lu", s->counter);
    lane_start("HoneSubGhz", subghz_lane, s);
    lane_start("HoneWifi", wifi_lane, s);
    lane_start("HoneAnnounce", announce_lane, s);
    lane_start("HoneBle", ble_lane, s);

    /* Release the sensors whenever another app starts (see lane_enter). */
    Loader* loader = furi_record_open(RECORD_LOADER);
    furi_pubsub_subscribe(loader_get_pubsub(loader), loader_event_cb, s);
    /* Show the Hone screen once after boot, so HONE is visible on the device.
     * The loader can be busy right after boot (update result, PIN lock):
     * retry for about a minute, then give up quietly. */
    uint8_t autostart_left = 12;
    uint32_t autostart_tick = furi_get_tick();

    static const char* const sensor_name[HoneSensorCount] =
        {"Sub-GHz", "NFC", "RFID", "iButton", "IR", "Wi-Fi", "heartbt", "readers"};
    uint32_t last_maint_check = furi_get_tick();
    uint32_t last_sd_check = 0;
    s->notif = furi_record_open(RECORD_NOTIFICATION);
    bool shown_yield = false;
    while(1) {
        if(furi_get_tick() - last_maint_check > furi_ms_to_ticks(5000)) {
            s->paused = storage_file_exists(s->storage, HONE_MAINT_PATH);
            owner_load(s); /* picks up a claim without a reboot */
            seed_load(s);  /* and a provisioned (or removed) id seed */
            tz_load(s);
            ST_LOCK(s);
            memcpy(s->rec.st.owner, s->owner, sizeof(s->owner));
            s->rec.st.owner[sizeof(s->owner)] = 0;
            ST_UNLOCK(s);
            last_maint_check = furi_get_tick();
        }
        /* BeforeLoad has no matching event when a start is refused (app not
         * found, loader locked): drop a hold that has no running app behind it. */
        if(s->app_hold && furi_get_tick() - s->hold_tick > furi_ms_to_ticks(5000) &&
           !loader_is_locked(loader)) {
            s->app_hold = false;
            s->rec.ui_open = false;
        }
        if(autostart_left &&
           furi_get_tick() - autostart_tick > furi_ms_to_ticks(5000)) {
            autostart_tick = furi_get_tick();
            autostart_left--;
            if(!loader_is_locked(loader) &&
               loader_start(loader, "Hone", NULL, NULL) == LoaderStatusOk)
                autostart_left = 0;
        }
        if(!last_sd_check || furi_get_tick() - last_sd_check > furi_ms_to_ticks(5u * 60u * 1000u)) {
            sd_manage(s);
            last_sd_check = furi_get_tick();
        }
        /* an alert wants the owner's eyes: open the Hone screen if nothing else runs */
        if(s->want_screen) {
            s->want_screen = false;
            if(!loader_is_locked(loader)) loader_start(loader, "Hone", NULL, NULL);
        }
        bool yield = hone_should_yield(s);
        if(yield != shown_yield) {
            shown_yield = yield;
            ST_LOCK(s);
            s->rec.st.paused = s->paused;
            s->rec.st.yielding = yield && !s->paused;
            ST_UNLOCK(s);
            view_port_update(icon);
        }
        if(yield) {
            furi_delay_ms(500);
            continue;
        }
        hone_sched_set_battery(&s->sched, furi_hal_power_get_pct());
        HoneSensorKind k = hone_sched_next(&s->sched);
        if(k >= HoneSensorCount) {
            /* every tag sensor is backed off (no card, no remote): idle one slot */
            furi_delay_ms(HONE_SLOT_MS);
            continue;
        }
        if(!lane_enter(s, HoneLaneTag)) continue;
        status_tag_lane(s, sensor_name[k]);
        /* tag sensors share TIM2 with Sub-GHz decoding; heartbeat needs no timer */
        bool timed = k != HoneSensorHeartbeat;
        if(timed) furi_check(furi_mutex_acquire(s->tim_lock, FuriWaitForever) == FuriStatusOk);
        bool found = run_slot(s, k);
        if(timed) furi_mutex_release(s->tim_lock);
        lane_leave(s, HoneLaneTag); /* NFC/RFID/iButton/IR all released */
        status_tag_lane(s, "");
        hone_sched_report(&s->sched, k, found);
        furi_delay_ms(hone_sched_cycle_delay_ms(&s->sched));
    }
    return 0;
}
