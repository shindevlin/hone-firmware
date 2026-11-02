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
#include <stdlib.h>

#define TAG "HoneSrv"
#define HONE_FW_VERSION "2.1.0"

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
} HoneSrv;

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

static void queue_append(HoneSrv* s, const uint8_t* frame, size_t len) {
    FileInfo fi;
    if(storage_common_stat(s->storage, HONE_QUEUE_PATH, &fi) == FSE_OK &&
       fi.size > HONE_QUEUE_MAX) {
        /* Keep every rotated queue: it is the evidence the signed batch hashes
         * commit to, and the SD card has room for years of it. */
        char path[64];
        storage_common_mkdir(s->storage, HONE_ARCHIVE_DIR);
        snprintf(path, sizeof(path), HONE_ARCHIVE_DIR "/q-%lu.bin", (unsigned long)furi_hal_rtc_get_timestamp());
        storage_common_rename(s->storage, HONE_QUEUE_PATH, path);
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
    bool otg_was_on = furi_hal_power_is_otg_enabled();
    if(!otg_was_on) furi_hal_power_enable_otg();
    FuriHalSerialHandle* h = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if(!h) {
        if(!otg_was_on) furi_hal_power_disable_otg();
        return false;
    }
    FuriStreamBuffer* sb = furi_stream_buffer_alloc(1024, 1);
    furi_hal_serial_init(h, HONE_WIFI_BAUD);
    furi_hal_serial_async_rx_start(h, wifi_rx_cb, sb, false);

    char* line = malloc(400);
    bool alive = false, got = false, new_board = false;
    *is_v2 = false;
    uint32_t start = furi_get_tick();
    while(!alive && furi_get_tick() - start < furi_ms_to_ticks(HONE_WIFI_BOOT_MS)) {
        furi_hal_serial_tx(h, (const uint8_t*)"PING\n", 5);
        while(wifi_readline(sb, line, 400, 500)) {
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
            if(wifi_readline(sb, line, 400, 200)) keyed = strncmp(line, "OK key", 6) == 0;
        }
        if(keyed) {
            char sc[24];
            int n = snprintf(sc, sizeof(sc), "SCAN2 %u\n", (unsigned)HONE_WIFI_LISTEN_MS);
            furi_hal_serial_tx(h, (const uint8_t*)sc, n);
            start = furi_get_tick();
            while(!got && furi_get_tick() - start < furi_ms_to_ticks(HONE_WIFI2_SCAN_MS)) {
                if(wifi_readline(sb, line, 400, 500)) got = wifi2_parse(line, v2);
            }
            *is_v2 = got;
        }
    }
    if(alive && !new_board) {
        furi_hal_serial_tx(h, (const uint8_t*)"SCAN\n", 5);
        start = furi_get_tick();
        while(!got && furi_get_tick() - start < furi_ms_to_ticks(HONE_WIFI_SCAN_MS)) {
            if(wifi_readline(sb, line, 400, 500)) got = wifi_parse(line, v1);
        }
    }
    free(line);

    furi_hal_serial_async_rx_stop(h);
    furi_hal_serial_deinit(h);
    furi_hal_serial_control_release(h);
    furi_stream_buffer_free(sb);
    if(!otg_was_on) furi_hal_power_disable_otg(); /* board fully off between slots */
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
    default: return -1;
    }
}

static void emit(HoneSrv* s, HoneMsgType type, const void* body, uint8_t body_len) {
    furi_check(furi_mutex_acquire(s->emit_lock, FuriWaitForever) == FuriStatusOk);
    size_t len = hone_frame_build(
        s->frame, type, body, body_len, s->pk, s->sk, counter_next(s), s->anchor);
    if(len) {
        queue_append(s, s->frame, len);
        s->total_frames++;
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
        FURI_LOG_I(TAG, "commit %s x%u", hone_group_name[g], (unsigned)count);
    }
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
                FURI_LOG_I(TAG, "ir proto %d addr %lx cmd %lx", irb.protocol, irb.address, irb.command);
            }
        }
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

/* ─── lanes ─────────────────────────────────────────────────────────────── */

#define HONE_LANE_STACK      (6 * 1024) /* ed25519 sign needs ~3 KB */
#define HONE_WIFI_RETRY_MS   15000      /* no board answering: try again later */

static int32_t subghz_lane(void* ctx) {
    HoneSrv* s = ctx;
    while(1) {
        if(s->paused) {
            furi_delay_ms(1000);
            continue;
        }
        HoneBodySubGhz b;
        if(capture_subghz(&b)) {
            emit(s, HoneMsgSubGhz, &b, sizeof(b));
            FURI_LOG_D(TAG, "subghz %lu peak %d avg %d", b.freq_hz, b.rssi_peak_dbm, b.rssi_avg_dbm);
        } else {
            furi_delay_ms(1000);
        }
    }
    return 0;
}

static int32_t wifi_lane(void* ctx) {
    HoneSrv* s = ctx;
    uint32_t last = 0;
    while(1) {
        if(s->paused) {
            furi_delay_ms(1000);
            continue;
        }
        /* Read VBUS while our 5 V output is off, so it reflects real external power. */
        if(!furi_hal_power_is_otg_enabled())
            s->ext_power = furi_hal_power_get_usb_voltage() > HONE_EXT_POWER_V;
        /* one scan a minute on battery and on USB alike (spec 2b) */
        if(last && furi_get_tick() - last < furi_ms_to_ticks(HONE_WIFI_EVERY_MS)) {
            furi_delay_ms(1000);
            continue;
        }
        last = furi_get_tick();
        HoneBodyWifi b;
        HoneBodyWifi2 b2;
        bool v2;
        if(capture_wifi(s, &b, &b2, &v2)) {
            s->wifi_ok_tick = furi_get_tick();
            if(v2) {
                emit(s, HoneMsgWifi2, &b2, (uint8_t)(offsetof(HoneBodyWifi2, top) + b2.n_top * sizeof(HoneWifiAp)));
                FURI_LOG_I(
                    TAG, "wifi2 aps %u la %u top %u probes %u senders %u",
                    b2.aps, b2.la_aps, b2.n_top, b2.probes, b2.probe_senders);
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
} HoneBle;

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
    if(day != b->day) {
        b->day = day;
        b->day_n = 0; /* new K_day: yesterday's oids mean nothing now */
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
        if(s->paused) {
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
        last_scan = furi_get_tick();

        s->observer_ok = gap_observer_supported();
        if(!s->observer_ok) {
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
                FURI_LOG_W(TAG, "ble: scan start refused");
                continue;
            }
        }
        uint32_t t0 = furi_get_tick();
        GapObserverReport r;
        while(furi_get_tick() - t0 < furi_ms_to_ticks(HONE_BLE_SCAN_MS)) {
            if(furi_message_queue_get(b->q, &r, furi_ms_to_ticks(100)) == FuriStatusOk)
                ble_take(b, &r, k_day);
        }
        gap_observer_stop();
        if(held) s->beacon_hold = false;
        uint32_t scan_ms = (furi_get_tick() - t0) * 1000 / furi_kernel_get_tick_frequency();
        while(furi_message_queue_get(b->q, &r, 0) == FuriStatusOk) ble_take(b, &r, k_day);
        b->crowd.scan_ms = (uint16_t)MIN(scan_ms, 0xFFFFu);
        if(b->scans < 255) b->scans++;
        if(b->dropped) FURI_LOG_D(TAG, "ble: %lu reports dropped", b->dropped);
        ble_emit_crowd(b, 0);
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
    if(s->wifi_ok_tick && furi_get_tick() - s->wifi_ok_tick < furi_ms_to_ticks(5 * 60000))
        b.caps |= HONE_CAP_WIFI;
    if(s->observer_ok) b.caps |= HONE_CAP_BLE_OBS;
    if(s->seed_ok) b.caps |= HONE_CAP_RID;
    if(s->ext_power) b.flags |= HONE_FLAG_EXT_POWER;
    if(s->paused) b.flags |= HONE_FLAG_PAUSED;

    furi_check(furi_mutex_acquire(s->emit_lock, FuriWaitForever) == FuriStatusOk);
    b.last_counter = s->counter ? s->counter - 1 : 0;
    size_t len = hone_frame_build(
        out, HoneMsgAnnounce, &b, sizeof(b), s->pk, s->sk, counter_next(s), s->anchor);
    furi_mutex_release(s->emit_lock);
    return len;
}

/* Advert (31 B): [len][0xFF][company lo][company hi]['H'][kind][seq][idx<<4 | total][data <= 23]
 * kind 'A' = signed announce frame, 'C' = signed batch commit. */
static void send_fragments(
    uint8_t* adv, char kind, uint8_t seq, const uint8_t* data, size_t len, bool* started) {
    uint8_t total = (uint8_t)((len + HONE_FRAG_DATA - 1) / HONE_FRAG_DATA);
    for(uint8_t i = 0; i < total; i++) {
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
    for(uint8_t half = 0; half < 2 && left_ms; half++) {
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
    while(1) {
        if(s->beacon_hold) {
            if(started) furi_hal_bt_extra_beacon_stop();
            started = false;
            s->beacon_held = true;
            while(s->beacon_hold) furi_delay_ms(100);
            s->beacon_held = false;
            continue;
        }
        if(s->paused) {
            if(started) furi_hal_bt_extra_beacon_stop();
            started = false;
            furi_delay_ms(1000);
            continue;
        }
        if(!len || furi_get_tick() - built > furi_ms_to_ticks(HONE_ANNOUNCE_EVERY_MS)) {
            len = build_announce(s, frame);
            built = furi_get_tick();
            seq++;
        }
        send_fragments(adv, 'A', seq, frame, len, &started);
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
            send_fragments(adv, 'C', c->seq, c->data, HONE_COMMIT_LEN, &started);
            break;
        }
        if(s->seed_ok) id_slot(s, &idkey, &cfg, &started);
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
    s->storage = furi_record_open(RECORD_STORAGE);

    /* Wait for the SD card: identity, counter and queue all live there. */
    while(storage_sd_status(s->storage) != FSE_OK) {
        furi_delay_ms(1000);
    }
    storage_simply_mkdir(s->storage, HONE_DIR);

    identity_load_or_create(s);
    counter_load(s);
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

    uint32_t last_maint_check = furi_get_tick();
    while(1) {
        if(furi_get_tick() - last_maint_check > furi_ms_to_ticks(5000)) {
            s->paused = storage_file_exists(s->storage, HONE_MAINT_PATH);
            owner_load(s); /* picks up a claim without a reboot */
            seed_load(s);  /* and a provisioned (or removed) id seed */
            tz_load(s);
            last_maint_check = furi_get_tick();
        }
        if(s->paused) {
            furi_delay_ms(1000);
            continue;
        }
        hone_sched_set_battery(&s->sched, furi_hal_power_get_pct());
        HoneSensorKind k = hone_sched_next(&s->sched);
        hone_sched_report(&s->sched, k, run_slot(s, k));
        furi_delay_ms(hone_sched_cycle_delay_ms(&s->sched));
    }
    return 0;
}
