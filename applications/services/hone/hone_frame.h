/*
 * hone_frame.h — HONE v2 signed reading frame
 *
 * One frame = header (32) + body (<= 32) + ed25519 signature (64).
 * The signature covers header + body. Little-endian throughout.
 *
 * The same bytes go everywhere: SD queue, BLE, Sub-GHz broadcast. Any HONE
 * device that hears a frame relays it unmodified; anyone can verify it against
 * the device public key registered on chain (device_id = first 8 bytes of it).
 *
 * Time fields:
 *   rtc_unix  — the Flipper's own RTC, taken as-is. Not trusted for accuracy.
 *   counter   — strictly increasing across reboots (reserved in blocks on SD).
 *               Orders frames and kills replays even when the RTC is wrong.
 *   anchor    — first 8 bytes of the latest chain epoch hash this device has
 *               heard. Proves the reading was made AFTER that epoch existed.
 *
 * Shin Devlin — honemesh.network
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define HONE_V2_MAGIC0   'H'
#define HONE_V2_MAGIC1   '2'
#define HONE_DEVICE_ID_LEN 8
#define HONE_ANCHOR_LEN  8
#define HONE_SIG_LEN     64
#define HONE_MAX_BODY    32

typedef enum {
    HoneMsgSubGhz    = 0x01,
    HoneMsgRfid      = 0x02,
    HoneMsgNfc       = 0x03,
    HoneMsgIButton   = 0x04,
    HoneMsgHeartbeat = 0x05,
    HoneMsgIr        = 0x06,
} HoneMsgType;

typedef struct __attribute__((packed)) {
    uint8_t  magic[2];                      /* "H2" */
    uint8_t  msg_type;                      /* HoneMsgType */
    uint8_t  body_len;
    uint8_t  device_id[HONE_DEVICE_ID_LEN]; /* pubkey[0..8] */
    uint32_t counter;
    uint32_t rtc_unix;
    uint32_t uptime_ms;
    uint8_t  anchor[HONE_ANCHOR_LEN];
} HoneV2Header; /* 32 bytes */

_Static_assert(sizeof(HoneV2Header) == 32, "HoneV2Header must be 32 bytes");

#define HONE_FRAME_MAX (sizeof(HoneV2Header) + HONE_MAX_BODY + HONE_SIG_LEN)

/* Bodies */
typedef struct __attribute__((packed)) {
    uint32_t freq_hz;
    int8_t   rssi_peak_dbm; /* peak over the slot window */
    int8_t   rssi_avg_dbm;  /* mean over the slot window */
    uint16_t samples;
} HoneBodySubGhz;

typedef struct __attribute__((packed)) {
    uint8_t  battery_pct;
    uint32_t uptime_s;
    uint32_t total_frames;
    char     fw[8];
    uint16_t battery_mv;   /* fuel gauge */
    int16_t  battery_ma;   /* fuel gauge, negative = discharging */
    int8_t   battery_c;    /* fuel gauge temperature, deg C */
    int16_t  mcu_c10;      /* STM32 die temperature, 0.1 deg C (1 deg resolution) */
} HoneBodyHeartbeat;

/* NFC / 125 kHz RFID / iButton. The raw ID is never published: id_hash is
 * sha256(device pubkey || "hone-tag" || type || protocol || raw id)[0..16].
 * Same Flipper + same tag = same hash; different Flippers cannot link it. */
typedef struct __attribute__((packed)) {
    uint8_t protocol;     /* library protocol id */
    uint8_t id_len;       /* raw id length (0 if none read) */
    uint8_t id_hash[16];
    uint8_t extra[3];     /* NFC-A: atqa[2], sak. else 0 */
} HoneBodyTag;

/* IR. Remote codes are not personal, so decoded signals go out as-is. */
typedef struct __attribute__((packed)) {
    int8_t   protocol;    /* InfraredProtocol, -1 = undecoded/raw */
    uint8_t  repeat;
    uint32_t address;
    uint32_t command;
    uint16_t raw_timings; /* timing count when undecoded */
} HoneBodyIr;

/* Build + sign a frame into out (>= HONE_FRAME_MAX). Returns total length. */
size_t hone_frame_build(
    uint8_t* out,
    HoneMsgType type,
    const void* body,
    uint8_t body_len,
    const uint8_t pk[32],
    const uint8_t sk[64],
    uint32_t counter,
    const uint8_t anchor[HONE_ANCHOR_LEN]);

/* Verify a frame against a full public key. */
bool hone_frame_verify(const uint8_t* frame, size_t len, const uint8_t pk[32]);
