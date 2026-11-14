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
#define HONE_MAX_BODY    128 /* frame <= 224 bytes, fits the u8 queue length */

typedef enum {
    HoneMsgSubGhz    = 0x01,
    HoneMsgRfid      = 0x02,
    HoneMsgNfc       = 0x03,
    HoneMsgIButton   = 0x04,
    HoneMsgHeartbeat = 0x05,
    HoneMsgIr        = 0x06,
    HoneMsgWifi      = 0x07,
    HoneMsgAnnounce  = 0x08, /* broadcast only, never queued */
    HoneMsgBleCrowd  = 0x09, /* BLE observer: crowd count per scan / window */
    HoneMsgSighting  = 0x0A, /* BLE observer: other HONE devices heard in a window */
    HoneMsgWifi2     = 0x0B, /* Wi-Fi dev board body v2 (top APs as oids) */
    HoneMsgGadget    = 0x0C, /* Sub-GHz gadget census: type + security class, never codes */
    HoneMsgJam       = 0x0D, /* Sub-GHz jamming event (start / end) */
    HoneMsgBleThreat = 0x0E, /* BLE trackers + skimmer-module names, counts only */
    HoneMsgReader    = 0x0F, /* card-reader field nearby (13.56 MHz / 125 kHz), no card data */
    HoneMsgWifiSec   = 0x10, /* Wi-Fi networks by security type, counts only */
    HoneMsgWifiCrowd = 0x11, /* Wi-Fi presence: probe senders, channel load, deauths; counts only */
} HoneMsgType;

/* ─── v3: hash-chained frames (store and forward) ─────────────────────────
 * "H3" = the v2 header + prev[16]: the first 16 bytes of sha256(previous queued
 * frame, all of its bytes incl. signature). counter is the chain seq. Every
 * reading is signed and linked, so a batch delivered later verifies against
 * the signed chain head the Flipper broadcast over BLE ('HH' beacon) and can
 * not be reordered, trimmed in the middle or backdated past that head. */
#define HONE_V3_MAGIC1 '3'
#define HONE_PREV_LEN  16

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

typedef struct __attribute__((packed)) {
    HoneV2Header v2;            /* magic "H3" */
    uint8_t prev[HONE_PREV_LEN];
} HoneV3Header; /* 48 bytes */

_Static_assert(sizeof(HoneV3Header) == 48, "HoneV3Header must be 48 bytes");

/* <= 240 bytes, still fits the u8 length prefix in queue.bin */
#define HONE_FRAME_MAX (sizeof(HoneV3Header) + HONE_MAX_BODY + HONE_SIG_LEN)

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

/* Wi-Fi dev board scan. Counts only: no SSID, BSSID or MAC is ever sent. */
typedef struct __attribute__((packed)) {
    uint8_t  aps;         /* access points seen (2.4 GHz) */
    int8_t   best_rssi;   /* strongest AP, dBm (0 if none) */
    uint8_t  ch[13];      /* APs per channel 1..13 */
    uint16_t probes;      /* probe requests heard (ch 1/6/11, 0.5 s each) */
    uint8_t  uniq;        /* distinct probe senders (upper bound: MAC randomisation) */
} HoneBodyWifi;

/* ─── privacy-keyed ids ───────────────────────────────────────────────────
 * oid = HMAC-SHA256(K, mac)[0..8]. K is random per UTC day, held in RAM only,
 * never stored or sent (spec 1b), so oids repeat within one day on this device
 * and cannot be linked across days or devices. BLE uses K_day itself; the Wi-Fi
 * board gets the subkey HMAC-SHA256(K_day, "hone-wifi"). */
#define HONE_OID_LEN 8

/* UTC quarter-hour window, the spec's aggregation and rotation unit. */
#define HONE_WINDOW_S 900u

/* BLE crowd (0x09). One frame per scan (about once a minute); the last frame of
 * a window has HONE_CROWD_FINAL set and carries that window's totals. */
#define HONE_CROWD_FINAL      (1u << 0)
#define HONE_CROWD_NO_OBSERVER (1u << 1) /* radio stack cannot scan: counts are 0 */
typedef struct __attribute__((packed)) {
    uint8_t  ver;           /* 1 */
    uint8_t  flags;
    uint32_t window;        /* floor(unix_utc / 900) */
    uint16_t scan_ms;       /* listening time of this scan */
    uint16_t seen;          /* distinct advertisers (oids) this scan */
    uint16_t win_distinct;  /* distinct advertisers this window so far */
    uint16_t win_returning; /* of those, also seen in an earlier window today (dwell) */
    uint16_t random_addr;   /* this scan: advertisers using a random address */
    uint16_t reports;       /* advertising reports received this scan */
    uint8_t  rssi_hist[7];  /* this scan, per advertiser: <-90,-90..-81,-80..-71,
                               -70..-61,-60..-51,-50..-41,>=-40 dBm (phone bins) */
    int8_t   rssi_max;      /* this scan, 0 if none */
    uint8_t  hone_rids;     /* distinct HONE rids this window */
    uint8_t  hone_flippers; /* distinct HONE Flipper ids (HA announce) this window */
    uint8_t  scans;         /* scans in this window so far */
} HoneBodyBleCrowd; /* 29 bytes */

/* HONE sightings (0x0A). Emitted when a window closes, 5 entries per frame. */
typedef enum {
    HoneSightRid     = 1, /* older rid advert ('hR' v1): id = rid[16] */
    HoneSightFlipper = 2, /* HONE Flipper announce ('HA'): id = device_id[8], rest 0 */
    HoneSightLookup  = 3, /* window key advert ('hK' v2): id = lookup id sha256(pk_w)[0..16] */
} HoneSightKind;
typedef struct __attribute__((packed)) {
    uint8_t kind;     /* HoneSightKind */
    uint8_t win8;     /* window & 0xFF claimed by the advert (rid kinds), else 0 */
    int8_t  rssi_max;
    uint8_t hits;     /* scans it was heard in this window */
    uint8_t id[16];
} HoneSighting; /* 20 bytes */
#define HONE_SIGHTINGS_PER_FRAME 5
typedef struct __attribute__((packed)) {
    uint8_t      ver;    /* 1 */
    uint32_t     window; /* floor(unix_utc / 900), observer clock */
    uint8_t      n;
    HoneSighting s[HONE_SIGHTINGS_PER_FRAME]; /* only n are sent */
} HoneBodySighting; /* 6 + 20n bytes */

/* Wi-Fi body v2 (0x0B), spec 2b. One scan a minute + ~15 s probe listening on
 * channels 1/6/11. No SSID, BSSID or client MAC: APs and probe senders are oids. */
typedef struct __attribute__((packed)) {
    uint8_t oid[HONE_OID_LEN];
    int8_t  rssi;
    uint8_t channel;
} HoneWifiAp; /* 10 bytes */
#define HONE_WIFI_TOP 8
typedef struct __attribute__((packed)) {
    uint8_t    ver;           /* 2 */
    uint8_t    aps;           /* access points seen (2.4 GHz) */
    uint8_t    la_aps;        /* of those, locally administered BSSID (phone hotspots / mobile APs) */
    int8_t     best_rssi;     /* strongest AP, dBm (0 if none) */
    uint16_t   probes;        /* probe requests heard */
    uint8_t    probe_senders; /* distinct probe senders (oids; MAC randomisation makes it an upper bound) */
    uint8_t    listen_s;      /* probe listening time, s */
    uint8_t    ch[13];        /* APs per channel 1..13 */
    uint8_t    n_top;
    HoneWifiAp top[HONE_WIFI_TOP]; /* strongest first; only n_top are sent */
} HoneBodyWifi2; /* 22 + 10 n_top bytes */

/* Signed announce, broadcast over BLE so any HONE device in range can verify
 * who this is without pairing. Carries the full public key; the chain's
 * device registration says who owns it. */
#define HONE_CAP_SUBGHZ  (1u << 0)
#define HONE_CAP_NFC     (1u << 1)
#define HONE_CAP_RFID    (1u << 2)
#define HONE_CAP_IBUTTON (1u << 3)
#define HONE_CAP_IR      (1u << 4)
#define HONE_CAP_WIFI    (1u << 5) /* Wi-Fi dev board attached (answered the last probe) */
#define HONE_CAP_BLE_OBS (1u << 6) /* BLE observer running (full radio stack) */
#define HONE_CAP_RID     (1u << 7) /* id_seed provisioned: rotating id advert ('hK') on */
#define HONE_CAP_BLE     (1u << 8) /* BLE radio (announce/observer) */
#define HONE_CAP_READERS (1u << 9) /* card-reader field census (NFC + 125 kHz) */
#define HONE_FLAG_EXT_POWER (1u << 0)
#define HONE_FLAG_PAUSED    (1u << 1)
typedef struct __attribute__((packed)) {
    uint8_t  pubkey[32];
    uint16_t caps;
    uint32_t last_counter; /* newest reading counter in the queue */
    uint8_t  battery_pct;
    uint8_t  flags;
    char     owner[16];    /* chain account this device is registered to, NUL-padded;
                              receivers confirm it against SensorRegister on chain */
} HoneBodyAnnounce; /* 56 bytes */

/* ─── what the Flipper alone can find (all bodies: type/class/counts only) ─ */

/* Sub-GHz gadget census (0x0C). One per distinct device per 10 min. No code,
 * key, serial or replayable payload is ever stored or sent. */
typedef enum {
    HoneGadgetOther = 0,
    HoneGadgetGate = 1,    /* garage / gate / barrier remote */
    HoneGadgetCar = 2,     /* car key fob / car alarm */
    HoneGadgetRolling = 3, /* rolling-code remote, use unknown (KeeLoq family: gates and cars) */
    HoneGadgetAlarm = 4,   /* alarm / security sensor or panel remote */
    HoneGadgetHome = 5,    /* blinds, sockets, lights, home automation */
    HoneGadgetGeneric = 6, /* generic fixed-code remote: doorbells, cheap sensors, remotes */
} HoneGadgetCategory;

typedef enum {
    HoneSecUnknown = 0,
    HoneSecFixed = 1,   /* fixed code: anyone who hears it once can replay it */
    HoneSecRolling = 2, /* rolling / hopping code */
} HoneSecClass;

typedef struct __attribute__((packed)) {
    uint8_t  ver;          /* 1 */
    uint8_t  category;     /* HoneGadgetCategory */
    uint8_t  sec_class;    /* HoneSecClass */
    char     protocol[12]; /* decoder name = brand/protocol family, NUL-padded */
    uint32_t freq_hz;
    int8_t   rssi_dbm;
    uint8_t  count;        /* packets heard in the window */
    uint8_t  token[4];     /* HMAC(K_day, protocol || code hash)[0..4]: rotates daily */
} HoneBodyGadget; /* 25 bytes */

/* Jamming (0x0D): sustained flat elevation on 2+ Sub-GHz bands. */
#define HONE_JAM_START 1
#define HONE_JAM_END   2
typedef struct __attribute__((packed)) {
    uint8_t  ver;        /* 1 */
    uint8_t  flags;      /* HONE_JAM_START / HONE_JAM_END */
    uint8_t  bands;      /* bit i = hone_subghz_freqs[i] elevated */
    int8_t   max_avg_dbm;
    uint16_t duration_s; /* END: how long it lasted */
    uint32_t started;    /* RTC (local) of the start */
} HoneBodyJam; /* 10 bytes */

/* BLE threats (0x0E), per UTC quarter-hour window. Counts only. */
typedef enum {
    HoneTrackerFindMy = 0, /* Apple Find My, separated from its owner (AirTag & co) */
    HoneTrackerTile,
    HoneTrackerSmartTag,
    HoneTrackerChipolo,
    HoneTrackerGoogle,     /* Google Find My Device network */
    HoneTrackerKinds,
} HoneTrackerKind;
typedef struct __attribute__((packed)) {
    uint8_t  ver;      /* 1 */
    uint32_t window;   /* floor(unix_utc / 900) */
    uint8_t  trackers[HoneTrackerKinds]; /* distinct tags heard this window */
    uint8_t  following; /* tags that kept reappearing (on-screen alert raised) */
    uint8_t  skimmer_names; /* BLE names matching known pump-skimmer modules */
} HoneBodyBleThreat; /* 12 bytes */

/* Card-reader field (0x0F). Field presence only: no card is emulated or read. */
#define HONE_READER_NFC   1 /* 13.56 MHz reader (NFC / MIFARE / DESFire class) */
#define HONE_READER_125K  2 /* 125 kHz legacy proximity reader (EM / HID Prox class) */
typedef struct __attribute__((packed)) {
    uint8_t  ver;  /* 1 */
    uint8_t  kind;
    uint32_t freq_hz; /* 125 kHz kind: measured carrier, else 0 */
} HoneBodyReader; /* 6 bytes */

/* Wi-Fi security census (0x10), from the dev board (hone-esp >= 0.3). */
typedef struct __attribute__((packed)) {
    uint8_t ver;  /* 1 */
    uint8_t open;
    uint8_t wep;
    uint8_t wpa;  /* WPA1 only */
    uint8_t wpa2; /* WPA2-PSK (incl. WPA/WPA2 mixed) */
    uint8_t wpa3; /* WPA3 / WPA2-WPA3 transition / OWE */
    uint8_t ent;  /* enterprise (802.1X) */
    uint8_t wps;  /* advertising WPS */
} HoneBodyWifiSec; /* 8 bytes */

/* Wi-Fi crowd / presence (0x11), from the dev board (hone-esp >= 0.3).
 * Probe-request senders arrive as daily-keyed 4-byte oids and are only
 * counted here; no MAC or oid goes upstream. */
#define HONE_WIFI_ATTACK (1u << 0) /* deauth/disassoc burst: likely an attack tool */
typedef struct __attribute__((packed)) {
    uint8_t  ver;          /* 1 */
    uint32_t window;       /* floor(unix_utc / 900) */
    uint8_t  scan_devices; /* distinct probe senders this scan */
    uint16_t win_devices;  /* distinct this window so far */
    uint16_t returning;    /* of those, also seen in an earlier window today */
    uint16_t cu[3];        /* frames/s heard on channels 1, 6, 11 (utilisation proxy) */
    uint16_t deauth;       /* deauth + disassoc frames heard this scan */
    uint8_t  flags;
} HoneBodyWifiCrowd; /* 19 bytes */

/* Build + sign a frame into out (>= HONE_FRAME_MAX). Returns total length.
 * prev == NULL: a v2 frame (announce, broadcast only). prev != NULL: v3, chained. */
size_t hone_frame_build(
    uint8_t* out,
    HoneMsgType type,
    const void* body,
    uint8_t body_len,
    const uint8_t pk[32],
    const uint8_t sk[64],
    uint32_t counter,
    const uint8_t anchor[HONE_ANCHOR_LEN],
    const uint8_t* prev);

/* Verify a frame against a full public key. */
bool hone_frame_verify(const uint8_t* frame, size_t len, const uint8_t pk[32]);
