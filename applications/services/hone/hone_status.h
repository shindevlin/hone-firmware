/*
 * hone_status.h — what HoneSrv is doing, for the Hone screen (record "hone")
 *
 * HoneSrv owns the struct and updates it as the lanes run. Readers take a copy
 * with hone_status_get(). Nothing secret lives here.
 *
 * Shin Devlin — honemesh.network
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

#define RECORD_HONE "hone"

typedef struct {
    char fw[8];
    bool paused;    /* maintenance file present */
    bool yielding;  /* another app is running: sensors released */
    char owner[17]; /* chain account, "" = not claimed */
    uint32_t frames;
    uint32_t counter;
    uint8_t battery_pct;
    bool ext_power;
    /* tag lane */
    char tag_lane[10];     /* sensor the tag lane is on now, "" = idle */
    char last_tag[24];     /* last tag/IR reading */
    uint32_t last_tag_tick;
    /* sub-GHz lane */
    uint32_t subghz_freq;
    int8_t subghz_peak;
    int8_t subghz_avg;
    uint32_t subghz_tick;
    /* Wi-Fi lane */
    uint8_t wifi_aps;
    uint16_t wifi_probes;
    uint32_t wifi_tick; /* 0 = dev board never answered */
    /* BLE lane */
    bool observer_ok;
    uint16_t ble_seen;
    uint16_t ble_window;
    uint32_t ble_tick;
    /* announce lane */
    bool beacon_on;
    bool id_advert;
    uint8_t announce_seq;
    uint32_t announce_tick;
    uint32_t commits;
    /* finds: newest first. find_seq bumps on every new find (the kiskadee
     * shows "found"). Text is type/class only, never a code. */
#define HONE_FINDS 6
    char finds[HONE_FINDS][30];
    uint32_t find_tick[HONE_FINDS];
    uint32_t find_seq;
    /* alert (tracker following, jamming, skimmer module): shown over any page */
    char alert[2][26];
    uint32_t alert_seq;
    uint32_t alert_tick;
    /* census counters since boot */
    uint16_t gadgets;      /* distinct Sub-GHz gadgets */
    uint16_t gadgets_fixed;
    uint16_t readers;
    uint16_t trackers;     /* distinct tracker tags today */
    uint8_t following;
    bool jamming;
    /* Wi-Fi security (last scan, hone-esp >= 0.3) */
    bool wifi_sec_ok;
    uint8_t wifi_open, wifi_wep, wifi_wpa, wifi_wpa2, wifi_wpa3, wifi_ent, wifi_wps;
    /* capture log */
    uint32_t chain_seq;    /* newest chained frame */
    uint32_t acked_seq;    /* delivered to a phone (ack.bin) */
    uint32_t sd_free_mb;
    bool sd_economy;       /* SD nearly full of undelivered data */
    /* last reboot (read once at boot) */
    char boot_reason[40];
    uint32_t boot_rtc;     /* local RTC time of this boot */
    uint32_t down_s;       /* seconds between last sign of life and this boot, 0 = unknown */
} HoneStatus;

typedef struct HoneStatusRecord HoneStatusRecord;

/* Copy the current status. */
void hone_status_get(HoneStatusRecord* rec, HoneStatus* out);

/* The Hone screen is open: keep sensing while it runs (any other app makes
 * HoneSrv release the sensors until it exits). */
void hone_status_ui_open(HoneStatusRecord* rec, bool open);
