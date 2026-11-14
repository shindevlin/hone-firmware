/*
 * hone_census.h — pure classification logic for what the Flipper alone can
 * find: Sub-GHz gadgets, BLE trackers and skimmer modules, jamming.
 * No hardware, no storage: unit-testable off device.
 *
 * Shin Devlin — honemesh.network
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "hone_frame.h"

/* Sub-GHz: decoder name -> category (brand family), decoder type -> security.
 * proto_type: SubGhzProtocolType (1 = static/fixed, 2 = dynamic/rolling). */
HoneGadgetCategory hone_gadget_category(const char* protocol_name);
HoneSecClass hone_gadget_security(int proto_type);
const char* hone_gadget_category_name(HoneGadgetCategory c);
const char* hone_sec_class_name(HoneSecClass s);

/* BLE advertising data (AD structures). Returns HoneTrackerKinds if not a
 * tracker. Find My counts only in "separated from owner" form, so a tag next to
 * its owner's iPhone is not counted. */
HoneTrackerKind hone_ble_tracker_kind(const uint8_t* ad, size_t len);
const char* hone_tracker_name(HoneTrackerKind k);

/* Name in the advert (complete or short local name) matches a Bluetooth module
 * reported in gas-pump card skimmers. Copies the matched name into out. */
bool hone_ble_skimmer_name(const uint8_t* ad, size_t len, char* out, size_t out_len);

/* ─── jamming: sustained, flat, wideband elevation ─────────────────────────
 * Feed one RSSI window per band. A band is "elevated" when its window mean is
 * >= HONE_JAM_AVG_DBM and the window is flat (peak - mean <= HONE_JAM_FLAT_DB),
 * which normal bursty traffic (remotes, sensors) never is. Jamming starts after
 * HONE_JAM_ROUNDS full rotations with 2+ elevated bands and ends after 2 clean
 * rotations. */
#define HONE_JAM_AVG_DBM  (-80)
#define HONE_JAM_FLAT_DB  6
#define HONE_JAM_ROUNDS   3
#define HONE_JAM_BANDS    4

typedef struct {
    uint8_t round_mask;   /* elevated bands seen in the current rotation */
    uint8_t round_seen;   /* bands visited in the current rotation */
    int8_t round_max;
    uint8_t hot_rounds;   /* consecutive elevated rotations */
    uint8_t cool_rounds;  /* consecutive clean rotations while jamming */
    bool jamming;
    uint8_t bands;        /* union of elevated bands during the event */
    int8_t max_avg;
} HoneJam;

typedef enum {
    HoneJamNone,
    HoneJamStarted,
    HoneJamEnded,
} HoneJamEvent;

HoneJamEvent hone_jam_feed(HoneJam* j, uint8_t band, int8_t avg_dbm, int8_t peak_dbm);
