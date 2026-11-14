/*
 * hone_census.c — see hone_census.h
 *
 * Shin Devlin — honemesh.network
 */
#include "hone_census.h"
#include <string.h>
#include <ctype.h>

/* ─── Sub-GHz gadgets ───────────────────────────────────────────────────── */

typedef struct {
    const char* key; /* lowercase substring of the decoder name */
    HoneGadgetCategory cat;
} GadgetRule;

/* First match wins. Names are the firmware's Sub-GHz decoder names. */
static const GadgetRule gadget_rules[] = {
    {"star line", HoneGadgetCar},
    {"scher", HoneGadgetCar},
    {"kia", HoneGadgetCar},
    {"keeloq", HoneGadgetRolling},
    {"security+", HoneGadgetGate},
    {"chamberlain", HoneGadgetGate},
    {"linear", HoneGadgetGate},
    {"megacode", HoneGadgetGate},
    {"came", HoneGadgetGate},
    {"nice", HoneGadgetGate},
    {"hormann", HoneGadgetGate},
    {"marantec", HoneGadgetGate},
    {"ansonic", HoneGadgetGate},
    {"bett", HoneGadgetGate},
    {"clemsa", HoneGadgetGate},
    {"doitrand", HoneGadgetGate},
    {"gate", HoneGadgetGate},
    {"phoenix", HoneGadgetGate},
    {"kinggates", HoneGadgetGate},
    {"alutech", HoneGadgetGate},
    {"faac", HoneGadgetGate},
    {"mastercode", HoneGadgetGate},
    {"elplast", HoneGadgetGate},
    {"hay21", HoneGadgetGate},
    {"revers", HoneGadgetGate},
    {"nero", HoneGadgetGate},
    {"dickert", HoneGadgetGate},
    {"magellan", HoneGadgetAlarm},
    {"hollarm", HoneGadgetAlarm},
    {"gangqi", HoneGadgetAlarm},
    {"honeywell", HoneGadgetAlarm},
    {"somfy", HoneGadgetHome},
    {"dooya", HoneGadgetHome},
    {"power smart", HoneGadgetHome},
    {"jarolift", HoneGadgetHome},
    {"intertechno", HoneGadgetHome},
    {"feron", HoneGadgetHome},
    {"x10", HoneGadgetHome},
    {"legrand", HoneGadgetHome},
    {"princeton", HoneGadgetGeneric},
    {"holtek", HoneGadgetGeneric},
    {"smc5326", HoneGadgetGeneric},
};

static bool contains_ci(const char* hay, const char* needle) {
    size_t n = strlen(needle);
    for(; *hay; hay++) {
        size_t i = 0;
        while(i < n && hay[i] && tolower((unsigned char)hay[i]) == needle[i]) i++;
        if(i == n) return true;
    }
    return false;
}

HoneGadgetCategory hone_gadget_category(const char* name) {
    if(!name) return HoneGadgetOther;
    for(size_t i = 0; i < sizeof(gadget_rules) / sizeof(gadget_rules[0]); i++)
        if(contains_ci(name, gadget_rules[i].key)) return gadget_rules[i].cat;
    return HoneGadgetOther;
}

HoneSecClass hone_gadget_security(int proto_type) {
    return proto_type == 1 ? HoneSecFixed : proto_type == 2 ? HoneSecRolling : HoneSecUnknown;
}

const char* hone_gadget_category_name(HoneGadgetCategory c) {
    switch(c) {
    case HoneGadgetGate: return "gate remote";
    case HoneGadgetCar: return "car fob";
    case HoneGadgetRolling: return "rolling remote";
    case HoneGadgetAlarm: return "alarm sensor";
    case HoneGadgetHome: return "home device";
    case HoneGadgetGeneric: return "remote/bell";
    default: return "gadget";
    }
}

const char* hone_sec_class_name(HoneSecClass s) {
    return s == HoneSecFixed ? "FIXED" : s == HoneSecRolling ? "rolling" : "?";
}

/* ─── BLE ───────────────────────────────────────────────────────────────── */

/* Walk AD structures: [len][type][data len-1]... Returns false at the end or on
 * a malformed structure. */
static bool ad_next(
    const uint8_t* ad,
    size_t len,
    size_t* off,
    uint8_t* type,
    const uint8_t** data,
    size_t* dlen) {
    if(*off + 1 >= len) return false;
    size_t l = ad[*off];
    if(l == 0 || *off + 1 + l > len) return false;
    *type = ad[*off + 1];
    *data = ad + *off + 2;
    *dlen = l - 1;
    *off += 1 + l;
    return true;
}
static bool has_uuid16(const uint8_t* d, size_t l, uint16_t uuid) {
    for(size_t i = 0; i + 1 < l; i += 2)
        if((uint16_t)(d[i] | (d[i + 1] << 8)) == uuid) return true;
    return false;
}

HoneTrackerKind hone_ble_tracker_kind(const uint8_t* ad, size_t len) {
    size_t off = 0, l;
    uint8_t t;
    const uint8_t* d;
    while(ad_next(ad, len, &off, &t, &d, &l)) {
        if(t == 0xFF && l >= 4 && d[0] == 0x4C && d[1] == 0x00) {
            /* Apple: type 0x12 Find My; length 0x19 = full key, i.e. the
             * accessory is separated from its owner (AirTag & co away from home) */
            if(d[2] == 0x12 && d[3] == 0x19) return HoneTrackerFindMy;
        } else if(t == 0x02 || t == 0x03) { /* 16-bit service UUID lists */
            if(has_uuid16(d, l, 0xFEED) || has_uuid16(d, l, 0xFEEC)) return HoneTrackerTile;
            if(has_uuid16(d, l, 0xFD5A)) return HoneTrackerSmartTag;
            if(has_uuid16(d, l, 0xFE33) || has_uuid16(d, l, 0xFE65)) return HoneTrackerChipolo;
        } else if(t == 0x16 && l >= 2) { /* service data, 16-bit UUID */
            uint16_t u = (uint16_t)(d[0] | (d[1] << 8));
            if(u == 0xFEED || u == 0xFEEC) return HoneTrackerTile;
            if(u == 0xFD5A) return HoneTrackerSmartTag;
            if(u == 0xFE33 || u == 0xFE65) return HoneTrackerChipolo;
            if(u == 0xFEAA && l >= 3 && (d[2] == 0x40 || d[2] == 0x41)) return HoneTrackerGoogle;
        }
    }
    return HoneTrackerKinds;
}

const char* hone_tracker_name(HoneTrackerKind k) {
    switch(k) {
    case HoneTrackerFindMy: return "AirTag/FindMy";
    case HoneTrackerTile: return "Tile";
    case HoneTrackerSmartTag: return "SmartTag";
    case HoneTrackerChipolo: return "Chipolo";
    case HoneTrackerGoogle: return "Google tag";
    default: return "tag";
    }
}

/* Bluetooth modules named in gas-pump skimmer reports and the open-source
 * skimmer scanners. HC-05/HC-06/RNBT are Bluetooth Classic and only show up
 * if a module also advertises over BLE; the BLE ones are listed as well. */
static const char* const skimmer_names[] = {
    "HC-05", "HC-06", "HC-08", "HC-02", "RNBT", "BT04", "BT05", "JDY-", "AT-09", "linvor",
    "Free2move",
};

bool hone_ble_skimmer_name(const uint8_t* ad, size_t len, char* out, size_t out_len) {
    size_t off = 0, l;
    uint8_t t;
    const uint8_t* d;
    while(ad_next(ad, len, &off, &t, &d, &l)) {
        if((t == 0x08 || t == 0x09) && l) {
            for(size_t i = 0; i < sizeof(skimmer_names) / sizeof(skimmer_names[0]); i++) {
                size_t n = strlen(skimmer_names[i]);
                if(l >= n && strncmp((const char*)d, skimmer_names[i], n) == 0) {
                    size_t c = l < out_len - 1 ? l : out_len - 1;
                    memcpy(out, d, c);
                    out[c] = 0;
                    for(size_t k = 0; k < c; k++)
                        if(!isprint((unsigned char)out[k])) out[k] = '?';
                    return true;
                }
            }
        }
    }
    return false;
}

/* ─── jamming ───────────────────────────────────────────────────────────── */

HoneJamEvent hone_jam_feed(HoneJam* j, uint8_t band, int8_t avg, int8_t peak) {
    if(band >= HONE_JAM_BANDS) return HoneJamNone;
    if(avg >= HONE_JAM_AVG_DBM && (int)peak - (int)avg <= HONE_JAM_FLAT_DB) {
        j->round_mask |= (uint8_t)(1u << band);
        if(avg > j->round_max) j->round_max = avg;
    }
    j->round_seen |= (uint8_t)(1u << band);
    if(j->round_seen != (1u << HONE_JAM_BANDS) - 1) return HoneJamNone;

    /* a full rotation is done */
    uint8_t hot = 0;
    for(uint8_t m = j->round_mask; m; m &= (uint8_t)(m - 1)) hot++;
    bool elevated = hot >= 2;
    HoneJamEvent ev = HoneJamNone;
    if(elevated) {
        j->cool_rounds = 0;
        if(j->hot_rounds < 255) j->hot_rounds++;
        if(j->jamming) {
            j->bands |= j->round_mask;
            if(j->round_max > j->max_avg) j->max_avg = j->round_max;
        } else if(j->hot_rounds >= HONE_JAM_ROUNDS) {
            j->jamming = true;
            j->bands = j->round_mask;
            j->max_avg = j->round_max;
            ev = HoneJamStarted;
        }
    } else {
        j->hot_rounds = 0;
        if(j->jamming && ++j->cool_rounds >= 2) {
            j->jamming = false;
            j->cool_rounds = 0;
            ev = HoneJamEnded;
        }
    }
    j->round_mask = 0;
    j->round_seen = 0;
    j->round_max = -128;
    return ev;
}
