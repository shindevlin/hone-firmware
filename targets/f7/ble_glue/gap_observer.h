/*
 * gap_observer.h — passive BLE scanning (GAP observer role)
 *
 * Needs the full BLE stack (COPRO_STACK_TYPE=ble_full); the light stack is
 * peripheral-only and cannot scan. Reports arrive on the BLE event thread:
 * the callback must be short and must not block (copy, queue, return).
 *
 * Firmware-internal, not part of the app SDK.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GAP_OBSERVER_MAX_DATA 31

typedef struct {
    uint8_t evt_type;  /* 0 ADV_IND, 1 DIRECT, 2 SCAN_IND, 3 NONCONN, 4 SCAN_RSP */
    uint8_t addr_type; /* 0 public, 1 random (2/3 resolved identity) */
    uint8_t addr[6];   /* little-endian, as on air */
    int8_t rssi;       /* dBm, 127 = unavailable */
    uint8_t data_len;
    uint8_t data[GAP_OBSERVER_MAX_DATA];
} GapObserverReport;

typedef void (*GapObserverCallback)(const GapObserverReport* report, void* context);

/* True when the running radio stack can scan. */
bool gap_observer_supported(void);

/* Start a passive scan with duplicate filtering (each advertiser is reported
 * about once per start). interval/window in ms, window <= interval. */
bool gap_observer_start(
    uint16_t interval_ms,
    uint16_t window_ms,
    GapObserverCallback callback,
    void* context);

/* Stop the scan. Safe to call when not scanning. */
void gap_observer_stop(void);

/* Called from the GAP event handler with the LE meta subevent payload
 * (everything after the subevent code). */
void gap_observer_on_adv_report(const uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif
