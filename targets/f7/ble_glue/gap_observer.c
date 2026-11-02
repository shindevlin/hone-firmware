#include "gap_observer.h"
#include "gap.h"
#include "ble_glue.h"

#include <ble/ble.h>
#include <interface/patterns/ble_thread/shci/shci.h>
#include <furi.h>
#include <string.h>

#define TAG "BleObserver"

#define OBS_MS_TO_UNITS(x) ((uint16_t)((x) * 1000 / 625))

static volatile GapObserverCallback observer_cb = NULL;
static void* volatile observer_ctx = NULL;
static volatile bool observer_running = false;

bool gap_observer_supported(void) {
    if(!ble_glue_is_radio_stack_ready()) return false;
    if(gap_get_state() == GapStateUninitialized) return false;
    return ble_glue_get_c2_info()->StackType == INFO_STACK_TYPE_BLE_FULL;
}

bool gap_observer_start(
    uint16_t interval_ms,
    uint16_t window_ms,
    GapObserverCallback callback,
    void* context) {
    furi_check(callback);
    if(!gap_observer_supported()) return false;
    if(window_ms > interval_ms) window_ms = interval_ms;
    if(observer_running) gap_observer_stop();

    observer_ctx = context;
    observer_cb = callback;
    tBleStatus status = aci_gap_start_observation_proc(
        OBS_MS_TO_UNITS(interval_ms),
        OBS_MS_TO_UNITS(window_ms),
        0x00, /* passive: never sends scan requests */
        0x00, /* own address type (unused when passive) */
        0x01, /* filter duplicates */
        0x00); /* accept all */
    if(status) {
        FURI_LOG_E(TAG, "start failed: 0x%x", status);
        observer_cb = NULL;
        return false;
    }
    observer_running = true;
    return true;
}

void gap_observer_stop(void) {
    if(observer_running) {
        observer_running = false;
        if(gap_get_state() != GapStateUninitialized) {
            tBleStatus status = aci_gap_terminate_gap_proc(GAP_OBSERVATION_PROC);
            if(status) FURI_LOG_D(TAG, "stop: 0x%x", status);
        }
    }
    observer_cb = NULL;
    observer_ctx = NULL;
}

/* Num_Reports, then per report: Event_Type, Address_Type, Address[6],
 * Length_Data, Data[Length_Data], RSSI */
void gap_observer_on_adv_report(const uint8_t* data, size_t len) {
    GapObserverCallback cb = observer_cb;
    void* ctx = observer_ctx;
    if(!cb || len < 1) return;
    uint8_t n = data[0];
    size_t off = 1;
    for(uint8_t i = 0; i < n; i++) {
        if(off + 9 > len) return;
        GapObserverReport r;
        r.evt_type = data[off];
        r.addr_type = data[off + 1];
        memcpy(r.addr, data + off + 2, 6);
        uint8_t dl = data[off + 8];
        off += 9;
        if(off + dl + 1 > len) return;
        r.data_len = dl > GAP_OBSERVER_MAX_DATA ? GAP_OBSERVER_MAX_DATA : dl;
        memcpy(r.data, data + off, r.data_len);
        off += dl;
        r.rssi = (int8_t)data[off];
        off += 1;
        cb(&r, ctx);
    }
}
