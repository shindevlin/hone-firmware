/*
 * hone_app.c — the Hone screen: what HoneSrv is doing right now
 *
 * Three pages (left/right): Status, Readings, Reboot. Back exits. While this
 * screen is open HoneSrv keeps sensing (any other app makes it yield).
 *
 * Shin Devlin — honemesh.network
 */
#include <hone/hone_status.h>

#include <furi.h>
#include <furi_hal_power.h>
#include <gui/gui.h>
#include <input/input.h>
#include <datetime/datetime.h>

#define HONE_PAGES 3

typedef struct {
    HoneStatusRecord* rec;
    HoneStatus st;
    FuriMutex* lock;
    uint8_t page;
} HoneApp;

static void fmt_dur(char* out, size_t n, uint32_t s) {
    if(s >= 86400)
        snprintf(out, n, "%lud%luh", (unsigned long)(s / 86400), (unsigned long)(s % 86400 / 3600));
    else if(s >= 3600)
        snprintf(out, n, "%luh%02lum", (unsigned long)(s / 3600), (unsigned long)(s % 3600 / 60));
    else if(s >= 60)
        snprintf(out, n, "%lum%02lus", (unsigned long)(s / 60), (unsigned long)(s % 60));
    else
        snprintf(out, n, "%lus", (unsigned long)s);
}

/* "12s ago" / "never" */
static void fmt_ago(char* out, size_t n, uint32_t tick) {
    if(!tick) {
        snprintf(out, n, "-");
        return;
    }
    char d[12];
    fmt_dur(d, sizeof(d), (furi_get_tick() - tick) / furi_kernel_get_tick_frequency());
    snprintf(out, n, "%s", d);
}

static void draw_cb(Canvas* canvas, void* ctx) {
    HoneApp* app = ctx;
    furi_check(furi_mutex_acquire(app->lock, FuriWaitForever) == FuriStatusOk);
    const HoneStatus* st = &app->st;
    char l[40], a[16];
    canvas_clear(canvas);

    /* header: HONE, page dots */
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 0, 9, "HONE");
    canvas_set_font(canvas, FontSecondary);
    static const char* const titles[HONE_PAGES] = {"status", "readings", "reboot"};
    canvas_draw_str(canvas, 30, 9, titles[app->page]);
    for(uint8_t i = 0; i < HONE_PAGES; i++) {
        if(i == app->page)
            canvas_draw_box(canvas, 110 + i * 6, 4, 4, 4);
        else
            canvas_draw_frame(canvas, 110 + i * 6, 4, 4, 4);
    }
    canvas_draw_line(canvas, 0, 10, 127, 10);

    int y = 19;
    const int dy = 9;
    if(app->page == 0) {
        snprintf(
            l, sizeof(l), "Service: %s",
            st->paused   ? "PAUSED (maint.)" :
            st->yielding ? "yielding to app" :
                           "RUNNING");
        canvas_draw_str(canvas, 0, y, l);
        y += dy;
        fmt_dur(a, sizeof(a), furi_get_tick() / furi_kernel_get_tick_frequency());
        snprintf(l, sizeof(l), "v%s up %s bat %u%%", st->fw, a, furi_hal_power_get_pct());
        canvas_draw_str(canvas, 0, y, l);
        y += dy;
        snprintf(l, sizeof(l), "Owner: %s", st->owner[0] ? st->owner : "(not claimed)");
        canvas_draw_str(canvas, 0, y, l);
        y += dy;
        snprintf(l, sizeof(l), "Tag lane: %s", st->tag_lane[0] ? st->tag_lane : "idle (backed off)");
        canvas_draw_str(canvas, 0, y, l);
        y += dy;
        fmt_ago(a, sizeof(a), st->announce_tick);
        snprintf(
            l, sizeof(l), "BLE announce: %s #%u %s", st->beacon_on ? "ON" : "off",
            st->announce_seq, st->id_advert ? "+id" : "");
        canvas_draw_str(canvas, 0, y, l);
        y += dy;
        snprintf(
            l, sizeof(l), "frames %lu  commits %lu", (unsigned long)st->frames,
            (unsigned long)st->commits);
        canvas_draw_str(canvas, 0, y, l);
    } else if(app->page == 1) {
        fmt_ago(a, sizeof(a), st->subghz_tick);
        snprintf(
            l, sizeof(l), "SubG %lu.%02lu %ddBm", (unsigned long)(st->subghz_freq / 1000000),
            (unsigned long)(st->subghz_freq / 10000 % 100), st->subghz_peak);
        canvas_draw_str(canvas, 0, y, l);
        canvas_draw_str_aligned(canvas, 127, y, AlignRight, AlignBottom, a);
        y += dy;
        fmt_ago(a, sizeof(a), st->wifi_tick);
        if(st->wifi_tick)
            snprintf(l, sizeof(l), "WiFi %u APs %u probes", st->wifi_aps, st->wifi_probes);
        else
            snprintf(l, sizeof(l), "Wi-Fi board: no answer");
        canvas_draw_str(canvas, 0, y, l);
        if(st->wifi_tick) canvas_draw_str_aligned(canvas, 127, y, AlignRight, AlignBottom, a);
        y += dy;
        fmt_ago(a, sizeof(a), st->ble_tick);
        if(st->observer_ok || !st->ble_tick)
            snprintf(l, sizeof(l), "BLE %u now %u /15min", st->ble_seen, st->ble_window);
        else
            snprintf(l, sizeof(l), "BLE: stack can't scan");
        canvas_draw_str(canvas, 0, y, l);
        canvas_draw_str_aligned(canvas, 127, y, AlignRight, AlignBottom, a);
        y += dy;
        snprintf(l, sizeof(l), "Tag/IR: %s", st->last_tag[0] ? st->last_tag : "none yet");
        canvas_draw_str(canvas, 0, y, l);
        y += dy;
        if(st->last_tag_tick) {
            fmt_ago(a, sizeof(a), st->last_tag_tick);
            canvas_draw_str_aligned(canvas, 127, y, AlignRight, AlignBottom, a);
        }
        y += dy;
        snprintf(l, sizeof(l), "counter %lu", (unsigned long)st->counter);
        canvas_draw_str(canvas, 0, y, l);
    } else {
        canvas_draw_str(canvas, 0, y, "Last reboot:");
        y += dy;
        canvas_draw_str(canvas, 0, y, st->boot_reason);
        y += dy;
        if(st->boot_rtc) {
            DateTime dt;
            datetime_timestamp_to_datetime(st->boot_rtc, &dt);
            snprintf(
                l, sizeof(l), "at %04u-%02u-%02u %02u:%02u", dt.year, dt.month, dt.day, dt.hour,
                dt.minute);
            canvas_draw_str(canvas, 0, y, l);
        }
        y += dy;
        if(st->down_s) {
            fmt_dur(a, sizeof(a), st->down_s);
            snprintf(l, sizeof(l), "silent %s before boot", a);
            canvas_draw_str(canvas, 0, y, l);
        }
        y += dy;
        canvas_draw_str(canvas, 0, y, "history: apps_data/hone/");
        y += dy;
        canvas_draw_str(canvas, 0, y, "  boot.log");
    }
    furi_mutex_release(app->lock);
}

static void input_cb(InputEvent* ev, void* ctx) {
    FuriMessageQueue* q = ctx;
    furi_message_queue_put(q, ev, 0);
}

/* `loader close` (and update install over USB) asks running apps to exit */
static bool signal_cb(uint32_t signal, void* arg, void* ctx) {
    UNUSED(arg);
    if(signal != FuriSignalExit) return false;
    InputEvent back = {.key = InputKeyBack, .type = InputTypeShort};
    furi_message_queue_put(ctx, &back, 0);
    return true;
}

int32_t hone_app(void* p) {
    UNUSED(p);
    HoneApp* app = malloc(sizeof(HoneApp));
    memset(app, 0, sizeof(*app));
    app->lock = furi_mutex_alloc(FuriMutexTypeNormal);
    app->rec = furi_record_open(RECORD_HONE);
    hone_status_ui_open(app->rec, true); /* keep sensing while we are on screen */
    hone_status_get(app->rec, &app->st);

    FuriMessageQueue* q = furi_message_queue_alloc(8, sizeof(InputEvent));
    ViewPort* vp = view_port_alloc();
    view_port_draw_callback_set(vp, draw_cb, app);
    view_port_input_callback_set(vp, input_cb, q);
    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, vp, GuiLayerFullscreen);
    furi_thread_set_signal_callback(furi_thread_get_current(), signal_cb, q);

    InputEvent ev;
    bool run = true;
    while(run) {
        if(furi_message_queue_get(q, &ev, 1000) == FuriStatusOk) {
            if(ev.type == InputTypeShort || ev.type == InputTypeRepeat) {
                furi_check(furi_mutex_acquire(app->lock, FuriWaitForever) == FuriStatusOk);
                if(ev.key == InputKeyBack) run = false;
                if(ev.key == InputKeyRight || ev.key == InputKeyOk || ev.key == InputKeyDown)
                    app->page = (app->page + 1) % HONE_PAGES;
                if(ev.key == InputKeyLeft || ev.key == InputKeyUp)
                    app->page = (app->page + HONE_PAGES - 1) % HONE_PAGES;
                furi_mutex_release(app->lock);
            }
        }
        furi_check(furi_mutex_acquire(app->lock, FuriWaitForever) == FuriStatusOk);
        hone_status_get(app->rec, &app->st);
        furi_mutex_release(app->lock);
        view_port_update(vp);
    }

    furi_thread_set_signal_callback(furi_thread_get_current(), NULL, NULL);
    gui_remove_view_port(gui, vp);
    view_port_free(vp);
    furi_record_close(RECORD_GUI);
    furi_message_queue_free(q);
    hone_status_ui_open(app->rec, false);
    furi_record_close(RECORD_HONE);
    furi_mutex_free(app->lock);
    free(app);
    return 0;
}
