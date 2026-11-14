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
#include "kiskadee_sprites.h"

#define HONE_PAGES 5

typedef struct {
    HoneStatusRecord* rec;
    HoneStatus st;
    FuriMutex* lock;
    uint8_t page;
    /* kiskadee */
    uint8_t mood;
    uint32_t mood_until;
    uint32_t last_event;
    uint32_t anim;
    HoneStatus prev;
    bool have_prev;
    uint32_t alert_seen; /* alert_seq the owner dismissed */
    char say[24];
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

/* ─── the kiskadee: mood follows what HoneSrv is really doing ──────────── */

typedef enum {
    MoodScan,  /* default: head turns, radio icon for the lane */
    MoodFound, /* crest up, "kis-ka-dee!" */
    MoodSend,  /* wing flap: an announce or commit went out */
    MoodSleep, /* on battery and idle, or paused/yielding */
    MoodHurt,  /* just rebooted: shows why */
} Mood;

#define FOUND_MS 3000u
#define SEND_MS  1500u
#define IDLE_MS  60000u

static bool tick_due(uint32_t until) {
    return (int32_t)(furi_get_tick() - until) >= 0;
}

/* Called with app->lock held, right after a fresh status copy. */
static void mood_update(HoneApp* app) {
    const HoneStatus* st = &app->st;
    const HoneStatus* pv = &app->prev;
    uint32_t now = furi_get_tick();
    if(app->have_prev) {
        char what[24] = {0};
        if(st->find_seq != pv->find_seq && st->finds[0][0]) {
            strlcpy(what, st->finds[0], sizeof(what));
        } else if(st->last_tag_tick != pv->last_tag_tick && st->last_tag[0]) {
            strlcpy(what, st->last_tag, sizeof(what));
        } else if(
            st->wifi_tick != pv->wifi_tick && pv->wifi_tick && st->wifi_aps > pv->wifi_aps) {
            snprintf(what, sizeof(what), "new Wi-Fi: %u APs", st->wifi_aps);
        } else if(st->subghz_tick != pv->subghz_tick && st->subghz_peak >= -65) {
            snprintf(
                what, sizeof(what), "%lu.%02lu %ddBm", (unsigned long)(st->subghz_freq / 1000000),
                (unsigned long)(st->subghz_freq / 10000 % 100), st->subghz_peak);
        }
        if(what[0]) {
            app->mood = MoodFound;
            app->mood_until = now + furi_ms_to_ticks(FOUND_MS);
            app->last_event = now;
            strlcpy(app->say, what, sizeof(app->say));
        } else if(
            (app->mood != MoodFound || tick_due(app->mood_until)) &&
            (st->announce_tick != pv->announce_tick || st->commits != pv->commits)) {
            app->mood = MoodSend;
            app->mood_until = now + furi_ms_to_ticks(SEND_MS);
        }
    } else {
        app->last_event = now;
    }
    app->prev = *st;
    app->have_prev = true;
    if((app->mood == MoodFound || app->mood == MoodSend) && !tick_due(app->mood_until)) return;

    uint32_t up = now / furi_kernel_get_tick_frequency();
    bool crash = strncmp(st->boot_reason, "crash", 5) == 0;
    bool ext = furi_hal_power_get_usb_voltage() > 4.5f;
    if(up < 60 || (crash && up < 600))
        app->mood = MoodHurt;
    else if(
        st->paused || st->yielding ||
        (!ext && !st->tag_lane[0] && now - app->last_event > furi_ms_to_ticks(IDLE_MS)))
        app->mood = MoodSleep;
    else
        app->mood = MoodScan;
}

/* tiny radio mast with two waves, baseline at y */
static void draw_radio(Canvas* c, int x, int y) {
    canvas_draw_line(c, x + 3, y - 6, x + 3, y);
    canvas_draw_line(c, x + 1, y, x + 5, y);
    canvas_draw_dot(c, x + 1, y - 5);
    canvas_draw_dot(c, x + 5, y - 5);
    canvas_draw_dot(c, x + 0, y - 6);
    canvas_draw_dot(c, x + 6, y - 6);
}

static void draw_kiskadee(Canvas* canvas, HoneApp* app) {
    const HoneStatus* st = &app->st;
    char l[40];
    KiskadeeFrame f;
    switch(app->mood) {
    case MoodFound: f = KiskadeeFrame_found; break;
    case MoodSend: f = (app->anim & 1) ? KiskadeeFrame_send_flap : KiskadeeFrame_idle; break;
    case MoodSleep: f = KiskadeeFrame_sleep; break;
    case MoodHurt: f = KiskadeeFrame_hurt; break;
    default: f = (app->anim / 4) & 1 ? KiskadeeFrame_scan_turn : KiskadeeFrame_idle; break;
    }
    canvas_draw_xbm(canvas, 0, 64 - KISKADEE_H, KISKADEE_W, KISKADEE_H, kiskadee_frames[f]);

    const int x = 44;
    canvas_set_font(canvas, FontSecondary);
    if(app->mood == MoodFound) {
        /* speech bubble from the beak */
        canvas_draw_rframe(canvas, x, 13, 80, 13, 3);
        canvas_draw_line(canvas, x, 23, x - 4, 28);
        canvas_draw_line(canvas, x - 4, 28, x + 4, 25);
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, x + 6, 23, "kis-ka-dee!");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, x, 36, "found:");
        canvas_draw_str(canvas, x, 45, app->say);
    } else if(app->mood == MoodSend) {
        canvas_draw_str(canvas, x, 21, "sending...");
        snprintf(l, sizeof(l), "BLE announce #%u", st->announce_seq);
        canvas_draw_str(canvas, x, 30, l);
        snprintf(l, sizeof(l), "commits %lu", (unsigned long)st->commits);
        canvas_draw_str(canvas, x, 39, l);
    } else if(app->mood == MoodSleep) {
        uint8_t z = (app->anim / 3) % 3;
        canvas_draw_str(canvas, 36, 26 - z * 3, "z");
        if(z) canvas_draw_str(canvas, 40, 20 - z * 3, "Z");
        canvas_draw_str(canvas, x, 21, "sleeping");
        canvas_draw_str(
            canvas, x, 30,
            st->paused   ? "paused (maint.)" :
            st->yielding ? "other app running" :
                           "on battery, quiet");
    } else if(app->mood == MoodHurt) {
        canvas_draw_str(canvas, x, 21, "ouch, rebooted:");
        size_t n = strlen(st->boot_reason);
        strlcpy(l, st->boot_reason, MIN(n, (size_t)17) + 1);
        canvas_draw_str(canvas, x, 30, l);
        if(n > 17) canvas_draw_str(canvas, x, 39, st->boot_reason + 17);
    } else {
        canvas_draw_str(canvas, x, 21, "scanning");
        draw_radio(canvas, x, 30);
        canvas_draw_str(canvas, x + 10, 30, st->tag_lane[0] ? st->tag_lane : "Sub-GHz");
        snprintf(l, sizeof(l), "BLE %s #%u", st->beacon_on ? "on" : "off", st->announce_seq);
        canvas_draw_str(canvas, x, 39, l);
    }
    char a[12];
    fmt_dur(a, sizeof(a), furi_get_tick() / furi_kernel_get_tick_frequency());
    snprintf(l, sizeof(l), "up %s  %lu fr", a, (unsigned long)st->frames);
    canvas_draw_str(canvas, x, 63, l);
}


/* ─── finds page + alert overlay ───────────────────────────────────────── */

static void draw_finds(Canvas* canvas, HoneApp* app) {
    const HoneStatus* st = &app->st;
    char l[64], a[12];
    int y = 19;
    if(!st->finds[0][0]) {
        canvas_draw_str(canvas, 0, y, "nothing new yet");
        y += 9;
    }
    for(int i = 0; i < 4 && st->finds[i][0]; i++, y += 9) {
        fmt_ago(a, sizeof(a), st->find_tick[i]);
        canvas_draw_str(canvas, 0, y, st->finds[i]);
        canvas_draw_str_aligned(canvas, 127, y, AlignRight, AlignBottom, a);
    }
    y = 55;
    snprintf(
        l, sizeof(l), "gadgets %u (%u fixed) rdr %u tag %u", st->gadgets, st->gadgets_fixed,
        st->readers, st->trackers);
    canvas_draw_str(canvas, 0, y, l);
    snprintf(
        l, sizeof(l), "log #%lu sent #%lu SD %luMB%s", (unsigned long)st->chain_seq,
        (unsigned long)st->acked_seq, (unsigned long)st->sd_free_mb, st->sd_economy ? "!" : "");
    canvas_draw_str(canvas, 0, 64, l);
}

static void draw_alert(Canvas* canvas, HoneApp* app) {
    const HoneStatus* st = &app->st;
    if(!st->alert_seq || st->alert_seq == app->alert_seen) return;
    if(furi_get_tick() - st->alert_tick > furi_ms_to_ticks(10u * 60u * 1000u)) return;
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_box(canvas, 4, 14, 120, 44);
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_rframe(canvas, 4, 14, 120, 44, 3);
    canvas_draw_rframe(canvas, 5, 15, 118, 42, 3);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 26, AlignCenter, AlignBottom, st->alert[0]);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 38, AlignCenter, AlignBottom, st->alert[1]);
    canvas_draw_str_aligned(canvas, 64, 52, AlignCenter, AlignBottom, "OK: got it");
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
    static const char* const titles[HONE_PAGES] = {"kiskadee", "finds", "status", "readings", "reboot"};
    canvas_draw_str(canvas, 30, 9, titles[app->page]);
    for(uint8_t i = 0; i < HONE_PAGES; i++) {
        if(i == app->page)
            canvas_draw_box(canvas, 98 + i * 6, 4, 4, 4);
        else
            canvas_draw_frame(canvas, 98 + i * 6, 4, 4, 4);
    }
    canvas_draw_line(canvas, 0, 10, 127, 10);

    int y = 19;
    const int dy = 9;
    if(app->page == 0) {
        draw_kiskadee(canvas, app);
    } else if(app->page == 1) {
        draw_finds(canvas, app);
    } else if(app->page == 2) {
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
    } else if(app->page == 3) {
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
    draw_alert(canvas, app);
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
        if(furi_message_queue_get(q, &ev, 250) == FuriStatusOk) {
            if(ev.type == InputTypeShort || ev.type == InputTypeRepeat) {
                furi_check(furi_mutex_acquire(app->lock, FuriWaitForever) == FuriStatusOk);
                if(ev.key == InputKeyBack) run = false;
                if(ev.key == InputKeyOk && app->st.alert_seq != app->alert_seen) {
                    app->alert_seen = app->st.alert_seq;
                } else if(ev.key == InputKeyRight || ev.key == InputKeyOk || ev.key == InputKeyDown)
                    app->page = (app->page + 1) % HONE_PAGES;
                if(ev.key == InputKeyLeft || ev.key == InputKeyUp)
                    app->page = (app->page + HONE_PAGES - 1) % HONE_PAGES;
                furi_mutex_release(app->lock);
            }
        }
        furi_check(furi_mutex_acquire(app->lock, FuriWaitForever) == FuriStatusOk);
        hone_status_get(app->rec, &app->st);
        mood_update(app);
        app->anim++;
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
