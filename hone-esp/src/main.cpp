// hone-esp — HONE companion firmware for the Flipper Zero Wi-Fi dev board (ESP32-S2)
//
// Talks to the Flipper over UART0 (GPIO43 TX / GPIO44 RX -> Flipper pins 14/13),
// 230400 8N1, one ASCII line per command and per reply. The same commands are
// accepted on the board's own USB port for bench testing.
//
//   PING            -> "PONG hone-esp <ver>"
//   SCAN            -> "WIFI aps=N best=R ch=c1,c2,...,c13 probes=P uniq=U ms=T"   (v1)
//   KEY <64 hex>    -> "OK key"      oid key for SCAN2, RAM only, lost at power-off
//   SCAN2 [listen_ms] -> "WIFI2 aps=N la=L best=R ch=c1,...,c13 probes=P uniq=U listen=S
//                        top=<oid16hex>:<rssi>:<ch>,... ms=T"                 (v2)
//   DLBOOT          -> "OK dlboot", then reboots into the ROM download mode on UART0,
//                      so the board can be reflashed through the Flipper's USB-UART bridge
//
// SCAN2 (HONE spec 2b): one active scan, then listen_ms (default 15000) of
// continuous probe listening hopping channels 1/6/11. APs and probe senders are
// reported as oid = HMAC-SHA256(key, mac)[0..8], with the key the Flipper sends
// (a subkey of its RAM-only per-day key). The top 8 APs by RSSI are listed.
// "la" counts APs whose BSSID is locally administered (phone hotspots / mobile APs).
//
// Privacy: no SSID, BSSID or client MAC ever leaves this chip. Access points are
// counted per channel. Probe requests (phones/laptops looking for networks) are
// counted, and distinct senders are counted via a salted hash held only in RAM;
// the salt is random per boot, so counts cannot be linked across boots or devices.
// Note: modern phones randomise probe MACs, so "uniq" is an upper bound.
//
// Shin Devlin — honemesh.net

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_random.h>
#include <mbedtls/md.h>
#include <soc/rtc_cntl_reg.h>

#define HONE_ESP_VER "0.3.0"
#define LINK_TX 43
#define LINK_RX 44
#define LINK_BAUD 230400
#define PROBE_DWELL_MS 500
#define LISTEN_DEFAULT_MS 15000
#define LISTEN_MAX_MS 30000
#define TOP_N 8
static const uint8_t PROBE_CHANNELS[] = {1, 6, 11};

// ── oid key (from the Flipper, RAM only) ──────────────────────────────────
static uint8_t oid_key[32];
static bool oid_key_set;

static void oid_of(const uint8_t* mac, uint8_t out[8]) {
    uint8_t d[32];
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(md, oid_key, sizeof(oid_key), mac, 6, d);
    memcpy(out, d, 8);
}

static bool set_key(const String& hex) {
    if(hex.length() != 64) return false;
    for(int i = 0; i < 32; i++) {
        char b[3] = {hex[2 * i], hex[2 * i + 1], 0};
        char* end;
        long v = strtol(b, &end, 16);
        if(*end) return false;
        oid_key[i] = (uint8_t)v;
    }
    oid_key_set = true;
    return true;
}

static HardwareSerial Link(0);

// ── probe-request counting (promiscuous) ──────────────────────────────────
#define UNIQ_MAX 128
static volatile uint16_t probe_count;
static uint32_t uniq[UNIQ_MAX];
static volatile uint8_t uniq_n;
static uint32_t salt;
static volatile bool keyed_uniq; // SCAN2: dedupe probe senders by oid

static uint32_t mac_hash(const uint8_t* m) {
    uint32_t h = 2166136261u ^ salt; // FNV-1a, salted
    for(int i = 0; i < 6; i++) {
        h ^= m[i];
        h *= 16777619u;
    }
    return h;
}

// 0.3: channel load (frames heard per channel) and deauth/disassoc counting
static volatile uint8_t cur_ch_idx;
static volatile uint32_t ch_frames[3];
static uint32_t ch_ms[3];
static volatile uint16_t deauth_count;

static void IRAM_ATTR sniff(void* buf, wifi_promiscuous_pkt_type_t type) {
    if(cur_ch_idx < 3) ch_frames[cur_ch_idx]++;
    if(type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t* p = (const wifi_promiscuous_pkt_t*)buf;
    const uint8_t* f = p->payload;
    uint8_t st = f[0] & 0xFC;
    if(st == 0xC0 || st == 0xA0) { // deauthentication / disassociation
        if(deauth_count < 0xFFFF) deauth_count++;
        return;
    }
    if(st != 0x40) return; // management, subtype 4 = probe request
    probe_count++;
    uint32_t h;
    if(keyed_uniq) {
        uint8_t o[8];
        oid_of(f + 10, o); // addr2 = sender
        memcpy(&h, o, 4);
    } else {
        h = mac_hash(f + 10); // addr2 = sender
    }
    for(uint8_t i = 0; i < uniq_n; i++)
        if(uniq[i] == h) return;
    if(uniq_n < UNIQ_MAX) uniq[uniq_n++] = h;
}

static void count_probes(uint16_t* probes, uint8_t* u, uint32_t listen_ms = 0) {
    probe_count = 0;
    uniq_n = 0;
    deauth_count = 0;
    for(int i = 0; i < 3; i++) ch_frames[i] = ch_ms[i] = 0;
    esp_wifi_set_promiscuous_rx_cb(sniff);
    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA};
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous(true);
    if(!listen_ms) {
        for(uint8_t i = 0; i < 3; i++) {
            cur_ch_idx = i;
            esp_wifi_set_channel(PROBE_CHANNELS[i], WIFI_SECOND_CHAN_NONE);
            delay(PROBE_DWELL_MS);
            ch_ms[i] += PROBE_DWELL_MS;
        }
    } else {
        // continuous: hop 1/6/11 every PROBE_DWELL_MS until listen_ms is used up
        uint32_t t0 = millis();
        for(uint8_t i = 0; millis() - t0 < listen_ms; i++) {
            uint8_t k = i % sizeof(PROBE_CHANNELS);
            cur_ch_idx = k;
            esp_wifi_set_channel(PROBE_CHANNELS[k], WIFI_SECOND_CHAN_NONE);
            uint32_t left = listen_ms - (millis() - t0);
            uint32_t d = left < PROBE_DWELL_MS ? left : PROBE_DWELL_MS;
            delay(d);
            ch_ms[k] += d;
        }
    }
    esp_wifi_set_promiscuous(false);
    cur_ch_idx = 3;
    *probes = probe_count;
    *u = uniq_n;
}

// ── scan ──────────────────────────────────────────────────────────────────
static void do_scan(Print& out) {
    uint32_t t0 = millis();
    int n = WiFi.scanNetworks(false, true); // blocking, include hidden
    uint8_t ch[14] = {0};
    int best = -127;
    for(int i = 0; i < n; i++) {
        int c = WiFi.channel(i);
        if(c >= 1 && c <= 13 && ch[c] < 255) ch[c]++;
        if(WiFi.RSSI(i) > best) best = WiFi.RSSI(i);
    }
    WiFi.scanDelete();
    uint16_t probes;
    uint8_t u;
    count_probes(&probes, &u);
    out.printf("WIFI aps=%d best=%d ch=", n < 0 ? 0 : n, n > 0 ? best : 0);
    for(int c = 1; c <= 13; c++) out.printf(c < 13 ? "%u," : "%u", ch[c]);
    out.printf(" probes=%u uniq=%u ms=%lu\n", probes, u, (unsigned long)(millis() - t0));
}

// v2: top APs as oids, locally administered count, continuous probe listening
static void do_scan2(Print& out, uint32_t listen_ms) {
    uint32_t t0 = millis();
    int n = WiFi.scanNetworks(false, true);
    uint8_t ch[14] = {0};
    int best = -127, la = 0;
    uint16_t sec[7] = {0}; // open, wep, wpa, wpa2, wpa3, enterprise, wps
    int idx[TOP_N];
    int ntop = 0;
    for(int i = 0; i < n; i++) {
        int c = WiFi.channel(i);
        if(c >= 1 && c <= 13 && ch[c] < 255) ch[c]++;
        if(WiFi.RSSI(i) > best) best = WiFi.RSSI(i);
        const uint8_t* b = WiFi.BSSID(i);
        if(b && (b[0] & 0x02)) la++;
        // security census: counts only
        switch(WiFi.encryptionType(i)) {
        case WIFI_AUTH_OPEN: sec[0]++; break;
        case WIFI_AUTH_WEP: sec[1]++; break;
        case WIFI_AUTH_WPA_PSK: sec[2]++; break;
        case WIFI_AUTH_WPA2_PSK:
        case WIFI_AUTH_WPA_WPA2_PSK: sec[3]++; break;
        case WIFI_AUTH_WPA3_PSK:
        case WIFI_AUTH_WPA2_WPA3_PSK: sec[4]++; break;
        case WIFI_AUTH_WPA2_ENTERPRISE: sec[5]++; break;
        default: break;
        }
        const wifi_ap_record_t* r = (const wifi_ap_record_t*)WiFi.getScanInfoByIndex(i);
        if(r && r->wps) sec[6]++;
    }
    // top APs by RSSI, strongest first (selection; n is small)
    bool used[256] = {false};
    for(; ntop < TOP_N && ntop < n && n <= 256; ntop++) {
        int m = -1;
        for(int i = 0; i < n; i++)
            if(!used[i] && (m < 0 || WiFi.RSSI(i) > WiFi.RSSI(m))) m = i;
        used[m] = true;
        idx[ntop] = m;
    }
    String top;
    for(int k = 0; k < ntop; k++) {
        const uint8_t* b = WiFi.BSSID(idx[k]);
        if(!b) continue;
        uint8_t o[8];
        oid_of(b, o);
        char item[32];
        snprintf(item, sizeof(item), "%s%02x%02x%02x%02x%02x%02x%02x%02x:%d:%d", top.length() ? "," : "",
                 o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], (int)WiFi.RSSI(idx[k]), (int)WiFi.channel(idx[k]));
        top += item;
    }
    WiFi.scanDelete();
    uint16_t probes;
    uint8_t u;
    keyed_uniq = true;
    count_probes(&probes, &u, listen_ms);
    keyed_uniq = false;
    out.printf("WIFI2 aps=%d la=%d best=%d ch=", n < 0 ? 0 : n, la, n > 0 ? best : 0);
    for(int c = 1; c <= 13; c++) out.printf(c < 13 ? "%u," : "%u", ch[c]);
    out.printf(" probes=%u uniq=%u listen=%lu top=%s", probes, u, (unsigned long)(listen_ms / 1000),
               top.length() ? top.c_str() : "-");
    // 0.3: security census, probe senders as 4-byte keyed oids (never MACs),
    // frames/s per channel 1/6/11, deauth+disassoc frames
    out.printf(" sec=%u,%u,%u,%u,%u,%u,%u", sec[0], sec[1], sec[2], sec[3], sec[4], sec[5], sec[6]);
    out.print(" pso=");
    if(!uniq_n) out.print("-");
    for(uint8_t i = 0; i < uniq_n && i < 32; i++) out.printf(i ? ",%08lx" : "%08lx", (unsigned long)uniq[i]);
    out.printf(" cu=%lu,%lu,%lu deauth=%u ms=%lu\n",
               (unsigned long)(ch_ms[0] ? ch_frames[0] * 1000 / ch_ms[0] : 0),
               (unsigned long)(ch_ms[1] ? ch_frames[1] * 1000 / ch_ms[1] : 0),
               (unsigned long)(ch_ms[2] ? ch_frames[2] * 1000 / ch_ms[2] : 0),
               deauth_count, (unsigned long)(millis() - t0));
}

static void handle(const String& cmd, Print& out) {
    if(cmd == "PING") out.println("PONG hone-esp " HONE_ESP_VER);
    else if(cmd == "SCAN") do_scan(out);
    else if(cmd.startsWith("KEY ")) out.println(set_key(cmd.substring(4)) ? "OK key" : "ERR key");
    else if(cmd == "SCAN2" || cmd.startsWith("SCAN2 ")) {
        if(!oid_key_set) {
            out.println("ERR nokey");
            return;
        }
        uint32_t ms = cmd.length() > 6 ? (uint32_t)cmd.substring(6).toInt() : LISTEN_DEFAULT_MS;
        if(ms > LISTEN_MAX_MS) ms = LISTEN_MAX_MS;
        do_scan2(out, ms);
    } else if(cmd == "DLBOOT") {
        out.println("OK dlboot");
        Link.flush();
        delay(50);
        REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
        esp_restart();
    }
    else if(cmd.length()) out.println("ERR unknown");
}

static String lbuf, ubuf;
static void poll(Stream& in, String& buf) {
    while(in.available()) {
        char c = in.read();
        if(c == '\n' || c == '\r') {
            buf.trim();
            if(buf.length()) handle(buf, in);
            buf = "";
        } else if(buf.length() < 96) {
            buf += c;
        }
    }
}

void setup() {
    salt = esp_random();
    Serial.begin(115200); // USB CDC (bench)
    Link.begin(LINK_BAUD, SERIAL_8N1, LINK_RX, LINK_TX);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    Link.println("READY hone-esp " HONE_ESP_VER);
    Serial.println("READY hone-esp " HONE_ESP_VER);
}

void loop() {
    poll(Link, lbuf);
    poll(Serial, ubuf);
    delay(5);
}
