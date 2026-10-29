// hone-esp — HONE companion firmware for the Flipper Zero Wi-Fi dev board (ESP32-S2)
//
// Talks to the Flipper over UART0 (GPIO43 TX / GPIO44 RX -> Flipper pins 14/13),
// 230400 8N1, one ASCII line per command and per reply. The same commands are
// accepted on the board's own USB port for bench testing.
//
//   PING            -> "PONG hone-esp <ver>"
//   SCAN            -> "WIFI aps=N best=R ch=c1,c2,...,c13 probes=P uniq=U ms=T"
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

#define HONE_ESP_VER "0.1.0"
#define LINK_TX 43
#define LINK_RX 44
#define LINK_BAUD 230400
#define PROBE_DWELL_MS 500
static const uint8_t PROBE_CHANNELS[] = {1, 6, 11};

static HardwareSerial Link(0);

// ── probe-request counting (promiscuous) ──────────────────────────────────
#define UNIQ_MAX 128
static volatile uint16_t probe_count;
static uint32_t uniq[UNIQ_MAX];
static volatile uint8_t uniq_n;
static uint32_t salt;

static uint32_t mac_hash(const uint8_t* m) {
    uint32_t h = 2166136261u ^ salt; // FNV-1a, salted
    for(int i = 0; i < 6; i++) {
        h ^= m[i];
        h *= 16777619u;
    }
    return h;
}

static void IRAM_ATTR sniff(void* buf, wifi_promiscuous_pkt_type_t type) {
    if(type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t* p = (const wifi_promiscuous_pkt_t*)buf;
    const uint8_t* f = p->payload;
    if((f[0] & 0xFC) != 0x40) return; // management, subtype 4 = probe request
    probe_count++;
    uint32_t h = mac_hash(f + 10);      // addr2 = sender
    for(uint8_t i = 0; i < uniq_n; i++)
        if(uniq[i] == h) return;
    if(uniq_n < UNIQ_MAX) uniq[uniq_n++] = h;
}

static void count_probes(uint16_t* probes, uint8_t* u) {
    probe_count = 0;
    uniq_n = 0;
    esp_wifi_set_promiscuous_rx_cb(sniff);
    wifi_promiscuous_filter_t filt = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous(true);
    for(uint8_t c : PROBE_CHANNELS) {
        esp_wifi_set_channel(c, WIFI_SECOND_CHAN_NONE);
        delay(PROBE_DWELL_MS);
    }
    esp_wifi_set_promiscuous(false);
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

static void handle(const String& cmd, Print& out) {
    if(cmd == "PING") out.println("PONG hone-esp " HONE_ESP_VER);
    else if(cmd == "SCAN") do_scan(out);
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
        } else if(buf.length() < 64) {
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
