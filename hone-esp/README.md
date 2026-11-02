# hone-esp

HONE companion firmware for the Flipper Zero Wi-Fi dev board (ESP32-S2).

Talks to the Flipper on UART0 (GPIO43 TX / GPIO44 RX, Flipper pins 14/13), 230400 8N1, one ASCII
line per command and reply. The board's own USB port accepts the same commands for bench testing.

| Command | Reply |
|---|---|
| `PING` | `PONG hone-esp <ver>` |
| `SCAN` | `WIFI aps=N best=R ch=c1,...,c13 probes=P uniq=U ms=T` (v1) |
| `KEY <64 hex>` | `OK key` — oid key for SCAN2, RAM only (the Flipper sends HMAC(K_day, "hone-wifi")) |
| `SCAN2 [listen_ms]` | `WIFI2 aps=N la=L best=R ch=c1,...,c13 probes=P uniq=U listen=S top=<oid>:<rssi>:<ch>,... ms=T` |
| `DLBOOT` | `OK dlboot`, then reboot into the ROM download mode on UART0 (reflash through the Flipper's USB-UART bridge) |

SCAN2 (0.2.0, HONE spec 2b): one active scan, then `listen_ms` (default 15000, max 30000) of continuous
probe listening hopping channels 1/6/11. The 8 strongest APs and the probe senders are reported as
`oid = HMAC-SHA256(key, mac)[0..8]`; `la` counts APs with a locally administered BSSID (phone hotspots).

No SSID, BSSID or client MAC leaves the chip. APs are counted per channel; probe requests are counted,
and distinct senders via a per-boot salted hash in RAM (MAC randomisation makes `uniq` an upper bound).

Build: `pio run` (PlatformIO, board esp32-s2-saola-1, Arduino). Flash the merged image at 0x0 with
esptool from download mode (hold BOOT, tap RESET). The stock Blackmagic image is backed up outside the repo.
