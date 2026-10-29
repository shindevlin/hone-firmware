# hone-esp

HONE companion firmware for the Flipper Zero Wi-Fi dev board (ESP32-S2).

Talks to the Flipper on UART0 (GPIO43 TX / GPIO44 RX, Flipper pins 14/13), 230400 8N1, one ASCII
line per command and reply. The board's own USB port accepts the same commands for bench testing.

| Command | Reply |
|---|---|
| `PING` | `PONG hone-esp <ver>` |
| `SCAN` | `WIFI aps=N best=R ch=c1,...,c13 probes=P uniq=U ms=T` |

No SSID, BSSID or client MAC leaves the chip. APs are counted per channel; probe requests are counted,
and distinct senders via a per-boot salted hash in RAM (MAC randomisation makes `uniq` an upper bound).

Build: `pio run` (PlatformIO, board esp32-s2-saola-1, Arduino). Flash the merged image at 0x0 with
esptool from download mode (hold BOOT, tap RESET). The stock Blackmagic image is backed up outside the repo.
