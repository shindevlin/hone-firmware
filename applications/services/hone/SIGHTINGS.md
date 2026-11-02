# HONE Flipper: BLE observer, rotating rid, Wi-Fi v2

Firmware side of the HONE sightings spec (2026-11-02): 1a rotating IDs, 1b keyed
hashes, 2b Wi-Fi body v2. Code: `hone_srv.c` (lanes), `hone_frame.h` (bodies),
`targets/f7/ble_glue/gap_observer.[ch]` (scanning).

## Radio stack

The light BLE stack is peripheral-only ("not able to scan", ST release notes), so the
firmware ships the **full** stack (`fbt_options.py`: `COPRO_STACK_TYPE=ble_full`,
`stm32wb5x_BLE_Stack_full_fw.bin`, `COPRO_OB_DATA=scripts/ob_custradio.data`).

| | light (before) | full (now) |
|---|---|---|
| install address | 0x080D7000 | 0x080CE000 |
| flash | 116 KB | 152 KB (+36 KB, comes out of `/int`) |
| M0 SRAM2a / SRAM2b | 14 K / 19 K | 22 K / 17 K |
| M4 SRAM | unchanged | unchanged (RAM2A/RAM2B 10 K each are below the secure boundary) |

GAP is initialised with `PERIPHERAL | OBSERVER` when the full stack runs (`gap.c`).
`CFG_BLE_NUM_LINK` is 3 (advert/connection, extra beacon, scan); without the third slot
the stack refuses scans with `BLE_STATUS_NO_VALID_SLOT` (0x82). If a scan is still
refused (e.g. a phone connected), the BLE lane pauses the extra beacon for that scan.
The connectable advert, BLE serial/RPC and the HA/HC beacon are unchanged.

## Time

The RTC holds **local** time. `utc = rtc - utc_offset_min * 60`, with `utc_offset_min`
read from `/ext/apps_data/hone/utc_offset_min` (text, minutes, e.g. `-360`), default
-360 (America/El_Salvador, UTC-6, no DST). `window = floor(utc / 900)`.
Frame headers keep `rtc_unix` as-is (local RTC, as before).

## Rotating id advert (spec 1a)

Matches the Android key schedule (`IdKeys.kt`, `IdAdvertiser.kt`, 2026-11-02, in progress).

- Provisioning (claim time, by the owner's phone; never logged, printed or sent):
  - `/ext/apps_data/hone/id_seed.sealed`, 92 bytes, preferred: `FindMy.provisionBlob(devicePub)`
    = ECIES to the X25519 form of this Flipper's ed25519 key:
    `epk 32 | nonce 12 | AES-256-GCM(seed) 32 + tag 16`,
    `key = HKDF(X25519(sk_x, epk), salt = epk || pk_x, "hone-seed-provision-v1")`,
    `sk_x = SHA-512(ed25519 seed)[0..32]`. The Flipper opens it with the hardware AES and
    keeps the seed in RAM only, so the SD never holds it in clear.
  - `/ext/apps_data/hone/id_seed`, 32 raw bytes: bench/USB fallback.
  - Write with RPC storage (USB or BLE), e.g. `storage.py send blob /ext/apps_data/hone/id_seed.sealed`.
    Re-read every 5 s. Deleting the file stops the advert. No file = no id advert.
  - `id_seed = HKDF(hide_private, "hone-id-seed" || device_pubkey)` on the phone.
- Per window (`window = floor(utc / 900)`):
  - `period = year*12 + (month-1)` of the window start (UTC)
  - `share_k = HKDF(id_seed, "hone-share" || period_be32)`
  - `sk_w = HKDF(share_k, "hone-pkw" || window_be64)`, `pk_w = X25519(sk_w, 9)`,
    lookup id `lid = SHA-256(pk_w)[0..16]`
  - `tag = HKDF(share_k, "hone-tag" || window_be64)[0..2]`
  - Flipper only: two advert addresses `HKDF(share_k, "hone-adr" || window_be64)[0..12]`,
    6 bytes each, top two bits set (random static).
  - HKDF is RFC 5869 SHA-256, empty salt = 32 zero bytes.
- Advert = the Android legacy fallback, two halves joined by `(win8, tag)`:
  `1A FF FF FF 'h' 'K' 02 win8 frag tag[2] pk_w-half[16]`, `frag` = `0x02` / `0x12`.
  Each half goes out on its own address (like Android's two advertising sets).
  The full stack has no extended advertising, so the one-advert (`frag 0x01`) form is not sent.
- The extra beacon is time-shared in the announce lane: HA fragments, one HC commit,
  then 0.8 s per half on its address (cut at the quarter-hour), then back to the HONE address.
  pk_w, tag and both addresses are derived at the start of every id slot, so they all
  change at the first slot after the boundary and never cross it.

## BLE observer lane (spec 1b, 2a crowd, 1a sightings)

Every 60 s a passive scan of 8 s (interval 100 ms, window 50 ms, duplicate filter on).
- `oid = HMAC-SHA256(K_day, addr[6])[0..8]`. `K_day` = 32 random bytes per UTC day,
  RAM only. Addresses never leave the lane.
- Crowd: distinct oids per scan and per window; `returning` = window oids already seen
  in an earlier window today (dwell; 4-byte fingerprints in RAM, cleared with K_day).
- Sightings: window-key adverts (`hK` v2, both halves joined, stored as lid, kind 3),
  older rid adverts (`hR` v1, kind 1) and HONE Flipper announces (`HA` fragment 0, devid, kind 2).
  The Flipper has no location, so it does not seal a cell to pk_w (the phone does); its
  sightings carry `(lid, win8, rssi_max, hits)` per window, signed and committed.
- Mobile devices: `random_addr` (BLE) and Wi-Fi `la_aps` (locally administered BSSID,
  i.e. phone hotspots) per scan. Cross-cell "mobile AP" needs a location stamp; the
  Flipper has none, but Wi-Fi top-AP oids are stable for the UTC day.

## Frames (queue.bin)

Same header and ed25519 signature as before. `HONE_MAX_BODY` is now 128 (frame <= 224 B).

| type | name | body |
|---|---|---|
| 0x09 | blecrowd | `HoneBodyBleCrowd`, 29 B: ver=1, flags (1 final, 2 no observer), window u32, scan_ms u16, seen u16, win_distinct u16, win_returning u16, random_addr u16, reports u16, rssi_hist[7] (<-90 .. >=-40), rssi_max i8, hone_rids u8, hone_flippers u8, scans u8 |
| 0x0A | sighting | `HoneBodySighting`, 6 + 20n B: ver=1, window u32, n u8, n x {kind u8 (1 rid, 2 flipper devid, 3 lid), win8 u8, rssi_max i8, hits u8, id[16]} |
| 0x0B | wifi v2 | `HoneBodyWifi2`, 22 + 10n B: ver=2, aps, la_aps, best_rssi i8, probes u16, probe_senders u8, listen_s u8, ch[13], n_top, n x {oid[8], rssi i8, channel u8} |

One blecrowd frame per scan; the window's last one has flags bit 0 and carries the
window totals. Sighting frames are written when a window closes (5 entries each).

## Batch commit groups

`commits.bin` records stay 107 bytes (devid 8 | group 1 | count u16 LE | batch_hash 32 | sig 64).

| group | name | sensor_type | message types |
|---|---|---|---|
| 0 | subghz | continuous | 0x01 |
| 1 | wifi | continuous | 0x07, 0x0B |
| 2 | tags | event | 0x02, 0x03, 0x04 |
| 3 | ir | event | 0x06 |
| 4 | **blecrowd** | continuous | 0x09 |
| 5 | **sightings** | event | 0x0A |

The chain must register `flipper-<devid>-blecrowd` and `flipper-<devid>-sightings`.
Announce caps: bit 6 `HONE_CAP_BLE_OBS`, bit 7 `HONE_CAP_RID` (id seed provisioned, id advert on).

## Wi-Fi body v2 (spec 2b)

One dev-board session a minute on battery and USB alike: `KEY <subkey>` then
`SCAN2 15000` (one active scan + 15 s probe listening hopping 1/6/11 every 500 ms).
The board gets `HMAC-SHA256(K_day, "hone-wifi")`, never K_day. A board on
hone-esp 0.1.x gets the old `SCAN` and a v1 frame (0x07). See `hone-esp/README.md`.
