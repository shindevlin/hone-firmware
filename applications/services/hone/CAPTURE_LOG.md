# HONE capture log (firmware 2.2.0)

Store-and-forward for the Flipper. Everything below lives in `/ext/apps_data/hone/`.

## Frames: v3 "H3", hash-chained

Each reading is one signed frame in `queue.bin`. A record is `[len u8][frame]`.

```
H3 header (48 bytes, little-endian)
  magic "H3" | type u8 | body_len u8 | device_id[8] | seq u32 | rtc_unix u32 | uptime_ms u32
  | anchor[8] | prev[16]
body (<= 128) | ed25519 signature (64) over header + body
```

- `seq` is the device counter. It only goes up but has gaps (announces and reboot reservations use numbers too).
- `prev` is `sha256(previous queued frame, all bytes incl. signature)[0..16]`. The first v3 frame links to the last v2 frame in the queue.
- `rtc_unix` is the Flipper RTC, which runs on local time (see `utc_offset_min`).
- At 4 MB, `queue.bin` rotates to `archive/q-<rtc>-<first_seq>-<last_seq>.bin`. Pre-2.2.0 archives are named `q-<rtc>.bin` and are never deleted.

## Chain head beacon 'HH'

The Flipper broadcasts this whenever BLE works, on the extra beacon, in the same fragment format as 'HA'/'HC' (kind byte 'H'). It is re-signed when the log moves, at most every 30 s.

```
devid[8] | seq u32 | rtc u32 | head[16] | sig[64]
sig = ed25519("HH1" | devid[8] | seq | rtc | head[16])  with the device key
head = sha256(frame seq)[0..16]
```

Every signed head is also appended to `heads.bin` as `seq | rtc | head[16] | sig[64]` (88 bytes).

## Bulk delivery to a phone

Any HONE phone can do this over BLE RPC (storage read):

1. Read `chain.bin` and `ack.bin`, then `queue.bin` and the `archive/` files after the ack.
2. Verify each frame's signature with the device key.
3. Verify each `prev` against the frame before it.
4. Check that the chain reaches a head signed in `heads.bin` (or heard as 'HH').
5. Store the frames.
6. Write `ack.bin` = u32 seq of the newest frame verified and stored.

A batch that doesn't chain to a signed head is rejected. The Flipper never deletes data above the ack.

## SD space

Every 5 minutes the Flipper checks free space:

- **Below 128 MB:** deletes the oldest archive whose `last_seq` is at or below the ack (one per check).
- **Below 32 MB with nothing deletable:** economy mode. Only 1 in 4 continuous Sub-GHz RSSI frames is kept; every event is still logged. The Hone screen shows "SD almost full: sync a phone".

## Bodies added in 2.2.0 (counts, types, classes only)

| type | body | notes |
|---|---|---|
| 0x0C gadget | ver, category, sec_class, protocol[12], freq, rssi, count, token[4] | Sub-GHz decoder name, fixed/rolling. Token = HMAC(K_day, protocol‖code-hash)[0..4], so it rotates daily. No code is ever kept. |
| 0x0D jam | ver, flags (1 start / 2 end), bands, max_avg_dbm, duration_s, started | flat elevation on 2+ bands for 3 rotations |
| 0x0E BLE threats | ver, window, trackers[5] (FindMy separated, Tile, SmartTag, Chipolo, Google), following, skimmer_names | per quarter-hour |
| 0x0F reader | ver, kind (1 NFC 13.56 MHz, 2 125 kHz), freq | external field presence only |
| 0x10 Wi-Fi security | ver, open, wep, wpa, wpa2, wpa3, ent, wps | hone-esp >= 0.3 |
| 0x11 Wi-Fi crowd | ver, window, scan_devices, win_devices, returning, cu[3] (frames/s ch 1/6/11), deauth, flags (bit0 attack) | hone-esp >= 0.3; no MAC or oid leaves |

The new types ride in the existing on-chain sensor groups:

- gadget and jam: subghz
- Wi-Fi security and Wi-Fi crowd: wifi
- reader: tags
- BLE threats: blecrowd

## Announce caps (HoneBodyAnnounce.caps)

| bit | name |
|---|---|
| 0 | subghz |
| 1 | nfc |
| 2 | rfid125 |
| 3 | ibutton |
| 4 | ir |
| 5 | wifi_board (attached at the last probe) |
| 6 | ble_observer |
| 7 | rotating id |
| 8 | ble |
| 9 | readers |

Several Flippers can share one owner account: each keeps its own key and device_id, and `owner` is the account.
