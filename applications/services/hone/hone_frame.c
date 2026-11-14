/*
 * hone_frame.c — HONE v2/v3 frame build/sign/verify (see hone_frame.h)
 *
 * Shin Devlin — honemesh.network
 */
#include "hone_frame.h"
#include "crypto/ed25519.h"

#include <furi_hal_rtc.h>
#include <furi.h>
#include <string.h>

size_t hone_frame_build(
    uint8_t* out,
    HoneMsgType type,
    const void* body,
    uint8_t body_len,
    const uint8_t pk[32],
    const uint8_t sk[64],
    uint32_t counter,
    const uint8_t anchor[HONE_ANCHOR_LEN],
    const uint8_t* prev) {
    if(body_len > HONE_MAX_BODY) return 0;

    HoneV3Header hdr = {
        .v2 =
            {
                .magic = {HONE_V2_MAGIC0, prev ? HONE_V3_MAGIC1 : HONE_V2_MAGIC1},
                .msg_type = (uint8_t)type,
                .body_len = body_len,
                .counter = counter,
                .rtc_unix = furi_hal_rtc_get_timestamp(),
                .uptime_ms =
                    (uint32_t)((uint64_t)furi_get_tick() * 1000 / furi_kernel_get_tick_frequency()),
            },
    };
    memcpy(hdr.v2.device_id, pk, HONE_DEVICE_ID_LEN);
    if(anchor) memcpy(hdr.v2.anchor, anchor, HONE_ANCHOR_LEN);
    if(prev) memcpy(hdr.prev, prev, HONE_PREV_LEN);
    size_t hlen = prev ? sizeof(HoneV3Header) : sizeof(HoneV2Header);

    memcpy(out, &hdr, hlen);
    memcpy(out + hlen, body, body_len);
    size_t signed_len = hlen + body_len;
    hone_ed25519_sign(out + signed_len, out, signed_len, sk);
    return signed_len + HONE_SIG_LEN;
}

bool hone_frame_verify(const uint8_t* frame, size_t len, const uint8_t pk[32]) {
    if(len < sizeof(HoneV2Header) + HONE_SIG_LEN) return false;
    const HoneV2Header* hdr = (const HoneV2Header*)frame;
    if(hdr->magic[0] != HONE_V2_MAGIC0) return false;
    size_t hlen;
    if(hdr->magic[1] == HONE_V2_MAGIC1)
        hlen = sizeof(HoneV2Header);
    else if(hdr->magic[1] == HONE_V3_MAGIC1)
        hlen = sizeof(HoneV3Header);
    else
        return false;
    size_t signed_len = hlen + hdr->body_len;
    if(len != signed_len + HONE_SIG_LEN) return false;
    return hone_ed25519_verify(frame + signed_len, frame, signed_len, pk) == 0;
}
