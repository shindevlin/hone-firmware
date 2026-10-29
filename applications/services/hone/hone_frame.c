/*
 * hone_frame.c — HONE v2 frame build/sign/verify (see hone_frame.h)
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
    const uint8_t anchor[HONE_ANCHOR_LEN]) {
    if(body_len > HONE_MAX_BODY) return 0;

    HoneV2Header hdr = {
        .magic = {HONE_V2_MAGIC0, HONE_V2_MAGIC1},
        .msg_type = (uint8_t)type,
        .body_len = body_len,
        .counter = counter,
        .rtc_unix = furi_hal_rtc_get_timestamp(),
        .uptime_ms = (uint32_t)((uint64_t)furi_get_tick() * 1000 / furi_kernel_get_tick_frequency()),
    };
    memcpy(hdr.device_id, pk, HONE_DEVICE_ID_LEN);
    if(anchor) memcpy(hdr.anchor, anchor, HONE_ANCHOR_LEN);

    memcpy(out, &hdr, sizeof(hdr));
    memcpy(out + sizeof(hdr), body, body_len);
    size_t signed_len = sizeof(hdr) + body_len;
    hone_ed25519_sign(out + signed_len, out, signed_len, sk);
    return signed_len + HONE_SIG_LEN;
}

bool hone_frame_verify(const uint8_t* frame, size_t len, const uint8_t pk[32]) {
    if(len < sizeof(HoneV2Header) + HONE_SIG_LEN) return false;
    const HoneV2Header* hdr = (const HoneV2Header*)frame;
    if(hdr->magic[0] != HONE_V2_MAGIC0 || hdr->magic[1] != HONE_V2_MAGIC1) return false;
    size_t signed_len = sizeof(HoneV2Header) + hdr->body_len;
    if(len != signed_len + HONE_SIG_LEN) return false;
    return hone_ed25519_verify(frame + signed_len, frame, signed_len, pk) == 0;
}
