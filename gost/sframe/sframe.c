/**
 *  @file  sframe.c
 *  @brief  SFrame-GOST frame encryption profile.
 */
#include "sframe.h"

#include <string.h>

/** Frame version written in every header. */
#define GOST_SFRAME_VERSION UINT8_C(0x01)

/** Number of bits in the replay window. */
#define GOST_SFRAME_WINDOW_BITS 64U

/**
 *  @brief  Find the slot of @p kid, or -1.
 */
static int find_slot(const gost_sframe_ctx_t *ctx, uint8_t kid)
{
    for (unsigned i = 0; i < GOST_SFRAME_KID_MAX; i++) {
        if (ctx->keys[i].used != 0U && ctx->keys[i].kid == kid) {
            return (int)i;
        }
    }
    return -1;
}

gost_status_t gost_sframe_init(gost_sframe_ctx_t *ctx)
{
    if (ctx == NULL) {
        return GOST_ERR_PARAM;
    }
    memset(ctx, 0, sizeof(*ctx));
    return GOST_OK;
}

gost_status_t gost_sframe_set_key(gost_sframe_ctx_t *ctx, uint8_t kid, const uint8_t key[GOST_AEAD_KEY])
{
    if (ctx == NULL || key == NULL) {
        return GOST_ERR_PARAM;
    }
    int slot = find_slot(ctx, kid);
    if (slot < 0) {
        for (unsigned i = 0; i < GOST_SFRAME_KID_MAX; i++) {
            if (ctx->keys[i].used == 0U) {
                slot = (int)i;
                break;
            }
        }
        if (slot < 0) {
            return GOST_ERR_STATE;
        }
        ctx->keys[slot].used = 1U;
        ctx->keys[slot].kid = kid;
    } else {
        /* Re-keying an epoch: erase the previous material. */
        gost_secure_zero(ctx->keys[slot].key, sizeof(ctx->keys[slot].key));
    }
    memcpy(ctx->keys[slot].key, key, sizeof(ctx->keys[slot].key));
    ctx->keys[slot].counter = 0U;
    ctx->keys[slot].highest = 0U;
    ctx->keys[slot].window = 0U;
    if (ctx->sender < 0) {
        ctx->sender = slot;
    }
    return GOST_OK;
}

gost_status_t gost_sframe_set_sender(gost_sframe_ctx_t *ctx, uint8_t kid)
{
    if (ctx == NULL) {
        return GOST_ERR_PARAM;
    }
    int slot = find_slot(ctx, kid);
    if (slot < 0) {
        return GOST_ERR_STATE;
    }
    ctx->sender = slot;
    return GOST_OK;
}

gost_status_t gost_sframe_encrypt(gost_sframe_ctx_t *ctx, const uint8_t *frame, size_t len,
                                  uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (ctx == NULL || out_len == NULL || (frame == NULL && len != 0U) || out == NULL) {
        return GOST_ERR_PARAM;
    }
    if (ctx->sender < 0) {
        return GOST_ERR_STATE;
    }
    size_t total = GOST_SFRAME_HEADER + len + GOST_AEAD_TAG;
    if (out_cap < total) {
        return GOST_ERR_PARAM;
    }
    gost_sframe_key_t *slot = &ctx->keys[ctx->sender];
    slot->counter++;
    uint8_t nonce[GOST_AEAD_NONCE];
    memset(nonce, 0, sizeof(nonce));
    for (unsigned i = 0; i < 8U; i++) {
        nonce[i] = (uint8_t)(slot->counter >> (56U - 8U * i));
    }
    out[0] = GOST_SFRAME_VERSION;
    out[1] = slot->kid;
    for (unsigned i = 0; i < 8U; i++) {
        out[2U + i] = nonce[i];
    }
    gost_status_t status = gost_aead_seal(slot->key, nonce, out, GOST_SFRAME_HEADER, frame, len,
                                          out + GOST_SFRAME_HEADER, out + GOST_SFRAME_HEADER + len);
    gost_secure_zero(nonce, sizeof(nonce));
    if (status != GOST_OK) {
        slot->counter--;
        return status;
    }
    *out_len = total;
    return GOST_OK;
}

/**
 *  @brief  Replay window check and update, per RFC 9605-style sliding
 *          window: counters older than highest - 63 are rejected, as
 *          are counters already seen.
 */
static gost_status_t replay_check(gost_sframe_key_t *slot, uint64_t counter)
{
    if (counter == 0U) {
        return GOST_ERR_AUTH;
    }
    if (slot->highest == 0U) {
        return GOST_OK;
    }
    if (counter > slot->highest) {
        return GOST_OK;
    }
    uint64_t age = slot->highest - counter;
    if (age >= GOST_SFRAME_WINDOW_BITS) {
        return GOST_ERR_AUTH;
    }
    if ((slot->window >> age) & UINT64_C(1)) {
        return GOST_ERR_AUTH;
    }
    return GOST_OK;
}

static void replay_mark(gost_sframe_key_t *slot, uint64_t counter)
{
    if (counter > slot->highest) {
        uint64_t shift = counter - slot->highest;
        slot->window = shift >= GOST_SFRAME_WINDOW_BITS ? 0U : (slot->window << shift);
        slot->window |= UINT64_C(1);
        slot->highest = counter;
    } else {
        slot->window |= (UINT64_C(1) << (slot->highest - counter));
    }
}

gost_status_t gost_sframe_decrypt(gost_sframe_ctx_t *ctx, const uint8_t *frame, size_t len,
                                  uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (ctx == NULL || out_len == NULL || (frame == NULL && len != 0U) || out == NULL) {
        return GOST_ERR_PARAM;
    }
    if (len < GOST_SFRAME_HEADER + GOST_AEAD_TAG) {
        return GOST_ERR_PARAM;
    }
    if (frame[0] != GOST_SFRAME_VERSION) {
        return GOST_ERR_STATE;
    }
    int slot = find_slot(ctx, frame[1]);
    if (slot < 0) {
        return GOST_ERR_STATE;
    }
    gost_sframe_key_t *key = &ctx->keys[slot];
    uint64_t counter = 0U;
    for (unsigned i = 0; i < 8U; i++) {
        counter = (counter << 8U) | frame[2U + i];
    }
    gost_status_t status = replay_check(key, counter);
    if (status != GOST_OK) {
        return status;
    }
    size_t payload_len = len - GOST_SFRAME_HEADER - GOST_AEAD_TAG;
    if (out_cap < payload_len) {
        return GOST_ERR_PARAM;
    }
    uint8_t nonce[GOST_AEAD_NONCE];
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce, frame + 2U, 8U);
    status = gost_aead_open(key->key, nonce, frame, GOST_SFRAME_HEADER, frame + GOST_SFRAME_HEADER,
                            payload_len, frame + GOST_SFRAME_HEADER + payload_len, out);
    gost_secure_zero(nonce, sizeof(nonce));
    if (status != GOST_OK) {
        return status;
    }
    replay_mark(key, counter);
    *out_len = payload_len;
    return GOST_OK;
}
