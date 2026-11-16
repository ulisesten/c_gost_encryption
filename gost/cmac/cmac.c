/**
 *  @file  cmac.c
 *  @brief  CMAC per GOST R 34.13-2015 over Kuznyechik.
 */
#include "cmac.h"

#include <string.h>

/** GF(2^128) reduction constant for doubling: x^128 + x^7 + x^6 + x^5 + x^4 + x + 1. */
#define GOST_CMAC_B UINT8_C(0x87)

/**
 *  @brief  Double a 128-bit block in GF(2^128), most significant bit of
 *          byte 0 first.
 */
static void block_double(const uint8_t in[GOST_CMAC_BLOCK], uint8_t out[GOST_CMAC_BLOCK])
{
    uint8_t carry = (uint8_t)(in[0] & UINT8_C(0x80));
    for (unsigned i = 0; i < GOST_CMAC_BLOCK; i++) {
        uint8_t next_carry = (uint8_t)(in[i] & UINT8_C(0x80));
        out[i] = (uint8_t)(in[i] << 1);
        if (i != 0U) {
            out[i - 1U] |= (uint8_t)(next_carry >> 7U);
        }
    }
    if (carry != 0U) {
        out[GOST_CMAC_BLOCK - 1U] ^= GOST_CMAC_B;
    }
}

/** @brief XOR @p src into @p dst. */
static void block_xor(uint8_t dst[GOST_CMAC_BLOCK], const uint8_t src[GOST_CMAC_BLOCK])
{
    for (unsigned i = 0; i < GOST_CMAC_BLOCK; i++) {
        dst[i] ^= src[i];
    }
}

gost_status_t gost_cmac_init(gost_cmac_ctx_t *ctx, const uint8_t key[GOST_KUZNYECHIK_KEY])
{
    if (ctx == NULL || key == NULL) {
        return GOST_ERR_PARAM;
    }
    memset(ctx, 0, sizeof(*ctx));
    gost_status_t status = gost_kuznyechik_init(&ctx->cipher, key);
    if (status != GOST_OK) {
        return status;
    }
    uint8_t zero[GOST_CMAC_BLOCK] = { 0 };
    uint8_t r[GOST_CMAC_BLOCK];
    gost_kuznyechik_encrypt_block(&ctx->cipher, zero, r);
    block_double(r, ctx->key1);
    block_double(ctx->key1, ctx->key2);
    gost_secure_zero(r, sizeof(r));
    return GOST_OK;
}

gost_status_t gost_cmac_update(gost_cmac_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (ctx == NULL || (data == NULL && len != 0U)) {
        return GOST_ERR_PARAM;
    }
    while (len != 0U) {
        if (ctx->pending_len == GOST_CMAC_BLOCK) {
            /* The buffer holds a full block and more data follows, so
               this block is not the last one: chain it. */
            block_xor(ctx->state, ctx->pending);
            gost_kuznyechik_encrypt_block(&ctx->cipher, ctx->state, ctx->state);
            ctx->pending_len = 0U;
        }
        size_t take = GOST_CMAC_BLOCK - ctx->pending_len;
        if (take > len) {
            take = len;
        }
        memcpy(ctx->pending + ctx->pending_len, data, take);
        ctx->pending_len += take;
        data += take;
        len -= take;
    }
    return GOST_OK;
}

gost_status_t gost_cmac_final(gost_cmac_ctx_t *ctx, uint8_t tag[GOST_CMAC_TAG])
{
    if (ctx == NULL || tag == NULL) {
        return GOST_ERR_PARAM;
    }
    uint8_t last[GOST_CMAC_BLOCK];
    const uint8_t *key;
    if (ctx->pending_len == GOST_CMAC_BLOCK) {
        memcpy(last, ctx->pending, GOST_CMAC_BLOCK);
        key = ctx->key1;
    } else {
        /* Incomplete block: pad with 10* and use the second subkey. */
        memset(last, 0, GOST_CMAC_BLOCK);
        memcpy(last, ctx->pending, ctx->pending_len);
        last[ctx->pending_len] = UINT8_C(0x80);
        key = ctx->key2;
    }
    block_xor(ctx->state, last);
    block_xor(ctx->state, key);
    gost_kuznyechik_encrypt_block(&ctx->cipher, ctx->state, tag);
    gost_secure_zero(ctx, sizeof(*ctx));
    return GOST_OK;
}

gost_status_t gost_cmac(const uint8_t key[GOST_KUZNYECHIK_KEY], const uint8_t *msg, size_t msg_len,
                        uint8_t tag[GOST_CMAC_TAG])
{
    if (tag == NULL || (msg == NULL && msg_len != 0U)) {
        return GOST_ERR_PARAM;
    }
    gost_cmac_ctx_t ctx;
    gost_status_t status = gost_cmac_init(&ctx, key);
    if (status != GOST_OK) {
        return status;
    }
    status = gost_cmac_update(&ctx, msg, msg_len);
    if (status != GOST_OK) {
        return status;
    }
    return gost_cmac_final(&ctx, tag);
}
