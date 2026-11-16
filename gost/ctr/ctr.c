/**
 *  @file  ctr.c
 *  @brief  CTR-ACPKM encryption mode, GOST R 34.13-2015 with the
 *          internal re-keying of RFC 8645 section 6.2.2.
 */
#include "ctr.h"

#include <string.h>

/** First half of the ACPKM constant D (RFC 8645, section 6.2.1). */
static const uint8_t acpkm_d1[GOST_KUZNYECHIK_BLOCK] = {
    UINT8_C(0x80), UINT8_C(0x81), UINT8_C(0x82), UINT8_C(0x83),
    UINT8_C(0x84), UINT8_C(0x85), UINT8_C(0x86), UINT8_C(0x87),
    UINT8_C(0x88), UINT8_C(0x89), UINT8_C(0x8a), UINT8_C(0x8b),
    UINT8_C(0x8c), UINT8_C(0x8d), UINT8_C(0x8e), UINT8_C(0x8f),
};

/** Second half of the ACPKM constant D. */
static const uint8_t acpkm_d2[GOST_KUZNYECHIK_BLOCK] = {
    UINT8_C(0x90), UINT8_C(0x91), UINT8_C(0x92), UINT8_C(0x93),
    UINT8_C(0x94), UINT8_C(0x95), UINT8_C(0x96), UINT8_C(0x97),
    UINT8_C(0x98), UINT8_C(0x99), UINT8_C(0x9a), UINT8_C(0x9b),
    UINT8_C(0x9c), UINT8_C(0x9d), UINT8_C(0x9e), UINT8_C(0x9f),
};

/**
 *  @brief  ACPKM transformation: K^(i+1) = E_K(D1) | E_K(D2).
 */
static void acpkm_rekey(gost_ctr_acpkm_ctx_t *ctx)
{
    uint8_t derived[GOST_KUZNYECHIK_KEY];
    gost_kuznyechik_encrypt_block(&ctx->cipher, acpkm_d1, derived);
    gost_kuznyechik_encrypt_block(&ctx->cipher, acpkm_d2, derived + GOST_KUZNYECHIK_BLOCK);
    gost_status_t status = gost_kuznyechik_init(&ctx->cipher, derived);
    (void)status;
    gost_secure_zero(derived, sizeof(derived));
}

/** @brief  Produce the gamma of the current block and advance counters. */
static gost_status_t next_gamma(gost_ctr_acpkm_ctx_t *ctx, uint8_t gamma[GOST_KUZNYECHIK_BLOCK])
{
    if (ctx->block_index != 0U && ctx->block_index % ctx->section_blocks == 0U) {
        acpkm_rekey(ctx);
    }
    uint8_t counter[GOST_KUZNYECHIK_BLOCK];
    memcpy(counter, ctx->icn, GOST_CTR_ICN);
    for (unsigned i = 0; i < 8U; i++) {
        counter[GOST_CTR_ICN + i] = (uint8_t)(ctx->block_index >> (56U - 8U * i));
    }
    gost_status_t status = gost_kuznyechik_encrypt_block(&ctx->cipher, counter, gamma);
    ctx->block_index++;
    return status;
}

gost_status_t gost_ctr_acpkm_init(gost_ctr_acpkm_ctx_t *ctx, const uint8_t key[GOST_KUZNYECHIK_KEY],
                                  const uint8_t icn[GOST_CTR_ICN], size_t section_blocks)
{
    if (ctx == NULL || key == NULL || icn == NULL) {
        return GOST_ERR_PARAM;
    }
    if (section_blocks == 0U) {
        section_blocks = GOST_CTR_ACPKM_SECTION_DEFAULT;
    }
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->icn, icn, GOST_CTR_ICN);
    ctx->section_blocks = section_blocks;
    return gost_kuznyechik_init(&ctx->cipher, key);
}

/**
 *  @brief  XOR @p len bytes with the keystream; symmetric for both
 *          directions.
 */
static gost_status_t crypt_stream(gost_ctr_acpkm_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t len)
{
    if (ctx == NULL || (in == NULL && len != 0U) || out == NULL) {
        return GOST_ERR_PARAM;
    }
    size_t offset = 0U;
    while (offset < len) {
        if (ctx->pending_len == 0U) {
            uint8_t gamma[GOST_KUZNYECHIK_BLOCK];
            gost_status_t status = next_gamma(ctx, gamma);
            if (status != GOST_OK) {
                return status;
            }
            memcpy(ctx->pending, gamma, GOST_KUZNYECHIK_BLOCK);
            ctx->pending_len = GOST_KUZNYECHIK_BLOCK;
        }
        size_t take = len - offset;
        if (take > ctx->pending_len) {
            take = ctx->pending_len;
        }
        size_t from = GOST_KUZNYECHIK_BLOCK - ctx->pending_len;
        for (size_t i = 0; i < take; i++) {
            out[offset + i] = (uint8_t)(in[offset + i] ^ ctx->pending[from + i]);
        }
        ctx->pending_len -= take;
        offset += take;
    }
    return GOST_OK;
}

gost_status_t gost_ctr_acpkm_encrypt(gost_ctr_acpkm_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t len)
{
    return crypt_stream(ctx, in, out, len);
}

gost_status_t gost_ctr_acpkm_decrypt(gost_ctr_acpkm_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t len)
{
    return crypt_stream(ctx, in, out, len);
}

gost_status_t gost_ctr_acpkm(const uint8_t key[GOST_KUZNYECHIK_KEY], const uint8_t icn[GOST_CTR_ICN],
                             size_t section_blocks, const uint8_t *in, uint8_t *out, size_t len)
{
    gost_ctr_acpkm_ctx_t ctx;
    gost_status_t status = gost_ctr_acpkm_init(&ctx, key, icn, section_blocks);
    if (status != GOST_OK) {
        return status;
    }
    status = crypt_stream(&ctx, in, out, len);
    gost_secure_zero(&ctx, sizeof(ctx));
    return status;
}
