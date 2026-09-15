/**
 *  @file  kdf.c
 *  @brief HMAC and PBKDF2 on GOST R 34.11-2012.
 */
#include "kdf.h"

#include <string.h>

/** ipad constant of RFC 2104. */
#define GOST_HMAC_IPAD UINT8_C(0x36)
/** opad constant of RFC 2104. */
#define GOST_HMAC_OPAD UINT8_C(0x5C)

/**
 *  @brief Normalize the key into the 64-byte HMAC block K0.
 *
 *  Keys longer than the block are hashed first.
 */
static gost_status_t key_block(const uint8_t *key, size_t key_len, gost_hash_width_t width,
                               uint8_t k0[GOST_KDF_BLOCK])
{
    memset(k0, 0, GOST_KDF_BLOCK);
    if (key_len <= GOST_KDF_BLOCK) {
        if (key == NULL && key_len != 0U) {
            return GOST_ERR_PARAM;
        }
        if (key_len != 0U) {
            memcpy(k0, key, key_len);
        }
        return GOST_OK;
    }
    gost_hash_ctx_t ctx;
    gost_hash_init(&ctx, width);
    gost_hash_update(&ctx, key, key_len);
    uint8_t digest[GOST_HMAC_MAX_DIGEST];
    gost_hash_final(&ctx, digest);
    memcpy(k0, digest, width == GOST_HASH_256 ? 32U : 64U);
    return GOST_OK;
}

gost_status_t gost_hmac_init(gost_hmac_ctx_t *ctx, const uint8_t *key, size_t key_len,
                             gost_hash_width_t width)
{
    if (ctx == NULL) {
        return GOST_ERR_PARAM;
    }
    memset(ctx, 0, sizeof(*ctx));
    uint8_t k0[GOST_KDF_BLOCK];
    gost_status_t status = key_block(key, key_len, width, k0);
    if (status != GOST_OK) {
        return status;
    }
    uint8_t padded[GOST_KDF_BLOCK];
    for (unsigned i = 0; i < GOST_KDF_BLOCK; i++) {
        padded[i] = k0[i] ^ GOST_HMAC_IPAD;
    }
    gost_hash_init(&ctx->inner, width);
    gost_hash_update(&ctx->inner, padded, GOST_KDF_BLOCK);
    for (unsigned i = 0; i < GOST_KDF_BLOCK; i++) {
        padded[i] = k0[i] ^ GOST_HMAC_OPAD;
    }
    gost_hash_init(&ctx->outer, width);
    gost_hash_update(&ctx->outer, padded, GOST_KDF_BLOCK);
    return GOST_OK;
}

gost_status_t gost_hmac_update(gost_hmac_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (ctx == NULL || (data == NULL && len != 0U)) {
        return GOST_ERR_PARAM;
    }
    gost_hash_update(&ctx->inner, data, len);
    return GOST_OK;
}

/** @return The digest size of the configured hash width. */
static size_t hmac_digest_size(const gost_hmac_ctx_t *ctx)
{
    return ctx->inner.digest_size;
}

gost_status_t gost_hmac_final(gost_hmac_ctx_t *ctx, uint8_t *out)
{
    if (ctx == NULL || out == NULL) {
        return GOST_ERR_PARAM;
    }
    gost_hash_final(&ctx->inner, ctx->inner_digest);
    gost_hash_update(&ctx->outer, ctx->inner_digest, hmac_digest_size(ctx));
    gost_hash_final(&ctx->outer, out);
    return GOST_OK;
}

gost_status_t gost_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                        gost_hash_width_t width, uint8_t *out)
{
    if (out == NULL || (width != GOST_HASH_256 && width != GOST_HASH_512)) {
        return GOST_ERR_PARAM;
    }
    gost_hmac_ctx_t ctx;
    gost_status_t status = gost_hmac_init(&ctx, key, key_len, width);
    if (status != GOST_OK) {
        return status;
    }
    gost_hash_update(&ctx.inner, msg, msg_len);
    return gost_hmac_final(&ctx, out);
}

/**
 *  @brief One PRF round of PBKDF2: U = HMAC(password, data).
 *
 *  The keyed interior states of @p base are copied per round, so only
 *  the round message is compressed; no allocation is involved.
 */
static gost_status_t pbkdf2_prf(const gost_hmac_ctx_t *base, const uint8_t data[4],
                                size_t data_len, const uint8_t *accumulation, size_t acc_len,
                                uint8_t u[GOST_HMAC_MAX_DIGEST])
{
    gost_hmac_ctx_t work = *base;
    gost_hash_update(&work.inner, data, data_len);
    gost_hash_update(&work.inner, accumulation, acc_len);
    gost_hash_final(&work.inner, work.inner_digest);
    gost_hash_update(&work.outer, work.inner_digest, work.inner.digest_size);
    gost_hash_final(&work.outer, u);
    return GOST_OK;
}

gost_status_t gost_pbkdf2(const uint8_t *password, size_t password_len, const uint8_t *salt,
                          size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len)
{
    if (out == NULL || out_len == 0U || iterations == 0U) {
        return GOST_ERR_PARAM;
    }
    size_t h_len = 64U;
    size_t blocks = (out_len + h_len - 1U) / h_len;
    if ((uint64_t)blocks > (uint64_t)0xFFFFFFFFU) {
        return GOST_ERR_PARAM;
    }
    gost_hmac_ctx_t base;
    gost_status_t status = gost_hmac_init(&base, password, password_len, GOST_HASH_512);
    if (status != GOST_OK) {
        return status;
    }
    uint8_t *cursor = out;
    size_t remaining = out_len;
    for (uint32_t block = 1; block <= blocks; block++) {
        uint8_t prefix[4] = { 0, 0, (uint8_t)(block >> 8U), (uint8_t)block };
        uint8_t u[GOST_HMAC_MAX_DIGEST];
        status = pbkdf2_prf(&base, salt, salt_len, prefix, sizeof(prefix), u);
        if (status != GOST_OK) {
            return status;
        }
        uint8_t accumulation[GOST_HMAC_MAX_DIGEST];
        memcpy(accumulation, u, h_len);
        for (uint32_t round = 1; round < iterations; round++) {
            status = pbkdf2_prf(&base, prefix, 0U, u, h_len, u);
            if (status != GOST_OK) {
                return status;
            }
            for (size_t i = 0; i < h_len; i++) {
                accumulation[i] ^= u[i];
            }
        }
        size_t chunk = remaining < h_len ? remaining : h_len;
        memcpy(cursor, accumulation, chunk);
        cursor += chunk;
        remaining -= chunk;
    }
    return GOST_OK;
}
