/**
 *  @file  hkdf.c
 *  @brief  HKDF per RFC 5869 with HMAC-Streebog as the PRF.
 */
#include "hkdf.h"

#include <string.h>

gost_status_t gost_hkdf_extract(gost_hash_width_t width, const uint8_t *salt, size_t salt_len,
                                const uint8_t *ikm, size_t ikm_len, uint8_t *prk)
{
    if (prk == NULL || (width != GOST_HASH_256 && width != GOST_HASH_512) ||
        (ikm == NULL && ikm_len != 0U) || (salt == NULL && salt_len != 0U)) {
        return GOST_ERR_PARAM;
    }
    /* RFC 5869: salt defaults to HashLen zeros when absent. */
    return gost_hmac(salt, salt_len, ikm, ikm_len, width, prk);
}

gost_status_t gost_hkdf_expand(gost_hash_width_t width, const uint8_t *prk, size_t prk_len,
                               const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len)
{
    if (out == NULL || (width != GOST_HASH_256 && width != GOST_HASH_512) ||
        (prk == NULL && prk_len != 0U) || (info == NULL && info_len != 0U)) {
        return GOST_ERR_PARAM;
    }
    size_t hash_len = width == GOST_HASH_256 ? 32U : 64U;
    if (prk_len < hash_len) {
        return GOST_ERR_PARAM;
    }
    if (out_len > 255U * hash_len) {
        return GOST_ERR_PARAM;
    }
    uint8_t t[GOST_HKDF_MAX_HASH];
    size_t t_len = 0U;
    size_t produced = 0U;
    for (unsigned counter = 1U; produced < out_len; counter++) {
        gost_hmac_ctx_t ctx;
        gost_status_t status = gost_hmac_init(&ctx, prk, prk_len, width);
        if (status != GOST_OK) {
            return status;
        }
        status = gost_hmac_update(&ctx, t, t_len);
        if (status != GOST_OK) {
            return status;
        }
        status = gost_hmac_update(&ctx, info, info_len);
        if (status != GOST_OK) {
            return status;
        }
        uint8_t counter_byte = (uint8_t)counter;
        status = gost_hmac_update(&ctx, &counter_byte, 1U);
        if (status != GOST_OK) {
            return status;
        }
        status = gost_hmac_final(&ctx, t);
        if (status != GOST_OK) {
            return status;
        }
        t_len = hash_len;
        size_t take = out_len - produced;
        if (take > hash_len) {
            take = hash_len;
        }
        memcpy(out + produced, t, take);
        produced += take;
    }
    gost_secure_zero(t, sizeof(t));
    return GOST_OK;
}
