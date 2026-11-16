/**
 *  @file  aead.c
 *  @brief  AEAD construction: Kuznyechik-CTR-ACPKM + CMAC,
 *          encrypt-then-MAC.
 */
#include "aead.h"

#include <string.h>

/** Info label separating the content encryption key. */
static const char aead_label_enc[] = "gost-aead-enc";

/** Info label separating the MAC key. */
static const char aead_label_mac[] = "gost-aead-mac";

/**
 *  @brief  Derive the AEAD subkeys from the master key and nonce.
 */
static gost_status_t derive_keys(const uint8_t key[GOST_AEAD_KEY], const uint8_t nonce[GOST_AEAD_NONCE],
                                 uint8_t enc_key[GOST_AEAD_KEY], uint8_t mac_key[GOST_AEAD_KEY])
{
    uint8_t prk[32];
    gost_status_t status = gost_hkdf_extract(GOST_HASH_256, nonce, GOST_AEAD_NONCE, key, GOST_AEAD_KEY, prk);
    if (status != GOST_OK) {
        return status;
    }
    status = gost_hkdf_expand(GOST_HASH_256, prk, sizeof(prk), (const uint8_t *)aead_label_enc,
                              sizeof(aead_label_enc) - 1U, enc_key, GOST_AEAD_KEY);
    if (status != GOST_OK) {
        return status;
    }
    status = gost_hkdf_expand(GOST_HASH_256, prk, sizeof(prk), (const uint8_t *)aead_label_mac,
                              sizeof(aead_label_mac) - 1U, mac_key, GOST_AEAD_KEY);
    gost_secure_zero(prk, sizeof(prk));
    return status;
}

/**
 *  @brief  Tag input: len8(aad) | aad | len8(ct) | ct | nonce.
 *
 *  The 8-byte big-endian lengths frame the variable parts so no two
 *  different inputs collide.
 */
static gost_status_t tag_input(const uint8_t nonce[GOST_AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                               const uint8_t *ct, size_t ct_len, gost_cmac_ctx_t *mac)
{
    uint8_t length[8];
    for (unsigned i = 0; i < 8U; i++) {
        length[i] = (uint8_t)((uint64_t)aad_len >> (56U - 8U * i));
    }
    gost_status_t status = gost_cmac_update(mac, length, sizeof(length));
    if (status != GOST_OK) {
        return status;
    }
    status = gost_cmac_update(mac, aad, aad_len);
    if (status != GOST_OK) {
        return status;
    }
    for (unsigned i = 0; i < 8U; i++) {
        length[i] = (uint8_t)((uint64_t)ct_len >> (56U - 8U * i));
    }
    status = gost_cmac_update(mac, length, sizeof(length));
    if (status != GOST_OK) {
        return status;
    }
    status = gost_cmac_update(mac, ct, ct_len);
    if (status != GOST_OK) {
        return status;
    }
    return gost_cmac_update(mac, nonce, GOST_AEAD_NONCE);
}

gost_status_t gost_aead_seal(const uint8_t key[GOST_AEAD_KEY], const uint8_t nonce[GOST_AEAD_NONCE],
                             const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t in_len,
                             uint8_t *out, uint8_t tag[GOST_AEAD_TAG])
{
    if (key == NULL || nonce == NULL || tag == NULL || (aad == NULL && aad_len != 0U) ||
        (in == NULL && in_len != 0U) || out == NULL) {
        return GOST_ERR_PARAM;
    }
    uint8_t enc_key[GOST_AEAD_KEY];
    uint8_t mac_key[GOST_AEAD_KEY];
    gost_status_t status = derive_keys(key, nonce, enc_key, mac_key);
    if (status != GOST_OK) {
        return status;
    }
    /* The ICN is the first half of the nonce; the second half only
       takes part in the tag input. */
    status = gost_ctr_acpkm(enc_key, nonce, 0U, in, out, in_len);
    if (status != GOST_OK) {
        gost_secure_zero(enc_key, sizeof(enc_key));
        gost_secure_zero(mac_key, sizeof(mac_key));
        return status;
    }
    gost_cmac_ctx_t mac;
    status = gost_cmac_init(&mac, mac_key);
    if (status == GOST_OK) {
        status = tag_input(nonce, aad, aad_len, out, in_len, &mac);
        if (status == GOST_OK) {
            status = gost_cmac_final(&mac, tag);
        }
    }
    gost_secure_zero(enc_key, sizeof(enc_key));
    gost_secure_zero(mac_key, sizeof(mac_key));
    return status;
}

gost_status_t gost_aead_open(const uint8_t key[GOST_AEAD_KEY], const uint8_t nonce[GOST_AEAD_NONCE],
                             const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t in_len,
                             const uint8_t tag[GOST_AEAD_TAG], uint8_t *out)
{
    if (key == NULL || nonce == NULL || tag == NULL || (aad == NULL && aad_len != 0U) ||
        (in == NULL && in_len != 0U) || out == NULL) {
        return GOST_ERR_PARAM;
    }
    uint8_t enc_key[GOST_AEAD_KEY];
    uint8_t mac_key[GOST_AEAD_KEY];
    gost_status_t status = derive_keys(key, nonce, enc_key, mac_key);
    if (status != GOST_OK) {
        return status;
    }
    /* Verify the tag in constant time BEFORE decrypting anything, so
       no plaintext is ever released on failure. */
    gost_cmac_ctx_t mac;
    status = gost_cmac_init(&mac, mac_key);
    if (status == GOST_OK) {
        status = tag_input(nonce, aad, aad_len, in, in_len, &mac);
        if (status == GOST_OK) {
            uint8_t check[GOST_AEAD_TAG];
            status = gost_cmac_final(&mac, check);
            if (status == GOST_OK) {
                if (gost_ct_equal(check, tag, GOST_AEAD_TAG) == 0) {
                    status = GOST_ERR_AUTH;
                }
                gost_secure_zero(check, sizeof(check));
            }
        }
    }
    if (status == GOST_OK) {
        status = gost_ctr_acpkm(enc_key, nonce, 0U, in, out, in_len);
        if (status != GOST_OK) {
            gost_secure_zero(out, in_len);
        }
    } else {
        gost_secure_zero(out, in_len);
    }
    gost_secure_zero(enc_key, sizeof(enc_key));
    gost_secure_zero(mac_key, sizeof(mac_key));
    return status;
}
