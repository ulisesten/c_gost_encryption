/**
 *  @file  cmac.h
 *  @brief  CMAC per GOST R 34.13-2015 over Kuznyechik: 128-bit block,
 *          128-bit tag.
 *
 *  The MAC is the OMAC construction of GOST R 34.13-2015: the chaining
 *  value starts at zero, the last block is padded with 10* when
 *  incomplete, and the subkeys K1/K2 are doublings of E(0^16) in
 *  GF(2^128) modulo x^128 + x^7 + x^6 + x^5 + x^4 + x + 1.  The tag is
 *  the full 16-byte block; do not truncate below 12 bytes without a
 *  fresh analysis.
 */
#ifndef GOST_CMAC_H
#define GOST_CMAC_H

#include <stddef.h>
#include <stdint.h>

#include "../common.h"
#include "../kuznyechik/kuznyechik.h"

#ifdef __cplusplus
extern "C" {
#endif

/** CMAC block size in bytes (Kuznyechik block). */
#define GOST_CMAC_BLOCK 16U

/** CMAC tag size in bytes. */
#define GOST_CMAC_TAG 16U

/**
 *  @brief  Streaming CMAC state.  Treat the contents as private.
 */
typedef struct gost_cmac_ctx {
    gost_kuznyechik_t cipher;  /**< Cipher keyed with the MAC key. */
    uint8_t key1[GOST_CMAC_BLOCK];  /**< Subkey for complete last blocks. */
    uint8_t key2[GOST_CMAC_BLOCK];  /**< Subkey for padded last blocks. */
    uint8_t state[GOST_CMAC_BLOCK];  /**< Chaining value. */
    uint8_t pending[GOST_CMAC_BLOCK];  /**< Last block, kept until final. */
    size_t pending_len;  /**< Bytes in @c pending. */
} gost_cmac_ctx_t;

/**
 *  @brief  Initialize a streaming CMAC.
 *  @param  ctx  State to initialize.
 *  @param  key  256-bit MAC key.
 *  @return GOST_OK, or GOST_ERR_PARAM for a NULL pointer.
 */
gost_status_t gost_cmac_init(gost_cmac_ctx_t *ctx, const uint8_t key[GOST_KUZNYECHIK_KEY]);

/**
 *  @brief  Absorb message bytes into a streaming CMAC.
 *  @param  ctx   Initialized state.
 *  @param  data  Message bytes, may be NULL when len is 0.
 *  @param  len   Message length.
 *  @return GOST_OK, or GOST_ERR_PARAM for invalid arguments.
 */
gost_status_t gost_cmac_update(gost_cmac_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 *  @brief  Finish a streaming CMAC and write the 16-byte tag.
 *
 *  The state is erased with @c gost_secure_zero before returning, so a
 *  state cannot be reused after final.
 *
 *  @param  ctx  Initialized state.
 *  @param  tag  Tag destination, 16 bytes.
 *  @return GOST_OK, or GOST_ERR_PARAM for a NULL destination.
 */
gost_status_t gost_cmac_final(gost_cmac_ctx_t *ctx, uint8_t tag[GOST_CMAC_TAG]);

/**
 *  @brief  CMAC of a complete message in one call.
 *  @param  key      256-bit MAC key.
 *  @param  msg      Message bytes, may be NULL when msg_len is 0.
 *  @param  msg_len  Message length.
 *  @param  tag      Tag destination, 16 bytes.
 *  @return GOST_OK, or GOST_ERR_PARAM for invalid arguments.
 */
gost_status_t gost_cmac(const uint8_t key[GOST_KUZNYECHIK_KEY], const uint8_t *msg, size_t msg_len,
                        uint8_t tag[GOST_CMAC_TAG]);

#ifdef __cplusplus
}
#endif

#endif /* GOST_CMAC_H */
