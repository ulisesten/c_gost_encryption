/**
 *  @file  kuznyechik.h
 *  @brief  Kuznyechik block cipher, GOST R 34.12-2015: 128-bit block,
 *          256-bit key, 10 rounds.
 *
 *  Blocks and keys are kept big-endian, exactly as the standard prints
 *  its test examples.  The implementation is table-light: the S-box is
 *  a 256-byte table and the linear transform is computed on the fly,
 *  so no large precomputed tables exist.  Like every software table
 *  driven cipher, the S-box lookups are cache-timing observable; see
 *  the security notes in the README before using in hostile settings.
 */
#ifndef GOST_KUZNYECHIK_H
#define GOST_KUZNYECHIK_H

#include <stddef.h>
#include <stdint.h>

#include "../common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Cipher block size in bytes. */
#define GOST_KUZNYECHIK_BLOCK 16U

/** Cipher key size in bytes. */
#define GOST_KUZNYECHIK_KEY 32U

/** Number of round keys derived by the key schedule. */
#define GOST_KUZNYECHIK_ROUNDS 10U

/**
 *  @brief  Kuznyechik key schedule.  Treat the contents as private.
 */
typedef struct gost_kuznyechik {
    uint8_t round_keys[GOST_KUZNYECHIK_ROUNDS][GOST_KUZNYECHIK_BLOCK];
    /**< Iterative keys K1..K10. */
} gost_kuznyechik_t;

/**
 *  @brief  Expand a 256-bit master key into the 10 iterative keys.
 *  @param  ctx  Schedule to initialize.
 *  @param  key  Master key, 32 bytes.
 *  @return GOST_OK, or GOST_ERR_PARAM for a NULL pointer.
 */
gost_status_t gost_kuznyechik_init(gost_kuznyechik_t *ctx, const uint8_t key[GOST_KUZNYECHIK_KEY]);

/**
 *  @brief  Encrypt one 16-byte block.
 *  @param  ctx  Initialized schedule.
 *  @param  in   Plaintext block.
 *  @param  out  Ciphertext block; may alias @p in.
 *  @return GOST_OK, or GOST_ERR_PARAM for a NULL pointer.
 */
gost_status_t gost_kuznyechik_encrypt_block(const gost_kuznyechik_t *ctx, const uint8_t in[GOST_KUZNYECHIK_BLOCK],
                                            uint8_t out[GOST_KUZNYECHIK_BLOCK]);

/**
 *  @brief  Decrypt one 16-byte block.
 *  @param  ctx  Initialized schedule.
 *  @param  in   Ciphertext block.
 *  @param  out  Plaintext block; may alias @p in.
 *  @return GOST_OK, or GOST_ERR_PARAM for a NULL pointer.
 */
gost_status_t gost_kuznyechik_decrypt_block(const gost_kuznyechik_t *ctx, const uint8_t in[GOST_KUZNYECHIK_BLOCK],
                                            uint8_t out[GOST_KUZNYECHIK_BLOCK]);

#ifdef __cplusplus
}
#endif

#endif /* GOST_KUZNYECHIK_H */
