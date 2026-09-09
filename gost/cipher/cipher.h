/**
 *  @file  cipher.h
 *  @brief Symmetric encryption per GOST 28147-89.
 *
 *  The block cipher operates on 64-bit blocks with a 256-bit key and one
 *  of the standard substitution tables.  Four modes are provided:
 *  simple substitution (ECB), gamma (counter-like stream), gamma with
 *  cipher feedback (CFB) and the authentication tag (imitovstavka).
 *
 *  All stream modes transform the caller buffer in place and accept
 *  messages of any length.  ECB and MAC require the message length to be
 *  a multiple of the 8-byte block size.
 *
 *  The mode mapping matches the reference gost-cryptography project:
 *  `Гаммование_с_обратной_связью` is @c gost_cipher_cfb_encrypt and
 *  `Гаммование` is @c gost_cipher_gamma.
 */
#ifndef GOST_CIPHER_H
#define GOST_CIPHER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Size of a cipher block in bytes. */
#define GOST_CIPHER_BLOCK 8
/** Size of the cipher key in 32-bit words. */
#define GOST_CIPHER_KEY_WORDS 8

/** Substitution table identifiers, ordered as in the reference project. */
typedef enum gost_sbox_id {
    GOST_SBOX_TEST = 0,              /**< Gost28147-89-TestParamSet. */
    GOST_SBOX_CRYPTOPRO_A,           /**< Gost28147-89-CryptoPro-A-ParamSet. */
    GOST_SBOX_CRYPTOPRO_B,           /**< Gost28147-89-CryptoPro-B-ParamSet. */
    GOST_SBOX_CRYPTOPRO_C,           /**< Gost28147-89-CryptoPro-C-ParamSet. */
    GOST_SBOX_CRYPTOPRO_D,           /**< Gost28147-89-CryptoPro-D-ParamSet. */
    GOST_SBOX_TC26_Z,                /**< tc26-gost-28147-param-Z. */
    GOST_SBOX_R3410_94_TEST,         /**< GostR3410-94-TestParamSet. */
    GOST_SBOX_R3410_94_CRYPTOPRO,    /**< GostR3410-94-CryptoProParamSet. */
    GOST_SBOX_EAC,                   /**< EACParamSet. */
    GOST_SBOX_DKE_A_001,             /**< ДКЕ-А-001. */
    GOST_SBOX_COUNT                  /**< Number of built-in tables. */
} gost_sbox_id_t;

/**
 *  @brief  Cipher state: expanded key and substitution table.  Treat the
 *          contents as private.
 */
typedef struct gost_cipher {
    uint32_t key[GOST_CIPHER_KEY_WORDS];  /**< Round key schedule. */
    uint32_t pi[8][256];                  /**< Combined substitution lookups. */
} gost_cipher_t;

/**
 *  @brief  Prepare a cipher with a built-in substitution table.
 *  @param  ctx   Cipher state to initialize.
 *  @param  key   256-bit key as 8 little-endian 32-bit words.
 *  @param  sbox  Built-in table identifier.
 *  @return GOST_OK, or GOST_ERR_PARAM for an unknown identifier.
 */
gost_status_t gost_cipher_init(gost_cipher_t *ctx, const uint32_t key[GOST_CIPHER_KEY_WORDS],
                               gost_sbox_id_t sbox);

/**
 *  @brief  Prepare a cipher with a caller supplied substitution table.
 *  @param  ctx   Cipher state to initialize.
 *  @param  key   256-bit key as 8 little-endian 32-bit words.
 *  @param  sbox  8 rows of 16 nibble values.
 *  @return GOST_OK.
 */
gost_status_t gost_cipher_init_sbox(gost_cipher_t *ctx, const uint32_t key[GOST_CIPHER_KEY_WORDS],
                                    const uint8_t sbox[8][16]);

/**
 *  @brief  Encrypt one block in place (simple substitution, cycle 32-Z).
 *  @param  ctx    Initialized cipher.
 *  @param  block  8-byte block, modified in place.
 */
void gost_cipher_block_encrypt(const gost_cipher_t *ctx, uint8_t block[GOST_CIPHER_BLOCK]);

/**
 *  @brief  Decrypt one block in place (simple substitution, cycle 32-R).
 *  @param  ctx    Initialized cipher.
 *  @param  block  8-byte block, modified in place.
 */
void gost_cipher_block_decrypt(const gost_cipher_t *ctx, uint8_t block[GOST_CIPHER_BLOCK]);

/**
 *  @brief  ECB encryption of a whole message (in place).
 *  @return GOST_OK, or GOST_ERR_PARAM when len is not a block multiple.
 */
gost_status_t gost_cipher_ecb_encrypt(const gost_cipher_t *ctx, uint8_t *data, size_t len);

/**
 *  @brief  ECB decryption of a whole message (in place).
 *  @return GOST_OK, or GOST_ERR_PARAM when len is not a block multiple.
 */
gost_status_t gost_cipher_ecb_decrypt(const gost_cipher_t *ctx, uint8_t *data, size_t len);

/**
 *  @brief  Gamma mode (counter stream, reversible, in place).
 *
 *  The counter follows the reference project exactly: it starts as the
 *  encrypted @p iv and advances by C1 and C2 per block.
 *
 *  @param  ctx  Initialized cipher.
 *  @param  iv   Initial state as two 32-bit words.
 *  @param  data Message bytes, modified in place.
 *  @param  len  Message length, any size.
 *  @return GOST_OK.
 */
gost_status_t gost_cipher_gamma(const gost_cipher_t *ctx, const uint32_t iv[2], uint8_t *data,
                                size_t len);

/**
 *  @brief  Gamma with cipher feedback, encryption (in place).
 *  @param  ctx  Initialized cipher.
 *  @param  iv   Initial state as two 32-bit words.
 *  @param  data Plaintext, replaced with ciphertext.
 *  @param  len  Message length, any size.
 *  @return GOST_OK.
 */
gost_status_t gost_cipher_cfb_encrypt(const gost_cipher_t *ctx, const uint32_t iv[2], uint8_t *data,
                                      size_t len);

/**
 *  @brief  Gamma with cipher feedback, decryption (in place).
 *  @param  ctx  Initialized cipher.
 *  @param  iv   Initial state as two 32-bit words.
 *  @param  data Ciphertext, replaced with plaintext.
 *  @param  len  Message length, any size.
 *  @return GOST_OK.
 */
gost_status_t gost_cipher_cfb_decrypt(const gost_cipher_t *ctx, const uint32_t iv[2], uint8_t *data,
                                      size_t len);

/**
 *  @brief  Authentication tag (imitovstavka) of a whole message.
 *
 *  Per GOST 28147-89 the tag is the 32-bit value in the first four bytes
 *  of @p tag; all eight bytes of the final state are returned for
 *  compatibility with the reference project.
 *
 *  @param  ctx  Initialized cipher.
 *  @param  data Message bytes.
 *  @param  len  Message length, multiple of the block size.
 *  @param  tag  8-byte destination.
 *  @return GOST_OK, or GOST_ERR_PARAM when len is not a block multiple.
 */
gost_status_t gost_cipher_mac(const gost_cipher_t *ctx, const uint8_t *data, size_t len,
                              uint8_t tag[GOST_CIPHER_BLOCK]);

#ifdef __cplusplus
}
#endif

#endif /* GOST_CIPHER_H */
