/**
 *  @file  kdf.h
 *  @brief HMAC and password-based key derivation per RFC 2104 and
 *         RFC 7836 / R 50.1.111-2016 on top of GOST R 34.11-2012
 *         (Streebog).
 *
 *  Every MAC here follows RFC 2104 over the streaming presentation of
 *  the hash (RFC 6986, digest bytes least significant first), which is
 *  the presentation of the test vectors of RFC 7836 and of the Linux
 *  kernel testmgr suite.  Keys are zero padded to the right (RFC 2104).
 *
 *  PBKDF2 derives keying material with HMAC-Streebog-512 as the pseudo
 *  random function, per R 50.1.111-2016 and the draft-pkcs5-gost test
 *  vectors; the output is 512 for the PRF regardless of the requested
 *  derived-key length, which is then truncated.  It is NOT memory hard:
 *  no GOST standard defines a memory hard password KDF.
 */
#ifndef GOST_KDF_H
#define GOST_KDF_H

#include <stddef.h>
#include <stdint.h>

#include "../common.h"
#include "../hash/hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Largest HMAC output (Streebog-512). */
#define GOST_HMAC_MAX_DIGEST 64U

/** Streebog block size, the HMAC key block as well. */
#define GOST_KDF_BLOCK 64U

/**
 *  @brief  Streaming HMAC state.  Treat the contents as private.
 */
typedef struct gost_hmac_ctx {
    gost_hash_ctx_t inner;  /**< Interior hash state. */
    gost_hash_ctx_t outer;  /**< Outer hash state. */
    uint8_t inner_digest[GOST_HMAC_MAX_DIGEST];  /**< Interior digest scratch. */
} gost_hmac_ctx_t;/**
 *  @brief  HMAC of a complete message in one call.
 *  @param  key      Authentication key, may be NULL when key_len is 0.
 *  @param  key_len  Key length in bytes.
 *  @param  msg      Message bytes.
 *  @param  msg_len  Message length in bytes.
 *  @param  width    Digest width of the inner hash.
 *  @param  out      MAC destination, 32 bytes for 256, 64 for 512.
 *  @return GOST_OK, or GOST_ERR_PARAM for an invalid width or pointer.
 */
gost_status_t gost_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                        gost_hash_width_t width, uint8_t *out);

/**
 *  @brief  Initialize a streaming HMAC state.
 *
 *  The state absorbs keys of any length: keys longer than the hash block
 *  are compressed first, as RFC 2104 requires.
 *
 *  @param  ctx      State to initialize.
 *  @param  key      Authentication key, may be NULL when key_len is 0.
 *  @param  key_len  Key length in bytes.
 *  @param  width    Digest width of the inner hash.
 *  @return GOST_OK, or GOST_ERR_PARAM for an invalid width or pointer.
 */
gost_status_t gost_hmac_init(gost_hmac_ctx_t *ctx, const uint8_t *key, size_t key_len,
                             gost_hash_width_t width);

/**
 *  @brief  Absorb message bytes into a streaming HMAC state.
 *  @param  ctx   Initialized state.
 *  @param  data  Message bytes.
 *  @param  len   Message length.
 *  @return GOST_OK, or GOST_ERR_STATE before @c gost_hmac_init.
 */
gost_status_t gost_hmac_update(gost_hmac_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 *  @brief  Finish a streaming HMAC and write the MAC.
 *  @param  ctx  Initialized state, consumed by the call.
 *  @param  out  MAC destination of the configured width's size.
 *  @return GOST_OK, or GOST_ERR_PARAM for a NULL destination.
 */
gost_status_t gost_hmac_final(gost_hmac_ctx_t *ctx, uint8_t *out);

/**
 *  @brief  PBKDF2 key derivation per R 50.1.111-2016 (RFC 8018 shape).
 *
 *  Derives @p out_len bytes from the password and salt through
 *  @p iterations rounds of the pseudo random function
 *  HMAC-GOSTR3411-2012-512 (fixed by the standard, regardless of the
 *  requested length).  Password and salt may be NULL when their lengths
 *  are zero.
 *
 *  @param  password      Password bytes, may be NULL if empty.
 *  @param  password_len  Password length.
 *  @param  salt          Salt bytes, may be NULL if empty.
 *  @param  salt_len      Salt length.
 *  @param  iterations    Round count (non zero).
 *  @param  out           Derived key destination.
 *  @param  out_len       Derived key length, non zero.
 *  @return GOST_OK, or GOST_ERR_PARAM for invalid arguments or when the
 *          output length overflows the block indexing.
 */
gost_status_t gost_pbkdf2(const uint8_t *password, size_t password_len, const uint8_t *salt,
                          size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* GOST_KDF_H */
