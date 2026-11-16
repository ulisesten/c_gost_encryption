/**
 *  @file  hkdf.h
 *  @brief  HKDF (RFC 5869) over HMAC-Streebog (RFC 7836).
 *
 *  The construction is RFC 5869 with the PRF fixed to
 *  HMAC_GOSTR3411_2012_256 or HMAC_GOSTR3411_2012_512; there are no
 *  official HKDF-Streebog vectors, so the known-answer tests of this
 *  library fix the values produced here and cross-checked against an
 *  independent implementation.
 *
 *  Use distinct @c info labels per purpose, e.g. "session-enc",
 *  "frame-key", "sender-key", so derived keys never collide.
 */
#ifndef GOST_HKDF_H
#define GOST_HKDF_H

#include <stddef.h>
#include <stdint.h>

#include "../common.h"
#include "kdf.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Largest hash output used by HKDF (Streebog-512). */
#define GOST_HKDF_MAX_HASH 64U

/**
 *  @brief  HKDF-Extract: PRK = HMAC(salt, IKM).
 *
 *  The output length equals the digest size of @p width: 32 bytes for
 *  256, 64 for 512.  An absent salt (NULL, 0) follows RFC 5869 and
 *  hashes with a zero-filled salt of HashLen bytes.
 *
 *  @param  width    Digest width of the PRF.
 *  @param  salt     Salt bytes, may be NULL when salt_len is 0.
 *  @param  salt_len Salt length.
 *  @param  ikm      Input keying material.
 *  @param  ikm_len  Input keying material length.
 *  @param  prk      Pseudo random key destination, HashLen bytes.
 *  @return GOST_OK, or GOST_ERR_PARAM for invalid arguments.
 */
gost_status_t gost_hkdf_extract(gost_hash_width_t width, const uint8_t *salt, size_t salt_len,
                                const uint8_t *ikm, size_t ikm_len, uint8_t *prk);

/**
 *  @brief  HKDF-Expand: OKM = first out_len bytes of the T chain.
 *
 *  Requires PRK of at least HashLen bytes and caps the output at
 *  255 * HashLen bytes, as RFC 5869 mandates.
 *
 *  @param  width    Digest width of the PRF.
 *  @param  prk      Pseudo random key.
 *  @param  prk_len  Pseudo random key length, at least HashLen.
 *  @param  info     Context bytes, may be NULL when info_len is 0.
 *  @param  info_len Context length.
 *  @param  out      Output keying material destination.
 *  @param  out_len  Output length, at most 255 * HashLen.
 *  @return GOST_OK, or GOST_ERR_PARAM for invalid arguments.
 */
gost_status_t gost_hkdf_expand(gost_hash_width_t width, const uint8_t *prk, size_t prk_len,
                               const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* GOST_HKDF_H */
