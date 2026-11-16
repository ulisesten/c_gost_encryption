/**
 *  @file  aead.h
 *  @brief  Authenticated encryption with associated data, built on
 *          Kuznyechik-CTR-ACPKM (GOST R 34.13-2015, RFC 8645) plus
 *          CMAC (GOST R 34.13-2015), encrypt-then-MAC.
 *
 *  Construction, fixed by this library:
 *
 *  - PRK = HKDF-Extract(HMAC-Streebog-256, salt = nonce, IKM = key).
 *  - Content key  K_enc = HKDF-Expand(PRK, "gost-aead-enc", 256).
 *  - MAC key      K_mac = HKDF-Expand(PRK, "gost-aead-mac", 256).
 *  - Ciphertext   = CTR-ACPKM(K_enc, ICN = nonce[0..8), section 4 KiB).
 *  - Tag          = CMAC-128(K_mac, len8(aad) | aad | len8(ct) | ct |
 *                             nonce), 8-byte big-endian lengths.
 *
 *  Security contract:
 *
 *  - The nonce MUST be unique per key; a nonce repetition under one
 *    key reveals the XOR of the plaintexts and enables tag forgery.
 *    With counters as nonce this is a caller obligation.
 *  - @c gost_aead_open verifies the tag in constant time before any
 *    decryption; on failure no plaintext is written (the output buffer
 *    is zeroed) and GOST_ERR_AUTH is returned.
 *  - The full 16-byte nonce is authenticated; only its first half
 *    feeds the counter, so the low half stays available for protocol
 *    framing if desired.
 */
#ifndef GOST_AEAD_H
#define GOST_AEAD_H

#include <stddef.h>
#include <stdint.h>

#include "../common.h"
#include "../ctr/ctr.h"
#include "../cmac/cmac.h"
#include "../kdf/hkdf.h"

#ifdef __cplusplus
extern "C" {
#endif

/** AEAD key size in bytes. */
#define GOST_AEAD_KEY GOST_KUZNYECHIK_KEY

/** AEAD nonce size in bytes. */
#define GOST_AEAD_NONCE 16U

/** AEAD tag size in bytes. */
#define GOST_AEAD_TAG GOST_CMAC_TAG

/**
 *  @brief  Seal: encrypt and authenticate in one call.
 *
 *  @param  key      256-bit master key.
 *  @param  nonce    16-byte nonce, unique per key.
 *  @param  aad      Associated data, authenticated but not encrypted;
 *                   may be NULL when aad_len is 0.
 *  @param  aad_len  Associated data length.
 *  @param  in       Plaintext, may be NULL when in_len is 0.
 *  @param  in_len   Plaintext length.
 *  @param  out      Ciphertext destination, in_len bytes; may alias @p in.
 *  @param  tag      Tag destination, 16 bytes.
 *  @return GOST_OK, or GOST_ERR_PARAM for invalid arguments.
 */
gost_status_t gost_aead_seal(const uint8_t key[GOST_AEAD_KEY], const uint8_t nonce[GOST_AEAD_NONCE],
                             const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t in_len,
                             uint8_t *out, uint8_t tag[GOST_AEAD_TAG]);

/**
 *  @brief  Open: verify the tag, then decrypt.
 *
 *  On any authentication failure the output buffer is zeroed and
 *  GOST_ERR_AUTH is returned; no plaintext is released.
 *
 *  @param  key      256-bit master key.
 *  @param  nonce    16-byte nonce used at sealing.
 *  @param  aad      Associated data, may be NULL when aad_len is 0.
 *  @param  aad_len  Associated data length.
 *  @param  in       Ciphertext, may be NULL when in_len is 0.
 *  @param  in_len   Ciphertext length.
 *  @param  tag      Tag received with the ciphertext.
 *  @param  out      Plaintext destination, in_len bytes; may alias @p in.
 *  @return GOST_OK, GOST_ERR_AUTH when the tag does not verify, or
 *          GOST_ERR_PARAM for invalid arguments.
 */
gost_status_t gost_aead_open(const uint8_t key[GOST_AEAD_KEY], const uint8_t nonce[GOST_AEAD_NONCE],
                             const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t in_len,
                             const uint8_t tag[GOST_AEAD_TAG], uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* GOST_AEAD_H */
