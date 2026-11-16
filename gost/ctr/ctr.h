/**
 *  @file  ctr.h
 *  @brief  CTR-ACPKM: the counter mode of GOST R 34.13-2015 extended
 *          with the internal re-keying mechanism ACPKM of RFC 8645.
 *
 *  The block counter uses c = 64 bits, so the initial counter nonce
 *  (ICN) is 8 bytes and CTR_1 = ICN | 0^64; the counter part counts
 *  blocks over the whole message and is never reset between sections.
 *  Every @c section_blocks blocks the section key is transformed with
 *  K^(i+1) = E_K(D1) | E_K(D2), the ACPKM transformation, so no single
 *  section key encrypts more than @c section_blocks * 16 bytes.
 *
 *  Limits to document per protocol: with c = 64 the maximum message is
 *  2^64 blocks; pick the section size from the key lifetime analysis of
 *  RFC 8645 (the default of 256 blocks = 4 KiB matches gost-engine).
 *  The ICN MUST be unique per (key, message); a repeated ICN reuses the
 *  whole keystream.
 */
#ifndef GOST_CTR_H
#define GOST_CTR_H

#include <stddef.h>
#include <stdint.h>

#include "../common.h"
#include "../kuznyechik/kuznyechik.h"

#ifdef __cplusplus
extern "C" {
#endif

/** ICN length in bytes (c = 64 counter bits). */
#define GOST_CTR_ICN 8U

/** Default section size in blocks: 256 blocks = 4 KiB per section key. */
#define GOST_CTR_ACPKM_SECTION_DEFAULT 256U

/**
 *  @brief  Streaming CTR-ACPKM state.  Treat the contents as private.
 */
typedef struct gost_ctr_acpkm_ctx {
    gost_kuznyechik_t cipher;  /**< Cipher of the current section key. */
    uint8_t icn[GOST_CTR_ICN];  /**< Initial counter nonce. */
    size_t section_blocks;  /**< Blocks per section key. */
    uint64_t block_index;  /**< Global block counter. */
    uint8_t pending[GOST_KUZNYECHIK_BLOCK];  /**< Unused keystream bytes. */
    size_t pending_len;  /**< Keystream bytes left in @c pending. */
} gost_ctr_acpkm_ctx_t;

/**
 *  @brief  Initialize a streaming CTR-ACPKM state.
 *  @param  ctx             State to initialize.
 *  @param  key             256-bit initial key K^1.
 *  @param  icn             8-byte initial counter nonce.
 *  @param  section_blocks  Blocks per section key; 0 selects the
 *                          default of 256.
 *  @return GOST_OK, or GOST_ERR_PARAM for a NULL pointer.
 */
gost_status_t gost_ctr_acpkm_init(gost_ctr_acpkm_ctx_t *ctx, const uint8_t key[GOST_KUZNYECHIK_KEY],
                                  const uint8_t icn[GOST_CTR_ICN], size_t section_blocks);

/**
 *  @brief  Encrypt @p len bytes (streaming).
 *
 *  @p in and @p out may alias.  Every call continues the keystream of
 *  the state, so a message may be encrypted piecewise.
 *
 *  @return GOST_OK, or GOST_ERR_PARAM for invalid arguments.
 */
gost_status_t gost_ctr_acpkm_encrypt(gost_ctr_acpkm_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t len);

/**
 *  @brief  Decrypt @p len bytes (streaming).
 *
 *  CTR keystream is symmetric, so this is the same operation as
 *  encryption.
 *
 *  @return GOST_OK, or GOST_ERR_PARAM for invalid arguments.
 */
gost_status_t gost_ctr_acpkm_decrypt(gost_ctr_acpkm_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t len);

/**
 *  @brief  CTR-ACPKM of a complete message in one call.
 *  @param  key             256-bit initial key.
 *  @param  icn             8-byte initial counter nonce.
 *  @param  section_blocks  Blocks per section key; 0 selects the
 *                          default.
 *  @param  in              Input bytes, may be NULL when len is 0.
 *  @param  out             Output destination; may alias @p in.
 *  @param  len             Length in bytes.
 *  @return GOST_OK, or GOST_ERR_PARAM for invalid arguments.
 */
gost_status_t gost_ctr_acpkm(const uint8_t key[GOST_KUZNYECHIK_KEY], const uint8_t icn[GOST_CTR_ICN],
                             size_t section_blocks, const uint8_t *in, uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* GOST_CTR_H */
