/**
 *  @file  hash.h
 *  @brief Hashing per GOST R 34.11-2012 (Streebog), 256 and 512 bits.
 *
 *  Two presentations of the same digest are available:
 *
 *  - The streaming API (@c gost_hash_init, @c gost_hash_update,
 *    @c gost_hash_final) follows RFC 6986 and processes the message in
 *    natural order, returning the digest bytes least significant first.
 *  - The one shot @c gost_hash follows the presentation used by the
 *    reference gost-cryptography JavaScript project and by the printed
 *    test vectors of the standard: message blocks are taken from the end
 *    and the digest is returned most significant first.
 *
 *  For every message both presentations produce the same digest value,
 *  mirrored byte by byte:
 *  @code
 *      gost_hash(m, len, w, out) == reverse(stream_digest(reverse(m)))
 *  @endcode
 */
#ifndef GOST_HASH_H
#define GOST_HASH_H

#include <stddef.h>
#include <stdint.h>

#include "../common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Digest width of the hash function. */
typedef enum gost_hash_width {
    GOST_HASH_256 = 256, /**< 256-bit digest (32 bytes). */
    GOST_HASH_512 = 512  /**< 512-bit digest (64 bytes). */
} gost_hash_width_t;

/** Number of bytes in a full digest. */
#define GOST_HASH_MAX_DIGEST 64

/**
 *  @brief  Streaming hash state.  Treat the contents as private.
 */
typedef struct gost_hash_ctx {
    uint64_t h[8];          /**< Chaining value, little-endian words. */
    uint64_t n[8];          /**< Processed message length mod 2^512. */
    uint64_t sigma[8];      /**< Sum of processed blocks mod 2^512. */
    uint8_t buffer[64];     /**< Pending bytes not yet compressed. */
    size_t buffer_len;      /**< Bytes currently in @c buffer. */
    unsigned digest_size;   /**< Digest size in bytes (32 or 64). */
} gost_hash_ctx_t;

/**
 *  @brief  Initialize a streaming hash state.
 *  @param  ctx    State to initialize.
 *  @param  width  Digest width.
 */
void gost_hash_init(gost_hash_ctx_t *ctx, gost_hash_width_t width);

/**
 *  @brief  Absorb message bytes into a streaming hash state.
 *  @param  ctx   Initialized state.
 *  @param  data  Message bytes.
 *  @param  len   Number of bytes.
 */
void gost_hash_update(gost_hash_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 *  @brief  Finish a streaming hash and write the digest.
 *
 *  The digest is written least significant byte first (RFC 6986
 *  presentation).  @p out receives 32 or 64 bytes depending on the
 *  configured width.
 *
 *  @param  ctx  Initialized state.
 *  @param  out  Digest destination, at least 64 bytes.
 */
void gost_hash_final(gost_hash_ctx_t *ctx, uint8_t *out);

/**
 *  @brief  Hash a complete message in one call.
 *
 *  The output follows the presentation of the reference gost-cryptography
 *  JavaScript project and of the printed vectors of GOST R 34.11-2012:
 *  the digest bytes are most significant first.
 *
 *  @param  data   Message bytes.
 *  @param  len    Message length in bytes.
 *  @param  width  Digest width.
 *  @param  out    Digest destination, at least 64 bytes.
 *  @return GOST_OK, or GOST_ERR_PARAM for an invalid width.
 */
gost_status_t gost_hash(const uint8_t *data, size_t len, gost_hash_width_t width, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* GOST_HASH_H */
