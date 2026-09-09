/**
 *  @file  bigint.h
 *  @brief Fixed-width unsigned integer arithmetic used by the elliptic
 *         curve features.
 *
 *  Values are little-endian arrays of 32-bit limbs.  @c gost_u512_t holds
 *  up to 512 bits (scalars, field elements) and @c gost_u1024_t holds the
 *  intermediate 1024-bit products.  All modular operations expect an odd
 *  modulus (the GOST curves use odd primes).
 */
#ifndef GOST_BIGINT_H
#define GOST_BIGINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Limbs in a 512-bit value. */
#define GOST_U512_LIMBS 16
/** Limbs in a 1024-bit value. */
#define GOST_U1024_LIMBS 32

/** Unsigned 512-bit integer, little-endian limbs. */
typedef struct gost_u512 {
    uint32_t limb[GOST_U512_LIMBS]; /**< Base 2^32 digits, least significant first. */
} gost_u512_t;

/** Unsigned 1024-bit integer, little-endian limbs. */
typedef struct gost_u1024 {
    uint32_t limb[GOST_U1024_LIMBS]; /**< Base 2^32 digits, least significant first. */
} gost_u1024_t;

/** @return The value 0. */
gost_u512_t gost_u512_zero(void);

/** @return The value @p v. */
gost_u512_t gost_u512_from_u64(uint64_t v);

/**
 *  @brief  Decode a big-endian byte string as an unsigned integer.
 *  @param  in   Input bytes, most significant first.
 *  @param  len  Input length, at most 64.
 *  @param  out  Decoded value.
 *  @return GOST_OK, or GOST_ERR_PARAM if len exceeds 64.
 */
gost_status_t gost_u512_from_bytes_be(const uint8_t *in, size_t len, gost_u512_t *out);

/**
 *  @brief  Decode a little-endian byte string as an unsigned integer.
 *  @param  in   Input bytes, least significant first.
 *  @param  len  Input length, at most 64.
 *  @param  out  Decoded value.
 *  @return GOST_OK, or GOST_ERR_PARAM if len exceeds 64.
 */
gost_status_t gost_u512_from_bytes_le(const uint8_t *in, size_t len, gost_u512_t *out);

/**
 *  @brief  Encode a value as a big-endian byte string, left aligned.
 *
 *  The output is zero padded on the left when the value is shorter than
 *  @p out_len bytes.
 *
 *  @param  v        Value to encode.
 *  @param  out      Destination buffer.
 *  @param  out_len  Destination length, at least the encoded size.
 *  @return GOST_OK, or GOST_ERR_PARAM if the value does not fit.
 */
gost_status_t gost_u512_to_bytes_be(gost_u512_t v, uint8_t *out, size_t out_len);

/** @return True when @p v equals zero. */
bool gost_u512_is_zero(gost_u512_t v);

/** @return -1, 0 or 1 comparing @p a against @p b. */
int gost_u512_cmp(gost_u512_t a, gost_u512_t b);

/** @return Number of significant bits of @p v (0 for zero). */
unsigned gost_u512_bit_len(gost_u512_t v);

/** @return The bit of @p v at index @p idx (0 when out of range). */
bool gost_u512_bit(gost_u512_t v, unsigned idx);

/**
 *  @brief  (a + b) mod m.  The modulus must be non zero; operands are
 *          expected to be reduced.
 */
gost_u512_t gost_u512_add_mod(gost_u512_t a, gost_u512_t b, gost_u512_t m);

/**
 *  @brief  (a - b) mod m.  Operands are expected to be reduced.
 */
gost_u512_t gost_u512_sub_mod(gost_u512_t a, gost_u512_t b, gost_u512_t m);

/**
 *  @brief  (a * b) mod m.  The modulus must be non zero.
 *  @return GOST_OK, or GOST_ERR_PARAM for a zero modulus.
 */
gost_status_t gost_u512_mul_mod(gost_u512_t a, gost_u512_t b, gost_u512_t m, gost_u512_t *out);

/**
 *  @brief  a^-1 mod m computed with the binary extended Euclidean
 *          algorithm.  The modulus must be odd.
 *  @return GOST_OK, or GOST_ERR_PARAM when the inverse does not exist.
 */
gost_status_t gost_u512_inv_mod(gost_u512_t a, gost_u512_t m, gost_u512_t *out);

/**
 *  @brief  b^e mod m.  The modulus must be non zero.
 *  @return GOST_OK, or GOST_ERR_PARAM for a zero modulus.
 */
gost_status_t gost_u512_exp_mod(gost_u512_t b, gost_u512_t e, gost_u512_t m, gost_u512_t *out);

/**
 *  @brief  Miller-Rabin probabilistic primality test.
 *
 *  Draws random witnesses through @p rng; each witness is retried until
 *  it falls in [2, n - 2].
 *
 *  @param  n        Candidate to test (odd, greater than 2).
 *  @param  rounds   Number of random witnesses.
 *  @param  rng      Random source.
 *  @param  rng_ctx  Context forwarded to @p rng.
 *  @param  prime    Set to true when @p n survives every round.
 *  @return GOST_OK, or the error of the random source.
 */
gost_status_t gost_u512_is_probable_prime(gost_u512_t n, unsigned rounds, gost_rng_fn rng,
                                          void *rng_ctx, bool *prime);

#ifdef __cplusplus
}
#endif

#endif /* GOST_BIGINT_H */
