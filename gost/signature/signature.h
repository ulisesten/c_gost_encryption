/**
 *  @file  signature.h
 *  @brief Digital signature per GOST R 34.10-2012.
 *
 *  Signing and verification accept either a ready hash value or a raw
 *  message that is hashed internally with the digest width paired to the
 *  curve, mirroring the reference gost-cryptography project:
 *  `Подписать` maps to @c gost_signature_sign and `Проверить` to
 *  @c gost_signature_verify.
 *
 *  Key agreement follows R 50.1.113-2016: the shared value is the hash
 *  of the big-endian coordinates of the product of the peer public key,
 *  the private key and the UKM.
 */
#ifndef GOST_SIGNATURE_H
#define GOST_SIGNATURE_H

#include <stddef.h>
#include <stdint.h>

#include "../common.h"
#include "../ecc/ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Signature (r, s) pair over the field of the curve. */
typedef struct gost_signature {
    gost_u512_t r; /**< First signature component. */
    gost_u512_t s; /**< Second signature component. */
} gost_signature_t;

/** Key pair of the signature scheme. */
typedef struct gost_key_pair {
    gost_u512_t private_key;    /**< Secret scalar d. */
    gost_ec_point_t public_key; /**< Public point Q = d * P. */
} gost_key_pair_t;

/**
 *  @brief  Generate a key pair on a curve.
 *
 *  The private scalar is drawn in [1, q - 1] through @p rng; when the
 *  draw falls outside the range it is retried.
 *
 *  @param  curve    Curve parameters.
 *  @param  rng      Random source.
 *  @param  rng_ctx  Context forwarded to @p rng.
 *  @param  keys     Generated pair.
 *  @return GOST_OK, or the error of the random source or the curve math.
 */
gost_status_t gost_signature_generate_keys(const gost_curve_t *curve, gost_rng_fn rng,
                                           void *rng_ctx, gost_key_pair_t *keys);

/**
 *  @brief  Sign a hash value: sig = (r, s) over the curve.
 *
 *  @p hash holds the big-endian digest bytes (32 or 64 bytes); it is
 *  interpreted as an integer and reduced modulo q.
 *
 *  @param  curve    Curve parameters.
 *  @param  priv     Private scalar d.
 *  @param  hash     Digest value bytes.
 *  @param  hash_len Digest length, at most 64.
 *  @param  rng      Random source for the per signature nonce.
 *  @param  rng_ctx  Context forwarded to @p rng.
 *  @param  sig      Generated signature.
 *  @return GOST_OK, or the error of the random source or the curve math.
 */
gost_status_t gost_signature_sign(const gost_curve_t *curve, const gost_u512_t *priv,
                                  const uint8_t *hash, size_t hash_len, gost_rng_fn rng,
                                  void *rng_ctx, gost_signature_t *sig);

/**
 *  @brief  Sign a raw message, hashing it with the curve digest width.
 *  @return GOST_OK, or the error of the random source or the curve math.
 */
gost_status_t gost_signature_sign_message(const gost_curve_t *curve, const gost_u512_t *priv,
                                          const uint8_t *message, size_t message_len,
                                          gost_rng_fn rng, void *rng_ctx, gost_signature_t *sig);

/**
 *  @brief  Verify a signature against a hash value.
 *  @param  curve    Curve parameters.
 *  @param  pub      Public point of the signer.
 *  @param  hash     Digest value bytes, at most 64.
 *  @param  hash_len Digest length in bytes.
 *  @param  sig      Signature to verify.
 *  @param  valid    Set to true when the signature matches.
 *  @return GOST_OK, or GOST_ERR_PARAM for a malformed signature.
 */
gost_status_t gost_signature_verify(const gost_curve_t *curve, const gost_ec_point_t *pub,
                                    const uint8_t *hash, size_t hash_len,
                                    const gost_signature_t *sig, bool *valid);

/**
 *  @brief  Verify a signature against a raw message.
 *  @param  curve       Curve parameters.
 *  @param  pub         Public point of the signer.
 *  @param  message     Raw message bytes.
 *  @param  message_len Message length in bytes.
 *  @param  sig         Signature to verify.
 *  @param  valid       Set to true when the signature matches.
 *  @return GOST_OK, or GOST_ERR_PARAM for a malformed signature.
 */
gost_status_t gost_signature_verify_message(const gost_curve_t *curve, const gost_ec_point_t *pub,
                                            const uint8_t *message, size_t message_len,
                                            const gost_signature_t *sig, bool *valid);

/**
 *  @brief  Key agreement (VKO) per R 50.1.113-2016.
 *
 *  Computes K = ukm * (priv * pub_peer) and returns the hash of the
 *  big-endian coordinates of K.  @p width selects the digest width of the
 *  result (32 or 64 bytes); it may differ from the curve default.
 *
 *  @param  curve    Curve parameters.
 *  @param  priv     Own private scalar.
 *  @param  peer     Peer public point.
 *  @param  ukm      User keying material multiplier.
 *  @param  width    Digest width of the shared value.
 *  @param  out      Shared key destination, at least 64 bytes.
 *  @return GOST_OK, or the error of the curve math.
 */
gost_status_t gost_signature_key_agreement(const gost_curve_t *curve, const gost_u512_t *priv,
                                           const gost_ec_point_t *peer, const gost_u512_t *ukm,
                                           gost_hash_width_t width, uint8_t *out);

/**
 *  @brief  Validate a curve and a key pair per GOST R 34.10-2012.
 *
 *  Checks the curve invariants, that q * P is the point at infinity,
 *  that Q = d * P, the bounds of d, that p^t mod q differs from one and
 *  the primality of p and q with Miller-Rabin.
 *
 *  @param  curve    Curve parameters.
 *  @param  keys     Key pair to validate.
 *  @param  rng      Random source for the primality witnesses.
 *  @param  rng_ctx  Context forwarded to @p rng.
 *  @param  valid    Set to true when every check passes.
 *  @return GOST_OK, or the error of the random source.
 */
gost_status_t gost_signature_validate(const gost_curve_t *curve, const gost_key_pair_t *keys,
                                      gost_rng_fn rng, void *rng_ctx, bool *valid);

#ifdef __cplusplus
}
#endif

#endif /* GOST_SIGNATURE_H */
