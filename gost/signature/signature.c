/**
 *  @file  signature.c
 *  @brief Digital signature per GOST R 34.10-2012.
 */
#include "signature.h"

#include <string.h>

/** Number of Miller-Rabin rounds used for parameter validation. */
#define GOST_PRIME_ROUNDS 50

/** @brief Draw a scalar of @p bits significant bits, masked to length. */
static gost_status_t random_bits(unsigned bits, gost_rng_fn rng, void *rng_ctx, gost_u512_t *out)
{
    uint8_t bytes[64] = { 0 };
    size_t len = (bits + 7U) / 8U;
    gost_status_t status = rng(rng_ctx, bytes, len);
    if (status != GOST_OK) {
        return status;
    }
    if ((bits % 8U) != 0U) {
        bytes[len - 1U] &= (uint8_t)((1U << (bits % 8U)) - 1U);
    }
    return gost_u512_from_bytes_le(bytes, len, out);
}

/**
 *  @brief Draw a random scalar in [1, modulus - 1] with the bit length
 *         of the modulus.
 */
static gost_status_t random_scalar(const gost_u512_t *modulus, gost_rng_fn rng, void *rng_ctx,
                                   gost_u512_t *out)
{
    do {
        gost_status_t status =
            random_bits(gost_u512_bit_len(*modulus), rng, rng_ctx, out);
        if (status != GOST_OK) {
            return status;
        }
    } while (gost_u512_is_zero(*out) || gost_u512_cmp(*out, *modulus) >= 0);
    return GOST_OK;
}

/** @brief Hash digest to integer, big-endian, reduced modulo q. */
static gost_status_t digest_mod_q(const gost_curve_t *curve, const uint8_t *hash, size_t hash_len,
                                  gost_u512_t *out)
{
    if (hash_len == 0U || hash_len > 64U) {
        return GOST_ERR_PARAM;
    }
    gost_u512_t value;
    gost_status_t status = gost_u512_from_bytes_be(hash, hash_len, &value);
    if (status != GOST_OK) {
        return status;
    }
    status = gost_u512_mul_mod(value, gost_u512_from_u64(1U), curve->q, &value);
    if (status != GOST_OK) {
        return status;
    }
    if (gost_u512_is_zero(value)) {
        value = gost_u512_from_u64(1U);
    }
    *out = value;
    return GOST_OK;
}

gost_status_t gost_signature_generate_keys(const gost_curve_t *curve, gost_rng_fn rng,
                                           void *rng_ctx, gost_key_pair_t *keys)
{
    gost_status_t status = random_scalar(&curve->q, rng, rng_ctx, &keys->private_key);
    if (status != GOST_OK) {
        return status;
    }
    return gost_ec_point_mul(keys->private_key, curve->base, curve, &keys->public_key);
}

gost_status_t gost_signature_sign(const gost_curve_t *curve, const gost_u512_t *priv,
                                  const uint8_t *hash, size_t hash_len, gost_rng_fn rng,
                                  void *rng_ctx, gost_signature_t *sig)
{
    gost_u512_t e;
    gost_status_t status = digest_mod_q(curve, hash, hash_len, &e);
    if (status != GOST_OK) {
        return status;
    }
    do {
        gost_u512_t k;
        status = random_scalar(&curve->q, rng, rng_ctx, &k);
        if (status != GOST_OK) {
            return status;
        }
        gost_ec_point_t c;
        status = gost_ec_point_mul(k, curve->base, curve, &c);
        if (status != GOST_OK) {
            return status;
        }
        status = gost_u512_mul_mod(c.x, gost_u512_from_u64(1U), curve->q, &sig->r);
        if (status != GOST_OK) {
            return status;
        }
        gost_u512_t r_d;
        status = gost_u512_mul_mod(sig->r, *priv, curve->q, &r_d);
        if (status != GOST_OK) {
            return status;
        }
        gost_u512_t k_e;
        status = gost_u512_mul_mod(k, e, curve->q, &k_e);
        if (status != GOST_OK) {
            return status;
        }
        sig->s = gost_u512_add_mod(r_d, k_e, curve->q);
    } while (gost_u512_is_zero(sig->s) || gost_u512_is_zero(sig->r));
    return GOST_OK;
}

gost_status_t gost_signature_sign_message(const gost_curve_t *curve, const gost_u512_t *priv,
                                          const uint8_t *message, size_t message_len,
                                          gost_rng_fn rng, void *rng_ctx, gost_signature_t *sig)
{
    uint8_t digest[GOST_HASH_MAX_DIGEST];
    gost_status_t status = gost_hash(message, message_len, curve->hash_width, digest);
    if (status != GOST_OK) {
        return status;
    }
    size_t digest_len = curve->hash_width == GOST_HASH_512 ? 64U : 32U;
    return gost_signature_sign(curve, priv, digest, digest_len, rng, rng_ctx, sig);
}

gost_status_t gost_signature_verify(const gost_curve_t *curve, const gost_ec_point_t *pub,
                                    const uint8_t *hash, size_t hash_len,
                                    const gost_signature_t *sig, bool *valid)
{
    *valid = false;
    if (gost_u512_is_zero(sig->r) || gost_u512_is_zero(sig->s) ||
        gost_u512_cmp(curve->q, sig->r) <= 0 || gost_u512_cmp(curve->q, sig->s) <= 0) {
        return GOST_ERR_PARAM;
    }
    gost_u512_t e;
    gost_status_t status = digest_mod_q(curve, hash, hash_len, &e);
    if (status != GOST_OK) {
        return status;
    }
    gost_u512_t v;
    status = gost_u512_inv_mod(e, curve->q, &v);
    if (status != GOST_OK) {
        return GOST_ERR_PARAM;
    }
    gost_u512_t s_v;
    status = gost_u512_mul_mod(sig->s, v, curve->q, &s_v);
    if (status != GOST_OK) {
        return status;
    }
    gost_ec_point_t left;
    status = gost_ec_point_mul(s_v, curve->base, curve, &left);
    if (status != GOST_OK) {
        return status;
    }
    gost_u512_t r_v;
    status = gost_u512_mul_mod(sig->r, v, curve->q, &r_v);
    if (status != GOST_OK) {
        return status;
    }
    gost_u512_t neg_r_v = gost_u512_sub_mod(curve->q, r_v, curve->q);
    gost_ec_point_t right;
    status = gost_ec_point_mul(neg_r_v, *pub, curve, &right);
    if (status != GOST_OK) {
        return status;
    }
    gost_ec_point_t c;
    status = gost_ec_point_add(left, right, curve, &c);
    if (status != GOST_OK) {
        return status;
    }
    gost_u512_t r_check;
    status = gost_u512_mul_mod(c.x, gost_u512_from_u64(1U), curve->q, &r_check);
    if (status != GOST_OK) {
        return status;
    }
    *valid = gost_u512_cmp(r_check, sig->r) == 0;
    return GOST_OK;
}

gost_status_t gost_signature_verify_message(const gost_curve_t *curve, const gost_ec_point_t *pub,
                                            const uint8_t *message, size_t message_len,
                                            const gost_signature_t *sig, bool *valid)
{
    uint8_t digest[GOST_HASH_MAX_DIGEST];
    gost_status_t status = gost_hash(message, message_len, curve->hash_width, digest);
    if (status != GOST_OK) {
        return status;
    }
    size_t digest_len = curve->hash_width == GOST_HASH_512 ? 64U : 32U;
    return gost_signature_verify(curve, pub, digest, digest_len, sig, valid);
}

gost_status_t gost_signature_key_agreement(const gost_curve_t *curve, const gost_u512_t *priv,
                                           const gost_ec_point_t *peer, const gost_u512_t *ukm,
                                           gost_hash_width_t width, uint8_t *out)
{
    gost_ec_point_t shared;
    gost_status_t status = gost_ec_point_mul(*priv, *peer, curve, &shared);
    if (status != GOST_OK) {
        return status;
    }
    status = gost_ec_point_mul(*ukm, shared, curve, &shared);
    if (status != GOST_OK) {
        return status;
    }
    size_t coord = gost_ec_coordinate_size(curve);
    uint8_t material[128];
    gost_status_t x_status = gost_u512_to_bytes_be(shared.x, material + coord, coord);
    gost_status_t y_status = gost_u512_to_bytes_be(shared.y, material, coord);
    if (x_status != GOST_OK || y_status != GOST_OK) {
        return GOST_ERR_PARAM;
    }
    return gost_hash(material, 2U * coord, width, out);
}

/**
 *  @brief Check that p^t mod q differs from one for small t.
 *  @return True when the check fails.
 */
static bool power_residue_fails(const gost_curve_t *curve)
{
    unsigned bound = curve->hash_width == GOST_HASH_512 ? 131U : 31U;
    for (unsigned t = 1; t <= bound; t++) {
        gost_u512_t residue;
        if (gost_u512_exp_mod(curve->p, gost_u512_from_u64(t), curve->q, &residue) != GOST_OK) {
            return true;
        }
        if (gost_u512_cmp(residue, gost_u512_from_u64(1U)) == 0) {
            return true;
        }
    }
    return false;
}

/** @brief Check y^2 = x^3 + a x + b (mod p) for a curve point. */
static bool point_on_curve(gost_u512_t x, gost_u512_t y, const gost_curve_t *curve)
{
    gost_u512_t square;
    if (gost_u512_mul_mod(y, y, curve->p, &square) != GOST_OK) {
        return false;
    }
    gost_u512_t cubic;
    if (gost_u512_mul_mod(x, x, curve->p, &cubic) != GOST_OK) {
        return false;
    }
    if (gost_u512_mul_mod(cubic, x, curve->p, &cubic) != GOST_OK) {
        return false;
    }
    gost_u512_t linear;
    if (gost_u512_mul_mod(curve->a, x, curve->p, &linear) != GOST_OK) {
        return false;
    }
    cubic = gost_u512_add_mod(cubic, linear, curve->p);
    cubic = gost_u512_add_mod(cubic, curve->b, curve->p);
    return gost_u512_cmp(square, cubic) == 0;
}

gost_status_t gost_signature_validate(const gost_curve_t *curve, const gost_key_pair_t *keys,
                                      gost_rng_fn rng, void *rng_ctx, bool *valid)
{
    *valid = false;
    const gost_u512_t four = gost_u512_from_u64(4U);
    const gost_u512_t zero = gost_u512_zero();
    gost_u512_t a3 = gost_u512_zero();
    gost_status_t status = gost_u512_mul_mod(curve->a, curve->a, curve->p, &a3);
    if (status != GOST_OK) {
        return status;
    }
    status = gost_u512_mul_mod(a3, curve->a, curve->p, &a3);
    if (status != GOST_OK) {
        return status;
    }
    status = gost_u512_mul_mod(a3, four, curve->p, &a3);
    if (status != GOST_OK) {
        return status;
    }
    gost_u512_t b2;
    status = gost_u512_mul_mod(curve->b, curve->b, curve->p, &b2);
    if (status != GOST_OK) {
        return status;
    }
    gost_u512_t b27;
    status = gost_u512_mul_mod(b2, gost_u512_from_u64(27U), curve->p, &b27);
    if (status != GOST_OK) {
        return status;
    }
    gost_u512_t discriminant = gost_u512_add_mod(a3, b27, curve->p);
    if (gost_u512_cmp(curve->p, four) < 0 || gost_u512_cmp(curve->p, curve->a) <= 0 ||
        gost_u512_cmp(curve->p, curve->b) <= 0 || gost_u512_is_zero(discriminant)) {
        return GOST_OK;
    }
    if (gost_u512_cmp(curve->q, curve->p) == 0 || !point_on_curve(curve->base.x, curve->base.y, curve) ||
        !point_on_curve(keys->public_key.x, keys->public_key.y, curve)) {
        return GOST_OK;
    }
    unsigned q_bits = gost_u512_bit_len(curve->q);
    unsigned digest_bits = curve->hash_width == GOST_HASH_512 ? 512U : 256U;
    unsigned low = digest_bits - (digest_bits >> 7U);
    if (q_bits < low || q_bits > digest_bits || gost_ec_point_is_infinity(curve->base)) {
        return GOST_OK;
    }
    gost_ec_point_t q_base;
    status = gost_ec_point_mul(curve->q, curve->base, curve, &q_base);
    if (status != GOST_OK) {
        return status;
    }
    if (!gost_ec_point_is_infinity(q_base)) {
        return GOST_OK;
    }
    gost_ec_point_t d_base;
    status = gost_ec_point_mul(keys->private_key, curve->base, curve, &d_base);
    if (status != GOST_OK) {
        return status;
    }
    if (gost_u512_cmp(d_base.x, keys->public_key.x) != 0 ||
        gost_u512_cmp(d_base.y, keys->public_key.y) != 0) {
        return GOST_OK;
    }
    if (gost_u512_cmp(curve->q, keys->private_key) <= 0 || gost_u512_is_zero(keys->private_key)) {
        return GOST_OK;
    }
    if (power_residue_fails(curve)) {
        return GOST_OK;
    }
    gost_u512_t j_inverse;
    if (gost_u512_inv_mod(discriminant, curve->p, &j_inverse) != GOST_OK) {
        return GOST_OK;
    }
    gost_u512_t j_invariant;
    status = gost_u512_mul_mod(gost_u512_from_u64(1728U), a3, curve->p, &j_invariant);
    if (status != GOST_OK) {
        return status;
    }
    status = gost_u512_mul_mod(j_invariant, j_inverse, curve->p, &j_invariant);
    if (status != GOST_OK) {
        return status;
    }
    if (gost_u512_is_zero(j_invariant) ||
        gost_u512_cmp(j_invariant, gost_u512_from_u64(1728U)) == 0) {
        return GOST_OK;
    }
    bool prime = false;
    status = gost_u512_is_probable_prime(curve->p, GOST_PRIME_ROUNDS, rng, rng_ctx, &prime);
    if (status != GOST_OK) {
        return status;
    }
    if (!prime) {
        return GOST_OK;
    }
    status = gost_u512_is_probable_prime(curve->q, GOST_PRIME_ROUNDS, rng, rng_ctx, &prime);
    if (status != GOST_OK) {
        return status;
    }
    if (!prime) {
        return GOST_OK;
    }
    *valid = true;
    return GOST_OK;
}
