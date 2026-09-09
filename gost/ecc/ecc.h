/**
 *  @file  ecc.h
 *  @brief Elliptic curve arithmetic and domain parameters per
 *         GOST R 34.10-2012.
 *
 *  Points live on short Weierstrass curves y^2 = x^3 + a*x + b over the
 *  prime field F_p.  The point at infinity is represented by (0, 0),
 *  matching the reference project.
 */
#ifndef GOST_ECC_H
#define GOST_ECC_H

#include <stdbool.h>

#include "../bigint/bigint.h"
#include "../hash/hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Affine curve point; (0, 0) is the point at infinity. */
typedef struct gost_ec_point {
    gost_u512_t x; /**< First affine coordinate. */
    gost_u512_t y; /**< Second affine coordinate. */
} gost_ec_point_t;

/**
 *  @brief Elliptic curve domain parameters.
 */
typedef struct gost_curve {
    gost_u512_t p;             /**< Field prime. */
    gost_u512_t a;             /**< Curve coefficient a. */
    gost_u512_t b;             /**< Curve coefficient b. */
    gost_u512_t q;             /**< Order of the base point. */
    gost_ec_point_t base;      /**< Base point P. */
    gost_hash_width_t hash_width;  /**< Digest width paired with the set. */
} gost_curve_t;

/** Curve parameter sets, ordered as in the reference project. */
typedef enum gost_curve_id {
    GOST_CURVE_2001_CC = 0,             /**< GostR3410-2001-ParamSet-CC. */
    GOST_CURVE_2001_TEST,               /**< GostR3410-2001-TestParamSet. */
    GOST_CURVE_2001_CRYPTOPRO_A,        /**< GostR3410-2001-CryptoPro-A. */
    GOST_CURVE_2001_CRYPTOPRO_B,        /**< GostR3410-2001-CryptoPro-B. */
    GOST_CURVE_2001_CRYPTOPRO_C,        /**< GostR3410-2001-CryptoPro-C. */
    GOST_CURVE_TC26_256_A,              /**< tc26-gost-3410-12-256-paramSetA. */
    GOST_CURVE_TC26_512_TEST,           /**< tc26-gost-3410-12-512-paramSetTest. */
    GOST_CURVE_TC26_512_A,              /**< tc26-gost-3410-12-512-paramSetA. */
    GOST_CURVE_TC26_512_B,              /**< tc26-gost-3410-12-512-paramSetB. */
    GOST_CURVE_TC26_512_C,              /**< tc26-gost-3410-12-512-paramSetC. */
    GOST_CURVE_COUNT                    /**< Number of built-in sets. */
} gost_curve_id_t;

/**
 *  @brief  Access a built-in curve parameter set.
 *  @param  id  Parameter set identifier.
 *  @return The static parameter set, or NULL for an unknown identifier.
 */
const gost_curve_t *gost_curve(gost_curve_id_t id);

/** @return True when @p point is the point at infinity. */
bool gost_ec_point_is_infinity(gost_ec_point_t point);

/**
 *  @brief  Add two points: out = a + b.
 *  @return GOST_OK, or GOST_ERR_PARAM when the inversion fails.
 */
gost_status_t gost_ec_point_add(gost_ec_point_t a, gost_ec_point_t b, const gost_curve_t *curve,
                                gost_ec_point_t *out);

/**
 *  @brief  Double a point: out = 2 * a.
 *  @return GOST_OK, or GOST_ERR_PARAM when the inversion fails.
 */
gost_status_t gost_ec_point_double(gost_ec_point_t a, const gost_curve_t *curve,
                                   gost_ec_point_t *out);

/**
 *  @brief  Scalar multiplication: out = k * point (double and add).
 *
 *  Multiplying by zero or by the group order yields the point at
 *  infinity.
 *
 *  @return GOST_OK, or GOST_ERR_PARAM when the inversion fails.
 */
gost_status_t gost_ec_point_mul(gost_u512_t k, gost_ec_point_t point, const gost_curve_t *curve,
                                gost_ec_point_t *out);

/**
 *  @brief  Number of bytes used to serialize one coordinate of @p curve.
 *  @return 64 for 512-bit sets, 32 otherwise.
 */
size_t gost_ec_coordinate_size(const gost_curve_t *curve);

#ifdef __cplusplus
}
#endif

#endif /* GOST_ECC_H */
