/**
 *  @file  common.h
 *  @brief Shared types for every GOST feature: result codes and the
 *         random source contract.
 */
#ifndef GOST_COMMON_H
#define GOST_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @brief  Result code returned by fallible library functions.
 */
typedef enum gost_status {
    GOST_OK = 0,             /**< Operation completed. */
    GOST_ERR_PARAM = -1,     /**< Invalid argument or value out of range. */
    GOST_ERR_STATE = -2,     /**< Object used in an invalid state. */
    GOST_ERR_RNG = -3        /**< Random source failed. */
} gost_status_t;

/**
 *  @brief  Random source used by key generation and signing.
 *
 *  The implementation must fill @p out with @p len uniformly random bytes
 *  and return GOST_OK, or return an error code on failure.  A
 *  deterministic source may be injected for tests.
 *
 *  @param ctx    Opaque context owned by the caller (may be NULL).
 *  @param out    Destination buffer.
 *  @param len    Number of bytes to produce.
 *
 *  @return GOST_OK on success, negative gost_status_t on failure.
 */
typedef gost_status_t (*gost_rng_fn)(void *ctx, uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* GOST_COMMON_H */
