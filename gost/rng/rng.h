/**
 *  @file  rng.h
 *  @brief System random source implementing the gost_rng_fn contract.
 */
#ifndef GOST_RNG_H
#define GOST_RNG_H

#include "../common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @brief  Cryptographically secure random source of the host system.
 *
 *  Uses getentropy on POSIX systems and BCryptGenRandom on Windows.  The
 *  @p ctx argument is ignored and may be NULL.
 *
 *  @param ctx    Unused context, pass NULL.
 *  @param out    Destination buffer.
 *  @param len    Number of bytes to produce.
 *  @return GOST_OK, or GOST_ERR_RNG when the system source fails.
 */
gost_status_t gost_rng_system(void *ctx, uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* GOST_RNG_H */
