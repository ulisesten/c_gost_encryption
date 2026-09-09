/**
 *  @file  rng.c
 *  @brief System random source implementing the gost_rng_fn contract.
 */
/** @def _DEFAULT_SOURCE
 *  @brief Libc feature macro exposing getentropy in unistd.h.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "rng.h"

#if defined(_WIN32)
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <unistd.h>
#endif

/** Largest request accepted by getentropy per call. */
#define GOST_ENTROPY_CHUNK 256U

#if defined(_WIN32)

gost_status_t gost_rng_system(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    if (len > 0U && out == NULL) {
        return GOST_ERR_PARAM;
    }
    while (len > 0U) {
        unsigned long chunk = len > 0xFFFFFFFFUL ? 0xFFFFFFFFUL : (unsigned long)len;
        NTSTATUS status = BCryptGenRandom(NULL, out, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status)) {
            return GOST_ERR_RNG;
        }
        out += chunk;
        len -= chunk;
    }
    return GOST_OK;
}

#elif defined(__unix__) || defined(__APPLE__)

gost_status_t gost_rng_system(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    if (len > 0U && out == NULL) {
        return GOST_ERR_PARAM;
    }
    while (len > 0U) {
        size_t chunk = len < GOST_ENTROPY_CHUNK ? len : GOST_ENTROPY_CHUNK;
        if (getentropy(out, chunk) != 0) {
            return GOST_ERR_RNG;
        }
        out += chunk;
        len -= chunk;
    }
    return GOST_OK;
}

#else

gost_status_t gost_rng_system(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    (void)out;
    (void)len;
    return GOST_ERR_RNG;
}

#endif
