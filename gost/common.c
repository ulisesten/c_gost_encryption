/**
 *  @file  common.c
 *  @brief  Shared helpers: secure erasure and constant-time comparison.
 */
#include "common.h"

#include <string.h>

/**
 *  @brief  Plain memset kept behind a volatile function pointer.
 */
static void *memset_impl(void *dst, int value, size_t len)
{
    unsigned char *cursor = dst;
    for (size_t i = 0; i < len; i++) {
        cursor[i] = (unsigned char)value;
    }
    return dst;
}

/** Function pointer so the erasure cannot be optimized away. */
static void *(*const volatile secure_zero_memset)(void *, int, size_t) = memset_impl;

void gost_secure_zero(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0U) {
        return;
    }
    secure_zero_memset(ptr, 0, len);
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

int gost_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    /* diff == 0 maps to 1, any other value maps to 0, branch free. */
    return (int)((((uint32_t)diff | (~(uint32_t)diff + 1U)) >> 8U) ^ 1U) & 1U;
}
