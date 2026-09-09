/**
 *  @file  bigint.c
 *  @brief Fixed-width unsigned integer arithmetic.
 */
#include "bigint.h"

/** Accumulate @p v plus @p carry into @p r, returning the carry out. */
static uint32_t limb_add_carry(uint32_t *r, uint32_t v, uint32_t carry)
{
    uint32_t sum = v + carry;
    uint32_t carry_out = sum < v;
    uint32_t before = *r;
    *r = before + sum;
    return carry_out | (*r < before);
}

/** Subtract @p v plus @p borrow from @p r, returning the borrow out. */
static uint32_t limb_sub_borrow(uint32_t *r, uint32_t v, uint32_t borrow)
{
    uint32_t before = *r;
    *r = before - v - borrow;
    return (uint32_t)(before < v) | ((uint32_t)(before == v) & borrow);
}

/** @return The bit length of a 1024-bit value (0 for zero). */
static unsigned u1024_bit_len(gost_u1024_t v)
{
    for (int i = GOST_U1024_LIMBS - 1; i >= 0; i--) {
        if (v.limb[i] != 0U) {
            uint32_t limb = v.limb[i];
            unsigned bits = 0;
            while (limb != 0U) {
                limb >>= 1U;
                bits++;
            }
            return (unsigned)i * 32U + bits;
        }
    }
    return 0;
}

/** @return -1, 0 or 1 comparing 1024-bit values. */
static int u1024_cmp(gost_u1024_t a, gost_u1024_t b)
{
    for (int i = GOST_U1024_LIMBS - 1; i >= 0; i--) {
        if (a.limb[i] != b.limb[i]) {
            return a.limb[i] > b.limb[i] ? 1 : -1;
        }
    }
    return 0;
}

gost_u512_t gost_u512_zero(void)
{
    gost_u512_t v = { .limb = { 0 } };
    return v;
}

gost_u512_t gost_u512_from_u64(uint64_t v)
{
    gost_u512_t r = gost_u512_zero();
    r.limb[0] = (uint32_t)v;
    r.limb[1] = (uint32_t)(v >> 32U);
    return r;
}

gost_status_t gost_u512_from_bytes_be(const uint8_t *in, size_t len, gost_u512_t *out)
{
    if (len > 64U) {
        return GOST_ERR_PARAM;
    }
    *out = gost_u512_zero();
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = in[len - 1U - i];
        out->limb[i / 4U] |= (uint32_t)byte << (8U * (i % 4U));
    }
    return GOST_OK;
}

gost_status_t gost_u512_from_bytes_le(const uint8_t *in, size_t len, gost_u512_t *out)
{
    if (len > 64U) {
        return GOST_ERR_PARAM;
    }
    *out = gost_u512_zero();
    for (size_t i = 0; i < len; i++) {
        out->limb[i / 4U] |= (uint32_t)in[i] << (8U * (i % 4U));
    }
    return GOST_OK;
}

gost_status_t gost_u512_to_bytes_be(gost_u512_t v, uint8_t *out, size_t out_len)
{
    if (out_len < 8U || gost_u512_bit_len(v) > 8U * out_len) {
        return GOST_ERR_PARAM;
    }
    for (size_t i = 0; i < out_len; i++) {
        uint32_t limb = v.limb[i / 4U];
        out[out_len - 1U - i] = (uint8_t)(limb >> (8U * (i % 4U)));
    }
    return GOST_OK;
}

bool gost_u512_is_zero(gost_u512_t v)
{
    for (unsigned i = 0; i < GOST_U512_LIMBS; i++) {
        if (v.limb[i] != 0U) {
            return false;
        }
    }
    return true;
}

int gost_u512_cmp(gost_u512_t a, gost_u512_t b)
{
    for (int i = GOST_U512_LIMBS - 1; i >= 0; i--) {
        if (a.limb[i] != b.limb[i]) {
            return a.limb[i] > b.limb[i] ? 1 : -1;
        }
    }
    return 0;
}

unsigned gost_u512_bit_len(gost_u512_t v)
{
    for (int i = GOST_U512_LIMBS - 1; i >= 0; i--) {
        if (v.limb[i] != 0U) {
            uint32_t limb = v.limb[i];
            unsigned bits = 0;
            while (limb != 0U) {
                limb >>= 1U;
                bits++;
            }
            return (unsigned)i * 32U + bits;
        }
    }
    return 0;
}

bool gost_u512_bit(gost_u512_t v, unsigned idx)
{
    if (idx >= 512U) {
        return false;
    }
    return ((v.limb[idx >> 5U] >> (idx & 31U)) & 1U) != 0U;
}

gost_u512_t gost_u512_add_mod(gost_u512_t a, gost_u512_t b, gost_u512_t m)
{
    gost_u512_t sum = gost_u512_zero();
    uint32_t carry = 0;
    for (unsigned i = 0; i < GOST_U512_LIMBS; i++) {
        carry = limb_add_carry(&sum.limb[i], a.limb[i], carry);
        carry = limb_add_carry(&sum.limb[i], b.limb[i], carry);
    }
    if (carry != 0U || gost_u512_cmp(sum, m) >= 0) {
        uint32_t borrow = 0;
        for (unsigned i = 0; i < GOST_U512_LIMBS; i++) {
            borrow = limb_sub_borrow(&sum.limb[i], m.limb[i], borrow);
        }
    }
    return sum;
}

gost_u512_t gost_u512_sub_mod(gost_u512_t a, gost_u512_t b, gost_u512_t m)
{
    gost_u512_t diff = a;
    uint32_t borrow = 0;
    for (unsigned i = 0; i < GOST_U512_LIMBS; i++) {
        borrow = limb_sub_borrow(&diff.limb[i], b.limb[i], borrow);
    }
    if (borrow != 0U) {
        uint32_t carry = 0;
        for (unsigned i = 0; i < GOST_U512_LIMBS; i++) {
            carry = limb_add_carry(&diff.limb[i], m.limb[i], carry);
        }
    }
    return diff;
}

/** @return The 1024-bit product a * b. */
static gost_u1024_t u512_mul_wide(gost_u512_t a, gost_u512_t b)
{
    gost_u1024_t r = { .limb = { 0 } };
    for (unsigned i = 0; i < GOST_U512_LIMBS; i++) {
        uint32_t carry = 0;
        for (unsigned j = 0; j < GOST_U512_LIMBS; j++) {
            uint64_t product = (uint64_t)a.limb[i] * b.limb[j];
            uint64_t acc = product + r.limb[i + j] + carry;
            r.limb[i + j] = (uint32_t)acc;
            carry = (uint32_t)(acc >> 32U);
        }
        r.limb[i + GOST_U512_LIMBS] = carry;
    }
    return r;
}

/** @return @p v zero extended to 1024 bits. */
static gost_u1024_t u512_to_wide(gost_u512_t v)
{
    gost_u1024_t r = { .limb = { 0 } };
    for (unsigned i = 0; i < GOST_U512_LIMBS; i++) {
        r.limb[i] = v.limb[i];
    }
    return r;
}

/** Reduce @p prod modulo the non zero @p m with binary long division. */
static gost_u512_t u1024_mod_u512(gost_u1024_t prod, gost_u512_t m)
{
    gost_u1024_t modulus = u512_to_wide(m);
    gost_u1024_t r = { .limb = { 0 } };
    unsigned bits = u1024_bit_len(prod);
    for (unsigned i = 0; i < bits; i++) {
        unsigned bit = bits - 1U - i;
        uint32_t carry = (prod.limb[bit / 32U] >> (bit % 32U)) & 1U;
        for (unsigned j = 0; j < GOST_U1024_LIMBS; j++) {
            uint32_t out = (r.limb[j] >> 31U) & 1U;
            r.limb[j] = (r.limb[j] << 1U) | carry;
            carry = out;
        }
        if (u1024_cmp(r, modulus) >= 0) {
            uint32_t borrow = 0;
            for (unsigned j = 0; j < GOST_U1024_LIMBS; j++) {
                borrow = limb_sub_borrow(&r.limb[j], modulus.limb[j], borrow);
            }
        }
    }
    gost_u512_t out;
    for (unsigned i = 0; i < GOST_U512_LIMBS; i++) {
        out.limb[i] = r.limb[i];
    }
    return out;
}

/** @return a mod m. */
static gost_u512_t u512_mod(gost_u512_t a, gost_u512_t m)
{
    if (gost_u512_cmp(a, m) < 0) {
        return a;
    }
    return u1024_mod_u512(u512_to_wide(a), m);
}

gost_status_t gost_u512_mul_mod(gost_u512_t a, gost_u512_t b, gost_u512_t m, gost_u512_t *out)
{
    if (gost_u512_is_zero(m)) {
        return GOST_ERR_PARAM;
    }
    *out = u1024_mod_u512(u512_mul_wide(a, b), m);
    return GOST_OK;
}

/** Halve @p v modulo the odd @p m: odd values absorb m before shifting. */
static gost_u512_t u512_half_mod(gost_u512_t v, gost_u512_t m)
{
    if ((v.limb[0] & 1U) == 0U) {
        for (unsigned i = 0; i < GOST_U512_LIMBS; i++) {
            uint32_t next = (i + 1U < GOST_U512_LIMBS) ? v.limb[i + 1U] : 0U;
            v.limb[i] = (v.limb[i] >> 1U) | (next << 31U);
        }
        return v;
    }
    /* v + m is even and fits in 513 bits; the carry becomes the top bit. */
    uint32_t carry = 0;
    for (unsigned i = 0; i < GOST_U512_LIMBS; i++) {
        carry = limb_add_carry(&v.limb[i], m.limb[i], carry);
    }
    for (unsigned i = 0; i < GOST_U512_LIMBS; i++) {
        uint32_t next = (i + 1U < GOST_U512_LIMBS) ? v.limb[i + 1U] : carry;
        v.limb[i] = (v.limb[i] >> 1U) | (next << 31U);
    }
    return v;
}

gost_status_t gost_u512_inv_mod(gost_u512_t a, gost_u512_t m, gost_u512_t *out)
{
    if (gost_u512_is_zero(m) || (m.limb[0] & 1U) == 0U) {
        return GOST_ERR_PARAM;
    }
    gost_u512_t u = u512_mod(a, m);
    if (gost_u512_is_zero(u)) {
        return GOST_ERR_PARAM;
    }
    gost_u512_t v = m;
    gost_u512_t x1 = gost_u512_from_u64(1U);
    gost_u512_t x2 = gost_u512_zero();
    /* The loop halves at least one operand per iteration, so it cannot
       exceed twice the bit length of the modulus. */
    for (unsigned guard = 0; guard < 2U * 512U + 8U; guard++) {
        if (gost_u512_cmp(u, v) == 0) {
            break;
        }
        if ((u.limb[0] & 1U) == 0U) {
            u = u512_half_mod(u, m);
            x1 = u512_half_mod(x1, m);
        } else if ((v.limb[0] & 1U) == 0U) {
            v = u512_half_mod(v, m);
            x2 = u512_half_mod(x2, m);
        } else if (gost_u512_cmp(u, v) > 0) {
            u = u512_half_mod(gost_u512_sub_mod(u, v, m), m);
            x1 = u512_half_mod(gost_u512_sub_mod(x1, x2, m), m);
        } else {
            v = u512_half_mod(gost_u512_sub_mod(v, u, m), m);
            x2 = u512_half_mod(gost_u512_sub_mod(x2, x1, m), m);
        }
    }
    if (gost_u512_cmp(u, gost_u512_from_u64(1U)) != 0) {
        return GOST_ERR_PARAM;
    }
    *out = x1;
    return GOST_OK;
}

gost_status_t gost_u512_exp_mod(gost_u512_t b, gost_u512_t e, gost_u512_t m, gost_u512_t *out)
{
    if (gost_u512_is_zero(m)) {
        return GOST_ERR_PARAM;
    }
    gost_u512_t base = u512_mod(b, m);
    gost_u512_t r = gost_u512_from_u64(1U);
    gost_status_t status = GOST_OK;
    unsigned bits = gost_u512_bit_len(e);
    for (unsigned i = 0; i < bits; i++) {
        status = gost_u512_mul_mod(r, r, m, &r);
        if (status != GOST_OK) {
            return status;
        }
        if (gost_u512_bit(e, bits - 1U - i)) {
            status = gost_u512_mul_mod(r, base, m, &r);
            if (status != GOST_OK) {
                return status;
            }
        }
    }
    *out = r;
    return GOST_OK;
}

/** @return A random value of exactly @p bits significant bits at most. */
static gost_status_t random_with_bits(unsigned bits, gost_rng_fn rng, void *rng_ctx, gost_u512_t *out)
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

gost_status_t gost_u512_is_probable_prime(gost_u512_t n, unsigned rounds, gost_rng_fn rng,
                                          void *rng_ctx, bool *prime)
{
    *prime = false;
    gost_u512_t two = gost_u512_from_u64(2U);
    gost_u512_t one = gost_u512_from_u64(1U);
    if ((n.limb[0] & 1U) == 0U || gost_u512_cmp(n, two) < 0) {
        return GOST_ERR_PARAM;
    }
    if (gost_u512_cmp(n, two) == 0 || gost_u512_cmp(n, gost_u512_from_u64(3U)) == 0) {
        *prime = true;
        return GOST_OK;
    }
    unsigned shift = 0;
    gost_u512_t odd = gost_u512_sub_mod(n, one, n);
    while ((odd.limb[0] & 1U) == 0U) {
        odd = u512_half_mod(odd, n);
        shift++;
    }
    for (unsigned round = 0; round < rounds; round++) {
        gost_u512_t a;
        gost_status_t status;
        do {
            status = random_with_bits(gost_u512_bit_len(n), rng, rng_ctx, &a);
            if (status != GOST_OK) {
                return status;
            }
        } while (gost_u512_cmp(a, two) < 0 || gost_u512_cmp(a, gost_u512_sub_mod(n, two, n)) > 0);
        gost_u512_t x;
        status = gost_u512_exp_mod(a, odd, n, &x);
        if (status != GOST_OK) {
            return status;
        }
        if (gost_u512_cmp(x, one) == 0 || gost_u512_cmp(x, gost_u512_sub_mod(n, one, n)) == 0) {
            continue;
        }
        bool witness = false;
        for (unsigned i = 1; i < shift; i++) {
            status = gost_u512_exp_mod(x, two, n, &x);
            if (status != GOST_OK) {
                return status;
            }
            if (gost_u512_cmp(x, gost_u512_sub_mod(n, one, n)) == 0) {
                witness = true;
                break;
            }
            if (gost_u512_cmp(x, one) == 0) {
                return GOST_OK;
            }
        }
        if (!witness) {
            return GOST_OK;
        }
    }
    *prime = true;
    return GOST_OK;
}
