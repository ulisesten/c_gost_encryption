/**
 *  @file  test_gost.c
 *  @brief Test suite: official vectors reproduced by the reference
 *         project plus internal consistency checks.
 */
#include <gost/gost.h>

#include <stdio.h>
#include <string.h>

static int checks;
static int failures;

#define CHECK(cond)                                                           \
    do {                                                                      \
        checks++;                                                             \
        if (!(cond)) {                                                        \
            failures++;                                                       \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
        }                                                                     \
    } while (0)

/** @brief Decode a hex string into a byte buffer. */
static size_t hex_to_bytes(const char *hex, uint8_t *out)
{
    size_t len = strlen(hex) / 2U;
    for (size_t i = 0; i < len; i++) {
        unsigned value = 0;
        sscanf(hex + 2U * i, "%2x", &value);
        out[i] = (uint8_t)value;
    }
    return len;
}

/** @brief Compare a buffer against a hex string. */
static bool bytes_equal_hex(const uint8_t *data, size_t len, const char *hex)
{
    uint8_t expected[128];
    size_t expected_len = hex_to_bytes(hex, expected);
    if (expected_len != len) {
        return false;
    }
    return memcmp(data, expected, len) == 0;
}

/** Test key from GOST R 34.11-94 ("This is a test key..." layout). */
static const uint32_t test_key[GOST_CIPHER_KEY_WORDS] = {
    0x33206D54, 0x326C6568, 0x20657369, 0x626E7373,
    0x79676120, 0x74746769, 0x65686573, 0x733D2C20
};

static void test_cipher_ecb(void)
{
    gost_cipher_t ctx;
    CHECK(gost_cipher_init(&ctx, test_key, GOST_SBOX_R3410_94_TEST) == GOST_OK);

    /* Official vector from GOST R 34.11-94: zero block. */
    uint8_t block[GOST_CIPHER_BLOCK] = { 0 };
    gost_cipher_block_encrypt(&ctx, block);
    CHECK(bytes_equal_hex(block, sizeof(block), "1b0bbc32cebcab42"));
    gost_cipher_block_decrypt(&ctx, block);
    CHECK(bytes_equal_hex(block, sizeof(block), "0000000000000000"));

    /* ECB roundtrip on a block multiple. */
    uint8_t data[16];
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)(0xA0 + i);
    }
    uint8_t backup[16];
    memcpy(backup, data, sizeof(data));
    CHECK(gost_cipher_ecb_encrypt(&ctx, data, sizeof(data)) == GOST_OK);
    CHECK(memcmp(data, backup, sizeof(data)) != 0);
    CHECK(gost_cipher_ecb_decrypt(&ctx, data, sizeof(data)) == GOST_OK);
    CHECK(memcmp(data, backup, sizeof(data)) == 0);

    /* Non multiple lengths are rejected. */
    uint8_t odd[7] = { 0 };
    CHECK(gost_cipher_ecb_encrypt(&ctx, odd, sizeof(odd)) == GOST_ERR_PARAM);
}

static void test_cipher_cfb(void)
{
    gost_cipher_t ctx;
    CHECK(gost_cipher_init(&ctx, test_key, GOST_SBOX_TC26_Z) == GOST_OK);
    const uint32_t iv[2] = { 0x11223344, 0x55667788 };

    /* Interop vector produced by the reference project. */
    uint8_t data[16];
    size_t len = hex_to_bytes("7061796c6f61642d746573742d313233", data);
    gost_cipher_cfb_encrypt(&ctx, iv, data, len);
    CHECK(bytes_equal_hex(data, len, "0e4db4719c067c29e2c10f04b5001654"));
    gost_cipher_cfb_decrypt(&ctx, iv, data, len);
    CHECK(bytes_equal_hex(data, len, "7061796c6f61642d746573742d313233"));

    /* Roundtrip on every length around the block boundary. */
    uint8_t buffer[33];
    for (size_t size = 1; size <= sizeof(buffer); size++) {
        for (size_t i = 0; i < size; i++) {
            buffer[i] = (uint8_t)(i * 7U + size);
        }
        uint8_t backup[33];
        memcpy(backup, buffer, size);
        CHECK(gost_cipher_cfb_encrypt(&ctx, iv, buffer, size) == GOST_OK);
        CHECK(gost_cipher_cfb_decrypt(&ctx, iv, buffer, size) == GOST_OK);
        CHECK(memcmp(buffer, backup, size) == 0);
    }
}

static void test_cipher_gamma(void)
{
    gost_cipher_t ctx;
    CHECK(gost_cipher_init(&ctx, test_key, GOST_SBOX_TC26_Z) == GOST_OK);
    const uint32_t iv[2] = { 0x11223344, 0x55667788 };

    /* Interop vector produced by the reference project. */
    uint8_t data[16];
    size_t len = hex_to_bytes("7061796c6f61642d746573742d313233", data);
    gost_cipher_gamma(&ctx, iv, data, len);
    CHECK(bytes_equal_hex(data, len, "f8049d13045b667934cd3655e0eee7cc"));
    gost_cipher_gamma(&ctx, iv, data, len);
    CHECK(bytes_equal_hex(data, len, "7061796c6f61642d746573742d313233"));

    /* Roundtrip on every length around the block boundary. */
    uint8_t buffer[33];
    for (size_t size = 1; size <= sizeof(buffer); size++) {
        for (size_t i = 0; i < size; i++) {
            buffer[i] = (uint8_t)(i * 11U + size);
        }
        uint8_t backup[33];
        memcpy(backup, buffer, size);
        CHECK(gost_cipher_gamma(&ctx, iv, buffer, size) == GOST_OK);
        CHECK(gost_cipher_gamma(&ctx, iv, buffer, size) == GOST_OK);
        CHECK(memcmp(buffer, backup, size) == 0);
    }
}

static void test_cipher_mac(void)
{
    gost_cipher_t ctx;
    CHECK(gost_cipher_init(&ctx, test_key, GOST_SBOX_TC26_Z) == GOST_OK);

    uint8_t data[16] = "payload-test-12";
    uint8_t tag1[GOST_CIPHER_BLOCK];
    uint8_t tag2[GOST_CIPHER_BLOCK];
    CHECK(gost_cipher_mac(&ctx, data, sizeof(data), tag1) == GOST_OK);
    CHECK(gost_cipher_mac(&ctx, data, sizeof(data), tag2) == GOST_OK);
    CHECK(memcmp(tag1, tag2, sizeof(tag1)) == 0);

    data[0] ^= 0x01;
    CHECK(gost_cipher_mac(&ctx, data, sizeof(data), tag2) == GOST_OK);
    CHECK(memcmp(tag1, tag2, sizeof(tag1)) != 0);

    uint8_t odd[7] = { 0 };
    CHECK(gost_cipher_mac(&ctx, odd, sizeof(odd), tag1) == GOST_ERR_PARAM);
}

/** The Igor's Tale message bytes of GOST R 34.11-2012, example 2. */
static const char *tale_hex =
    "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2"
    "f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202c"
    "e8f0f2e5e220e5d1";

/** RFC 6986 message M1: "0123456789012345678901234567890123456789..." (63 bytes). */
static const char *m1_hex =
    "3031323334353637383930313233343536373839303132333435363738393031"
    "32333435363738393031323334353637383930313233343536373839303132";

static void test_hash_one_shot(void)
{
    const struct {
        const char *input_hex;
        const char *digest256;
        const char *digest512;
    } vectors[] = {
        {
            "",
            "bbe19c8d2025d99f943a932a0b365a822aa36a4c479d22cc02c8973e219a533f",
            "8a1a1c4cbf909f8ecb81cd1b5c713abad26a4cac2a5fda3ce86e352855712f36"
            "a7f0be98eb6cf51553b507b73a87e97946aebc29859255049f86aa09a25d948e",
        },
        {
            "616263",
            "b2fd82456abac138932d3e9c70b8e0f6852c2148229a33c5a4180eb98e99cf10",
            "ccf58ecafefa63f9dcd5aea122c16d0fbcbd6c5701c62c01e6e3a3e58dd31eb1"
            "08643f2063428c7b914a0aaae9f1a9dd15aa8b9e507cbb84be8b16fa2da381fd",
        },
        {
            tale_hex,
            "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d",
            "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f03"
            "7613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e",
        },
    };
    uint8_t data[128];
    uint8_t digest[GOST_HASH_MAX_DIGEST];
    for (size_t v = 0; v < sizeof(vectors) / sizeof(vectors[0]); v++) {
        size_t len = hex_to_bytes(vectors[v].input_hex, data);
        CHECK(gost_hash(data, len, GOST_HASH_256, digest) == GOST_OK);
        CHECK(bytes_equal_hex(digest, 32U, vectors[v].digest256));
        CHECK(gost_hash(data, len, GOST_HASH_512, digest) == GOST_OK);
        CHECK(bytes_equal_hex(digest, 64U, vectors[v].digest512));
    }
}

static void test_hash_streaming(void)
{
    /* RFC 6986 vectors, digest bytes least significant first. */
    const struct {
        const char *input_hex;
        const char *digest256;
        const char *digest512;
    } vectors[] = {
        {
            m1_hex,
            "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500",
            "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa"
            "00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48",
        },
        {
            tale_hex,
            "0e7ab4efd0915eaac2dab58dae45d0f28d14f83c57794b3338f7872c10542c19",
            "9663a3abce48e5b8545169e9ede65e0c96b827afdad47ac56c8ba343b3628e64"
            "a25418a6ed0685e414a4420960c38e102180f7e1759f8f61262185115fea5703",
        },
    };
    uint8_t data[128];
    uint8_t digest[GOST_HASH_MAX_DIGEST];
    for (size_t v = 0; v < sizeof(vectors) / sizeof(vectors[0]); v++) {
        size_t len = hex_to_bytes(vectors[v].input_hex, data);
        gost_hash_ctx_t ctx;
        gost_hash_init(&ctx, GOST_HASH_256);
        gost_hash_update(&ctx, data, len);
        gost_hash_final(&ctx, digest);
        CHECK(bytes_equal_hex(digest, 32U, vectors[v].digest256));
        gost_hash_init(&ctx, GOST_HASH_512);
        gost_hash_update(&ctx, data, len);
        gost_hash_final(&ctx, digest);
        CHECK(bytes_equal_hex(digest, 64U, vectors[v].digest512));
    }
}

/** @brief Reverse @p len bytes in place. */
static void reverse_bytes(uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len / 2U; i++) {
        uint8_t tmp = data[i];
        data[i] = data[len - 1U - i];
        data[len - 1U - i] = tmp;
    }
}

static void test_hash_presentation_duality(void)
{
    /* gost_hash(m) == reverse(stream(reverse(m))) for assorted lengths. */
    uint8_t data[131];
    uint8_t mirrored[131];
    uint8_t one_shot[GOST_HASH_MAX_DIGEST];
    uint8_t streamed[GOST_HASH_MAX_DIGEST];
    for (size_t size = 0; size <= sizeof(data); size += 7U) {
        for (size_t i = 0; i < size; i++) {
            data[i] = (uint8_t)(i * 31U + size);
        }
        memcpy(mirrored, data, size);
        reverse_bytes(mirrored, size);
        for (unsigned w = 0; w < 2; w++) {
            gost_hash_width_t width = w == 0 ? GOST_HASH_256 : GOST_HASH_512;
            unsigned digest_size = w == 0 ? 32U : 64U;
            CHECK(gost_hash(data, size, width, one_shot) == GOST_OK);
            gost_hash_ctx_t ctx;
            gost_hash_init(&ctx, width);
            gost_hash_update(&ctx, mirrored, size);
            gost_hash_final(&ctx, streamed);
            for (unsigned i = 0; i < digest_size; i++) {
                CHECK(one_shot[i] == streamed[digest_size - 1U - i]);
            }
        }
    }
}

static void test_hash_incremental(void)
{
    /* Splitting the input across updates must not change the digest. */
    uint8_t data[300];
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)(i * 13U + 5U);
    }
    uint8_t whole[GOST_HASH_MAX_DIGEST];
    uint8_t parts[GOST_HASH_MAX_DIGEST];
    for (unsigned w = 0; w < 2; w++) {
        gost_hash_width_t width = w == 0 ? GOST_HASH_256 : GOST_HASH_512;
        unsigned digest_size = w == 0 ? 32U : 64U;
        gost_hash_ctx_t ctx;
        gost_hash_init(&ctx, width);
        gost_hash_update(&ctx, data, sizeof(data));
        gost_hash_final(&ctx, whole);
        gost_hash_init(&ctx, width);
        size_t offset = 0;
        const size_t steps[] = { 1U, 63U, 64U, 65U, 107U };
        for (size_t s = 0; s < sizeof(steps) / sizeof(steps[0]); s++) {
            gost_hash_update(&ctx, data + offset, steps[s]);
            offset += steps[s];
        }
        gost_hash_update(&ctx, data + offset, sizeof(data) - offset);
        gost_hash_final(&ctx, parts);
        CHECK(memcmp(whole, parts, digest_size) == 0);
    }
}

/** Deterministic source: serves a fixed little-endian value once, then fails. */
static gost_status_t fixed_rng(void *ctx, uint8_t *out, size_t len)
{
    static bool spent = false;
    const gost_u512_t *value = ctx;
    if (spent) {
        return GOST_ERR_RNG;
    }
    spent = true;
    memset(out, 0, len);
    for (size_t i = 0; i < len && i < 64U; i++) {
        out[i] = (uint8_t)(value->limb[i / 4U] >> (8U * (i % 4U)));
    }
    return GOST_OK;
}

/** Monotonic counter source for primality witnesses. */
static gost_status_t counter_rng(void *ctx, uint8_t *out, size_t len)
{
    uint64_t *counter = ctx;
    memset(out, 0, len);
    for (size_t i = 0; i < len && i < 8U; i++) {
        out[i] = (uint8_t)(*counter >> (8U * i));
    }
    (*counter)++;
    return GOST_OK;
}

static void test_bigint(void)
{
    gost_u512_t a = gost_u512_from_u64(0xDEADBEEFCAFEBABEULL);
    gost_u512_t b = gost_u512_from_u64(0x1234567890ABCDEFULL);
    gost_u512_t m = gost_u512_from_u64(1000000007ULL);

    /* (a * b) mod m == (b * a) mod m */
    gost_u512_t ab;
    gost_u512_t ba;
    CHECK(gost_u512_mul_mod(a, b, m, &ab) == GOST_OK);
    CHECK(gost_u512_mul_mod(b, a, m, &ba) == GOST_OK);
    CHECK(gost_u512_cmp(ab, ba) == 0);

    /* a * a^-1 == 1 */
    gost_u512_t inverse;
    CHECK(gost_u512_inv_mod(a, m, &inverse) == GOST_OK);
    gost_u512_t product;
    CHECK(gost_u512_mul_mod(a, inverse, m, &product) == GOST_OK);
    CHECK(gost_u512_cmp(product, gost_u512_from_u64(1U)) == 0);

    /* a^5 mod m == ((a^2)^2 * a) mod m */
    gost_u512_t power;
    gost_u512_t exponent = gost_u512_from_u64(5U);
    CHECK(gost_u512_exp_mod(a, exponent, m, &power) == GOST_OK);
    gost_u512_t manual;
    CHECK(gost_u512_mul_mod(a, a, m, &manual) == GOST_OK);
    CHECK(gost_u512_mul_mod(manual, manual, m, &manual) == GOST_OK);
    CHECK(gost_u512_mul_mod(manual, a, m, &manual) == GOST_OK);
    CHECK(gost_u512_cmp(power, manual) == 0);

    /* Byte roundtrip, big-endian. */
    uint8_t bytes[64];
    CHECK(gost_u512_to_bytes_be(a, bytes, sizeof(bytes)) == GOST_OK);
    gost_u512_t decoded;
    CHECK(gost_u512_from_bytes_be(bytes, sizeof(bytes), &decoded) == GOST_OK);
    CHECK(gost_u512_cmp(a, decoded) == 0);

    /* Mersenne prime 2^61 - 1 passes Miller-Rabin; the Carmichael number
       561 does not. */
    bool prime = false;
    uint64_t counter = 3U;
    CHECK(gost_u512_is_probable_prime(gost_u512_from_u64(2305843009213693951ULL), 20U,
                                      counter_rng, &counter, &prime) == GOST_OK);
    CHECK(prime);
    counter = 3U;
    CHECK(gost_u512_is_probable_prime(gost_u512_from_u64(561ULL), 20U, counter_rng, &counter,
                                      &prime) == GOST_OK);
    CHECK(!prime);
}

static void test_signature_official(void)
{
    /* GOST R 34.10-2012 appendix vector over GostR3410-2001-TestParamSet. */
    const gost_curve_t *curve = gost_curve(GOST_CURVE_2001_TEST);
    CHECK(curve != NULL);

    uint8_t hash[32];
    hex_to_bytes("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5", hash);
    const char *priv_hex =
        "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28";
    const char *pub_x_hex =
        "7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B";
    const char *pub_y_hex =
        "26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA";
    const char *nonce_hex =
        "77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3";

    uint8_t bytes[64];
    gost_u512_t priv;
    CHECK(gost_u512_from_bytes_be(bytes, hex_to_bytes(priv_hex, bytes), &priv) == GOST_OK);
    gost_ec_point_t pub;
    CHECK(gost_u512_from_bytes_be(bytes, hex_to_bytes(pub_x_hex, bytes), &pub.x) == GOST_OK);
    CHECK(gost_u512_from_bytes_be(bytes, hex_to_bytes(pub_y_hex, bytes), &pub.y) == GOST_OK);
    gost_u512_t nonce;
    CHECK(gost_u512_from_bytes_be(bytes, hex_to_bytes(nonce_hex, bytes), &nonce) == GOST_OK);

    /* d * P == Q. */
    gost_ec_point_t derived;
    CHECK(gost_ec_point_mul(priv, curve->base, curve, &derived) == GOST_OK);
    CHECK(gost_u512_cmp(derived.x, pub.x) == 0 && gost_u512_cmp(derived.y, pub.y) == 0);

    /* q * P == O. */
    gost_ec_point_t order_point;
    CHECK(gost_ec_point_mul(curve->q, curve->base, curve, &order_point) == GOST_OK);
    CHECK(gost_ec_point_is_infinity(order_point));

    /* Signature with the nonce k of the standard example. */
    gost_signature_t sig;
    CHECK(gost_signature_sign(curve, &priv, hash, sizeof(hash), fixed_rng, &nonce, &sig) ==
          GOST_OK);
    CHECK(gost_u512_to_bytes_be(sig.r, bytes, 32U) == GOST_OK);
    CHECK(bytes_equal_hex(bytes, 32U, "41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"));
    CHECK(gost_u512_to_bytes_be(sig.s, bytes, 32U) == GOST_OK);
    CHECK(bytes_equal_hex(bytes, 32U, "01456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40"));

    /* Verification of the official signature. */
    bool valid = false;
    CHECK(gost_signature_verify(curve, &pub, hash, sizeof(hash), &sig, &valid) == GOST_OK);
    CHECK(valid);

    /* Tampered hash must fail. */
    hash[0] ^= 0x01;
    CHECK(gost_signature_verify(curve, &pub, hash, sizeof(hash), &sig, &valid) == GOST_OK);
    CHECK(!valid);
}

static void test_signature_lifecycle(void)
{
    const gost_curve_t *curve = gost_curve(GOST_CURVE_2001_CRYPTOPRO_C);
    CHECK(curve != NULL);

    gost_key_pair_t keys;
    CHECK(gost_signature_generate_keys(curve, gost_rng_system, NULL, &keys) == GOST_OK);

    const uint8_t message[] = "mensaje de prueba para la firma";
    gost_signature_t sig;
    CHECK(gost_signature_sign_message(curve, &keys.private_key, message, sizeof(message) - 1U,
                                      gost_rng_system, NULL, &sig) == GOST_OK);
    bool valid = false;
    CHECK(gost_signature_verify_message(curve, &keys.public_key, message, sizeof(message) - 1U,
                                        &sig, &valid) == GOST_OK);
    CHECK(valid);

    uint8_t tampered[sizeof(message)];
    memcpy(tampered, message, sizeof(message));
    tampered[0] ^= 0x40;
    CHECK(gost_signature_verify_message(curve, &keys.public_key, tampered, sizeof(tampered) - 1U,
                                        &sig, &valid) == GOST_OK);
    CHECK(!valid);

    /* Parameter validation with a pair generated on the same curve. */
    gost_key_pair_t cc_keys;
    CHECK(gost_signature_generate_keys(gost_curve(GOST_CURVE_2001_CC), gost_rng_system, NULL,
                                       &cc_keys) == GOST_OK);
    uint64_t counter = 7U;
    valid = false;
    CHECK(gost_signature_validate(gost_curve(GOST_CURVE_2001_CC), &cc_keys, counter_rng, &counter,
                                  &valid) == GOST_OK);
    CHECK(valid);
}

static void test_key_agreement(void)
{
    /* R 50.1.113-2016 vector over tc26-gost-3410-12-512-paramSetA. */
    const gost_curve_t *curve = gost_curve(GOST_CURVE_TC26_512_A);
    CHECK(curve != NULL);

    uint8_t bytes[64];
    gost_u512_t ukm;
    CHECK(gost_u512_from_bytes_be(bytes, hex_to_bytes("27C744853C60801D", bytes), &ukm) ==
          GOST_OK);

    gost_u512_t a_priv;
    CHECK(gost_u512_from_bytes_be(
              bytes,
              hex_to_bytes("67B63CA4AC8D2BB32618D89296C7476DBEB9F9048496F202B1902CF2CE41DBC"
                           "2F847712D960483458D4B380867F426C7CA0FF5782702DBC44EE8FC72D9EC90"
                           "C9",
                           bytes),
              &a_priv) == GOST_OK);
    gost_u512_t b_priv;
    CHECK(gost_u512_from_bytes_be(
              bytes,
              hex_to_bytes("DBD09213A592DA5BBFD8ED068CCCCCBBFBEDA4FEAC96B9B4908591440B07148"
                           "03B9EB763EF932266D4C0181A9B73EACF9013EFC65EC07C888515F1B6F759C"
                           "848",
                           bytes),
              &b_priv) == GOST_OK);

    gost_ec_point_t a_pub;
    CHECK(gost_u512_from_bytes_be(
              bytes,
              hex_to_bytes("A7C0ADB12743C10C3C1BEB97C8F631242F7937A1DEB6BCE5E664E49261BACCD"
                           "3F5DC56EC53B2ABB90CA1EB703078BA546655A8B99F79188D2021FFABA4EDB"
                           "0AA",
                           bytes),
              &a_pub.x) == GOST_OK);
    CHECK(gost_u512_from_bytes_be(
              bytes,
              hex_to_bytes("5ADB1C63A4E4465E0BBEFD897FB9016475934CFA0F8C95F992EA402D47921F4"
                           "6382D00481B720314B19D8C878E75D81B9763358DD304B2ED3A364E07A3134"
                           "691",
                           bytes),
              &a_pub.y) == GOST_OK);
    gost_ec_point_t b_pub;
    CHECK(gost_u512_from_bytes_be(
              bytes,
              hex_to_bytes("51A6D54EE932D176E87591121CCE5F395CB2F2F147114D95F463C8A7ED74A9F"
                           "C5ECD2325A35FB6387831EA66BC3D2AA42EDE35872CC75372073A71B983E12F"
                           "19",
                           bytes),
              &b_pub.x) == GOST_OK);
    CHECK(gost_u512_from_bytes_be(
              bytes,
              hex_to_bytes("793BDE5BF72840AD22B02A363AE4772D4A52FC08BA1A20F7458A222A13BF98B"
                           "53BE002D1973F1E398CE46C17DA6D00D9B6D0076F8284DCC42E599B4C413B88"
                           "04",
                           bytes),
              &b_pub.y) == GOST_OK);

    uint8_t kek_a[GOST_HASH_MAX_DIGEST];
    uint8_t kek_b[GOST_HASH_MAX_DIGEST];
    CHECK(gost_signature_key_agreement(curve, &a_priv, &b_pub, &ukm, GOST_HASH_256, kek_a) ==
          GOST_OK);
    CHECK(bytes_equal_hex(kek_a, 32U,
                          "21c236efc054c082056748a65fa9ce2c19e2476fce2dd79e55cce22073a7a9c9"));

    /* Both parties must reach the same key. */
    CHECK(gost_signature_key_agreement(curve, &b_priv, &a_pub, &ukm, GOST_HASH_256, kek_b) ==
          GOST_OK);
    CHECK(bytes_equal_hex(kek_b, 32U,
                          "21c236efc054c082056748a65fa9ce2c19e2476fce2dd79e55cce22073a7a9c9"));
    CHECK(memcmp(kek_a, kek_b, 32U) == 0);
}

static void test_text_compatibility(void)
{
    /* The reference project hashes strings after UTF-16LE encoding. */
    const struct {
        const char *text;
        const char *digest256;
    } vectors[] = {
        { "Chikatina", "abe508184523894f72aea279571a540424ed54b224b2e638c05e0d6ce006e512" },
        { "Проверка", "263ab64f81382ff31b2e7cbb37cb82802c33e31f6517203f4cc7c214d8ca89b9" },
    };
    uint8_t digest[GOST_HASH_MAX_DIGEST];
    for (size_t v = 0; v < sizeof(vectors) / sizeof(vectors[0]); v++) {
        CHECK(gost_hash_text(vectors[v].text, strlen(vectors[v].text), GOST_HASH_256, digest) ==
              GOST_OK);
        CHECK(bytes_equal_hex(digest, 32U, vectors[v].digest256));
    }

    /* Size query without a buffer. */
    size_t encoded_len = 0;
    CHECK(gost_text_utf16le("AB", 2U, NULL, 0U, &encoded_len) == GOST_OK);
    CHECK(encoded_len == 4U);

    /* Invalid UTF-8 is rejected. */
    const uint8_t broken[] = { 0xFF };
    CHECK(gost_text_utf16le((const char *)broken, sizeof(broken), NULL, 0U, &encoded_len) ==
          GOST_ERR_PARAM);
}

static void test_hmac(void)
{
    /* RFC 7836, appendix B: HMAC_GOSTR3411_2012 over key K and message T. */
    uint8_t key[32];
    for (unsigned i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t)i;
    }
    uint8_t message[16];
    hex_to_bytes("0126bdb87800af214341456563780100", message);
    uint8_t mac[GOST_HMAC_MAX_DIGEST];

    CHECK(gost_hmac(key, sizeof(key), message, sizeof(message), GOST_HASH_256, mac) == GOST_OK);
    CHECK(bytes_equal_hex(mac, 32U,
                          "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"));

    CHECK(gost_hmac(key, sizeof(key), message, sizeof(message), GOST_HASH_512, mac) == GOST_OK);
    CHECK(bytes_equal_hex(mac, 64U,
                          "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a77"
                          "3d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"));

    /* Streaming HMAC equals the one call form. */
    gost_hmac_ctx_t ctx;
    CHECK(gost_hmac_init(&ctx, key, sizeof(key), GOST_HASH_256) == GOST_OK);
    gost_hmac_update(&ctx, message, 10U);
    gost_hmac_update(&ctx, message + 10U, sizeof(message) - 10U);
    CHECK(gost_hmac_final(&ctx, mac) == GOST_OK);
    CHECK(bytes_equal_hex(mac, 32U,
                          "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"));

    /* Key longer than the block goes through K = H(key); the streaming
       form computes the same MAC as the one call form. */
    uint8_t long_key[80];
    for (unsigned i = 0; i < sizeof(long_key); i++) {
        long_key[i] = (uint8_t)(i * 5U + 1U);
    }
    uint8_t first[GOST_HMAC_MAX_DIGEST];
    uint8_t second[GOST_HMAC_MAX_DIGEST];
    gost_hmac_ctx_t state;
    CHECK(gost_hmac(long_key, sizeof(long_key), message, sizeof(message), GOST_HASH_256, first) ==
          GOST_OK);
    CHECK(gost_hmac_init(&state, long_key, sizeof(long_key), GOST_HASH_256) == GOST_OK);
    CHECK(gost_hmac_update(&state, message, sizeof(message)) == GOST_OK);
    CHECK(gost_hmac_final(&state, second) == GOST_OK);
    CHECK(memcmp(first, second, 32U) == 0);

    /* Guards. */
    CHECK(gost_hmac(key, sizeof(key), message, sizeof(message), (gost_hash_width_t)128, mac) ==
          GOST_ERR_PARAM);
    CHECK(gost_hmac(key, sizeof(key), NULL, 0U, GOST_HASH_256, NULL) == GOST_ERR_PARAM);
}

static void test_pbkdf2(void)
{
    /* Official vectors of draft-pkcs5-gost-02 (R 50.1.111-2016): the PRF
       is HMAC-GOSTR3411-2012-512, fixed regardless of the output length. */
    uint8_t derived[GOST_HMAC_MAX_DIGEST];

    /* c = 1, dkLen = 64. */
    CHECK(gost_pbkdf2((const uint8_t *)"password", 8U, (const uint8_t *)"salt", 4U, 1U, derived,
                      64U) == GOST_OK);
    CHECK(bytes_equal_hex(derived, 64U,
                          "64770af7f748c3b1c9ac831dbcfd85c26111b30a8a657ddc3056b80ca73e040d"
                          "2854fd36811f6d825cc4ab66ec0a68a490a9e5cf5156b3a2b7eecddbf9a16b47"));
    /* c = 2, dkLen = 64. */
    CHECK(gost_pbkdf2((const uint8_t *)"password", 8U, (const uint8_t *)"salt", 4U, 2U, derived,
                      64U) == GOST_OK);
    CHECK(bytes_equal_hex(derived, 64U,
                          "5a585bafdfbb6e8830d6d68aa3b43ac00d2e4aebce01c9b31c2caed56f0236d4d"
                          "34b2b8fbd2c4e89d54d46f50e47d45bbac301571743119e8d3c42ba66d348de"));
    /* c = 4096, dkLen = 64. */
    CHECK(gost_pbkdf2((const uint8_t *)"password", 8U, (const uint8_t *)"salt", 4U, 4096U,
                      derived, 64U) == GOST_OK);
    CHECK(bytes_equal_hex(derived, 64U,
                          "e52deb9a2d2aaff4e2ac9d47a41f34c20376591c67807f0477e32549dc341bc7"
                          "867c09841b6d58e29d0347c996301d55df0d34e47cf68f4e3c2cdaf1d9ab86c3"));
    /* Long password and salt, dkLen = 100 (two blocks, truncated). */
    const char *long_password = "passwordPASSWORDpassword";
    const char *long_salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    CHECK(gost_pbkdf2((const uint8_t *)long_password, strlen(long_password),
                      (const uint8_t *)long_salt, strlen(long_salt), 4096U, derived,
                      100U) == GOST_OK);
    CHECK(bytes_equal_hex(derived, 100U,
                          "b2d8f1245fc4d29274802057e4b54e0a0753aa22fc53760b301cf008679e58fe"
                          "4bee9addcae99ba2b0b20f431a9c5e50f395c89387d0945aedeca6eb4015dfc2"
                          "bd2421ee9bb71183ba882ceebfef259f33f9e27dc6178cb89dc37428cf9cc52a"
                          "2baa2d3a"));
    /* Embedded NUL bytes. */
    CHECK(gost_pbkdf2((const uint8_t *)"pass\0word", 9U, (const uint8_t *)"sa\0lt", 5U, 4096U,
                      derived, 64U) == GOST_OK);
    CHECK(bytes_equal_hex(derived, 64U,
                          "50df062885b69801a3c10248eb0a27ab6e522ffeb20c991c660f001475d73a4e"
                          "167f782c18e97e92976d9c1d970831ea78ccb879f67068cdac1910740844e830"));

    /* Guards. */
    CHECK(gost_pbkdf2((const uint8_t *)"p", 1U, (const uint8_t *)"s", 1U, 0U, derived,
                      32U) == GOST_ERR_PARAM);
    CHECK(gost_pbkdf2((const uint8_t *)"p", 1U, (const uint8_t *)"s", 1U, 1U, NULL, 0U) ==
          GOST_ERR_PARAM);
}

static void test_hmac_guards(void)
{
    uint8_t key[32];
    for (unsigned i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t)i;
    }
    uint8_t message[16];
    hex_to_bytes("0126bdb87800af214341456563780100", message);
    uint8_t mac[GOST_HMAC_MAX_DIGEST];
    CHECK(gost_hmac(key, sizeof(key), message, sizeof(message), (gost_hash_width_t)128, mac) ==
          GOST_ERR_PARAM);
    CHECK(gost_hmac(key, sizeof(key), NULL, 0U, GOST_HASH_256, NULL) == GOST_ERR_PARAM);
}

int main(void)
{
    test_cipher_ecb();
    test_cipher_cfb();
    test_cipher_gamma();
    test_cipher_mac();
    test_bigint();
    test_hash_one_shot();
    test_hash_streaming();
    test_hash_presentation_duality();
    test_hash_incremental();
    test_text_compatibility();
    test_hmac();
    test_pbkdf2();
    test_hmac_guards();
    test_signature_official();
    test_signature_lifecycle();
    test_key_agreement();

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
