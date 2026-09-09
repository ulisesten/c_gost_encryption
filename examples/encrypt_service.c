/**
 *  @file  encrypt_service.c
 *  @brief Usage example mirroring the reference encrypt.js service:
 *         reversible encryption, hashing and digital signature.
 */
#include <gost/gost.h>

#include <stdio.h>
#include <string.h>

/** Service configuration (settings.getSecretKey / settings.getXVector). */
static const uint32_t secret_key[GOST_CIPHER_KEY_WORDS] = {
    0x33206D54, 0x326C6568, 0x20657369, 0x626E7373,
    0x79676120, 0x74746769, 0x65686573, 0x733D2C20,
};
static const uint32_t x_vector[2] = { 0x11223344, 0x55667788 };

/** Reversible encryption of a buffer in place; returns its new length. */
static size_t reversible_encrypt(uint8_t *data, size_t len)
{
    gost_cipher_t cipher;
    gost_cipher_init(&cipher, secret_key, GOST_SBOX_TC26_Z);
    gost_cipher_cfb_encrypt(&cipher, x_vector, data, len);
    return len;
}

/** In place decryption; returns the recovered length. */
static size_t decrypt(uint8_t *data, size_t len)
{
    gost_cipher_t cipher;
    gost_cipher_init(&cipher, secret_key, GOST_SBOX_TC26_Z);
    gost_cipher_cfb_decrypt(&cipher, x_vector, data, len);
    return len;
}

/** Streebog-256 of the data, compatible with EncryptService.hash. */
static void hash_data(const uint8_t *data, size_t len, uint8_t digest[32])
{
    gost_hash(data, len, GOST_HASH_256, digest);
}

/** Print a buffer as hex. */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void)
{
    const char *message = "payload-test-123";
    uint8_t buffer[64];
    size_t len = strlen(message);
    memcpy(buffer, message, len);

    /* Reversible encryption and decryption. */
    len = reversible_encrypt(buffer, len);
    print_hex("ciphertext: ", buffer, len);
    len = decrypt(buffer, len);
    printf("decrypted:  %.*s\n", (int)len, buffer);

    /* Hash of the plaintext. */
    len = strlen(message);
    uint8_t digest[32];
    hash_data((const uint8_t *)message, len, digest);
    print_hex("hash-256:   ", digest, sizeof(digest));

    /* Digital signature over the message. */
    const gost_curve_t *curve = gost_curve(GOST_CURVE_2001_CRYPTOPRO_C);
    gost_key_pair_t keys;
    if (gost_signature_generate_keys(curve, gost_rng_system, NULL, &keys) != GOST_OK) {
        printf("key generation failed\n");
        return 1;
    }
    gost_signature_t signature;
    gost_signature_sign_message(curve, &keys.private_key, message, len, gost_rng_system, NULL,
                                &signature);
    uint8_t r[64];
    uint8_t s[64];
    gost_u512_to_bytes_be(signature.r, r, 32U);
    gost_u512_to_bytes_be(signature.s, s, 32U);
    print_hex("signature r:", r, 32U);
    print_hex("signature s:", s, 32U);

    bool valid = false;
    gost_signature_verify_message(curve, &keys.public_key, message, len, &signature, &valid);
    printf("verified:   %s\n", valid ? "true" : "false");
    return valid ? 0 : 1;
}
