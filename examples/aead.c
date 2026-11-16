/**
 *  @file  aead.c
 *  @brief  End-to-end encrypted media flow with the AEAD construction
 *          and the SFrame-GOST profile of this library.
 *
 *  This mirrors the usage planned for cws_sodastream calls: a session
 *  key agreement (not shown here) produces 256-bit keys, the sender
 *  seals audio-shaped frames, the receiver opens them, and key
 *  rotation by KID switches to a new epoch.
 */
#include <gost/gost.h>

#include <stdio.h>
#include <string.h>

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%-14s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void)
{
    /* Session keys, in practice derived from VKO plus HKDF-Streebog. */
    uint8_t session_key[32];
    for (unsigned i = 0; i < sizeof(session_key); i++) {
        session_key[i] = (uint8_t)(i * 7U + 11U);
    }

    /* 1. One-shot AEAD over a whole payload. */
    const uint8_t nonce[16] = {
        UINT8_C(0x12), UINT8_C(0x34), UINT8_C(0x56), UINT8_C(0x78), UINT8_C(0x90), UINT8_C(0xab),
        UINT8_C(0xce), UINT8_C(0xf0), UINT8_C(0xa1), UINT8_C(0xb2), UINT8_C(0xc3), UINT8_C(0xd4),
        UINT8_C(0xe5), UINT8_C(0xf0), UINT8_C(0x01), UINT8_C(0x12),
    };
    const char *aad = "call-frame-header";
    const char *message = "20 ms of audio, encrypted end to end";
    size_t message_len = strlen(message);

    uint8_t ciphertext[64];
    uint8_t tag[16];
    if (gost_aead_seal(session_key, nonce, (const uint8_t *)aad, strlen(aad), (const uint8_t *)message,
                       message_len, ciphertext, tag) != GOST_OK) {
        printf("seal failed\n");
        return 1;
    }
    print_hex("ciphertext:", ciphertext, message_len);
    print_hex("tag:", tag, sizeof(tag));

    uint8_t plaintext[64];
    gost_status_t status = gost_aead_open(session_key, nonce, (const uint8_t *)aad, strlen(aad),
                                          ciphertext, message_len, tag, plaintext);
    printf("aead open:  %s\n", status == GOST_OK ? "authenticated" : "rejected");
    if (status != GOST_OK) {
        return 1;
    }

    /* 2. SFrame-GOST flow: register the session key, seal frames. */
    gost_sframe_ctx_t sender;
    gost_sframe_ctx_t receiver;
    gost_sframe_init(&sender);
    gost_sframe_init(&receiver);
    gost_sframe_set_key(&sender, 1U, session_key);
    gost_sframe_set_key(&receiver, 1U, session_key);

    uint8_t audio[160];  /* e.g. 20 ms of 8 kHz samples. */
    for (unsigned frame = 0; frame < 3U; frame++) {
        for (unsigned i = 0; i < sizeof(audio); i++) {
            audio[i] = (uint8_t)(frame * 37U + i);
        }
        uint8_t wire[512];
        size_t wire_len = 0U;
        if (gost_sframe_encrypt(&sender, audio, sizeof(audio), wire, sizeof(wire), &wire_len) != GOST_OK) {
            printf("frame %u seal failed\n", frame);
            return 1;
        }
        uint8_t media[512];
        size_t media_len = 0U;
        status = gost_sframe_decrypt(&receiver, wire, wire_len, media, sizeof(media), &media_len);
        printf("frame %u:    %s (%zu bytes)\n", frame, status == GOST_OK ? "ok" : "rejected", media_len);
        if (status != GOST_OK || memcmp(media, audio, sizeof(audio)) != 0) {
            return 1;
        }
    }

    /* 3. Epoch rotation: a new key under a new KID. */
    uint8_t next_epoch[32];
    for (unsigned i = 0; i < sizeof(next_epoch); i++) {
        next_epoch[i] = (uint8_t)(i * 13U + 5U);
    }
    gost_sframe_set_key(&sender, 2U, next_epoch);
    gost_sframe_set_key(&receiver, 2U, next_epoch);
    gost_sframe_set_sender(&sender, 2U);
    uint8_t rotated[512];
    size_t rotated_len = 0U;
    status = gost_sframe_encrypt(&sender, audio, sizeof(audio), rotated, sizeof(rotated), &rotated_len);
    printf("rotation:   %s, KID byte = %u\n", status == GOST_OK ? "ok" : "failed", rotated[1]);
    if (status != GOST_OK) {
        return 1;
    }

    gost_secure_zero(session_key, sizeof(session_key));
    gost_secure_zero(next_epoch, sizeof(next_epoch));
    return 0;
}
