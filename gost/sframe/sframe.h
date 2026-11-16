/**
 *  @file  sframe.h
 *  @brief  SFrame-GOST: frame encryption profile for E2EE media calls.
 *
 *  Own profile, NOT interoperable with SFrame (RFC 9605); every
 *  endpoint is under this library's control.  Frame layout:
 *
 *      byte 0      version, always 0x01
 *      byte 1      key ID (KID)
 *      bytes 2..9  frame counter, big-endian 64-bit
 *      rest        ciphertext || CMAC tag (16 bytes)
 *
 *  The header is the AEAD associated data, so version, KID and counter
 *  are authenticated.  The counter of each key starts at 1 and the
 *  AEAD nonce is counter || 0^8, unique per key by construction.  The
 *  decrypt side keeps a sliding replay window of 64 counters per KID
 *  and rejects replays and counters older than the window.
 *
 *  Key rotation: register a new KID with @c gost_sframe_set_key and
 *  select it for sending with @c gost_sframe_set_sender; re-registering
 *  an existing KID replaces its key and resets its counter and replay
 *  state, which is the epoch rotation.  Session management (VKO key
 *  agreement, sender keys, epoch distribution) belongs to the
 *  application; this feature only seals and opens frames.
 */
#ifndef GOST_SFRAME_H
#define GOST_SFRAME_H

#include <stddef.h>
#include <stdint.h>

#include "../common.h"
#include "../aead/aead.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Frame header size: version, KID and 64-bit counter. */
#define GOST_SFRAME_HEADER 10U

/** Maximum number of registered KIDs. */
#define GOST_SFRAME_KID_MAX 8U

/** Replay window size in frames. */
#define GOST_SFRAME_WINDOW 64U

/** Overhead a frame adds over the plaintext. */
#define GOST_SFRAME_OVERHEAD (GOST_SFRAME_HEADER + GOST_AEAD_TAG)

/**
 *  @brief  Registered key slot.  Treat the contents as private.
 */
typedef struct gost_sframe_key {
    uint8_t kid;  /**< Key identifier on the wire. */
    uint8_t used;  /**< Slot in use. */
    uint8_t key[GOST_AEAD_KEY];  /**< AEAD master key of the KID. */
    uint64_t counter;  /**< Last counter used for sending. */
    uint64_t highest;  /**< Highest counter accepted. */
    uint64_t window;  /**< Sliding replay bitmap. */
} gost_sframe_key_t;

/**
 *  @brief  SFrame context.  Treat the contents as private.
 */
typedef struct gost_sframe_ctx {
    gost_sframe_key_t keys[GOST_SFRAME_KID_MAX];  /**< Registered KIDs. */
    int sender;  /**< Index of the sending key, -1 while unset. */
} gost_sframe_ctx_t;

/**
 *  @brief  Initialize an empty context.
 *  @return GOST_OK, or GOST_ERR_PARAM for a NULL pointer.
 */
gost_status_t gost_sframe_init(gost_sframe_ctx_t *ctx);

/**
 *  @brief  Register or replace the key of a KID.
 *
 *  Replacing a KID resets its counter and replay state; that is the
 *  epoch rotation.  The key material is copied into the context.
 *
 *  @param  ctx  Initialized context.
 *  @param  kid  Key identifier, 0..255.
 *  @param  key  256-bit AEAD key.
 *  @return GOST_OK, GOST_ERR_STATE when all slots are used, or
 *          GOST_ERR_PARAM for invalid arguments.
 */
gost_status_t gost_sframe_set_key(gost_sframe_ctx_t *ctx, uint8_t kid, const uint8_t key[GOST_AEAD_KEY]);

/**
 *  @brief  Select the KID used by @c gost_sframe_encrypt.
 *  @return GOST_OK, GOST_ERR_STATE for an unknown KID, or
 *          GOST_ERR_PARAM for a NULL context.
 */
gost_status_t gost_sframe_set_sender(gost_sframe_ctx_t *ctx, uint8_t kid);

/**
 *  @brief  Encrypt one media frame.
 *
 *  The output frame is header || ciphertext || tag, of
 *  len + GOST_SFRAME_OVERHEAD bytes.  The frame counter of the sender
 *  key increments per call.
 *
 *  @param  ctx      Initialized context with a sender key set.
 *  @param  frame    Plaintext frame, may be NULL when len is 0.
 *  @param  len      Frame length.
 *  @param  out      Output frame destination.
 *  @param  out_cap  Capacity of @p out.
 *  @param  out_len  Receives the produced frame length.
 *  @return GOST_OK, GOST_ERR_STATE without a sender key,
 *          GOST_ERR_PARAM when the output capacity is short or the
 *          arguments are invalid.
 */
gost_status_t gost_sframe_encrypt(gost_sframe_ctx_t *ctx, const uint8_t *frame, size_t len,
                                  uint8_t *out, size_t out_cap, size_t *out_len);

/**
 *  @brief  Decrypt one media frame.
 *
 *  Rejects malformed frames, unknown KIDs, replays within the window
 *  and any authentication failure.  No plaintext is released unless
 *  the tag verifies.
 *
 *  @param  ctx      Initialized context holding the KID's key.
 *  @param  frame    Received frame.
 *  @param  len      Frame length, at least GOST_SFRAME_OVERHEAD.
 *  @param  out      Plaintext destination.
 *  @param  out_cap  Capacity of @p out.
 *  @param  out_len  Receives the plaintext length.
 *  @return GOST_OK, GOST_ERR_AUTH for replays or tag failures,
 *          GOST_ERR_STATE for unknown versions or KIDs, or
 *          GOST_ERR_PARAM for malformed input.
 */
gost_status_t gost_sframe_decrypt(gost_sframe_ctx_t *ctx, const uint8_t *frame, size_t len,
                                  uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* GOST_SFRAME_H */
