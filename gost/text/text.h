/**
 *  @file  text.h
 *  @brief Text helpers for compatibility with the reference
 *         gost-cryptography project.
 *
 *  The reference service hashes strings after converting them with
 *  `Код.Строку_в_байты`, which emits UTF-16LE bytes.  These helpers
 *  reproduce that encoding from C strings so both platforms produce the
 *  same digests while the migration is in progress.
 */
#ifndef GOST_TEXT_H
#define GOST_TEXT_H

#include <stddef.h>
#include <stdint.h>

#include "../common.h"
#include "../hash/hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @brief  Encode a UTF-8 string as UTF-16LE, matching the reference
 *          project's `Код.Строку_в_байтов`.
 *
 * dst receives at most @p out_cap bytes; the number of bytes actually
 * produced is reported through @p out_len.  Since every code point needs
 * at least two bytes, @p 2 * len is a sufficient buffer size for every
 * input.
 *
 *  @param  utf8     Source text in UTF-8.
 *  @param  len      Source length in bytes.
 *  @param  out      Destination buffer, may be NULL to compute the size.
 *  @param  out_cap  Destination capacity in bytes.
 *  @param  out_len  Number of encoded bytes, may be NULL when out is set.
 *  @return GOST_OK, GOST_ERR_PARAM for invalid UTF-8 or an undersized
 *          buffer.
 */
gost_status_t gost_text_utf16le(const char *utf8, size_t len, uint8_t *out, size_t out_cap,
                                size_t *out_len);

/**
 *  @brief  Hash a text string exactly like the reference
 *          `EncryptService.hash`: UTF-16LE encoding followed by Streebog.
 *
 *  The digest follows the one shot presentation of @ref gost_hash, so it
 *  matches the hex string printed by the JavaScript project.
 *
 *  @param  utf8     Source text in UTF-8.
 *  @param  len      Source length in bytes.
 *  @param  width    Digest width.
 *  @param  out      Digest destination, at least 64 bytes.
 *  @return GOST_OK, GOST_ERR_PARAM for invalid UTF-8 or an invalid width.
 */
gost_status_t gost_hash_text(const char *utf8, size_t len, gost_hash_width_t width, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* GOST_TEXT_H */
