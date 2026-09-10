/**
 *  @file  text.c
 *  @brief Text helpers for compatibility with the reference project.
 */
#include "text.h"

#include <stdbool.h>

/** Maximum stack size the convenience hash accepts, in encoded bytes. */
#define GOST_TEXT_STACK_LIMIT 4096

/** @brief Decode the UTF-8 code point at @p *pos; negative on error. */
static int32_t decode_utf8(const char *utf8, size_t len, size_t *pos)
{
    if (*pos >= len) {
        return -1;
    }
    uint8_t lead = (uint8_t)utf8[*pos];
    size_t sequence_len = 0;
    uint32_t code = 0;
    if (lead < 0x80U) {
        sequence_len = 1;
        code = lead;
    } else if ((lead & 0xE0U) == 0xC0U) {
        sequence_len = 2;
        code = lead & 0x1FU;
    } else if ((lead & 0xF0U) == 0xE0U) {
        sequence_len = 3;
        code = lead & 0x0FU;
    } else if ((lead & 0xF8U) == 0xF0U) {
        sequence_len = 4;
        code = lead & 0x07U;
    } else {
        return -1;
    }
    if (*pos + sequence_len > len) {
        return -1;
    }
    for (size_t i = 1; i < sequence_len; i++) {
        uint8_t continuation = (uint8_t)utf8[*pos + i];
        if ((continuation & 0xC0U) != 0x80U) {
            return -1;
        }
        code = (code << 6U) | (continuation & 0x3FU);
    }
    *pos += sequence_len;
    return (int32_t)code;
}

/** @brief Reject surrogate gaps and values beyond the Unicode range. */
static bool code_point_valid(uint32_t code)
{
    return !(code >= 0xD800U && code <= 0xDFFFU) && code <= 0x10FFFFU;
}

/** @brief Append one code unit in little-endian order (NULL out measures). */
static gost_status_t append_unit(uint8_t *out, size_t out_cap, size_t *written, uint16_t unit)
{
    if (out != NULL && *written + 2U > out_cap) {
        return GOST_ERR_PARAM;
    }
    if (out != NULL) {
        out[*written] = (uint8_t)(unit & 0xFFU);
        out[*written + 1U] = (uint8_t)(unit >> 8U);
    }
    *written += 2U;
    return GOST_OK;
}

gost_status_t gost_text_utf16le(const char *utf8, size_t len, uint8_t *out, size_t out_cap,
                                size_t *out_len)
{
    if (utf8 == NULL || out_len == NULL) {
        return GOST_ERR_PARAM;
    }
    if (out == NULL) {
        out_cap = 0;
    }
    size_t written = 0;
    size_t position = 0;
    while (position < len) {
        int32_t code = decode_utf8(utf8, len, &position);
        if (code < 0 || !code_point_valid((uint32_t)code)) {
            return GOST_ERR_PARAM;
        }
        gost_status_t status;
        if ((uint32_t)code < 0x10000U) {
            status = append_unit(out, out_cap, &written, (uint16_t)code);
        } else {
            uint32_t offset = (uint32_t)code - 0x10000U;
            status = append_unit(out, out_cap, &written, (uint16_t)(0xD800U + (offset >> 10U)));
            if (status != GOST_OK) {
                return status;
            }
            status = append_unit(out, out_cap, &written, (uint16_t)(0xDC00U + (offset & 0x3FFU)));
        }
        if (status != GOST_OK) {
            return status;
        }
    }
    *out_len = written;
    return GOST_OK;
}

gost_status_t gost_hash_text(const char *utf8, size_t len, gost_hash_width_t width, uint8_t *out)
{
    if (utf8 == NULL) {
        return GOST_ERR_PARAM;
    }
    size_t encoded_len = 0;
    gost_status_t status = gost_text_utf16le(utf8, len, NULL, 0U, &encoded_len);
    if (status != GOST_OK) {
        return status;
    }
    if (encoded_len > GOST_TEXT_STACK_LIMIT) {
        /* Longer texts go through gost_text_utf16le plus gost_hash. */
        return GOST_ERR_PARAM;
    }
    uint8_t encoded[GOST_TEXT_STACK_LIMIT];
    status = gost_text_utf16le(utf8, len, encoded, sizeof(encoded), &encoded_len);
    if (status != GOST_OK) {
        return status;
    }
    return gost_hash(encoded, encoded_len, width, out);
}
