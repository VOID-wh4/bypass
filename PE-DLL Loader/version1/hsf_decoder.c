#include "hsf_decoder.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum {
    HSF_VERSION = 1,
    HSF_MODE_MAC = 3,
    HSF_MAC_CHUNK_SIZE = 6,
    HSF_MAC_TEXT_LENGTH = 17,
    HSF_HEADER_SIZE = 32
};

#define HSF_FNV_OFFSET UINT64_C(14695981039346656037)
#define HSF_FNV_PRIME  UINT64_C(1099511628211)

static void hsf_secure_zero(void *memory, size_t size)
{
    volatile unsigned char *cursor = (volatile unsigned char *)memory;

    while (size > 0U) {
        *cursor++ = 0U;
        --size;
    }
}

static int take_bytes(
    const unsigned char *input,
    size_t input_size,
    size_t *offset,
    size_t count,
    const unsigned char **result
)
{
    if (input == NULL || offset == NULL || result == NULL
        || *offset > input_size || count > input_size - *offset) {
        return 0;
    }

    *result = input + *offset;
    *offset += count;
    return 1;
}

static int read_u16_le(
    const unsigned char *input,
    size_t input_size,
    size_t *offset,
    uint16_t *value
)
{
    const unsigned char *bytes;

    if (value == NULL
        || !take_bytes(input, input_size, offset, 2U, &bytes)) {
        return 0;
    }

    *value = (uint16_t)bytes[0]
        | ((uint16_t)bytes[1] << 8U);
    return 1;
}

static int read_u64_le(
    const unsigned char *input,
    size_t input_size,
    size_t *offset,
    uint64_t *value
)
{
    const unsigned char *bytes;
    uint64_t result = 0U;
    unsigned int i;

    if (value == NULL
        || !take_bytes(input, input_size, offset, 8U, &bytes)) {
        return 0;
    }

    for (i = 0U; i < 8U; ++i) {
        result |= (uint64_t)bytes[i] << (i * 8U);
    }
    *value = result;
    return 1;
}

static uint64_t fnv1a_update(
    uint64_t hash,
    const unsigned char *data,
    size_t size
)
{
    size_t i;

    for (i = 0U; i < size; ++i) {
        hash ^= data[i];
        hash *= HSF_FNV_PRIME;
    }
    return hash;
}

static int hex_value(unsigned char character)
{
    if (character >= (unsigned char)'0'
        && character <= (unsigned char)'9') {
        return character - (unsigned char)'0';
    }
    if (character >= (unsigned char)'A'
        && character <= (unsigned char)'F') {
        return character - (unsigned char)'A' + 10;
    }
    if (character >= (unsigned char)'a'
        && character <= (unsigned char)'f') {
        return character - (unsigned char)'a' + 10;
    }
    return -1;
}

static int parse_mac_record(
    const unsigned char *text,
    size_t text_length,
    unsigned char output[HSF_MAC_CHUNK_SIZE]
)
{
    unsigned int i;

    if (text == NULL || output == NULL
        || text_length != HSF_MAC_TEXT_LENGTH) {
        return 0;
    }

    for (i = 0U; i < HSF_MAC_CHUNK_SIZE; ++i) {
        size_t text_offset = (size_t)i * 3U;
        int high = hex_value(text[text_offset]);
        int low = hex_value(text[text_offset + 1U]);

        if (high < 0 || low < 0) {
            return 0;
        }
        output[i] = (unsigned char)((high << 4) | low);

        if (i + 1U < HSF_MAC_CHUNK_SIZE
            && text[text_offset + 2U] != (unsigned char)'-') {
            return 0;
        }
    }

    return 1;
}

HsfDecodeStatus hsf_decode_mac_buffer(
    const unsigned char *encoded_buffer,
    size_t encoded_size,
    unsigned char **decoded_buffer,
    size_t *decoded_size
)
{
    size_t offset = 0U;
    const unsigned char *magic;
    const unsigned char *fixed_fields;
    uint64_t original_size_u64;
    uint64_t record_count;
    uint64_t expected_hash;
    uint64_t expected_record_count;
    uint64_t actual_hash = HSF_FNV_OFFSET;
    uint64_t record_index;
    size_t original_size;
    size_t written = 0U;
    unsigned char *output = NULL;
    HsfDecodeStatus status = HSF_DECODE_INVALID_METADATA;

    if (encoded_buffer == NULL || decoded_buffer == NULL
        || decoded_size == NULL) {
        return HSF_DECODE_INVALID_ARGUMENT;
    }

    *decoded_buffer = NULL;
    *decoded_size = 0U;

    if (encoded_size < HSF_HEADER_SIZE) {
        return HSF_DECODE_TRUNCATED_HEADER;
    }
    if (!take_bytes(
            encoded_buffer,
            encoded_size,
            &offset,
            4U,
            &magic
        )) {
        return HSF_DECODE_TRUNCATED_HEADER;
    }
    if (memcmp(magic, "HSF1", 4U) != 0) {
        return HSF_DECODE_INVALID_MAGIC;
    }
    if (!take_bytes(
            encoded_buffer,
            encoded_size,
            &offset,
            4U,
            &fixed_fields
        )) {
        return HSF_DECODE_TRUNCATED_HEADER;
    }
    if (fixed_fields[0] != HSF_VERSION) {
        return HSF_DECODE_UNSUPPORTED_VERSION;
    }
    if (fixed_fields[1] != HSF_MODE_MAC) {
        return HSF_DECODE_UNEXPECTED_MODE;
    }
    if (fixed_fields[2] != 0U || fixed_fields[3] != 0U) {
        return HSF_DECODE_INVALID_METADATA;
    }
    if (!read_u64_le(
            encoded_buffer,
            encoded_size,
            &offset,
            &original_size_u64
        )
        || !read_u64_le(
            encoded_buffer,
            encoded_size,
            &offset,
            &record_count
        )
        || !read_u64_le(
            encoded_buffer,
            encoded_size,
            &offset,
            &expected_hash
        )) {
        return HSF_DECODE_TRUNCATED_HEADER;
    }

    if (original_size_u64 == 0U
        || original_size_u64 > (uint64_t)SIZE_MAX) {
        return HSF_DECODE_INVALID_METADATA;
    }

    expected_record_count = original_size_u64 / HSF_MAC_CHUNK_SIZE;
    if (original_size_u64 % HSF_MAC_CHUNK_SIZE != 0U) {
        ++expected_record_count;
    }
    if (record_count != expected_record_count) {
        return HSF_DECODE_INVALID_METADATA;
    }

    original_size = (size_t)original_size_u64;
    output = (unsigned char *)malloc(original_size);
    if (output == NULL) {
        return HSF_DECODE_OUT_OF_MEMORY;
    }

    for (record_index = 0U; record_index < record_count; ++record_index) {
        uint16_t text_length;
        const unsigned char *text;
        unsigned char decoded[HSF_MAC_CHUNK_SIZE];
        size_t bytes_to_copy = HSF_MAC_CHUNK_SIZE;

        if (!read_u16_le(
                encoded_buffer,
                encoded_size,
                &offset,
                &text_length
            )
            || !take_bytes(
                encoded_buffer,
                encoded_size,
                &offset,
                (size_t)text_length,
                &text
            )
            || !parse_mac_record(text, (size_t)text_length, decoded)) {
            status = HSF_DECODE_INVALID_RECORD;
            goto failure;
        }

        if (bytes_to_copy > original_size - written) {
            bytes_to_copy = original_size - written;
        }
        memcpy(output + written, decoded, bytes_to_copy);
        actual_hash = fnv1a_update(actual_hash, decoded, bytes_to_copy);
        written += bytes_to_copy;
    }

    if (written != original_size) {
        status = HSF_DECODE_INVALID_METADATA;
        goto failure;
    }
    if (offset != encoded_size) {
        status = HSF_DECODE_TRAILING_DATA;
        goto failure;
    }
    if (actual_hash != expected_hash) {
        status = HSF_DECODE_INTEGRITY_FAILURE;
        goto failure;
    }

    *decoded_buffer = output;
    *decoded_size = original_size;
    return HSF_DECODE_OK;

failure:
    hsf_secure_zero(output, original_size);
    free(output);
    return status;
}

const char *hsf_decode_status_string(HsfDecodeStatus status)
{
    switch (status) {
    case HSF_DECODE_OK:
        return "success";
    case HSF_DECODE_INVALID_ARGUMENT:
        return "invalid argument";
    case HSF_DECODE_TRUNCATED_HEADER:
        return "truncated HSF header";
    case HSF_DECODE_INVALID_MAGIC:
        return "invalid HSF1 magic";
    case HSF_DECODE_UNSUPPORTED_VERSION:
        return "unsupported HSF version";
    case HSF_DECODE_UNEXPECTED_MODE:
        return "input is not HSF MAC mode";
    case HSF_DECODE_INVALID_METADATA:
        return "inconsistent HSF metadata";
    case HSF_DECODE_OUT_OF_MEMORY:
        return "out of memory";
    case HSF_DECODE_INVALID_RECORD:
        return "malformed HSF MAC record";
    case HSF_DECODE_TRAILING_DATA:
        return "unexpected trailing HSF data";
    case HSF_DECODE_INTEGRITY_FAILURE:
        return "FNV-1a integrity verification failed";
    default:
        return "unknown HSF decode error";
    }
}
