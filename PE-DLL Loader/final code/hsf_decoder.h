#ifndef WHS_HSF_DECODER_H
#define WHS_HSF_DECODER_H

#include <stddef.h>

typedef enum HsfDecodeStatus {
    HSF_DECODE_OK = 0,
    HSF_DECODE_INVALID_ARGUMENT,
    HSF_DECODE_TRUNCATED_HEADER,
    HSF_DECODE_INVALID_MAGIC,
    HSF_DECODE_UNSUPPORTED_VERSION,
    HSF_DECODE_UNEXPECTED_MODE,
    HSF_DECODE_INVALID_METADATA,
    HSF_DECODE_OUT_OF_MEMORY,
    HSF_DECODE_INVALID_RECORD,
    HSF_DECODE_TRAILING_DATA,
    HSF_DECODE_INTEGRITY_FAILURE
} HsfDecodeStatus;

/*
 * HSF1 mode 3(MAC 문자열) 데이터를 메모리에서 디코딩한다.
 * 성공 시 *decoded_buffer는 malloc으로 할당된 원본 바이트를 가리킨다.
 * 호출자는 사용 후 버퍼를 지우고 free해야 한다.
 */
HsfDecodeStatus hsf_decode_mac_buffer(
    const unsigned char *encoded_buffer,
    size_t encoded_size,
    unsigned char **decoded_buffer,
    size_t *decoded_size
);

const char *hsf_decode_status_string(HsfDecodeStatus status);

#endif
