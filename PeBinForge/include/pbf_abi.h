#ifndef PBF_ABI_H
#define PBF_ABI_H

#include <stdint.h>

#define PBF_ABI_VERSION 1U
#define PBF_RESULT_OK UINT64_C(0x5042460000000001)

typedef struct pbf_context_t {
    uint32_t size;
    uint32_t abi_version;
    uint64_t input_a;
    uint64_t input_b;
    uint64_t result;
    uint8_t proof[16];
} pbf_context;

typedef uint64_t (__fastcall *pbf_entry_fn)(pbf_context *context);
typedef void (__fastcall *pbf_standalone_entry_fn)(void);

#endif
