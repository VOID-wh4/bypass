/* A relocation-free C payload used to validate the raw BIN pipeline. */

#include "pbf_abi.h"

#pragma code_seg(push, ".pbf")
__declspec(noinline) uint64_t __fastcall PbfPayload(pbf_context *context) {
    uint64_t state;
    uint32_t i;

    if (context == 0 || context->size != sizeof(*context) ||
        context->abi_version != PBF_ABI_VERSION) {
        return 0;
    }

    state = context->input_a ^ (context->input_b + UINT64_C(0x9e3779b97f4a7c15));
    for (i = 0; i < 16; ++i) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state *= UINT64_C(0x2545f4914f6cdd1d);
        context->proof[i] = (uint8_t)(state >> 56);
    }

    context->result = (context->input_a * UINT64_C(0x100000001b3)) ^
        ((context->input_b << 17) | (context->input_b >> 47));
    return PBF_RESULT_OK;
}
#pragma code_seg(pop)
