/* Native x64 DLL used to validate the clean-room in-memory PE mapper. */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "pbf_abi.h"

__declspec(dllimport) uint64_t __fastcall PbfDependencyValue(uint64_t value);

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}

__declspec(dllexport) uint64_t __fastcall PbfEntry(pbf_context *context);
static void *volatile g_expected_entry = (void *)&PbfEntry;

__declspec(dllexport) uint64_t __fastcall PbfEntry(pbf_context *context) {
    uint64_t process_id;
    uint64_t dependency_value;
    uint32_t i;

    if (context == NULL || g_expected_entry != (void *)&PbfEntry ||
        context->size != sizeof(*context) ||
        context->abi_version != PBF_ABI_VERSION) {
        return 0;
    }
    process_id = (uint64_t)GetCurrentProcessId();
    dependency_value = PbfDependencyValue(context->input_a + context->input_b);
    dependency_value ^= UINT64_C(0x5a6b7c8d9eaf1021);
    context->result = dependency_value ^ (process_id << 32);
    for (i = 0; i < sizeof(context->proof); ++i) {
        context->proof[i] = (uint8_t)(((const uint8_t *)&context->result)[i & 7U] ^ i);
    }
    return PBF_RESULT_OK;
}
