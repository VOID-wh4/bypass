/* Second-level private dependency for recursive native bundle validation. */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}

__declspec(dllexport) uint64_t __fastcall PbfLeafValue(uint64_t value);
static void *volatile g_leaf_entry = (void *)&PbfLeafValue;

__declspec(dllexport) uint64_t __fastcall PbfLeafValue(uint64_t value) {
    if (g_leaf_entry != (void *)&PbfLeafValue) return 0;
    return value ^ UINT64_C(0x1029384756abcdef);
}
