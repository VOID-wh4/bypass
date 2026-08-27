/* Private native dependency used to validate embedded-DLL import resolution. */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

__declspec(dllimport) uint64_t __fastcall PbfLeafValue(uint64_t value);

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}

__declspec(dllexport) uint64_t __fastcall PbfDependencyValue(uint64_t value);
static void *volatile g_dependency_entry = (void *)&PbfDependencyValue;

__declspec(dllexport) uint64_t __fastcall PbfDependencyValue(uint64_t value) {
    if (g_dependency_entry != (void *)&PbfDependencyValue) return 0;
    value = PbfLeafValue(value);
    value ^= UINT64_C(0x1029384756abcdef);
    return value ^ UINT64_C(0x5a6b7c8d9eaf1021);
}
