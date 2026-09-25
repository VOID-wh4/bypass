/* Small private DLL for the documented TEST.EXE bundle example. */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}

__declspec(dllexport) uint64_t __fastcall Test1Add(uint64_t left, uint64_t right);
static void *volatile g_test1_export = (void *)&Test1Add;

__declspec(dllexport) uint64_t __fastcall Test1Add(uint64_t left, uint64_t right) {
    if (g_test1_export != (void *)&Test1Add) return 255;
    return left + right;
}
