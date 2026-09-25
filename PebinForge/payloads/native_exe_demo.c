/* Conventional x64 console EXE used to validate mapped EXE entry execution. */

#include <stdint.h>

__declspec(dllimport) uint64_t __fastcall PbfDependencyValue(uint64_t value);

int main(void) {
    uint64_t value = PbfDependencyValue(42);
    value ^= UINT64_C(0x5a6b7c8d9eaf1021);
    return value == 42 ? 42 : 111;
}
