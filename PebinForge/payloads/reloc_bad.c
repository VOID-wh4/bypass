/* Deliberately invalid PIC input used to verify relocation rejection. */

#include <stdint.h>

extern uint64_t PbfExternalValue;

#pragma code_seg(push, ".pbf")
__declspec(noinline) uint64_t __fastcall PbfRelocationTest(void *context) {
    (void)context;
    return PbfExternalValue;
}
#pragma code_seg(pop)
