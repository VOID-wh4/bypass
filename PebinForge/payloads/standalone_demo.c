/* A relocation-free, parameterless entry used to validate standalone mode. */

#pragma code_seg(push, ".pbf")
__declspec(noinline) void __fastcall PbfStandalone(void) {
    volatile unsigned __int64 marker = 42;
    (void)marker;
}
#pragma code_seg(pop)
