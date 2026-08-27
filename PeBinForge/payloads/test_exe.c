/* Conventional console EXE that statically imports test1.dll. */

#include <stdint.h>

__declspec(dllimport) uint64_t __fastcall Test1Add(uint64_t left, uint64_t right);

int main(void) {
    return (int)Test1Add(40, 2);
}
