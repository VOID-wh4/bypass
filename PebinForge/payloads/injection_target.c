/* Benign x64 process used only by the CTF remote-injection integration test. */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int main(void) {
    Sleep(120000);
    return 0;
}
