/* Minimal no-context loader for self-contained PeBinForge native v3 BINs. */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SIMPLE_MAX_BIN_SIZE (64U * 1024U * 1024U)
#define SIMPLE_RESULT_OK UINT64_C(0x5042460000000001)

typedef uint64_t (__fastcall *simple_entry_fn)(void);

int main(int argc, char **argv) {
    struct _stat64 status;
    FILE *file = NULL;
    BYTE *file_data = NULL;
    BYTE *memory = NULL;
    DWORD old_protection = 0;
    uint64_t result = 0;
    int exit_code = 1;

    if (argc != 2) {
        puts("Usage: simple-memory-loader <self-contained-native.bin>");
        return 2;
    }
    if (_stat64(argv[1], &status) != 0 || status.st_size <= 0 ||
        status.st_size > SIMPLE_MAX_BIN_SIZE) {
        fputs("[-] BIN is missing, empty, or exceeds 64 MiB.\n", stderr);
        return 3;
    }
    file_data = (BYTE *)malloc((size_t)status.st_size);
    file = fopen(argv[1], "rb");
    if (file_data == NULL || file == NULL ||
        fread(file_data, 1, (size_t)status.st_size, file) != (size_t)status.st_size) {
        fputs("[-] Unable to read BIN.\n", stderr);
        goto cleanup;
    }
    fclose(file);
    file = NULL;

    memory = (BYTE *)VirtualAlloc(NULL, (SIZE_T)status.st_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (memory == NULL) {
        fprintf(stderr, "[-] VirtualAlloc failed: %lu\n", GetLastError());
        goto cleanup;
    }
    memcpy(memory, file_data, (size_t)status.st_size);
    free(file_data);
    file_data = NULL;
    if (!VirtualProtect(memory, (SIZE_T)status.st_size,
                        PAGE_EXECUTE_READ, &old_protection) ||
        !FlushInstructionCache(GetCurrentProcess(), memory, (SIZE_T)status.st_size)) {
        fprintf(stderr, "[-] RW -> RX transition failed: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Copied %lld bytes; calling entry() at %p.\n",
        status.st_size, (void *)memory);
    fflush(stdout);
    __try {
        result = ((simple_entry_fn)(void *)memory)();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[-] entry() raised exception 0x%08lx.\n", GetExceptionCode());
        exit_code = 5;
        goto cleanup;
    }
    if (result != SIMPLE_RESULT_OK) {
        fprintf(stderr, "[-] Self-contained entry() returned 0x%016" PRIx64 ".\n",
            result);
        exit_code = 6;
        goto cleanup;
    }
    printf("[+] Self-contained entry() returned 0x%016" PRIx64 ".\n", result);
    exit_code = 0;

cleanup:
    if (memory != NULL) VirtualFree(memory, 0, MEM_RELEASE);
    if (file != NULL) fclose(file);
    free(file_data);
    return exit_code;
}
