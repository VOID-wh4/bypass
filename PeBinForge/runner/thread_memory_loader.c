/* CreateThread-based no-context loader with an x86/x64 ABI adapter. */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "pbf_abi.h"

#define THREAD_LOADER_MAX_BIN (64U * 1024U * 1024U)

typedef uint64_t (__fastcall *pbf_noargs_entry_fn)(void);

typedef struct pbf_thread_call_t {
    BYTE *entry;
    uint64_t result;
} pbf_thread_call;

static DWORD WINAPI call_pbf_entry(LPVOID parameter) {
    pbf_thread_call *call = (pbf_thread_call *)parameter;
    call->result = ((pbf_noargs_entry_fn)(void *)call->entry)();
    return call->result == PBF_RESULT_OK ? 0 : 1;
}

int main(int argc, char **argv) {
    struct _stat64 status;
    FILE *file = NULL;
    BYTE *file_data = NULL;
    BYTE *memory = NULL;
    HANDLE thread = NULL;
    DWORD old_protection = 0;
    DWORD thread_exit = 1;
    pbf_thread_call call;
    int exit_code = 1;

    if (argc != 2) {
        puts("Usage: thread-memory-loader <self-contained.bin>");
        return 2;
    }
    if (_stat64(argv[1], &status) != 0 || status.st_size <= 0 ||
        status.st_size > THREAD_LOADER_MAX_BIN) {
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
    if (!VirtualProtect(memory, (SIZE_T)status.st_size, PAGE_EXECUTE_READ,
                        &old_protection) ||
        !FlushInstructionCache(GetCurrentProcess(), memory, (SIZE_T)status.st_size)) {
        fprintf(stderr, "[-] RW to RX transition failed: %lu\n", GetLastError());
        goto cleanup;
    }
    memset(&call, 0, sizeof(call));
    call.entry = memory;
    thread = CreateThread(NULL, 0, call_pbf_entry, &call, 0, NULL);
    if (thread == NULL) {
        fprintf(stderr, "[-] CreateThread failed: %lu\n", GetLastError());
        goto cleanup;
    }
    if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0 ||
        !GetExitCodeThread(thread, &thread_exit)) {
        fputs("[-] Unable to wait for the loader thread.\n", stderr);
        goto cleanup;
    }
    if (thread_exit != 0 || call.result != PBF_RESULT_OK) {
        fprintf(stderr, "[-] entry() failed: thread=%lu result=0x%016" PRIx64 "\n",
            thread_exit, call.result);
        exit_code = 6;
        goto cleanup;
    }
    printf("[+] CreateThread adapter completed: 0x%016" PRIx64 "\n", call.result);
    exit_code = 0;

cleanup:
    if (thread != NULL) CloseHandle(thread);
    if (memory != NULL) VirtualFree(memory, 0, MEM_RELEASE);
    if (file != NULL) fclose(file);
    free(file_data);
    return exit_code;
}
