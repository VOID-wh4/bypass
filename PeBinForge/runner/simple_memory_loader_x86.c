/* CRT-free x86 no-context loader that leaves conventional PE base 0x400000 free. */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#define SIMPLE_MAX_BIN_SIZE (64U * 1024U * 1024U)
#define SIMPLE_RESULT_OK UINT64_C(0x5042460000000001)

typedef uint64_t (__fastcall *simple_entry_fn)(void);

#pragma bss_seg(".pbfhost")
static volatile BYTE g_host_image_reservation[SIMPLE_MAX_BIN_SIZE];
#pragma bss_seg()

static const WCHAR *skip_spaces(const WCHAR *text) {
    while (*text == L' ' || *text == L'\t') ++text;
    return text;
}

static const WCHAR *skip_argument(const WCHAR *text) {
    int quoted = 0;
    text = skip_spaces(text);
    while (*text != 0) {
        if (*text == L'"') quoted = !quoted;
        else if (!quoted && (*text == L' ' || *text == L'\t')) break;
        ++text;
    }
    return skip_spaces(text);
}

static int read_path_argument(WCHAR path[MAX_PATH]) {
    const WCHAR *text = skip_argument(GetCommandLineW());
    const WCHAR *start;
    const WCHAR *end;
    SIZE_T length;
    if (*text == 0) return 0;
    if (*text == L'"') {
        start = ++text;
        while (*text != 0 && *text != L'"') ++text;
        if (*text != L'"') return 0;
        end = text++;
    } else {
        start = text;
        while (*text != 0 && *text != L' ' && *text != L'\t') ++text;
        end = text;
    }
    if (*skip_spaces(text) != 0) return 0;
    length = (SIZE_T)(end - start);
    if (length == 0 || length >= MAX_PATH) return 0;
    while (start != end) *path++ = *start++;
    *path = 0;
    return 1;
}

static void write_message(const char *message) {
    DWORD length = 0;
    DWORD written;
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    while (message[length] != 0) ++length;
    if (output != NULL && output != INVALID_HANDLE_VALUE)
        WriteFile(output, message, length, &written, NULL);
}

static __declspec(noinline) void copy_bytes(BYTE *destination,
                                            const BYTE *source,
                                            DWORD size) {
    DWORD index;
    for (index = 0; index < size; ++index) destination[index] = source[index];
}

void WINAPI PbfSimpleLoaderEntry(void) {
    WCHAR path[MAX_PATH];
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER size;
    BYTE *file_data = NULL;
    BYTE *memory = NULL;
    DWORD read_size = 0;
    DWORD old_protection = 0;
    uint64_t result;
    DWORD exit_code = 1;

    g_host_image_reservation[0] = 0;
    if (!read_path_argument(path)) {
        write_message("Usage: simple-memory-loader-x86 <self-contained-native.bin>\r\n");
        ExitProcess(2);
    }
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE || !GetFileSizeEx(file, &size) ||
        size.HighPart != 0 || size.LowPart == 0 || size.LowPart > SIMPLE_MAX_BIN_SIZE) {
        write_message("[-] BIN is missing, empty, or exceeds 64 MiB.\r\n");
        ExitProcess(3);
    }
    file_data = (BYTE *)VirtualAlloc(NULL, size.LowPart,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    memory = (BYTE *)VirtualAlloc(NULL, size.LowPart,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (file_data == NULL || memory == NULL ||
        !ReadFile(file, file_data, size.LowPart, &read_size, NULL) ||
        read_size != size.LowPart) {
        write_message("[-] Unable to read or allocate the BIN.\r\n");
        goto cleanup;
    }
    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;
    copy_bytes(memory, file_data, size.LowPart);
    VirtualFree(file_data, 0, MEM_RELEASE);
    file_data = NULL;
    if (!VirtualProtect(memory, size.LowPart, PAGE_EXECUTE_READ, &old_protection) ||
        !FlushInstructionCache(GetCurrentProcess(), memory, size.LowPart)) {
        write_message("[-] RW to RX transition failed.\r\n");
        exit_code = 5;
        goto cleanup;
    }
    result = ((simple_entry_fn)(void *)memory)();
    if (result != SIMPLE_RESULT_OK) {
        write_message("[-] Self-contained entry() failed.\r\n");
        exit_code = 6;
        goto cleanup;
    }
    write_message("[+] Self-contained entry() completed.\r\n");
    exit_code = 0;

cleanup:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (file_data != NULL) VirtualFree(file_data, 0, MEM_RELEASE);
    if (memory != NULL) VirtualFree(memory, 0, MEM_RELEASE);
    ExitProcess(exit_code);
}
