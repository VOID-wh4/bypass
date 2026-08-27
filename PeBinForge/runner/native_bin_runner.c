/* Local first-byte runner for PeBinForge native raw BIN bundles. */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wincrypt.h>
#include <intrin.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "pbf_native.h"

#define SHA256_SIZE 32U

static int checked_range(uint64_t offset, uint64_t length, uint64_t total) {
    return offset <= total && length <= total - offset;
}

static int hex_value(int character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

static int read_expected_hash(const char *bin_path, BYTE expected[SHA256_SIZE]) {
    char sidecar[MAX_PATH];
    char text[64];
    FILE *file;
    size_t length = strlen(bin_path);
    unsigned int index;
    if (length + 8 >= sizeof(sidecar)) return 0;
    memcpy(sidecar, bin_path, length + 1);
    strcat(sidecar, ".sha256");
    file = fopen(sidecar, "rb");
    if (file == NULL || fread(text, 1, sizeof(text), file) != sizeof(text)) {
        if (file != NULL) fclose(file);
        return 0;
    }
    fclose(file);
    for (index = 0; index < SHA256_SIZE; ++index) {
        int high = hex_value(text[index * 2]);
        int low = hex_value(text[index * 2 + 1]);
        if (high < 0 || low < 0) return 0;
        expected[index] = (BYTE)((high << 4) | low);
    }
    return 1;
}

static int hash_bytes(const BYTE *data, DWORD length, BYTE digest[SHA256_SIZE]) {
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    DWORD digest_size = SHA256_SIZE;
    int ok = 0;
    if (!CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) goto cleanup;
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) goto cleanup;
    if (!CryptHashData(hash, data, length, 0)) goto cleanup;
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_size, 0) ||
        digest_size != SHA256_SIZE) goto cleanup;
    ok = 1;
cleanup:
    if (hash != 0) CryptDestroyHash(hash);
    if (provider != 0) CryptReleaseContext(provider, 0);
    return ok;
}

static int valid_magic(const uint8_t magic[PBF_NATIVE_MAGIC_SIZE]) {
    return magic[0] == 'P' && magic[1] == 'B' && magic[2] == 'F' && magic[3] == 'N' &&
        magic[4] == 'A' && magic[5] == 'T' && magic[6] == '3' && magic[7] == 0;
}

static int parse_u64(const char *text, uint64_t *value) {
    char *end = NULL;
    unsigned long long parsed;
    errno = 0;
    parsed = _strtoui64(text, &end, 0);
    if (errno != 0 || end == text || *end != 0) return 0;
    *value = (uint64_t)parsed;
    return 1;
}

static int preferred_image_range(const BYTE *dll, uint32_t dll_size,
                                 LPVOID *preferred, SIZE_T *image_size,
                                 int *can_relocate) {
    const IMAGE_DOS_HEADER *dos;
    uint64_t nt_offset;
    if (!checked_range(0, sizeof(*dos), dll_size)) return 0;
    dos = (const IMAGE_DOS_HEADER *)dll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    nt_offset = (uint32_t)dos->e_lfanew;
    *can_relocate = 0;
#if defined(_M_IX86)
    {
    const IMAGE_NT_HEADERS32 *nt;
    if (!checked_range(nt_offset, sizeof(*nt), dll_size)) return 0;
    nt = (const IMAGE_NT_HEADERS32 *)(dll + nt_offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return 0;
    *preferred = (LPVOID)(uintptr_t)nt->OptionalHeader.ImageBase;
    *image_size = nt->OptionalHeader.SizeOfImage;
    if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC &&
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 &&
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0)
        *can_relocate = 1;
    }
#else
    {
    const IMAGE_NT_HEADERS64 *nt;
    if (!checked_range(nt_offset, sizeof(*nt), dll_size)) return 0;
    nt = (const IMAGE_NT_HEADERS64 *)(dll + nt_offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;
    *preferred = (LPVOID)(uintptr_t)nt->OptionalHeader.ImageBase;
    *image_size = nt->OptionalHeader.SizeOfImage;
    if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC &&
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 &&
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0)
        *can_relocate = 1;
    }
#endif
    return *image_size != 0;
}

static void print_proof(const uint8_t proof[16]) {
    unsigned int index;
    for (index = 0; index < 16; ++index) printf("%02x", proof[index]);
}

static LPVOID WINAPI swap_process_image_base(LPVOID new_base) {
#if defined(_M_X64)
    BYTE *peb = (BYTE *)(uintptr_t)__readgsqword(0x60);
    LPVOID *image_base = (LPVOID *)(peb + 0x10);
    LPVOID old_base = *image_base;
    *image_base = new_base;
    return old_base;
#elif defined(_M_IX86)
    BYTE *peb = (BYTE *)(uintptr_t)__readfsdword(0x30);
    LPVOID *image_base = (LPVOID *)(peb + 0x08);
    LPVOID old_base = *image_base;
    *image_base = new_base;
    return old_base;
#else
    (void)new_base;
    return NULL;
#endif
}

int main(int argc, char **argv) {
    const char *path;
    struct _stat64 status;
    FILE *file = NULL;
    BYTE *file_data = NULL;
    BYTE *bundle = NULL;
    BYTE *workspace = NULL;
    BYTE expected_hash[SHA256_SIZE];
    BYTE actual_hash[SHA256_SIZE];
    pbf_native_footer footer;
    pbf_native_footer header;
    pbf_native_module_record primary_record;
    pbf_native_context context;
    pbf_native_entry_fn entry;
    LPVOID preferred = NULL;
    SIZE_T preferred_size = 0;
    LPVOID preferred_blocker = NULL;
    DWORD old_protection;
    int32_t jump_displacement;
    uint64_t call_result = 0;
    int primary_is_exe = 0;
    int can_relocate = 0;
    int exit_code = 1;

    if (argc < 2 || argc > 4 || strcmp(argv[1], "--help") == 0) {
        puts("native-bin-runner 0.3.0\n"
             "Usage: native-bin-runner <native-bundle.bin> [input-a] [input-b]");
        return argc == 2 ? 0 : 2;
    }
    path = argv[1];
    if (_stat64(path, &status) != 0 ||
        status.st_size < (long long)(PBF_NATIVE_HEADER_OFFSET +
            sizeof(header) + sizeof(footer)) ||
        status.st_size > PBF_NATIVE_MAX_BUNDLE) {
        fputs("[-] Native BIN is missing, truncated, or too large.\n", stderr);
        return 3;
    }
    file_data = (BYTE *)malloc((size_t)status.st_size);
    file = fopen(path, "rb");
    if (file_data == NULL || file == NULL ||
        fread(file_data, 1, (size_t)status.st_size, file) != (size_t)status.st_size) {
        fputs("[-] Unable to read native BIN.\n", stderr);
        goto cleanup;
    }
    fclose(file);
    file = NULL;
    if (!read_expected_hash(path, expected_hash) ||
        !hash_bytes(file_data, (DWORD)status.st_size, actual_hash) ||
        memcmp(expected_hash, actual_hash, SHA256_SIZE) != 0) {
        fputs("[-] SHA-256 verification failed; native BIN was not executed.\n", stderr);
        exit_code = 4;
        goto cleanup;
    }
    memcpy(&footer, file_data + status.st_size - sizeof(footer), sizeof(footer));
    memcpy(&header, file_data + PBF_NATIVE_HEADER_OFFSET, sizeof(header));
    if (!valid_magic(footer.magic) || footer.version != PBF_NATIVE_ABI_VERSION ||
        footer.architecture != PBF_NATIVE_ARCH_CURRENT || footer.total_size != status.st_size ||
        memcmp(&header, &footer, sizeof(header)) != 0 ||
        footer.code_size < PBF_NATIVE_HEADER_OFFSET + sizeof(header) ||
        footer.entry_offset >= footer.code_size ||
        footer.standalone_entry_offset >= footer.code_size ||
        footer.module_table_offset < footer.code_size ||
        footer.dll_offset < footer.code_size ||
        footer.module_count == 0 ||
        footer.module_count > PBF_NATIVE_MAX_EMBEDDED_MODULES ||
        footer.primary_module_index >= footer.module_count ||
        !checked_range(footer.module_table_offset,
            (uint64_t)footer.module_count * sizeof(pbf_native_module_record),
            footer.total_size - sizeof(footer)) ||
        !checked_range(footer.dll_offset, footer.dll_size, footer.total_size - sizeof(footer)) ||
#if defined(_M_IX86)
        file_data[0] != 0xe8 || file_data[1] != 0 || file_data[2] != 0 ||
        file_data[3] != 0 || file_data[4] != 0 || file_data[5] != 0x59 ||
        file_data[6] != 0x83 || file_data[7] != 0xe9 ||
        file_data[8] != 0x05 || file_data[9] != 0xe9) {
#else
        file_data[0] != 0x48 || file_data[1] != 0x8d || file_data[2] != 0x0d ||
        file_data[3] != 0xf9 || file_data[4] != 0xff || file_data[5] != 0xff ||
        file_data[6] != 0xff || file_data[7] != 0xe9) {
#endif
        fputs("[-] Native BIN footer or layout is invalid.\n", stderr);
        exit_code = 5;
        goto cleanup;
    }
    memcpy(&primary_record, file_data + footer.module_table_offset +
        footer.primary_module_index * sizeof(primary_record), sizeof(primary_record));
    if ((primary_record.flags & PBF_NATIVE_MODULE_PRIMARY) == 0 ||
        primary_record.offset != footer.dll_offset ||
        primary_record.size != footer.dll_size) {
        fputs("[-] Native primary-module record is invalid.\n", stderr);
        exit_code = 5;
        goto cleanup;
    }
    primary_is_exe = (primary_record.flags & PBF_NATIVE_MODULE_EXE) != 0;
    if (primary_is_exe && argc != 2) {
        fputs("[-] Native EXE bundles do not accept numeric payload inputs.\n", stderr);
        exit_code = 2;
        goto cleanup;
    }
#if defined(_M_IX86)
    memcpy(&jump_displacement, file_data + 10, sizeof(jump_displacement));
#else
    memcpy(&jump_displacement, file_data + 8, sizeof(jump_displacement));
#endif
    if ((uint32_t)(PBF_NATIVE_BOOTSTRAP_SIZE + jump_displacement) !=
        footer.standalone_entry_offset) {
        fputs("[-] First-byte standalone jump does not match the footer.\n", stderr);
        exit_code = 5;
        goto cleanup;
    }
    if (!preferred_image_range(file_data + footer.dll_offset, footer.dll_size,
                               &preferred, &preferred_size, &can_relocate)) {
        fputs("[-] Embedded DLL header is invalid.\n", stderr);
        exit_code = 5;
        goto cleanup;
    }
    if (can_relocate)
        preferred_blocker = VirtualAlloc(preferred, preferred_size, MEM_RESERVE, PAGE_NOACCESS);
    bundle = (BYTE *)VirtualAlloc(NULL, (SIZE_T)status.st_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (bundle == NULL) {
        fputs("[-] Unable to allocate bundle memory.\n", stderr);
        goto cleanup;
    }
    workspace = (BYTE *)VirtualAlloc(NULL, PBF_NATIVE_PIC_WORKSPACE_SIZE,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (workspace == NULL) {
        fputs("[-] Unable to allocate PIC workspace.\n", stderr);
        goto cleanup;
    }
    memcpy(bundle, file_data, (size_t)status.st_size);
    SecureZeroMemory(file_data, (SIZE_T)status.st_size);
    free(file_data);
    file_data = NULL;
    if (!VirtualProtect(bundle, footer.dll_offset, PAGE_EXECUTE_READ, &old_protection) ||
        !VirtualProtect(bundle + footer.dll_offset,
            (SIZE_T)status.st_size - footer.dll_offset, PAGE_READONLY, &old_protection) ||
        !FlushInstructionCache(GetCurrentProcess(), bundle, footer.dll_offset)) {
        fputs("[-] Unable to apply bundle memory protections.\n", stderr);
        goto cleanup;
    }

    memset(&context, 0, sizeof(context));
    context.size = sizeof(context);
    context.abi_version = PBF_NATIVE_ABI_VERSION;
    context.bundle_base = bundle;
    context.bundle_size = (uint32_t)status.st_size;
    context.dll_offset = footer.dll_offset;
    context.dll_size = footer.dll_size;
    context.module_table_offset = footer.module_table_offset;
    context.module_count = footer.module_count;
    context.primary_module_index = footer.primary_module_index;
    context.workspace = workspace;
    context.workspace_size = PBF_NATIVE_PIC_WORKSPACE_SIZE;
    context.payload.size = sizeof(context.payload);
    context.payload.abi_version = PBF_ABI_VERSION;
    context.payload.input_a = 40;
    context.payload.input_b = 2;
    if (argc >= 3 && !parse_u64(argv[2], &context.payload.input_a)) {
        exit_code = 2;
        goto cleanup;
    }
    if (argc >= 4 && !parse_u64(argv[3], &context.payload.input_b)) {
        exit_code = 2;
        goto cleanup;
    }
    context.api.virtual_alloc = VirtualAlloc;
    context.api.virtual_free = VirtualFree;
    context.api.virtual_protect = VirtualProtect;
    context.api.load_library_a = LoadLibraryA;
    context.api.free_library = FreeLibrary;
    context.api.get_proc_address = GetProcAddress;
    context.api.flush_instruction_cache = FlushInstructionCache;
    context.api.get_current_process = GetCurrentProcess;
#if defined(_M_X64)
    context.api.rtl_add_function_table = RtlAddFunctionTable;
    context.api.rtl_delete_function_table = RtlDeleteFunctionTable;
#endif
    context.api.swap_process_image_base = swap_process_image_base;

    entry = (pbf_native_entry_fn)(void *)(bundle + footer.entry_offset);
    if (primary_is_exe) {
        printf("[+] SHA-256 and native EXE manifest verified.\n");
        printf("[+] Starting mapped EXE entry point with %u embedded PE image(s).\n",
            footer.module_count);
        fflush(stdout);
    }
    __try {
        call_result = entry(&context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[-] Native PIC raised exception 0x%08lx.\n", GetExceptionCode());
        exit_code = 6;
        goto cleanup;
    }
    if (call_result != PBF_RESULT_OK || context.status != PBF_NATIVE_STATUS_OK) {
        fprintf(stderr, "[-] Native PIC failed: status=%u result=0x%016" PRIx64 "\n",
            context.status, call_result);
        exit_code = 7;
        goto cleanup;
    }
    printf("[+] SHA-256 and native footer verified.\n");
    printf("[+] Native context entry executed; %u embedded PE image(s) mapped and cleaned up.\n",
        footer.module_count);
    if (primary_is_exe) {
        puts("[+] Native EXE entry point returned without calling ExitProcess.");
        exit_code = 0;
        goto cleanup;
    }
    printf("[+] Relocated=%s Result=0x%016" PRIx64 "\n",
        context.mapped_at_preferred_base ? "no" : "yes", context.payload.result);
    printf("[+] Proof: ");
    print_proof(context.payload.proof);
    putchar('\n');
    exit_code = 0;

cleanup:
    if (preferred_blocker != NULL) VirtualFree(preferred_blocker, 0, MEM_RELEASE);
    if (workspace != NULL) VirtualFree(workspace, 0, MEM_RELEASE);
    if (bundle != NULL) VirtualFree(bundle, 0, MEM_RELEASE);
    if (file != NULL) fclose(file);
    if (file_data != NULL) {
        SecureZeroMemory(file_data, (SIZE_T)status.st_size);
        free(file_data);
    }
    return exit_code;
}
