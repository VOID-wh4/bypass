/* Local first-byte runner for PeBinForge managed raw BIN bundles. */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "pbf_managed.h"
#include "pbf_clr_host.h"

#define SHA256_SIZE 32U

static int checked_range(uint64_t offset, uint64_t length, uint64_t total) {
    return offset <= total && length <= total - offset;
}

static int hex_value(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int read_expected_hash(const char *path, BYTE digest[SHA256_SIZE]) {
    char sidecar[MAX_PATH];
    char text[64];
    FILE *file;
    size_t length = strlen(path);
    unsigned int index;
    if (length + 8 >= sizeof(sidecar)) return 0;
    memcpy(sidecar, path, length + 1);
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
        digest[index] = (BYTE)((high << 4) | low);
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

static int valid_magic(const uint8_t magic[PBF_MANAGED_MAGIC_SIZE]) {
    return magic[0] == 'P' && magic[1] == 'B' && magic[2] == 'F' && magic[3] == 'N' &&
        magic[4] == 'E' && magic[5] == 'T' && magic[6] == '2' && magic[7] == 0;
}

static int valid_bootstrap(const BYTE *data, const pbf_managed_footer *footer) {
    int32_t displacement;
#if defined(_M_IX86)
    if (data[0] != 0xe8 || data[5] != 0x59 || data[6] != 0x83 ||
        data[7] != 0xe9 || data[8] != 0x05 || data[9] != 0xe9 ||
        *(const int32_t *)(data + 1) != 0) return 0;
    memcpy(&displacement, data + 10, sizeof(displacement));
    return (uint32_t)(PBF_MANAGED_BOOTSTRAP_SIZE_X86 + displacement) ==
        footer->standalone_entry_offset;
#else
    if (data[0] != 0x48 || data[1] != 0x8d || data[2] != 0x0d ||
        data[7] != 0xe9) return 0;
    memcpy(&displacement, data + 3, sizeof(displacement));
    if (displacement != -7) return 0;
    memcpy(&displacement, data + 8, sizeof(displacement));
    return (uint32_t)(PBF_MANAGED_BOOTSTRAP_SIZE_X64 + displacement) ==
        footer->standalone_entry_offset;
#endif
}

int main(int argc, char **argv) {
    const char *path;
    struct _stat64 status;
    FILE *file = NULL;
    BYTE *file_data = NULL;
    BYTE *bundle = NULL;
    BYTE expected_hash[SHA256_SIZE];
    BYTE actual_hash[SHA256_SIZE];
    pbf_managed_footer header;
    pbf_managed_footer footer;
    pbf_managed_context context;
    pbf_managed_entry_fn entry;
    DWORD old_protection;
    uint64_t call_result = 0;
    int exit_code = 1;

    if (argc != 2 || strcmp(argv[1], "--help") == 0) {
        puts("managed-bin-runner 0.3.0\nUsage: managed-bin-runner <managed-bundle.bin>");
        return argc == 2 ? 0 : 2;
    }
    path = argv[1];
    if (_stat64(path, &status) != 0 || status.st_size <= (long long)sizeof(footer) ||
        status.st_size > PBF_MANAGED_MAX_BUNDLE) {
        fputs("[-] Managed BIN is missing, truncated, or too large.\n", stderr);
        return 3;
    }
    file_data = (BYTE *)malloc((size_t)status.st_size);
    file = fopen(path, "rb");
    if (file_data == NULL || file == NULL ||
        fread(file_data, 1, (size_t)status.st_size, file) != (size_t)status.st_size) goto cleanup;
    fclose(file);
    file = NULL;
    if (!read_expected_hash(path, expected_hash) ||
        !hash_bytes(file_data, (DWORD)status.st_size, actual_hash) ||
        memcmp(expected_hash, actual_hash, SHA256_SIZE) != 0) {
        fputs("[-] SHA-256 verification failed; managed BIN was not executed.\n", stderr);
        exit_code = 4;
        goto cleanup;
    }
    memcpy(&footer, file_data + status.st_size - sizeof(footer), sizeof(footer));
    if (status.st_size < PBF_MANAGED_HEADER_OFFSET + sizeof(header) + sizeof(footer)) {
        fputs("[-] Managed BIN header is truncated.\n", stderr);
        exit_code = 5;
        goto cleanup;
    }
    memcpy(&header, file_data + PBF_MANAGED_HEADER_OFFSET, sizeof(header));
    if (!valid_magic(footer.magic) || footer.version != PBF_MANAGED_ABI_VERSION ||
        footer.architecture != PBF_MANAGED_ARCH_CURRENT ||
        footer.total_size != status.st_size || footer.code_size == 0 ||
        footer.code_size < PBF_MANAGED_HEADER_OFFSET + sizeof(footer) ||
        footer.entry_offset >= footer.code_size ||
        footer.standalone_entry_offset >= footer.code_size ||
        footer.assembly_offset < footer.code_size ||
        !checked_range(footer.assembly_offset, footer.assembly_size,
            footer.total_size - sizeof(footer)) ||
        memcmp(&header, &footer, sizeof(footer)) != 0 ||
        !valid_bootstrap(file_data, &footer)) {
        fputs("[-] Managed BIN footer or layout is invalid.\n", stderr);
        exit_code = 5;
        goto cleanup;
    }
    bundle = (BYTE *)VirtualAlloc(NULL, (SIZE_T)status.st_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (bundle == NULL) goto cleanup;
    memcpy(bundle, file_data, (size_t)status.st_size);
    SecureZeroMemory(file_data, (SIZE_T)status.st_size);
    free(file_data);
    file_data = NULL;
    if (!VirtualProtect(bundle, footer.assembly_offset, PAGE_EXECUTE_READ, &old_protection) ||
        !VirtualProtect(bundle + footer.assembly_offset,
            (SIZE_T)status.st_size - footer.assembly_offset, PAGE_READONLY, &old_protection) ||
        !FlushInstructionCache(GetCurrentProcess(), bundle, footer.assembly_offset)) {
        fputs("[-] Unable to apply managed bundle memory protections.\n", stderr);
        exit_code = 5;
        goto cleanup;
    }
    memset(&context, 0, sizeof(context));
    context.size = sizeof(context);
    context.abi_version = PBF_MANAGED_ABI_VERSION;
    context.bundle_base = bundle;
    context.bundle_size = (uint32_t)status.st_size;
    context.assembly_offset = footer.assembly_offset;
    context.assembly_size = footer.assembly_size;
    context.execute_managed = pbf_clr_execute_parameterless;
    entry = (pbf_managed_entry_fn)(void *)(bundle + footer.entry_offset);
    __try {
        call_result = entry(&context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[-] Managed PIC raised exception 0x%08lx.\n", GetExceptionCode());
        exit_code = 6;
        goto cleanup;
    }
    if (call_result != PBF_RESULT_OK || FAILED((HRESULT)context.status)) {
        fprintf(stderr, "[-] Managed PIC failed: HRESULT=0x%08x\n", context.status);
        exit_code = 7;
        goto cleanup;
    }
    printf("[+] SHA-256 and managed footer verified.\n");
    printf("[+] Managed context entry verified; %s CLR v4 loaded embedded assembly bytes.\n",
        footer.architecture == PBF_MANAGED_ARCH_X86 ? "x86" : "x64");
    printf("[+] Parameterless Main returned: %ld\n", context.managed_result);
    exit_code = context.managed_result >= 1000 ? 0 : 8;

cleanup:
    if (bundle != NULL) VirtualFree(bundle, 0, MEM_RELEASE);
    if (file != NULL) fclose(file);
    if (file_data != NULL) {
        SecureZeroMemory(file_data, (SIZE_T)status.st_size);
        free(file_data);
    }
    return exit_code;
}
