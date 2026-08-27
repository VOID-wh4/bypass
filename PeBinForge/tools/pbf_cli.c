/* Unified local CLI and ECDSA P-256 package signing for PeBinForge. */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "pbf_native.h"
#include "pbf_managed.h"

#pragma comment(lib, "bcrypt.lib")

#define PBF_SIGNATURE_VERSION 1U
#define PBF_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 1U
#define PBF_SHA256_SIZE 32U
#define PBF_ECDSA_P256_SIGNATURE_SIZE 64U
#define PBF_MAX_KEY_BLOB (64U * 1024U)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#pragma pack(push, 1)
typedef struct pbf_signature_t {
    uint8_t magic[8];
    uint32_t version;
    uint32_t algorithm;
    uint64_t signed_size;
    uint8_t public_key_sha256[PBF_SHA256_SIZE];
    uint8_t file_sha256[PBF_SHA256_SIZE];
    uint8_t signature[PBF_ECDSA_P256_SIGNATURE_SIZE];
} pbf_signature;
#pragma pack(pop)

typedef enum pbf_input_kind_t {
    PBF_KIND_UNKNOWN = 0,
    PBF_KIND_RAW,
    PBF_KIND_NATIVE_BUNDLE,
    PBF_KIND_NATIVE_EXE_BUNDLE,
    PBF_KIND_MANAGED_BUNDLE
} pbf_input_kind;

typedef struct pbf_pe_kind_t {
    int valid;
    int managed;
    int dll;
    WORD machine;
} pbf_pe_kind;

static void usage(void) {
    puts("PeBinForge unified CLI 0.3.0\n"
         "Usage:\n"
         "  pbf inspect <input>\n"
         "  pbf pack <input.exe|input.dll|input.obj> <output.bin> [--force]\n"
         "  pbf run <bundle.bin> [input-a] [input-b] [--entry context|noargs]\n"
         "          [--inject-pid <pid>] [--pubkey <key.pbfpub>]\n"
         "  pbf keygen <key-prefix> [--force]\n"
         "  pbf sign <key.pbfpriv> <bundle.bin>\n"
         "  pbf verify <key.pbfpub> <bundle.bin>\n\n"
         "Native PE packing supports x86/x64 EXEs and DLLs. Managed packing supports .NET Framework 4\n"
         "assemblies with a parameterless static Main entry point.");
}

static int file_exists(const char *path) {
    struct _stat64 status;
    return _stat64(path, &status) == 0;
}

static int make_suffix_path(const char *base, const char *suffix,
                            char output[MAX_PATH]) {
    size_t base_length = strlen(base);
    size_t suffix_length = strlen(suffix);
    if (base_length + suffix_length + 1 > MAX_PATH) return 0;
    memcpy(output, base, base_length);
    memcpy(output + base_length, suffix, suffix_length + 1);
    return 1;
}

static int sibling_path(const char *name, char output[MAX_PATH]) {
    DWORD length = GetModuleFileNameA(NULL, output, MAX_PATH);
    char *slash;
    size_t directory_length;
    size_t name_length = strlen(name);
    if (length == 0 || length >= MAX_PATH) return 0;
    slash = strrchr(output, '\\');
    if (slash == NULL) slash = strrchr(output, '/');
    if (slash == NULL) return 0;
    directory_length = (size_t)(slash - output + 1);
    if (directory_length + name_length + 1 > MAX_PATH) return 0;
    memcpy(output + directory_length, name, name_length + 1);
    return 1;
}

static int append_quoted(char *command, size_t capacity, const char *argument) {
    size_t used = strlen(command);
    size_t length = strlen(argument);
    if (strchr(argument, '"') != NULL || used + length + 4 > capacity) return 0;
    command[used++] = ' ';
    command[used++] = '"';
    memcpy(command + used, argument, length);
    used += length;
    command[used++] = '"';
    command[used] = 0;
    return 1;
}

static int run_sibling(const char *program, int argument_count,
                       const char *const *arguments) {
    char path[MAX_PATH];
    char command[32768];
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    DWORD exit_code = 1;
    int index;
    if (!sibling_path(program, path)) return 3;
    if (strlen(path) + 3 > sizeof(command)) return 3;
    command[0] = '"';
    strcpy(command + 1, path);
    strcat(command, "\"");
    for (index = 0; index < argument_count; ++index) {
        if (!append_quoted(command, sizeof(command), arguments[index])) {
            fputs("[-] Command argument is too long or contains a quote.\n", stderr);
            return 2;
        }
    }
    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    startup.cb = sizeof(startup);
    fflush(stdout);
    fflush(stderr);
    if (!CreateProcessA(path, command, NULL, NULL, FALSE, 0, NULL, NULL,
                        &startup, &process)) {
        fprintf(stderr, "[-] Unable to start %s (error %lu).\n", program, GetLastError());
        return 3;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    if (!GetExitCodeProcess(process.hProcess, &exit_code)) exit_code = 1;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return (int)exit_code;
}

static int read_blob(const char *path, BYTE **data, DWORD *size) {
    struct _stat64 status;
    FILE *file = NULL;
    *data = NULL;
    *size = 0;
    if (_stat64(path, &status) != 0 || status.st_size <= 0 ||
        status.st_size > PBF_MAX_KEY_BLOB) return 0;
    *size = (DWORD)status.st_size;
    *data = (BYTE *)malloc(*size);
    file = fopen(path, "rb");
    if (*data == NULL || file == NULL || fread(*data, 1, *size, file) != *size) {
        if (file != NULL) fclose(file);
        free(*data);
        *data = NULL;
        *size = 0;
        return 0;
    }
    fclose(file);
    return 1;
}

static int write_blob(const char *path, const BYTE *data, DWORD size, int force) {
    FILE *file;
    if (!force && file_exists(path)) return 0;
    file = fopen(path, "wb");
    if (file == NULL) return 0;
    if (fwrite(data, 1, size, file) != size || fclose(file) != 0) return 0;
    return 1;
}

static int sha256_bytes(const BYTE *data, DWORD size,
                        BYTE digest[PBF_SHA256_SIZE]) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE *object = NULL;
    DWORD object_size = 0;
    DWORD result_size = 0;
    int result = 0;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm,
            BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto cleanup;
    if (!NT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&object_size, sizeof(object_size), &result_size, 0))) goto cleanup;
    object = (BYTE *)malloc(object_size);
    if (object == NULL) goto cleanup;
    if (!NT_SUCCESS(BCryptCreateHash(algorithm, &hash, object, object_size,
                                     NULL, 0, 0))) goto cleanup;
    if (size != 0 && !NT_SUCCESS(BCryptHashData(hash, (PUCHAR)data, size, 0))) goto cleanup;
    if (!NT_SUCCESS(BCryptFinishHash(hash, digest, PBF_SHA256_SIZE, 0))) goto cleanup;
    result = 1;
cleanup:
    if (hash != NULL) BCryptDestroyHash(hash);
    if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
    free(object);
    return result;
}

static int sha256_file(const char *path, BYTE digest[PBF_SHA256_SIZE],
                       uint64_t *file_size) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE *object = NULL;
    BYTE buffer[64U * 1024U];
    DWORD object_size = 0;
    DWORD result_size = 0;
    FILE *file = NULL;
    size_t read_size;
    uint64_t total = 0;
    int result = 0;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm,
            BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto cleanup;
    if (!NT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&object_size, sizeof(object_size), &result_size, 0))) goto cleanup;
    object = (BYTE *)malloc(object_size);
    file = fopen(path, "rb");
    if (object == NULL || file == NULL) goto cleanup;
    if (!NT_SUCCESS(BCryptCreateHash(algorithm, &hash, object, object_size,
                                     NULL, 0, 0))) goto cleanup;
    while ((read_size = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        if (!NT_SUCCESS(BCryptHashData(hash, buffer, (ULONG)read_size, 0))) goto cleanup;
        total += read_size;
    }
    if (ferror(file) || !NT_SUCCESS(BCryptFinishHash(hash, digest,
            PBF_SHA256_SIZE, 0))) goto cleanup;
    *file_size = total;
    result = 1;
cleanup:
    SecureZeroMemory(buffer, sizeof(buffer));
    if (file != NULL) fclose(file);
    if (hash != NULL) BCryptDestroyHash(hash);
    if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
    free(object);
    return result;
}

static int hex_value(int character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

static int verify_sha256_sidecar(const char *path) {
    char sidecar[MAX_PATH];
    char text[PBF_SHA256_SIZE * 2U];
    BYTE expected[PBF_SHA256_SIZE];
    BYTE actual[PBF_SHA256_SIZE];
    uint64_t file_size = 0;
    FILE *file = NULL;
    uint32_t index;
    int ok = 0;
    if (!make_suffix_path(path, ".sha256", sidecar)) return 0;
    file = fopen(sidecar, "rb");
    if (file == NULL || fread(text, 1, sizeof(text), file) != sizeof(text)) goto cleanup;
    for (index = 0; index < PBF_SHA256_SIZE; ++index) {
        int high = hex_value((unsigned char)text[index * 2U]);
        int low = hex_value((unsigned char)text[index * 2U + 1U]);
        if (high < 0 || low < 0) goto cleanup;
        expected[index] = (BYTE)((high << 4) | low);
    }
    if (!sha256_file(path, actual, &file_size) ||
        memcmp(expected, actual, sizeof(actual)) != 0) goto cleanup;
    ok = 1;
cleanup:
    if (file != NULL) fclose(file);
    SecureZeroMemory(expected, sizeof(expected));
    SecureZeroMemory(actual, sizeof(actual));
    return ok;
}

static void print_hex(const BYTE *data, DWORD size) {
    DWORD index;
    for (index = 0; index < size; ++index) printf("%02x", data[index]);
}

static int export_key(BCRYPT_KEY_HANDLE key, LPCWSTR blob_type,
                      BYTE **blob, DWORD *blob_size) {
    *blob = NULL;
    *blob_size = 0;
    if (!NT_SUCCESS(BCryptExportKey(key, NULL, blob_type, NULL, 0,
                                    blob_size, 0))) return 0;
    *blob = (BYTE *)malloc(*blob_size);
    if (*blob == NULL) return 0;
    if (!NT_SUCCESS(BCryptExportKey(key, NULL, blob_type, *blob, *blob_size,
                                    blob_size, 0))) {
        free(*blob);
        *blob = NULL;
        *blob_size = 0;
        return 0;
    }
    return 1;
}

static int keygen(const char *prefix, int force) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    BYTE *private_blob = NULL;
    BYTE *public_blob = NULL;
    DWORD private_size = 0;
    DWORD public_size = 0;
    BYTE fingerprint[PBF_SHA256_SIZE];
    char private_path[MAX_PATH];
    char public_path[MAX_PATH];
    int result = 5;
    if (!make_suffix_path(prefix, ".pbfpriv", private_path) ||
        !make_suffix_path(prefix, ".pbfpub", public_path)) return 2;
    if (!force && (file_exists(private_path) || file_exists(public_path))) {
        fputs("[-] Key output already exists; use --force to replace it.\n", stderr);
        return 3;
    }
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm,
            BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0)) ||
        !NT_SUCCESS(BCryptGenerateKeyPair(algorithm, &key, 256, 0)) ||
        !NT_SUCCESS(BCryptFinalizeKeyPair(key, 0)) ||
        !export_key(key, BCRYPT_ECCPRIVATE_BLOB, &private_blob, &private_size) ||
        !export_key(key, BCRYPT_ECCPUBLIC_BLOB, &public_blob, &public_size) ||
        !sha256_bytes(public_blob, public_size, fingerprint)) goto cleanup;
    if (!write_blob(private_path, private_blob, private_size, force) ||
        !write_blob(public_path, public_blob, public_size, force)) {
        fputs("[-] Unable to write key files.\n", stderr);
        result = 3;
        goto cleanup;
    }
    printf("[+] ECDSA P-256 private key: %s\n", private_path);
    printf("[+] ECDSA P-256 public key:  %s\n", public_path);
    printf("[+] Public-key SHA-256: ");
    print_hex(fingerprint, sizeof(fingerprint));
    putchar('\n');
    result = 0;
cleanup:
    if (private_blob != NULL) {
        SecureZeroMemory(private_blob, private_size);
        free(private_blob);
    }
    free(public_blob);
    if (key != NULL) BCryptDestroyKey(key);
    if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
    return result;
}

static void set_signature_magic(uint8_t magic[8]) {
    magic[0] = 'P'; magic[1] = 'B'; magic[2] = 'F'; magic[3] = 'S';
    magic[4] = 'I'; magic[5] = 'G'; magic[6] = '1'; magic[7] = 0;
}

static int valid_signature_magic(const uint8_t magic[8]) {
    return magic[0] == 'P' && magic[1] == 'B' && magic[2] == 'F' && magic[3] == 'S' &&
        magic[4] == 'I' && magic[5] == 'G' && magic[6] == '1' && magic[7] == 0;
}

static int sign_file(const char *private_path, const char *input_path) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    BYTE *private_blob = NULL;
    BYTE *public_blob = NULL;
    DWORD private_size = 0;
    DWORD public_size = 0;
    DWORD signature_size = 0;
    pbf_signature signature;
    char signature_path[MAX_PATH];
    int result = 5;
    memset(&signature, 0, sizeof(signature));
    if (!make_suffix_path(input_path, ".sig", signature_path)) return 2;
    if (!read_blob(private_path, &private_blob, &private_size)) {
        fputs("[-] Unable to read private key.\n", stderr);
        return 3;
    }
    if (!sha256_file(input_path, signature.file_sha256, &signature.signed_size)) {
        fputs("[-] Unable to hash input file.\n", stderr);
        result = 3;
        goto cleanup;
    }
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm,
            BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0)) ||
        !NT_SUCCESS(BCryptImportKeyPair(algorithm, NULL, BCRYPT_ECCPRIVATE_BLOB,
            &key, private_blob, private_size, 0)) ||
        !export_key(key, BCRYPT_ECCPUBLIC_BLOB, &public_blob, &public_size) ||
        !sha256_bytes(public_blob, public_size, signature.public_key_sha256)) goto cleanup;
    if (!NT_SUCCESS(BCryptSignHash(key, NULL, signature.file_sha256,
            PBF_SHA256_SIZE, signature.signature, sizeof(signature.signature),
            &signature_size, 0)) || signature_size != sizeof(signature.signature)) goto cleanup;
    set_signature_magic(signature.magic);
    signature.version = PBF_SIGNATURE_VERSION;
    signature.algorithm = PBF_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256;
    if (!write_blob(signature_path, (const BYTE *)&signature,
                    sizeof(signature), 1)) {
        fputs("[-] Unable to write signature sidecar.\n", stderr);
        result = 3;
        goto cleanup;
    }
    printf("[+] Signed %llu bytes with ECDSA P-256.\n",
        (unsigned long long)signature.signed_size);
    printf("[+] Signature: %s\n[+] Public-key SHA-256: ", signature_path);
    print_hex(signature.public_key_sha256, sizeof(signature.public_key_sha256));
    putchar('\n');
    result = 0;
cleanup:
    SecureZeroMemory(&signature, sizeof(signature));
    if (private_blob != NULL) {
        SecureZeroMemory(private_blob, private_size);
        free(private_blob);
    }
    free(public_blob);
    if (key != NULL) BCryptDestroyKey(key);
    if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
    return result;
}

static int verify_file(const char *public_path, const char *input_path, int quiet) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    BYTE *public_blob = NULL;
    BYTE *signature_blob = NULL;
    DWORD public_size = 0;
    DWORD signature_size = 0;
    BYTE file_hash[PBF_SHA256_SIZE];
    BYTE fingerprint[PBF_SHA256_SIZE];
    uint64_t file_size = 0;
    pbf_signature *signature;
    char signature_path[MAX_PATH];
    int result = 6;
    if (!make_suffix_path(input_path, ".sig", signature_path)) return 2;
    if (!read_blob(public_path, &public_blob, &public_size) ||
        !read_blob(signature_path, &signature_blob, &signature_size)) {
        if (!quiet) fputs("[-] Public key or signature sidecar is missing.\n", stderr);
        result = 3;
        goto cleanup;
    }
    if (signature_size != sizeof(pbf_signature)) goto invalid;
    signature = (pbf_signature *)signature_blob;
    if (!valid_signature_magic(signature->magic) ||
        signature->version != PBF_SIGNATURE_VERSION ||
        signature->algorithm != PBF_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256) goto invalid;
    if (!sha256_file(input_path, file_hash, &file_size) ||
        !sha256_bytes(public_blob, public_size, fingerprint)) {
        result = 3;
        goto cleanup;
    }
    if (file_size != signature->signed_size ||
        memcmp(file_hash, signature->file_sha256, sizeof(file_hash)) != 0 ||
        memcmp(fingerprint, signature->public_key_sha256, sizeof(fingerprint)) != 0) goto invalid;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm,
            BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0)) ||
        !NT_SUCCESS(BCryptImportKeyPair(algorithm, NULL, BCRYPT_ECCPUBLIC_BLOB,
            &key, public_blob, public_size, 0))) {
        result = 5;
        goto cleanup;
    }
    if (!NT_SUCCESS(BCryptVerifySignature(key, NULL, file_hash,
            sizeof(file_hash), signature->signature,
            sizeof(signature->signature), 0))) goto invalid;
    if (!quiet) {
        printf("[+] ECDSA P-256 signature verified.\n");
        printf("[+] Signed file SHA-256: ");
        print_hex(file_hash, sizeof(file_hash));
        putchar('\n');
    }
    result = 0;
    goto cleanup;
invalid:
    if (!quiet) fputs("[-] Signature verification failed.\n", stderr);
    result = 6;
cleanup:
    SecureZeroMemory(file_hash, sizeof(file_hash));
    free(signature_blob);
    free(public_blob);
    if (key != NULL) BCryptDestroyKey(key);
    if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
    return result;
}

static pbf_input_kind detect_bundle(const char *path, uint64_t *size,
                                    WORD *bundle_machine) {
    struct _stat64 status;
    FILE *file = NULL;
    pbf_native_footer native_footer;
    pbf_native_module_record primary_record;
    pbf_managed_footer managed_footer;
    *size = 0;
    if (bundle_machine != NULL) *bundle_machine = 0;
    if (_stat64(path, &status) != 0 || status.st_size <= 0) return PBF_KIND_UNKNOWN;
    *size = (uint64_t)status.st_size;
    file = fopen(path, "rb");
    if (file == NULL) return PBF_KIND_UNKNOWN;
    if (status.st_size >= (long long)sizeof(native_footer) &&
        _fseeki64(file, status.st_size - sizeof(native_footer), SEEK_SET) == 0 &&
        fread(&native_footer, 1, sizeof(native_footer), file) == sizeof(native_footer) &&
        memcmp(native_footer.magic, "PBFNAT3", 7) == 0 &&
        native_footer.version == PBF_NATIVE_ABI_VERSION &&
        (native_footer.architecture == PBF_NATIVE_ARCH_X64 ||
         native_footer.architecture == PBF_NATIVE_ARCH_X86) &&
        native_footer.total_size == status.st_size) {
        if (bundle_machine != NULL) *bundle_machine = (WORD)native_footer.architecture;
        if (native_footer.module_count != 0 &&
            native_footer.module_count <= PBF_NATIVE_MAX_EMBEDDED_MODULES &&
            native_footer.primary_module_index < native_footer.module_count &&
            (uint64_t)native_footer.module_table_offset +
                (uint64_t)native_footer.module_count * sizeof(pbf_native_module_record) <=
                (uint64_t)status.st_size - sizeof(native_footer) &&
            _fseeki64(file, native_footer.module_table_offset +
                native_footer.primary_module_index * sizeof(primary_record), SEEK_SET) == 0 &&
            fread(&primary_record, 1, sizeof(primary_record), file) == sizeof(primary_record) &&
            (primary_record.flags & PBF_NATIVE_MODULE_EXE) != 0) {
            fclose(file);
            return PBF_KIND_NATIVE_EXE_BUNDLE;
        }
        fclose(file);
        return PBF_KIND_NATIVE_BUNDLE;
    }
    if (status.st_size >= (long long)sizeof(managed_footer) &&
        _fseeki64(file, status.st_size - sizeof(managed_footer), SEEK_SET) == 0 &&
        fread(&managed_footer, 1, sizeof(managed_footer), file) == sizeof(managed_footer) &&
        memcmp(managed_footer.magic, "PBFNET2", 7) == 0 &&
        managed_footer.version == PBF_MANAGED_ABI_VERSION &&
        (managed_footer.architecture == PBF_MANAGED_ARCH_X86 ||
         managed_footer.architecture == PBF_MANAGED_ARCH_X64) &&
        managed_footer.total_size == status.st_size) {
        if (bundle_machine != NULL) *bundle_machine = (WORD)managed_footer.architecture;
        fclose(file);
        return PBF_KIND_MANAGED_BUNDLE;
    }
    fclose(file);
    return PBF_KIND_RAW;
}

static pbf_pe_kind classify_pe(const char *path) {
    pbf_pe_kind result;
    IMAGE_DOS_HEADER dos;
    DWORD signature;
    IMAGE_FILE_HEADER file_header;
    BYTE optional[sizeof(IMAGE_OPTIONAL_HEADER64)];
    FILE *file = NULL;
    memset(&result, 0, sizeof(result));
    file = fopen(path, "rb");
    if (file == NULL || fread(&dos, 1, sizeof(dos), file) != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        _fseeki64(file, dos.e_lfanew, SEEK_SET) != 0 ||
        fread(&signature, 1, sizeof(signature), file) != sizeof(signature) ||
        signature != IMAGE_NT_SIGNATURE ||
        fread(&file_header, 1, sizeof(file_header), file) != sizeof(file_header) ||
        file_header.SizeOfOptionalHeader < sizeof(WORD) ||
        file_header.SizeOfOptionalHeader > sizeof(optional) ||
        fread(optional, 1, file_header.SizeOfOptionalHeader, file) != file_header.SizeOfOptionalHeader) goto cleanup;
    result.machine = file_header.Machine;
    result.dll = (file_header.Characteristics & IMAGE_FILE_DLL) != 0;
    if (*(const WORD *)optional == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        file_header.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64)) {
        const IMAGE_OPTIONAL_HEADER64 *header = (const IMAGE_OPTIONAL_HEADER64 *)optional;
        result.managed = header->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
            header->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0;
    } else if (*(const WORD *)optional == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        file_header.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
        const IMAGE_OPTIONAL_HEADER32 *header = (const IMAGE_OPTIONAL_HEADER32 *)optional;
        result.managed = header->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
            header->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0;
    } else goto cleanup;
    result.valid = 1;
cleanup:
    if (file != NULL) fclose(file);
    return result;
}

static int has_obj_extension(const char *path) {
    const char *dot = strrchr(path, '.');
    return dot != NULL && _stricmp(dot, ".obj") == 0;
}

static int finish_pack(int child_result, const char *output) {
    char signature_path[MAX_PATH];
    if (child_result == 0 && make_suffix_path(output, ".sig", signature_path) &&
        file_exists(signature_path) && !DeleteFileA(signature_path)) {
        fputs("[-] Package was created, but a stale signature sidecar could not be removed.\n", stderr);
        return 3;
    }
    return child_result;
}

static int command_inspect(const char *path) {
    uint64_t size;
    WORD bundle_machine = 0;
    pbf_input_kind kind = detect_bundle(path, &size, &bundle_machine);
    char signature_path[MAX_PATH];
    const char *arguments[1];
    if (kind == PBF_KIND_UNKNOWN) {
        fputs("[-] Input file is missing or empty.\n", stderr);
        return 3;
    }
    if (kind == PBF_KIND_NATIVE_BUNDLE || kind == PBF_KIND_NATIVE_EXE_BUNDLE ||
        kind == PBF_KIND_MANAGED_BUNDLE) {
        printf("Kind: %s raw bundle\n",
            kind == PBF_KIND_NATIVE_BUNDLE ?
                (bundle_machine == PBF_NATIVE_ARCH_X86 ? "native x86 DLL" : "native x64 DLL") :
            (kind == PBF_KIND_NATIVE_EXE_BUNDLE ?
                (bundle_machine == PBF_NATIVE_ARCH_X86 ? "native x86 EXE" : "native x64 EXE") :
                (bundle_machine == PBF_MANAGED_ARCH_X86 ?
                    ".NET Framework 4 x86" : ".NET Framework 4 x64")));
        printf("Size: %llu bytes\n", (unsigned long long)size);
        if (make_suffix_path(path, ".sig", signature_path))
            printf("Signature sidecar: %s\n", file_exists(signature_path) ? "present" : "absent");
        return 0;
    }
    if (classify_pe(path).valid) {
        arguments[0] = path;
        return run_sibling("peprobe.exe", 1, arguments);
    }
    printf("Kind: %s\nSize: %llu bytes\n",
        has_obj_extension(path) ? "COFF object" : "raw PIC BIN",
        (unsigned long long)size);
    return 0;
}

static int command_pack(int argc, char **argv) {
    const char *input;
    const char *output;
    int force = 0;
    pbf_pe_kind pe;
    const char *arguments[4];
    char stub[MAX_PATH];
    char x86_stub[MAX_PATH];
    int child_result;
    if (argc != 4 && argc != 5) return 2;
    input = argv[2];
    output = argv[3];
    if (argc == 5) {
        if (strcmp(argv[4], "--force") != 0) return 2;
        force = 1;
    }
    if (!force && file_exists(output)) {
        fputs("[-] Output already exists; use --force to replace it.\n", stderr);
        return 3;
    }
    pe = classify_pe(input);
    if (!pe.valid) {
        if (!has_obj_extension(input)) {
            fputs("[-] Input is neither a supported PE nor a COFF object.\n", stderr);
            return 4;
        }
        arguments[0] = input;
        arguments[1] = output;
        arguments[2] = "--force";
        child_result = run_sibling("pbfgen.exe", 3, arguments);
        return finish_pack(child_result, output);
    }
    if (pe.managed) {
        if (!sibling_path("obj\\managed_pic_stub.obj", stub) ||
            !sibling_path("x86\\obj\\managed_pic_stub.obj", x86_stub)) return 3;
        arguments[0] = stub;
        arguments[1] = x86_stub;
        arguments[2] = input;
        arguments[3] = output;
        child_result = run_sibling("managed-bin-pack.exe", 4, arguments);
        return finish_pack(child_result, output);
    }
    if (pe.machine != IMAGE_FILE_MACHINE_AMD64 && pe.machine != IMAGE_FILE_MACHINE_I386) {
        fputs("[-] Native packing requires an x86 or x64 PE image.\n", stderr);
        return 4;
    }
    if (!sibling_path(pe.machine == IMAGE_FILE_MACHINE_I386 ?
                      "x86\\obj\\native_stub.obj" : "obj\\native_stub.obj", stub)) return 3;
    arguments[0] = stub;
    arguments[1] = input;
    arguments[2] = output;
    arguments[3] = "--force";
    child_result = run_sibling("native-bin-gen.exe", 4, arguments);
    return finish_pack(child_result, output);
}

static int command_run(int argc, char **argv) {
    const char *bundle;
    const char *public_key = NULL;
    const char *entry_abi = NULL;
    const char *inject_pid = NULL;
    const char *payload_arguments[3];
    const char *runner_arguments[8];
    int payload_count = 0;
    int runner_count = 0;
    int index;
    int verify_result;
    uint64_t size;
    WORD bundle_machine = 0;
    pbf_input_kind kind;
    char signature_path[MAX_PATH];
    if (argc < 3) return 2;
    bundle = argv[2];
    for (index = 3; index < argc; ++index) {
        if (strcmp(argv[index], "--pubkey") == 0) {
            if (++index >= argc || public_key != NULL) return 2;
            public_key = argv[index];
        } else if (strcmp(argv[index], "--entry") == 0) {
            if (++index >= argc || entry_abi != NULL ||
                (strcmp(argv[index], "context") != 0 &&
                 strcmp(argv[index], "noargs") != 0)) return 2;
            entry_abi = argv[index];
        } else if (strcmp(argv[index], "--inject-pid") == 0) {
            if (++index >= argc || inject_pid != NULL) return 2;
            inject_pid = argv[index];
        } else {
            if (payload_count >= 2) return 2;
            payload_arguments[payload_count++] = argv[index];
        }
    }
    if (public_key != NULL) {
        verify_result = verify_file(public_key, bundle, 0);
        if (verify_result != 0) {
            fputs("[-] Execution blocked because package signature is not valid.\n", stderr);
            return verify_result;
        }
    } else if (make_suffix_path(bundle, ".sig", signature_path) &&
               file_exists(signature_path)) {
        fputs("[!] Signature sidecar exists but was not checked; supply --pubkey to require it.\n", stderr);
    }
    kind = detect_bundle(bundle, &size, &bundle_machine);
    if (kind == PBF_KIND_UNKNOWN) return 3;
    if (kind != PBF_KIND_RAW && (entry_abi != NULL || inject_pid != NULL)) {
        fputs("[-] --entry and --inject-pid are supported only for raw PIC BINs.\n", stderr);
        return 2;
    }
    if (entry_abi != NULL && strcmp(entry_abi, "noargs") == 0 &&
        payload_count != 0) {
        fputs("[-] The noargs entry ABI does not accept numeric payload inputs.\n", stderr);
        return 2;
    }
    runner_arguments[runner_count++] = bundle;
    for (index = 0; index < payload_count; ++index)
        runner_arguments[runner_count++] = payload_arguments[index];
    if (entry_abi != NULL) {
        runner_arguments[runner_count++] = "--entry";
        runner_arguments[runner_count++] = entry_abi;
    }
    if (inject_pid != NULL) {
        runner_arguments[runner_count++] = "--inject-pid";
        runner_arguments[runner_count++] = inject_pid;
    }
    if (kind == PBF_KIND_MANAGED_BUNDLE) {
        if (payload_count != 0) {
            fputs("[-] Managed bundle runner does not accept numeric payload inputs.\n", stderr);
            return 2;
        }
        return run_sibling(bundle_machine == PBF_MANAGED_ARCH_X86 ?
            "x86\\managed-bin-runner-x86.exe" : "managed-bin-runner.exe",
            runner_count, runner_arguments);
    }
    if (kind == PBF_KIND_NATIVE_BUNDLE || kind == PBF_KIND_NATIVE_EXE_BUNDLE) {
        if (bundle_machine == PBF_NATIVE_ARCH_X86) {
            if (payload_count != 0) {
                fputs("[-] x86 standalone bundles do not accept numeric payload inputs; use entry() defaults.\n",
                    stderr);
                return 2;
            }
            if (!verify_sha256_sidecar(bundle)) {
                fputs("[-] SHA-256 verification failed; x86 native BIN was not executed.\n",
                    stderr);
                return 4;
            }
            return run_sibling("x86\\simple-memory-loader-x86.exe", 1, runner_arguments);
        } else {
            return run_sibling("native-bin-runner.exe", runner_count, runner_arguments);
        }
    }
    return run_sibling("pbf-runner.exe", runner_count, runner_arguments);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        usage();
        return argc >= 2 ? 0 : 2;
    }
    if (strcmp(argv[1], "inspect") == 0)
        return argc == 3 ? command_inspect(argv[2]) : 2;
    if (strcmp(argv[1], "pack") == 0)
        return command_pack(argc, argv);
    if (strcmp(argv[1], "run") == 0)
        return command_run(argc, argv);
    if (strcmp(argv[1], "keygen") == 0) {
        int force = argc == 4 && strcmp(argv[3], "--force") == 0;
        return (argc == 3 || force) ? keygen(argv[2], force) : 2;
    }
    if (strcmp(argv[1], "sign") == 0)
        return argc == 4 ? sign_file(argv[2], argv[3]) : 2;
    if (strcmp(argv[1], "verify") == 0)
        return argc == 4 ? verify_file(argv[2], argv[3], 0) : 2;
    usage();
    return 2;
}
