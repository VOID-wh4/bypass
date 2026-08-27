/*
 * PeBinForge clean-room COFF-to-raw generator.
 *
 * Only a dedicated architecture-selected .pbf code section with zero relocations is accepted.
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_PAYLOAD_SIZE (1024U * 1024U)
#define SHA256_SIZE 32U

#ifndef PBFGEN_EXPECTED_MACHINE
#define PBFGEN_EXPECTED_MACHINE IMAGE_FILE_MACHINE_AMD64
#endif

static const char *machine_name(WORD machine) {
    return machine == IMAGE_FILE_MACHINE_I386 ? "I386" : "AMD64";
}

static void usage(void) {
    printf("pbfgen 0.2.0\n"
           "Usage: pbfgen <input.obj> <output.bin> [--machine x86|x64] [--force]\n\n"
           "The input must contain a dedicated .pbf code section with no relocation records.\n");
}

static int file_exists(const char *path) {
    DWORD attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static int ends_with_bin(const char *path) {
    const char *dot = strrchr(path, '.');
    return dot != NULL && _stricmp(dot, ".bin") == 0;
}

static int checked_range(uint64_t offset, uint64_t length, uint64_t total) {
    return offset <= total && length <= total - offset;
}

static int hash_bytes(const BYTE *data, DWORD length, BYTE digest[SHA256_SIZE]) {
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    DWORD digest_size = SHA256_SIZE;
    int ok = 0;

    if (!CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        goto cleanup;
    }
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) goto cleanup;
    if (!CryptHashData(hash, data, length, 0)) goto cleanup;
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_size, 0) ||
        digest_size != SHA256_SIZE) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    if (hash != 0) CryptDestroyHash(hash);
    if (provider != 0) CryptReleaseContext(provider, 0);
    return ok;
}

static int write_hash_sidecar(const char *output_path,
                              const BYTE digest[SHA256_SIZE], int force) {
    char sidecar[MAX_PATH];
    const char *name;
    FILE *file;
    size_t output_length = strlen(output_path);
    unsigned int i;

    if (output_length + 8 >= sizeof(sidecar)) {
        fputs("[-] Output path is too long for the SHA-256 sidecar.\n", stderr);
        return 0;
    }
    memcpy(sidecar, output_path, output_length + 1);
    strcat(sidecar, ".sha256");
    if (!force && file_exists(sidecar)) {
        fprintf(stderr, "[-] Sidecar already exists: %s\n", sidecar);
        return 0;
    }
    file = fopen(sidecar, "wb");
    if (file == NULL) {
        fprintf(stderr, "[-] Unable to create sidecar: %s\n", sidecar);
        return 0;
    }
    name = strrchr(output_path, '\\');
    if (name == NULL) name = strrchr(output_path, '/');
    name = name == NULL ? output_path : name + 1;
    for (i = 0; i < SHA256_SIZE; ++i) fprintf(file, "%02x", digest[i]);
    fprintf(file, "  %s\r\n", name);
    if (fclose(file) != 0) {
        fputs("[-] Failed to finalize SHA-256 sidecar.\n", stderr);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *input_path;
    const char *output_path;
    int force = 0;
    WORD expected_machine = PBFGEN_EXPECTED_MACHINE;
    struct _stat64 status;
    FILE *input = NULL;
    FILE *output = NULL;
    BYTE *object_data = NULL;
    IMAGE_FILE_HEADER *file_header;
    IMAGE_SECTION_HEADER *sections;
    IMAGE_SECTION_HEADER *payload_section = NULL;
    uint64_t section_table_offset;
    uint16_t index;
    BYTE digest[SHA256_SIZE];
    int exit_code = 1;
    int argument_index;

    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage();
        return 0;
    }
    if (argc < 3 || argc > 6) {
        usage();
        return 2;
    }
    input_path = argv[1];
    output_path = argv[2];
    for (argument_index = 3; argument_index < argc; ++argument_index) {
        if (strcmp(argv[argument_index], "--force") == 0 && !force) {
            force = 1;
        } else if (strcmp(argv[argument_index], "--machine") == 0 &&
                   argument_index + 1 < argc) {
            const char *value = argv[++argument_index];
            if (strcmp(value, "x86") == 0) expected_machine = IMAGE_FILE_MACHINE_I386;
            else if (strcmp(value, "x64") == 0) expected_machine = IMAGE_FILE_MACHINE_AMD64;
            else {
                usage();
                return 2;
            }
        } else {
            usage();
            return 2;
        }
    }

    if (!ends_with_bin(output_path)) {
        fputs("[-] Output must use the .bin extension.\n", stderr);
        return 2;
    }
    if (!force && file_exists(output_path)) {
        fprintf(stderr, "[-] Output already exists: %s\n", output_path);
        return 3;
    }
    if (_stat64(input_path, &status) != 0 || status.st_size < (long long)sizeof(IMAGE_FILE_HEADER)) {
        fprintf(stderr, "[-] Input COFF object is missing or too small: %s\n", input_path);
        return 4;
    }
    if (status.st_size > 64LL * 1024LL * 1024LL) {
        fputs("[-] COFF object exceeds the 64 MiB safety limit.\n", stderr);
        return 4;
    }

    object_data = (BYTE *)malloc((size_t)status.st_size);
    input = fopen(input_path, "rb");
    if (object_data == NULL || input == NULL ||
        fread(object_data, 1, (size_t)status.st_size, input) != (size_t)status.st_size) {
        fputs("[-] Unable to read input COFF object.\n", stderr);
        goto cleanup;
    }
    fclose(input);
    input = NULL;

    file_header = (IMAGE_FILE_HEADER *)object_data;
    if (file_header->Machine != expected_machine ||
        file_header->NumberOfSections == 0 || file_header->NumberOfSections > 96 ||
        file_header->SizeOfOptionalHeader != 0) {
        fprintf(stderr, "[-] Input is not a supported %s COFF object.\n",
            machine_name(expected_machine));
        goto cleanup;
    }
    section_table_offset = sizeof(IMAGE_FILE_HEADER) + file_header->SizeOfOptionalHeader;
    if (!checked_range(section_table_offset,
                       (uint64_t)file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER),
                       (uint64_t)status.st_size)) {
        fputs("[-] COFF section table is truncated.\n", stderr);
        goto cleanup;
    }
    sections = (IMAGE_SECTION_HEADER *)(object_data + section_table_offset);
    for (index = 0; index < file_header->NumberOfSections; ++index) {
        char name[IMAGE_SIZEOF_SHORT_NAME + 1];
        memcpy(name, sections[index].Name, IMAGE_SIZEOF_SHORT_NAME);
        name[IMAGE_SIZEOF_SHORT_NAME] = 0;
        if (strcmp(name, ".pbf") == 0) {
            if (payload_section != NULL) {
                fputs("[-] COFF object contains more than one .pbf section.\n", stderr);
                goto cleanup;
            }
            payload_section = &sections[index];
        }
    }
    if (payload_section == NULL) {
        fputs("[-] No .pbf section was found.\n", stderr);
        goto cleanup;
    }
    if ((payload_section->Characteristics & IMAGE_SCN_CNT_CODE) == 0 ||
        payload_section->SizeOfRawData == 0 ||
        payload_section->SizeOfRawData > MAX_PAYLOAD_SIZE) {
        fputs("[-] The .pbf section is empty, not code, or exceeds 1 MiB.\n", stderr);
        goto cleanup;
    }
    if (payload_section->NumberOfRelocations != 0 ||
        (payload_section->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) != 0) {
        fprintf(stderr, "[-] The .pbf section has %u relocation(s); it is not position independent.\n",
            payload_section->NumberOfRelocations);
        goto cleanup;
    }
    if (!checked_range(payload_section->PointerToRawData,
                       payload_section->SizeOfRawData,
                       (uint64_t)status.st_size)) {
        fputs("[-] The .pbf raw-data range is invalid.\n", stderr);
        goto cleanup;
    }
    if (!hash_bytes(object_data + payload_section->PointerToRawData,
                    payload_section->SizeOfRawData, digest)) {
        fputs("[-] SHA-256 calculation failed.\n", stderr);
        goto cleanup;
    }

    output = fopen(output_path, "wb");
    if (output == NULL) {
        fputs("[-] Unable to create output BIN.\n", stderr);
        goto cleanup;
    }
    if (fwrite(object_data + payload_section->PointerToRawData, 1,
               payload_section->SizeOfRawData, output) != payload_section->SizeOfRawData) {
        fclose(output);
        output = NULL;
        fputs("[-] Unable to write output BIN.\n", stderr);
        goto cleanup;
    }
    if (fclose(output) != 0) {
        output = NULL;
        fputs("[-] Unable to finalize output BIN.\n", stderr);
        goto cleanup;
    }
    output = NULL;
    if (!write_hash_sidecar(output_path, digest, force)) goto cleanup;

    printf("[+] Verified %s PIC section: %u bytes, relocations=0\n",
        machine_name(expected_machine), payload_section->SizeOfRawData);
    printf("[+] Raw BIN: %s\n[+] SHA-256: ", output_path);
    for (index = 0; index < SHA256_SIZE; ++index) printf("%02x", digest[index]);
    putchar('\n');
    exit_code = 0;

cleanup:
    if (output != NULL) fclose(output);
    if (input != NULL) fclose(input);
    free(object_data);
    return exit_code;
}
