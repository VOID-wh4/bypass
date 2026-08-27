/* Reusable first-pass PE/CLR classifier for future mapper backends. */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct pe_probe_t {
    uint16_t machine;
    uint16_t characteristics;
    uint16_t optional_magic;
    uint32_t entry_rva;
    uint64_t image_base;
    uint32_t image_size;
    uint32_t headers_size;
    IMAGE_DATA_DIRECTORY directories[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} pe_probe;

static int checked_range(uint64_t offset, uint64_t length, uint64_t total) {
    return offset <= total && length <= total - offset;
}

static int parse_pe(const BYTE *data, uint64_t length, pe_probe *probe) {
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_FILE_HEADER *file_header;
    uint64_t nt_offset;
    uint64_t optional_offset;
    DWORD signature;

    memset(probe, 0, sizeof(*probe));
    if (!checked_range(0, sizeof(*dos), length)) return 0;
    dos = (const IMAGE_DOS_HEADER *)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    nt_offset = (uint32_t)dos->e_lfanew;
    if (!checked_range(nt_offset, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), length)) return 0;
    memcpy(&signature, data + nt_offset, sizeof(signature));
    if (signature != IMAGE_NT_SIGNATURE) return 0;
    file_header = (const IMAGE_FILE_HEADER *)(data + nt_offset + sizeof(DWORD));
    optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!checked_range(optional_offset, file_header->SizeOfOptionalHeader, length) ||
        file_header->SizeOfOptionalHeader < sizeof(WORD)) {
        return 0;
    }

    probe->machine = file_header->Machine;
    probe->characteristics = file_header->Characteristics;
    memcpy(&probe->optional_magic, data + optional_offset, sizeof(WORD));
    if (probe->optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_OPTIONAL_HEADER64 *optional;
        uint32_t count;
        if (file_header->SizeOfOptionalHeader < sizeof(*optional)) return 0;
        optional = (const IMAGE_OPTIONAL_HEADER64 *)(data + optional_offset);
        probe->entry_rva = optional->AddressOfEntryPoint;
        probe->image_base = optional->ImageBase;
        probe->image_size = optional->SizeOfImage;
        probe->headers_size = optional->SizeOfHeaders;
        count = optional->NumberOfRvaAndSizes;
        if (count > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) count = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        memcpy(probe->directories, optional->DataDirectory,
               count * sizeof(IMAGE_DATA_DIRECTORY));
    } else if (probe->optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const IMAGE_OPTIONAL_HEADER32 *optional;
        uint32_t count;
        if (file_header->SizeOfOptionalHeader < sizeof(*optional)) return 0;
        optional = (const IMAGE_OPTIONAL_HEADER32 *)(data + optional_offset);
        probe->entry_rva = optional->AddressOfEntryPoint;
        probe->image_base = optional->ImageBase;
        probe->image_size = optional->SizeOfImage;
        probe->headers_size = optional->SizeOfHeaders;
        count = optional->NumberOfRvaAndSizes;
        if (count > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) count = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        memcpy(probe->directories, optional->DataDirectory,
               count * sizeof(IMAGE_DATA_DIRECTORY));
    } else {
        return 0;
    }
    return probe->image_size != 0 && probe->headers_size != 0;
}

static const char *machine_name(uint16_t machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_AMD64: return "x64";
        case IMAGE_FILE_MACHINE_I386: return "x86";
        case IMAGE_FILE_MACHINE_ARM64: return "arm64";
        default: return "unknown";
    }
}

static void print_directory(const char *name, const IMAGE_DATA_DIRECTORY *directory) {
    printf("%-13s RVA=0x%08x Size=%u\n", name,
        directory->VirtualAddress, directory->Size);
}

int main(int argc, char **argv) {
    const char *path;
    struct _stat64 status;
    FILE *file = NULL;
    BYTE *data = NULL;
    pe_probe probe;
    int result = 1;

    if (argc != 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        puts("peprobe 0.1.0\nUsage: peprobe <file.exe|file.dll>");
        return argc == 2 ? 0 : 2;
    }
    path = argv[1];
    if (_stat64(path, &status) != 0 || status.st_size <= 0 ||
        status.st_size > 512LL * 1024LL * 1024LL) {
        fputs("[-] Input is missing, empty, or exceeds 512 MiB.\n", stderr);
        return 3;
    }
    data = (BYTE *)malloc((size_t)status.st_size);
    file = fopen(path, "rb");
    if (data == NULL || file == NULL ||
        fread(data, 1, (size_t)status.st_size, file) != (size_t)status.st_size) {
        fputs("[-] Unable to read input.\n", stderr);
        goto cleanup;
    }
    fclose(file);
    file = NULL;
    if (!parse_pe(data, (uint64_t)status.st_size, &probe)) {
        fputs("[-] Input is not a supported PE32/PE32+ image.\n", stderr);
        result = 4;
        goto cleanup;
    }

    printf("Kind: %s\n",
        probe.directories[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0 ?
        "managed" : "native");
    printf("Architecture: %s (0x%04x)\n", machine_name(probe.machine), probe.machine);
    printf("Image type: %s\n",
        (probe.characteristics & IMAGE_FILE_DLL) != 0 ? "DLL" : "EXE");
    printf("Image base: 0x%016llx\n", (unsigned long long)probe.image_base);
    printf("Image size: %u\nEntry RVA: 0x%08x\n",
        probe.image_size, probe.entry_rva);
    print_directory("Imports", &probe.directories[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    print_directory("Relocations", &probe.directories[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
    print_directory("TLS", &probe.directories[IMAGE_DIRECTORY_ENTRY_TLS]);
    print_directory("Exceptions", &probe.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION]);
    print_directory("Delay imports", &probe.directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
    print_directory("CLR", &probe.directories[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]);
    result = 0;

cleanup:
    if (file != NULL) fclose(file);
    free(data);
    return result;
}
