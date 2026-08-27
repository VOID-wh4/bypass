/* Links a managed CLR PIC object and .NET assembly into a self-contained raw BIN. */

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

#define SHA256_SIZE 32U
#define PAGE_ALIGNMENT 4096U
#define MAX_STUB_OBJECT (16U * 1024U * 1024U)
#define PBF_COR_ILONLY 0x00000001U
#define PBF_COR_32BITREQUIRED 0x00000002U
#define PBF_COR_32BITPREFERRED 0x00020000U

typedef struct file_buffer_t { BYTE *data; uint32_t size; } file_buffer;

static int checked_range(uint64_t offset, uint64_t length, uint64_t total) {
    return offset <= total && length <= total - offset;
}

static uint32_t align_up(uint32_t value, uint32_t alignment) {
    uint32_t mask = alignment - 1U;
    if (value > UINT32_MAX - mask) return 0;
    return (value + mask) & ~mask;
}

static int read_file(const char *path, file_buffer *buffer) {
    struct _stat64 status;
    FILE *file;
    memset(buffer, 0, sizeof(*buffer));
    if (_stat64(path, &status) != 0 || status.st_size <= 0 ||
        status.st_size > PBF_MANAGED_MAX_BUNDLE) return 0;
    buffer->size = (uint32_t)status.st_size;
    buffer->data = (BYTE *)malloc(buffer->size);
    file = fopen(path, "rb");
    if (buffer->data == NULL || file == NULL ||
        fread(buffer->data, 1, buffer->size, file) != buffer->size) {
        if (file != NULL) fclose(file);
        free(buffer->data);
        memset(buffer, 0, sizeof(*buffer));
        return 0;
    }
    fclose(file);
    return 1;
}

static int short_name_equals(const BYTE name[IMAGE_SIZEOF_SHORT_NAME], const char *wanted) {
    char text[IMAGE_SIZEOF_SHORT_NAME + 1];
    memcpy(text, name, IMAGE_SIZEOF_SHORT_NAME);
    text[IMAGE_SIZEOF_SHORT_NAME] = 0;
    return strcmp(text, wanted) == 0;
}

static const char *symbol_name(const file_buffer *object, const IMAGE_FILE_HEADER *header,
                               const IMAGE_SYMBOL *symbol, char short_buffer[9]) {
    uint64_t symbols_size = (uint64_t)header->NumberOfSymbols * sizeof(IMAGE_SYMBOL);
    uint64_t string_offset = (uint64_t)header->PointerToSymbolTable + symbols_size;
    uint32_t string_size;
    uint32_t name_offset;
    if (symbol->N.Name.Short != 0) {
        memcpy(short_buffer, symbol->N.ShortName, 8);
        short_buffer[8] = 0;
        return short_buffer;
    }
    if (!checked_range(string_offset, sizeof(uint32_t), object->size)) return NULL;
    memcpy(&string_size, object->data + string_offset, sizeof(string_size));
    name_offset = symbol->N.Name.Long;
    if (string_size < sizeof(uint32_t) || name_offset < sizeof(uint32_t) ||
        name_offset >= string_size || !checked_range(string_offset, string_size, object->size))
        return NULL;
    if (memchr(object->data + string_offset + name_offset, 0,
               string_size - name_offset) == NULL) return NULL;
    return (const char *)(object->data + string_offset + name_offset);
}

static int link_pic_section(const file_buffer *object, BYTE **linked_code,
                            uint32_t *linked_size, uint32_t *entry_offset,
                            uint32_t *standalone_entry_offset, WORD *machine) {
    const IMAGE_FILE_HEADER *header;
    const IMAGE_SECTION_HEADER *sections;
    const IMAGE_SECTION_HEADER *pbf = NULL;
    uint16_t pbf_number = 0;
    uint64_t section_offset;
    uint64_t symbol_bytes;
    uint32_t entry_value = UINT32_MAX;
    uint32_t standalone_value = UINT32_MAX;
    uint32_t symbol_index;
    uint16_t section_index;
    BYTE *code = NULL;
    const IMAGE_RELOCATION *relocations;
    uint32_t relocation_index;
    if (!checked_range(0, sizeof(IMAGE_FILE_HEADER), object->size)) return 0;
    header = (const IMAGE_FILE_HEADER *)object->data;
    if ((header->Machine != IMAGE_FILE_MACHINE_AMD64 &&
         header->Machine != IMAGE_FILE_MACHINE_I386) || header->NumberOfSections == 0 ||
        header->NumberOfSections > 128 || header->SizeOfOptionalHeader != 0) return 0;
    section_offset = sizeof(IMAGE_FILE_HEADER);
    if (!checked_range(section_offset,
        (uint64_t)header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER), object->size)) return 0;
    sections = (const IMAGE_SECTION_HEADER *)(object->data + section_offset);
    for (section_index = 0; section_index < header->NumberOfSections; ++section_index) {
        if (short_name_equals(sections[section_index].Name, ".pbf")) {
            if (pbf != NULL) return 0;
            pbf = &sections[section_index];
            pbf_number = section_index + 1;
        }
    }
    if (pbf == NULL || pbf->SizeOfRawData == 0 ||
        (pbf->Characteristics & IMAGE_SCN_CNT_CODE) == 0 ||
        (pbf->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) != 0 ||
        !checked_range(pbf->PointerToRawData, pbf->SizeOfRawData, object->size) ||
        !checked_range(pbf->PointerToRelocations,
            (uint64_t)pbf->NumberOfRelocations * sizeof(IMAGE_RELOCATION), object->size)) return 0;
    symbol_bytes = (uint64_t)header->NumberOfSymbols * sizeof(IMAGE_SYMBOL);
    if (header->PointerToSymbolTable == 0 ||
        !checked_range(header->PointerToSymbolTable, symbol_bytes, object->size)) return 0;
    for (symbol_index = 0; symbol_index < header->NumberOfSymbols;) {
        const IMAGE_SYMBOL *symbol = (const IMAGE_SYMBOL *)(object->data +
            header->PointerToSymbolTable + symbol_index * sizeof(IMAGE_SYMBOL));
        char short_buffer[9];
        const char *name = symbol_name(object, header, symbol, short_buffer);
        if (name != NULL && (strcmp(name, "PbfManagedEntry") == 0 ||
            strcmp(name, "_PbfManagedEntry") == 0 ||
            strcmp(name, "@PbfManagedEntry@4") == 0)) {
            if (symbol->SectionNumber != (SHORT)pbf_number ||
                symbol->Value >= pbf->SizeOfRawData) return 0;
            entry_value = symbol->Value;
        } else if (name != NULL && (strcmp(name, "PbfManagedStandalone") == 0 ||
                   strcmp(name, "_PbfManagedStandalone") == 0 ||
                   strcmp(name, "@PbfManagedStandalone@4") == 0)) {
            if (symbol->SectionNumber != (SHORT)pbf_number ||
                symbol->Value >= pbf->SizeOfRawData) return 0;
            standalone_value = symbol->Value;
        }
        symbol_index += 1U + symbol->NumberOfAuxSymbols;
    }
    if (entry_value == UINT32_MAX || standalone_value == UINT32_MAX) return 0;
    code = (BYTE *)malloc(pbf->SizeOfRawData);
    if (code == NULL) return 0;
    memcpy(code, object->data + pbf->PointerToRawData, pbf->SizeOfRawData);
    relocations = (const IMAGE_RELOCATION *)(object->data + pbf->PointerToRelocations);
    for (relocation_index = 0; relocation_index < pbf->NumberOfRelocations; ++relocation_index) {
        const IMAGE_RELOCATION *relocation = &relocations[relocation_index];
        const IMAGE_SYMBOL *symbol;
        int32_t addend;
        int64_t displacement;
        uint32_t trailing = 0;
        if (relocation->SymbolTableIndex >= header->NumberOfSymbols ||
            !checked_range(relocation->VirtualAddress, sizeof(int32_t), pbf->SizeOfRawData)) goto fail;
        symbol = (const IMAGE_SYMBOL *)(object->data + header->PointerToSymbolTable +
            relocation->SymbolTableIndex * sizeof(IMAGE_SYMBOL));
        if (symbol->SectionNumber != (SHORT)pbf_number) goto fail;
        if (header->Machine == IMAGE_FILE_MACHINE_I386) {
            if (relocation->Type != IMAGE_REL_I386_REL32) goto fail;
        } else {
            switch (relocation->Type) {
                case IMAGE_REL_AMD64_REL32: trailing = 0; break;
                case IMAGE_REL_AMD64_REL32_1: trailing = 1; break;
                case IMAGE_REL_AMD64_REL32_2: trailing = 2; break;
                case IMAGE_REL_AMD64_REL32_3: trailing = 3; break;
                case IMAGE_REL_AMD64_REL32_4: trailing = 4; break;
                case IMAGE_REL_AMD64_REL32_5: trailing = 5; break;
                default: goto fail;
            }
        }
        memcpy(&addend, code + relocation->VirtualAddress, sizeof(addend));
        displacement = (int64_t)symbol->Value + addend -
            ((int64_t)relocation->VirtualAddress + 4 + trailing);
        if (displacement < INT32_MIN || displacement > INT32_MAX) goto fail;
        addend = (int32_t)displacement;
        memcpy(code + relocation->VirtualAddress, &addend, sizeof(addend));
    }
    *linked_code = code;
    *linked_size = pbf->SizeOfRawData;
    *entry_offset = entry_value;
    *standalone_entry_offset = standalone_value;
    *machine = header->Machine;
    return 1;
fail:
    free(code);
    return 0;
}

static int pe_rva_to_offset(const file_buffer *assembly,
                            const IMAGE_FILE_HEADER *file_header,
                            uint64_t section_offset, uint32_t size_of_headers,
                            uint32_t rva, uint32_t length, uint32_t *offset) {
    const IMAGE_SECTION_HEADER *sections;
    uint16_t index;
    if (rva < size_of_headers && checked_range(rva, length, assembly->size)) {
        *offset = rva;
        return 1;
    }
    if (!checked_range(section_offset,
        (uint64_t)file_header->NumberOfSections * sizeof(*sections), assembly->size)) return 0;
    sections = (const IMAGE_SECTION_HEADER *)(assembly->data + section_offset);
    for (index = 0; index < file_header->NumberOfSections; ++index) {
        uint64_t span = sections[index].Misc.VirtualSize;
        uint64_t relative;
        uint64_t raw;
        if (span < sections[index].SizeOfRawData) span = sections[index].SizeOfRawData;
        if (rva < sections[index].VirtualAddress ||
            (uint64_t)rva + length > (uint64_t)sections[index].VirtualAddress + span) continue;
        relative = (uint64_t)rva - sections[index].VirtualAddress;
        if (relative + length > sections[index].SizeOfRawData) return 0;
        raw = sections[index].PointerToRawData + relative;
        if (!checked_range(raw, length, assembly->size)) return 0;
        *offset = (uint32_t)raw;
        return 1;
    }
    return 0;
}

static int managed_host_architecture(const file_buffer *assembly, WORD *host_architecture) {
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_FILE_HEADER *file_header;
    const BYTE *optional;
    IMAGE_DATA_DIRECTORY managed;
    IMAGE_COR20_HEADER cor_header;
    uint64_t nt_offset;
    uint64_t optional_offset;
    uint64_t section_offset;
    uint32_t size_of_headers;
    uint32_t cor_offset;
    WORD magic;
    if (!checked_range(0, sizeof(*dos), assembly->size)) return 0;
    dos = (const IMAGE_DOS_HEADER *)assembly->data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    nt_offset = (uint32_t)dos->e_lfanew;
    if (!checked_range(nt_offset, sizeof(DWORD) + sizeof(*file_header), assembly->size) ||
        *(const DWORD *)(assembly->data + nt_offset) != IMAGE_NT_SIGNATURE) return 0;
    file_header = (const IMAGE_FILE_HEADER *)(assembly->data + nt_offset + sizeof(DWORD));
    optional_offset = nt_offset + sizeof(DWORD) + sizeof(*file_header);
    if (file_header->NumberOfSections == 0 || file_header->NumberOfSections > 96 ||
        file_header->SizeOfOptionalHeader < sizeof(WORD) ||
        !checked_range(optional_offset, file_header->SizeOfOptionalHeader, assembly->size)) return 0;
    optional = assembly->data + optional_offset;
    memcpy(&magic, optional, sizeof(magic));
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        file_header->Machine == IMAGE_FILE_MACHINE_I386 &&
        file_header->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
        const IMAGE_OPTIONAL_HEADER32 *header = (const IMAGE_OPTIONAL_HEADER32 *)optional;
        if (header->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) return 0;
        managed = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        size_of_headers = header->SizeOfHeaders;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
               file_header->Machine == IMAGE_FILE_MACHINE_AMD64 &&
               file_header->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64)) {
        const IMAGE_OPTIONAL_HEADER64 *header = (const IMAGE_OPTIONAL_HEADER64 *)optional;
        if (header->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) return 0;
        managed = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        size_of_headers = header->SizeOfHeaders;
    } else {
        return 0;
    }
    section_offset = optional_offset + file_header->SizeOfOptionalHeader;
    if (managed.VirtualAddress == 0 || managed.Size < sizeof(cor_header) ||
        !pe_rva_to_offset(assembly, file_header, section_offset, size_of_headers,
                          managed.VirtualAddress, sizeof(cor_header), &cor_offset)) return 0;
    memcpy(&cor_header, assembly->data + cor_offset, sizeof(cor_header));
    if (cor_header.cb < sizeof(cor_header) ||
        (cor_header.Flags & PBF_COR_ILONLY) == 0 || cor_header.EntryPointToken == 0) return 0;
    if (file_header->Machine == IMAGE_FILE_MACHINE_AMD64) {
        *host_architecture = PBF_MANAGED_ARCH_X64;
    } else if ((cor_header.Flags & (PBF_COR_32BITREQUIRED | PBF_COR_32BITPREFERRED)) != 0) {
        *host_architecture = PBF_MANAGED_ARCH_X86;
    } else {
        *host_architecture = PBF_MANAGED_ARCH_X64;
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

static void set_magic(uint8_t magic[PBF_MANAGED_MAGIC_SIZE]) {
    magic[0] = 'P'; magic[1] = 'B'; magic[2] = 'F'; magic[3] = 'N';
    magic[4] = 'E'; magic[5] = 'T'; magic[6] = '2'; magic[7] = 0;
}

static int write_sidecar(const char *output, const BYTE digest[SHA256_SIZE]) {
    char path[MAX_PATH];
    FILE *file;
    size_t length = strlen(output);
    unsigned int index;
    if (length + 8 >= sizeof(path)) return 0;
    memcpy(path, output, length + 1);
    strcat(path, ".sha256");
    file = fopen(path, "wb");
    if (file == NULL) return 0;
    for (index = 0; index < SHA256_SIZE; ++index) fprintf(file, "%02x", digest[index]);
    fprintf(file, "  managed-bundle\r\n");
    return fclose(file) == 0;
}

int main(int argc, char **argv) {
    file_buffer object_x64;
    file_buffer object_x86;
    file_buffer *object;
    file_buffer assembly;
    const char *assembly_path;
    const char *output_path;
    WORD host_architecture = 0;
    WORD stub_machine = 0;
    BYTE *pic = NULL;
    uint32_t pic_size = 0;
    uint32_t pic_entry = 0;
    uint32_t pic_standalone_entry = 0;
    uint32_t bootstrap_size;
    uint32_t code_offset;
    uint32_t actual_code_size;
    uint32_t assembly_offset;
    uint32_t total_size;
    BYTE *bundle = NULL;
    pbf_managed_footer *header;
    pbf_managed_footer *footer;
    int32_t jump_displacement;
    BYTE digest[SHA256_SIZE];
    FILE *output = NULL;
    unsigned int index;
    int result = 1;

    memset(&object_x64, 0, sizeof(object_x64));
    memset(&object_x86, 0, sizeof(object_x86));
    memset(&assembly, 0, sizeof(assembly));
    if (argc != 4 && argc != 5) {
        puts("managed-bin-pack 0.3.0\n"
             "Usage: managed-bin-pack <x64-pic.obj> [x86-pic.obj] <framework4.exe> <output.bin>");
        return 2;
    }
    assembly_path = argc == 5 ? argv[3] : argv[2];
    output_path = argc == 5 ? argv[4] : argv[3];
    if (!read_file(assembly_path, &assembly)) {
        fputs("[-] Unable to read managed assembly.\n", stderr);
        goto cleanup;
    }
    if (!managed_host_architecture(&assembly, &host_architecture)) {
        fputs("[-] Input is not a supported IL-only managed PE with a Main entry point.\n", stderr);
        goto cleanup;
    }
    if (host_architecture == PBF_MANAGED_ARCH_X86 && argc != 5) {
        fputs("[-] The assembly requires the x86 managed PIC object; use automatic dual-object mode.\n", stderr);
        goto cleanup;
    }
    if (!read_file(argv[1], &object_x64) || object_x64.size > MAX_STUB_OBJECT ||
        (argc == 5 && (!read_file(argv[2], &object_x86) ||
                       object_x86.size > MAX_STUB_OBJECT))) {
        fputs("[-] Unable to read the selected managed PIC objects.\n", stderr);
        goto cleanup;
    }
    object = host_architecture == PBF_MANAGED_ARCH_X86 ? &object_x86 : &object_x64;
    if (!link_pic_section(object, &pic, &pic_size, &pic_entry,
                          &pic_standalone_entry, &stub_machine)) {
        fputs("[-] Managed PIC COFF linking failed or an unsupported relocation was found.\n", stderr);
        goto cleanup;
    }
    if (stub_machine != host_architecture) {
        fputs("[-] Managed PIC object architecture does not match the selected CLR host.\n", stderr);
        goto cleanup;
    }
    bootstrap_size = host_architecture == PBF_MANAGED_ARCH_X86 ?
        PBF_MANAGED_BOOTSTRAP_SIZE_X86 : PBF_MANAGED_BOOTSTRAP_SIZE_X64;
    code_offset = align_up(bootstrap_size + (uint32_t)sizeof(*header), 16U);
    if (code_offset == 0 || pic_size > UINT32_MAX - code_offset) goto cleanup;
    actual_code_size = code_offset + pic_size;
    assembly_offset = align_up(actual_code_size, PAGE_ALIGNMENT);
    if (assembly_offset == 0 || assembly.size > UINT32_MAX - assembly_offset - sizeof(*footer)) goto cleanup;
    total_size = assembly_offset + assembly.size + (uint32_t)sizeof(*footer);
    if (total_size > PBF_MANAGED_MAX_BUNDLE) goto cleanup;
    bundle = (BYTE *)calloc(1, total_size);
    if (bundle == NULL) goto cleanup;
    if (host_architecture == PBF_MANAGED_ARCH_X86) {
        bundle[0] = 0xe8;
        memset(bundle + 1, 0, sizeof(int32_t));
        bundle[5] = 0x59;
        bundle[6] = 0x83;
        bundle[7] = 0xe9;
        bundle[8] = 0x05;
        bundle[9] = 0xe9;
        jump_displacement = (int32_t)(code_offset + pic_standalone_entry -
            PBF_MANAGED_BOOTSTRAP_SIZE_X86);
        memcpy(bundle + 10, &jump_displacement, sizeof(jump_displacement));
    } else {
        bundle[0] = 0x48;
        bundle[1] = 0x8d;
        bundle[2] = 0x0d;
        jump_displacement = -7;
        memcpy(bundle + 3, &jump_displacement, sizeof(jump_displacement));
        bundle[7] = 0xe9;
        jump_displacement = (int32_t)(code_offset + pic_standalone_entry -
            PBF_MANAGED_BOOTSTRAP_SIZE_X64);
        memcpy(bundle + 8, &jump_displacement, sizeof(jump_displacement));
    }
    memcpy(bundle + code_offset, pic, pic_size);
    memcpy(bundle + assembly_offset, assembly.data, assembly.size);
    footer = (pbf_managed_footer *)(bundle + total_size - sizeof(*footer));
    set_magic(footer->magic);
    footer->version = PBF_MANAGED_ABI_VERSION;
    footer->architecture = host_architecture;
    footer->entry_offset = code_offset + pic_entry;
    footer->code_size = actual_code_size;
    footer->assembly_offset = assembly_offset;
    footer->assembly_size = assembly.size;
    footer->total_size = total_size;
    footer->standalone_entry_offset = code_offset + pic_standalone_entry;
    header = (pbf_managed_footer *)(bundle + bootstrap_size);
    memcpy(header, footer, sizeof(*header));
    if (!hash_bytes(bundle, total_size, digest)) goto cleanup;
    output = fopen(output_path, "wb");
    if (output == NULL || fwrite(bundle, 1, total_size, output) != total_size) goto cleanup;
    if (fclose(output) != 0) { output = NULL; goto cleanup; }
    output = NULL;
    if (!write_sidecar(output_path, digest)) goto cleanup;
    printf("[+] Managed %s PIC: %u linked bytes, self-contained entry at offset 0\n",
        host_architecture == PBF_MANAGED_ARCH_X86 ? "x86" : "x64", pic_size);
    printf("[+] Embedded assembly: %u bytes at offset 0x%08x\n", assembly.size, assembly_offset);
    printf("[+] Managed raw BIN: %s (%u bytes)\n[+] SHA-256: ", output_path, total_size);
    for (index = 0; index < SHA256_SIZE; ++index) printf("%02x", digest[index]);
    putchar('\n');
    result = 0;
cleanup:
    if (output != NULL) fclose(output);
    free(bundle);
    free(pic);
    free(assembly.data);
    free(object_x86.data);
    free(object_x64.data);
    return result;
}
