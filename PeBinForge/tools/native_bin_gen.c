/* PeBinForge COFF PIC linker and native x86/x64 PE raw-bundle generator. */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "pbf_native.h"

#define SHA256_SIZE 32U
#define MAX_STUB_OBJECT (16U * 1024U * 1024U)
#define PAGE_ALIGNMENT 4096U

typedef struct file_buffer_t {
    BYTE *data;
    uint32_t size;
} file_buffer;

typedef struct embedded_module_t {
    char path[MAX_PATH];
    char name[PBF_NATIVE_MODULE_NAME_SIZE];
    file_buffer file;
    int is_exe;
} embedded_module;

typedef struct pe_view_t {
    const IMAGE_FILE_HEADER *file_header;
    const IMAGE_DATA_DIRECTORY *directories;
    uint32_t directory_count;
    uint32_t size_of_headers;
    uint32_t address_of_entry_point;
    uint64_t section_offset;
    WORD machine;
    WORD optional_magic;
} pe_view;

static int checked_range(uint64_t offset, uint64_t length, uint64_t total) {
    return offset <= total && length <= total - offset;
}

static uint32_t align_up(uint32_t value, uint32_t alignment) {
    uint32_t mask = alignment - 1U;
    if (value > UINT32_MAX - mask) return 0;
    return (value + mask) & ~mask;
}

static int file_exists(const char *path) {
    DWORD attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static int read_file(const char *path, uint32_t limit, file_buffer *buffer) {
    struct _stat64 status;
    FILE *file;

    memset(buffer, 0, sizeof(*buffer));
    if (_stat64(path, &status) != 0 || status.st_size <= 0 || status.st_size > limit) return 0;
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

static int sidecar_path(const char *output, char path[MAX_PATH]) {
    size_t length = strlen(output);
    if (length + 8 >= MAX_PATH) return 0;
    memcpy(path, output, length + 1);
    strcat(path, ".sha256");
    return 1;
}

static int write_sidecar(const char *output, const BYTE digest[SHA256_SIZE]) {
    char path[MAX_PATH];
    const char *name;
    FILE *file;
    unsigned int index;
    if (!sidecar_path(output, path)) return 0;
    file = fopen(path, "wb");
    if (file == NULL) return 0;
    name = strrchr(output, '\\');
    if (name == NULL) name = strrchr(output, '/');
    name = name == NULL ? output : name + 1;
    for (index = 0; index < SHA256_SIZE; ++index) fprintf(file, "%02x", digest[index]);
    fprintf(file, "  %s\r\n", name);
    return fclose(file) == 0;
}

static int short_name_equals(const BYTE name[IMAGE_SIZEOF_SHORT_NAME], const char *wanted) {
    char text[IMAGE_SIZEOF_SHORT_NAME + 1];
    memcpy(text, name, IMAGE_SIZEOF_SHORT_NAME);
    text[IMAGE_SIZEOF_SHORT_NAME] = 0;
    return strcmp(text, wanted) == 0;
}

static int parse_pe(const file_buffer *file, pe_view *view) {
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_FILE_HEADER *file_header;
    const BYTE *optional;
    uint64_t nt_offset;
    uint64_t optional_offset;
    uint32_t available_directories;
    WORD magic;

    memset(view, 0, sizeof(*view));
    if (!checked_range(0, sizeof(*dos), file->size)) return 0;
    dos = (const IMAGE_DOS_HEADER *)file->data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    nt_offset = (uint32_t)dos->e_lfanew;
    if (!checked_range(nt_offset, sizeof(DWORD) + sizeof(*file_header), file->size) ||
        *(const DWORD *)(file->data + nt_offset) != IMAGE_NT_SIGNATURE) return 0;
    file_header = (const IMAGE_FILE_HEADER *)(file->data + nt_offset + sizeof(DWORD));
    optional_offset = nt_offset + sizeof(DWORD) + sizeof(*file_header);
    if (file_header->NumberOfSections == 0 || file_header->NumberOfSections > 96 ||
        !checked_range(optional_offset, file_header->SizeOfOptionalHeader, file->size) ||
        file_header->SizeOfOptionalHeader < sizeof(WORD)) return 0;
    optional = file->data + optional_offset;
    memcpy(&magic, optional, sizeof(magic));
    if (file_header->Machine == IMAGE_FILE_MACHINE_I386 &&
        magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const IMAGE_OPTIONAL_HEADER32 *header = (const IMAGE_OPTIONAL_HEADER32 *)optional;
        uint32_t directory_offset = (uint32_t)FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, DataDirectory);
        if (file_header->SizeOfOptionalHeader < directory_offset) return 0;
        available_directories = (file_header->SizeOfOptionalHeader - directory_offset) /
            sizeof(IMAGE_DATA_DIRECTORY);
        view->directory_count = header->NumberOfRvaAndSizes;
        if (view->directory_count > available_directories) return 0;
        view->directories = header->DataDirectory;
        view->size_of_headers = header->SizeOfHeaders;
        view->address_of_entry_point = header->AddressOfEntryPoint;
    } else if (file_header->Machine == IMAGE_FILE_MACHINE_AMD64 &&
               magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_OPTIONAL_HEADER64 *header = (const IMAGE_OPTIONAL_HEADER64 *)optional;
        uint32_t directory_offset = (uint32_t)FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, DataDirectory);
        if (file_header->SizeOfOptionalHeader < directory_offset) return 0;
        available_directories = (file_header->SizeOfOptionalHeader - directory_offset) /
            sizeof(IMAGE_DATA_DIRECTORY);
        view->directory_count = header->NumberOfRvaAndSizes;
        if (view->directory_count > available_directories) return 0;
        view->directories = header->DataDirectory;
        view->size_of_headers = header->SizeOfHeaders;
        view->address_of_entry_point = header->AddressOfEntryPoint;
    } else {
        return 0;
    }
    view->file_header = file_header;
    view->section_offset = optional_offset + file_header->SizeOfOptionalHeader;
    view->machine = file_header->Machine;
    view->optional_magic = magic;
    return checked_range(view->section_offset,
        (uint64_t)file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER), file->size);
}

static IMAGE_DATA_DIRECTORY pe_directory(const pe_view *view, uint32_t index) {
    IMAGE_DATA_DIRECTORY empty;
    empty.VirtualAddress = 0;
    empty.Size = 0;
    if (index >= view->directory_count) return empty;
    return view->directories[index];
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
        name_offset >= string_size || !checked_range(string_offset, string_size, object->size)) {
        return NULL;
    }
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
    uint32_t standalone_entry_value = UINT32_MAX;
    uint32_t symbol_index;
    uint16_t section_index;
    BYTE *code = NULL;
    IMAGE_RELOCATION *relocations;
    uint32_t relocation_index;

    if (!checked_range(0, sizeof(IMAGE_FILE_HEADER), object->size)) return 0;
    header = (const IMAGE_FILE_HEADER *)object->data;
    if ((header->Machine != IMAGE_FILE_MACHINE_AMD64 &&
         header->Machine != IMAGE_FILE_MACHINE_I386) || header->NumberOfSections == 0 ||
        header->NumberOfSections > 96 || header->SizeOfOptionalHeader != 0) return 0;
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
        if (name != NULL && (strcmp(name, "PbfNativeEntry") == 0 ||
            strcmp(name, "_PbfNativeEntry") == 0 ||
            strcmp(name, "@PbfNativeEntry@4") == 0)) {
            if (symbol->SectionNumber != (SHORT)pbf_number || symbol->Value >= pbf->SizeOfRawData) return 0;
            entry_value = symbol->Value;
        } else if (name != NULL && (strcmp(name, "PbfNativeStandalone") == 0 ||
                   strcmp(name, "_PbfNativeStandalone") == 0 ||
                   strcmp(name, "@PbfNativeStandalone@4") == 0)) {
            if (symbol->SectionNumber != (SHORT)pbf_number || symbol->Value >= pbf->SizeOfRawData) return 0;
            standalone_entry_value = symbol->Value;
        }
        symbol_index += 1U + symbol->NumberOfAuxSymbols;
    }
    if (entry_value == UINT32_MAX || standalone_entry_value == UINT32_MAX) return 0;
    code = (BYTE *)malloc(pbf->SizeOfRawData);
    if (code == NULL) return 0;
    memcpy(code, object->data + pbf->PointerToRawData, pbf->SizeOfRawData);
    relocations = (IMAGE_RELOCATION *)(object->data + pbf->PointerToRelocations);
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
    *standalone_entry_offset = standalone_entry_value;
    *machine = header->Machine;
    return 1;
fail:
    free(code);
    return 0;
}

static int validate_native_dll(const file_buffer *dll, WORD expected_machine) {
    pe_view view;
    IMAGE_DATA_DIRECTORY managed;
    if (!parse_pe(dll, &view) || view.machine != expected_machine ||
        (view.file_header->Characteristics & IMAGE_FILE_DLL) == 0) return 0;
    managed = pe_directory(&view, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    return managed.VirtualAddress == 0;
}

static int validate_native_primary(const file_buffer *image, int *is_exe, WORD *machine) {
    pe_view view;
    IMAGE_DATA_DIRECTORY managed;
    if (!parse_pe(image, &view)) return 0;
    managed = pe_directory(&view, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    if (managed.VirtualAddress != 0) return 0;
    *is_exe = (view.file_header->Characteristics & IMAGE_FILE_DLL) == 0;
    if (*is_exe && view.address_of_entry_point == 0) return 0;
    *machine = view.machine;
    return 1;
}

static const char *path_basename(const char *path) {
    const char *backslash = strrchr(path, '\\');
    const char *slash = strrchr(path, '/');
    const char *name = backslash;
    if (slash != NULL && (name == NULL || slash > name)) name = slash;
    return name == NULL ? path : name + 1;
}

static int path_directory(const char *path, char directory[MAX_PATH]) {
    const char *name = path_basename(path);
    size_t length = (size_t)(name - path);
    if (length == 0) {
        directory[0] = '.';
        directory[1] = '\\';
        directory[2] = 0;
        return 1;
    }
    if (length + 1 > MAX_PATH) return 0;
    memcpy(directory, path, length);
    directory[length] = 0;
    return 1;
}

static int dependency_path(const char *directory, const char *name,
                           char path[MAX_PATH]) {
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    if (strchr(name, '\\') != NULL || strchr(name, '/') != NULL ||
        name_length == 0 || name_length >= PBF_NATIVE_MODULE_NAME_SIZE ||
        directory_length + name_length + 1 > MAX_PATH) return 0;
    memcpy(path, directory, directory_length);
    memcpy(path + directory_length, name, name_length + 1);
    return 1;
}

static int rva_to_file_offset(const file_buffer *file, uint32_t rva,
                              uint32_t length, uint32_t *offset) {
    pe_view view;
    const IMAGE_SECTION_HEADER *sections;
    uint16_t index;
    if (!parse_pe(file, &view)) return 0;
    if (rva < view.size_of_headers &&
        checked_range(rva, length, file->size)) {
        *offset = rva;
        return 1;
    }
    sections = (const IMAGE_SECTION_HEADER *)(file->data + view.section_offset);
    for (index = 0; index < view.file_header->NumberOfSections; ++index) {
        uint64_t section_size = sections[index].Misc.VirtualSize;
        uint64_t relative;
        uint64_t raw_offset;
        if (section_size < sections[index].SizeOfRawData)
            section_size = sections[index].SizeOfRawData;
        if (rva < sections[index].VirtualAddress ||
            (uint64_t)rva + length > (uint64_t)sections[index].VirtualAddress + section_size)
            continue;
        relative = (uint64_t)rva - sections[index].VirtualAddress;
        if (relative + length > sections[index].SizeOfRawData) return 0;
        raw_offset = sections[index].PointerToRawData + relative;
        if (!checked_range(raw_offset, length, file->size)) return 0;
        *offset = (uint32_t)raw_offset;
        return 1;
    }
    return 0;
}

static int module_index_by_name(const embedded_module *modules, uint32_t count,
                                const char *name) {
    uint32_t index;
    for (index = 0; index < count; ++index) {
        if (_stricmp(modules[index].name, name) == 0) return (int)index;
    }
    return -1;
}

static int add_module_recursive(embedded_module modules[PBF_NATIVE_MAX_EMBEDDED_MODULES],
                                uint32_t *count, const char *path,
                                const char *directory, WORD *bundle_machine) {
    const char *name = path_basename(path);
    embedded_module *module;
    pe_view view;
    IMAGE_DATA_DIRECTORY imports;
    uint32_t descriptor_offset;
    uint32_t descriptor_limit;
    uint32_t descriptor_index;
    if (strlen(path) >= MAX_PATH || strlen(name) == 0 ||
        strlen(name) >= PBF_NATIVE_MODULE_NAME_SIZE) return 0;
    if (module_index_by_name(modules, *count, name) >= 0) return 1;
    if (*count >= PBF_NATIVE_MAX_EMBEDDED_MODULES) {
        fputs("[-] Native dependency graph exceeds 16 embedded modules.\n", stderr);
        return 0;
    }
    module = &modules[*count];
    memset(module, 0, sizeof(*module));
    strcpy(module->path, path);
    strcpy(module->name, name);
    if (!read_file(path, PBF_NATIVE_MAX_BUNDLE, &module->file) ||
        ((*count == 0 && !validate_native_primary(&module->file, &module->is_exe,
                                                   bundle_machine)) ||
         (*count != 0 && !validate_native_dll(&module->file, *bundle_machine)))) {
        fprintf(stderr, "[-] Image is not a supported native x86/x64 PE, or its architecture differs: %s\n", path);
        free(module->file.data);
        memset(module, 0, sizeof(*module));
        return 0;
    }
    ++*count;
    if (!parse_pe(&module->file, &view)) return 0;
    imports = pe_directory(&view, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (imports.VirtualAddress == 0 || imports.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) return 1;
    if (!rva_to_file_offset(&module->file, imports.VirtualAddress,
                            sizeof(IMAGE_IMPORT_DESCRIPTOR), &descriptor_offset)) return 0;
    descriptor_limit = imports.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (descriptor_limit > 4096U) descriptor_limit = 4096U;
    for (descriptor_index = 0; descriptor_index < descriptor_limit; ++descriptor_index) {
        IMAGE_IMPORT_DESCRIPTOR descriptor;
        uint32_t name_offset;
        const char *import_name;
        char candidate[MAX_PATH];
        uint64_t descriptor_position = (uint64_t)descriptor_offset +
            descriptor_index * sizeof(descriptor);
        if (!checked_range(descriptor_position, sizeof(descriptor), module->file.size)) return 0;
        memcpy(&descriptor, module->file.data + descriptor_position, sizeof(descriptor));
        if (descriptor.Name == 0 && descriptor.FirstThunk == 0) return 1;
        if (!rva_to_file_offset(&module->file, descriptor.Name, 1, &name_offset)) return 0;
        import_name = (const char *)(module->file.data + name_offset);
        if (memchr(import_name, 0, module->file.size - name_offset) == NULL) return 0;
        if (!dependency_path(directory, import_name, candidate)) continue;
        if (file_exists(candidate) &&
            !add_module_recursive(modules, count, candidate, directory, bundle_machine)) return 0;
    }
    return descriptor_index < descriptor_limit;
}

static void set_magic(uint8_t magic[PBF_NATIVE_MAGIC_SIZE]) {
    magic[0] = 'P'; magic[1] = 'B'; magic[2] = 'F'; magic[3] = 'N';
    magic[4] = 'A'; magic[5] = 'T'; magic[6] = '3'; magic[7] = 0;
}

int main(int argc, char **argv) {
    const char *stub_path;
    const char *dll_path;
    const char *output_path;
    int force;
    file_buffer object;
    embedded_module modules[PBF_NATIVE_MAX_EMBEDDED_MODULES];
    uint32_t module_count = 0;
    char module_directory[MAX_PATH];
    BYTE *pic = NULL;
    uint32_t pic_size = 0;
    uint32_t pic_entry = 0;
    uint32_t pic_standalone_entry = 0;
    WORD stub_machine = 0;
    WORD bundle_machine = 0;
    uint32_t bootstrap_size;
    uint32_t header_offset;
    uint32_t code_offset;
    uint32_t actual_code_size;
    uint32_t module_table_offset;
    uint32_t module_data_offset;
    uint32_t current_offset;
    uint32_t total_size;
    BYTE *bundle = NULL;
    pbf_native_module_record *records;
    pbf_native_footer *header;
    pbf_native_footer *footer;
    int32_t jump_displacement;
    BYTE digest[SHA256_SIZE];
    FILE *output = NULL;
    char hash_path[MAX_PATH];
    uint32_t index;
    int result = 1;

    memset(&object, 0, sizeof(object));
    memset(modules, 0, sizeof(modules));
    if (argc < 4 || argc > 5 || (argc == 5 && strcmp(argv[4], "--force") != 0)) {
        puts("native-bin-gen 0.3.0\n"
             "Usage: native-bin-gen <pic-stub.obj> <native-x86-or-x64.exe|dll> <output.bin> [--force]\n"
             "Creates a self-contained noargs v3 BIN and embeds same-architecture DLLs recursively.");
        return 2;
    }
    stub_path = argv[1];
    dll_path = argv[2];
    output_path = argv[3];
    force = argc == 5;
    if (strlen(output_path) < 4 || _stricmp(output_path + strlen(output_path) - 4, ".bin") != 0 ||
        !sidecar_path(output_path, hash_path)) {
        fputs("[-] Output must be a valid .bin path.\n", stderr);
        return 2;
    }
    if (!force && (file_exists(output_path) || file_exists(hash_path))) {
        fputs("[-] Output or SHA-256 sidecar already exists.\n", stderr);
        return 3;
    }
    if (!read_file(stub_path, MAX_STUB_OBJECT, &object)) {
        fputs("[-] Unable to read stub object.\n", stderr);
        goto cleanup;
    }
    if (!link_pic_section(&object, &pic, &pic_size, &pic_entry,
                          &pic_standalone_entry, &stub_machine)) {
        fputs("[-] PIC COFF linking failed or an unsupported relocation was found.\n", stderr);
        goto cleanup;
    }
    if (!path_directory(dll_path, module_directory) ||
        !add_module_recursive(modules, &module_count, dll_path, module_directory,
                              &bundle_machine)) {
        fputs("[-] Unable to build the native dependency graph.\n", stderr);
        goto cleanup;
    }
    if (stub_machine != bundle_machine) {
        fprintf(stderr, "[-] PIC stub architecture (0x%04x) does not match PE architecture (0x%04x).\n",
            stub_machine, bundle_machine);
        goto cleanup;
    }
    bootstrap_size = bundle_machine == IMAGE_FILE_MACHINE_I386 ?
        PBF_NATIVE_BOOTSTRAP_SIZE_X86 : PBF_NATIVE_BOOTSTRAP_SIZE_X64;
    header_offset = bootstrap_size;
    code_offset = align_up(header_offset +
        (uint32_t)sizeof(pbf_native_footer), 16U);
    if (code_offset == 0 || pic_size > UINT32_MAX - code_offset) goto cleanup;
    actual_code_size = code_offset + pic_size;
    module_table_offset = align_up(actual_code_size, 16U);
    if (module_table_offset == 0 || module_count >
        (UINT32_MAX - module_table_offset) / sizeof(pbf_native_module_record)) goto cleanup;
    module_data_offset = align_up(module_table_offset +
        module_count * (uint32_t)sizeof(pbf_native_module_record), PAGE_ALIGNMENT);
    if (module_data_offset == 0) goto cleanup;
    current_offset = module_data_offset;
    for (index = 0; index < module_count; ++index) {
        if (modules[index].file.size > UINT32_MAX - current_offset) goto cleanup;
        current_offset += modules[index].file.size;
        if (index + 1 < module_count) {
            current_offset = align_up(current_offset, PAGE_ALIGNMENT);
            if (current_offset == 0) goto cleanup;
        }
    }
    if (current_offset > UINT32_MAX - sizeof(*footer)) goto cleanup;
    total_size = current_offset + (uint32_t)sizeof(*footer);
    if (total_size > PBF_NATIVE_MAX_BUNDLE) {
        fputs("[-] Native bundle exceeds 64 MiB.\n", stderr);
        goto cleanup;
    }
    bundle = (BYTE *)calloc(1, total_size);
    if (bundle == NULL) goto cleanup;
    if (bundle_machine == IMAGE_FILE_MACHINE_I386) {
        /* entry(): CALL/POP obtains bundle base in ECX, then jumps to bootstrap. */
        bundle[0] = 0xe8;
        memset(bundle + 1, 0, sizeof(int32_t));
        bundle[5] = 0x59;
        bundle[6] = 0x83;
        bundle[7] = 0xe9;
        bundle[8] = 0x05;
        bundle[9] = 0xe9;
        jump_displacement = (int32_t)(code_offset + pic_standalone_entry -
            PBF_NATIVE_BOOTSTRAP_SIZE_X86);
        memcpy(bundle + 10, &jump_displacement, sizeof(jump_displacement));
    } else {
        /* entry(): LEA RCX,[RIP-7] obtains bundle base, then jumps to bootstrap. */
        bundle[0] = 0x48;
        bundle[1] = 0x8d;
        bundle[2] = 0x0d;
        jump_displacement = -7;
        memcpy(bundle + 3, &jump_displacement, sizeof(jump_displacement));
        bundle[7] = 0xe9;
        jump_displacement = (int32_t)(code_offset + pic_standalone_entry -
            PBF_NATIVE_BOOTSTRAP_SIZE_X64);
        memcpy(bundle + 8, &jump_displacement, sizeof(jump_displacement));
    }
    memcpy(bundle + code_offset, pic, pic_size);
    records = (pbf_native_module_record *)(bundle + module_table_offset);
    current_offset = module_data_offset;
    for (index = 0; index < module_count; ++index) {
        strcpy(records[index].name, modules[index].name);
        records[index].offset = current_offset;
        records[index].size = modules[index].file.size;
        records[index].flags = index == 0 ? PBF_NATIVE_MODULE_PRIMARY : 0;
        if (modules[index].is_exe) records[index].flags |= PBF_NATIVE_MODULE_EXE;
        records[index].reserved = 0;
        memcpy(bundle + current_offset, modules[index].file.data, modules[index].file.size);
        current_offset += modules[index].file.size;
        if (index + 1 < module_count) current_offset = align_up(current_offset, PAGE_ALIGNMENT);
    }
    footer = (pbf_native_footer *)(bundle + total_size - sizeof(*footer));
    set_magic(footer->magic);
    footer->version = PBF_NATIVE_ABI_VERSION;
    footer->architecture = bundle_machine;
    footer->entry_offset = code_offset + pic_entry;
    footer->code_size = actual_code_size;
    footer->dll_offset = records[0].offset;
    footer->dll_size = records[0].size;
    footer->module_table_offset = module_table_offset;
    footer->module_count = module_count;
    footer->primary_module_index = 0;
    footer->total_size = total_size;
    footer->standalone_entry_offset = code_offset + pic_standalone_entry;
    header = (pbf_native_footer *)(bundle + header_offset);
    memcpy(header, footer, sizeof(*header));
    if (!hash_bytes(bundle, total_size, digest)) goto cleanup;

    output = fopen(output_path, "wb");
    if (output == NULL || fwrite(bundle, 1, total_size, output) != total_size) {
        fputs("[-] Unable to write native bundle.\n", stderr);
        goto cleanup;
    }
    if (fclose(output) != 0) {
        output = NULL;
        goto cleanup;
    }
    output = NULL;
    if (!write_sidecar(output_path, digest)) goto cleanup;
    printf("[+] Linked %s PIC: %u bytes, context=0x%08x standalone=0x%08x, COFF relocations resolved\n",
        bundle_machine == IMAGE_FILE_MACHINE_I386 ? "x86" : "x64",
        pic_size, footer->entry_offset, footer->standalone_entry_offset);
    printf("[+] Embedded modules: %u (primary=%s)\n", module_count, records[0].name);
    for (index = 0; index < module_count; ++index) {
        printf("    [%u] %s: %u bytes at 0x%08x%s\n", index,
            records[index].name, records[index].size, records[index].offset,
            index == 0 ? (modules[index].is_exe ? " [entry EXE]" : " [entry DLL]") : "");
    }
    printf("[+] Native raw BIN: %s (%u bytes)\n[+] SHA-256: ", output_path, total_size);
    for (index = 0; index < SHA256_SIZE; ++index) printf("%02x", digest[index]);
    putchar('\n');
    result = 0;
cleanup:
    if (output != NULL) fclose(output);
    free(bundle);
    free(pic);
    for (index = 0; index < module_count; ++index) free(modules[index].file.data);
    free(object.data);
    return result;
}
