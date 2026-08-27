/*
 * Clean-room, local-process x64 native DLL mapper.
 *
 * This stage validates the mapping core before it is made position independent
 * and packaged into a raw BIN. It does not access or inject another process.
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "pbf_abi.h"

#define PBF_MAX_IMAGE_SIZE (512U * 1024U * 1024U)
#define PBF_MAX_SECTIONS 96U
#define PBF_MAX_IMPORTS 4096U
#define PBF_MAX_IMPORT_MODULES 128U
#define PBF_MAX_TLS_CALLBACKS 128U

typedef BOOL (WINAPI *dll_entry_fn)(HINSTANCE, DWORD, LPVOID);

typedef struct raw_pe_view_t {
    const BYTE *file_data;
    size_t file_size;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_SECTION_HEADER *sections;
} raw_pe_view;

typedef struct mapped_image_t {
    BYTE *base;
    SIZE_T size;
    dll_entry_fn dll_entry;
    HMODULE imported_modules[PBF_MAX_IMPORT_MODULES];
    size_t imported_module_count;
    PRUNTIME_FUNCTION function_table;
    DWORD function_count;
    int function_table_registered;
    int process_attached;
} mapped_image;

static int checked_range_u64(uint64_t offset, uint64_t length, uint64_t total) {
    return offset <= total && length <= total - offset;
}

static int image_range(const mapped_image *image, uint32_t rva, size_t length) {
    return checked_range_u64(rva, length, image->size);
}

static void *image_pointer(const mapped_image *image, uint32_t rva, size_t length) {
    if (!image_range(image, rva, length)) return NULL;
    return image->base + rva;
}

static const char *image_string(const mapped_image *image, uint32_t rva) {
    const char *text;
    size_t remaining;

    if (!image_range(image, rva, 1)) return NULL;
    text = (const char *)(image->base + rva);
    remaining = image->size - rva;
    return memchr(text, 0, remaining) != NULL ? text : NULL;
}

static int parse_raw_dll(const BYTE *data, size_t size, raw_pe_view *view) {
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_SECTION_HEADER *sections;
    uint64_t nt_offset;
    uint64_t section_offset;
    uint16_t index;

    memset(view, 0, sizeof(*view));
    if (!checked_range_u64(0, sizeof(IMAGE_DOS_HEADER), size)) return 0;
    dos = (const IMAGE_DOS_HEADER *)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    nt_offset = (uint32_t)dos->e_lfanew;
    if (!checked_range_u64(nt_offset, sizeof(IMAGE_NT_HEADERS64), size)) return 0;
    nt = (const IMAGE_NT_HEADERS64 *)(data + nt_offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->FileHeader.NumberOfSections == 0 ||
        nt->FileHeader.NumberOfSections > PBF_MAX_SECTIONS ||
        nt->OptionalHeader.SizeOfImage == 0 ||
        nt->OptionalHeader.SizeOfImage > PBF_MAX_IMAGE_SIZE ||
        nt->OptionalHeader.SizeOfHeaders == 0 ||
        nt->OptionalHeader.SizeOfHeaders > size ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR ||
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0) {
        return 0;
    }

    section_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        nt->FileHeader.SizeOfOptionalHeader;
    if (!checked_range_u64(section_offset,
        (uint64_t)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), size)) {
        return 0;
    }
    sections = (const IMAGE_SECTION_HEADER *)(data + section_offset);
    for (index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        uint64_t mapped_size = sections[index].Misc.VirtualSize;
        if (mapped_size < sections[index].SizeOfRawData) {
            mapped_size = sections[index].SizeOfRawData;
        }
        if (mapped_size != 0 && !checked_range_u64(sections[index].VirtualAddress,
            mapped_size, nt->OptionalHeader.SizeOfImage)) {
            return 0;
        }
        if (sections[index].SizeOfRawData != 0 &&
            !checked_range_u64(sections[index].PointerToRawData,
                sections[index].SizeOfRawData, size)) {
            return 0;
        }
    }
    view->file_data = data;
    view->file_size = size;
    view->nt = nt;
    view->sections = sections;
    return 1;
}

static int copy_image(const raw_pe_view *view, mapped_image *image) {
    uint16_t index;

    memcpy(image->base, view->file_data, view->nt->OptionalHeader.SizeOfHeaders);
    for (index = 0; index < view->nt->FileHeader.NumberOfSections; ++index) {
        const IMAGE_SECTION_HEADER *section = &view->sections[index];
        if (section->SizeOfRawData == 0) continue;
        memcpy(image->base + section->VirtualAddress,
            view->file_data + section->PointerToRawData,
            section->SizeOfRawData);
    }
    return 1;
}

static int apply_relocations(const raw_pe_view *view, mapped_image *image) {
    const IMAGE_DATA_DIRECTORY *directory =
        &view->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    intptr_t delta = (intptr_t)image->base - (intptr_t)view->nt->OptionalHeader.ImageBase;
    uint32_t consumed = 0;

    if (delta == 0) return 1;
    if (directory->VirtualAddress == 0 || directory->Size < sizeof(IMAGE_BASE_RELOCATION) ||
        !image_range(image, directory->VirtualAddress, directory->Size)) {
        fputs("[-] Image requires relocation but has no valid relocation directory.\n", stderr);
        return 0;
    }
    while (consumed < directory->Size) {
        IMAGE_BASE_RELOCATION *block;
        WORD *entries;
        uint32_t entry_count;
        uint32_t index;

        if (directory->Size - consumed < sizeof(*block)) return 0;
        block = (IMAGE_BASE_RELOCATION *)(image->base + directory->VirtualAddress + consumed);
        if (block->SizeOfBlock < sizeof(*block) || block->SizeOfBlock > directory->Size - consumed) {
            return 0;
        }
        entry_count = (block->SizeOfBlock - sizeof(*block)) / sizeof(WORD);
        entries = (WORD *)(block + 1);
        for (index = 0; index < entry_count; ++index) {
            WORD type = entries[index] >> 12;
            WORD offset = entries[index] & 0x0fff;
            uint32_t patch_rva = block->VirtualAddress + offset;
            uint64_t *patch;

            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            if (type != IMAGE_REL_BASED_DIR64) {
                fprintf(stderr, "[-] Unsupported relocation type %u.\n", type);
                return 0;
            }
            patch = (uint64_t *)image_pointer(image, patch_rva, sizeof(*patch));
            if (patch == NULL) return 0;
            *patch += (uint64_t)delta;
        }
        consumed += block->SizeOfBlock;
    }
    return consumed == directory->Size;
}

static int resolve_imports(const raw_pe_view *view, mapped_image *image) {
    const IMAGE_DATA_DIRECTORY *directory =
        &view->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    uint32_t descriptor_index;
    uint32_t descriptor_limit;

    if (directory->VirtualAddress == 0 || directory->Size == 0) return 1;
    if (!image_range(image, directory->VirtualAddress, directory->Size)) return 0;
    descriptor_limit = directory->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (descriptor_limit > PBF_MAX_IMPORTS) descriptor_limit = PBF_MAX_IMPORTS;
    for (descriptor_index = 0; descriptor_index < descriptor_limit; ++descriptor_index) {
        IMAGE_IMPORT_DESCRIPTOR *descriptor;
        const char *module_name;
        HMODULE module;
        uint32_t lookup_rva;
        uint32_t address_rva;
        uint32_t thunk_index;

        descriptor = (IMAGE_IMPORT_DESCRIPTOR *)image_pointer(image,
            directory->VirtualAddress + descriptor_index * sizeof(*descriptor),
            sizeof(*descriptor));
        if (descriptor == NULL) return 0;
        if (descriptor->Name == 0 && descriptor->FirstThunk == 0) return 1;
        module_name = image_string(image, descriptor->Name);
        if (module_name == NULL || image->imported_module_count >= PBF_MAX_IMPORT_MODULES) return 0;
        module = LoadLibraryA(module_name);
        if (module == NULL) {
            fprintf(stderr, "[-] LoadLibraryA failed for %s: %lu\n", module_name, GetLastError());
            return 0;
        }
        image->imported_modules[image->imported_module_count++] = module;
        lookup_rva = descriptor->OriginalFirstThunk != 0 ?
            descriptor->OriginalFirstThunk : descriptor->FirstThunk;
        address_rva = descriptor->FirstThunk;

        for (thunk_index = 0; thunk_index < PBF_MAX_IMPORTS; ++thunk_index) {
            IMAGE_THUNK_DATA64 *lookup = (IMAGE_THUNK_DATA64 *)image_pointer(image,
                lookup_rva + thunk_index * sizeof(*lookup), sizeof(*lookup));
            IMAGE_THUNK_DATA64 *address = (IMAGE_THUNK_DATA64 *)image_pointer(image,
                address_rva + thunk_index * sizeof(*address), sizeof(*address));
            FARPROC procedure;

            if (lookup == NULL || address == NULL) return 0;
            if (lookup->u1.AddressOfData == 0) break;
            if (IMAGE_SNAP_BY_ORDINAL64(lookup->u1.Ordinal)) {
                procedure = GetProcAddress(module,
                    (LPCSTR)(uintptr_t)IMAGE_ORDINAL64(lookup->u1.Ordinal));
            } else {
                IMAGE_IMPORT_BY_NAME *by_name = (IMAGE_IMPORT_BY_NAME *)image_pointer(image,
                    (uint32_t)lookup->u1.AddressOfData, sizeof(WORD) + 1);
                if (by_name == NULL || image_string(image,
                    (uint32_t)lookup->u1.AddressOfData + (uint32_t)offsetof(IMAGE_IMPORT_BY_NAME, Name)) == NULL) {
                    return 0;
                }
                procedure = GetProcAddress(module, (LPCSTR)by_name->Name);
            }
            if (procedure == NULL) return 0;
            address->u1.Function = (ULONGLONG)(uintptr_t)procedure;
        }
        if (thunk_index == PBF_MAX_IMPORTS) return 0;
    }
    return 0;
}

static int register_exceptions(const raw_pe_view *view, mapped_image *image) {
    const IMAGE_DATA_DIRECTORY *directory =
        &view->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    if (directory->VirtualAddress == 0 || directory->Size == 0) return 1;
    if (directory->Size % sizeof(RUNTIME_FUNCTION) != 0) return 0;
    image->function_table = (PRUNTIME_FUNCTION)image_pointer(image,
        directory->VirtualAddress, directory->Size);
    if (image->function_table == NULL) return 0;
    image->function_count = directory->Size / sizeof(RUNTIME_FUNCTION);
    if (!RtlAddFunctionTable(image->function_table, image->function_count,
                             (DWORD64)(uintptr_t)image->base)) {
        return 0;
    }
    image->function_table_registered = 1;
    return 1;
}

static int run_tls_callbacks(const raw_pe_view *view, mapped_image *image) {
    const IMAGE_DATA_DIRECTORY *directory =
        &view->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    IMAGE_TLS_DIRECTORY64 *tls;
    PIMAGE_TLS_CALLBACK *callbacks;
    uintptr_t callback_array;
    uint32_t index;

    if (directory->VirtualAddress == 0 || directory->Size == 0) return 1;
    tls = (IMAGE_TLS_DIRECTORY64 *)image_pointer(image,
        directory->VirtualAddress, sizeof(*tls));
    if (tls == NULL || tls->AddressOfCallBacks == 0) return tls != NULL;
    callback_array = (uintptr_t)tls->AddressOfCallBacks;
    if (callback_array < (uintptr_t)image->base ||
        callback_array >= (uintptr_t)image->base + image->size) {
        return 0;
    }
    callbacks = (PIMAGE_TLS_CALLBACK *)callback_array;
    for (index = 0; index < PBF_MAX_TLS_CALLBACKS; ++index) {
        uintptr_t callback_address;
        if ((BYTE *)&callbacks[index] + sizeof(callbacks[index]) > image->base + image->size) return 0;
        if (callbacks[index] == NULL) return 1;
        callback_address = (uintptr_t)callbacks[index];
        if (callback_address < (uintptr_t)image->base ||
            callback_address >= (uintptr_t)image->base + image->size) {
            return 0;
        }
        callbacks[index]((PVOID)image->base, DLL_PROCESS_ATTACH, NULL);
    }
    return 0;
}

static DWORD protection_for_section(DWORD characteristics) {
    int execute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    int read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    int write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    if (execute) {
        if (write) return PAGE_EXECUTE_READWRITE;
        if (read) return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if (write) return PAGE_READWRITE;
    if (read) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

static int apply_section_protections(const raw_pe_view *view, mapped_image *image) {
    DWORD old_protection;
    uint16_t index;

    if (!VirtualProtect(image->base, view->nt->OptionalHeader.SizeOfHeaders,
                        PAGE_READONLY, &old_protection)) {
        return 0;
    }
    for (index = 0; index < view->nt->FileHeader.NumberOfSections; ++index) {
        const IMAGE_SECTION_HEADER *section = &view->sections[index];
        SIZE_T size = section->Misc.VirtualSize;
        DWORD protection;
        if (size < section->SizeOfRawData) size = section->SizeOfRawData;
        if (size == 0) continue;
        protection = protection_for_section(section->Characteristics);
        if (!VirtualProtect(image->base + section->VirtualAddress,
                            size, protection, &old_protection)) {
            return 0;
        }
    }
    return FlushInstructionCache(GetCurrentProcess(), image->base, image->size) != 0;
}

static void *find_export(const raw_pe_view *view, const mapped_image *image, const char *wanted) {
    const IMAGE_DATA_DIRECTORY *directory =
        &view->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *exports;
    DWORD *names;
    WORD *ordinals;
    DWORD *functions;
    DWORD index;

    if (directory->VirtualAddress == 0 || directory->Size < sizeof(*exports)) return NULL;
    exports = (IMAGE_EXPORT_DIRECTORY *)image_pointer(image,
        directory->VirtualAddress, sizeof(*exports));
    if (exports == NULL || exports->NumberOfNames > PBF_MAX_IMPORTS ||
        exports->NumberOfFunctions > PBF_MAX_IMPORTS) return NULL;
    names = (DWORD *)image_pointer(image, exports->AddressOfNames,
        exports->NumberOfNames * sizeof(DWORD));
    ordinals = (WORD *)image_pointer(image, exports->AddressOfNameOrdinals,
        exports->NumberOfNames * sizeof(WORD));
    functions = (DWORD *)image_pointer(image, exports->AddressOfFunctions,
        exports->NumberOfFunctions * sizeof(DWORD));
    if (names == NULL || ordinals == NULL || functions == NULL) return NULL;
    for (index = 0; index < exports->NumberOfNames; ++index) {
        const char *name = image_string(image, names[index]);
        WORD ordinal;
        DWORD function_rva;
        if (name == NULL || strcmp(name, wanted) != 0) continue;
        ordinal = ordinals[index];
        if (ordinal >= exports->NumberOfFunctions) return NULL;
        function_rva = functions[ordinal];
        if (function_rva >= directory->VirtualAddress &&
            function_rva < directory->VirtualAddress + directory->Size) {
            return NULL;
        }
        return image_pointer(image, function_rva, 1);
    }
    return NULL;
}

static void unmap_image(mapped_image *image) {
    size_t index;

    if (image->process_attached && image->dll_entry != NULL) {
        image->dll_entry((HINSTANCE)image->base, DLL_PROCESS_DETACH, NULL);
        image->process_attached = 0;
    }
    if (image->function_table_registered) {
        RtlDeleteFunctionTable(image->function_table);
        image->function_table_registered = 0;
    }
    for (index = image->imported_module_count; index > 0; --index) {
        FreeLibrary(image->imported_modules[index - 1]);
    }
    image->imported_module_count = 0;
    if (image->base != NULL) VirtualFree(image->base, 0, MEM_RELEASE);
    memset(image, 0, sizeof(*image));
}

static int map_dll(const raw_pe_view *view, mapped_image *image) {
    BYTE *preferred;

    memset(image, 0, sizeof(*image));
    image->size = view->nt->OptionalHeader.SizeOfImage;
    preferred = (BYTE *)(uintptr_t)view->nt->OptionalHeader.ImageBase;
    image->base = (BYTE *)VirtualAlloc(preferred, image->size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (image->base == NULL) {
        image->base = (BYTE *)VirtualAlloc(NULL, image->size,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (image->base == NULL) return 0;
    if (!copy_image(view, image) || !apply_relocations(view, image) ||
        !resolve_imports(view, image) || !register_exceptions(view, image) ||
        !apply_section_protections(view, image) || !run_tls_callbacks(view, image)) {
        return 0;
    }
    if (view->nt->OptionalHeader.AddressOfEntryPoint != 0) {
        image->dll_entry = (dll_entry_fn)image_pointer(image,
            view->nt->OptionalHeader.AddressOfEntryPoint, 1);
        if (image->dll_entry == NULL ||
            !image->dll_entry((HINSTANCE)image->base, DLL_PROCESS_ATTACH, NULL)) {
            return 0;
        }
        image->process_attached = 1;
    }
    return 1;
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

static void print_proof(const uint8_t proof[16]) {
    unsigned int index;
    for (index = 0; index < 16; ++index) printf("%02x", proof[index]);
}

int main(int argc, char **argv) {
    const char *path;
    struct _stat64 status;
    FILE *file = NULL;
    BYTE *file_data = NULL;
    raw_pe_view view;
    mapped_image image;
    BYTE *preferred_blocker = NULL;
    pbf_entry_fn entry;
    pbf_context context;
    uint64_t entry_result;
    int exit_code = 1;

    memset(&image, 0, sizeof(image));
    if (argc < 2 || argc > 4 || strcmp(argv[1], "--help") == 0) {
        puts("native-maptest 0.1.0\n"
             "Usage: native-maptest <native-x64.dll> [input-a] [input-b]");
        return argc == 2 ? 0 : 2;
    }
    path = argv[1];
    memset(&context, 0, sizeof(context));
    context.size = sizeof(context);
    context.abi_version = PBF_ABI_VERSION;
    context.input_a = 40;
    context.input_b = 2;
    if (argc >= 3 && !parse_u64(argv[2], &context.input_a)) return 2;
    if (argc >= 4 && !parse_u64(argv[3], &context.input_b)) return 2;

    if (_stat64(path, &status) != 0 || status.st_size <= 0 ||
        status.st_size > PBF_MAX_IMAGE_SIZE) {
        fputs("[-] DLL is missing, empty, or too large.\n", stderr);
        return 3;
    }
    file_data = (BYTE *)malloc((size_t)status.st_size);
    file = fopen(path, "rb");
    if (file_data == NULL || file == NULL ||
        fread(file_data, 1, (size_t)status.st_size, file) != (size_t)status.st_size) {
        fputs("[-] Unable to read DLL.\n", stderr);
        goto cleanup;
    }
    fclose(file);
    file = NULL;
    if (!parse_raw_dll(file_data, (size_t)status.st_size, &view)) {
        fputs("[-] Input is not a supported native x64 DLL.\n", stderr);
        exit_code = 4;
        goto cleanup;
    }
    preferred_blocker = (BYTE *)VirtualAlloc(
        (LPVOID)(uintptr_t)view.nt->OptionalHeader.ImageBase,
        view.nt->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
    if (!map_dll(&view, &image)) {
        fputs("[-] In-memory DLL mapping failed.\n", stderr);
        exit_code = 5;
        goto cleanup;
    }
    if (preferred_blocker != NULL) {
        VirtualFree(preferred_blocker, 0, MEM_RELEASE);
        preferred_blocker = NULL;
    }
    entry = (pbf_entry_fn)find_export(&view, &image, "PbfEntry");
    if (entry == NULL) {
        fputs("[-] Export PbfEntry was not found.\n", stderr);
        exit_code = 6;
        goto cleanup;
    }
    __try {
        entry_result = entry(&context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[-] Mapped DLL raised exception 0x%08lx.\n", GetExceptionCode());
        exit_code = 7;
        goto cleanup;
    }
    if (entry_result != PBF_RESULT_OK) {
        fputs("[-] PbfEntry returned an ABI error.\n", stderr);
        exit_code = 7;
        goto cleanup;
    }

    printf("[+] Native x64 DLL mapped in the current process.\n");
    printf("[+] Sections=%u Imports=%zu Base=%p Relocated=%s\n",
        view.nt->FileHeader.NumberOfSections, image.imported_module_count, (void *)image.base,
        (uintptr_t)image.base != (uintptr_t)view.nt->OptionalHeader.ImageBase ? "yes" : "no");
    printf("[+] PbfEntry result: 0x%016" PRIx64 "\n[+] Proof: ", context.result);
    print_proof(context.proof);
    putchar('\n');
    exit_code = 0;

cleanup:
    if (preferred_blocker != NULL) VirtualFree(preferred_blocker, 0, MEM_RELEASE);
    unmap_image(&image);
    if (file != NULL) fclose(file);
    free(file_data);
    return exit_code;
}
