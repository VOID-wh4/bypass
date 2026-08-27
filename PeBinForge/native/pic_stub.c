/* Import-free x64 PIC mapper for native bundles with embedded DLL dependencies. */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <stddef.h>

#include "pbf_native.h"

#define PIC_MAX_SECTIONS 96U
#define PIC_MAX_IMPORTS 4096U
#define PIC_MAX_EXTERNAL_MODULES 64U
#define PIC_MAX_TLS_CALLBACKS 128U
#define PIC_MAX_LOADED_MODULES 256U
#define PIC_MAX_LOADED_EXPORTS 16384U
#define PIC_MAX_EXPORT_NAME 256U

#define PIC_HASH_VIRTUAL_ALLOC          UINT32_C(0x03285501)
#define PIC_HASH_VIRTUAL_FREE           UINT32_C(0x3a9acc72)
#define PIC_HASH_VIRTUAL_PROTECT        UINT32_C(0x820621f3)
#define PIC_HASH_LOAD_LIBRARY_A         UINT32_C(0x53b2070f)
#define PIC_HASH_FREE_LIBRARY           UINT32_C(0xab45c5ee)
#define PIC_HASH_GET_PROC_ADDRESS       UINT32_C(0xf8f45725)
#define PIC_HASH_GET_CURRENT_PROCESS    UINT32_C(0x6dd8a845)
#define PIC_HASH_FLUSH_INSTRUCTION      UINT32_C(0x0490286b)
#define PIC_HASH_RTL_ADD_FUNCTION       UINT32_C(0x38791528)
#define PIC_HASH_RTL_DELETE_FUNCTION    UINT32_C(0x052cd70a)

typedef BOOL (WINAPI *pic_dll_entry_fn)(HINSTANCE, DWORD, LPVOID);
typedef void (__fastcall *pic_exe_entry_fn)(void);

#if defined(_M_IX86)
typedef IMAGE_NT_HEADERS32 pic_nt_headers;
typedef IMAGE_THUNK_DATA32 pic_thunk_data;
typedef IMAGE_TLS_DIRECTORY32 pic_tls_directory;
#define PIC_IMAGE_MACHINE IMAGE_FILE_MACHINE_I386
#define PIC_OPTIONAL_MAGIC IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define PIC_RELOCATION_TYPE IMAGE_REL_BASED_HIGHLOW
#else
typedef IMAGE_NT_HEADERS64 pic_nt_headers;
typedef IMAGE_THUNK_DATA64 pic_thunk_data;
typedef IMAGE_TLS_DIRECTORY64 pic_tls_directory;
#define PIC_IMAGE_MACHINE IMAGE_FILE_MACHINE_AMD64
#define PIC_OPTIONAL_MAGIC IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define PIC_RELOCATION_TYPE IMAGE_REL_BASED_DIR64
#endif

typedef struct pic_raw_view_t {
    const BYTE *data;
    uint32_t size;
    const pic_nt_headers *nt;
    const IMAGE_SECTION_HEADER *sections;
} pic_raw_view;

typedef struct pic_map_state_t {
    BYTE *base;
    SIZE_T size;
    int owns_base;
    HMODULE external_modules[PIC_MAX_EXTERNAL_MODULES];
    uint32_t external_module_count;
#if defined(_M_X64)
    PRUNTIME_FUNCTION function_table;
#else
    LPVOID function_table;
#endif
    DWORD function_count;
    int function_table_registered;
    pic_dll_entry_fn dll_entry;
    int tls_attached;
    int process_attached;
} pic_map_state;

typedef struct pic_bundle_state_t {
    pbf_native_context *context;
    const pbf_native_module_record *records;
    pic_raw_view views[PBF_NATIVE_MAX_EMBEDDED_MODULES];
    pic_map_state maps[PBF_NATIVE_MAX_EMBEDDED_MODULES];
    uint8_t phase[PBF_NATIVE_MAX_EMBEDDED_MODULES];
    uint8_t load_order[PBF_NATIVE_MAX_EMBEDDED_MODULES];
    uint32_t load_count;
} pic_bundle_state;

#pragma code_seg(push, ".pbf")

static int pic_range_u64(uint64_t offset, uint64_t length, uint64_t total) {
    return offset <= total && length <= total - offset;
}

static void pic_zero(void *destination, SIZE_T length) {
    volatile BYTE *bytes = (volatile BYTE *)destination;
    SIZE_T index;
    for (index = 0; index < length; ++index) bytes[index] = 0;
}

static void pic_copy(void *destination, const void *source, SIZE_T length) {
    volatile BYTE *out = (volatile BYTE *)destination;
    const volatile BYTE *in = (const volatile BYTE *)source;
    SIZE_T index;
    for (index = 0; index < length; ++index) out[index] = in[index];
}

static uint32_t pic_host_image_size(BYTE *base) {
    const IMAGE_DOS_HEADER *dos;
    const pic_nt_headers *nt;
    if (base == NULL) return 0;
    dos = (const IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        dos->e_lfanew > 0x1000) return 0;
    nt = (const pic_nt_headers *)(base + (uint32_t)dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != PIC_IMAGE_MACHINE ||
        nt->OptionalHeader.Magic != PIC_OPTIONAL_MAGIC) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

static int pic_equal(const void *left, const void *right, SIZE_T length) {
    const volatile BYTE *a = (const volatile BYTE *)left;
    const volatile BYTE *b = (const volatile BYTE *)right;
    SIZE_T index;
    for (index = 0; index < length; ++index) {
        if (a[index] != b[index]) return 0;
    }
    return 1;
}

static int pic_hash_export_name(const BYTE *base, uint32_t image_size,
                                uint32_t name_rva, uint32_t *hash) {
    uint32_t value = UINT32_C(0x811c9dc5);
    uint32_t index;
    if (name_rva >= image_size) return 0;
    for (index = 0; index < PIC_MAX_EXPORT_NAME && name_rva + index < image_size; ++index) {
        BYTE character = base[name_rva + index];
        if (character == 0) {
            *hash = value;
            return 1;
        }
        value ^= character;
        value *= UINT32_C(0x01000193);
    }
    return 0;
}

static FARPROC pic_find_loaded_export(uint32_t wanted_hash) {
#if defined(_M_X64)
    BYTE *peb = (BYTE *)(uintptr_t)__readgsqword(0x60);
#elif defined(_M_IX86)
    BYTE *peb = (BYTE *)(uintptr_t)__readfsdword(0x30);
#endif
#if defined(_M_X64) || defined(_M_IX86)
    BYTE *loader;
    LIST_ENTRY *head;
    LIST_ENTRY *link;
    uint32_t module_index;
    if (peb == NULL) return NULL;
#if defined(_M_X64)
    loader = *(BYTE **)(peb + 0x18);
#else
    loader = *(BYTE **)(peb + 0x0c);
#endif
    if (loader == NULL) return NULL;
#if defined(_M_X64)
    head = (LIST_ENTRY *)(loader + 0x20);
#else
    head = (LIST_ENTRY *)(loader + 0x14);
#endif
    link = head->Flink;
    for (module_index = 0; link != NULL && link != head &&
         module_index < PIC_MAX_LOADED_MODULES; ++module_index, link = link->Flink) {
        BYTE *entry;
        BYTE *base;
        const IMAGE_DOS_HEADER *dos;
        const pic_nt_headers *nt;
        const IMAGE_DATA_DIRECTORY *directory;
        const IMAGE_EXPORT_DIRECTORY *exports;
        const DWORD *names;
        const WORD *ordinals;
        const DWORD *functions;
        uint32_t image_size;
        uint32_t name_count;
        uint32_t name_index;
#if defined(_M_X64)
        entry = (BYTE *)link - 0x10;
        base = *(BYTE **)(entry + 0x30);
#else
        entry = (BYTE *)link - 0x08;
        base = *(BYTE **)(entry + 0x18);
#endif
        if (base == NULL) continue;
        dos = (const IMAGE_DOS_HEADER *)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
            (uint32_t)dos->e_lfanew > 0x100000U) continue;
        nt = (const pic_nt_headers *)(base + (uint32_t)dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != PIC_OPTIONAL_MAGIC) continue;
        image_size = nt->OptionalHeader.SizeOfImage;
        if (image_size < sizeof(*dos) ||
            !pic_range_u64((uint32_t)dos->e_lfanew, sizeof(*nt), image_size) ||
            nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) continue;
        directory = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (directory->VirtualAddress == 0 || directory->Size < sizeof(*exports) ||
            !pic_range_u64(directory->VirtualAddress, directory->Size, image_size)) continue;
        exports = (const IMAGE_EXPORT_DIRECTORY *)(base + directory->VirtualAddress);
        name_count = exports->NumberOfNames;
        if (name_count > PIC_MAX_LOADED_EXPORTS ||
            exports->NumberOfFunctions > PIC_MAX_LOADED_EXPORTS ||
            !pic_range_u64(exports->AddressOfNames,
                (uint64_t)name_count * sizeof(DWORD), image_size) ||
            !pic_range_u64(exports->AddressOfNameOrdinals,
                (uint64_t)name_count * sizeof(WORD), image_size) ||
            !pic_range_u64(exports->AddressOfFunctions,
                (uint64_t)exports->NumberOfFunctions * sizeof(DWORD), image_size)) continue;
        names = (const DWORD *)(base + exports->AddressOfNames);
        ordinals = (const WORD *)(base + exports->AddressOfNameOrdinals);
        functions = (const DWORD *)(base + exports->AddressOfFunctions);
        for (name_index = 0; name_index < name_count; ++name_index) {
            uint32_t hash;
            uint32_t function_rva;
            if (!pic_hash_export_name(base, image_size, names[name_index], &hash) ||
                hash != wanted_hash || ordinals[name_index] >= exports->NumberOfFunctions)
                continue;
            function_rva = functions[ordinals[name_index]];
            if (function_rva >= directory->VirtualAddress &&
                function_rva < directory->VirtualAddress + directory->Size) continue;
            if (function_rva >= image_size) continue;
            return (FARPROC)(base + function_rva);
        }
    }
#else
    (void)wanted_hash;
#endif
    return NULL;
}

static LPVOID WINAPI pic_swap_process_image_base(LPVOID new_base) {
#if defined(_M_X64)
    BYTE *peb = (BYTE *)(uintptr_t)__readgsqword(0x60);
    LPVOID *image_base;
    LPVOID old_base;
    if (peb == NULL) return NULL;
    image_base = (LPVOID *)(peb + 0x10);
    old_base = *image_base;
    *image_base = new_base;
    return old_base;
#elif defined(_M_IX86)
    BYTE *peb = (BYTE *)(uintptr_t)__readfsdword(0x30);
    LPVOID *image_base;
    LPVOID old_base;
    if (peb == NULL) return NULL;
    image_base = (LPVOID *)(peb + 0x08);
    old_base = *image_base;
    *image_base = new_base;
    return old_base;
#else
    (void)new_base;
    return NULL;
#endif
}

static int pic_native_magic(const uint8_t magic[PBF_NATIVE_MAGIC_SIZE]) {
    return magic[0] == 'P' && magic[1] == 'B' && magic[2] == 'F' && magic[3] == 'N' &&
        magic[4] == 'A' && magic[5] == 'T' && magic[6] == '3' && magic[7] == 0;
}

static char pic_lower(char value) {
    if (value >= 'A' && value <= 'Z') return (char)(value + ('a' - 'A'));
    return value;
}

static int pic_string_equal_ci(const char *left, const char *right) {
    SIZE_T index;
    if (left == NULL || right == NULL) return 0;
    for (index = 0; index < PBF_NATIVE_MODULE_NAME_SIZE; ++index) {
        char a = pic_lower(left[index]);
        char b = pic_lower(right[index]);
        if (a != b) return 0;
        if (a == 0) return 1;
    }
    return 0;
}

static int pic_module_name_valid(const char name[PBF_NATIVE_MODULE_NAME_SIZE]) {
    uint32_t index;
    if (name[0] == 0) return 0;
    for (index = 0; index < PBF_NATIVE_MODULE_NAME_SIZE; ++index) {
        if (name[index] == 0) return 1;
    }
    return 0;
}

static int pic_image_range(const pic_map_state *state, uint32_t rva, SIZE_T length) {
    return pic_range_u64(rva, length, state->size);
}

static void *pic_image_pointer(const pic_map_state *state, uint32_t rva, SIZE_T length) {
    if (!pic_image_range(state, rva, length)) return NULL;
    return state->base + rva;
}

static const char *pic_image_string(const pic_map_state *state, uint32_t rva) {
    const char *text;
    SIZE_T index;
    SIZE_T remaining;
    if (!pic_image_range(state, rva, 1)) return NULL;
    text = (const char *)(state->base + rva);
    remaining = state->size - rva;
    for (index = 0; index < remaining; ++index) {
        if (text[index] == 0) return text;
    }
    return NULL;
}

static int pic_is_pbf_entry_name(const char *name) {
    const char *value = name;
    if (value == NULL) return 0;
    if (*value == '_' || *value == '@') ++value;
    if (value[0] != 'P' || value[1] != 'b' || value[2] != 'f' ||
        value[3] != 'E' || value[4] != 'n' || value[5] != 't' ||
        value[6] != 'r' || value[7] != 'y') return 0;
    return value[8] == 0 ||
        (value[8] == '@' && value[9] == '4' && value[10] == 0);
}

static int pic_parse_raw_image(const BYTE *data, uint32_t size, int allow_exe,
                               pic_raw_view *view) {
    const IMAGE_DOS_HEADER *dos;
    const pic_nt_headers *nt;
    const IMAGE_SECTION_HEADER *sections;
    uint64_t nt_offset;
    uint64_t section_offset;
    uint16_t index;
    pic_zero(view, sizeof(*view));
    if (!pic_range_u64(0, sizeof(*dos), size)) return 0;
    dos = (const IMAGE_DOS_HEADER *)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    nt_offset = (uint32_t)dos->e_lfanew;
    if (!pic_range_u64(nt_offset, sizeof(*nt), size)) return 0;
    nt = (const pic_nt_headers *)(data + nt_offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != PIC_IMAGE_MACHINE ||
        (!allow_exe && (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) ||
        nt->OptionalHeader.Magic != PIC_OPTIONAL_MAGIC ||
        nt->FileHeader.NumberOfSections == 0 ||
        nt->FileHeader.NumberOfSections > PIC_MAX_SECTIONS ||
        nt->OptionalHeader.SizeOfImage == 0 ||
        nt->OptionalHeader.SizeOfImage > PBF_NATIVE_MAX_BUNDLE ||
        nt->OptionalHeader.SizeOfHeaders == 0 ||
        nt->OptionalHeader.SizeOfHeaders > size ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR ||
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0)
        return 0;
    section_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        nt->FileHeader.SizeOfOptionalHeader;
    if (!pic_range_u64(section_offset,
        (uint64_t)nt->FileHeader.NumberOfSections * sizeof(*sections), size)) return 0;
    sections = (const IMAGE_SECTION_HEADER *)(data + section_offset);
    for (index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        uint64_t mapped_size = sections[index].Misc.VirtualSize;
        if (mapped_size < sections[index].SizeOfRawData)
            mapped_size = sections[index].SizeOfRawData;
        if (mapped_size != 0 && !pic_range_u64(sections[index].VirtualAddress,
            mapped_size, nt->OptionalHeader.SizeOfImage)) return 0;
        if (sections[index].SizeOfRawData != 0 &&
            !pic_range_u64(sections[index].PointerToRawData,
                sections[index].SizeOfRawData, size)) return 0;
    }
    view->data = data;
    view->size = size;
    view->nt = nt;
    view->sections = sections;
    return 1;
}

static void pic_copy_image(const pic_raw_view *view, pic_map_state *state) {
    uint16_t index;
    pic_copy(state->base, view->data, view->nt->OptionalHeader.SizeOfHeaders);
    for (index = 0; index < view->nt->FileHeader.NumberOfSections; ++index) {
        const IMAGE_SECTION_HEADER *section = &view->sections[index];
        if (section->SizeOfRawData != 0) {
            pic_copy(state->base + section->VirtualAddress,
                view->data + section->PointerToRawData, section->SizeOfRawData);
        }
    }
}

static int pic_apply_relocations(const pic_raw_view *view, pic_map_state *state) {
    const IMAGE_DATA_DIRECTORY *directory =
        &view->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    intptr_t delta = (intptr_t)state->base - (intptr_t)view->nt->OptionalHeader.ImageBase;
    uint32_t consumed = 0;
    if (delta == 0) return 1;
    if (directory->VirtualAddress == 0 || directory->Size < sizeof(IMAGE_BASE_RELOCATION) ||
        !pic_image_range(state, directory->VirtualAddress, directory->Size)) return 0;
    while (consumed < directory->Size) {
        IMAGE_BASE_RELOCATION *block;
        WORD *entries;
        uint32_t entry_count;
        uint32_t index;
        if (directory->Size - consumed < sizeof(*block)) return 0;
        block = (IMAGE_BASE_RELOCATION *)(state->base + directory->VirtualAddress + consumed);
        if (block->SizeOfBlock < sizeof(*block) ||
            block->SizeOfBlock > directory->Size - consumed) return 0;
        entry_count = (block->SizeOfBlock - sizeof(*block)) / sizeof(WORD);
        entries = (WORD *)(block + 1);
        for (index = 0; index < entry_count; ++index) {
            WORD type = entries[index] >> 12;
            WORD offset = entries[index] & 0x0fff;
            BYTE *patch;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            if (type != PIC_RELOCATION_TYPE) return 0;
#if defined(_M_IX86)
            patch = (BYTE *)pic_image_pointer(state,
                block->VirtualAddress + offset, sizeof(uint32_t));
            if (patch == NULL) return 0;
            *(uint32_t *)patch += (uint32_t)delta;
#else
            patch = (BYTE *)pic_image_pointer(state,
                block->VirtualAddress + offset, sizeof(uint64_t));
            if (patch == NULL) return 0;
            *(uint64_t *)patch += (uint64_t)delta;
#endif
        }
        consumed += block->SizeOfBlock;
    }
    return consumed == directory->Size;
}

static int pic_find_embedded_module(const pic_bundle_state *bundle,
                                    const char *name) {
    uint32_t index;
    for (index = 0; index < bundle->context->module_count; ++index) {
        if (pic_string_equal_ci(bundle->records[index].name, name)) return (int)index;
    }
    return -1;
}

static FARPROC pic_find_export(const pic_raw_view *view,
                               const pic_map_state *state,
                               LPCSTR requested) {
    const IMAGE_DATA_DIRECTORY *directory =
        &view->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *exports;
    DWORD *functions;
    DWORD function_index = UINT32_MAX;
    DWORD function_rva;
    if (directory->VirtualAddress == 0 || directory->Size < sizeof(*exports)) return NULL;
    exports = (IMAGE_EXPORT_DIRECTORY *)pic_image_pointer(state,
        directory->VirtualAddress, sizeof(*exports));
    if (exports == NULL || exports->NumberOfFunctions == 0 ||
        exports->NumberOfFunctions > PIC_MAX_IMPORTS ||
        exports->NumberOfNames > PIC_MAX_IMPORTS) return NULL;
    functions = (DWORD *)pic_image_pointer(state, exports->AddressOfFunctions,
        exports->NumberOfFunctions * sizeof(DWORD));
    if (functions == NULL) return NULL;
    if ((uintptr_t)requested <= 0xffffU) {
        DWORD ordinal = (DWORD)(uintptr_t)requested;
        if (ordinal < exports->Base || ordinal - exports->Base >= exports->NumberOfFunctions)
            return NULL;
        function_index = ordinal - exports->Base;
    } else {
        DWORD *names = (DWORD *)pic_image_pointer(state, exports->AddressOfNames,
            exports->NumberOfNames * sizeof(DWORD));
        WORD *ordinals = (WORD *)pic_image_pointer(state, exports->AddressOfNameOrdinals,
            exports->NumberOfNames * sizeof(WORD));
        DWORD index;
        if (names == NULL || ordinals == NULL) return NULL;
        for (index = 0; index < exports->NumberOfNames; ++index) {
            const char *name = pic_image_string(state, names[index]);
            const char *left = name;
            const char *right = requested;
            if (name == NULL) return NULL;
            while (*left != 0 && *left == *right) { ++left; ++right; }
            if (*left == 0 && *right == 0) {
                if (ordinals[index] >= exports->NumberOfFunctions) return NULL;
                function_index = ordinals[index];
                break;
            }
        }
    }
    if (function_index == UINT32_MAX) return NULL;
    function_rva = functions[function_index];
    /* Forwarded exports are intentionally rejected in embedded private DLLs. */
    if (function_rva >= directory->VirtualAddress &&
        function_rva < directory->VirtualAddress + directory->Size) return NULL;
    return (FARPROC)pic_image_pointer(state, function_rva, 1);
}

static int pic_map_module(pic_bundle_state *bundle, uint32_t module_index);

static int pic_resolve_imports(const pic_raw_view *view, pic_map_state *state,
                               pic_bundle_state *bundle) {
    const IMAGE_DATA_DIRECTORY *directory =
        &view->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    uint32_t descriptor_limit;
    uint32_t descriptor_index;
    const pbf_native_api *api = &bundle->context->api;
    if (directory->VirtualAddress == 0 || directory->Size == 0) return 1;
    if (!pic_image_range(state, directory->VirtualAddress, directory->Size)) return 0;
    descriptor_limit = directory->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (descriptor_limit > PIC_MAX_IMPORTS) descriptor_limit = PIC_MAX_IMPORTS;
    for (descriptor_index = 0; descriptor_index < descriptor_limit; ++descriptor_index) {
        IMAGE_IMPORT_DESCRIPTOR *descriptor = (IMAGE_IMPORT_DESCRIPTOR *)pic_image_pointer(
            state, directory->VirtualAddress + descriptor_index * sizeof(*descriptor),
            sizeof(*descriptor));
        const char *module_name;
        HMODULE external_module = NULL;
        int embedded_index;
        uint32_t lookup_rva;
        uint32_t address_rva;
        uint32_t thunk_index;
        if (descriptor == NULL) return 0;
        if (descriptor->Name == 0 && descriptor->FirstThunk == 0) return 1;
        module_name = pic_image_string(state, descriptor->Name);
        if (module_name == NULL) return 0;
        embedded_index = pic_find_embedded_module(bundle, module_name);
        if (embedded_index >= 0) {
            if (!pic_map_module(bundle, (uint32_t)embedded_index)) return 0;
        } else {
            if (state->external_module_count >= PIC_MAX_EXTERNAL_MODULES) return 0;
            external_module = api->load_library_a(module_name);
            if (external_module == NULL) return 0;
            state->external_modules[state->external_module_count++] = external_module;
        }
        lookup_rva = descriptor->OriginalFirstThunk != 0 ?
            descriptor->OriginalFirstThunk : descriptor->FirstThunk;
        address_rva = descriptor->FirstThunk;
        for (thunk_index = 0; thunk_index < PIC_MAX_IMPORTS; ++thunk_index) {
            pic_thunk_data *lookup = (pic_thunk_data *)pic_image_pointer(state,
                lookup_rva + thunk_index * sizeof(*lookup), sizeof(*lookup));
            pic_thunk_data *address = (pic_thunk_data *)pic_image_pointer(state,
                address_rva + thunk_index * sizeof(*address), sizeof(*address));
            LPCSTR requested;
            FARPROC procedure;
            if (lookup == NULL || address == NULL) return 0;
            if (lookup->u1.AddressOfData == 0) break;
#if defined(_M_IX86)
            if (IMAGE_SNAP_BY_ORDINAL32(lookup->u1.Ordinal)) {
                requested = (LPCSTR)(uintptr_t)IMAGE_ORDINAL32(lookup->u1.Ordinal);
#else
            if (IMAGE_SNAP_BY_ORDINAL64(lookup->u1.Ordinal)) {
                requested = (LPCSTR)(uintptr_t)IMAGE_ORDINAL64(lookup->u1.Ordinal);
#endif
            } else {
                IMAGE_IMPORT_BY_NAME *by_name = (IMAGE_IMPORT_BY_NAME *)pic_image_pointer(
                    state, (uint32_t)lookup->u1.AddressOfData, sizeof(WORD) + 1);
                if (by_name == NULL || pic_image_string(state,
                    (uint32_t)lookup->u1.AddressOfData +
                    (uint32_t)offsetof(IMAGE_IMPORT_BY_NAME, Name)) == NULL) return 0;
                requested = (LPCSTR)by_name->Name;
            }
            if (embedded_index >= 0) {
                procedure = pic_find_export(&bundle->views[embedded_index],
                    &bundle->maps[embedded_index], requested);
            } else {
                procedure = api->get_proc_address(external_module, requested);
            }
            if (procedure == NULL) return 0;
            address->u1.Function = (uintptr_t)procedure;
        }
        if (thunk_index == PIC_MAX_IMPORTS) return 0;
    }
    return 0;
}

static DWORD pic_section_protection(DWORD characteristics) {
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

static int pic_apply_protections(const pic_raw_view *view, pic_map_state *state,
                                 const pbf_native_api *api) {
    DWORD old_protection;
    uint16_t index;
    if (!api->virtual_protect(state->base, view->nt->OptionalHeader.SizeOfHeaders,
                              PAGE_READONLY, &old_protection)) return 0;
    for (index = 0; index < view->nt->FileHeader.NumberOfSections; ++index) {
        const IMAGE_SECTION_HEADER *section = &view->sections[index];
        SIZE_T size = section->Misc.VirtualSize;
        if (size < section->SizeOfRawData) size = section->SizeOfRawData;
        if (size != 0 && !api->virtual_protect(state->base + section->VirtualAddress,
            size, pic_section_protection(section->Characteristics), &old_protection)) return 0;
    }
    return api->flush_instruction_cache(api->get_current_process(),
        state->base, state->size) != 0;
}

static int pic_register_exceptions(const pic_raw_view *view, pic_map_state *state,
                                   const pbf_native_api *api) {
#if defined(_M_IX86)
    (void)view;
    (void)state;
    (void)api;
    return 1;
#else
    const IMAGE_DATA_DIRECTORY *directory =
        &view->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (directory->VirtualAddress == 0 || directory->Size == 0) return 1;
    if (directory->Size % sizeof(RUNTIME_FUNCTION) != 0) return 0;
    state->function_table = (PRUNTIME_FUNCTION)pic_image_pointer(state,
        directory->VirtualAddress, directory->Size);
    if (state->function_table == NULL || api->rtl_add_function_table == NULL) return 0;
    state->function_count = directory->Size / sizeof(RUNTIME_FUNCTION);
    if (!api->rtl_add_function_table(state->function_table, state->function_count,
                                     (DWORD64)(uintptr_t)state->base)) return 0;
    state->function_table_registered = 1;
    return 1;
#endif
}

static int pic_run_tls(const pic_raw_view *view, pic_map_state *state, DWORD reason) {
    const IMAGE_DATA_DIRECTORY *directory =
        &view->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    pic_tls_directory *tls;
    PIMAGE_TLS_CALLBACK *callbacks;
    uintptr_t callback_array;
    uint32_t index;
    if (directory->VirtualAddress == 0 || directory->Size == 0) return 1;
    tls = (pic_tls_directory *)pic_image_pointer(state,
        directory->VirtualAddress, sizeof(*tls));
    if (tls == NULL || tls->AddressOfCallBacks == 0) return tls != NULL;
    callback_array = (uintptr_t)tls->AddressOfCallBacks;
    if (callback_array < (uintptr_t)state->base ||
        callback_array >= (uintptr_t)state->base + state->size) return 0;
    callbacks = (PIMAGE_TLS_CALLBACK *)callback_array;
    for (index = 0; index < PIC_MAX_TLS_CALLBACKS; ++index) {
        uintptr_t address;
        if ((BYTE *)&callbacks[index] + sizeof(callbacks[index]) >
            state->base + state->size) return 0;
        if (callbacks[index] == NULL) return 1;
        address = (uintptr_t)callbacks[index];
        if (address < (uintptr_t)state->base ||
            address >= (uintptr_t)state->base + state->size) return 0;
        callbacks[index]((PVOID)state->base, reason, NULL);
    }
    return 0;
}

static int pic_map_module(pic_bundle_state *bundle, uint32_t module_index) {
    const pbf_native_module_record *record;
    pic_raw_view *view;
    pic_map_state *state;
    const pbf_native_api *api = &bundle->context->api;
    if (module_index >= bundle->context->module_count) return 0;
    if (bundle->phase[module_index] != 0) return 1;
    record = &bundle->records[module_index];
    view = &bundle->views[module_index];
    state = &bundle->maps[module_index];
    if (!pic_parse_raw_image(bundle->context->bundle_base + record->offset,
            record->size, (record->flags & PBF_NATIVE_MODULE_EXE) != 0, view)) return 0;
    pic_zero(state, sizeof(*state));
    state->size = view->nt->OptionalHeader.SizeOfImage;
    state->base = (BYTE *)api->virtual_alloc(
        (LPVOID)(uintptr_t)view->nt->OptionalHeader.ImageBase, state->size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (state->base != NULL) state->owns_base = 1;
#if defined(_M_IX86)
    if (state->base == NULL && (record->flags & PBF_NATIVE_MODULE_EXE) != 0 &&
        bundle->context->allow_host_image_reuse != 0) {
        BYTE *host_base = (BYTE *)(uintptr_t)__readfsdword(0x30);
        DWORD old_protection;
        host_base = *(BYTE **)(host_base + 0x08);
        if ((uintptr_t)host_base == (uintptr_t)view->nt->OptionalHeader.ImageBase &&
            pic_host_image_size(host_base) >= state->size &&
            api->virtual_protect(host_base, state->size, PAGE_READWRITE,
                                 &old_protection)) {
            state->base = host_base;
            state->owns_base = 0;
        }
    }
#endif
    if (state->base == NULL) {
        state->base = (BYTE *)api->virtual_alloc(NULL, state->size,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (state->base != NULL) state->owns_base = 1;
    }
    if (state->base == NULL) return 0;
    pic_copy_image(view, state);
    if (!pic_apply_relocations(view, state)) return 0;
    bundle->phase[module_index] = 1;
    if (!pic_resolve_imports(view, state, bundle)) return 0;
    if (!pic_register_exceptions(view, state, api)) return 0;
    if (!pic_apply_protections(view, state, api)) return 0;
    if (!pic_run_tls(view, state, DLL_PROCESS_ATTACH)) return 0;
    state->tls_attached = 1;
    if ((record->flags & PBF_NATIVE_MODULE_EXE) == 0 &&
        view->nt->OptionalHeader.AddressOfEntryPoint != 0) {
        state->dll_entry = (pic_dll_entry_fn)pic_image_pointer(state,
            view->nt->OptionalHeader.AddressOfEntryPoint, 1);
        if (state->dll_entry == NULL ||
            !state->dll_entry((HINSTANCE)state->base, DLL_PROCESS_ATTACH, NULL)) return 0;
        state->process_attached = 1;
    }
    bundle->phase[module_index] = 2;
    bundle->load_order[bundle->load_count++] = (uint8_t)module_index;
    return 1;
}

static void pic_cleanup_one(const pic_raw_view *view, pic_map_state *state,
                            const pbf_native_api *api) {
    uint32_t index;
    if (state->process_attached && state->dll_entry != NULL)
        state->dll_entry((HINSTANCE)state->base, DLL_PROCESS_DETACH, NULL);
    if (state->tls_attached) pic_run_tls(view, state, DLL_PROCESS_DETACH);
    if (state->function_table_registered && api->rtl_delete_function_table != NULL)
        api->rtl_delete_function_table(state->function_table);
    for (index = state->external_module_count; index > 0; --index)
        api->free_library(state->external_modules[index - 1]);
    if (state->base != NULL && state->owns_base)
        api->virtual_free(state->base, 0, MEM_RELEASE);
    pic_zero(state, sizeof(*state));
}

static void pic_cleanup_bundle(pic_bundle_state *bundle) {
    uint8_t cleaned[PBF_NATIVE_MAX_EMBEDDED_MODULES];
    uint32_t index;
    pic_zero(cleaned, sizeof(cleaned));
    for (index = bundle->load_count; index > 0; --index) {
        uint32_t module_index = bundle->load_order[index - 1];
        pic_cleanup_one(&bundle->views[module_index], &bundle->maps[module_index],
                        &bundle->context->api);
        cleaned[module_index] = 1;
    }
    for (index = 0; index < bundle->context->module_count; ++index) {
        if (!cleaned[index] && bundle->maps[index].base != NULL)
            pic_cleanup_one(&bundle->views[index], &bundle->maps[index],
                            &bundle->context->api);
    }
}

__declspec(dllexport) uint64_t __fastcall PbfNativeEntry(pbf_native_context *context) {
    pic_bundle_state *bundle;
    const pbf_native_module_record *primary_record;
    pic_map_state *primary_state;
    pic_raw_view *primary_view;
    pbf_entry_fn payload_entry;
    uint64_t result = 0;
    uint32_t index;
    if (context == NULL || context->size != sizeof(*context) ||
        context->abi_version != PBF_NATIVE_ABI_VERSION ||
        context->bundle_base == NULL || context->bundle_size > PBF_NATIVE_MAX_BUNDLE ||
        context->module_count == 0 ||
        context->module_count > PBF_NATIVE_MAX_EMBEDDED_MODULES ||
        context->primary_module_index >= context->module_count ||
        context->workspace == NULL ||
        context->workspace_size < sizeof(pic_bundle_state) ||
        !pic_range_u64(context->module_table_offset,
            (uint64_t)context->module_count * sizeof(pbf_native_module_record),
            context->bundle_size) ||
        context->api.virtual_alloc == NULL || context->api.virtual_free == NULL ||
        context->api.virtual_protect == NULL || context->api.load_library_a == NULL ||
        context->api.free_library == NULL || context->api.get_proc_address == NULL ||
        context->api.flush_instruction_cache == NULL ||
        context->api.get_current_process == NULL) {
        if (context != NULL) context->status = PBF_NATIVE_STATUS_BAD_CONTEXT;
        return 0;
    }
    bundle = (pic_bundle_state *)context->workspace;
    pic_zero(bundle, sizeof(*bundle));
    bundle->context = context;
    bundle->records = (const pbf_native_module_record *)(context->bundle_base +
        context->module_table_offset);
    for (index = 0; index < context->module_count; ++index) {
        if (!pic_module_name_valid(bundle->records[index].name) ||
            bundle->records[index].reserved != 0 ||
            (index != context->primary_module_index &&
             (bundle->records[index].flags & PBF_NATIVE_MODULE_EXE) != 0) ||
            !pic_range_u64(bundle->records[index].offset, bundle->records[index].size,
                           context->bundle_size)) {
            context->status = PBF_NATIVE_STATUS_BAD_IMAGE;
            return 0;
        }
    }
    primary_record = &bundle->records[context->primary_module_index];
    if ((primary_record->flags & PBF_NATIVE_MODULE_PRIMARY) == 0 ||
        primary_record->offset != context->dll_offset ||
        primary_record->size != context->dll_size) {
        context->status = PBF_NATIVE_STATUS_BAD_IMAGE;
        return 0;
    }
    context->status = PBF_NATIVE_STATUS_BAD_IMAGE;
    if (!pic_map_module(bundle, context->primary_module_index)) {
        context->status = PBF_NATIVE_STATUS_IMPORT_FAILED;
        pic_cleanup_bundle(bundle);
        return 0;
    }
    primary_state = &bundle->maps[context->primary_module_index];
    primary_view = &bundle->views[context->primary_module_index];
    context->mapped_at_preferred_base =
        (uintptr_t)primary_state->base == (uintptr_t)primary_view->nt->OptionalHeader.ImageBase;
    if ((primary_record->flags & PBF_NATIVE_MODULE_EXE) != 0) {
        pic_exe_entry_fn exe_entry;
        LPVOID old_image_base;
        if (primary_view->nt->OptionalHeader.AddressOfEntryPoint == 0) {
            context->status = PBF_NATIVE_STATUS_EXPORT_FAILED;
            pic_cleanup_bundle(bundle);
            return 0;
        }
        exe_entry = (pic_exe_entry_fn)pic_image_pointer(primary_state,
            primary_view->nt->OptionalHeader.AddressOfEntryPoint, 1);
        if (exe_entry == NULL) {
            context->status = PBF_NATIVE_STATUS_EXPORT_FAILED;
            pic_cleanup_bundle(bundle);
            return 0;
        }
        context->status = PBF_NATIVE_STATUS_OK;
        old_image_base = pic_swap_process_image_base(primary_state->base);
        exe_entry();
        pic_swap_process_image_base(old_image_base);
        result = PBF_RESULT_OK;
        pic_cleanup_bundle(bundle);
        return result;
    }
    payload_entry = NULL;
    /* Find PbfEntry by name without introducing a string literal relocation. */
    if (payload_entry == NULL) {
        const IMAGE_DATA_DIRECTORY *directory =
            &primary_view->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)pic_image_pointer(
            primary_state, directory->VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY));
        if (exports != NULL && exports->NumberOfNames <= PIC_MAX_IMPORTS) {
            DWORD *names = (DWORD *)pic_image_pointer(primary_state, exports->AddressOfNames,
                exports->NumberOfNames * sizeof(DWORD));
            WORD *ordinals = (WORD *)pic_image_pointer(primary_state,
                exports->AddressOfNameOrdinals, exports->NumberOfNames * sizeof(WORD));
            DWORD *functions = (DWORD *)pic_image_pointer(primary_state,
                exports->AddressOfFunctions, exports->NumberOfFunctions * sizeof(DWORD));
            if (names != NULL && ordinals != NULL && functions != NULL) {
                for (index = 0; index < exports->NumberOfNames; ++index) {
                    const char *name = pic_image_string(primary_state, names[index]);
                    if (pic_is_pbf_entry_name(name) &&
                        ordinals[index] < exports->NumberOfFunctions) {
                        DWORD rva = functions[ordinals[index]];
                        if (!(rva >= directory->VirtualAddress &&
                              rva < directory->VirtualAddress + directory->Size))
                            payload_entry = (pbf_entry_fn)pic_image_pointer(primary_state, rva, 1);
                        break;
                    }
                }
            }
        }
    }
    if (payload_entry == NULL) {
        context->status = PBF_NATIVE_STATUS_EXPORT_FAILED;
        pic_cleanup_bundle(bundle);
        return 0;
    }
    result = payload_entry(&context->payload);
    context->status = result == PBF_RESULT_OK ?
        PBF_NATIVE_STATUS_OK : PBF_NATIVE_STATUS_ENTRY_FAILED;
    pic_cleanup_bundle(bundle);
    return result;
}

__declspec(dllexport) uint64_t __fastcall PbfNativeStandalone(BYTE *bundle_base) {
    const pbf_native_footer *header;
    const pbf_native_footer *footer;
    pbf_native_context context;
    BYTE *workspace;
    uint64_t result;
    if (bundle_base == NULL) return 0;
    header = (const pbf_native_footer *)(bundle_base + PBF_NATIVE_HEADER_OFFSET);
    if (!pic_native_magic(header->magic) ||
        header->version != PBF_NATIVE_ABI_VERSION ||
        header->architecture != PBF_NATIVE_ARCH_CURRENT ||
        header->total_size < PBF_NATIVE_HEADER_OFFSET + sizeof(*header) + sizeof(*footer) ||
        header->total_size > PBF_NATIVE_MAX_BUNDLE ||
        header->code_size < PBF_NATIVE_HEADER_OFFSET + sizeof(*header) ||
        header->code_size > header->total_size - sizeof(*footer) ||
        header->entry_offset >= header->code_size ||
        header->standalone_entry_offset >= header->code_size ||
        header->module_table_offset < header->code_size ||
        header->dll_offset < header->code_size ||
        !pic_range_u64(header->dll_offset, header->dll_size,
                       header->total_size - sizeof(*footer)) ||
        header->module_count == 0 ||
        header->module_count > PBF_NATIVE_MAX_EMBEDDED_MODULES ||
        header->primary_module_index >= header->module_count ||
        !pic_range_u64(header->module_table_offset,
            (uint64_t)header->module_count * sizeof(pbf_native_module_record),
            header->total_size - sizeof(*footer))) return 0;
    footer = (const pbf_native_footer *)(bundle_base + header->total_size - sizeof(*footer));
    if (!pic_equal(header, footer, sizeof(*header))) return 0;

    pic_zero(&context, sizeof(context));
    context.api.virtual_alloc = (pbf_virtual_alloc_fn)pic_find_loaded_export(
        PIC_HASH_VIRTUAL_ALLOC);
    context.api.virtual_free = (pbf_virtual_free_fn)pic_find_loaded_export(
        PIC_HASH_VIRTUAL_FREE);
    context.api.virtual_protect = (pbf_virtual_protect_fn)pic_find_loaded_export(
        PIC_HASH_VIRTUAL_PROTECT);
    context.api.load_library_a = (pbf_load_library_a_fn)pic_find_loaded_export(
        PIC_HASH_LOAD_LIBRARY_A);
    context.api.free_library = (pbf_free_library_fn)pic_find_loaded_export(
        PIC_HASH_FREE_LIBRARY);
    context.api.get_proc_address = (pbf_get_proc_address_fn)pic_find_loaded_export(
        PIC_HASH_GET_PROC_ADDRESS);
    context.api.flush_instruction_cache =
        (pbf_flush_instruction_cache_fn)pic_find_loaded_export(
            PIC_HASH_FLUSH_INSTRUCTION);
#if defined(_M_X64)
    context.api.rtl_add_function_table =
        (pbf_rtl_add_function_table_fn)pic_find_loaded_export(
            PIC_HASH_RTL_ADD_FUNCTION);
    context.api.rtl_delete_function_table =
        (pbf_rtl_delete_function_table_fn)pic_find_loaded_export(
            PIC_HASH_RTL_DELETE_FUNCTION);
#endif
    context.api.get_current_process =
        (pbf_get_current_process_fn)pic_find_loaded_export(
            PIC_HASH_GET_CURRENT_PROCESS);
    if (context.api.virtual_alloc == NULL || context.api.virtual_free == NULL ||
        context.api.virtual_protect == NULL || context.api.load_library_a == NULL ||
        context.api.free_library == NULL || context.api.get_proc_address == NULL ||
        context.api.flush_instruction_cache == NULL ||
        context.api.get_current_process == NULL) return 0;
#if defined(_M_X64)
    if (context.api.rtl_add_function_table == NULL ||
        context.api.rtl_delete_function_table == NULL) return 0;
#endif

    workspace = (BYTE *)context.api.virtual_alloc(NULL, PBF_NATIVE_PIC_WORKSPACE_SIZE,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (workspace == NULL) return 0;
    context.size = sizeof(context);
    context.abi_version = PBF_NATIVE_ABI_VERSION;
    context.bundle_base = bundle_base;
    context.bundle_size = header->total_size;
    context.dll_offset = header->dll_offset;
    context.dll_size = header->dll_size;
    context.module_table_offset = header->module_table_offset;
    context.module_count = header->module_count;
    context.primary_module_index = header->primary_module_index;
    context.workspace = workspace;
    context.workspace_size = PBF_NATIVE_PIC_WORKSPACE_SIZE;
    context.allow_host_image_reuse = 1;
    context.payload.size = sizeof(context.payload);
    context.payload.abi_version = PBF_ABI_VERSION;
    context.payload.input_a = 40;
    context.payload.input_b = 2;
    result = PbfNativeEntry(&context);
    context.api.virtual_free(workspace, 0, MEM_RELEASE);
    return result;
}

#pragma code_seg(pop)
