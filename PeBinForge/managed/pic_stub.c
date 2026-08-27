/* Import-free x86/x64 PIC CLR v4 host for PeBinForge managed raw bundles. */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#define CINTERFACE
#define COBJMACROS

#include <windows.h>
#include <metahost.h>
#include <mscoree.h>
#include <oleauto.h>
#include <intrin.h>
#include <stdint.h>
#include <stddef.h>

#include "pbf_managed.h"

#define PIC_MAX_LOADED_MODULES 256U
#define PIC_MAX_LOADED_EXPORTS 16384U
#define PIC_MAX_EXPORT_NAME 256U

#define PIC_HASH_LOAD_LIBRARY_A          UINT32_C(0x53b2070f)
#define PIC_HASH_CO_INITIALIZE_EX        UINT32_C(0x4cacfe40)
#define PIC_HASH_CO_UNINITIALIZE         UINT32_C(0xa0f3063e)
#define PIC_HASH_SAFE_ARRAY_CREATE       UINT32_C(0x07536a8d)
#define PIC_HASH_SAFE_ARRAY_VECTOR       UINT32_C(0xc20c62ba)
#define PIC_HASH_SAFE_ARRAY_ACCESS       UINT32_C(0xa2ae57e3)
#define PIC_HASH_SAFE_ARRAY_UNACCESS     UINT32_C(0x5c92c994)
#define PIC_HASH_SAFE_ARRAY_DESTROY      UINT32_C(0xce87be55)
#define PIC_HASH_VARIANT_CHANGE_TYPE     UINT32_C(0x0b12ff02)
#define PIC_HASH_VARIANT_CLEAR           UINT32_C(0xbfc8e6d7)
#define PIC_HASH_CLR_CREATE_INSTANCE     UINT32_C(0xc5688927)

#if defined(_M_IX86)
typedef IMAGE_NT_HEADERS32 pic_nt_headers;
#define PIC_OPTIONAL_MAGIC IMAGE_NT_OPTIONAL_HDR32_MAGIC
#else
typedef IMAGE_NT_HEADERS64 pic_nt_headers;
#define PIC_OPTIONAL_MAGIC IMAGE_NT_OPTIONAL_HDR64_MAGIC
#endif

typedef HRESULT (WINAPI *pic_co_initialize_ex_fn)(LPVOID, DWORD);
typedef void (WINAPI *pic_co_uninitialize_fn)(void);
typedef SAFEARRAY *(WINAPI *pic_safe_array_create_fn)(VARTYPE, UINT, SAFEARRAYBOUND *);
typedef SAFEARRAY *(WINAPI *pic_safe_array_create_vector_fn)(VARTYPE, LONG, ULONG);
typedef HRESULT (WINAPI *pic_safe_array_access_data_fn)(SAFEARRAY *, void **);
typedef HRESULT (WINAPI *pic_safe_array_unaccess_data_fn)(SAFEARRAY *);
typedef HRESULT (WINAPI *pic_safe_array_destroy_fn)(SAFEARRAY *);
typedef HRESULT (WINAPI *pic_variant_change_type_fn)(VARIANTARG *, const VARIANTARG *, USHORT, VARTYPE);
typedef HRESULT (WINAPI *pic_variant_clear_fn)(VARIANTARG *);
typedef HRESULT (WINAPI *pic_clr_create_instance_fn)(REFCLSID, REFIID, LPVOID *);
typedef HMODULE (WINAPI *pic_load_library_a_fn)(LPCSTR);

typedef struct pic_managed_api_t {
    pic_load_library_a_fn load_library_a;
    pic_co_initialize_ex_fn co_initialize_ex;
    pic_co_uninitialize_fn co_uninitialize;
    pic_safe_array_create_fn safe_array_create;
    pic_safe_array_create_vector_fn safe_array_create_vector;
    pic_safe_array_access_data_fn safe_array_access_data;
    pic_safe_array_unaccess_data_fn safe_array_unaccess_data;
    pic_safe_array_destroy_fn safe_array_destroy;
    pic_variant_change_type_fn variant_change_type;
    pic_variant_clear_fn variant_clear;
    pic_clr_create_instance_fn clr_create_instance;
} pic_managed_api;

typedef struct pic_clr_host_t {
    ICLRMetaHost *meta_host;
    ICLRRuntimeInfo *runtime_info;
    ICorRuntimeHost *runtime_host;
    IUnknown *domain_unknown;
    IDispatch *domain_dispatch;
    int com_initialized;
    int runtime_started;
} pic_clr_host;

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

static void pic_set_guid(GUID *guid, uint32_t data1, uint16_t data2, uint16_t data3,
                         BYTE d0, BYTE d1, BYTE d2, BYTE d3,
                         BYTE d4, BYTE d5, BYTE d6, BYTE d7) {
    guid->Data1 = data1;
    guid->Data2 = data2;
    guid->Data3 = data3;
    guid->Data4[0] = d0; guid->Data4[1] = d1;
    guid->Data4[2] = d2; guid->Data4[3] = d3;
    guid->Data4[4] = d4; guid->Data4[5] = d5;
    guid->Data4[6] = d6; guid->Data4[7] = d7;
}

static void pic_set_runtime_name(WCHAR name[11]) {
    name[0] = L'v'; name[1] = L'4'; name[2] = L'.'; name[3] = L'0';
    name[4] = L'.'; name[5] = L'3'; name[6] = L'0'; name[7] = L'3';
    name[8] = L'1'; name[9] = L'9'; name[10] = 0;
}

static void pic_set_dll_names(char ole32[10], char oleaut32[13], char mscoree[12]) {
    ole32[0] = 'o'; ole32[1] = 'l'; ole32[2] = 'e'; ole32[3] = '3';
    ole32[4] = '2'; ole32[5] = '.'; ole32[6] = 'd'; ole32[7] = 'l';
    ole32[8] = 'l'; ole32[9] = 0;
    oleaut32[0] = 'o'; oleaut32[1] = 'l'; oleaut32[2] = 'e'; oleaut32[3] = 'a';
    oleaut32[4] = 'u'; oleaut32[5] = 't'; oleaut32[6] = '3'; oleaut32[7] = '2';
    oleaut32[8] = '.'; oleaut32[9] = 'd'; oleaut32[10] = 'l'; oleaut32[11] = 'l';
    oleaut32[12] = 0;
    mscoree[0] = 'm'; mscoree[1] = 's'; mscoree[2] = 'c'; mscoree[3] = 'o';
    mscoree[4] = 'r'; mscoree[5] = 'e'; mscoree[6] = 'e'; mscoree[7] = '.';
    mscoree[8] = 'd'; mscoree[9] = 'l'; mscoree[10] = 'l'; mscoree[11] = 0;
}

static int pic_resolve_managed_api(pic_managed_api *api) {
    char ole32[10];
    char oleaut32[13];
    char mscoree[12];
    pic_zero(api, sizeof(*api));
    api->load_library_a = (pic_load_library_a_fn)pic_find_loaded_export(
        PIC_HASH_LOAD_LIBRARY_A);
    if (api->load_library_a == NULL) return 0;
    pic_set_dll_names(ole32, oleaut32, mscoree);
    if (api->load_library_a(ole32) == NULL ||
        api->load_library_a(oleaut32) == NULL ||
        api->load_library_a(mscoree) == NULL) return 0;
    api->co_initialize_ex = (pic_co_initialize_ex_fn)pic_find_loaded_export(
        PIC_HASH_CO_INITIALIZE_EX);
    api->co_uninitialize = (pic_co_uninitialize_fn)pic_find_loaded_export(
        PIC_HASH_CO_UNINITIALIZE);
    api->safe_array_create = (pic_safe_array_create_fn)pic_find_loaded_export(
        PIC_HASH_SAFE_ARRAY_CREATE);
    api->safe_array_create_vector = (pic_safe_array_create_vector_fn)pic_find_loaded_export(
        PIC_HASH_SAFE_ARRAY_VECTOR);
    api->safe_array_access_data = (pic_safe_array_access_data_fn)pic_find_loaded_export(
        PIC_HASH_SAFE_ARRAY_ACCESS);
    api->safe_array_unaccess_data = (pic_safe_array_unaccess_data_fn)pic_find_loaded_export(
        PIC_HASH_SAFE_ARRAY_UNACCESS);
    api->safe_array_destroy = (pic_safe_array_destroy_fn)pic_find_loaded_export(
        PIC_HASH_SAFE_ARRAY_DESTROY);
    api->variant_change_type = (pic_variant_change_type_fn)pic_find_loaded_export(
        PIC_HASH_VARIANT_CHANGE_TYPE);
    api->variant_clear = (pic_variant_clear_fn)pic_find_loaded_export(
        PIC_HASH_VARIANT_CLEAR);
    api->clr_create_instance = (pic_clr_create_instance_fn)pic_find_loaded_export(
        PIC_HASH_CLR_CREATE_INSTANCE);
    return api->co_initialize_ex != NULL && api->co_uninitialize != NULL &&
        api->safe_array_create != NULL && api->safe_array_create_vector != NULL &&
        api->safe_array_access_data != NULL && api->safe_array_unaccess_data != NULL &&
        api->safe_array_destroy != NULL && api->variant_change_type != NULL &&
        api->variant_clear != NULL && api->clr_create_instance != NULL;
}

static void pic_clr_close(pic_clr_host *host, const pic_managed_api *api) {
    if (host->domain_dispatch != NULL) IDispatch_Release(host->domain_dispatch);
    if (host->domain_unknown != NULL) IUnknown_Release(host->domain_unknown);
    if (host->runtime_started && host->runtime_host != NULL)
        ICorRuntimeHost_Stop(host->runtime_host);
    if (host->runtime_host != NULL) ICorRuntimeHost_Release(host->runtime_host);
    if (host->runtime_info != NULL) ICLRRuntimeInfo_Release(host->runtime_info);
    if (host->meta_host != NULL) ICLRMetaHost_Release(host->meta_host);
    if (host->com_initialized) api->co_uninitialize();
    pic_zero(host, sizeof(*host));
}

static HRESULT pic_clr_open(pic_clr_host *host, const pic_managed_api *api) {
    GUID clsid_meta_host;
    GUID iid_meta_host;
    GUID iid_runtime_info;
    GUID clsid_runtime_host;
    GUID iid_runtime_host;
    GUID iid_app_domain;
    WCHAR runtime_name[11];
    HRESULT hr;
    BOOL loadable = FALSE;
    pic_zero(host, sizeof(*host));
    pic_set_guid(&clsid_meta_host, 0x9280188d, 0x0e8e, 0x4867,
        0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde);
    pic_set_guid(&iid_meta_host, 0xd332db9e, 0xb9b3, 0x4125,
        0x82, 0x07, 0xa1, 0x48, 0x84, 0xf5, 0x32, 0x16);
    pic_set_guid(&iid_runtime_info, 0xbd39d1d2, 0xba2f, 0x486a,
        0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91);
    pic_set_guid(&clsid_runtime_host, 0xcb2f6723, 0xab3a, 0x11d2,
        0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e);
    pic_set_guid(&iid_runtime_host, 0xcb2f6722, 0xab3a, 0x11d2,
        0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e);
    pic_set_guid(&iid_app_domain, 0x05f696dc, 0x2b29, 0x3663,
        0xad, 0x8b, 0xc4, 0x38, 0x9c, 0xf2, 0xa7, 0x13);
    pic_set_runtime_name(runtime_name);

    hr = api->co_initialize_ex(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr)) host->com_initialized = 1;
    else if (hr != RPC_E_CHANGED_MODE) return hr;
    hr = api->clr_create_instance(&clsid_meta_host, &iid_meta_host,
                                  (LPVOID *)&host->meta_host);
    if (FAILED(hr)) return hr;
    hr = ICLRMetaHost_GetRuntime(host->meta_host, runtime_name,
        &iid_runtime_info, (LPVOID *)&host->runtime_info);
    if (FAILED(hr)) return hr;
    hr = ICLRRuntimeInfo_IsLoadable(host->runtime_info, &loadable);
    if (FAILED(hr) || !loadable) return FAILED(hr) ? hr : E_FAIL;
    hr = ICLRRuntimeInfo_GetInterface(host->runtime_info,
        &clsid_runtime_host, &iid_runtime_host, (LPVOID *)&host->runtime_host);
    if (FAILED(hr)) return hr;
    hr = ICorRuntimeHost_Start(host->runtime_host);
    if (FAILED(hr)) return hr;
    host->runtime_started = 1;
    hr = ICorRuntimeHost_GetDefaultDomain(host->runtime_host, &host->domain_unknown);
    if (FAILED(hr)) return hr;
    return IUnknown_QueryInterface(host->domain_unknown, &iid_app_domain,
        (void **)&host->domain_dispatch);
}

static void *pic_interface_method(void *interface_pointer, SIZE_T method_index) {
    void ***object = (void ***)interface_pointer;
    return (*object)[method_index];
}

static HRESULT pic_load_assembly(IDispatch *domain, const BYTE *assembly,
                                 ULONG assembly_size, IDispatch **assembly_dispatch,
                                 const pic_managed_api *api) {
    typedef HRESULT (__stdcall *appdomain_load_3_fn)(void *, SAFEARRAY *, void **);
    SAFEARRAY *bytes = NULL;
    SAFEARRAYBOUND bound;
    BYTE *destination = NULL;
    appdomain_load_3_fn load_3;
    HRESULT hr;
    *assembly_dispatch = NULL;
    bound.lLbound = 0;
    bound.cElements = assembly_size;
    bytes = api->safe_array_create(VT_UI1, 1, &bound);
    if (bytes == NULL) return E_OUTOFMEMORY;
    hr = api->safe_array_access_data(bytes, (void **)&destination);
    if (FAILED(hr)) goto cleanup;
    pic_copy(destination, assembly, assembly_size);
    api->safe_array_unaccess_data(bytes);
    destination = NULL;
    load_3 = (appdomain_load_3_fn)pic_interface_method(domain, 45);
    hr = load_3(domain, bytes, (void **)assembly_dispatch);
cleanup:
    if (destination != NULL) api->safe_array_unaccess_data(bytes);
    if (bytes != NULL) api->safe_array_destroy(bytes);
    return hr;
}

static HRESULT pic_get_entry_point(IDispatch *assembly, IDispatch **method) {
    typedef HRESULT (__stdcall *assembly_get_entry_point_fn)(void *, void **);
    assembly_get_entry_point_fn get_entry;
    *method = NULL;
    get_entry = (assembly_get_entry_point_fn)pic_interface_method(assembly, 16);
    return get_entry(assembly, (void **)method);
}

static HRESULT pic_invoke_parameterless_main(IDispatch *method, LONG *managed_result,
                                             const pic_managed_api *api) {
    typedef HRESULT (__stdcall *method_invoke_3_fn)(void *, VARIANT, SAFEARRAY *, VARIANT *);
    method_invoke_3_fn invoke_3;
    SAFEARRAY *empty_parameters;
    VARIANT target;
    VARIANT result;
    HRESULT hr;
    *managed_result = 0;
    empty_parameters = api->safe_array_create_vector(VT_VARIANT, 0, 0);
    if (empty_parameters == NULL) return E_OUTOFMEMORY;
    pic_zero(&target, sizeof(target));
    V_VT(&target) = VT_NULL;
    pic_zero(&result, sizeof(result));
    invoke_3 = (method_invoke_3_fn)pic_interface_method(method, 37);
    hr = invoke_3(method, target, empty_parameters, &result);
    if (SUCCEEDED(hr)) {
        hr = api->variant_change_type(&result, &result, 0, VT_I4);
        if (SUCCEEDED(hr)) *managed_result = V_I4(&result);
    }
    api->variant_clear(&result);
    api->safe_array_destroy(empty_parameters);
    return hr;
}

static HRESULT __stdcall pic_execute_managed(const BYTE *assembly_bytes,
                                             ULONG assembly_size,
                                             LONG *managed_result) {
    pic_managed_api api;
    pic_clr_host host;
    IDispatch *assembly = NULL;
    IDispatch *method = NULL;
    HRESULT hr;
    if (assembly_bytes == NULL || assembly_size == 0 || managed_result == NULL)
        return E_INVALIDARG;
    pic_zero(&api, sizeof(api));
    pic_zero(&host, sizeof(host));
    *managed_result = 0;
    if (!pic_resolve_managed_api(&api)) return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    hr = pic_clr_open(&host, &api);
    if (FAILED(hr)) goto cleanup;
    hr = pic_load_assembly(host.domain_dispatch, assembly_bytes, assembly_size,
                           &assembly, &api);
    if (FAILED(hr)) goto cleanup;
    hr = pic_get_entry_point(assembly, &method);
    if (FAILED(hr)) goto cleanup;
    hr = pic_invoke_parameterless_main(method, managed_result, &api);
cleanup:
    if (method != NULL) IDispatch_Release(method);
    if (assembly != NULL) IDispatch_Release(assembly);
    pic_clr_close(&host, &api);
    return hr;
}

__declspec(dllexport) __declspec(noinline)
uint64_t __fastcall PbfManagedEntry(pbf_managed_context *context) {
    HRESULT hr;
    uint64_t assembly_end;
    if (context == NULL || context->size != sizeof(*context) ||
        context->abi_version != PBF_MANAGED_ABI_VERSION ||
        context->bundle_base == NULL ||
        context->assembly_size == 0) {
        if (context != NULL) context->status = (uint32_t)E_INVALIDARG;
        return 0;
    }
    assembly_end = (uint64_t)context->assembly_offset + context->assembly_size;
    if (context->assembly_offset >= context->bundle_size ||
        assembly_end > context->bundle_size) {
        context->status = (uint32_t)E_INVALIDARG;
        return 0;
    }
    if (context->execute_managed != NULL) {
        hr = context->execute_managed(
            context->bundle_base + context->assembly_offset,
            context->assembly_size, &context->managed_result);
    } else {
        hr = pic_execute_managed(
            context->bundle_base + context->assembly_offset,
            context->assembly_size, &context->managed_result);
    }
    context->status = (uint32_t)hr;
    return SUCCEEDED(hr) ? PBF_RESULT_OK : 0;
}

__declspec(dllexport) __declspec(noinline)
uint64_t __fastcall PbfManagedStandalone(BYTE *bundle_base) {
    const pbf_managed_footer *header;
    const pbf_managed_footer *footer;
    pbf_managed_context context;
    if (bundle_base == NULL) return 0;
    header = (const pbf_managed_footer *)(bundle_base + PBF_MANAGED_HEADER_OFFSET);
    if (header->magic[0] != 'P' || header->magic[1] != 'B' ||
        header->magic[2] != 'F' || header->magic[3] != 'N' ||
        header->magic[4] != 'E' || header->magic[5] != 'T' ||
        header->magic[6] != '2' || header->magic[7] != 0 ||
        header->version != PBF_MANAGED_ABI_VERSION ||
        header->architecture != PBF_MANAGED_ARCH_CURRENT ||
        header->total_size < PBF_MANAGED_HEADER_OFFSET + sizeof(*header) + sizeof(*footer) ||
        header->total_size > PBF_MANAGED_MAX_BUNDLE ||
        header->code_size < PBF_MANAGED_HEADER_OFFSET + sizeof(*header) ||
        header->code_size > header->total_size - sizeof(*footer) ||
        header->entry_offset >= header->code_size ||
        header->standalone_entry_offset >= header->code_size ||
        header->assembly_offset < header->code_size ||
        !pic_range_u64(header->assembly_offset, header->assembly_size,
                       header->total_size - sizeof(*footer))) return 0;
    footer = (const pbf_managed_footer *)(bundle_base + header->total_size - sizeof(*footer));
    if (!pic_equal(header, footer, sizeof(*header))) return 0;
    pic_zero(&context, sizeof(context));
    context.size = sizeof(context);
    context.abi_version = PBF_MANAGED_ABI_VERSION;
    context.bundle_base = bundle_base;
    context.bundle_size = header->total_size;
    context.assembly_offset = header->assembly_offset;
    context.assembly_size = header->assembly_size;
    return PbfManagedEntry(&context);
}

#pragma code_seg(pop)
