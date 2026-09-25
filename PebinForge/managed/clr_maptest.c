/*
 * Clean-room .NET Framework 4 in-memory assembly host written in C.
 *
 * The assembly is loaded from a SAFEARRAY of bytes into the default AppDomain.
 * No temporary assembly file is created and no other process is accessed.
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#define CINTERFACE
#define COBJMACROS
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <metahost.h>
#include <mscoree.h>
#include <oleauto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "pbf_clr_host.h"

#define PBF_MAX_MANAGED_ASSEMBLY (64U * 1024U * 1024U)

static const GUID PBF_IID_AppDomain =
    {0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13}};

typedef struct clr_host_t {
    ICLRMetaHost *meta_host;
    ICLRRuntimeInfo *runtime_info;
    ICorRuntimeHost *runtime_host;
    IUnknown *domain_unknown;
    IDispatch *domain_dispatch;
    int com_initialized;
    int runtime_started;
} clr_host;

#ifndef PBF_CLR_LIBRARY
static int checked_range(uint64_t offset, uint64_t length, uint64_t total) {
    return offset <= total && length <= total - offset;
}

static int is_managed_pe(const BYTE *data, size_t size) {
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS32 *nt32;
    uint64_t nt_offset;
    WORD magic;

    if (!checked_range(0, sizeof(IMAGE_DOS_HEADER), size)) return 0;
    dos = (const IMAGE_DOS_HEADER *)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    nt_offset = (uint32_t)dos->e_lfanew;
    if (!checked_range(nt_offset, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD), size)) return 0;
    if (*(const DWORD *)(data + nt_offset) != IMAGE_NT_SIGNATURE) return 0;
    nt32 = (const IMAGE_NT_HEADERS32 *)(data + nt_offset);
    magic = nt32->OptionalHeader.Magic;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (!checked_range(nt_offset, sizeof(IMAGE_NT_HEADERS32), size) ||
            nt32->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) return 0;
        return nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0 &&
            nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size >= sizeof(IMAGE_COR20_HEADER);
    }
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_NT_HEADERS64 *nt64;
        if (!checked_range(nt_offset, sizeof(IMAGE_NT_HEADERS64), size)) return 0;
        nt64 = (const IMAGE_NT_HEADERS64 *)(data + nt_offset);
        if (nt64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) return 0;
        return nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0 &&
            nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size >= sizeof(IMAGE_COR20_HEADER);
    }
    return 0;
}
#endif

static void clr_host_close(clr_host *host) {
    if (host->domain_dispatch != NULL) IDispatch_Release(host->domain_dispatch);
    if (host->domain_unknown != NULL) IUnknown_Release(host->domain_unknown);
    if (host->runtime_started && host->runtime_host != NULL) ICorRuntimeHost_Stop(host->runtime_host);
    if (host->runtime_host != NULL) ICorRuntimeHost_Release(host->runtime_host);
    if (host->runtime_info != NULL) ICLRRuntimeInfo_Release(host->runtime_info);
    if (host->meta_host != NULL) ICLRMetaHost_Release(host->meta_host);
    if (host->com_initialized) CoUninitialize();
    memset(host, 0, sizeof(*host));
}

static HRESULT clr_host_open(clr_host *host) {
    HRESULT hr;
    BOOL loadable = FALSE;

    memset(host, 0, sizeof(*host));
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr)) host->com_initialized = 1;
    else if (hr != RPC_E_CHANGED_MODE) return hr;

    hr = CLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost,
                           (LPVOID *)&host->meta_host);
    if (FAILED(hr)) return hr;
    hr = ICLRMetaHost_GetRuntime(host->meta_host, L"v4.0.30319",
        &IID_ICLRRuntimeInfo, (LPVOID *)&host->runtime_info);
    if (FAILED(hr)) return hr;
    hr = ICLRRuntimeInfo_IsLoadable(host->runtime_info, &loadable);
    if (FAILED(hr) || !loadable) return FAILED(hr) ? hr : E_FAIL;
    hr = ICLRRuntimeInfo_GetInterface(host->runtime_info,
        &CLSID_CorRuntimeHost, &IID_ICorRuntimeHost,
        (LPVOID *)&host->runtime_host);
    if (FAILED(hr)) return hr;
    hr = ICorRuntimeHost_Start(host->runtime_host);
    if (FAILED(hr)) return hr;
    host->runtime_started = 1;
    hr = ICorRuntimeHost_GetDefaultDomain(host->runtime_host,
        &host->domain_unknown);
    if (FAILED(hr)) return hr;
    return IUnknown_QueryInterface(host->domain_unknown, &PBF_IID_AppDomain,
        (void **)&host->domain_dispatch);
}

static void *interface_method(void *interface_pointer, size_t method_index) {
    void ***object = (void ***)interface_pointer;
    return (*object)[method_index];
}

static HRESULT load_assembly(IDispatch *domain, const BYTE *assembly,
                             ULONG assembly_size, IDispatch **assembly_dispatch) {
    typedef HRESULT (__stdcall *appdomain_load_3_fn)(void *, SAFEARRAY *, void **);
    SAFEARRAY *bytes = NULL;
    SAFEARRAYBOUND bound;
    BYTE *destination = NULL;
    appdomain_load_3_fn load_3;
    HRESULT hr;

    *assembly_dispatch = NULL;
    bound.lLbound = 0;
    bound.cElements = assembly_size;
    bytes = SafeArrayCreate(VT_UI1, 1, &bound);
    if (bytes == NULL) return E_OUTOFMEMORY;
    hr = SafeArrayAccessData(bytes, (void **)&destination);
    if (FAILED(hr)) goto cleanup;
    memcpy(destination, assembly, assembly_size);
    SafeArrayUnaccessData(bytes);
    destination = NULL;

    /* _AppDomain vtable: IUnknown(3), automation methods(4), then Load_3 at 45. */
    load_3 = (appdomain_load_3_fn)interface_method(domain, 45);
    hr = load_3(domain, bytes, (void **)assembly_dispatch);

cleanup:
    if (destination != NULL) SafeArrayUnaccessData(bytes);
    if (bytes != NULL) SafeArrayDestroy(bytes);
    return hr;
}

static HRESULT get_entry_point(IDispatch *assembly, IDispatch **method) {
    typedef HRESULT (__stdcall *assembly_get_entry_point_fn)(void *, void **);
    assembly_get_entry_point_fn get_entry;
    *method = NULL;
    /* _Assembly derives IDispatch; get_EntryPoint is vtable method 16. */
    get_entry = (assembly_get_entry_point_fn)interface_method(assembly, 16);
    return get_entry(assembly, (void **)method);
}

static HRESULT invoke_parameterless_main(IDispatch *method, LONG *managed_result) {
    typedef HRESULT (__stdcall *method_invoke_3_fn)(
        void *, VARIANT, SAFEARRAY *, VARIANT *);
    method_invoke_3_fn invoke_3;
    SAFEARRAY *empty_parameters = NULL;
    VARIANT target;
    VARIANT result;
    HRESULT hr;

    *managed_result = 0;
    empty_parameters = SafeArrayCreateVector(VT_VARIANT, 0, 0);
    if (empty_parameters == NULL) return E_OUTOFMEMORY;
    VariantInit(&target);
    V_VT(&target) = VT_NULL;
    VariantInit(&result);
    /* _MethodInfo manual automation interface; Invoke_3 is vtable method 37. */
    invoke_3 = (method_invoke_3_fn)interface_method(method, 37);
    hr = invoke_3(method, target, empty_parameters, &result);
    if (SUCCEEDED(hr)) {
        hr = VariantChangeType(&result, &result, 0, VT_I4);
        if (SUCCEEDED(hr)) *managed_result = V_I4(&result);
    }
    VariantClear(&result);
    SafeArrayDestroy(empty_parameters);
    return hr;
}

HRESULT __stdcall pbf_clr_execute_parameterless(const BYTE *assembly_bytes,
                                                ULONG assembly_size,
                                                LONG *managed_result) {
    clr_host host;
    IDispatch *assembly = NULL;
    IDispatch *method = NULL;
    HRESULT hr;

    if (assembly_bytes == NULL || assembly_size == 0 || managed_result == NULL) {
        return E_INVALIDARG;
    }
    memset(&host, 0, sizeof(host));
    *managed_result = 0;
    hr = clr_host_open(&host);
    if (FAILED(hr)) goto cleanup;
    hr = load_assembly(host.domain_dispatch, assembly_bytes, assembly_size, &assembly);
    if (FAILED(hr)) goto cleanup;
    hr = get_entry_point(assembly, &method);
    if (FAILED(hr)) goto cleanup;
    hr = invoke_parameterless_main(method, managed_result);

cleanup:
    if (method != NULL) IDispatch_Release(method);
    if (assembly != NULL) IDispatch_Release(assembly);
    clr_host_close(&host);
    return hr;
}

#ifndef PBF_CLR_LIBRARY
int main(int argc, char **argv) {
    const char *path;
    struct _stat64 status;
    FILE *file = NULL;
    BYTE *assembly_bytes = NULL;
    LONG managed_result = 0;
    HRESULT hr;
    int exit_code = 1;

    if (argc != 2 || strcmp(argv[1], "--help") == 0) {
        puts("clr-maptest 0.1.0\nUsage: clr-maptest <managed-framework4.exe>");
        return argc == 2 ? 0 : 2;
    }
    path = argv[1];
    if (_stat64(path, &status) != 0 || status.st_size <= 0 ||
        status.st_size > PBF_MAX_MANAGED_ASSEMBLY) {
        fputs("[-] Managed assembly is missing, empty, or too large.\n", stderr);
        return 3;
    }
    assembly_bytes = (BYTE *)malloc((size_t)status.st_size);
    file = fopen(path, "rb");
    if (assembly_bytes == NULL || file == NULL ||
        fread(assembly_bytes, 1, (size_t)status.st_size, file) != (size_t)status.st_size) {
        fputs("[-] Unable to read managed assembly.\n", stderr);
        goto cleanup;
    }
    fclose(file);
    file = NULL;
    if (!is_managed_pe(assembly_bytes, (size_t)status.st_size)) {
        fputs("[-] Input is not a managed PE assembly.\n", stderr);
        exit_code = 4;
        goto cleanup;
    }
    hr = pbf_clr_execute_parameterless(assembly_bytes,
        (ULONG)status.st_size, &managed_result);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] CLR in-memory execution failed: 0x%08lx\n", hr);
        exit_code = 6;
        goto cleanup;
    }
    printf("[+] CLR v4 hosted from C.\n");
    printf("[+] Assembly loaded directly from %lld memory bytes.\n", (long long)status.st_size);
    printf("[+] Parameterless Main returned: %ld\n", managed_result);
    exit_code = managed_result >= 1000 ? 0 : 9;

cleanup:
    if (file != NULL) fclose(file);
    if (assembly_bytes != NULL) {
        SecureZeroMemory(assembly_bytes, (SIZE_T)status.st_size);
        free(assembly_bytes);
    }
    return exit_code;
}
#endif
