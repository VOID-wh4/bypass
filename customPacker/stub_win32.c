/* stub_win32.c -- Windows runtime loader (native Win32, 32-bit ONLY).
 *
 * ============================================================================
 * 32-bit 전용 스텁. 64-bit PE 페이로드는 로드할 수 없다.
 *   - IMAGE_NT_HEADERS32 / IMAGE_THUNK_DATA32 / IMAGE_ORDINAL_FLAG32 사용
 *   - IMAGE_REL_BASED_HIGHLOW 만 처리 (IMAGE_REL_BASED_DIR64 무시)
 *   - IMAGE_FILE_MACHINE_I386 검증
 * ============================================================================
 *
 * A packed file looks like:
 *   [ this stub .exe ][ compressed+encoded payload ][ orig_size u64 ]
 *   [ comp_size u64 ][ "MBApack!" magic ]
 *
 * At run time the stub:
 *   1. finds its own .exe path            (GetModuleFileNameA)
 *   2. reads the 24-byte footer to locate the payload
 *   3. reads the payload, DECODEs it (MBA), then INFLATEs it (zlib)
 *   4. maps the payload PE into memory and jumps to its entry point
 *
 * Build (MinGW-w64 i686):
 *     i686-w64-mingw32-gcc -O2 -Wall -m32 stub_win32.c -o stub_x86.exe -lz -lws2_32
 *
 * Build (MSVC x86 dev prompt):
 *     cl /nologo /O2 /W3 stub_win32.c /link zlib.lib ws2_32.lib
 *
 * Build (일반 MinGW 32-bit gcc):
 *     gcc -O2 -Wall -m32 stub_win32.c -o stub_x86.exe -lz -lws2_32
 */

/* 이 파일은 32비트 전용. 실수로 64비트 툴체인으로 빌드하면 즉시 실패시킴. */
#ifdef _WIN64
#error "stub_win32.c is 32-bit ONLY. Use an x86 (i686) toolchain, not x86_64."
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mathcrypt.h"
#include "miniz.h"
#pragma warning (disable: 4996)
#pragma comment(lib,"WS2_32.lib")
#define _CRT_SECURE_NO_WARNINGS


static const char MAGIC[8] = {'M','B','A','p','a','c','k','!'};
#define FOOTER_SIZE (8 + 8 + 8) /* orig_size + comp_size + magic */

static void die(const char *msg) {
    fprintf(stderr, "stub: %s (GetLastError=%lu)\n",
            msg, (unsigned long)GetLastError());
    exit(1);
}

/* ------------------------------------------------------------------ */
/* PE 헤더 파서 — 32비트 전용                                          */
/* ------------------------------------------------------------------ */
static IMAGE_NT_HEADERS32* GetNTHeaders32(char* pe_buffer)
{
    IMAGE_DOS_HEADER*   idh;
    IMAGE_NT_HEADERS32* inh;
    LONG                pe_offset;
    const LONG          kMaxOffset = 1024;

    if (pe_buffer == NULL) return NULL;

    idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    pe_offset = idh->e_lfanew;
    if (pe_offset > kMaxOffset) return NULL;

    inh = (IMAGE_NT_HEADERS32*)((char*)pe_buffer + pe_offset);
    if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;

    /* 64비트 PE는 로드 못 함 */
    if (inh->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        fprintf(stderr,
                "[error] Payload is not a 32-bit PE (Magic=0x%X). "
                "Use the 64-bit stub for 64-bit payloads.\n",
                inh->OptionalHeader.Magic);
        return NULL;
    }
    if (inh->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        fprintf(stderr,
                "[error] Payload Machine=0x%X is not IMAGE_FILE_MACHINE_I386.\n",
                inh->FileHeader.Machine);
        return NULL;
    }

    return inh;
}

static IMAGE_DATA_DIRECTORY* GetPEDirectory32(PVOID pe_buffer, size_t dir_id)
{
    IMAGE_NT_HEADERS32*    nt;
    IMAGE_DATA_DIRECTORY*  peDir;

    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

    nt = GetNTHeaders32((char*)pe_buffer);
    if (nt == NULL) return NULL;

    peDir = &(nt->OptionalHeader.DataDirectory[dir_id]);
    if (peDir->VirtualAddress == 0) return NULL;
    return peDir;
}

/* ------------------------------------------------------------------ */
/* IAT 복구 — 32비트 전용                                              */
/* ------------------------------------------------------------------ */
static int RepairIAT32(PVOID modulePtr)
{
    IMAGE_DATA_DIRECTORY*    importsDir;
    IMAGE_IMPORT_DESCRIPTOR* lib_desc;
    DWORD                    maxSize, impAddr, parsedSize;

    importsDir = GetPEDirectory32(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return 0;

    maxSize    = importsDir->Size;
    impAddr    = importsDir->VirtualAddress;
    parsedSize = 0;

    for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR))
    {
        LPSTR       lib_name;
        HMODULE     hLib;
        DWORD       call_via, thunk_addr;
        DWORD       offsetField, offsetThunk;

        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)modulePtr + impAddr + parsedSize);
        if (lib_desc->OriginalFirstThunk == 0 && lib_desc->FirstThunk == 0) break;

        lib_name   = (LPSTR)((DWORD)modulePtr + lib_desc->Name);
        hLib       = LoadLibraryA(lib_name);
        if (!hLib) continue;

        call_via   = lib_desc->FirstThunk;
        thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == 0) thunk_addr = lib_desc->FirstThunk;

        offsetField = 0;
        offsetThunk = 0;

        while (1)
        {
            IMAGE_THUNK_DATA32* fieldThunk;
            IMAGE_THUNK_DATA32* orginThunk;
            FARPROC             addr;

            fieldThunk = (IMAGE_THUNK_DATA32*)((DWORD)modulePtr + call_via   + offsetField);
            orginThunk = (IMAGE_THUNK_DATA32*)((DWORD)modulePtr + thunk_addr + offsetThunk);

            if (orginThunk->u1.AddressOfData == 0) break;

            /* 서수(ordinal)로 임포트 */
            if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
            {
                addr = GetProcAddress(hLib,
                    (LPCSTR)(orginThunk->u1.Ordinal & 0xFFFF));
                fieldThunk->u1.Function = (DWORD)addr;
            }
            /* 이름으로 임포트 */
            else
            {
                PIMAGE_IMPORT_BY_NAME by_name;
                by_name = (PIMAGE_IMPORT_BY_NAME)((DWORD)modulePtr + orginThunk->u1.AddressOfData);
                addr = GetProcAddress(hLib, (LPCSTR)by_name->Name);
                fieldThunk->u1.Function = (DWORD)addr;
            }

            offsetField += sizeof(IMAGE_THUNK_DATA32);
            offsetThunk += sizeof(IMAGE_THUNK_DATA32);
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Relocation — 32비트 전용 (IMAGE_REL_BASED_HIGHLOW만 처리)          */
/* ------------------------------------------------------------------ */
static void RelocateImage32(BYTE* pImageBase, DWORD delta)
{
    IMAGE_DATA_DIRECTORY*  relocDirEntry;
    IMAGE_BASE_RELOCATION* reloc;

    if (delta == 0) return;

    relocDirEntry = GetPEDirectory32(pImageBase, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (relocDirEntry == NULL) {
        printf("[warn] No relocation directory - base address may mismatch.\n");
        return;
    }

    reloc = (IMAGE_BASE_RELOCATION*)(pImageBase + relocDirEntry->VirtualAddress);

    while (reloc->VirtualAddress != 0)
    {
        DWORD  blockSize = reloc->SizeOfBlock;
        DWORD  count     = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD*  entries   = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
        DWORD  k;

        for (k = 0; k < count; k++)
        {
            WORD type   = entries[k] >> 12;
            WORD offset = entries[k] & 0x0FFF;

            if (type == IMAGE_REL_BASED_HIGHLOW)   /* 32-bit absolute */
            {
                DWORD* ptr = (DWORD*)(pImageBase + reloc->VirtualAddress + offset);
                *ptr += delta;
            }
            /* IMAGE_REL_BASED_ABSOLUTE (0) = padding, no-op */
            /* IMAGE_REL_BASED_DIR64 은 32비트 PE에 나타나면 안 되지만 만약 있으면 무시 */
        }

        reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + blockSize);
    }
}

/* ------------------------------------------------------------------ */
/* PE Loader — 32비트 전용                                             */
/* ------------------------------------------------------------------ */
static void PELoader32(char* data, long long datasize)
{
    unsigned int chksum = 0;
    long long    i;

    BYTE*        pImageBase   = NULL;
    LPVOID       preferAddr   = 0;
    DWORD        originalBase = 0;

    IMAGE_NT_HEADERS32*    ntHeader;
    IMAGE_DATA_DIRECTORY*  relocDir;
    IMAGE_SECTION_HEADER*  SectionHeaderArr;
    DWORD                  retAddr;
    int                    j;

    /* 체크섬 (진단용) */
    for (i = 0; i < datasize; i++)
        chksum = (unsigned char)data[i] * (unsigned int)i + chksum / 3;

    /* step 1: NT 헤더 확보 (32비트 PE 검증 포함) */
    printf("  -- 1 GET NT Header (PE32)\n");
    ntHeader = GetNTHeaders32(data);
    if (!ntHeader) {
        printf("[error] Invalid or non-32-bit PE.\n");
        exit(0);
    }

    originalBase = ntHeader->OptionalHeader.ImageBase;
    preferAddr   = (LPVOID)originalBase;
    relocDir     = GetPEDirectory32(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);

    /* step 2: 실행 가능한 메모리 할당 */
    printf("  -- 2 VirtualAlloc Memory\n");
    pImageBase = (BYTE*)VirtualAlloc(preferAddr,
                                     ntHeader->OptionalHeader.SizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);

    if (!pImageBase) {
        /* 선호 주소 실패 → OS가 고른 주소로 재시도 (relocation으로 보정) */
        if (!relocDir) {
            printf("[error] VirtualAlloc at preferred base failed and no reloc dir.\n");
            exit(0);
        }
        pImageBase = (BYTE*)VirtualAlloc(NULL,
                                         ntHeader->OptionalHeader.SizeOfImage,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
        if (!pImageBase) {
            printf("[error] VirtualAlloc failed entirely.\n");
            exit(0);
        }
    }
    printf("  -- 2 allocated at %p (preferred %p)\n", pImageBase, preferAddr);

    /* step 3: 헤더 + 섹션 매핑 */
    printf("  -- 3 FILL the memory block with PE data\n");
    memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

    SectionHeaderArr = (IMAGE_SECTION_HEADER*)(
        (BYTE*)ntHeader + sizeof(IMAGE_NT_HEADERS32));

    for (j = 0; j < ntHeader->FileHeader.NumberOfSections; j++)
    {
        memcpy((LPVOID)(pImageBase + SectionHeaderArr[j].VirtualAddress),
               (LPVOID)((BYTE*)data + SectionHeaderArr[j].PointerToRawData),
               SectionHeaderArr[j].SizeOfRawData);
    }

    /* step 4: Relocation — 실제 로드 주소와 ImageBase 차이 보정 */
    {
        DWORD delta = (DWORD)((DWORD_PTR)pImageBase - (DWORD_PTR)originalBase);
        printf("  -- 4 Relocate (delta = 0x%08lX)\n", (unsigned long)delta);
        RelocateImage32(pImageBase, delta);
    }

    /* ImageBase 필드도 실제 주소로 갱신 */
    {
        IMAGE_NT_HEADERS32* loadedNT = (IMAGE_NT_HEADERS32*)(
            pImageBase + ((IMAGE_DOS_HEADER*)pImageBase)->e_lfanew);
        loadedNT->OptionalHeader.ImageBase = (DWORD)(DWORD_PTR)pImageBase;
    }

    /* step 5: IAT 복구 */
    printf("  -- 5 Fix the PE Import addr table (pImageBase:%p)\n", pImageBase);
    RepairIAT32(pImageBase);

    /* step 6 & 7: 진입점으로 점프 */
    printf("  -- 6 Seek the AddressOfEntryPoint\n");
    retAddr = (DWORD)(DWORD_PTR)pImageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
    printf("  -- 7 Rush the PE in Memory (size %lld)(addr 0x%08lX)(chksum %u)\n",
           datasize, (unsigned long)retAddr, chksum);

    ((void(*)(void))(DWORD_PTR)retAddr)();
}


int main(void) {
    /* --- 1. our own executable path ------------------------------------ */
    char self[MAX_PATH];
    DWORD sn = GetModuleFileNameA(NULL, self, sizeof(self));
    if (sn == 0 || sn >= sizeof(self)) die("GetModuleFileName failed");

    /* --- 2. open self and read footer ---------------------------------- */
    FILE *f = fopen(self, "rb");
    if (!f) die("cannot open self");

    if (fseek(f, 0, SEEK_END) != 0) die("seek end failed");
    long file_size = ftell(f);
    if (file_size < FOOTER_SIZE) die("file too small; not packed");

    uint8_t footer[FOOTER_SIZE];
    if (fseek(f, file_size - FOOTER_SIZE, SEEK_SET) != 0) die("seek footer failed");
    if (fread(footer, 1, FOOTER_SIZE, f) != FOOTER_SIZE) die("read footer failed");

    if (memcmp(footer + 16, MAGIC, 8) != 0)
        die("magic not found; this stub has no payload appended");

    uint64_t orig_size, comp_size;
    memcpy(&orig_size, footer + 0, 8);
    memcpy(&comp_size, footer + 8, 8);

    /* --- 3. read + decode + inflate ------------------------------------ */
    long payload_off = file_size - FOOTER_SIZE - (long)comp_size;
    if (payload_off < 0) die("bad payload offset");

    uint8_t *enc = (uint8_t *)malloc(comp_size ? (size_t)comp_size : 1);
    if (!enc) die("oom enc");
    if (fseek(f, payload_off, SEEK_SET) != 0) die("seek payload failed");
    if (fread(enc, 1, (size_t)comp_size, f) != (size_t)comp_size) die("read payload failed");
    fclose(f);

    decode_buf(enc, (size_t)comp_size);          /* undo affine cipher (MBA) */

    uint8_t *out = (uint8_t *)malloc(orig_size ? (size_t)orig_size : 1);
    if (!out) die("oom out");
    uLongf out_len = (uLongf)orig_size;
    if (uncompress(out, &out_len, enc, (uLong)comp_size) != Z_OK) die("uncompress failed");
    if (out_len != orig_size) die("size mismatch after inflate");
    free(enc);

    /* --- 4. loader (32비트 PE 전용) ------------------------------------ */
    PELoader32((char*)out, (long long)orig_size);

    return 0;
}
