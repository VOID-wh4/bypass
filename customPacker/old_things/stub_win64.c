/* stub_win.c -- Windows runtime loader (native Win32).
 *
 * A packed file looks like:
 *   [ this stub .exe ][ compressed+encoded payload ][ orig_size u64 ]
 *   [ comp_size u64 ][ "MBApack!" magic ]
 *
 * At run time the stub:
 *   1. finds its own .exe path            (GetModuleFileNameA)
 *   2. reads the 24-byte footer to locate the payload
 *   3. reads the payload, DECODEs it (MBA), then INFLATEs it (zlib)
 *   4. writes the result to a temp .exe    (GetTempPath + GetTempFileName)
 *   5. runs it and waits                    (CreateProcess + WaitForSingleObject)
 *   6. deletes the temp file and forwards the child's exit code
 *
 * Build (MinGW):  gcc -O2 -Wall stub_win.c -o stub.exe -lz
 * Note: order matters -- put -lz AFTER the source file.
 */

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
char* GetNTHeaders(char* pe_buffer)
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
 
    return (char*)inh;
}
 
IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)
{
    IMAGE_DATA_DIRECTORY* peDir = NULL;
    char* nt_headers;
    WORD  magic;

    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

    nt_headers = GetNTHeaders((char*)pe_buffer);
    if (nt_headers == NULL) return NULL;

    /* Magic은 32/64 모두 OptionalHeader 첫 번째 필드 — 어느 쪽으로 읽어도 동일 */
    magic = ((IMAGE_NT_HEADERS*)nt_headers)->OptionalHeader.Magic;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)nt_headers;
        peDir = &(nt64->OptionalHeader.DataDirectory[dir_id]);
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)nt_headers;
        peDir = &(nt32->OptionalHeader.DataDirectory[dir_id]);
    }
    else {
        return NULL; /* 알 수 없는 PE 형식 */
    }

    if (peDir->VirtualAddress == 0) return NULL;
    return peDir;
}
 
/* ------------------------------------------------------------------ */
int RepairIAT(PVOID modulePtr)
{
    IMAGE_DATA_DIRECTORY*   importsDir;
    IMAGE_IMPORT_DESCRIPTOR* lib_desc;
    size_t maxSize, impAddr, parsedSize;
    size_t call_via, thunk_addr, offsetField, offsetThunk;
 
    importsDir = GetPEDirectory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return 0;
 
    maxSize    = importsDir->Size;
    impAddr    = importsDir->VirtualAddress;
    lib_desc   = NULL;
    parsedSize = 0;
 
    for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR))
    {
        LPSTR lib_name;
 
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);
        if (lib_desc->OriginalFirstThunk == 0 && lib_desc->FirstThunk == 0) break;
 
        lib_name   = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
        call_via   = lib_desc->FirstThunk;
        thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == 0) thunk_addr = lib_desc->FirstThunk;
 
        offsetField = 0;
        offsetThunk = 0;
 
        while (1)
        {
            IMAGE_THUNK_DATA* fieldThunk;
            IMAGE_THUNK_DATA* orginThunk;
 
            fieldThunk = (IMAGE_THUNK_DATA*)((size_t)modulePtr + offsetField + call_via);
            orginThunk = (IMAGE_THUNK_DATA*)((size_t)modulePtr + offsetThunk + thunk_addr);
 
            /* 서수(ordinal)로 임포트하는 경우 */
            if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 ||
                orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
            {
                size_t addr = (size_t)GetProcAddress(
                    LoadLibraryA(lib_name),
                    (LPCSTR)(orginThunk->u1.Ordinal & 0xFFFF));
                fieldThunk->u1.Function = addr;
            }
 
            if (fieldThunk->u1.Function == 0) break;
 
            /* 이름으로 임포트하는 경우 */
            if (fieldThunk->u1.Function == orginThunk->u1.Function)
            {
                PIMAGE_IMPORT_BY_NAME by_name;
                LPSTR  func_name;
                size_t addr;
 
                by_name   = (PIMAGE_IMPORT_BY_NAME)((size_t)modulePtr + orginThunk->u1.AddressOfData);
                func_name = (LPSTR)by_name->Name;
                addr      = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);
 
                fieldThunk->u1.Function = addr;
            }
 
            offsetField += sizeof(IMAGE_THUNK_DATA);
            offsetThunk += sizeof(IMAGE_THUNK_DATA);
        }
    }
    return 1;
}
 
/* Relocation: pImageBase에 올라간 PE의 절대 주소들을 delta만큼 보정    */
static void RelocateImage(BYTE* pImageBase, ULONGLONG delta)
{
    IMAGE_DATA_DIRECTORY*  relocDirEntry;
    IMAGE_BASE_RELOCATION* reloc;

    if (delta == 0) return;

    relocDirEntry = GetPEDirectory(pImageBase, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (relocDirEntry == NULL) {
        printf("[warn] No relocation directory — base address may mismatch.\n");
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

            if (type == IMAGE_REL_BASED_DIR64)          /* 64-bit absolute */
            {
                ULONGLONG* ptr = (ULONGLONG*)(pImageBase + reloc->VirtualAddress + offset);
                *ptr += delta;
            }
            else if (type == IMAGE_REL_BASED_HIGHLOW)   /* 32-bit absolute */
            {
                DWORD* ptr = (DWORD*)(pImageBase + reloc->VirtualAddress + offset);
                *ptr += (DWORD)(ULONGLONG)delta;
            }
            /* IMAGE_REL_BASED_ABSOLUTE (0) = padding, no-op */
        }

        reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + blockSize);
    }
}


/* ------------------------------------------------------------------ */
void PELoader(char* data, long long datasize)
{
    unsigned int chksum = 0;
    long long    i;

    BYTE*       pImageBase    = NULL;
    LPVOID      preferAddr    = 0;
    ULONGLONG   originalBase  = 0;

    IMAGE_NT_HEADERS*       ntHeader;
    IMAGE_DATA_DIRECTORY*   relocDir;
    IMAGE_SECTION_HEADER*   SectionHeaderArr;
    size_t  retAddr;
    int     j;

    /* 체크섬 계산 */
    for (i = 0; i < datasize; i++)
        chksum = (unsigned char)data[i] * (unsigned int)i + chksum / 3;

    /* step 1: NT 헤더 확보 */
    printf("  -- 1 GET NT Header\n");
    ntHeader = (IMAGE_NT_HEADERS*)GetNTHeaders(data);
    if (!ntHeader) {
        printf("[error] Invalid PE.\n");
        exit(0);
    }

    originalBase = ntHeader->OptionalHeader.ImageBase;
    preferAddr   = (LPVOID)(size_t)originalBase;
    relocDir     = GetPEDirectory(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);

    /* step 2: (NtUnmapViewOfSection 제거)
     * 이 호출은 현재 프로세스(-1 핸들) 자신의 메모리를 해제해서
     * 스텁 코드를 날려버림 → 즉시 크래시. in-process 로딩에는 불필요. */

    /* step 3: 실행 가능한 메모리 할당 */
    printf("  -- 3 VirtualAlloc Memory\n");
    pImageBase = (BYTE*)VirtualAlloc(preferAddr,
                                     ntHeader->OptionalHeader.SizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
                                     
    if (!pImageBase) {
        /* 선호 주소 실패 → Windows가 고른 주소로 재시도 (relocation으로 보정) */
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
    printf("  -- 3 allocated at %p (preferred %p)\n", pImageBase, preferAddr);

    /* step 4: 헤더 + 섹션 매핑 */
    printf("  -- 4 FILL the memory block with PEdata\n");
    memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

    SectionHeaderArr = (IMAGE_SECTION_HEADER*)(
        (size_t)ntHeader + sizeof(IMAGE_NT_HEADERS));

    for (j = 0; j < ntHeader->FileHeader.NumberOfSections; j++)
    {
        memcpy((LPVOID)((size_t)pImageBase + SectionHeaderArr[j].VirtualAddress),
               (LPVOID)((size_t)data      + SectionHeaderArr[j].PointerToRawData),
               SectionHeaderArr[j].SizeOfRawData);
    }

    /* step 4-b: Relocation — 실제 로드 주소와 ImageBase 차이 보정 */
    printf("  -- 4b Relocate (delta = %p)\n",
           (long long)((ULONGLONG)pImageBase - originalBase));
    RelocateImage(pImageBase, (ULONGLONG)pImageBase - originalBase);

    /* ImageBase 필드도 실제 주소로 갱신 */
    ((IMAGE_NT_HEADERS*)(pImageBase + ((IMAGE_DOS_HEADER*)pImageBase)->e_lfanew))
        ->OptionalHeader.ImageBase = (size_t)pImageBase;

    /* step 5: IAT 복구 */
    printf("  -- 5 Fix the PE Import addr table (pImageBase:%p)\n", pImageBase);
    RepairIAT(pImageBase);

    /* step 6 & 7: 진입점으로 점프 */
    printf("  -- 6 Seek the AddressOfEntryPoint\n");
    retAddr = (size_t)pImageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
    printf("  -- 7 Rush the PE in Memory (size %lld)(addr %p)(chksum %u)\n",
           datasize, (void*)retAddr, chksum);

    ((void(*)(void))retAddr)();
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

    /* --- 4. loader ---------------------------*/
    PELoader(out, orig_size);

    // /* --- 4. write to a temp .exe --------------------------------------- */
    // char tmp_dir[MAX_PATH];
    // if (GetTempPathA(sizeof(tmp_dir), tmp_dir) == 0) die("GetTempPath failed");

    // char tmp_file[MAX_PATH];
    // /* uUnique=0 => make a unique name AND create the (empty) file. Ext is .tmp */
    // if (GetTempFileNameA(tmp_dir, "MBA", 0, tmp_file) == 0) die("GetTempFileName failed");

    // /* Windows really wants an .exe extension to run it cleanly. Rename .tmp -> .exe */
    // char exe_file[MAX_PATH];
    // strncpy(exe_file, tmp_file, sizeof(exe_file) - 1);
    // exe_file[sizeof(exe_file) - 1] = '\0';
    // size_t L = strlen(exe_file);
    // if (L > 4 && _stricmp(exe_file + L - 4, ".tmp") == 0) {
    //     strcpy(exe_file + L - 4, ".exe");
    //     DeleteFileA(exe_file);                    /* in case it exists */
    //     if (!MoveFileA(tmp_file, exe_file)) {
    //         /* Fall back to the .tmp name if rename fails. */
    //         strcpy(exe_file, tmp_file);
    //     }
    // }

    // FILE *tf = fopen(exe_file, "wb");
    // if (!tf) die("cannot open temp exe");
    // if (fwrite(out, 1, (size_t)out_len, tf) != (size_t)out_len) die("write temp failed");
    // fclose(tf);
    // free(out);

    // /* --- 5. run it and wait -------------------------------------------- */
    // STARTUPINFOA si;
    // PROCESS_INFORMATION pi;
    // ZeroMemory(&si, sizeof(si));
    // si.cb = sizeof(si);
    // ZeroMemory(&pi, sizeof(pi));

    // /* CreateProcess may modify the command-line buffer, so use a writable copy. */
    // char cmdline[MAX_PATH + 2];
    // snprintf(cmdline, sizeof(cmdline), "\"%s\"", exe_file);

    // if (!CreateProcessA(exe_file, cmdline, NULL, NULL, FALSE,
    //                     0, NULL, NULL, &si, &pi)) {
    //     die("CreateProcess failed");
    // }

    // WaitForSingleObject(pi.hProcess, INFINITE);

    // DWORD code = 0;
    // GetExitCodeProcess(pi.hProcess, &code);
    // CloseHandle(pi.hProcess);
    // CloseHandle(pi.hThread);

    // /* --- 6. clean up --------------------------------------------------- */
    // DeleteFileA(exe_file);   /* best effort; may fail if AV holds a lock */

    return 0;
}
