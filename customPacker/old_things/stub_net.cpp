// stub_net.cpp -- .NET assembly in-memory loader (C++/CLI). [v2 - fixed Byte ambiguity]
//
// ============================================================================
// 이 스텁은 .NET 어셈블리를 임시 파일 없이 완전히 메모리에서 실행한다.
// C++/CLI를 쓰는 이유: managed 코드와 native 코드를 한 파일에서 자유롭게 오갈 수 있어서
//   - 파일 I/O, 압축 해제, MBA 디코딩은 native (unmanaged) C++로
//   - Assembly 로드 및 EntryPoint 호출은 managed (.NET) 코드로
// 각각 가장 자연스러운 언어에서 처리한다.
//
// Payload format (unchanged from original stub_win.c):
//   [ this stub .exe ][ compressed+encoded payload ][ orig_size u64 ]
//   [ comp_size u64 ][ "MBApack!" magic ]
//
// Build (MSVC x86 Developer Command Prompt): see build.bat
// ============================================================================
 
#pragma once
 
// Native includes
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
 
// mathcrypt.h와 miniz.h는 native C 헤더이므로 /clr 컨텍스트에서
// managed IL로 컴파일되지 않도록 #pragma managed(off) 블록으로 감쌈.
#pragma managed(push, off)
extern "C" {
    #include "mathcrypt.h"   // decode_buf
    #include "miniz.h"       // uncompress, Z_OK, uLongf, uLong
}
#pragma managed(pop)
 
// Managed using directives
// 주의: `using namespace System;` 를 하면 miniz.h의 typedef Byte와 System::Byte가 충돌.
// 그래서 System namespace 전체 using은 하지 않고, 필요한 것만 명시적으로 참조한다.
using namespace System::Reflection;
using namespace System::Runtime::InteropServices;
 
// 자주 쓰는 것만 typedef로 짧게
typedef System::String    SysString;
typedef System::Console   SysConsole;
typedef System::Object    SysObject;
typedef System::Exception SysException;
 
// ---------------------------------------------------------------------------
// Native 헬퍼: 에러 발생 시 종료
// ---------------------------------------------------------------------------
static void die(const char* msg) {
    fprintf(stderr, "stub_net: %s (GetLastError=%lu)\n",
            msg, (unsigned long)GetLastError());
    exit(1);
}
 
static const char MAGIC[8] = { 'M', 'B', 'A', 'p', 'a', 'c', 'k', '!' };
#define FOOTER_SIZE (8 + 8 + 8)   // orig_size + comp_size + magic
 
// ---------------------------------------------------------------------------
// Managed 헬퍼: native byte 버퍼를 System::Byte[]로 복사
//   Byte 대신 System::Byte로 명시하여 miniz.h의 typedef Byte와의 충돌 회피.
// ---------------------------------------------------------------------------
static array<System::Byte>^ NativeToManagedBytes(const uint8_t* src, size_t len) {
    array<System::Byte>^ dst = gcnew array<System::Byte>((int)len);
    if (len == 0) return dst;
 
    // pin_ptr로 관리 배열의 주소를 GC 이동으로부터 고정
    pin_ptr<System::Byte> pDst = &dst[0];
    memcpy((void*)pDst, src, len);
    return dst;
}
 
// ---------------------------------------------------------------------------
// Managed 함수: byte[]에서 .NET 어셈블리 로드하고 EntryPoint 실행
// ---------------------------------------------------------------------------
static int LoadAndRunAssembly(array<System::Byte>^ payload, array<SysString^>^ args) {
    try {
        // Assembly.Load(byte[]) — 여기가 in-memory 실행의 핵심.
        // CLR이 payload를 파싱해서 메타데이터/IL을 그대로 로드한다.
        Assembly^ asm_ = Assembly::Load(payload);
 
        // EntryPoint = static Main 메서드 정보
        MethodInfo^ entry = asm_->EntryPoint;
        if (entry == nullptr) {
            SysConsole::Error->WriteLine("[error] Assembly has no entry point.");
            return 1;
        }
 
        // Main의 시그니처: Main() 또는 Main(string[]). 파라미터 개수 보고 처리.
        // GetParameters()는 managed array를 반환하므로 array<T>^로 받아야 함.
        array<ParameterInfo^>^ params = entry->GetParameters();
 
        array<SysObject^>^ invokeArgs;
        if (params->Length == 0) {
            invokeArgs = nullptr;                          // Main()
        } else {
            invokeArgs = gcnew array<SysObject^>(1);
            invokeArgs[0] = args;                          // Main(string[] args)
        }
 
        // 정적 메서드이므로 obj=nullptr로 Invoke
        SysObject^ ret = entry->Invoke(nullptr, invokeArgs);
 
        // Main이 int 반환하면 그 값을 프로세스 종료 코드로 사용
        if (ret != nullptr && ret->GetType() == int::typeid) {
            return (int)ret;
        }
        return 0;
    }
    catch (System::BadImageFormatException^ ex) {
        SysConsole::Error->WriteLine("[error] Not a valid .NET assembly: {0}", ex->Message);
        return 2;
    }
    catch (SysException^ ex) {
        SysConsole::Error->WriteLine("[error] Assembly execution failed: {0}", ex->Message);
        SysConsole::Error->WriteLine(ex->StackTrace);
        return 3;
    }
}
 
// ---------------------------------------------------------------------------
// Main: native → managed 브리지
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    // --- 1. 자기 exe 경로 얻기 ------------------------------------------
    char self[MAX_PATH];
    DWORD sn = GetModuleFileNameA(NULL, self, sizeof(self));
    if (sn == 0 || sn >= sizeof(self)) die("GetModuleFileName failed");
 
    // --- 2. 파일 열고 footer 읽기 ---------------------------------------
    FILE* f = fopen(self, "rb");
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
 
    // --- 3. payload 읽고 MBA 디코딩 후 zlib 압축 해제 -------------------
    long payload_off = file_size - FOOTER_SIZE - (long)comp_size;
    if (payload_off < 0) die("bad payload offset");
 
    uint8_t* enc = (uint8_t*)malloc(comp_size ? (size_t)comp_size : 1);
    if (!enc) die("oom enc");
    if (fseek(f, payload_off, SEEK_SET) != 0) die("seek payload failed");
    if (fread(enc, 1, (size_t)comp_size, f) != (size_t)comp_size) die("read payload failed");
    fclose(f);
 
    // MBA affine cipher 역변환 (in-place)
    decode_buf(enc, (size_t)comp_size);
 
    uint8_t* out = (uint8_t*)malloc(orig_size ? (size_t)orig_size : 1);
    if (!out) die("oom out");
    uLongf out_len = (uLongf)orig_size;
    if (uncompress(out, &out_len, enc, (uLong)comp_size) != Z_OK) die("uncompress failed");
    if (out_len != orig_size) die("size mismatch after inflate");
    free(enc);
 
    // --- 4. .NET 어셈블리 검증 (COM Descriptor 존재 확인) ---------------
    {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)out;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) die("payload not a PE");
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(out + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) die("payload PE signature invalid");
        DWORD comRVA = nt->OptionalHeader.DataDirectory[14].VirtualAddress;
        if (comRVA == 0) {
            fprintf(stderr, "[error] payload is not a .NET assembly (no CLR header). "
                            "Use stub_win32.exe for native payloads.\n");
            free(out);
            return 1;
        }
    }
 
    // --- 5. Managed 영역으로 진입 ---------------------------------------
    array<System::Byte>^ payload = NativeToManagedBytes(out, (size_t)orig_size);
    free(out);   // native 버퍼는 이제 필요 없음
 
    // 프로세스에 전달된 CLI 인자를 payload의 Main으로 그대로 넘겨줌 (argv[0] 제외)
    array<SysString^>^ mgArgs = gcnew array<SysString^>(argc > 1 ? argc - 1 : 0);
    for (int i = 1; i < argc; i++) {
        mgArgs[i - 1] = gcnew SysString(argv[i]);
    }
 
    int exitCode = LoadAndRunAssembly(payload, mgArgs);
    return exitCode;
}