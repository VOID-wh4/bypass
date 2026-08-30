#include <windows.h>
#include <stdio.h>

typedef void (*StartFunc)();

/**
 * 파일에서 DLL 바이너리를 읽어 버퍼에 저장
 * @param path  DLL 파일 경로
 * @param size  읽은 바이트 수 (출력)
 * @return      할당된 버퍼 포인터 (사용 후 free 필요), 실패 시 NULL
 */
static unsigned char* read_file(const char* path, size_t* size) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[!] 파일 열기 실패: %s\n", path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    *size = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char* buf = (unsigned char*)malloc(*size);
    if (!buf) {
        fprintf(stderr, "[!] 메모리 할당 실패\n");
        fclose(f);
        return NULL;
    }

    if (fread(buf, 1, *size, f) != *size) {
        fprintf(stderr, "[!] 파일 읽기 실패\n");
        free(buf);
        fclose(f);
        return NULL;
    }

    fclose(f);
    return buf;
}

/**
 * 버퍼 전체를 0x55로 XOR 복호화 (in-place)
 */
static void xor_decrypt(unsigned char* buf, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buf[i] ^= 0x55;
    }
    printf("[*] XOR 0x55 복호화 완료 (%zu bytes)\n", size);
}

/**
 * 복호화된 바이너리를 임시 파일로 저장 후 LoadLibrary로 로드
 * (메모리 매핑 없이 안전하게 로드)
 */
static HMODULE load_decrypted_dll(const unsigned char* buf, size_t size) {
    // 임시 경로 생성
    char tmp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp_path);
    strcat_s(tmp_path, MAX_PATH, "decrypted_module.dll");

    // 복호화된 DLL 임시 저장
    FILE* f = fopen(tmp_path, "wb");
    if (!f) {
        fprintf(stderr, "[!] 임시 파일 쓰기 실패\n");
        return NULL;
    }
    fwrite(buf, 1, size, f);
    fclose(f);

    // DLL 로드
    HMODULE hMod = LoadLibraryA(tmp_path);
    if (!hMod) {
        fprintf(stderr, "[!] LoadLibrary 실패 (오류 코드: %lu)\n", GetLastError());
    } else {
        printf("[*] DLL 로드 성공: %s\n", tmp_path);
    }

    return hMod;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <dll_path>\n", argv[0]);
        return 1;
    }
    const char* dll_path = argv[1];

    printf("[*] 대상 DLL: %s\n", dll_path);

    // 1. 파일 읽기
    size_t size = 0;
    unsigned char* buf = read_file(dll_path, &size);
    if (!buf) return 1;

    // 2. XOR 0x55 복호화
    xor_decrypt(buf, size);

    // 3. 복호화된 DLL 로드
    HMODULE hMod = load_decrypted_dll(buf, size);
    free(buf);
    if (!hMod) return 1;

    // 4. start() 함수 찾아 실행
    StartFunc start = (StartFunc)GetProcAddress(hMod, "Start");
    if (!start) {
        fprintf(stderr, "[!] Start() 함수를 찾을 수 없음 (오류 코드: %lu)\n", GetLastError());
        FreeLibrary(hMod);
        return 1;
    }

    printf("[*] Start() 호출\n");
    start();
    printf("[*] Start() 완료\n");

    FreeLibrary(hMod);
    return 0;
}
