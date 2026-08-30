#include <stdio.h>
#include <stdlib.h>

int xor_file(const char *input_filename, const char *output_filename, unsigned char key) {
    // 1. 파일 열기 (읽기/쓰기 바이너리 모드)
    FILE *infile = fopen(input_filename, "rb");
    if (!infile) {
        perror("입력 파일을 열 수 없습니다");
        return 0;
    }

    // 파일 크기 구하기
    fseek(infile, 0, SEEK_END);
    long file_size = ftell(infile);
    rewind(infile);

    // 2. 메모리 할당
    unsigned char *buffer = (unsigned char *)malloc(file_size);
    if (!buffer) {
        perror("메모리 할당 실패");
        fclose(infile);
        return 0;
    }

    // 파일 내용을 버퍼로 읽기
    size_t bytes_read = fread(buffer, 1, file_size, infile);
    fclose(infile);

    if (bytes_read != (size_t)file_size) {
        perror("파일 읽기 오류");
        free(buffer);
        return 0;
    }

    // 3. 0x53으로 XOR 연산 수행
    for (long i = 0; i < file_size; i++) {
        buffer[i] ^= key;
    }

    // 4. 결과 파일 저장
    FILE *outfile = fopen(output_filename, "wb");
    if (!outfile) {
        perror("출력 파일을 생성할 수 없습니다");
        free(buffer);
        return 0;
    }

    fwrite(buffer, 1, file_size, outfile);
    fclose(outfile);
    free(buffer);

    return 1;
}

int main() {
    const char *target = "ld.bin";     // 원본 파일
    const char *output = "xor.bin";  // 결과 파일
    unsigned char key = 0x53;              // XOR 키

    if (xor_file(target, output, key)) {
        printf("[+] 성공적으로 0x53 XOR 처리가 완료되었습니다: %s -> %s\n", target, output);
    } else {
        printf("[-] 처리 중 오류가 발생했습니다.\n");
    }

    return 0;
}
