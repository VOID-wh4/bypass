"""
xor_encrypt.py
shellcode.bin 을 단일 바이트 XOR 키로 암호화/복호화합니다.
XOR 은 대칭 연산이므로 같은 스크립트로 암호화와 복호화 모두 수행합니다.

사용법:
    python xor_encrypt.py <입력파일> <출력파일> <XOR키(hex)>

예시:
    python xor_encrypt.py shellcode.bin shellcode.bin 0x41
    → shellcode.bin 을 XOR 0x41 로 암호화하여 shellcode.bin 에 덮어씀

주의:
    - C 코드의 XOR_KEY 와 반드시 동일한 키를 사용해야 합니다.
    - 입력 == 출력 경로이면 제자리(in-place) 암호화가 수행됩니다.
"""

import sys
import os


def xor_file(input_path: str, output_path: str, key: int) -> None:
    """
    파일을 XOR 암호화/복호화합니다.
    """
    # 입력 파일 존재 확인
    if not os.path.isfile(input_path):
        print(f"[!] 파일을 찾을 수 없습니다: {input_path}")
        sys.exit(1)

    # 파일 읽기
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    original_size = len(data)
    print(f"[*] 입력 파일  : {input_path} ({original_size} bytes)")
    print(f"[*] XOR 키     : 0x{key:02X}")

    # XOR 적용 (바이트 단위)
    for i in range(len(data)):
        data[i] ^= key

    # 결과 저장
    with open(output_path, "wb") as f:
        f.write(data)

    print(f"[+] 출력 파일  : {output_path} ({len(data)} bytes)")
    print(f"[+] 완료 — C 코드의 XOR_KEY 를 0x{key:02X} 로 설정하세요.")


def main():
    # 인자 검증
    if len(sys.argv) != 4:
        print("사용법: python xor_encrypt.py <입력파일> <출력파일> <XOR키(hex)>")
        print("예시 : python xor_encrypt.py shellcode.bin shellcode.bin 0x41")
        sys.exit(1)

    input_path  = sys.argv[1]
    output_path = sys.argv[2]

    # 키 파싱 (0x41 또는 41 형식 모두 허용)
    try:
        key = int(sys.argv[3], 16)
    except ValueError:
        print(f"[!] 잘못된 XOR 키 형식: {sys.argv[3]} (예: 0x41 또는 41)")
        sys.exit(1)

    # 키 범위 확인 (0x00 ~ 0xFF)
    if not (0x00 <= key <= 0xFF):
        print(f"[!] XOR 키는 0x00 ~ 0xFF 범위여야 합니다: 0x{key:X}")
        sys.exit(1)

    xor_file(input_path, output_path, key)


if __name__ == "__main__":
    main()