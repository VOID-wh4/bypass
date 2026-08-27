> 문의사항은 @VeryBigsilver

## packer
압축 과정 중 MBA를 이용해서 난독화하는 패커
-> 현재 정적 탐지만 우회됨

## 사용법
1. (추천) 각 환경에 맞춰 컴파일
2. release에 있는 exe 파일 사용
```
packer.exe <아키텍쳐> <파일> <출력파일>
```

```
ex) packer.exe stub_win32 client.exe client_packed.exe
```
### 컴파일
```
# packer
gcc -O2 -Wall packer.c miniz.c -o packer.exe

# win64
gcc -O2 -Wall stub_win64.c miniz.c -o stub.exe -Wl,--image-base,0x60000000

# win32 (mingw32 필요)
i686-w64-mingw32-gcc -O2 -Wall stub_win32.c miniz.c -o stub.exe -Wl,--image-base,0x400000

# .net
msvc x86창에서 build_net.bat 실행

```
참고) 패킹할 파일 만들 떄 gcc보다 msvc로 컴파일 하는게 훨씬 오류가 덜함

## 주의사항
패킹할 파일에 reloc 테이블이 있어야 합니다.
```
objdump -x <파일> | Select-String -Pattern "reloc" -Context 0,2
```