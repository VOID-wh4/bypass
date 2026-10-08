# Quasar 빌드 및 실행

## 1. 입력 파일 준비

Quasar client를 다음 위치에 넣는다.

```text
inputs\quasar.exe
```

## 2. 빌드

PowerShell에서 이 폴더로 이동한 후 실행한다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

빌드 결과는 `output\quasar`에 생성된다.

- `submit.exe`: 실행파일
- `stage.dat`: stage server가 전송할 데이터
- `connection.txt`: 추출된 Quasar 및 stage server 접속정보

## 3. 호스트에서 실행

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\start-runtime.ps1
```

해당 프로그램이 작동하기 위해서는 호스트에서 stage server를 실행시켜야 한다.
