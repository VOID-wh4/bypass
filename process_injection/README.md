# Process Injection

Windows에서 생성한 프로세스에 데이터를 기록하고, 초기 스레드의 실행 문맥을 변경하는 과정을 살펴보는 실습 자료입니다. 기본 C 버전 두 가지와 DLL 동반 로딩을 결합한 C++ 버전을 포함합니다.

기본 버전 두 가지는 읽어 들이는 입력 파일이 다릅니다. DLL 버전은 프로세스를 생성할 때 DLL을 함께 로드하는 런처와, 해당 프로세스 안에서 AMSI 검사 함수를 후킹하는 DLL로 구성됩니다.

## 파일 구성

| 파일 | 설명 |
|---|---|
| [`process_injection.c`](./process_injection.c) | `client.bin`을 읽는 버전의 C 소스 코드 |
| `process_injection.exe` | `process_injection.c`에 대응하는 실행 파일 |
| [`process_injection_S.c`](./process_injection_S.c) | `client_S.bin`을 읽는 버전의 C 소스 코드 |
| `process_injection_S.exe` | `process_injection_S.c`에 대응하는 실행 파일 |
| `client.bin` | 기본 버전의 입력 파일. Donut으로 생성한 쉘코드 |
| `client_S.bin` | `_S` 버전의 입력 파일. 커스텀 쉘코드 |
| `P_I_DLL.exe` | DLL 동반 로딩과 프로세스 주입을 결합한 런처. 설명 기준 소스: `P_I_DLL.cpp` |
| `amsi_bypass.dll` | 로드된 프로세스의 AMSI 검사 함수를 후킹하는 DLL. 설명 기준 소스: `amsi_bypass.cpp` |

DLL 버전의 설명은 별도로 제공된 `P_I_DLL.cpp`와 `amsi_bypass.cpp`를 기준으로 작성했습니다. 두 C++ 소스는 현재 이 폴더에 포함되어 있지 않으며, 배포된 바이너리와 소스의 일치 여부는 검증하지 않았습니다.

## 동작 개요

### 기본 버전: `process_injection` / `process_injection_S`

두 소스 코드는 현재 작업 폴더에서 각 버전에 해당하는 입력 파일을 읽고, 일시 중지 상태의 메모장 프로세스를 생성합니다. 이후 대상 프로세스의 메모리에 입력 데이터를 기록하고, 초기 스레드의 실행 문맥을 변경한 뒤 실행을 재개합니다.

Enter 입력 후에는 원격 메모리와 로컬 버퍼를 해제하고, 생성한 프로세스를 종료한 뒤 프로세스·스레드 핸들을 닫습니다.

### DLL 버전: `P_I_DLL.exe`

`P_I_DLL.cpp`는 Detours를 사용해 DLL이 함께 로드되도록 메모장 프로세스를 생성하는 런처입니다. DLL 파일은 외부에서 지정받으며, 입력 데이터는 현재 작업 폴더의 `client.bin`에서 읽습니다.

기본 버전과 달리 대상 프로세스의 실행을 한 차례 재개한 뒤 다시 일시 중지하는 흐름이 포함되어 있습니다. 이후 입력 데이터를 대상 프로세스의 메모리에 기록하고 초기 스레드의 실행 문맥을 변경합니다. Enter 입력 후에는 메모리, 프로세스 및 핸들을 정리합니다.

### AMSI 후킹 DLL: `amsi_bypass.dll`

`amsi_bypass.cpp`는 자신이 로드된 프로세스의 `AmsiScanBuffer` 호출을 Detours로 후킹합니다. DLL이 프로세스에 연결될 때 후킹을 등록하고, 프로세스에서 분리될 때 후킹을 해제하는 구조입니다.

후킹 함수는 원본 검사 함수에 버퍼를 전달하지 않고 HRESULT 성공값을 반환합니다. 다만 검사 결과를 전달하는 `result` 출력값은 설정하지 않으므로, 반환값만으로 유효한 검사 결과까지 제공된다고 해석할 수는 없습니다.

프로세스 생성과 데이터 기록은 `P_I_DLL` 런처가 담당하고, AMSI 후킹은 대상 프로세스에 로드된 DLL이 담당합니다. 후킹의 범위는 해당 DLL이 로드된 프로세스입니다.

## 환경 및 확인 사항

- Windows x64 환경을 대상으로 합니다.
- 입력 파일 경로는 실행 파일의 위치가 아닌 **현재 작업 폴더**를 기준으로 해석됩니다. 기본 버전과 `P_I_DLL` 버전은 `client.bin`, `_S` 버전은 `client_S.bin`을 읽습니다.
- DLL 버전의 두 C++ 소스는 Detours에 의존합니다. 위 설명은 소스의 정적 분석에 근거하며, 바이너리의 실행 결과를 검증한 내용은 아닙니다.
- 일부 주석과 출력 메시지에는 `loader.bin` 또는 `hello_donut.bin`이라는 이름이 남아 있지만, 실제 입력 파일명은 각 소스 코드의 `fopen` 호출을 기준으로 합니다.
- 입력 바이트의 아키텍처, 진입점, 위치 독립성 및 종료 방식은 코드에서 검증하지 않습니다.
- 코드는 `PAGE_EXECUTE_READWRITE` 원격 메모리와 스레드 문맥 변경을 사용하므로 보안 제품에서 프로세스 주입 행위로 탐지될 수 있습니다.
- 입력 데이터의 실행 완료를 확인하지 않고 원격 메모리를 해제하므로 안정성 문제가 발생할 수 있습니다. 승인된 격리 실습 환경에서 분석해야 합니다.

## SHA-256

현재 폴더에 포함된 파일의 해시입니다. 파일 내용이 변경되면 해시도 갱신해야 합니다.

| 파일 | SHA-256 |
|---|---|
| `process_injection.c` | `E85AA329E690BF9A06BD5B9A079E5AFA9086F95C70014637F798B28A42E0A9C9` |
| `process_injection.exe` | `84888E76572347BB8497FE923D654199970D119E65511663082B2CF110EFAE37` |
| `process_injection_S.c` | `6EB37808F11C89F84ACE7724DFF86A990929B07E8A1C20D202EF1769594CD0F1` |
| `process_injection_S.exe` | `B29A64A7F71CC6C11EFD881BD19818CFEF04A4D58E30C0D5E535D2F6A3A0B04A` |
| `client.bin` | `F58E402ABE3269792B4C9DA73533ED3D3A4175AF07F6D16BB9568572962B3015` |
| `client_S.bin` | `92CBF38863025B2FAAE03F28EFF273045C07B0CB482D81F2B074792838920FE1` |
| `P_I_DLL.exe` | `FF99C7EC39C532C9B1B0895C588324B184BFA25520B556F9F1593A0A065A082D` |
| `amsi_bypass.dll` | `81A5CFFDD0BA67ED41CBB690260C466F900806B7655D34B8A88EABDEF5A568F6` |
