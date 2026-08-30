# Process Injection

Windows에서 정지 상태로 생성한 프로세스에 데이터를 기록하고 초기 스레드의 실행 문맥을 변경하는 과정을 학습하기 위한 C 실습 자료입니다.

## 파일 구성

| 파일 | 설명 |
|---|---|
| `process_injection.c` | `CreateProcessA`, `VirtualAllocEx`, `WriteProcessMemory`, `GetThreadContext`, `SetThreadContext`, `ResumeThread` 흐름을 포함한 원본 소스 코드 |
| `process_injection.exe` | 위 소스의 Windows x64 빌드 결과물 |

## 동작 개요

1. 현재 작업 폴더에서 `client.bin`을 읽습니다.
2. `C:\Windows\System32\notepad.exe`를 `CREATE_SUSPENDED` 상태로 생성합니다.
3. 대상 프로세스에 원격 메모리를 할당하고 입력 바이트를 기록합니다.
4. 초기 스레드의 `RIP`를 할당된 메모리 주소로 변경합니다.
5. 스레드를 재개한 뒤 사용자 입력을 기다리고 관련 자원을 정리합니다.

## 요구 사항 및 주의점

- Windows x64 환경을 대상으로 합니다.
- 실행 시 별도의 `client.bin` 파일이 필요하며 이 폴더에는 포함하지 않았습니다.
- 입력 바이트의 아키텍처, 진입점, 위치 독립성 및 종료 방식은 코드에서 검증하지 않습니다.
- 코드는 `PAGE_EXECUTE_READWRITE` 원격 메모리와 스레드 문맥 변경을 사용하므로 보안 제품에서 프로세스 주입 행위로 탐지될 수 있습니다.
- 실행 중인 원격 메모리를 해제할 가능성 등 안정성 문제가 있으므로 실제 시스템이나 제3자 프로세스가 아닌 승인된 격리 실습 환경에서만 분석해야 합니다.

## SHA-256

```text
process_injection.c    E85AA329E690BF9A06BD5B9A079E5AFA9086F95C70014637F798B28A42E0A9C9
process_injection.exe  84888E76572347BB8497FE923D654199970D119E65511663082B2CF110EFAE37
```

## 면책

본 자료는 Windows 내부 동작과 보안 탐지 기법을 학습하기 위한 연구·교육용 자료입니다. 허가받지 않은 시스템이나 프로세스에 사용해서는 안 됩니다.
