# WHS4-PeBinForge

WHS4-PeBinForge는 Windows x86/x64 네이티브 PE와 .NET Framework 4 PE를 self-contained raw `.bin`으로 패키징하는 C/C++ 프로젝트입니다. 생성된 BIN은 별도 PE 파서나 런타임 컨텍스트를 준비하지 않는 작은 로더에서도 `RW 할당 → 복사 → RX 전환 → entry()` 순서로 실행할 수 있습니다.

네이티브 입력에는 위치 독립 부트스트랩과 수동 PE 매퍼를 결합하고, .NET 입력에는 CLR v4 자체 호스팅 코어를 결합합니다. 단순히 EXE의 섹션을 잘라내거나 확장자만 바꾸는 도구가 아니라, 원본 PE와 실행 코어를 하나의 독립 번들로 구성합니다.

> 이 저장소는 WHS 4기 CTF 및 Windows 로더 구조 학습·검증을 목적으로 합니다. 본인이 소유하거나 명시적으로 허가받은 환경에서만 사용하세요.

## 작동 원리

### EXE를 단순히 복사해서는 실행할 수 없는 이유

Windows의 EXE와 DLL은 곧바로 CPU가 실행할 수 있는 연속된 명령어가 아니라 PE(Portable Executable) 파일입니다. PE에는 코드와 데이터 외에도 섹션 배치, import, base relocation, TLS, 실행 권한, 진입점 같은 로더용 메타데이터가 들어 있습니다. 따라서 PE 파일 전체를 `VirtualAlloc` 영역에 복사한 뒤 첫 바이트를 함수처럼 호출하면 DOS/PE 헤더를 명령어로 해석하게 되며 정상적으로 실행되지 않습니다.

WHS4-PeBinForge는 확장자를 바꾸거나 PE 헤더를 제거하는 변환기가 아닙니다. 입력 PE를 그대로 보존하면서, 해당 PE를 메모리에서 초기화할 수 있는 위치 독립 실행 코어와 첫 바이트의 부트스트랩을 앞에 결합합니다. 결과 BIN의 첫 주소는 원본 EXE의 첫 주소가 아니라 PeBinForge가 만든 `entry()`입니다.

```text
일반 PE
[DOS/PE headers][sections][imports][relocations][resources ...]
        └─ 파일 그대로 복사한 주소는 호출 가능한 entry()가 아님

PeBinForge BIN
[entry trampoline][PIC 실행 코어][원본 PE와 의존성][검증용 footer]
        └─ BIN의 첫 바이트부터 호출 가능
```

### 패키징 단계

`pbf pack`은 먼저 PE 헤더와 CLR 헤더를 검사하여 네이티브/.NET 여부와 x86/x64 아키텍처를 판별합니다. 이후 입력 종류에 맞는 실행 코어를 선택해 하나의 raw BIN을 만듭니다.

네이티브 EXE/DLL은 다음 구조로 패키징됩니다.

```text
[noargs trampoline]
[native v3 header]
[PIC PE mapper]
[module manifest]
[페이지 정렬된 주 PE]
[같이 포함된 사설 DLL들]
[native v3 footer]
```

입력 PE와 같은 폴더에서 발견한 동일 아키텍처의 사설 DLL import는 최대 16개까지 재귀적으로 찾아 함께 넣습니다. 시스템 DLL은 번들에 복사하지 않고 실행 시 Windows가 제공하는 모듈을 사용합니다.

.NET Framework 4 어셈블리는 다음 구조로 패키징됩니다.

```text
[noargs trampoline]
[managed v2 header]
[PIC CLR v4 host]
[페이지 정렬된 관리형 PE]
[managed v2 footer]
```

CLR 헤더의 CorFlags를 이용해 x86, x64, AnyCPU를 구분합니다. AnyCPU는 기본적으로 x64 코어를 사용하고 `32BITREQUIRED` 또는 `32BITPREFERRED`가 설정된 PE는 x86 코어를 사용합니다.

### 실행 단계

최소 로더가 담당하는 일은 의도적으로 단순합니다.

```text
BIN 읽기
  → VirtualAlloc(PAGE_READWRITE)
  → BIN 복사
  → VirtualProtect(PAGE_EXECUTE_READ)
  → FlushInstructionCache
  → BIN 첫 주소의 entry() 호출
```

처음부터 `PAGE_EXECUTE_READWRITE`로 할당하지 않고 쓰기 단계와 실행 단계를 분리합니다. 실제 PE 해석과 초기화는 외부 로더가 아니라 BIN 내부의 self-bootstrap이 수행합니다.

네이티브 BIN의 내부 실행 순서는 다음과 같습니다.

```text
자기 BIN base 계산
  → bundle header/footer와 module manifest 확인
  → 필요한 Windows API 해석
  → 각 PE의 메모리 이미지 공간 할당
  → PE 섹션 배치
  → base relocation 적용
  → 내장 DLL과 시스템 DLL을 이용해 import/IAT 연결
  → TLS callback 및 x64 예외 테이블 초기화
  → 섹션별 최종 메모리 권한 적용
  → EXE AddressOfEntryPoint 또는 DLL DllMain/PbfEntry 호출
```

x64 부트스트랩은 RIP-relative 주소 계산을, x86 부트스트랩은 `CALL/POP` 방식을 사용해 고정 주소 없이 자신의 BIN base를 구합니다. 그래서 `VirtualAlloc`이 어느 주소를 반환하더라도 같은 BIN을 실행할 수 있습니다.

.NET BIN은 PE를 네이티브 명령어로 직접 실행하지 않습니다. 내부 PIC 호스트가 CLR v4를 시작하고, 번들에 포함된 어셈블리 바이트를 메모리에서 로드한 뒤 어셈블리 진입점인 매개변수 없는 정적 `int Main()`을 호출합니다. 원본 관리형 EXE를 임시 파일로 풀지 않지만, 대상 시스템에는 .NET Framework 4 런타임이 있어야 합니다.

### 두 가지 진입 ABI

- `entry()`: 아무 인자도 필요 없는 독립 실행 경로입니다. 사용자가 만든 최소 로더처럼 BIN 첫 주소만 호출할 때 사용합니다.
- `entry(&context)`: 입력값, 결과값, proof, 상태 코드 같은 정보를 전문 러너와 주고받는 검증 경로입니다.

`CreateThread`의 시작 함수는 `DWORD WINAPI function(LPVOID)` 호출 규약을 요구하므로 BIN의 noargs `entry()`를 그대로 `LPTHREAD_START_ROUTINE`으로 캐스팅하지 않습니다. `thread-memory-loader`는 올바른 스레드 시작 함수가 BIN의 `entry()`를 대신 호출하는 ABI 어댑터를 사용합니다.

### 무결성 검증 범위

패키징 시 BIN과 함께 `.sha256` sidecar가 생성됩니다. `pbf run`과 전문 러너는 실행 전에 이를 확인하며, 선택적으로 ECDSA 서명까지 강제할 수 있습니다. 반면 `simple-memory-loader`는 BIN 자체의 독립성을 보여주는 예제라서 의도적으로 header, footer, hash를 해석하지 않습니다. 검증이 필요한 환경에서는 최소 로더가 아니라 `pbf run --pubkey ...` 또는 전문 러너를 사용해야 합니다.

이 도구가 만드는 결과물은 범용 기계어 변환본이 아니라 원본 PE와 실행 코어를 결합한 Windows 전용 번들입니다. BIN과 실행 프로세스의 아키텍처가 일치해야 하며, 원본 프로그램이 요구하는 운영체제 기능과 .NET 런타임 조건도 그대로 적용됩니다.

## 빠른 시작

### 1. 빌드

Visual Studio 2022 C++ Build Tools가 설치된 Windows에서 실행합니다.

```powershell
.\build.ps1
```

PowerShell 실행 정책에 막히면 설정을 영구 변경하지 않고 다음 래퍼를 사용할 수 있습니다.

```cmd
build.cmd
```

### 2. 입력 파일 확인

```powershell
.\build\pbf.exe inspect .\program.exe
```

출력에서 `native x86`, `native x64`, `.NET Framework 4 x86`, `.NET Framework 4 x64` 중 어떤 형식인지 확인합니다. BIN과 로더의 아키텍처는 반드시 같아야 합니다.

### 3. EXE 또는 DLL을 BIN으로 패키징

```powershell
.\build\pbf.exe pack .\program.exe .\program.bin --force
.\build\pbf.exe inspect .\program.bin
```

입력 아키텍처와 네이티브/.NET 여부는 자동 판별됩니다. 네이티브 PE가 같은 폴더의 사설 DLL을 import하면 동일 아키텍처 DLL을 재귀적으로 함께 포함합니다.

### 4. 실행

무결성 검증과 자동 아키텍처 선택이 필요한 기본 실행 방식입니다.

```powershell
.\build\pbf.exe run .\program.bin
```

BIN의 독립 `entry()`만 검증하려면 다음 최소 로더를 사용합니다.

```powershell
# x64 BIN
.\build\simple-memory-loader.exe .\program.bin

# x86 BIN
.\build\x86\simple-memory-loader-x86.exe .\program.bin
```

`CreateThread` 방식은 BIN 주소를 `LPTHREAD_START_ROUTINE`으로 직접 캐스팅하지 않고, 제공되는 호출 규약 어댑터를 사용합니다.

```powershell
# x64 BIN
.\build\thread-memory-loader.exe .\program.bin

# x86 BIN
.\build\x86\thread-memory-loader-x86.exe .\program.bin
```

### 지원 범위

| 입력 | 지원 범위 |
|---|---|
| 네이티브 x86/x64 EXE | 일반 MSVC entrypoint, imports, base relocation, TLS callback, 동일 폴더 사설 DLL |
| 네이티브 x86/x64 DLL | `DllMain`, imports, exports, base relocation, TLS callback |
| .NET Framework 4 EXE | IL-only, x86/x64/AnyCPU, 매개변수 없는 정적 `int Main()` |
| 미지원 | .NET 6/8, mixed-mode C++/CLI, delay-load import, 임의 관리형 메서드 지정 |

## 현재 완성된 기능

현재 버전은 특별히 작성한 C 함수를 실제 위치 독립 raw code로 변환하는 최소 end-to-end 경로를 제공합니다.

```text
payloads/demo.c
   ↓ MSVC COFF object
build/obj/demo.obj
   ↓ pbfgen: .pbf section + relocation=0 검사
build/demo.bin + demo.bin.sha256
   ↓ pbf-runner: SHA-256 검사, RW 할당, RX 전환, 호출
실행 결과
```

일반 네이티브 x86 또는 x64 EXE/DLL은 해당 아키텍처의 자체 PIC 매퍼와 결합하여 첫 바이트부터 실행되는 단일 raw BIN으로 만듭니다. 진입 PE와 같은 폴더에서 발견되는 동일 아키텍처의 사설 DLL import는 최대 16개까지 재귀 탐색하여 함께 포함합니다.

```text
native-exe-demo.exe 또는 native-demo.dll
                  ↓ pbfdep.dll → pbfleaf.dll
             + native_stub.obj
   ↓ native-bin-gen: import 재귀 탐색, COFF REL32 내부 링크, v3 self-bootstrap 생성
native-demo.bin + native-demo.bin.sha256
   ↓ 아무 독립 로더: RW 할당 → 복사 → RX → entry()
self-bootstrap → PEB/API 해석 → PIC 매퍼 → 내장 DLL 우선 import → TLS → EXE entry 또는 DllMain/PbfEntry
```

v3 native BIN 레이아웃은 `[noargs 트램펄린][고정 self-bootstrap 헤더][PIC 매퍼][module manifest][페이지 정렬된 PE들][footer]`입니다. x64는 RIP-relative 트램펄린, x86은 `CALL/POP` 트램펄린으로 자신의 base를 계산합니다. PIC bootstrap은 PEB의 로드 모듈 export를 찾아 Windows API 테이블과 작업공간을 자체 구성합니다. 내장 DLL은 디스크에 풀지 않고 각자 메모리 매핑되며, 이름/ordinal export를 이용해 IAT를 연결합니다.

네이티브 EXE는 PE의 실제 `AddressOfEntryPoint`를 호출합니다. 실행 동안 PEB의 main image base를 매핑된 EXE로 교체하므로 `GetModuleHandle(NULL)` 계열의 기본 동작을 보존합니다. 일반 CRT EXE가 `ExitProcess`를 호출하면 러너도 응용 프로그램의 종료 코드로 종료되며, 이 경우 메모리 정리는 운영체제가 처리합니다.

.NET Framework 4 어셈블리도 아키텍처별 관리형 PIC 진입부와 함께 단일 raw BIN으로 패키징합니다. CLR 헤더의 CorFlags를 읽어 AnyCPU는 기본 x64, `32BITREQUIRED`/`32BITPREFERRED`는 x86, PE32+ AMD64는 x64 호스트를 자동 선택합니다.

```text
ManagedEntry.exe + x64/x86 managed_pic_stub.obj
   ↓ managed-bin-pack: CorFlags 판별, COFF REL32 내부 링크, v2 layout/footer + SHA-256 생성
managed-demo.bin + managed-demo.bin.sha256
   ↓ 아무 독립 로더: RW 할당 → 복사 → RX → 첫 주소의 entry()
self-bootstrap → PEB/API 해석 → CLR v4/COM 호스팅 → 메모리 바이트에서 Main 호출
```

관리형 v2 BIN 레이아웃은 `[noargs 트램펄린][중복 검증 헤더][PIC CLR 호스트][페이지 정렬된 관리형 PE][중복 footer]`입니다. 첫 주소는 x64 RIP-relative 또는 x86 `CALL/POP` 방식으로 BIN base를 스스로 계산합니다. PIC 코어는 PEB의 로드 모듈 export를 해석해 `LoadLibraryA`, COM/OLE Automation, `CLRCreateInstance`를 구하고 CLR v4를 시작하므로 러너 콜백이 필요하지 않습니다. 전문 러너는 별도의 컨텍스트 엔트리와 콜백도 시험하여 두 ABI를 모두 검증합니다.

현재 관리형 진입 규약은 .NET Framework 4의 매개변수 없는 정적 `Main()`이며 반환값은 `int`여야 합니다. .NET Core/.NET 5+와 `string[] args`, 비동기 `Main`은 아직 지원하지 않습니다.

`pbfgen`은 단순히 `.text`를 복사하지 않습니다. AMD64 COFF 형식, 전용 `.pbf` code section, raw-data 범위, 크기 제한, relocation 개수를 검사합니다. relocation이 하나라도 있으면 위치 독립 코드가 아니므로 변환을 거부합니다.

raw PIC BIN은 기본 `entry(&context)` ABI와 인자 없는 독립형 `entry()` ABI를 모두 지원합니다. 독립형 모드는 `--entry noargs`로 선택하며 반환값이나 러너 컨텍스트를 요구하지 않습니다. `--inject-pid <PID>`를 추가하면 기존의 다른 x64 프로세스에 raw code를 주입합니다. 이 경로는 대상 프로세스를 열고 원격 `RW` 메모리에 payload를 복사한 뒤 `RX`로 전환하고 원격 스레드로 첫 바이트를 호출합니다. 컨텍스트 ABI에서는 별도의 원격 `RW` 컨텍스트를 전달하고 실행 후 결과와 proof를 다시 읽습니다.

일반 raw PIC 러너 입력은 1 MiB로, self-contained native 번들은 64 MiB로 제한합니다. 전문 러너는 생성 시 만든 SHA-256 sidecar를 검증합니다. 모든 실행 경로는 메모리를 `RWX`로 할당하지 않고 `RW`로 복사한 뒤 `RX`로 변경합니다.

## 빌드와 테스트

Visual Studio 2022의 C/C++ 빌드 도구가 필요합니다.

```powershell
.\build.ps1
.\tests\test.ps1
```

PowerShell 실행 정책으로 `.ps1` 실행이 차단된 환경에서는 시스템 설정을 변경하지 않고 CMD 래퍼를 사용합니다.

```powershell
.\build.cmd
.\test.cmd
```

또는 현재 PowerShell 프로세스에만 일시적으로 허용할 수 있습니다.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\build.ps1
.\tests\test.ps1
```

주요 결과물:

- `build\pbf.exe`: 판별·패키징·실행·ECDSA 서명을 묶은 통합 CLI
- `build\pbfgen.exe`: 자체 C COFF→BIN 생성기
- `build\pbf-runner.exe`: raw-code 로컬 실행 및 원격 PID 주입기
- `build\simple-memory-loader.exe`: BIN 파싱이나 컨텍스트 준비 없이 `RW→복사→RX→entry()`만 수행하는 독립 검증 로더
- `build\thread-memory-loader.exe`: x86/x64 호출 규약 어댑터를 거쳐 `CreateThread`에서 noargs `entry()`를 검증하는 로더
- `build\injection-target.exe`: 원격 PID 주입 자동 테스트용 무해한 x64 대상 프로세스
- `build\peprobe.exe`: 네이티브/CLR PE 분류 및 data-directory 분석기
- `build\native-maptest.exe`: 현재 프로세스 전용 x64 DLL 매퍼 검증기
- `build\native-demo.dll`: import/export가 있는 매퍼 검증용 DLL
- `build\native-exe-demo.exe`: 일반 MSVC CRT entrypoint와 종료 코드 검증용 EXE
- `build\native-exe-demo.bin`: EXE와 재귀 DLL 체인을 포함한 self-contained native v3 BIN
- `build\pbfdep.dll`, `build\pbfleaf.dll`: 재귀 내장 import 검증용 사설 DLL 체인
- `build\native-bin-gen.exe`: COFF PIC 내부 링크 및 DLL 결합 생성기
- `build\native-bin-runner.exe`: SHA-256, v3 헤더와 context 결과까지 확인하는 전문 검증 실행기
- `build\native-demo.bin`: `[self-bootstrap][PIC 매퍼][DLL 체인][footer]` 단일 raw BIN
- `build\x86\simple-memory-loader-x86.exe`: CRT 없이 빌드된 x86 native v3 BIN용 독립 `RW→복사→RX→entry()` 로더
- `build\x86\thread-memory-loader-x86.exe`: x86 `CreateThread` 호출 규약을 안전하게 맞추는 독립 검증 로더
- `build\x86\native-demo-x86.bin`: x86 DLL과 재귀 의존성을 포함한 검증 번들
- `build\x86\native-exe-demo-x86.bin`: 재배치 가능한 x86 EXE 검증 번들
- `build\x86\fixed-exe-demo-x86.bin`: ImageBase `0x400000`, relocation 없는 x86 EXE 검증 번들
- `build\clr-maptest.exe`: C 기반 CLR v4 in-memory assembly host 검증기
- `build\obj\managed_pic_stub.obj`: x64 self-contained CLR v4 PIC 코어
- `build\x86\obj\managed_pic_stub.obj`: x86 self-contained CLR v4 PIC 코어
- `build\managed-bin-pack.exe`: 관리형 PE와 선택된 PIC COFF 코어를 v2 단일 BIN으로 패키징
- `build\managed-bin-runner.exe`: v2 헤더·SHA-256·컨텍스트 엔트리를 검증하는 x64 관리형 BIN 실행기
- `build\x86\managed-bin-runner-x86.exe`: x86 전용 CLR v4 메모리 호스트/번들 실행기
- `build\x86\clr-maptest-x86.exe`: x86 관리형 어셈블리 메모리 로드 검증기
- `build\managed-demo.bin`: 테스트에서 생성되는 `[트램펄린][헤더][PIC CLR 호스트][관리형 PE][footer]` BIN
- `build\demo.bin`: C로 작성한 위치 독립 raw code
- `build\standalone-demo.bin`: 인자 없는 `entry()` ABI 검증용 raw code
- `build\demo.bin.sha256`: 무결성 sidecar

`simple-memory-loader.exe`는 self-contained ABI 검증을 위해 의도적으로 BIN이나 sidecar를 파싱하지 않습니다. 무결성·서명 정책이 필요한 실제 실행에는 `pbf run --pubkey ...` 또는 전문 러너를 사용합니다.

## 통합 CLI

`pbf.exe`는 입력을 검사하여 관리형 PE, 네이티브 x86/x64 EXE/DLL, 전용 `.pbf` COFF object를 적절한 backend로 전달합니다. 네이티브 PE를 패키징할 때 같은 폴더에 존재하는 동일 아키텍처의 사설 DLL import는 자동으로 따라가므로 별도의 dependency 인자가 필요하지 않습니다.

```powershell
# 형식 확인
.\build\pbf.exe inspect .\build\native-demo.dll

# 자동 판별 후 raw BIN 생성
.\build\pbf.exe pack .\build\native-demo.dll .\build\app.bin --force
.\build\pbf.exe pack .\build\native-exe-demo.exe .\build\native-app.bin --force
.\build\pbf.exe pack .\build\ManagedEntry.exe .\build\managed-app.bin --force

# /platform:x86, /platform:x64, AnyCPU는 자동 판별
.\build\pbf.exe pack .\build\ManagedEntry-x86.exe .\build\managed-x86.bin --force

# x86 EXE 예시(basic.exe가 x86이어도 자동 판별)
.\build\pbf.exe pack .\basic.exe .\shell.bin --force

# 로컬 실행
.\build\pbf.exe run .\build\app.bin 40 2
.\build\pbf.exe run .\build\native-app.bin
.\build\pbf.exe run .\build\managed-app.bin
.\build\pbf.exe run .\build\managed-x86.bin
.\build\pbf.exe run .\shell.bin

# 별도 초소형 로더: BIN을 파싱하지 않고 첫 주소의 entry()만 호출
.\build\simple-memory-loader.exe .\build\native-app.bin
.\build\simple-memory-loader.exe .\build\managed-app.bin
.\build\x86\simple-memory-loader-x86.exe .\shell.bin

# CreateThread가 필요할 때는 호출 규약 어댑터를 포함한 로더 사용
.\build\thread-memory-loader.exe .\build\managed-app.bin
.\build\x86\thread-memory-loader-x86.exe .\build\managed-x86.bin

# 기존 x64 프로세스에 컨텍스트 ABI raw code 주입
.\build\pbf.exe run .\build\demo.bin 40 2 --inject-pid 1234

# 같은 대상에 인자 없는 raw entry() 주입
.\build\pbf.exe run .\build\standalone-demo.bin --entry noargs --inject-pid 1234
```

### TEST.EXE + test1.dll 예제

빌드하면 `build\example`에 실제 정적 import 관계를 가진 테스트 파일과 단일 BIN이 생성됩니다.

```text
build\example\TEST.EXE
build\example\test1.dll
        ↓ 자동 패키징
build\example\TEST.bin
```

```powershell
.\build\pbf.exe inspect .\build\example\TEST.EXE
.\build\pbf.exe inspect .\build\example\TEST.bin
.\build\pbf.exe run .\build\example\TEST.bin
$LASTEXITCODE  # test1.dll의 Test1Add(40, 2) 결과인 42
```

자동 테스트는 원본 `test1.dll`을 잠시 치운 상태에서도 `TEST.bin`이 종료 코드 42를 반환하는지 확인합니다.

## 패키지 서명

SHA-256 sidecar는 우발적인 손상은 찾지만 파일과 sidecar를 함께 교체하는 공격에 대한 출처 증명은 제공하지 않습니다. 통합 CLI는 Windows CNG의 ECDSA P-256 서명을 별도의 `.sig` 파일로 생성하고 실행 전에 공개키로 검증할 수 있습니다.

```powershell
# 최초 1회 키 쌍 생성
New-Item -ItemType Directory -Force .\keys | Out-Null
.\build\pbf.exe keygen .\keys\release

# release.pbfpriv로 서명하고 release.pbfpub로 검증
.\build\pbf.exe sign .\keys\release.pbfpriv .\build\managed-app.bin
.\build\pbf.exe verify .\keys\release.pbfpub .\build\managed-app.bin

# 서명이 유효할 때만 실행
.\build\pbf.exe run .\build\managed-app.bin --pubkey .\keys\release.pbfpub
```

`.pbfpriv`는 서명 권한 그 자체이므로 저장소나 배포물에 포함하지 말고 별도로 보호해야 합니다. 배포에는 `.pbfpub`, `.bin`, `.bin.sha256`, `.bin.sig`만 포함합니다. `--pubkey`를 지정하면 서명 누락, 다른 키, BIN 변조를 모두 실행 전에 거부합니다. 전문 backend 러너를 직접 호출하면 ECDSA 정책을 우회하고 기존 SHA-256만 검사하므로, 서명 필수 배포에서는 `pbf run --pubkey ...`를 진입점으로 사용합니다.

## C payload 작성 규칙

- 진입 함수는 `.pbf` code section에 둡니다.
- 외부 함수, 전역 변수, 문자열 리터럴을 참조하지 않습니다.
- 빌드 시 `/GS-`, `/GR-`, `/Zl` 제한을 유지합니다.
- `pbf_context` ABI를 사용합니다.
- 컨텍스트가 필요 없는 payload는 `entry()`로 작성하고 실행 시 `--entry noargs`를 지정합니다.
- 다른 프로세스에서 실행할 때는 대상과 러너가 모두 x64여야 하며 `--inject-pid`에 현재 실행 중인 다른 PID를 지정합니다.
- 생성기가 relocation=0을 확인하기 전에는 결과를 raw code로 취급하지 않습니다.

## 다음 단계

완성된 네이티브 매핑 코어는 PE32/PE32+ 섹션 복사, x86 `HIGHLOW`/x64 `DIR64` base relocation, 재귀 내장 imports, 시스템 imports, TLS callback, section protection, x64 unwind function table 등록, `DllMain`, export 탐색을 처리합니다. `native-bin-gen`은 MSVC COFF의 `.pbf` section을 읽고 내부 I386/AMD64 `REL32` relocation을 직접 해결합니다.

1. 현대 .NET 6/8용 `hostfxr` 백엔드와 CLR v4 backend 자동 구분
2. Windows 인증서 저장소 또는 하드웨어 키를 이용한 private-key 보호
3. 네이티브 EXE 명령행/환경 정책 확장

현재 내장 종속성은 주 PE와 같은 아키텍처, 동일 폴더 자동 탐색, 최대 16개로 제한됩니다. 내장 사설 DLL의 forwarded export와 delay-load import는 아직 지원하지 않으며, 같은 폴더에 없는 import는 시스템의 `LoadLibrary` 검색 규칙으로 처리합니다. 재배치가 필요한 PE에는 해당 아키텍처의 유효한 base relocation directory가 있어야 합니다. relocation이 없고 ImageBase가 `0x400000`인 x86 EXE를 위해 제공 로더는 그 주소에 64 MiB의 가상 이미지 공간을 먼저 차지한 뒤, 별도 RX 메모리에서 실행되는 PIC가 해당 공간을 대상 EXE로 교체합니다. 로더의 디스크 파일 크기는 약 3 KiB이며 이 가상 여유 공간은 파일에 0으로 저장되지 않습니다.

EXE 1차 지원에는 사용자 지정 명령행, loader module list 등록, 완전한 static TLS 초기화가 없습니다. 따라서 자체 모듈 열거, 특수 런처/보호기, 복잡한 TLS 또는 delay-load에 의존하는 EXE는 거부되거나 실행에 실패할 수 있습니다. 현재 검증 범위는 일반 MSVC x86/x64 콘솔 EXE, 정적 CRT, 재귀 사설 DLL import, 정상 `main()` 종료입니다. x86 번들의 통합 실행 경로는 독립 `entry()`를 사용하므로 숫자 context 입력은 받지 않습니다.

관리형 backend의 현재 범위는 .NET Framework 4, IL-only EXE, 매개변수 없는 정적 `Main`, 메모리 바이트에서의 `Assembly.Load`입니다. x86/x64/AnyCPU를 지원하지만 C++/CLI mixed-mode, 일반 DLL의 임의 메서드 지정, `Main(string[] args)`, .NET Core/.NET 5+는 아직 지원하지 않습니다.

암호화, 난독화, AMSI/ETW 우회와 원격 staging은 프로젝트 범위에 포함하지 않습니다. 통합 CLI의 `--inject-pid`는 현재 relocation 없는 1 MiB 이하 raw PIC BIN에 한해 지원합니다. native v3 및 managed v2 BIN은 모두 현재 프로세스의 컨텍스트 없는 `entry()` 형식이며, 최대 64 MiB self-contained 번들을 다루는 통합 원격 주입 정책은 별도입니다.
