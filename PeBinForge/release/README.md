# WHS4-PeBinForge v0.3.0 배포본

이 폴더는 Visual Studio로 직접 빌드하지 않고 사용할 수 있는 Windows x86/x64 배포본을 제공합니다.

## 다운로드 파일

- [`WHS4-PeBinForge-v0.3.0-windows-x86-x64.zip`](./WHS4-PeBinForge-v0.3.0-windows-x86-x64.zip): x64 통합 CLI, 패킹 백엔드, x86/x64 PIC 코어 및 최소 메모리 로더
- [`SHA256.txt`](./SHA256.txt): ZIP 무결성 확인값

일반 네이티브 PE 패키징에는 Visual Studio가 필요하지 않습니다. .NET Framework 4 어셈블리를 실행할 대상 PC에는 해당 런타임이 설치되어 있어야 합니다.

## 무결성 확인

PowerShell에서 다음 명령을 실행합니다.

```powershell
(Get-FileHash .\WHS4-PeBinForge-v0.3.0-windows-x86-x64.zip -Algorithm SHA256).Hash.ToLower()
```

출력값이 다음 값과 일치해야 합니다.

```text
d06555136f62bd34f29f4a110048f49896fa21b64e11c312cd7d1a4cd10569e1
```

## 사용 방법

ZIP을 내려받아 원하는 폴더에 압축을 풉니다.

```powershell
Expand-Archive .\WHS4-PeBinForge-v0.3.0-windows-x86-x64.zip .\WHS4-PeBinForge
cd .\WHS4-PeBinForge\WHS4-PeBinForge-v0.3.0-windows-x86-x64
```

입력 파일을 확인하고 BIN으로 패키징합니다.

```powershell
.\pbf.exe inspect .\program.exe
.\pbf.exe pack .\program.exe .\program.bin --force
.\pbf.exe inspect .\program.bin
```

생성된 BIN을 기본 러너로 실행합니다.

```powershell
.\pbf.exe run .\program.bin
```

BIN의 아키텍처와 실행 프로세스의 아키텍처는 반드시 일치해야 합니다. 전체 작동 원리, 지원 범위, 최소 로더 사용법 및 서명 검증 방법은 상위 [PeBinForge README](../README.md)를 확인하세요.

> 이 배포본은 WHS 4기 CTF 및 Windows 로더 구조 학습·검증을 목적으로 합니다. 본인이 소유하거나 명시적으로 허가받은 환경에서만 사용하세요.
