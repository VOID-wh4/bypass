# dotnetXorPacker
@laneeeey

## packer

NetCrypt 기반 .NET 패커 변형본.

기존 NetCrypt에 다음 기능을 추가.

- AES 암호화 이후 XOR 변환 추가
- `Main()` / `Main(string[] args)` 엔트리포인트 처리
- 의존 DLL을 payload 컨테이너에 포함하는 CLI 경로 추가
- 큰 payload를 `payloadChunks`로 분할
- 컨테이너 헤더 검증용 `VerifyContainer()` 추가

## 사용법

1. 원본 NetCrypt 파일을 백업
2. `Packer.cs`를 원본 프로젝트의 `netcrypt/netcrypt/Packer.cs`에 반영
3. `Resources.resx`를 원본 프로젝트의 `netcrypt/netcrypt/Properties/Resources.resx`에 반영
4. `NetCryptCLI.cs`, `NetCryptCLI.csproj`를 솔루션 폴더 아래 `NetCryptCLI/`로 복사
5. `NetCryptCLI.csproj`를 솔루션에 추가
6. 솔루션 전체 Rebuild

폴더 배치:

```
netcrypt/
├── netcrypt.sln
├── netcrypt/
├── SimplePacker/
└── NetCryptCLI/
    ├── NetCryptCLI.cs
    └── NetCryptCLI.csproj
```

## CLI

```
NetCryptCLI.exe <input.exe> <output.exe> [dependency.dll ...]
```

예시:

```
NetCryptCLI.exe TestApp.exe TestApp_packed.exe TestLibrary.dll
```

의존 DLL이 없는 경우:

```
NetCryptCLI.exe TestApp.exe TestApp_packed.exe
```

## 파일 설명

- `Packer.cs`: 최종 패커 로직
- `Resources.resx`: 최종 StubCode가 반영된 리소스 파일
- `StubCode-resx.txt`: `Resources.resx`의 `StubCode` 값에 넣는 StubCode 원문
- `NetCryptCLI.cs`: CLI 진입점
- `NetCryptCLI.csproj`: CLI 프로젝트 파일

## 컴파일

Visual Studio에서 빌드:

```
netcrypt/netcrypt.sln 열기
NetCryptCLI 프로젝트 추가
전체 Rebuild
```

`NetCryptCLI.csproj`의 `ProjectReference`는 아래 배치를 기준으로 작성되어 있습니다.

```
NetCryptCLI/NetCryptCLI.csproj
netcrypt/netcrypt.csproj
```