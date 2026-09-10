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
- Stub 실행 단계와 예외 정보를 `%TEMP%/ncstub.log`에 기록
- 별도 종료 모니터를 통해 payload 프로세스의 종료 코드 기록
- 의존 어셈블리 로드 성공·실패 진단 보강

## 사용법

1. 원본 NetCrypt 파일을 백업
2. 이 폴더의 `Packer.cs`를 원본 솔루션의 `netcrypt/Packer.cs`에 반영
3. 이 폴더의 `Resources.resx`를 원본 솔루션의 `netcrypt/Properties/Resources.resx`에 반영
4. 원본 솔루션 루트에 `NetCryptCLI/` 폴더를 만들고 `NetCryptCLI.cs`, `NetCryptCLI.csproj`를 복사
5. 원본 `netcrypt.sln`에 `NetCryptCLI/NetCryptCLI.csproj`를 추가
6. 솔루션 전체를 Rebuild

이 저장소의 배포 패키지 구성:

```
dotnetXorPacker/
├── NetCryptCLI.cs
├── NetCryptCLI.csproj
├── Packer.cs
├── packed_final.exe
├── Resources.resx
├── StubCode-resx.txt
└── release/
    └── NetCryptCLI-dotnet40/
        ├── NetCryptCLI.exe
        ├── NetCryptCLI.exe.config
        └── netcrypt.dll
```

원본 솔루션에 반영한 뒤의 목표 배치:

```
netcrypt/                       # 원본 솔루션 루트
├── netcrypt.sln
├── netcrypt/
│   ├── netcrypt.csproj
│   ├── Packer.cs
│   └── Properties/
│       └── Resources.resx
└── NetCryptCLI/
    ├── NetCryptCLI.cs
    └── NetCryptCLI.csproj
```

`StubCode-resx.txt`는 `Resources.resx` 내부 `StubCode`의 확인·편집용 원문이므로
원본 솔루션에 별도로 복사할 필요가 없습니다.

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
- `StubCode-resx.txt`: `Resources.resx`의 `StubCode` 값과 동기화된 StubCode 원문
- `NetCryptCLI.cs`: CLI 진입점
- `NetCryptCLI.csproj`: CLI 프로젝트 파일

`PackedClient.exe`는 저장소에서 제거하며, 필요한 실행 파일은 소스에서 직접 빌드합니다.

## 진단 로그

생성된 Stub은 실행 단계, 의존 어셈블리 로드 결과, 처리되지 않은 예외와 종료 코드를
`%TEMP%/ncstub.log`에 기록합니다.

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

## Release

Windows 실행용 파일은 `release/NetCryptCLI-dotnet40/`에 정리.

필수 파일:

```
NetCryptCLI.exe
NetCryptCLI.exe.config
netcrypt.dll
```
