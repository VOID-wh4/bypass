$ErrorActionPreference = "Stop"

$root = [IO.Path]::GetFullPath($PSScriptRoot)
$payloadPath = Join-Path $root "sample.exe"
$outputPath = Join-Path $root "solution.exe"
$compiler = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) "csc.exe"
$confuser = Join-Path $root "tools\ConfuserEx\bin\Confuser.CLI.exe"
$dnlib = Join-Path $root "tools\ConfuserEx\bin\dnlib.dll"

if (-not (Test-Path -LiteralPath $payloadPath -PathType Leaf)) {
    throw "sample.exe not found."
}
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
    $compiler = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
}
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
    throw ".NET Framework C# compiler was not found."
}

$workingDirectory = Join-Path ([IO.Path]::GetTempPath()) ("ctf-final-" + [Guid]::NewGuid().ToString("N"))
[IO.Directory]::CreateDirectory($workingDirectory) | Out-Null

try {
    # 모든 중간 산출물은 임시 작업 폴더에 만들며 원본 sample.exe는 수정하지 않는다.
    $sanitizerPath = Join-Path $workingDirectory "SanitizeAssembly.exe"
    $sanitizedPayloadPath = Join-Path $workingDirectory "sample-sanitized.exe"
    $payloadProtectedDirectory = Join-Path $workingDirectory "payload-protected"
    $payloadProjectPath = Join-Path $workingDirectory "payload.crproj"
    $basePath = Join-Path $workingDirectory "overlay-base.exe"
    $packagePath = Join-Path $workingDirectory "overlay-package.bin"
    $injectorPath = Join-Path $workingDirectory "ResourceInjector.exe"
    $protectedDirectory = Join-Path $workingDirectory "protected-overlay"
    $projectPath = Join-Path $workingDirectory "outer.crproj"
    $utf8WithoutBom = New-Object Text.UTF8Encoding($false)

    # ConfuserEx 1.x와 충돌하는 일부 컴파일러 생성 특성만 제거한다.
    # 형식명, 메서드명, protobuf 계약 및 Quasar 설정은 변경하지 않는다.
    & $compiler /nologo /target:exe /platform:anycpu "/out:$sanitizerPath" `
        "/reference:$dnlib" (Join-Path $root "SanitizeAssembly.cs")
    if ($LASTEXITCODE -ne 0) { throw "Payload sanitizer compilation failed." }
    [IO.File]::Copy($dnlib, (Join-Path $workingDirectory "dnlib.dll"), $true)

    & $sanitizerPath $payloadPath $sanitizedPayloadPath
    if ($LASTEXITCODE -ne 0) { throw "Payload metadata normalization failed." }

    # Quasar 기능 보존을 위해 payload에는 rename을 적용하지 않는다.
    # 상수, 제어 흐름, 리소스, anti-tamper 및 참조 프록시 보호만 적용한다.
    $payloadProject = @"
<?xml version="1.0" encoding="utf-8"?>
<project outputDir="payload-protected" baseDir="." xmlns="http://confuser.codeplex.com">
  <rule pattern="true" preset="none" inherit="false">
    <protection id="constants" action="add" />
    <protection id="ctrl flow" action="add" />
    <protection id="resources" action="add" />
    <protection id="anti tamper" action="add">
      <argument name="mode" value="normal" />
      <argument name="key" value="dynamic" />
    </protection>
    <protection id="ref proxy" action="add" />
  </rule>
  <module path="sample-sanitized.exe" />
</project>
"@
    [IO.File]::WriteAllText($payloadProjectPath, $payloadProject, $utf8WithoutBom)

    & $confuser -n $payloadProjectPath
    if ($LASTEXITCODE -ne 0) { throw "Name-preserving payload protection failed." }
    $protectedPayloadPath = Join-Path $payloadProtectedDirectory "sample-sanitized.exe"

    # 보호된 payload를 AES로 암호화하고 내부 runner와 외부 loader를 생성한다.
    # PackageOutput으로 반환된 암호문은 아래 단계에서 Win32 RCDATA로 삽입한다.
    & (Join-Path $root "Build-Loader.ps1") -Payload $protectedPayloadPath -Output $basePath `
        -PackageOutput $packagePath -Platform x64

    & $compiler /nologo /target:exe /platform:x64 "/out:$injectorPath" `
        (Join-Path $root "ResourceInjector.cs")
    if ($LASTEXITCODE -ne 0) { throw "Resource injector compilation failed." }

    # 암호화된 최초 실행용 payload를 RT_RCDATA(10), ID 101에 기록한다.
    & $injectorPath $basePath $packagePath
    if ($LASTEXITCODE -ne 0) { throw "Encrypted resource injection failed." }

    # 외부 loader는 내부 구현을 포함하므로 payload와 달리 rename까지 적용한다.
    $project = @"
<?xml version="1.0" encoding="utf-8"?>
<project outputDir="protected-overlay" baseDir="." xmlns="http://confuser.codeplex.com">
  <rule pattern="true" preset="none" inherit="false">
    <protection id="rename" action="add" />
    <protection id="constants" action="add" />
    <protection id="ctrl flow" action="add" />
    <protection id="resources" action="add" />
    <protection id="anti tamper" action="add">
      <argument name="mode" value="normal" />
      <argument name="key" value="dynamic" />
    </protection>
    <protection id="ref proxy" action="add" />
  </rule>
  <module path="overlay-base.exe" />
</project>
"@
    [IO.File]::WriteAllText($projectPath, $project, $utf8WithoutBom)

    & $confuser -n $projectPath
    if ($LASTEXITCODE -ne 0) { throw "Outer loader protection failed." }

    $protectedPath = Join-Path $protectedDirectory "overlay-base.exe"
    [IO.File]::Copy($protectedPath, $outputPath, $true)

    $result = Get-Item -LiteralPath $outputPath
    $hash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
    Write-Host ""
    Write-Host "Build complete"
    Write-Host "Output  : $outputPath"
    Write-Host "Size    : $($result.Length) bytes"
    Write-Host "SHA-256 : $hash"
}
finally {
    # 의도한 임시 폴더인지 다시 확인한 후에만 중간 산출물을 제거한다.
    if (Test-Path -LiteralPath $workingDirectory) {
        $resolvedWork = [IO.Path]::GetFullPath($workingDirectory)
        $resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        $leaf = Split-Path -Leaf $resolvedWork
        if ($resolvedWork.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase) -and
            $leaf.StartsWith("ctf-final-", [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedWork -Recurse -Force
        }
    }
}
