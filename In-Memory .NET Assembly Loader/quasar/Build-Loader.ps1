[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Payload,

    [Parameter(Position = 1)]
    [string] $Output = ".\loader.exe",

    [string] $PackageOutput = "",

    [ValidateSet("x64", "x86", "anycpu")]
    [string] $Platform = "x64"
)

$ErrorActionPreference = "Stop"

# 빌드 결과를 식별하기 위한 SHA-256 계산 함수다.
function Get-Sha256Hex([string] $Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($stream))).Replace("-", "")
    }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

$payloadPath = (Resolve-Path -LiteralPath $Payload).Path
$outputPath = [IO.Path]::GetFullPath($Output)
$packageOutputPath = if ([string]::IsNullOrWhiteSpace($PackageOutput)) { $null } else { [IO.Path]::GetFullPath($PackageOutput) }
$templatePath = Join-Path $PSScriptRoot "LoaderStub.cs.in"
$runnerTemplatePath = Join-Path $PSScriptRoot "SandboxRunner.cs.in"
$compilerPath = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) "csc.exe"

if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
    throw "Loader template not found: $templatePath"
}
if (-not (Test-Path -LiteralPath $runnerTemplatePath -PathType Leaf)) {
    throw "Runner template not found: $runnerTemplatePath"
}

if (-not (Test-Path -LiteralPath $compilerPath -PathType Leaf)) {
    $compilerPath = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
}

if (-not (Test-Path -LiteralPath $compilerPath -PathType Leaf)) {
    throw "The .NET Framework C# compiler was not found."
}

$outputDirectory = Split-Path -Parent $outputPath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ("ctf-loader-" + [Guid]::NewGuid().ToString("N"))
[IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null

try {
    # 빌드할 때마다 새로운 AES 키와 IV를 생성하므로 같은 payload도 암호문이 달라진다.
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $key = New-Object byte[] 32
        $iv = New-Object byte[] 16
        $random.GetBytes($key)
        $random.GetBytes($iv)
    }
    finally {
        $random.Dispose()
    }

    # 보호된 .NET payload 전체를 AES-256-CBC/PKCS7로 암호화한다.
    $encryptedPath = Join-Path $temporaryDirectory "package.bin"
    $inputStream = [IO.File]::OpenRead($payloadPath)
    $encryptedStream = [IO.File]::Create($encryptedPath)
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $key
        $aes.IV = $iv
        $encryptor = $aes.CreateEncryptor()
        $cryptoStream = New-Object Security.Cryptography.CryptoStream(
            $encryptedStream,
            $encryptor,
            [Security.Cryptography.CryptoStreamMode]::Write
        )
        try {
            $inputStream.CopyTo($cryptoStream)
            $cryptoStream.FlushFinalBlock()
        }
        finally {
            $cryptoStream.Dispose()
            $encryptor.Dispose()
        }
    }
    finally {
        $inputStream.Dispose()
        $encryptedStream.Dispose()
        $aes.Dispose()
    }
    if ($packageOutputPath) {
        # 외부 build.ps1이 이 파일을 RCDATA ID 101에 삽입한다.
        $packageDirectory = Split-Path -Parent $packageOutputPath
        if (-not (Test-Path -LiteralPath $packageDirectory -PathType Container)) {
            New-Item -ItemType Directory -Path $packageDirectory | Out-Null
        }
        [IO.File]::Copy($encryptedPath, $packageOutputPath, $true)
    }

    # 소스 템플릿의 이름과 AppDomain 슬롯을 빌드마다 무작위 값으로 치환한다.
    $namespaceName = "Runtime" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
    $className = "Module" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
    $resourceName = "Data" + [Guid]::NewGuid().ToString("N")
    $warmupResourceName = "Warmup" + [Guid]::NewGuid().ToString("N")
    $runnerResourceName = "Runner" + [Guid]::NewGuid().ToString("N")
    $runnerPayloadResourceName = "Payload" + [Guid]::NewGuid().ToString("N")
    $runnerWarmupResourceName = "RunnerWarmup" + [Guid]::NewGuid().ToString("N")
    $imageSlot = "Image" + [Guid]::NewGuid().ToString("N")
    $argumentSlot = "Args" + [Guid]::NewGuid().ToString("N")
    $source = [IO.File]::ReadAllText($templatePath)
    $source = $source.Replace("__NAMESPACE__", $namespaceName)
    $source = $source.Replace("__CLASS__", $className)
    $source = $source.Replace("__KEY__", [Convert]::ToBase64String($key))
    $source = $source.Replace("__IV__", [Convert]::ToBase64String($iv))
    $source = $source.Replace("__RESOURCE__", $resourceName)
    $source = $source.Replace("__WARMUP_RESOURCE__", $warmupResourceName)
    $source = $source.Replace("__RUNNER_RESOURCE__", $runnerResourceName)
    $source = $source.Replace("__IMAGE_SLOT__", $imageSlot)
    $source = $source.Replace("__ARGUMENT_SLOT__", $argumentSlot)
    $runnerSource = [IO.File]::ReadAllText($runnerTemplatePath)
    $runnerSource = $runnerSource.Replace("__IMAGE_SLOT__", $imageSlot)
    $runnerSource = $runnerSource.Replace("__ARGUMENT_SLOT__", $argumentSlot)
    $runnerSource = $runnerSource.Replace("__KEY__", [Convert]::ToBase64String($key))
    $runnerSource = $runnerSource.Replace("__IV__", [Convert]::ToBase64String($iv))
    $runnerSource = $runnerSource.Replace("__PAYLOAD_RESOURCE__", $runnerPayloadResourceName)
    $runnerSource = $runnerSource.Replace("__WARMUP_RESOURCE__", $runnerWarmupResourceName)

    $sourcePath = Join-Path $temporaryDirectory "loader.cs"
    $stubPath = Join-Path $temporaryDirectory "loader.exe"
    $warmupSourcePath = Join-Path $temporaryDirectory "warmup.cs"
    $warmupPath = Join-Path $temporaryDirectory "warmup.dll"
    $runnerSourcePath = Join-Path $temporaryDirectory "runner.cs"
    $runnerFileName = "runner" + [Guid]::NewGuid().ToString("N") + ".exe"
    $runnerPath = Join-Path $temporaryDirectory $runnerFileName
    $runnerProtectedDirectory = Join-Path $temporaryDirectory "runner-protected"
    $runnerProjectPath = Join-Path $temporaryDirectory "runner.crproj"
    $utf8WithoutBom = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($sourcePath, $source, $utf8WithoutBom)
    [IO.File]::WriteAllText($runnerSourcePath, $runnerSource, $utf8WithoutBom)
    # warmup.dll은 실제 payload보다 먼저 CLR의 managed-load 경로를 초기화하는 작은 어셈블리다.
    $warmupSource = "using System.Reflection; [assembly: AssemblyVersion(`"1.0.0.0`")] internal sealed class Component" + [Guid]::NewGuid().ToString("N") + " { }"
    [IO.File]::WriteAllText($warmupSourcePath, $warmupSource, $utf8WithoutBom)
    & $compilerPath /nologo /target:library /optimize+ "/out:$warmupPath" $warmupSourcePath
    if ($LASTEXITCODE -ne 0) { throw "Warm-up assembly compilation failed." }
    # runner에는 설치 후 독립 실행에 사용할 암호화 payload를 별도로 내장한다.
    & $compilerPath /nologo /target:exe "/platform:$Platform" /optimize+ /debug- `
        "/out:$runnerPath" "/resource:$encryptedPath,$runnerPayloadResourceName,private" `
        "/resource:$warmupPath,$runnerWarmupResourceName,private" $runnerSourcePath
    if ($LASTEXITCODE -ne 0) { throw "Sandbox runner compilation failed." }

    # runner는 디스크에 잠시 나타나므로 rename을 포함한 보호를 모두 적용한다.
    $runnerProject = @"
<?xml version="1.0" encoding="utf-8"?>
<project outputDir="runner-protected" baseDir="." xmlns="http://confuser.codeplex.com">
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
  <module path="$runnerFileName" />
</project>
"@
    [IO.File]::WriteAllText($runnerProjectPath, $runnerProject, $utf8WithoutBom)
    $confuserPath = Join-Path $PSScriptRoot "tools\ConfuserEx\bin\Confuser.CLI.exe"
    & $confuserPath -n $runnerProjectPath
    if ($LASTEXITCODE -ne 0) { throw "Sandbox runner protection failed." }
    $runnerEmbedPath = Join-Path $runnerProtectedDirectory $runnerFileName
    if (-not (Test-Path -LiteralPath $runnerEmbedPath -PathType Leaf)) {
        throw "Protected sandbox runner was not created."
    }

    # 외부 loader에는 보호된 runner와 warmup 어셈블리를 managed resource로 포함한다.
    $compilerArguments = @(
        "/nologo",
        "/target:winexe",
        "/platform:$Platform",
        "/optimize+",
        "/debug-",
        "/out:$stubPath",
        "/resource:$warmupPath,$warmupResourceName,private",
        "/resource:$runnerEmbedPath,$runnerResourceName,private",
        $sourcePath
    )
    if (-not $packageOutputPath) {
        # 단독 호출 모드에서는 암호화 payload도 managed resource로 포함한다.
        $compilerArguments = $compilerArguments[0..5] + "/resource:$encryptedPath,$resourceName,private" + $compilerArguments[6..($compilerArguments.Length - 1)]
    }
    & $compilerPath @compilerArguments
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $stubPath -PathType Leaf)) {
        throw "C# compilation failed with exit code $LASTEXITCODE."
    }

    [IO.File]::Copy($stubPath, $outputPath, $true)

    $hash = Get-Sha256Hex $outputPath
    $size = (Get-Item -LiteralPath $outputPath).Length
    Write-Host "Built: $outputPath"
    Write-Host "Payload: $payloadPath"
    Write-Host "Size: $size bytes"
    Write-Host "SHA-256: $hash"
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
