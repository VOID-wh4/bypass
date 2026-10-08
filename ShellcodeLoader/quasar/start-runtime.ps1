param(
    [string] $StagePath,
    [ValidateRange(1024, 65535)] [int] $StagePort = 4817,
    [switch] $Serve
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

if ([string]::IsNullOrWhiteSpace($StagePath)) {
    $stage = Join-Path $root 'output\quasar\stage.dat'
}
else {
    $stage = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($StagePath)
}

if ($Serve) {
    $payload = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $stage))
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, $StagePort)
    $listener.Start()
    Write-Output ("LISTEN port={0} stageBytes={1}" -f $StagePort, $payload.Length)
    try {
        while ($true) {
            $client = $listener.AcceptTcpClient()
            $remote = $client.Client.RemoteEndPoint
            try {
                $client.NoDelay = $true
                $stream = $client.GetStream()
                $length = [BitConverter]::GetBytes([uint32]$payload.Length)
                $stream.Write($length, 0, $length.Length)
                $stream.Write($payload, 0, $payload.Length)
                $stream.Flush()
                Write-Output ("{0:o} SENT remote={1} bytes={2}" -f
                    [DateTime]::UtcNow, $remote, $payload.Length)
                while ($stream.ReadByte() -ge 0) { }
            }
            catch {
                Write-Output ("{0:o} ERROR remote={1} message={2}" -f
                    [DateTime]::UtcNow, $remote, $_.Exception.Message)
            }
            finally {
                $client.Dispose()
            }
        }
    }
    finally {
        $listener.Stop()
        [Array]::Clear($payload, 0, $payload.Length)
    }
    return
}

foreach ($path in @($stage, $MyInvocation.MyCommand.Path)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required runtime file is missing: $path"
    }
}
if (Get-NetTCPConnection -State Listen -LocalPort $StagePort -ErrorAction SilentlyContinue) {
    throw "Port $StagePort is already listening. Stop the old stage server first."
}

$connectionInfo = Join-Path $root 'output\quasar\connection.txt'
$logDirectory = Join-Path $root 'output\runtime'
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
$powerShell = (Get-Process -Id $PID).Path
$stageOut = Join-Path $logDirectory 'quasar-stage.stdout.log'
$stageErr = Join-Path $logDirectory 'quasar-stage.stderr.log'

$stageProcess = Start-Process -FilePath $powerShell `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        $MyInvocation.MyCommand.Path, '-Serve', '-StagePort', [string]$StagePort,
        '-StagePath', $stage) `
    -WorkingDirectory $root -WindowStyle Hidden `
    -RedirectStandardOutput $stageOut -RedirectStandardError $stageErr -PassThru

Write-Output "Stage server PID: $($stageProcess.Id), port: $StagePort"
if (Test-Path -LiteralPath $connectionInfo) {
    Write-Output 'The submitted client will use these settings:'
    Get-Content -LiteralPath $connectionInfo
}
Write-Output 'The Quasar Server is assumed to be running at the embedded HOSTS endpoint.'
Write-Output "Logs: $logDirectory"
