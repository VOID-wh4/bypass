[CmdletBinding()]
param(
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'

if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio Installer (vswhere.exe) was not found.'
}
$installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) {
    throw 'Visual Studio C/C++ build tools were not found.'
}
$devShell = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
$target = if ($Clean) { 'clean' } else { 'all' }
$x64Command = 'call "{0}" -arch=x64 -host_arch=x64 >nul && nmake /nologo /f Makefile.msvc {1}' -f $devShell, $target
$x86Command = 'call "{0}" -arch=x86 -host_arch=x64 >nul && nmake /nologo /f Makefile.x86.msvc {1}' -f $devShell, $target

Push-Location $projectRoot
try {
    & $env:ComSpec /d /s /c $x64Command
    if ($LASTEXITCODE -ne 0) { throw "x64 build failed with exit code $LASTEXITCODE." }
    & $env:ComSpec /d /s /c $x86Command
    if ($LASTEXITCODE -ne 0) { throw "x86 build failed with exit code $LASTEXITCODE." }
} finally {
    Pop-Location
}
