[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $projectRoot 'build'
$runner = Join-Path $buildDir 'pbf-runner.exe'
$simpleMemoryLoader = Join-Path $buildDir 'simple-memory-loader.exe'
$threadMemoryLoader = Join-Path $buildDir 'thread-memory-loader.exe'
$injectionTarget = Join-Path $buildDir 'injection-target.exe'
$probe = Join-Path $buildDir 'peprobe.exe'
$nativeMapper = Join-Path $buildDir 'native-maptest.exe'
$nativeDll = Join-Path $buildDir 'native-demo.dll'
$nativeDependencyDll = Join-Path $buildDir 'pbfdep.dll'
$nativeLeafDll = Join-Path $buildDir 'pbfleaf.dll'
$nativeBinGenerator = Join-Path $buildDir 'native-bin-gen.exe'
$nativeBinRunner = Join-Path $buildDir 'native-bin-runner.exe'
$nativeBin = Join-Path $buildDir 'native-demo.bin'
$nativeExe = Join-Path $buildDir 'native-exe-demo.exe'
$nativeExeBin = Join-Path $buildDir 'native-exe-demo.bin'
$x86Dir = Join-Path $buildDir 'x86'
$x86SimpleMemoryLoader = Join-Path $x86Dir 'simple-memory-loader-x86.exe'
$x86ThreadMemoryLoader = Join-Path $x86Dir 'thread-memory-loader-x86.exe'
$x86NativeBin = Join-Path $x86Dir 'native-demo-x86.bin'
$x86NativeExeBin = Join-Path $x86Dir 'native-exe-demo-x86.bin'
$x86FixedExe = Join-Path $x86Dir 'fixed-exe-demo-x86.exe'
$x86FixedExeBin = Join-Path $x86Dir 'fixed-exe-demo-x86.bin'
$exampleDir = Join-Path $buildDir 'example'
$testExe = Join-Path $exampleDir 'TEST.EXE'
$testDll = Join-Path $exampleDir 'test1.dll'
$testBin = Join-Path $exampleDir 'TEST.bin'
$clrMapTest = Join-Path $buildDir 'clr-maptest.exe'
$managedPicObject = Join-Path $buildDir 'obj\managed_pic_stub.obj'
$managedBinPacker = Join-Path $buildDir 'managed-bin-pack.exe'
$managedBinRunner = Join-Path $buildDir 'managed-bin-runner.exe'
$managedBin = Join-Path $buildDir 'managed-demo.bin'
$x86ManagedPicObject = Join-Path $x86Dir 'obj\managed_pic_stub.obj'
$x86ManagedBinRunner = Join-Path $x86Dir 'managed-bin-runner-x86.exe'
$x86ClrMapTest = Join-Path $x86Dir 'clr-maptest-x86.exe'
$x86ManagedBin = Join-Path $buildDir 'managed-x86-test.bin'
$pbf = Join-Path $buildDir 'pbf.exe'
$payload = Join-Path $buildDir 'demo.bin'
$standalonePayload = Join-Path $buildDir 'standalone-demo.bin'
$sidecar = "$payload.sha256"
$generator = Join-Path $buildDir 'pbfgen.exe'

& (Join-Path $projectRoot 'build.ps1')
if (-not (Test-Path -LiteralPath $runner) -or
    -not (Test-Path -LiteralPath $simpleMemoryLoader) -or
    -not (Test-Path -LiteralPath $threadMemoryLoader) -or
    -not (Test-Path -LiteralPath $injectionTarget) -or
    -not (Test-Path -LiteralPath $generator) -or
    -not (Test-Path -LiteralPath $probe) -or
    -not (Test-Path -LiteralPath $nativeMapper) -or
    -not (Test-Path -LiteralPath $nativeDll) -or
    -not (Test-Path -LiteralPath $nativeDependencyDll) -or
    -not (Test-Path -LiteralPath $nativeLeafDll) -or
    -not (Test-Path -LiteralPath $nativeBinGenerator) -or
    -not (Test-Path -LiteralPath $nativeBinRunner) -or
    -not (Test-Path -LiteralPath $nativeBin) -or
    -not (Test-Path -LiteralPath $nativeExe) -or
    -not (Test-Path -LiteralPath $nativeExeBin) -or
    -not (Test-Path -LiteralPath $x86SimpleMemoryLoader) -or
    -not (Test-Path -LiteralPath $x86ThreadMemoryLoader) -or
    -not (Test-Path -LiteralPath $x86NativeBin) -or
    -not (Test-Path -LiteralPath $x86NativeExeBin) -or
    -not (Test-Path -LiteralPath $x86FixedExe) -or
    -not (Test-Path -LiteralPath $x86FixedExeBin) -or
    -not (Test-Path -LiteralPath $testExe) -or
    -not (Test-Path -LiteralPath $testDll) -or
    -not (Test-Path -LiteralPath $testBin) -or
    -not (Test-Path -LiteralPath $clrMapTest) -or
    -not (Test-Path -LiteralPath $managedPicObject) -or
    -not (Test-Path -LiteralPath $managedBinPacker) -or
    -not (Test-Path -LiteralPath $managedBinRunner) -or
    -not (Test-Path -LiteralPath $x86ManagedPicObject) -or
    -not (Test-Path -LiteralPath $x86ManagedBinRunner) -or
    -not (Test-Path -LiteralPath $x86ClrMapTest) -or
    -not (Test-Path -LiteralPath $pbf) -or
    -not (Test-Path -LiteralPath $payload) -or
    -not (Test-Path -LiteralPath $standalonePayload) -or
    -not (Test-Path -LiteralPath $sidecar)) {
    throw 'Expected build artifacts are missing.'
}

& $runner $payload 40 2
if ($LASTEXITCODE -ne 0) { throw 'Valid payload execution failed.' }

$standaloneOutput = & $runner $standalonePayload --entry noargs | Out-String
$standaloneExit = $LASTEXITCODE
Write-Host $standaloneOutput.TrimEnd()
if ($standaloneExit -ne 0 -or $standaloneOutput -notmatch 'Standalone entry\(\) completed') {
    throw 'Parameterless standalone entry execution failed.'
}

$targetProcess = Start-Process -FilePath $injectionTarget -PassThru -WindowStyle Hidden
try {
    $remoteContextOutput = & $runner $payload 40 2 --inject-pid $targetProcess.Id | Out-String
    $remoteContextExit = $LASTEXITCODE
    Write-Host $remoteContextOutput.TrimEnd()
    if ($remoteContextExit -ne 0 -or
        $remoteContextOutput -notmatch "PID $($targetProcess.Id) memory transitioned RW -> RX" -or
        $remoteContextOutput -notmatch 'Remote payload result:') {
        throw 'Remote entry(&context) injection failed.'
    }

    $remoteStandaloneOutput = & $runner $standalonePayload --entry noargs `
        --inject-pid $targetProcess.Id | Out-String
    $remoteStandaloneExit = $LASTEXITCODE
    Write-Host $remoteStandaloneOutput.TrimEnd()
    if ($remoteStandaloneExit -ne 0 -or
        $remoteStandaloneOutput -notmatch "Standalone entry\(\) completed in remote PID $($targetProcess.Id)") {
        throw 'Remote standalone entry() injection failed.'
    }

    & $pbf run $standalonePayload --entry noargs --inject-pid $targetProcess.Id
    if ($LASTEXITCODE -ne 0) { throw 'Unified CLI remote standalone injection failed.' }
} finally {
    if (-not $targetProcess.HasExited) { Stop-Process -Id $targetProcess.Id -Force }
    $targetProcess.Dispose()
}

& $runner $standalonePayload 1 --entry noargs
if ($LASTEXITCODE -ne 2) {
    throw 'Standalone noargs mode accepted an invalid numeric input.'
}

$tampered = Join-Path $buildDir 'demo-tampered.bin'
$tamperedSidecar = "$tampered.sha256"
Copy-Item -LiteralPath $payload -Destination $tampered -Force
Copy-Item -LiteralPath $sidecar -Destination $tamperedSidecar -Force
$bytes = [System.IO.File]::ReadAllBytes($tampered)
$bytes[[Math]::Floor($bytes.Length / 2)] = $bytes[[Math]::Floor($bytes.Length / 2)] -bxor 1
[System.IO.File]::WriteAllBytes($tampered, $bytes)

& $runner $tampered 40 2
if ($LASTEXITCODE -ne 4) {
    throw "Tampered payload returned $LASTEXITCODE instead of integrity error 4."
}

& $generator (Join-Path $buildDir 'obj\demo.obj') $payload
if ($LASTEXITCODE -ne 3) {
    throw "Existing-output protection returned $LASTEXITCODE instead of 3."
}

$relocOutput = Join-Path $buildDir 'reloc-bad.bin'
if (Test-Path -LiteralPath $relocOutput) { Remove-Item -LiteralPath $relocOutput -Force }
& $generator (Join-Path $buildDir 'obj\reloc_bad.obj') $relocOutput
if ($LASTEXITCODE -eq 0 -or (Test-Path -LiteralPath $relocOutput)) {
    throw 'Relocation-bearing C code was not rejected.'
}

$nativeProbe = & $probe $runner | Out-String
if ($LASTEXITCODE -ne 0 -or $nativeProbe -notmatch 'Kind: native') {
    throw 'Native PE classification failed.'
}

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$managedExe = Join-Path $buildDir 'ManagedSample.exe'
$managedEntryExe = Join-Path $buildDir 'ManagedEntry.exe'
$managedX86Exe = Join-Path $buildDir 'ManagedEntry-x86-test.exe'
$managedX64Exe = Join-Path $buildDir 'ManagedEntry-x64-test.exe'
if (-not (Test-Path -LiteralPath $csc)) { throw '.NET Framework C# compiler was not found.' }
& $csc /nologo /target:exe "/out:$managedExe" (Join-Path $projectRoot 'tests\ManagedSample.cs')
if ($LASTEXITCODE -ne 0) { throw 'Managed classification sample compilation failed.' }
& $csc /nologo /target:exe "/out:$managedEntryExe" (Join-Path $projectRoot 'tests\ManagedEntry.cs')
if ($LASTEXITCODE -ne 0) { throw 'Managed entry sample compilation failed.' }
& $csc /nologo /target:exe /platform:x86 "/out:$managedX86Exe" (Join-Path $projectRoot 'tests\ManagedEntry.cs')
if ($LASTEXITCODE -ne 0) { throw 'x86 managed entry sample compilation failed.' }
& $csc /nologo /target:exe /platform:x64 "/out:$managedX64Exe" (Join-Path $projectRoot 'tests\ManagedEntry.cs')
if ($LASTEXITCODE -ne 0) { throw 'x64 managed entry sample compilation failed.' }
$managedProbe = & $probe $managedExe | Out-String
if ($LASTEXITCODE -ne 0 -or $managedProbe -notmatch 'Kind: managed') {
    throw 'Managed PE classification failed.'
}

$nativeMapOutput = & $nativeMapper $nativeDll 40 2 | Out-String
$nativeMapExit = $LASTEXITCODE
Write-Host $nativeMapOutput.TrimEnd()
if ($nativeMapExit -ne 0 -or $nativeMapOutput -notmatch 'Relocated=yes') {
    throw 'Native DLL in-memory relocation/mapping failed.'
}

& $nativeMapper $managedExe
if ($LASTEXITCODE -ne 4) {
    throw "Managed PE rejection returned $LASTEXITCODE instead of 4."
}

& $clrMapTest $managedEntryExe
if ($LASTEXITCODE -ne 0) { throw 'CLR in-memory assembly execution failed.' }
& $x86ClrMapTest $managedX86Exe
if ($LASTEXITCODE -ne 0) { throw 'x86 CLR in-memory assembly execution failed.' }
& $clrMapTest $nativeDll
if ($LASTEXITCODE -ne 4) {
    throw "CLR host native-input rejection returned $LASTEXITCODE instead of 4."
}

& $managedBinPacker $managedPicObject $managedEntryExe $managedBin
if ($LASTEXITCODE -ne 0) { throw 'Managed raw BIN packaging failed.' }
& $managedBinRunner $managedBin
if ($LASTEXITCODE -ne 0) { throw 'Managed first-byte raw BIN execution failed.' }
$managedSimpleOutput = & $simpleMemoryLoader $managedBin | Out-String
if ($LASTEXITCODE -ne 0 -or $managedSimpleOutput -notmatch 'Self-contained entry\(\) returned') {
    throw 'x64 managed v2 BIN failed in the direct minimal loader.'
}
$managedThreadOutput = & $threadMemoryLoader $managedBin | Out-String
if ($LASTEXITCODE -ne 0 -or $managedThreadOutput -notmatch 'CreateThread adapter completed') {
    throw 'x64 managed v2 BIN failed through the CreateThread ABI adapter.'
}
& $managedBinPacker $managedPicObject $x86ManagedPicObject $managedX86Exe $x86ManagedBin
if ($LASTEXITCODE -ne 0) { throw 'x86 managed raw BIN packaging failed.' }
& $x86ManagedBinRunner $x86ManagedBin
if ($LASTEXITCODE -ne 0) { throw 'x86 managed first-byte raw BIN execution failed.' }
$x86ManagedSimpleOutput = & $x86SimpleMemoryLoader $x86ManagedBin | Out-String
if ($LASTEXITCODE -ne 0 -or $x86ManagedSimpleOutput -notmatch 'Self-contained entry\(\) completed') {
    throw 'x86 managed v2 BIN failed in the direct minimal loader.'
}
$x86ManagedThreadOutput = & $x86ThreadMemoryLoader $x86ManagedBin | Out-String
if ($LASTEXITCODE -ne 0 -or $x86ManagedThreadOutput -notmatch 'CreateThread adapter completed') {
    throw 'x86 managed v2 BIN failed through the CreateThread ABI adapter.'
}
$x86ManagedInspect = & $pbf inspect $x86ManagedBin | Out-String
if ($LASTEXITCODE -ne 0 -or $x86ManagedInspect -notmatch '\.NET Framework 4 x86 raw bundle') {
    throw 'Unified CLI did not identify the x86 managed bundle.'
}

$managedInvalidBin = Join-Path $buildDir 'managed-invalid.bin'
if (Test-Path -LiteralPath $managedInvalidBin) { Remove-Item -LiteralPath $managedInvalidBin -Force }
& $managedBinPacker $managedPicObject $nativeDll $managedInvalidBin
if ($LASTEXITCODE -eq 0 -or (Test-Path -LiteralPath $managedInvalidBin)) {
    throw 'Managed BIN packer accepted a native DLL.'
}

$managedTampered = Join-Path $buildDir 'managed-demo-tampered.bin'
$managedTamperedHash = "$managedTampered.sha256"
Copy-Item -LiteralPath $managedBin -Destination $managedTampered -Force
Copy-Item -LiteralPath "$managedBin.sha256" -Destination $managedTamperedHash -Force
$managedBytes = [System.IO.File]::ReadAllBytes($managedTampered)
$managedBytes[[Math]::Floor($managedBytes.Length / 2)] = $managedBytes[[Math]::Floor($managedBytes.Length / 2)] -bxor 1
[System.IO.File]::WriteAllBytes($managedTampered, $managedBytes)
& $managedBinRunner $managedTampered
if ($LASTEXITCODE -ne 4) {
    throw "Tampered managed BIN returned $LASTEXITCODE instead of integrity error 4."
}

$heldNativeDependency = Join-Path $buildDir 'pbfdep.dll.embedded-test'
$heldNativeLeaf = Join-Path $buildDir 'pbfleaf.dll.embedded-test'
if ((Test-Path -LiteralPath $heldNativeDependency) -or
    (Test-Path -LiteralPath $heldNativeLeaf)) {
    throw 'Native dependency test holding path already exists.'
}
Move-Item -LiteralPath $nativeDependencyDll -Destination $heldNativeDependency
Move-Item -LiteralPath $nativeLeafDll -Destination $heldNativeLeaf
try {
    $nativeBinOutput = & $nativeBinRunner $nativeBin 40 2 | Out-String
    $nativeBinExit = $LASTEXITCODE
    $simpleNativeOutput = & $simpleMemoryLoader $nativeBin | Out-String
    $simpleNativeExit = $LASTEXITCODE
} finally {
    Move-Item -LiteralPath $heldNativeLeaf -Destination $nativeLeafDll
    Move-Item -LiteralPath $heldNativeDependency -Destination $nativeDependencyDll
}
Write-Host $nativeBinOutput.TrimEnd()
Write-Host $simpleNativeOutput.TrimEnd()
if ($nativeBinExit -ne 0 -or $nativeBinOutput -notmatch 'Relocated=yes' -or
    $nativeBinOutput -notmatch '3 embedded PE image') {
    throw 'Native context-entry BIN embedded-dependency execution failed.'
}
if ($simpleNativeExit -ne 0 -or
    $simpleNativeOutput -notmatch 'Self-contained entry\(\) returned 0x5042460000000001') {
    throw 'Self-contained native DLL BIN failed in the minimal memory loader.'
}

$nativeTampered = Join-Path $buildDir 'native-demo-tampered.bin'
$nativeTamperedHash = "$nativeTampered.sha256"
Copy-Item -LiteralPath $nativeBin -Destination $nativeTampered -Force
Copy-Item -LiteralPath "$nativeBin.sha256" -Destination $nativeTamperedHash -Force
$nativeBytes = [System.IO.File]::ReadAllBytes($nativeTampered)
$nativeBytes[[Math]::Floor($nativeBytes.Length / 2)] = $nativeBytes[[Math]::Floor($nativeBytes.Length / 2)] -bxor 1
[System.IO.File]::WriteAllBytes($nativeTampered, $nativeBytes)
& $nativeBinRunner $nativeTampered
if ($LASTEXITCODE -ne 4) {
    throw "Tampered native BIN returned $LASTEXITCODE instead of integrity error 4."
}

Move-Item -LiteralPath $nativeDependencyDll -Destination $heldNativeDependency
Move-Item -LiteralPath $nativeLeafDll -Destination $heldNativeLeaf
try {
    & $nativeBinRunner $nativeExeBin
    $nativeExeExit = $LASTEXITCODE
    & $simpleMemoryLoader $nativeExeBin
    $simpleNativeExeExit = $LASTEXITCODE
} finally {
    Move-Item -LiteralPath $heldNativeLeaf -Destination $nativeLeafDll
    Move-Item -LiteralPath $heldNativeDependency -Destination $nativeDependencyDll
}
if ($nativeExeExit -ne 42) {
    throw "Mapped native EXE returned $nativeExeExit instead of application exit code 42."
}
if ($simpleNativeExeExit -ne 42) {
    throw "Self-contained EXE BIN returned $simpleNativeExeExit instead of application exit code 42."
}

$x86DllOutput = & $x86SimpleMemoryLoader $x86NativeBin | Out-String
$x86DllExit = $LASTEXITCODE
Write-Host $x86DllOutput.TrimEnd()
if ($x86DllExit -ne 0 -or
    $x86DllOutput -notmatch 'Self-contained entry\(\) completed') {
    throw 'Self-contained x86 DLL BIN failed in the minimal memory loader.'
}
& $x86SimpleMemoryLoader $x86NativeExeBin
if ($LASTEXITCODE -ne 42) { throw 'Self-contained x86 EXE BIN did not return 42.' }

$x86FixedProbe = & $probe $x86FixedExe | Out-String
if ($LASTEXITCODE -ne 0 -or $x86FixedProbe -notmatch 'Architecture: x86' -or
    $x86FixedProbe -notmatch 'Relocations\s+RVA=0x00000000 Size=0') {
    throw 'Fixed-base, relocation-free x86 EXE fixture is invalid.'
}
& $x86SimpleMemoryLoader $x86FixedExeBin
if ($LASTEXITCODE -ne 42) {
    throw 'Relocation-free x86 EXE BIN failed in the minimal memory loader.'
}
$x86Inspect = & $pbf inspect $x86FixedExeBin | Out-String
if ($LASTEXITCODE -ne 0 -or $x86Inspect -notmatch 'native x86 EXE raw bundle') {
    throw 'Unified CLI did not identify the x86 EXE bundle.'
}
& $pbf run $x86FixedExeBin
if ($LASTEXITCODE -ne 42) { throw 'Unified CLI x86 EXE execution failed.' }
$x86Tampered = Join-Path $buildDir 'x86-fixed-tampered.bin'
Copy-Item -LiteralPath $x86FixedExeBin -Destination $x86Tampered -Force
Copy-Item -LiteralPath "$x86FixedExeBin.sha256" -Destination "$x86Tampered.sha256" -Force
$x86TamperedBytes = [System.IO.File]::ReadAllBytes($x86Tampered)
$x86TamperedBytes[[Math]::Floor($x86TamperedBytes.Length / 2)] =
    $x86TamperedBytes[[Math]::Floor($x86TamperedBytes.Length / 2)] -bxor 1
[System.IO.File]::WriteAllBytes($x86Tampered, $x86TamperedBytes)
& $pbf run $x86Tampered
if ($LASTEXITCODE -ne 4) { throw 'Tampered x86 native BIN was not blocked.' }

$heldTestDll = "$testDll.embedded-test"
if (Test-Path -LiteralPath $heldTestDll) { throw 'TEST example holding path already exists.' }
Move-Item -LiteralPath $testDll -Destination $heldTestDll
try {
    & $pbf run $testBin
    $testBinExit = $LASTEXITCODE
} finally {
    Move-Item -LiteralPath $heldTestDll -Destination $testDll
}
if ($testBinExit -ne 42) {
    throw "TEST.bin without external test1.dll returned $testBinExit instead of 42."
}

$unifiedManaged = Join-Path $buildDir 'unified-managed.bin'
$unifiedNative = Join-Path $buildDir 'unified-native.bin'
$unifiedNativeExe = Join-Path $buildDir 'unified-native-exe.bin'
$unifiedRaw = Join-Path $buildDir 'unified-raw.bin'
$unifiedX86Exe = Join-Path $buildDir 'unified-native-x86-exe.bin'
$unifiedManagedX86 = Join-Path $buildDir 'unified-managed-x86.bin'
$unifiedManagedX64 = Join-Path $buildDir 'unified-managed-x64.bin'
& $pbf pack $managedEntryExe $unifiedManaged --force
if ($LASTEXITCODE -ne 0) { throw 'Unified CLI managed packing failed.' }
& $pbf pack $nativeDll $unifiedNative --force
if ($LASTEXITCODE -ne 0) { throw 'Unified CLI native packing failed.' }
& $pbf pack $nativeExe $unifiedNativeExe --force
if ($LASTEXITCODE -ne 0) { throw 'Unified CLI native EXE packing failed.' }
& $pbf pack (Join-Path $buildDir 'obj\demo.obj') $unifiedRaw --force
if ($LASTEXITCODE -ne 0) { throw 'Unified CLI raw COFF packing failed.' }
& $pbf pack $x86FixedExe $unifiedX86Exe --force
if ($LASTEXITCODE -ne 0) { throw 'Unified CLI x86 native EXE packing failed.' }
& $pbf pack $managedX86Exe $unifiedManagedX86 --force
if ($LASTEXITCODE -ne 0) { throw 'Unified CLI x86 managed packing failed.' }
& $pbf pack $managedX64Exe $unifiedManagedX64 --force
if ($LASTEXITCODE -ne 0) { throw 'Unified CLI x64 managed packing failed.' }

$unifiedInspect = & $pbf inspect $unifiedManaged | Out-String
if ($LASTEXITCODE -ne 0 -or $unifiedInspect -notmatch '\.NET Framework 4 x64 raw bundle') {
    throw 'Unified CLI bundle inspection failed.'
}
$nativeExeInspect = & $pbf inspect $unifiedNativeExe | Out-String
if ($LASTEXITCODE -ne 0 -or $nativeExeInspect -notmatch 'native x64 EXE raw bundle') {
    throw 'Unified CLI native EXE bundle inspection failed.'
}
& $pbf run $unifiedNative 40 2
if ($LASTEXITCODE -ne 0) { throw 'Unified CLI native execution failed.' }
& $pbf run $unifiedNativeExe
if ($LASTEXITCODE -ne 42) { throw 'Unified CLI native EXE execution failed.' }
& $pbf run $unifiedRaw 40 2
if ($LASTEXITCODE -ne 0) { throw 'Unified CLI raw execution failed.' }
& $pbf run $unifiedX86Exe
if ($LASTEXITCODE -ne 42) { throw 'Unified CLI packed x86 EXE execution failed.' }
& $pbf run $unifiedManagedX86
if ($LASTEXITCODE -ne 0) { throw 'Unified CLI x86 managed execution failed.' }
& $pbf run $unifiedManagedX64
if ($LASTEXITCODE -ne 0) { throw 'Unified CLI x64 managed execution failed.' }
$signingPrefix = Join-Path $buildDir 'test-signing-key'
$wrongPrefix = Join-Path $buildDir 'test-wrong-key'
& $pbf keygen $signingPrefix --force
if ($LASTEXITCODE -ne 0) { throw 'ECDSA signing key generation failed.' }
& $pbf keygen $wrongPrefix --force
if ($LASTEXITCODE -ne 0) { throw 'Second ECDSA key generation failed.' }
$privateKey = "$signingPrefix.pbfpriv"
$publicKey = "$signingPrefix.pbfpub"
$wrongPublicKey = "$wrongPrefix.pbfpub"
& $pbf sign $privateKey $unifiedManaged
if ($LASTEXITCODE -ne 0) { throw 'Managed package signing failed.' }
& $pbf verify $publicKey $unifiedManaged
if ($LASTEXITCODE -ne 0) { throw 'Managed package signature verification failed.' }
& $pbf run $unifiedManaged --pubkey $publicKey
if ($LASTEXITCODE -ne 0) { throw 'Signature-required managed execution failed.' }

& $pbf verify $wrongPublicKey $unifiedManaged
if ($LASTEXITCODE -ne 6) {
    throw "Wrong-key verification returned $LASTEXITCODE instead of signature error 6."
}

$signedTampered = Join-Path $buildDir 'unified-managed-signed-tampered.bin'
Copy-Item -LiteralPath $unifiedManaged -Destination $signedTampered -Force
Copy-Item -LiteralPath "$unifiedManaged.sha256" -Destination "$signedTampered.sha256" -Force
Copy-Item -LiteralPath "$unifiedManaged.sig" -Destination "$signedTampered.sig" -Force
$signedBytes = [System.IO.File]::ReadAllBytes($signedTampered)
$signedBytes[[Math]::Floor($signedBytes.Length / 2)] = $signedBytes[[Math]::Floor($signedBytes.Length / 2)] -bxor 1
[System.IO.File]::WriteAllBytes($signedTampered, $signedBytes)
& $pbf run $signedTampered --pubkey $publicKey
if ($LASTEXITCODE -ne 6) {
    throw 'Signature failure did not block managed package execution.'
}

Write-Host 'Validation passed: local/remote raw entries, x86/x64 self-contained native v3 entry(), relocation-free x86 EXEs, x86/x64 self-contained CLR v4 managed v2 bundles, direct/CreateThread loaders, TEST.EXE/test1.dll bundle, recursive dependencies, unified CLI, signatures, and rejection checks.'
