@echo off
setlocal
pushd "%~dp0"

where cl >nul 2>nul
if not errorlevel 1 goto toolchain_ready

set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARS%" set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARS%" goto missing_toolchain

call "%VCVARS%" x64 >nul
if errorlevel 1 goto build_failed

:toolchain_ready
set "INCLUDE=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319;%INCLUDE%"

if not exist mimi.vxor goto missing_payload

rc /nologo /fo stage2_loader.res stage2_loader.rc
if errorlevel 1 goto build_failed
cl /nologo /W4 /WX /O2 /MT /TC stage2_loader.c /Fe:stage2_loader.exe /link stage2_loader.res
if errorlevel 1 goto build_failed

del /q stage2_loader.vxor stage2_loader.baes >nul 2>nul
cl /nologo /W4 /WX /O2 /MT /TC aes_pack.c /Fe:aes_pack.exe /link bcrypt.lib
if errorlevel 1 goto build_failed
aes_pack.exe stage2_loader.exe stage2_loader.baes
if errorlevel 1 goto build_failed

rc /nologo /fo stage1_ghost.res stage1_ghost.rc
if errorlevel 1 goto build_failed
cl /nologo /W4 /WX /EHsc /O2 /MT /TP stage1_ghost.c /Fe:benign_ghost_chain.exe /link stage1_ghost.res bcrypt.lib
if errorlevel 1 goto build_failed

echo [+] Built embedded VXOR stage2_loader.exe and AES-wrapped benign_ghost_chain.exe
popd
exit /b 0

:missing_payload
echo [-] Required CTF resource mimi.vxor was not found.
popd
exit /b 1

:missing_toolchain
echo [-] Visual Studio Build Tools x64 toolchain was not found.
popd
exit /b 1

:build_failed
echo [-] Build failed.
popd
exit /b 1
