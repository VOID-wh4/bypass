@echo off
setlocal

echo [1/3] Compiling miniz.c (native C)...
cl /nologo /EHsc /MD /c /TC miniz.c
if errorlevel 1 goto :error

echo [2/3] Compiling stub_net.cpp (C++/CLI)...
cl /nologo /clr /EHa /MD /c stub_net.cpp
if errorlevel 1 goto :error

echo [3/3] Linking stub_net.exe...
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 /BASE:0x10000000 ^
     /OUT:stub_net.exe stub_net.obj miniz.obj
if errorlevel 1 goto :error

echo.
echo === Build successful: stub_net.exe ===
goto :end

:error
echo.
echo === Build FAILED ===
exit /b 1

:end
en