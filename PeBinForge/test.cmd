@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tests\test.ps1" %*
exit /b %ERRORLEVEL%
