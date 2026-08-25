# client.bat

@echo off
setlocal

set /p "filename=enter filename "

if "%filename%"=="" (
    echo.
    echo [-] no filename
    pause
    exit /b 1
)

set "timestamp=%date:~0,4%-%date:~5,2%-%date:~8,2%_%time:~0,2%-%time:~3,2%-%time:~6,2%"
set "timestamp=%timestamp: =0%"

cd /d C:\Users\bigsilver\Desktop\share

echo.
echo [*] Downloading %filename%...

curl.exe "http://192.168.127.129:8000/%filename%" -o "%~dp0%filename%"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] Download complete.
    echo [+] Saved as %filename%
) else (
    echo.
    echo [-] Download failed.
)

pause