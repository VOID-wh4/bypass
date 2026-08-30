@echo off
cd /d C:\Users\bigsilver\Desktop\share

echo [*] HTTP server starting on port 8000...
echo.

python -m http.server 8000 --bind 0.0.0.0

pause