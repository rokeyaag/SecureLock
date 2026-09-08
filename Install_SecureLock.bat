@echo off
title SecureLock Setup & Installer
cd /d "%~dp0"

echo ========================================================
echo   SecureLock - Windows Installation Setup
echo ========================================================
echo.
python install.py
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Installation failed.
)
echo.
pause
