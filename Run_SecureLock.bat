@echo off
title SecureLock Launcher
cd /d "%~dp0"

echo ========================================================
echo   SecureLock - Windows Folder Locker
echo ========================================================
echo Starting SecureLock...

python main.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo An error occurred while launching SecureLock.
    echo Make sure Python is installed and cryptography library is available:
    echo pip install cryptography
    pause
)
