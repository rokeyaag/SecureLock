@echo off
title Create Desktop Shortcut
cd /d "%~dp0"

echo Creating SecureLock shortcut on your Desktop...
python make_shortcut.py
echo.
pause
