@echo off
rem Double-click this file to build and run PhishGuard.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_and_run.ps1"
echo.
echo (Finished. Scroll up to read any messages.)
pause
