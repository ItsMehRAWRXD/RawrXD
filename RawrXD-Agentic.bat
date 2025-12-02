@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "Launch-RawrXD-Agentic.ps1" -Terminal
pause
