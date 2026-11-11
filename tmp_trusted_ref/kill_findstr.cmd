@echo off
taskkill /F /IM findstr.exe >nul 2>&1
taskkill /F /IM llama-cli.exe >nul 2>&1
echo KILLED
