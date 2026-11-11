@echo off
echo SMOKE_START
taskkill /F /IM rg.exe >nul 2>&1
echo killed_rg
echo hello
ver
echo SMOKE_END
