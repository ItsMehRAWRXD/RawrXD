@echo off
setlocal
set "REPO=G:\~dev\rawrxd"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-GpuForwardChain.ps1" -Repo "%REPO%" %*
exit /b %ERRORLEVEL%
