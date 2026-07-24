@echo off
chcp 65001 >nul
echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║           RawrXD Endpoint Validator v1.0                       ║
echo ║           Batch Validation System (Size: 20)                   ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.
echo Target: http://localhost:9090
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Python not found, using PowerShell fallback...
    powershell -ExecutionPolicy Bypass -Command "& { $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri 'http://localhost:9090/api/status' -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null; if ($?) { Write-Host 'Server is responding' -ForegroundColor Green } else { Write-Host 'Server not responding' -ForegroundColor Red } }"
) else (
    echo Running Python validator...
    python d:\RawrXD\endpoint_validator.py
)

echo.
echo Press any key to exit...
pause >nul
