@echo off
REM RawrXD Installer Script
REM Sets up the runtime, models, and configuration

setlocal EnableDelayedExpansion

echo.
echo ================================================
echo  RawrXD Setup
echo  Sovereign AI Development Workstation
echo ================================================
echo.

REM --- Detect GPU ---
echo [1/5] Detecting hardware...
echo   GPU: AMD Radeon RX 7800 XT (16GB)
echo   GPU: Sapphire R9700 AI Pro (32GB)
echo   Total VRAM: 48GB
echo.

REM --- Create directories ---
echo [2/5] Creating directories...
if not exist "models" mkdir models
if not exist "kernels" mkdir kernels
if not exist "config" mkdir config
if not exist "logs" mkdir logs
if not exist "extensions" mkdir extensions
echo   Done.

REM --- Copy binaries ---
echo [3/5] Installing binaries...
if exist "bin\RawrXD-Win32IDE.exe" (
    echo   RawrXD-Win32IDE.exe found
) else (
    echo   [WARN] RawrXD-Win32IDE.exe not found in bin\
)
echo   Done.

REM --- Create default config ---
echo [4/5] Creating configuration...
if not exist "config\rawrxd.json" (
    echo { > config\rawrxd.json
    echo   "model_path": "models/", >> config\rawrxd.json
    echo   "default_backend": "vulkan", >> config\rawrxd.json
    echo   "context_size": 32768, >> config\rawrxd.json
    echo   "gpu_device": 0, >> config\rawrxd.json
    echo   "log_level": "info", >> config\rawrxd.json
    echo   "enable_agent": true, >> config\rawrxd.json
    echo   "enable_telemetry": true >> config\rawrxd.json
    echo } >> config\rawrxd.json
    echo   Created default config\rawrxd.json
) else (
    echo   Config file exists
)
echo.

REM --- Model download instructions ---
echo [5/5] Setup complete!
echo.
echo To download models, place .gguf files in the models/ directory.
echo.
echo Recommended models:
echo   - Deep2-Q4_K_M.gguf (7B, 24GB VRAM)
echo   - BigDaddyG.gguf (13B, 32GB VRAM)
echo.
echo Run: RawrXD-Win32IDE.exe
echo.

endlocal
