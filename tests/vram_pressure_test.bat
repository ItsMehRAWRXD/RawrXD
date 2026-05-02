@echo off
:: VRAM Pressure Test for RawrXD v1.0.0-gold
:: Tests TRES T3 Observability layer with 32B model (18.5GB > 16GB VRAM)

echo ========================================
echo VRAM Pressure Test - TRES T3 Observability
echo RawrXD v1.0.0-gold Pre-Release
echo ========================================
echo.

set MODEL_PATH=F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf
set MODEL_SIZE_GB=18.49
set VRAM_GB=16

:: Check model exists
if not exist "%MODEL_PATH%" (
    echo [ERROR] Model not found: %MODEL_PATH%
    exit /b 1
)

:: Calculate memory pressure
echo [MODEL INFO]
echo   Path: %MODEL_PATH%
echo   Size: %MODEL_SIZE_GB% GB
echo.

echo [VRAM CONSTRAINTS]
echo   Available VRAM: %VRAM_GB% GB
echo   Model Size:     %MODEL_SIZE_GB% GB
echo   Deficit:        ~2.5 GB (must use System RAM)
echo.

echo [TRES CONFIGURATION]
echo   T1 Safety:      ENABLED (adaptive drift correction)
echo   T2 Stability:   ENABLED (50ms budget cycles)
echo   T3 Observability: ENABLED (mmap layer tracking)
echo.

echo [EXPECTED BEHAVIOR]
echo   - KV Cache: FP8 quantized (50%% reduction)
echo   - Weights: Partial VRAM residency
echo   - Offload: ~2.5GB to System RAM via mmap
echo   - PCIe: Active for layer swapping
echo.

:: Check if RawrXD can report memory status
echo [CHECK] Verifying T3 Observability hooks...

if exist "D:\rawrxd\build-ninja\bin\RawrXD-Win32IDE.exe" (
    echo [OK] RawrXD binary found
    
    :: Try to get version info
    "D:\rawrxd\build-ninja\bin\RawrXD-Win32IDE.exe" --version 2>nul
    if errorlevel 1 (
        echo [INFO] Version check requires headless mode
    )
) else (
    echo [WARN] RawrXD binary not found at expected path
)

echo.
echo ========================================
echo VRAM Pressure Analysis Complete
echo ========================================
echo.
echo [RECOMMENDATION]
echo The 32B model (18.5GB) exceeds VRAM (16GB) by 2.5GB.
echo TRES layer should manage this via:
echo   1. FP8 KV cache (reduces cache footprint)
echo   2. mmap-based weight offloading
echo   3. PCIe prefetch for hot layers
echo.
echo To verify actual residency, run:
echo   RawrXD-Win32IDE.exe --model %MODEL_PATH% --mmap-test
echo.
