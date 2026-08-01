@echo off
set "MINGW=C:\ProgramData\mingw64\mingw64\bin"
set "PATH=%MINGW%;%PATH%"
set "OUT=D:\rawrxd-ci-bootstrap\out"
set "REL=D:\rawrxd-ci-bootstrap\release"

echo === LINKING RawrXDEngine.exe with Real GGUF Inference ===

g++ -o "%REL%\RawrXDEngine.exe" ^
    "%OUT%\EngineMain.o" ^
    "%OUT%\Engine.o" ^
    "%OUT%\GpuDevice.o" ^
    "%OUT%\RealGGUFInference.o" ^
    "%OUT%\cpu_inference_engine_clean.o" ^
    "%OUT%\transformer.o" ^
    "%OUT%\streaming_gguf_loader.o" ^
    "%OUT%\inference_kernels.o" ^
    "%OUT%\diagnostics_stub.o" ^
    "%OUT%\AIRuntime.o" ^
    "%OUT%\BackendFactory.o" ^
    "%OUT%\BackendManager.o" ^
    "%OUT%\PowerShellDriver.o" ^
    "%OUT%\BareMetalDriver.o" ^
    "%OUT%\ProcessorMetrics.o" ^
    "%OUT%\GpuMetrics.o" ^
    "%OUT%\BackendTelemetry.o" ^
    "%OUT%\GdiDashboardPainter.o" ^
    "%OUT%\BackendRegistry.obj" ^
    -lwinmm -ldxgi -ld3d11 -lgdi32 -static -mconsole

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo SUCCESS: RawrXDEngine.exe with Real GGUF
    echo ========================================
) else (
    echo LINK FAILED
    exit /b 1
)
