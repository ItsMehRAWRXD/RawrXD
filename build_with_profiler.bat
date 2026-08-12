@echo off
REM Build script for RawrXD with Negative Space Profiler integration
REM This assembles the MASM profiler and compiles the instrumented source files

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd

REM Add Windows SDK lib path
set "LIB=%LIB%;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

echo ==========================================
echo RawrXD + Negative Space Profiler Build
echo ==========================================

REM Assemble the profiler
echo [1/3] Assembling NegativeSpaceProfiler_v2.asm...
ml64 /c /Zi /Fosrc\inference\NegativeSpaceProfiler.obj src\inference\NegativeSpaceProfiler_v2.asm
if errorlevel 1 (
    echo ERROR: Assembly failed!
    exit /b 1
)
echo     OK: NegativeSpaceProfiler.obj created.

REM Compile instrumented source files
echo.
echo [2/3] Compiling instrumented source files...
cl /c /O2 /EHsc /Zi /W4 /I. /Isrc /Isrc\core /Isrc\inference /Fosrc\rawrxd_transformer_forwardbatch.obj src\rawrxd_transformer_forwardbatch.cpp
if errorlevel 1 (
    echo ERROR: ForwardBatch compilation failed!
    exit /b 1
)

cl /c /O2 /EHsc /Zi /W4 /I. /Isrc /Isrc\core /Isrc\inference /Fosrc\rawrxd_transformer.obj src\rawrxd_transformer.cpp
if errorlevel 1 (
    echo ERROR: Transformer compilation failed!
    exit /b 1
)

echo     OK: Source files compiled.

REM Note: Full RawrXD link would require all object files. This demonstrates the instrumentation.
echo.
echo [3/3] Build complete. Objects ready for linking:
echo     src\inference\NegativeSpaceProfiler.obj
echo     src\rawrxd_transformer_forwardbatch.obj
echo     src\rawrxd_transformer.obj
echo.
echo To complete the build, add NegativeSpaceProfiler.obj to your link step.
