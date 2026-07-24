@echo off
setlocal EnableDelayedExpansion

echo ============================================================================
echo Universal Runtime Smoke Test Build
echo ============================================================================

set VS18=C:\Program Files\Microsoft Visual Studio\18\Enterprise
set WINSDK=C:\Program Files (x86)\Windows Kits\10
set WINSDK_VER=10.0.26100.0

call "%VS18%\VC\Auxiliary\Build\vcvars64.bat"

set INCLUDE=%WINSDK%\Include\%WINSDK_VER%\um;%WINSDK%\Include\%WINSDK_VER%\shared;%WINSDK%\Include\%WINSDK_VER%\ucrt;%INCLUDE%
set LIB=%WINSDK%\Lib\%WINSDK_VER%\um\x64;%WINSDK%\Lib\%WINSDK_VER%\ucrt\x64;%LIB%

echo.
echo Compiling all sources...
cl /W4 /O2 /nologo /Zi /EHsc /std:c++20 /I ../deep2 /Fe:UniversalRuntime_SmokeTest.exe UniversalRuntime_SmokeTest.cpp ..\deep2\UniversalModelLoader.cpp ..\deep2\RuntimePlanner.cpp ..\deep2\TensorHop.cpp /link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /LARGEADDRESSAWARE:NO kernel32.lib libucrt.lib legacy_stdio_definitions.lib
if errorlevel 1 (
    echo ERROR: Build failed
    exit /b 1
)
echo OK: UniversalRuntime_SmokeTest.exe

echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo Run with: UniversalRuntime_SmokeTest.exe