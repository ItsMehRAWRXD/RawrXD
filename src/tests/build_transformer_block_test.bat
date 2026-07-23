@echo off
setlocal EnableDelayedExpansion

echo ============================================================================
echo Transformer Block Numerical Test Build
echo ============================================================================

set VS18=C:\Program Files\Microsoft Visual Studio\18\Enterprise
set WINSDK=C:\Program Files (x86)\Windows Kits\10
set WINSDK_VER=10.0.26100.0

call "%VS18%\VC\Auxiliary\Build\vcvars64.bat"

set INCLUDE=%WINSDK%\Include\%WINSDK_VER%\um;%WINSDK%\Include\%WINSDK_VER%\shared;%WINSDK%\Include\%WINSDK_VER%\ucrt;%INCLUDE%
set LIB=%WINSDK%\Lib\%WINSDK_VER%\um\x64;%WINSDK%\Lib\%WINSDK_VER%\ucrt\x64;%LIB%

echo.
echo Compiling and linking...
cl /W4 /O2 /nologo /Zi /EHsc /std:c++20 /I ../deep2 /Fe:TransformerBlock_NumericalTest.exe TransformerBlock_NumericalTest.cpp /link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /LARGEADDRESSAWARE:NO kernel32.lib libucrt.lib legacy_stdio_definitions.lib
if errorlevel 1 (
    echo ERROR: Build failed
    exit /b 1
)
echo OK: TransformerBlock_NumericalTest.exe

echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo Run with: TransformerBlock_NumericalTest.exe