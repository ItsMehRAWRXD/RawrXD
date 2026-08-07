@echo off
REM Build script for VAL-051.2.A Standalone Token Proof
REM Requires: Visual Studio 2022 (cl.exe)

setlocal EnableDelayedExpansion

echo === Building VAL-051.2.A Standalone Token Proof ===
echo.

REM Find VS2022
set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found. Please install Visual Studio 2022.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VSINSTALLPATH=%%i"
)

if not defined VSINSTALLPATH (
    echo ERROR: Visual Studio 2022 with C++ tools not found.
    exit /b 1
)

echo Found VS2022 at: %VSINSTALLPATH%

REM Setup environment
call "%VSINSTALLPATH%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo ERROR: Failed to setup VS environment
    exit /b 1
)

REM Paths
set "RAWRXD_ROOT=D:\rawrxd"
set "SRC=%RAWRXD_ROOT%\tests\val_051_2_a_standalone_token_proof.cpp"
set "OUT=%RAWRXD_ROOT%\tests\val_051_2_a.exe"

REM Include paths
set "INCLUDES=/I"%RAWRXD_ROOT%\include" /I"%RAWRXD_ROOT%\src" /I"%RAWRXD_ROOT%\include\core" /I"%WindowsSdkDir%Include\%WindowsSDKVersion%um" /I"%WindowsSdkDir%Include\%WindowsSDKVersion%shared" /I"%WindowsSdkDir%Include\%WindowsSDKVersion%ucrt"

REM Compiler flags
set "CFLAGS=/std:c++20 /O2 /EHsc /W3 /nologo /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN"

REM Source files needed (minimal set for RawrXDInference)
REM Note: RawrXDInference is header-only in rawrxd_inference.h
set "SRC1=%RAWRXD_ROOT%\src\gguf_loader.cpp"
set "SRC2=%RAWRXD_ROOT%\src\core\inference_witness.cpp"

echo.
echo Compiling...
echo Source: %SRC%
echo Output: %OUT%
echo.

cl %CFLAGS% %INCLUDES% "%SRC%" "%SRC1%" "%SRC2%" /Fe:"%OUT%"

if errorlevel 1 (
    echo.
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo === Build SUCCESS ===
echo Executable: %OUT%
echo.
echo To run:
echo   %OUT%
echo   %OUT% [path_to_model.gguf]
echo.

endlocal
