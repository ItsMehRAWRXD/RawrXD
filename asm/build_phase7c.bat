@echo off
:: Build Phase 7C - Runtime Dispatch System
::
:: Compiles:
::   - Sovereign_CPUFeatures.cpp
::   - Sovereign_KernelRegistry.cpp
::   - Sovereign_KernelRegistration.cpp
::   - test_phase7c_dispatch.cpp

setlocal enabledelayedexpansion

echo ============================================================================
echo Phase 7C - Runtime Dispatch Build
echo ============================================================================
echo.

:: Configuration
set SRC_DIR=d:\src\asm
set OUT_DIR=%SRC_DIR%\bin
set VS_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise
set MSVC_VER=14.51.36231
set "VS_TOOLS=%VS_ROOT%\VC\Tools\MSVC\%MSVC_VER%\bin\Hostx64\x64"

:: Windows SDK
set WINSDK_VER=10.0.22621.0
set WINSDK_ROOT=C:\Program Files (x86)\Windows Kits\10

:: Setup environment
set "INCLUDE=%VS_ROOT%\VC\Tools\MSVC\%MSVC_VER%\include;%WINSDK_ROOT%\Include\%WINSDK_VER%\ucrt;%WINSDK_ROOT%\Include\%WINSDK_VER%\um;%WINSDK_ROOT%\Include\%WINSDK_VER%\shared"
set "LIB=%VS_ROOT%\VC\Tools\MSVC\%MSVC_VER%\lib\x64;%WINSDK_ROOT%\Lib\%WINSDK_VER%\ucrt\x64;%WINSDK_ROOT%\Lib\%WINSDK_VER%\um\x64"
set "PATH=%VS_TOOLS%;%PATH%"

:: Create output directory
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

:: Compiler and linker
set "CL=%VS_TOOLS%\cl.exe"
set "LINK=%VS_TOOLS%\link.exe"

:: Flags
set CFLAGS=/c /O2 /arch:AVX2 /W3 /nologo /EHsc /MD /I"%SRC_DIR%"
set LFLAGS=/SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE

:: Libraries
set LIBS=kernel32.lib user32.lib

echo [1/5] Compiling Sovereign_CPUFeatures.cpp...
"%CL%" %CFLAGS% /Fo"%OUT_DIR%\Sovereign_CPUFeatures.obj" "%SRC_DIR%\Sovereign_CPUFeatures.cpp"
if errorlevel 1 goto :error
echo     OK

echo.
echo [2/5] Compiling Sovereign_KernelRegistry.cpp...
"%CL%" %CFLAGS% /Fo"%OUT_DIR%\Sovereign_KernelRegistry.obj" "%SRC_DIR%\Sovereign_KernelRegistry.cpp"
if errorlevel 1 goto :error
echo     OK

echo.
echo [3/5] Compiling Sovereign_KernelRegistration.cpp...
"%CL%" %CFLAGS% /Fo"%OUT_DIR%\Sovereign_KernelRegistration.obj" "%SRC_DIR%\Sovereign_KernelRegistration.cpp"
if errorlevel 1 goto :error
echo     OK

echo.
echo [4/5] Compiling test_phase7c_dispatch.cpp...
"%CL%" %CFLAGS% /Fo"%OUT_DIR%\test_phase7c_dispatch.obj" "%SRC_DIR%\test_phase7c_dispatch.cpp"
if errorlevel 1 goto :error
echo     OK

echo.
echo [5/5] Linking test executable...
"%LINK%" %LFLAGS% /OUT:"%OUT_DIR%\test_phase7c_dispatch.exe" ^
    "%OUT_DIR%\test_phase7c_dispatch.obj" ^
    "%OUT_DIR%\Sovereign_CPUFeatures.obj" ^
    "%OUT_DIR%\Sovereign_KernelRegistry.obj" ^
    "%OUT_DIR%\Sovereign_KernelRegistration.obj" ^
    "%SRC_DIR%\Sovereign_RMSNorm.lib" ^
    "%SRC_DIR%\Sovereign_LayerNorm.lib" ^
    "%SRC_DIR%\Sovereign_ResidualAdd.lib" ^
    "%SRC_DIR%\Sovereign_RoPE.lib" ^
    "%SRC_DIR%\Sovereign_Q4K_Dequant.lib" ^
    "%SRC_DIR%\Sovereign_Legacy_Kernels.lib" ^
    "%SRC_DIR%\Sovereign_Intrinsics.lib" ^
    %LIBS%
if errorlevel 1 goto :error
echo     OK

echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo Output files:
dir /b "%OUT_DIR%\Sovereign_CPUFeatures.*" 2^>nul
dir /b "%OUT_DIR%\Sovereign_KernelRegistry.*" 2^>nul
dir /b "%OUT_DIR%\Sovereign_KernelRegistration.*" 2^>nul
dir /b "%OUT_DIR%\test_phase7c_dispatch.*" 2^>nul
echo.
echo Run tests: %OUT_DIR%\test_phase7c_dispatch.exe
echo.
goto :end

:error
echo.
echo ERROR: Build failed!
exit /b 1

:end
endlocal
