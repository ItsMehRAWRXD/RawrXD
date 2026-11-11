@echo off
REM Sovereign Build Driver for RawrXD/Deep2
REM Zero MSVC dependency - uses Clang/LLVM or custom toolchain
REM =========================================================

setlocal EnableDelayedExpansion

echo ==========================================
echo RawrXD Sovereign Build System v0.1
echo ==========================================
echo.

REM Configuration
set "PROJECT_ROOT=d:\rawrxd"
set "BUILD_DIR=%PROJECT_ROOT%\build_sovereign"
set "TOOLS_DIR=%PROJECT_ROOT%\tools"

REM Find toolchain
set "CLANG=clang.exe"
set "CLANGXX=clang++.exe"
set "LLD_LINK=lld-link.exe"
set "LLVM_AR=llvm-ar.exe"

REM Check for LLVM/Clang
where clang.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: clang.exe not found in PATH
    echo Please install LLVM or add to PATH
    exit /b 1
)

for /f "tokens=*" %%a in ('clang.exe --version 2^>^&1 ^| findstr "version"') do (
    echo Found: %%a
)

echo.
echo Toolchain verified.
echo.

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Build phases
set "PHASE=0"

:parse_args
if "%~1"=="" goto :build_start
if "%~1"=="--target" (
    set "TARGET=%~2"
    shift
    shift
    goto :parse_args
)
if "%~1"=="--release" (
    set "BUILD_TYPE=release"
    shift
    goto :parse_args
)
if "%~1"=="--debug" (
    set "BUILD_TYPE=debug"
    shift
    goto :parse_args
)
shift
goto :parse_args

:build_start
if not defined TARGET set "TARGET=deep2_server"
if not defined BUILD_TYPE set "BUILD_TYPE=release"

echo Building: %TARGET%
echo Configuration: %BUILD_TYPE%
echo.

if "%TARGET%"=="deep2_server" goto :build_deep2_server
if "%TARGET%"=="rawrxd_runtime" goto :build_rawrxd_runtime
if "%TARGET%"=="all" goto :build_all

echo Unknown target: %TARGET%
echo Available targets: deep2_server, rawrxd_runtime, all
exit /b 1

:build_deep2_server
echo === Building Deep2 HTTP Server ===
echo.

REM Compile CRT startup (custom, no MSVC CRT)
echo [1/5] Building CRT startup...
clang.exe -c -O2 -fno-builtin -ffreestanding -m64 ^
    -o "%BUILD_DIR%\crt0.obj" ^
    "%TOOLS_DIR%\crt0.asm" ^
    -target x86_64-pc-windows-msvc ^
    -Wl,-entry:_start

if %ERRORLEVEL% NEQ 0 goto :build_fail

REM Compile Deep2 server core
echo [2/5] Compiling Deep2 server...
clang++.exe -c -O3 -march=native -mavx2 -mfma -std=c++20 ^
    -ffreestanding -fno-exceptions -fno-rtti ^
    -D_CRT_SECURE_NO_WARNINGS ^
    -DDEEP2_STANDALONE ^
    -I"%PROJECT_ROOT%\src\deep2" ^
    -o "%BUILD_DIR%\deep2_server.obj" ^
    "%PROJECT_ROOT%\src\deep2\Deep2Server_Minimal.cpp" ^
    -target x86_64-pc-windows-gnu

if %ERRORLEVEL% NEQ 0 goto :build_fail

REM Compile socket wrapper (Winsock2, but no CRT)
echo [3/5] Compiling socket layer...
clang.exe -c -O2 -m64 ^
    -ffreestanding ^
    -o "%BUILD_DIR%\socket_wrapper.obj" ^
    "%TOOLS_DIR%\socket_wrapper.c" ^
    -target x86_64-pc-windows-gnu

if %ERRORLEVEL% NEQ 0 goto :build_fail

REM Link with LLD (no MSVC linker)
echo [4/5] Linking with LLD...
lld-link.exe ^
    /subsystem:console ^
    /entry:_start ^
    /nodefaultlib ^
    /out:"%BUILD_DIR%\Deep2Server_Sovereign.exe" ^
    "%BUILD_DIR%\crt0.obj" ^
    "%BUILD_DIR%\deep2_server.obj" ^
    "%BUILD_DIR%\socket_wrapper.obj" ^
    kernel32.lib ^
    ws2_32.lib ^
    ntdll.lib

if %ERRORLEVEL% NEQ 0 goto :build_fail

echo [5/5] Build complete!
echo.
goto :build_success

:build_rawrxd_runtime
echo === Building RawrXD Runtime ===
echo.

REM Compile runtime components
echo [1/3] Compiling runtime core...
clang++.exe -c -O3 -march=native -mavx2 -mfma -std=c++20 ^
    -ffreestanding -fno-exceptions -fno-rtti ^
    -I"%PROJECT_ROOT%\src\deep2" ^
    -o "%BUILD_DIR%\runtime_core.obj" ^
    "%PROJECT_ROOT%\src\deep2\Deep2Engine.cpp" ^
    -target x86_64-pc-windows-gnu

if %ERRORLEVEL% NEQ 0 goto :build_fail

echo [2/3] Compiling GGUF loader...
clang++.exe -c -O3 -mavx2 ^
    -ffreestanding -fno-exceptions -fno-rtti ^
    -o "%BUILD_DIR%\gguf_loader.obj" ^
    "%PROJECT_ROOT%\src\deep2\GGUFLoader.cpp" ^
    -target x86_64-pc-windows-gnu

if %ERRORLEVEL% NEQ 0 goto :build_fail

echo [3/3] Linking runtime...
lld-link.exe ^
    /subsystem:console ^
    /entry:_start ^
    /nodefaultlib ^
    /out:"%BUILD_DIR%\RawrXD_Runtime_Sovereign.exe" ^
    "%BUILD_DIR%\crt0.obj" ^
    "%BUILD_DIR%\runtime_core.obj" ^
    "%BUILD_DIR%\gguf_loader.obj" ^
    kernel32.lib ^
    ntdll.lib

if %ERRORLEVEL% NEQ 0 goto :build_fail

goto :build_success

:build_all
call :build_deep2_server
if %ERRORLEVEL% NEQ 0 goto :build_fail
call :build_rawrxd_runtime
if %ERRORLEVEL% NEQ 0 goto :build_fail
goto :build_success

:build_fail
echo.
echo ==========================================
echo BUILD FAILED
echo ==========================================
exit /b 1

:build_success
echo.
echo ==========================================
echo SOVEREIGN BUILD SUCCESSFUL
echo ==========================================
echo.
echo Artifacts:
for %%f in ("%BUILD_DIR%\*.exe") do (
    echo   %%~nxf (%%~zf bytes)
)
echo.
echo Next steps:
echo   cd %BUILD_DIR%
echo   Deep2Server_Sovereign.exe
echo   curl http://127.0.0.1:11436/health
echo ==========================================
exit /b 0
