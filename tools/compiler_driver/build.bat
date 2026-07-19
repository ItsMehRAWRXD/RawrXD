@echo off
REM RAWRXD Compiler Driver Build Script
REM Builds the unified compiler driver with all backends

setlocal enabledelayedexpansion

echo ==========================================
echo RAWRXD Compiler Driver Build
echo ==========================================
echo.

REM Set paths
set "SRC_DIR=%~dp0src"
set "INC_DIR=%~dp0include"
set "OUT_DIR=%~dp0bin"
set "OBJ_DIR=%~dp0obj"

REM Create output directories
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

REM Find Visual Studio
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VS_PATH=%%i"
    )
)

if not defined VS_PATH (
    echo ERROR: Visual Studio not found
    exit /b 1
)

echo Found Visual Studio at: %VS_PATH%

REM Setup environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

REM Compiler flags
set "CFLAGS=/nologo /W3 /O2 /MD /I"%INC_DIR%" /D_CRT_SECURE_NO_WARNINGS"
set "LDFLAGS=/nologo /SUBSYSTEM:CONSOLE"

echo.
echo Compiling source files...
echo.

REM Compile main driver
cl %CFLAGS% /c /Fo"%OBJ_DIR%\compiler_driver.obj" "%SRC_DIR%\compiler_driver.c" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile compiler_driver.c
    exit /b 1
)
echo [OK] compiler_driver.c

REM Compile backends
cl %CFLAGS% /c /Fo"%OBJ_DIR%\c_backend.obj" "%SRC_DIR%\backends\c_backend.c" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile c_backend.c
    exit /b 1
)
echo [OK] c_backend.c

cl %CFLAGS% /c /Fo"%OBJ_DIR%\asm_backend.obj" "%SRC_DIR%\backends\asm_backend.c" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile asm_backend.c
    exit /b 1
)
echo [OK] asm_backend.c

cl %CFLAGS% /c /Fo"%OBJ_DIR%\csharp_backend.obj" "%SRC_DIR%\backends\csharp_backend.c" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile csharp_backend.c
    exit /b 1
)
echo [OK] csharp_backend.c

REM Compile main
cl %CFLAGS% /c /Fo"%OBJ_DIR%\main.obj" "%SRC_DIR%\main.c" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Failed to compile main.c
    exit /b 1
)
echo [OK] main.c

echo.
echo Linking...
echo.

REM Link all objects
link %LDFLAGS% /OUT:"%OUT_DIR%\rawrxd-compiler.exe" ^
    "%OBJ_DIR%\compiler_driver.obj" ^
    "%OBJ_DIR%\c_backend.obj" ^
    "%OBJ_DIR%\asm_backend.obj" ^
    "%OBJ_DIR%\csharp_backend.obj" ^
    "%OBJ_DIR%\main.obj" ^
    kernel32.lib user32.lib

if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo [OK] rawrxd-compiler.exe
echo.

REM Copy to system path (optional)
if "%1"=="--install" (
    echo Installing to system...
    copy /Y "%OUT_DIR%\rawrxd-compiler.exe" "C:\Windows\System32\" >nul 2>&1
    if errorlevel 1 (
        echo WARNING: Could not install to system path
    ) else (
        echo [OK] Installed to C:\Windows\System32\
    )
)

echo ==========================================
echo Build Complete!
echo ==========================================
echo.
echo Output: %OUT_DIR%\rawrxd-compiler.exe
echo.
echo Usage:
echo   rawrxd-compiler compile hello.c
echo   rawrxd-compiler compile hello.asm
echo   rawrxd-compiler compile hello.cs
echo   rawrxd-compiler list-backends
echo.

endlocal
