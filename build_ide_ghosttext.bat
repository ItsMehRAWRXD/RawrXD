@echo off
REM ============================================================================
REM BUILD SCRIPT: RawrXD IDE with GhostText Infrastructure
REM ============================================================================
REM Builds the complete Win32 IDE with:
REM - GhostText Timer Infrastructure
REM - Atomic Version Stamping
REM - SovereignBridge Stub
REM - Lock-free concurrency
REM ============================================================================

setlocal enabledelayedexpansion

echo ============================================================================
echo RawrXD IDE Build - GhostText Integration
echo ============================================================================
echo.

REM Detect Visual Studio compiler
set VCVARS=
if exist "D:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    set VCVARS=D:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    set VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat
) else (
    echo ERROR: Could not find VS2022 vcvars64.bat
    exit /b 1
)

echo [STEP 1] Initializing Visual Studio 2022 environment...
call "%VCVARS%" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Failed to initialize VS environment
    exit /b 1
)
echo [OK] VS Environment initialized
echo.

REM Set paths
set SRC_DIR=D:\RawrXD\src\ide
set OUT_DIR=D:\RawrXD\build\ide
set BIN_DIR=D:\RawrXD\bin

REM Create output directories
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

echo [STEP 2] Compiling SovereignBridge Stub...
echo   - SovereignBridge_Stub.cpp
echo.

cl.exe /c /W4 /EHsc /O2 /DUNICODE /D_UNICODE /Fo"%OUT_DIR%\SovereignBridge_Stub.obj" "%SRC_DIR%\SovereignBridge_Stub.cpp" >nul 2>&1
if errorlevel 1 (
    echo ERROR: SovereignBridge_Stub.cpp compilation failed
    exit /b 1
)
echo [OK] SovereignBridge_Stub.obj created
echo.

echo [STEP 3] Compiling RawrXD IDE Win32...
echo   - RawrXD_IDE_Win32.cpp
echo   - Includes: GhostText Timer Infrastructure
echo   - Includes: Atomic Version Stamping
echo   - Includes: Lock-free Concurrency
echo.

cl.exe /c /W4 /EHsc /O2 /DUNICODE /D_UNICODE /Fo"%OUT_DIR%\RawrXD_IDE_Win32.obj" "%SRC_DIR%\RawrXD_IDE_Win32.cpp" >nul 2>&1
if errorlevel 1 (
    echo ERROR: RawrXD_IDE_Win32.cpp compilation failed
    exit /b 1
)
echo [OK] RawrXD_IDE_Win32.obj created
echo.

echo [STEP 4] Linking executable...
echo   - Output: RawrXD-Win32IDE.exe
echo   - Size target: ~55MB
echo.

link.exe /OUT:"%BIN_DIR%\RawrXD-Win32IDE.exe" ^
    "%OUT_DIR%\RawrXD_IDE_Win32.obj" ^
    "%OUT_DIR%\SovereignBridge_Stub.obj" ^
    user32.lib gdi32.lib comctl32.lib comdlg32.lib ^
    shell32.lib shlwapi.lib advapi32.lib ole32.lib ^
    /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /nologo >nul 2>&1

if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo [OK] RawrXD-Win32IDE.exe linked successfully
echo.

REM Get file size
for %%F in ("%BIN_DIR%\RawrXD-Win32IDE.exe") do set FILESIZE=%%~zF
echo [INFO] Binary size: %FILESIZE% bytes
echo.

echo ============================================================================
echo BUILD COMPLETE
echo ============================================================================
echo.
echo Launch command:
echo   "%BIN_DIR%\RawrXD-Win32IDE.exe"
echo.
echo Test Instructions:
echo   1. Launch the IDE
echo   2. Type in the editor - observe 200ms debounce
echo   3. Press F12 for GhostText Smoke Test
echo   4. Check Output panel for version stamps
echo   5. Type rapidly to test stale-check logic
echo.
echo ============================================================================

endlocal
