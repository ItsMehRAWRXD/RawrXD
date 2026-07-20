@echo off
REM ============================================================================
REM Build script for RawrXD IDE Deterministic Replay Gate
REM ============================================================================

setlocal enabledelayedexpansion

set "GATE_NAME=deterministic_replay_gate"
set "SOURCE_FILE=%~dp0%GATE_NAME%.cpp"
set "OUTPUT_DIR=%~dp0..\..\build-ninja\tests"
set "OUTPUT_EXE=%OUTPUT_DIR%\%GATE_NAME%.exe"

REM Create output directory if it doesn't exist
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo ============================================================================
echo  Building %GATE_NAME%
echo ============================================================================
echo Source: %SOURCE_FILE%
echo Output: %OUTPUT_EXE%
echo.

REM Check for Visual Studio environment
if not defined VSINSTALLDIR (
    echo ERROR: Visual Studio environment not set.
    echo Please run from a Visual Studio Developer Command Prompt.
    exit /b 1
)

REM Compile with MSVC
cl.exe /nologo /W4 /EHsc /O2 /DUNICODE /D_UNICODE ^
    /Fe:"%OUTPUT_EXE%" ^
    /Fo:"%OUTPUT_DIR%\%GATE_NAME%.obj" ^
    "%SOURCE_FILE%" ^
    kernel32.lib user32.lib

if errorlevel 1 (
    echo.
    echo ERROR: Compilation failed.
    exit /b 1
)

echo.
echo Build successful: %OUTPUT_EXE%
echo.

REM Run the gate if --run flag is provided
if "%1"=="--run" (
    echo Running gate...
    echo.
    "%OUTPUT_EXE%"
    exit /b %errorlevel%
)

exit /b 0
