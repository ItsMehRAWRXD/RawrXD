@echo off
REM ============================================================================
REM Minimal runner for Deterministic Replay Gate (no VS environment required)
REM ============================================================================

setlocal enabledelayedexpansion

set "GATE_NAME=deterministic_replay_gate"
set "BUILD_DIR=%~dp0..\..\build-ninja\tests"
set "GATE_EXE=%BUILD_DIR%\%GATE_NAME%.exe"

echo ============================================================================
echo  RawrXD IDE Deterministic Replay Gate
echo ============================================================================
echo.

REM Check if already built
if exist "%GATE_EXE%" (
    echo Found existing gate executable: %GATE_EXE%
    goto :run_gate
)

REM Try to find cl.exe in common locations
set "CL_PATH="

REM Check VS2022 Enterprise
if exist "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe" (
    set "CL_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
    goto :found_compiler
)

REM Check VS2022 Community
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.*\bin\Hostx64\x64\cl.exe" (
    for /f "delims=" %%i in ('dir /b /s "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.*\bin\Hostx64\x64\cl.exe" 2^>nul') do (
        set "CL_PATH=%%i"
        goto :found_compiler
    )
)

REM Check VS2022 Professional
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.*\bin\Hostx64\x64\cl.exe" (
    for /f "delims=" %%i in ('dir /b /s "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.*\bin\Hostx64\x64\cl.exe" 2^>nul') do (
        set "CL_PATH=%%i"
        goto :found_compiler
    )
)

REM Check VS2022 Enterprise (standard path)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.*\bin\Hostx64\x64\cl.exe" (
    for /f "delims=" %%i in ('dir /b /s "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.*\bin\Hostx64\x64\cl.exe" 2^>nul') do (
        set "CL_PATH=%%i"
        goto :found_compiler
    )
)

if not defined CL_PATH (
    echo ERROR: Could not find cl.exe
    echo Please run from a Visual Studio Developer Command Prompt,
    echo or ensure Visual Studio is installed in a standard location.
    exit /b 2
)

:found_compiler
echo Found compiler: %CL_PATH%

REM Create output directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Compile
echo.
echo Building %GATE_NAME%...
"%CL_PATH%" /nologo /W4 /EHsc /O2 /DUNICODE /D_UNICODE ^
    /Fe:"%GATE_EXE%" ^
    /Fo:"%BUILD_DIR%\%GATE_NAME%.obj" ^
    "%~dp0%GATE_NAME%.cpp" ^
    kernel32.lib user32.lib

if errorlevel 1 (
    echo.
    echo ERROR: Compilation failed.
    exit /b 2
)

echo Build successful!
echo.

:run_gate
echo Running gate...
echo.

"%GATE_EXE%" %*

set "EXIT_CODE=%ERRORLEVEL%"
echo.
echo Gate exited with code: %EXIT_CODE%

if %EXIT_CODE%==0 (
    echo RESULT: ALL TESTS PASSED
) else if %EXIT_CODE%==1 (
    echo RESULT: DETERMINISM VIOLATION DETECTED
) else if %EXIT_CODE%==2 (
    echo RESULT: INFRASTRUCTURE FAILURE
) else if %EXIT_CODE%==3 (
    echo RESULT: TIMEOUT
) else (
    echo RESULT: UNKNOWN ERROR
)

exit /b %EXIT_CODE%
