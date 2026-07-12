@echo off
REM Build script for Phase 12: Autonomous Code Generation + Execution Loops

echo ================================================================================
echo Sovereign AutoLoop Build - Phase 12
echo ================================================================================
echo.

REM Set up Visual Studio environment
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VSINSTALLPATH=%%i"
)
call "%VSINSTALLPATH%\VC\Auxiliary\Build\vcvars64.bat"

REM Create output directory
if not exist "bin" mkdir bin

echo [1/2] Compiling SovereignAutoLoop.cpp...
cl.exe /nologo /c /W3 /O2 /EHsc /Fo:bin\SovereignAutoLoop.obj ^
    src\core\SovereignAutoLoop.cpp ^
    /D_CRT_SECURE_NO_WARNINGS

if %ERRORLEVEL% neq 0 (
    echo FAILED: AutoLoop compilation error
    exit /b 1
)
echo OK

echo [2/2] Compiling AutoLoopCommands.cpp...
cl.exe /nologo /c /W3 /O2 /EHsc /Fo:bin\AutoLoopCommands.obj ^
    src\cli\AutoLoopCommands.cpp ^
    /D_CRT_SECURE_NO_WARNINGS

if %ERRORLEVEL% neq 0 (
    echo FAILED: AutoLoopCommands compilation error
    exit /b 1
)
echo OK

echo.
echo ================================================================================
echo AutoLoop Components Built
echo ================================================================================
echo.
echo To use AutoLoop:
echo   1. Link AutoLoop objects into SovereignCLI_Unified.exe
echo   2. Register AutoLoop subsystem in CLI
echo   3. Run: SovereignCLI_Unified.exe loop run write_execute_fix main.rs rust
echo.
echo Example loops:
echo   loop run write_execute_fix main.rs rust "Hello world"
echo   loop run optimize_benchmark kernel.rs rust throughput
echo   loop run multi_language "Sort algorithm" main.rs rust
echo.
