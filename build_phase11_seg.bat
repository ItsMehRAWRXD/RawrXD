@echo off
REM Build script for Phase 11: Sovereign Execution Graph

echo ================================================================================
echo Sovereign Execution Graph Build - Phase 11
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

echo [1/2] Compiling SovereignSEG.cpp...
cl.exe /nologo /c /W3 /O2 /EHsc /Fo:bin\SovereignSEG.obj ^
    src\core\SovereignSEG.cpp ^
    /D_CRT_SECURE_NO_WARNINGS

if %ERRORLEVEL% neq 0 (
    echo FAILED: SEG compilation error
    exit /b 1
)
echo OK

echo [2/2] Compiling SEGCommands.cpp...
cl.exe /nologo /c /W3 /O2 /EHsc /Fo:bin\SEGCommands.obj ^
    src\cli\SEGCommands.cpp ^
    /D_CRT_SECURE_NO_WARNINGS

if %ERRORLEVEL% neq 0 (
    echo FAILED: SEGCommands compilation error
    exit /b 1
)
echo OK

echo.
echo ================================================================================
echo SEG Components Built
echo ================================================================================
echo.
echo To use SEG:
echo   1. Link SEG objects into SovereignCLI_Unified.exe
echo   2. Register SEG subsystem in CLI
echo   3. Run: SovereignCLI_Unified.exe seg run workflows\build_and_test.json
echo.
