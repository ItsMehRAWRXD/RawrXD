@echo off
REM Build script for SovereignGUI - Phase 10: Agentic IDE Integration
REM Requires: Visual Studio 2022 with C++ tools

echo ================================================================================
echo Sovereign GUI Build - Phase 10
echo ================================================================================
echo.

REM Set up Visual Studio environment
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: Visual Studio not found
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VSINSTALLPATH=%%i"
)

if not defined VSINSTALLPATH (
    echo ERROR: Visual Studio C++ tools not found
    exit /b 1
)

call "%VSINSTALLPATH%\VC\Auxiliary\Build\vcvars64.bat"

REM Create output directory
if not exist "bin" mkdir bin

echo [1/2] Compiling SovereignGUI.cpp...
cl.exe /nologo /W3 /O2 /EHsc /Fe:bin\SovereignGUI.exe ^
    src\gui\SovereignGUI.cpp ^
    user32.lib gdi32.lib shell32.lib comctl32.lib ^
    /D_CRT_SECURE_NO_WARNINGS

if %ERRORLEVEL% neq 0 (
    echo FAILED: Compilation error
    exit /b 1
)

echo OK
echo.
echo [2/2] Build complete
echo.
echo ================================================================================
echo Output: bin\SovereignGUI.exe
echo ================================================================================
echo.
echo To run: bin\SovereignGUI.exe
echo.
echo Features:
echo   - Three-pane layout (Explorer ^| Editor ^| Output)
echo   - Real-time subsystem health status
echo   - Direct CLI integration
echo   - Multi-language execution panels
echo.
