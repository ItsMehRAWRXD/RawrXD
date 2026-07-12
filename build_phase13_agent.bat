@echo off
REM Build script for Phase 13: Real Agent Integration (LLM + Sovereign Runtime)

echo ================================================================================
echo Sovereign Agent Build - Phase 13
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

echo [1/2] Compiling AgentSubsystem.cpp...
cl.exe /nologo /c /W3 /O2 /EHsc /Fo:bin\AgentSubsystem.obj ^
    src\core\AgentSubsystem.cpp ^
    /D_CRT_SECURE_NO_WARNINGS

if %ERRORLEVEL% neq 0 (
    echo FAILED: Agent compilation error
    exit /b 1
)
echo OK

echo.
echo ================================================================================
echo Agent Subsystem Built
echo ================================================================================
echo.
echo Configuration:
echo   Default Provider: Ollama (http://localhost:11434)
echo   Default Model: codellama
echo   Timeout: 120 seconds
echo.
echo To use Agent:
echo   1. Start Ollama: ollama run codellama
echo   2. Link Agent objects into SovereignCLI_Unified.exe
echo   3. Register Agent subsystem
echo   4. Run: SovereignCLI_Unified.exe agent generate "Hello world" rust
echo.
echo Example commands:
echo   agent generate "Sort algorithm" rust
echo   agent fix "$CODE" "$ERROR" rust
echo   agent optimize "$CODE" rust throughput
echo   agent plan "Build a web server"
echo.
