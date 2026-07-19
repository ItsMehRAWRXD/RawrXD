@echo off
::============================================================================
:: RAWRXD IDE Build Script with Compiler Driver Integration
:: Builds both GUI and CLI IDE with compiler support
::============================================================================

echo ==========================================
echo RAWRXD IDE Build with Compiler Integration
echo ==========================================
echo.

set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"

if not exist "%VCVARS%" (
    echo [ERROR] Visual Studio not found!
    echo Please run this script from a Visual Studio Developer Command Prompt.
    pause
    exit /b 1
)

call "%VCVARS%"
if errorlevel 1 (
    echo [ERROR] Failed to initialize Visual Studio environment
    pause
    exit /b 1
)

echo [OK] Visual Studio environment loaded

:: Set paths
set "IDE_ROOT=%~dp0"
set "COMMON_DIR=%IDE_ROOT%common"
set "GUI_DIR=%IDE_ROOT%gui"
set "CLI_DIR=%IDE_ROOT%cli"
set "OUTPUT_DIR=%IDE_ROOT%bin"

:: Create output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo.
echo ==========================================
echo Building Common Library
echo ==========================================
cl /nologo /c /O2 /W4 /EHsc /I"%COMMON_DIR%" /Fo"%OUTPUT_DIR%\compiler_integration.obj" "%COMMON_DIR%\compiler_integration.c"
if errorlevel 1 (
    echo [ERROR] Failed to build common library
    pause
    exit /b 1
)
echo [OK] Common library built

echo.
echo ==========================================
echo Building GUI IDE
echo ==========================================
cl /nologo /O2 /W3 /EHsc /Fe"%OUTPUT_DIR%\codex_gui_ide.exe" ^
    "%GUI_DIR%\codex_gui_ide.cpp" ^
    "%GUI_DIR%\compiler_gui_integration.cpp" ^
    "%OUTPUT_DIR%\compiler_integration.obj" ^
    /I"%COMMON_DIR%" ^
    user32.lib gdi32.lib comdlg32.lib shell32.lib comctl32.lib

if errorlevel 1 (
    echo [ERROR] Failed to build GUI IDE
    pause
    exit /b 1
)
echo [OK] GUI IDE built: %OUTPUT_DIR%\codex_gui_ide.exe

echo.
echo ==========================================
echo Building CLI IDE
echo ==========================================
cl /nologo /O2 /W3 /EHsc /Fe"%OUTPUT_DIR%\codex_cli_ide.exe" ^
    "%CLI_DIR%\codex_cli_ide.cpp" ^
    "%CLI_DIR%\compiler_cli_integration.cpp" ^
    "%OUTPUT_DIR%\compiler_integration.obj" ^
    /I"%COMMON_DIR%"

if errorlevel 1 (
    echo [ERROR] Failed to build CLI IDE
    pause
    exit /b 1
)
echo [OK] CLI IDE built: %OUTPUT_DIR%\codex_cli_ide.exe

echo.
echo ==========================================
echo Build Complete!
echo ==========================================
echo.
echo Output files:
echo   - %OUTPUT_DIR%\codex_gui_ide.exe
echo   - %OUTPUT_DIR%\codex_cli_ide.exe
echo.
echo Features:
echo   - GGUF Model Loading (36 quant types)
echo   - RAWRXD Compiler Integration (C, Assembly, C#)
echo   - GUI: Win32 native interface
echo   - CLI: Interactive REPL
echo.
echo Usage:
echo   GUI: codex_gui_ide.exe [modelfile.gguf]
echo   CLI: codex_cli_ide.exe [command]
echo.

pause
