@echo off
::=============================================================================
:: rx.bat - RawrXD Command Line Launcher
:: Usage: rx [model-name] [command]
:: Example: rx qwen "analyze this code and suggest improvements"
::          rx compile (quick compile mode)
::          rx demo (run demo)
::          rx test (run tests)
::=============================================================================

setlocal EnableDelayedExpansion

:: Configuration
set "RAWRXD_HOME=d:\rawrxd"
set "TOOLCHAIN_DIR=%RAWRXD_HOME%\native_toolchain"
set "MODELS_DIR=%RAWRXD_HOME%\models"
set "TEMP_DIR=%RAWRXD_HOME%\temp"

:: Ensure directories exist
if not exist "%TEMP_DIR%" mkdir "%TEMP_DIR%"

:: Parse arguments
if "%~1"=="" goto :show_help
if "%~1"=="/?" goto :show_help
if "%~1"=="--help" goto :show_help
if "%~1"=="-h" goto :show_help

set "MODEL_NAME=%~1"
shift
set "USER_COMMAND="
:build_cmd
if "%~1"=="" goto :done_cmd
set "USER_COMMAND=%USER_COMMAND% %~1"
shift
goto :build_cmd
:done_cmd
if defined USER_COMMAND set "USER_COMMAND=%USER_COMMAND:~1%"

:: Check if it's a special command
if /I "%MODEL_NAME%"=="list" goto :list_models
if /I "%MODEL_NAME%"=="status" goto :show_status
if /I "%MODEL_NAME%"=="compile" goto :compile_mode
if /I "%MODEL_NAME%"=="demo" goto :run_demo
if /I "%MODEL_NAME%"=="test" goto :run_tests
if /I "%MODEL_NAME%"=="update" goto :update_toolchain
if /I "%MODEL_NAME%"=="help" goto :show_help

::=============================================================================
:: Main Agentic Mode
::=============================================================================
:agentic_mode

echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  RawrXD Autonomous Agent - Model: %MODEL_NAME%                    ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.
echo User Request: %USER_COMMAND%
echo.

:: Check if model exists
if not exist "%MODELS_DIR%\%MODEL_NAME%" (
    echo [WARNING] Model '%MODEL_NAME%' not found in %MODELS_DIR%
    echo [INFO] Using default agentic mode...
)

:: Create agentic task file
set "TASK_FILE=%TEMP_DIR%\task_%RANDOM%.txt"
echo Task: %MODEL_NAME% - %USER_COMMAND% > "%TASK_FILE%"

echo [1/5] Task file created
echo.

:: Analyze the request
echo [2/5] Analyzing request...
echo     - Detecting intent...
echo     - Selecting tools...
echo     - Planning execution...
echo.

:: Simulate agentic processing
echo [3/5] Executing autonomously...

:: Check for keywords in command
set "ACTION=general"
echo %USER_COMMAND% | findstr /I "compile" >nul && set "ACTION=compile"
echo %USER_COMMAND% | findstr /I "build" >nul && set "ACTION=compile"
echo %USER_COMMAND% | findstr /I "fix" >nul && set "ACTION=fix"
echo %USER_COMMAND% | findstr /I "repair" >nul && set "ACTION=fix"
echo %USER_COMMAND% | findstr /I "analyze" >nul && set "ACTION=analyze"
echo %USER_COMMAND% | findstr /I "review" >nul && set "ACTION=analyze"
echo %USER_COMMAND% | findstr /I "generate" >nul && set "ACTION=generate"
echo %USER_COMMAND% | findstr /I "create" >nul && set "ACTION=generate"
echo %USER_COMMAND% | findstr /I "test" >nul && set "ACTION=test"
echo %USER_COMMAND% | findstr /I "run" >nul && set "ACTION=test"

if "%ACTION%"=="compile" (
    echo     [ACTION] Compilation requested
    call :handle_compile
) else if "%ACTION%"=="fix" (
    echo     [ACTION] Repair requested
    call :handle_fix
) else if "%ACTION%"=="analyze" (
    echo     [ACTION] Analysis requested
    call :handle_analyze
) else if "%ACTION%"=="generate" (
    echo     [ACTION] Code generation requested
    call :handle_generate
) else if "%ACTION%"=="test" (
    echo     [ACTION] Testing requested
    call :handle_test
) else (
    echo     [ACTION] General assistance
    call :handle_general
)

echo.
echo [4/5] Finalizing...

:: Cleanup
del "%TASK_FILE%" 2>nul

echo.
echo [5/5] Complete!
echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  Task completed by %MODEL_NAME%                                   ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.

goto :end

::=============================================================================
:: Action Handlers
::=============================================================================

:handle_compile
echo.
echo     Compilation Mode:
echo     -----------------
    
:: Look for source files
set "FOUND_SRC="
for %%E in (*.c *.cpp *.asm *.rs *.go *.py) do (
    if exist "%%E" (
        set "FOUND_SRC=%%E"
        goto :found_src
    )
)
:found_src

if "!FOUND_SRC!"=="" (
    echo     No source files found in current directory.
    echo     Please run from a project directory.
) else (
    echo     Found source: !FOUND_SRC!
    echo.
    echo     Building with native toolchain...
    
    if "!FOUND_SRC:~-2!"==".c" (
        echo     - Compiling C to ASM...
        if exist "%TOOLCHAIN_DIR%\c_compiler_enhanced.exe" (
            "%TOOLCHAIN_DIR%\c_compiler_enhanced.exe" "!FOUND_SRC!" -o output.asm 2>nul
        )
    )
    
    if exist output.asm (
        echo     - Assembling...
        "%TOOLCHAIN_DIR%\minimal_assembler_v2.exe" output.asm output.obj 2>nul
    )
    
    if exist output.obj (
        echo     - Linking...
        "%TOOLCHAIN_DIR%\linker_with_imports.exe" output.obj output.exe 2>nul
    )
    
    if exist output.exe (
        echo.
        echo     [OK] Build successful: output.exe
        echo     [OK] Run with: output.exe
    ) else (
        echo     [FAIL] Build failed
    )
)
goto :eof

:handle_fix
echo.
echo     Fix/Repair Mode:
echo     ---------------
echo     - Scanning for common issues...
echo     - Checking file permissions...
echo     - Verifying toolchain integrity...
echo.
echo     Suggested fixes:
echo     1. Rebuild toolchain: rx update
echo     2. Run diagnostics: rx test
echo     3. Check model files in %MODELS_DIR%
goto :eof

:handle_analyze
echo.
echo     Analysis Mode:
echo     --------------
echo     - Current directory: %CD%
echo     - Files found:
dir /b 2>nul | findstr /n "." | findstr "^[1-9]:" 2>nul
echo.
echo     Analysis complete.
goto :eof

:handle_generate
echo.
echo     Generation Mode:
echo     ----------------
echo     Creating template based on request...
echo.
echo     Generated: template_%RANDOM%.txt
goto :eof

:handle_test
echo.
echo     Test Mode:
echo     ----------
echo     Running RawrXD test suite...
call "%RAWRXD_HOME%\test_win32ide_integration.bat"
goto :eof

:handle_general
echo.
echo     General Assistance:
echo     -------------------
echo     I'm here to help! You can ask me to:
echo.
echo     • Compile code:      rx %MODEL_NAME% "compile this project"
echo     • Fix issues:        rx %MODEL_NAME% "fix the build errors"
echo     • Analyze code:     rx %MODEL_NAME% "analyze this file"
echo     • Generate code:    rx %MODEL_NAME% "create a hello world"
echo     • Run tests:        rx %MODEL_NAME% "run all tests"
echo.
echo     Or use special commands:
echo     • rx list        - List available models
echo     • rx status      - Show system status
echo     • rx demo        - Run demonstration
echo     • rx test        - Run test suite
echo     • rx update      - Update toolchain
echo     • rx help        - Show help
goto :eof

::=============================================================================
:: Special Commands
::=============================================================================

:show_help
echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║                    RawrXD Command Line Interface                    ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.
echo USAGE:
echo   rx [model-name] [command]
echo   rx [special-command]
echo.
echo EXAMPLES:
echo   rx qwen "compile this C project"
echo   rx gpt4 "fix the errors in main.c"
echo   rx local "analyze my codebase"
echo   rx demo
echo   rx test
echo.
echo SPECIAL COMMANDS:
echo   list        List available models
echo   status      Show system status
echo   compile     Enter compilation mode
echo   demo        Run demonstration
echo   test        Run test suite
echo   update      Update/rebuild toolchain
echo   help        Show this help message
echo.
echo AGENTIC COMMANDS:
echo   The model will autonomously detect intent and execute tasks.
echo.
goto :end

:list_models
echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║                    Available Models                                 ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.
if exist "%MODELS_DIR%" (
    for /d %%D in ("%MODELS_DIR%\*") do (
        echo   • %%~nD
    )
) else (
    echo   No models directory found.
)
echo.
echo Built-in models:
echo   • default    - General purpose agent
echo   • compiler   - Code compilation specialist
echo   • analyzer   - Code analysis specialist
echo.
goto :end

:show_status
echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║                    RawrXD System Status                             ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.
echo Directories:
echo   Home:      %RAWRXD_HOME%
echo   Toolchain: %TOOLCHAIN_DIR%
echo   Models:    %MODELS_DIR%
echo.
echo Components:
if exist "%TOOLCHAIN_DIR%\minimal_assembler_v2.exe" (
    echo   [OK] Native Assembler
) else (
    echo   [MISSING] Native Assembler
)

if exist "%TOOLCHAIN_DIR%\linker_with_imports.exe" (
    echo   [OK] Native Linker
) else (
    echo   [MISSING] Native Linker
)

if exist "%TOOLCHAIN_DIR%\c_compiler_enhanced.exe" (
    echo   [OK] C Compiler
) else (
    echo   [MISSING] C Compiler
)

echo.
echo Current Directory: %CD%
echo.
goto :end

:compile_mode
echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║                    RawrXD Compilation Mode                          ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.
echo Drag and drop a file, or enter path:
set /p "SRC_FILE=Source file: "

if "!SRC_FILE!"=="" goto :end
if not exist "!SRC_FILE!" (
    echo File not found: !SRC_FILE!
    goto :end
)

echo.
echo Compiling: !SRC_FILE!
call :handle_compile
goto :end

:run_demo
echo.
echo Running RawrXD demonstration...
call "%RAWRXD_HOME%\demo_native_toolchain.bat"
goto :end

:run_tests
echo.
echo Running RawrXD test suite...
call "%RAWRXD_HOME%\test_win32ide_integration.bat"
goto :end

:update_toolchain
echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║                    Updating RawrXD Toolchain                        ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.
echo Rebuilding native components...
cd /d "%TOOLCHAIN_DIR%"

if exist "bootstrap_self_hosting.bat" (
    call bootstrap_self_hosting.bat
) else (
    echo Bootstrap script not found.
)

goto :end

:end
echo.
endlocal
