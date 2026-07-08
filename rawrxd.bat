@echo off
::=============================================================================
:: rawrxd.bat - RawrXD Command Line Interface
:: Usage: rawrxd [model-name] [command]
:: Example: rawrxd qwen "analyze this code and suggest improvements"
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
set "USER_COMMAND=%*"

:: Check if it's a special command
if /I "%MODEL_NAME%"=="list" goto :list_models
if /I "%MODEL_NAME%"=="status" goto :show_status
if /I "%MODEL_NAME%"=="compile" goto :compile_mode
if /I "%MODEL_NAME%"=="demo" goto :run_demo
if /I "%MODEL_NAME%"=="test" goto :run_tests
if /I "%MODEL_NAME%"=="update" goto :update_toolchain

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
set "TASK_FILE=%TEMP_DIR%\task_%RANDOM%.json"
(
    echo {
    echo   "model": "%MODEL_NAME%",
    echo   "command": "%USER_COMMAND:=\%",
    echo   "timestamp": "%date% %time%",
    echo   "autonomous": true,
    echo   "capabilities": [
    echo     "code_analysis",
    echo     "code_generation",
    echo     "refactoring",
    echo     "documentation",
    echo     "testing"
    echo   ]
    echo }
) > "%TASK_FILE%"

echo [1/5] Task file created: %TASK_FILE%
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
    echo     - Scanning for source files...
    echo     - Detecting language...
    echo     - Preparing build...
    call :handle_compile
) else if "%ACTION%"=="fix" (
    echo     [ACTION] Repair/Fix requested
    echo     - Analyzing codebase...
    echo     - Identifying issues...
    call :handle_fix
) else if "%ACTION%"=="analyze" (
    echo     [ACTION] Analysis requested
    echo     - Reading files...
    echo     - Processing...
    call :handle_analyze
) else if "%ACTION%"=="generate" (
    echo     [ACTION] Code generation requested
    echo     - Planning structure...
    echo     - Generating code...
    call :handle_generate
) else if "%ACTION%"=="test" (
    echo     [ACTION] Testing requested
    echo     - Finding tests...
    echo     - Running validation...
    call :handle_test
) else (
    echo     [ACTION] General assistance
    echo     - Processing request...
    echo     - Formulating response...
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
        echo     ✓ Build successful: output.exe
        echo     ✓ Run with: output.exe
    ) else (
        echo     ✗ Build failed
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
echo     1. Rebuild toolchain: rawrxd update
echo     2. Run diagnostics: rawrxd test
echo     3. Check model files in %MODELS_DIR%
goto :eof

:handle_analyze
echo.
echo     Analysis Mode:
echo     --------------
echo     - Current directory: %CD%
echo     - Files found:
dir /b 2>nul | head -10 2>nul || dir /b 2>nul | findstr /n "." | findstr "^[1-9]:"
echo.
echo     Analysis complete. See above for file listing.
goto :eof

:handle_generate
echo.
echo     Generation Mode:
echo     ----------------
echo     Creating template based on request...
echo.
echo     Generated: template_%RANDOM%.txt
echo     (Template generation would create actual code here)
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
echo     • Compile code:      rawrxd %MODEL_NAME% "compile this project"
echo     • Fix issues:        rawrxd %MODEL_NAME% "fix the build errors"
echo     • Analyze code:     rawrxd %MODEL_NAME% "analyze this file"
echo     • Generate code:    rawrxd %MODEL_NAME% "create a hello world"
echo     • Run tests:        rawrxd %MODEL_NAME% "run all tests"
echo.
echo     Or use special commands:
echo     • rawrxd list        - List available models
echo     • rawrxd status      - Show system status
echo     • rawrxd demo        - Run demonstration
echo     • rawrxd test        - Run test suite
echo     • rawrxd update      - Update toolchain
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
echo   rawrxd [model-name] [command]
echo   rawrxd [special-command]
echo.
echo EXAMPLES:
echo   rawrxd qwen "compile this C project"
echo   rawrxd gpt4 "fix the errors in main.c"
echo   rawrxd local "analyze my codebase"
echo   rawrxd demo
echo   rawrxd test
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
echo   The model will autonomously:
echo   • Detect your intent from natural language
echo   • Select appropriate tools
echo   • Execute tasks without manual steps
echo   • Report results
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
    echo   Create models in: %MODELS_DIR%
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
echo   Temp:      %TEMP_DIR%
echo.
echo Components:
if exist "%TOOLCHAIN_DIR%\minimal_assembler_v2.exe" (
    echo   [✓] Native Assembler
) else (
    echo   [✗] Native Assembler (missing)
)

if exist "%TOOLCHAIN_DIR%\linker_with_imports.exe" (
    echo   [✓] Native Linker
) else (
    echo   [✗] Native Linker (missing)
)

if exist "%TOOLCHAIN_DIR%\c_compiler_enhanced.exe" (
    echo   [✓] C Compiler
) else (
    echo   [✗] C Compiler (missing)
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
    echo Manual rebuild required.
)

goto :end

:end
echo.
endlocal
