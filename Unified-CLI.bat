@echo off
REM RawrXD Unified CLI Batch Wrapper
REM Version: 4.0
REM Provides easy access to the unified command interface

set "UNIFIED_EXE=d:\rawrxd\src\RawrXD_Unified.exe"

if "%~1"=="" (
    REM No arguments - launch interactive mode
    "%UNIFIED_EXE%"
    goto :eof
)

if "%~1"=="--help" goto :help
if "%~1"=="-h" goto :help
if "%~1"=="/?" goto :help
if "%~1"=="--status" goto :status
if "%~1"=="--tools" goto :tools
if "%~1"=="--compilers" goto :compilers

REM Pass all arguments to the unified CLI
"%UNIFIED_EXE%" %*
goto :eof

:help
echo RawrXD Unified CLI Wrapper
echo ==========================
echo.
echo USAGE:
echo     Unified-CLI.bat [command] [arguments]
echo     Unified-CLI.bat --status
echo     Unified-CLI.bat ide
echo     Unified-CLI.bat python script.py
echo.
echo COMMANDS:
echo     --status        Show tool availability status
echo     --tools         List all available tools
echo     --compilers     List all compilers
echo     --help          Show this help
echo.
echo IDE Commands:
echo     ide, hybrid, sovereign, titan, production, autonomous
echo.
echo Compiler Commands (50+ languages):
echo     cc, python, javascript, bash, powershell, csharp, java
echo     rust, go, ruby, php, typescript, lua, perl, kotlin
echo     scala, swift, cpp, fortran, cobol, julia, dart, r
echo     matlab, groovy, clojure, haskell, erlang, elixir
echo     ocaml, lisp, scheme, fsharp, vb, objc, d, nim
echo     zig, crystal, v, odin
echo.
echo Testing Commands:
echo     test, benchmark, soak, contention, lock, golden
echo     phase19-26, phase3c, rbtree, diagnostic, fusion
echo.
echo Model Commands:
echo     model, gemm, lora, rmsnorm, http-chat, p2p
echo.
echo GPU Commands:
echo     gpu, amphibious
echo.
echo Debug Commands:
echo     debug-rms, debug-acc, debug-micro, debug-rax, debug-hang
echo     minimal, direct, stub
echo.
echo Batch Operations:
echo     run-all, test-all, benchmark-all, compiler-all
echo     titan-all, gpu-all, debug-all
echo.
goto :eof

:status
"%UNIFIED_EXE%" --status
goto :eof

:tools
"%UNIFIED_EXE%" --tools
goto :eof

:compilers
"%UNIFIED_EXE%" --compilers
goto :eof
