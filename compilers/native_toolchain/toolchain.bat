@echo off
REM ============================================================================
REM RawrXD Native Toolchain - Unified Wrapper
REM ============================================================================
REM This script provides a single entry point for all toolchain operations.
REM
REM Usage:
REM   toolchain.bat assemble <input.asm> <output.obj>
REM   toolchain.bat link <input.obj> <output.exe>
REM   toolchain.bat build <input.asm> <output.exe>
REM   toolchain.bat library <output.lib> <input1.obj> [input2.obj ...]
REM   toolchain.bat resource <input.rc> <output.res>
REM   toolchain.bat test
REM   toolchain.bat clean
REM ============================================================================

setlocal enabledelayedexpansion

set "TOOLCHAIN_DIR=%~dp0"
set "ASSEMBLER=%TOOLCHAIN_DIR%rawrxd_native_assembler.exe"
set "LINKER=%TOOLCHAIN_DIR%rawrxd_native_linker.exe"
set "LIBRARIAN=%TOOLCHAIN_DIR%rawrxd_native_librarian.exe"
set "RC=%TOOLCHAIN_DIR%rawrxd_native_rc.exe"

if "%1"=="" goto :usage
if /I "%1"=="assemble" goto :assemble
if /I "%1"=="link" goto :link
if /I "%1"=="build" goto :build
if /I "%1"=="library" goto :library
if /I "%1"=="resource" goto :resource
if /I "%1"=="test" goto :test
if /I "%1"=="clean" goto :clean
if /I "%1"=="help" goto :usage
goto :usage

:assemble
if "%2"=="" goto :usage
if "%3"=="" goto :usage
echo [ASSEMBLE] %2 -^> %3
"%ASSEMBLER%" /c "%2" "%3"
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Assembly complete
) else (
    echo [ERROR] Assembly failed
)
exit /b %ERRORLEVEL%

:link
if "%2"=="" goto :usage
if "%3"=="" goto :usage
echo [LINK] %2 -^> %3
"%LINKER%" "%2" /out:"%3"
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Link complete
) else (
    echo [ERROR] Link failed
)
exit /b %ERRORLEVEL%

:build
if "%2"=="" goto :usage
if "%3"=="" goto :usage
set "ASM_FILE=%2"
set "EXE_FILE=%3"
set "OBJ_FILE=%TEMP%\toolchain_temp.obj"

echo [BUILD] %ASM_FILE% -^> %EXE_FILE%

REM Step 1: Assemble
echo [1/2] Assembling...
"%ASSEMBLER%" /c "%ASM_FILE%" "%OBJ_FILE%"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Assembly failed
    if exist "%OBJ_FILE%" del "%OBJ_FILE%"
    exit /b 1
)

REM Step 2: Link
echo [2/2] Linking...
"%LINKER%" "%OBJ_FILE%" /out:"%EXE_FILE%"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Link failed
    if exist "%OBJ_FILE%" del "%OBJ_FILE%"
    exit /b 1
)

REM Cleanup
if exist "%OBJ_FILE%" del "%OBJ_FILE%"
echo [SUCCESS] Build complete
exit /b 0

:library
if "%2"=="" goto :usage
if "%3"=="" goto :usage
set "LIB_FILE=%2"
shift
shift
set "OBJ_FILES="
:library_loop
if "%1"=="" goto :library_exec
set "OBJ_FILES=%OBJ_FILES% %1"
shift
goto :library_loop
:library_exec
echo [LIBRARY] Creating %LIB_FILE%
"%LIBRARIAN%" /out:"%LIB_FILE%" %OBJ_FILES%
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Library created
) else (
    echo [ERROR] Library creation failed
)
exit /b %ERRORLEVEL%

:resource
if "%2"=="" goto :usage
if "%3"=="" goto :usage
echo [RESOURCE] %2 -^> %3
"%RC%" "%2" "%3"
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Resource compiled
) else (
    echo [ERROR] Resource compilation failed
)
exit /b %ERRORLEVEL%

:test
echo [TEST] Running toolchain tests...
call "%TOOLCHAIN_DIR%test_toolchain.bat"
exit /b %ERRORLEVEL%

:clean
echo [CLEAN] Removing generated files...
if exist *.obj del *.obj
if exist *.exe del *.exe
if exist *.lib del *.lib
if exist *.res del *.res
if exist *.pdb del *.pdb
echo [SUCCESS] Clean complete
exit /b 0

:usage
echo.
echo ================================================================================
echo RawrXD Native Toolchain - Unified Wrapper
echo ================================================================================
echo.
echo Usage: toolchain.bat ^<command^> [arguments]
echo.
echo Commands:
echo   assemble ^<input.asm^> ^<output.obj^>    Assemble assembly to object file
echo   link ^<input.obj^> ^<output.exe^>        Link object file to executable
echo   build ^<input.asm^> ^<output.exe^>       Assemble and link in one step
echo   library ^<output.lib^> ^<inputs.obj^>   Create static library
echo   resource ^<input.rc^> ^<output.res^>    Compile resource script
echo   test                                 Run integration tests
echo   clean                                Remove generated files
echo   help                                 Show this help
echo.
echo Examples:
echo   toolchain.bat assemble kernel.asm kernel.obj
echo   toolchain.bat link kernel.obj kernel.exe
echo   toolchain.bat build kernel.asm kernel.exe
echo   toolchain.bat library mylib.lib obj1.obj obj2.obj
echo   toolchain.bat test
echo.
echo Toolchain Components:
echo   Assembler:  %ASSEMBLER%
echo   Linker:     %LINKER%
echo   Librarian:  %LIBRARIAN%
echo   RC:         %RC%
echo ================================================================================
exit /b 1