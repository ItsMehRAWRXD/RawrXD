@echo off
REM ===============================================================================
REM Rebuild Silent Executables with Correct Settings
REM Fixes STATUS_INVALID_HANDLE crashes
REM ===============================================================================

setlocal EnableDelayedExpansion

echo ===============================================================================
echo Silent Executable Rebuilder
echo ===============================================================================
echo.

REM Set up VS2022 environment
set VS_PATH=C:\VS2022Enterprise
set VC_TOOLS=%VS_PATH%\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64
set WINSDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64
set WINSDK_UCRT=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64

set ML64=%VC_TOOLS%\ml64.exe
set LINK=%VC_TOOLS%\link.exe

set SRC_DIR=d:\rawrxd\compilers\assembly_source
set OUT_DIR=d:\rawrxd\compilers\rebuilt
set LOG_DIR=d:\rawrxd\compilers\rebuilt\logs

REM Create directories
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo Tools:
echo   ML64: %ML64%
echo   LINK: %LINK%
echo   SDK Lib: %WINSDK_LIB%
echo   Output: %OUT_DIR%
echo.

REM Check tools
if not exist "%ML64%" (
    echo ERROR: ml64.exe not found
    exit /b 1
)
if not exist "%LINK%" (
    echo ERROR: link.exe not found
    exit /b 1
)

echo [OK] Tools found
echo.

REM ===============================================================================
REM Test Toolchain
REM ===============================================================================
echo Testing toolchain...
echo.

REM Create minimal test assembly
echo ; Toolchain test > "%OUT_DIR%\test.asm"
echo extrn ExitProcess: proc >> "%OUT_DIR%\test.asm"
echo .code >> "%OUT_DIR%\test.asm"
echo mainCRTStartup proc >> "%OUT_DIR%\test.asm"
echo   xor ecx, ecx >> "%OUT_DIR%\test.asm"
echo   call ExitProcess >> "%OUT_DIR%\test.asm"
echo mainCRTStartup endp >> "%OUT_DIR%\test.asm"
echo end >> "%OUT_DIR%\test.asm"

echo Assembling test...
"%ML64%" /c /Fo"%OUT_DIR%\test.obj" /W3 /nologo "%OUT_DIR%\test.asm" > "%LOG_DIR%\test_asm.log" 2>&1
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Assembly failed
    type "%LOG_DIR%\test_asm.log"
    exit /b 1
)
echo [OK] Assembly

echo Linking test...
"%LINK%" /LIBPATH:"%WINSDK_LIB%" /LIBPATH:"%WINSDK_UCRT%" ^
    /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup ^
    kernel32.lib ucrt.lib legacy_stdio_definitions.lib /OUT:"%OUT_DIR%\test.exe" "%OUT_DIR%\test.obj" ^
    > "%LOG_DIR%\test_link.log" 2>&1
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Link failed
    type "%LOG_DIR%\test_link.log"
    exit /b 1
)
echo [OK] Link

echo Testing executable...
echo %TIME% > "%LOG_DIR%\test_run.log"
"%OUT_DIR%\test.exe" >> "%LOG_DIR%\test_run.log" 2>&1
echo Exit: %ERRORLEVEL% >> "%LOG_DIR%\test_run.log"
echo %TIME% >> "%LOG_DIR%\test_run.log"

if %ERRORLEVEL% equ 0 (
    echo [OK] Test executable ran successfully
) else (
    echo [WARN] Test executable exit code: %ERRORLEVEL%
)

echo.
echo [OK] Toolchain verified!
echo.

REM ===============================================================================
REM Rebuild Executables
REM ===============================================================================
echo ===============================================================================
echo Rebuilding Executables
echo ===============================================================================
echo.

set SUCCESS=0
set FAILED=0

REM Function to rebuild
:Rebuild
set EXE_NAME=%~1
set SOURCE_NAME=%~2
set ENTRY_POINT=%~3

if "%~3"=="" set ENTRY_POINT=mainCRTStartup

echo.
echo Building: %EXE_NAME%
echo   Source: %SOURCE_NAME%
echo   Entry: %ENTRY_POINT%

set SOURCE_PATH=%SRC_DIR%\%SOURCE_NAME%
if not exist "%SOURCE_PATH%" (
    echo   [SKIP] Source not found: %SOURCE_PATH%
    exit /b 1
)

set OBJ_FILE=%OUT_DIR%\%EXE_NAME:.exe=.obj%
set EXE_FILE=%OUT_DIR%\%EXE_NAME%

echo   Assembling...
"%ML64%" /c /Fo"%OBJ_FILE%" /W3 /nologo "%SOURCE_PATH%" > "%LOG_DIR%\%EXE_NAME%_asm.log" 2>&1
if %ERRORLEVEL% neq 0 (
    echo   [FAIL] Assembly failed
    exit /b 1
)

echo   Linking...
"%LINK%" /LIBPATH:"%WINSDK_LIB%" /LIBPATH:"%WINSDK_UCRT%" ^
    /SUBSYSTEM:CONSOLE /ENTRY:%ENTRY_POINT% /NODEFAULTLIB ^
    kernel32.lib ucrt.lib /OUT:"%EXE_FILE%" "%OBJ_FILE%" ^
    > "%LOG_DIR%\%EXE_NAME%_link.log" 2>&1
if %ERRORLEVEL% neq 0 (
    echo   [FAIL] Link failed
    exit /b 1
)

for %%F in ("%EXE_FILE%") do echo   [OK] Built: %%~zF bytes
exit /b 0

REM Try to find and rebuild each executable

REM universal_compiler_runtime.exe - try various source names
call :Rebuild "universal_compiler_runtime.exe" "universal_compiler_runtime.asm"
if %ERRORLEVEL% neq 0 (
    call :Rebuild "universal_compiler_runtime.exe" "universal_runtime.asm"
    if %ERRORLEVEL% neq 0 (
        call :Rebuild "universal_compiler_runtime.exe" "runtime.asm"
    )
)
if %ERRORLEVEL% equ 0 (set /a SUCCESS+=1) else (set /a FAILED+=1)

REM bash_compiler_from_scratch.exe
call :Rebuild "bash_compiler_from_scratch.exe" "bash_compiler_from_scratch.asm"
if %ERRORLEVEL% neq 0 (
    call :Rebuild "bash_compiler_from_scratch.exe" "bash_compiler.asm"
)
if %ERRORLEVEL% equ 0 (set /a SUCCESS+=1) else (set /a FAILED+=1)

REM powershell_compiler_from_scratch.exe
call :Rebuild "powershell_compiler_from_scratch.exe" "powershell_compiler_from_scratch.asm"
if %ERRORLEVEL% neq 0 (
    call :Rebuild "powershell_compiler_from_scratch.exe" "powershell_compiler.asm"
)
if %ERRORLEVEL% equ 0 (set /a SUCCESS+=1) else (set /a FAILED+=1)

REM eon_bootstrap_compiler.exe
call :Rebuild "eon_bootstrap_compiler.exe" "eon_bootstrap_compiler.asm"
if %ERRORLEVEL% neq 0 (
    call :Rebuild "eon_bootstrap_compiler.exe" "eon_compiler.asm"
)
if %ERRORLEVEL% equ 0 (set /a SUCCESS+=1) else (set /a FAILED+=1)

REM universal_cross_platform_compiler.exe
call :Rebuild "universal_cross_platform_compiler.exe" "universal_cross_platform_compiler.asm"
if %ERRORLEVEL% neq 0 (
    call :Rebuild "universal_cross_platform_compiler.exe" "universal_compiler.asm"
)
if %ERRORLEVEL% equ 0 (set /a SUCCESS+=1) else (set /a FAILED+=1)

echo.
echo ===============================================================================
echo Rebuild Summary
echo ===============================================================================
echo.
echo Success: %SUCCESS%
echo Failed:  %FAILED%
echo.
echo Output: %OUT_DIR%
echo Logs:   %LOG_DIR%
echo.

if %FAILED% gtr 0 (
    echo Some builds failed. Check logs in %LOG_DIR%
    echo.
    echo Common issues:
    echo   - Source file not found (different name)
    echo   - Assembly syntax errors
    echo   - Missing imports or externs
    echo.
)

pause
