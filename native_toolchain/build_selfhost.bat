@echo off
REM Build self-hosting toolchain test
setlocal enabledelayedexpansion

echo Building self-hosting toolchain...
cd /d d:\rawrxd\native_toolchain

REM Assemble test
echo [1/3] Assembling test_exit2.asm...
minimal_assembler_v5.exe test_exit2.asm test_exit2.obj
if errorlevel 1 (
    echo ❌ Assembly failed
    exit /b 1
)

REM Link with our linker
echo [2/3] Linking test_exit2.exe...
linker_v4.exe test_exit2.obj test_exit2.exe
if errorlevel 1 (
    echo ❌ Linking failed
    exit /b 1
)

REM Test
echo [3/3] Testing exit code...
test_exit2.exe
echo Exit code: %ERRORLEVEL%

if "%ERRORLEVEL%"=="42" (
    echo ✅ Exit code working!
) else (
    echo ❌ Exit code failed: %ERRORLEVEL%
)

endlocal
