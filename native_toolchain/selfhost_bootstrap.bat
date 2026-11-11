@echo off
REM Self-Hosting Bootstrap Loop
setlocal enabledelayedexpansion

echo ========================================
echo   SELF-HOSTING BOOTSTRAP LOOP
echo ========================================
cd /d d:\rawrxd\native_toolchain

echo [1/6] Building runtime library...
minimal_assembler_v5.exe rawrxd_runtime.asm rawrxd_runtime.obj
if errorlevel 1 (
    echo   Assembly failed
    exit /b 1
)
echo   Runtime object created

echo [2/6] Compiling self-hosting compiler with GCC...
gcc -c -o c_compiler_selfhost.o c_compiler_selfhost.c
if errorlevel 1 (
    echo   GCC compilation failed
    exit /b 1
)
echo   Object file created

echo [3/6] Linking stage1 compiler with MSVC...
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:stage1_cc.exe c_compiler_selfhost.o rawrxd_runtime.lib /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" kernel32.lib
if errorlevel 1 (
    echo   Linking failed
    exit /b 1
)
echo   stage1_cc.exe created

echo [4/6] Testing stage1 compiler...
echo int main() { return 42; } > test_simple.c
stage1_cc.exe test_simple.c
if errorlevel 1 (
    echo   Stage1 execution failed
    exit /b 1
)
echo   Stage1 ran successfully

echo [5/6] Checking test output...
if exist test_simple.exe (
    test_simple.exe
    echo   Exit code: %ERRORLEVEL%
    if "%ERRORLEVEL%"=="42" (
        echo   Stage1 compiler works!
    ) else (
        echo   Stage1 output incorrect
    )
) else (
    echo   No executable generated
)

echo [6/6] Bootstrap complete!
echo.
echo Files created:
dir *.exe 2>nul | findstr /E ".exe"

endlocal
