@echo off
echo === Building Fixed Universal Compiler v3 ===
echo.

cd /d d:\rawrxd\compilers\real_compilers

REM Assemble with NASM
nasm -f win64 universal_compiler_v3_fixed.asm -o universal_compiler_v3_fixed.obj
if errorlevel 1 (
    echo Assembly failed!
    pause
    exit /b 1
)

echo Assembly complete. Linking...

REM Link with proper settings
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" /subsystem:console /entry:main /defaultlib:kernel32.lib universal_compiler_v3_fixed.obj /out:universal_compiler_v3_fixed.exe
if errorlevel 1 (
    echo Link failed!
    pause
    exit /b 1
)

echo.
echo === Build Complete ===
echo.
echo Testing with C file:
universal_compiler_v3_fixed.exe ..\test_corpus\test.c
echo Exit code: %ERRORLEVEL%
echo.
echo Testing with no args:
universal_compiler_v3_fixed.exe
echo Exit code: %ERRORLEVEL%
echo.
echo === Done ===
pause
