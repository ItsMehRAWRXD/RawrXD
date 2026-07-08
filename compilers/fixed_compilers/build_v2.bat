@echo off
cd /d d:\rawrxd\compilers\fixed_compilers

echo === Building Fixed Compilers ===
echo.

"C:\Program Files\NASM\nasm.exe" -f win64 universal_compiler_v2.asm -o universal_compiler_v2.obj
if %ERRORLEVEL% neq 0 (
    echo NASM assembly failed
    exit /b 1
)

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" universal_compiler_v2.obj /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:universal_compiler_v2.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
if %ERRORLEVEL% neq 0 (
    echo Link failed
    exit /b 1
)

echo Build successful!
echo.
echo === Testing ===
echo.
echo Test 1: No arguments
dir universal_compiler_v2.exe
echo.
echo Test 2: Run executable
universal_compiler_v2.exe
echo Exit code: %ERRORLEVEL%
echo.
echo Test 3: With file argument
universal_compiler_v2.exe ..\test_corpus\test.c
echo Exit code: %ERRORLEVEL%
echo.
echo === Done ===
