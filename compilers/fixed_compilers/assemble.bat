@echo off
cd /d d:\rawrxd\compilers\fixed_compilers
"C:\Program Files\NASM\nasm.exe" -f win64 universal_compiler_fixed.asm -o universal_compiler_fixed.obj
if %ERRORLEVEL% neq 0 (
    echo Assembly failed
    exit /b 1
)
echo Assembly successful
