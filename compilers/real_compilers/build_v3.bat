@echo off
cd /d d:\rawrxd\compilers\real_compilers

echo === Building Real Universal Compiler v3 ===
echo.

if exist universal_compiler_v3.exe del universal_compiler_v3.exe 2>nul
if exist universal_compiler_v3_new.exe del universal_compiler_v3_new.exe 2>nul

"C:\Program Files\NASM\nasm.exe" -f win64 universal_compiler_v3.asm -o universal_compiler_v3.obj
if %ERRORLEVEL% neq 0 goto :error

echo Assembly complete. Linking...

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" universal_compiler_v3.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:universal_compiler_v3_new.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
if %ERRORLEVEL% neq 0 goto :error

ren universal_compiler_v3_new.exe universal_compiler_v3.exe

echo.
echo === Build Complete ===
echo.
echo Testing with C file:
universal_compiler_v3.exe ..\test_corpus\test.c
echo Exit code: %ERRORLEVEL%
echo.
echo === Done ===
goto :end

:error
echo Build failed!
exit /b 1

:end
