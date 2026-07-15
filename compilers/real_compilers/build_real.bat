@echo off
cd /d d:\rawrxd\compilers\real_compilers

echo === Building Real Universal Compiler ===
echo.

"C:\Program Files\NASM\nasm.exe" -f win64 universal_compiler_real_v2.asm -o universal_compiler_real_v2.obj
if %ERRORLEVEL% neq 0 goto :error

echo Assembly complete. Linking...

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" universal_compiler_real_v2.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:universal_compiler_real.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
if %ERRORLEVEL% neq 0 goto :error

echo.
echo === Build Complete ===
echo.
echo Testing with C file:
universal_compiler_real.exe ..\test_corpus\test.c
echo Exit code: %ERRORLEVEL%
echo.
echo Testing with no args:
universal_compiler_real.exe
echo Exit code: %ERRORLEVEL%
echo.
echo === Done ===
goto :end

:error
echo Build failed!
exit /b 1

:end
