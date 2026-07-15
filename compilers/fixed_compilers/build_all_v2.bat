@echo off
cd /d d:\rawrxd\compilers\fixed_compilers

echo === Building All Fixed Compilers ===
echo.

"C:\Program Files\NASM\nasm.exe" -f win64 eon_compiler_v2.asm -o eon_compiler_v2.obj
if %ERRORLEVEL% neq 0 goto :error

"C:\Program Files\NASM\nasm.exe" -f win64 bash_compiler_v2.asm -o bash_compiler_v2.obj
if %ERRORLEVEL% neq 0 goto :error

echo Assembly complete. Linking...

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" eon_compiler_v2.obj /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:eon_compiler_v2.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
if %ERRORLEVEL% neq 0 goto :error

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" bash_compiler_v2.obj /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:bash_compiler_v2.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
if %ERRORLEVEL% neq 0 goto :error

echo.
echo === Build Complete ===
echo.
echo Testing EON Compiler:
eon_compiler_v2.exe
echo Exit code: %ERRORLEVEL%
echo.
eon_compiler_v2.exe ..\test_corpus\test.eon
echo Exit code: %ERRORLEVEL%
echo.
echo Testing Bash Compiler:
bash_compiler_v2.exe
echo Exit code: %ERRORLEVEL%
echo.
bash_compiler_v2.exe ..\test_corpus\test.sh
echo Exit code: %ERRORLEVEL%
echo.
echo === All Tests Complete ===
goto :end

:error
echo Build failed!
exit /b 1

:end
