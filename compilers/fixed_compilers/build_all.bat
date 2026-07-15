@echo off
cd /d d:\rawrxd\compilers\fixed_compilers

echo Building fixed compilers...

"C:\Program Files\NASM\nasm.exe" -f win64 eon_compiler_fixed.asm -o eon_compiler_fixed.obj
if %ERRORLEVEL% neq 0 goto :error

"C:\Program Files\NASM\nasm.exe" -f win64 bash_compiler_fixed.asm -o bash_compiler_fixed.obj
if %ERRORLEVEL% neq 0 goto :error

"C:\Program Files\NASM\nasm.exe" -f win64 powershell_compiler_fixed.asm -o powershell_compiler_fixed.obj
if %ERRORLEVEL% neq 0 goto :error

echo Assembly complete. Linking...

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" eon_compiler_fixed.obj /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:eon_compiler_fixed.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
if %ERRORLEVEL% neq 0 goto :error

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" bash_compiler_fixed.obj /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:bash_compiler_fixed.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
if %ERRORLEVEL% neq 0 goto :error

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" powershell_compiler_fixed.obj /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:powershell_compiler_fixed.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
if %ERRORLEVEL% neq 0 goto :error

echo.
echo Build complete! Testing...
echo.

echo === Testing EON Compiler ===
eon_compiler_fixed.exe
if %ERRORLEVEL% neq 0 echo Exit code: %ERRORLEVEL%
echo.

echo === Testing EON Compiler with file ===
eon_compiler_fixed.exe ..\test_corpus\test.eon
if %ERRORLEVEL% neq 0 echo Exit code: %ERRORLEVEL%
echo.

echo === Testing Bash Compiler ===
bash_compiler_fixed.exe
if %ERRORLEVEL% neq 0 echo Exit code: %ERRORLEVEL%
echo.

echo === Testing Bash Compiler with file ===
bash_compiler_fixed.exe ..\test_corpus\test.sh
if %ERRORLEVEL% neq 0 echo Exit code: %ERRORLEVEL%
echo.

echo === Testing PowerShell Compiler ===
powershell_compiler_fixed.exe
if %ERRORLEVEL% neq 0 echo Exit code: %ERRORLEVEL%
echo.

echo === Testing PowerShell Compiler with file ===
powershell_compiler_fixed.exe ..\test_corpus\test.ps1
if %ERRORLEVEL% neq 0 echo Exit code: %ERRORLEVEL%
echo.

echo.
echo All tests complete!
goto :end

:error
echo Build failed!
exit /b 1

:end
