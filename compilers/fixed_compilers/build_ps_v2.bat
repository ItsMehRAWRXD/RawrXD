@echo off
cd /d d:\rawrxd\compilers\fixed_compilers

echo === Building PowerShell Compiler ===
echo.

"C:\Program Files\NASM\nasm.exe" -f win64 powershell_compiler_v2.asm -o powershell_compiler_v2.obj
if %ERRORLEVEL% neq 0 goto :error

echo Assembly complete. Linking...

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe" powershell_compiler_v2.obj /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:powershell_compiler_v2.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
if %ERRORLEVEL% neq 0 goto :error

echo.
echo === Build Complete ===
echo.
echo Testing PowerShell Compiler:
powershell_compiler_v2.exe
echo Exit code: %ERRORLEVEL%
echo.
powershell_compiler_v2.exe ..\test_corpus\test.ps1
echo Exit code: %ERRORLEVEL%
echo.
echo === Test Complete ===
goto :end

:error
echo Build failed!
exit /b 1

:end
