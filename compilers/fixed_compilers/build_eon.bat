@echo off
echo Building EON Compiler...
"C:\Program Files\NASM\nasm.exe" -f win64 eon_compiler_v2.asm -o eon_compiler_v2.obj
if %ERRORLEVEL% neq 0 goto :error

echo Linking...
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" eon_compiler_v2.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:eon_compiler_v2.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
if %ERRORLEVEL% neq 0 goto :error

echo Build complete!
dir eon_compiler_v2.exe
goto :end

:error
echo Build failed!
exit /b 1

:end