@echo off
echo Building C# Compiler...
"C:\Program Files\NASM\nasm.exe" -f win64 csharp_compiler.asm -o csharp_compiler.obj
if %ERRORLEVEL% neq 0 goto :error

echo Linking...
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" csharp_compiler.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:csharp_compiler.exe "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
if %ERRORLEVEL% neq 0 goto :error

echo Build complete!
dir csharp_compiler.exe
goto :end

:error
echo Build failed!
exit /b 1

:end