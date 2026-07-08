@echo off
echo ============================================
echo Building All RawrXD Compilers
echo ============================================
echo.

cd /d d:\rawrxd\compilers\fixed_compilers

set NASM="C:\Program Files\NASM\nasm.exe"
set LINK="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set LIBS="C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"

echo [1/8] Building Universal Compiler v2...
%NASM% -f win64 universal_compiler_v2.asm -o universal_compiler_v2.obj
%LINK% universal_compiler_v2.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:universal_compiler_v2.exe %LIBS%

echo [2/8] Building EON Compiler v2...
%NASM% -f win64 eon_compiler_v2.asm -o eon_compiler_v2.obj
%LINK% eon_compiler_v2.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:eon_compiler_v2.exe %LIBS%

echo [3/8] Building Bash Compiler v2...
%NASM% -f win64 bash_compiler_v2.asm -o bash_compiler_v2.obj
%LINK% bash_compiler_v2.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:bash_compiler_v2.exe %LIBS%

echo [4/8] Building PowerShell Compiler v2...
%NASM% -f win64 powershell_compiler_v2.asm -o powershell_compiler_v2.obj
%LINK% powershell_compiler_v2.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:powershell_compiler_v2.exe %LIBS%

echo [5/8] Building Java Compiler...
%NASM% -f win64 java_compiler.asm -o java_compiler.obj
%LINK% java_compiler.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:java_compiler.exe %LIBS%

echo [6/8] Building C# Compiler...
%NASM% -f win64 csharp_compiler.asm -o csharp_compiler.obj
%LINK% csharp_compiler.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:csharp_compiler.exe %LIBS%

echo [7/8] Building Python Compiler...
%NASM% -f win64 python_compiler.asm -o python_compiler.obj
%LINK% python_compiler.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:python_compiler.exe %LIBS%

echo [8/8] Building JavaScript Compiler...
%NASM% -f win64 javascript_compiler.asm -o javascript_compiler.obj
%LINK% javascript_compiler.obj /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:javascript_compiler.exe %LIBS%

echo.
echo ============================================
echo Build Complete
echo ============================================
echo.
dir *.exe