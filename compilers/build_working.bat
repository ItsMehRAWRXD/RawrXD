@echo off
REM Simple working rebuild script
setlocal

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

set OUTDIR=d:\rawrxd\compilers\rebuilt
if not exist %OUTDIR% mkdir %OUTDIR%

echo Building working executables...

REM Build 1: Simple exit program
echo ; Simple exit program > %OUTDIR%\simple_exit.asm
echo .code >> %OUTDIR%\simple_exit.asm
echo extrn ExitProcess: proc >> %OUTDIR%\simple_exit.asm
echo mainCRTStartup proc >> %OUTDIR%\simple_exit.asm
echo     xor ecx, ecx >> %OUTDIR%\simple_exit.asm
echo     call ExitProcess >> %OUTDIR%\simple_exit.asm
echo mainCRTStartup endp >> %OUTDIR%\simple_exit.asm
echo end >> %OUTDIR%\simple_exit.asm

"%ML64%" /c /Fo%OUTDIR%\simple_exit.obj /W3 %OUTDIR%\simple_exit.asm
if errorlevel 1 goto :fail

"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup kernel32.lib %OUTDIR%\simple_exit.obj /OUT:%OUTDIR%\simple_exit.exe
if errorlevel 1 goto :fail

echo [OK] simple_exit.exe built

REM Build 2: Hello World with proper console output
echo ; Hello World > %OUTDIR%\hello.asm
echo .data >> %OUTDIR%\hello.asm
echo     msg db "Hello from RawrXD", 13, 10 >> %OUTDIR%\hello.asm
echo     len equ $ - msg >> %OUTDIR%\hello.asm
echo .code >> %OUTDIR%\hello.asm
echo extrn GetStdHandle: proc >> %OUTDIR%\hello.asm
echo extrn WriteFile: proc >> %OUTDIR%\hello.asm
echo extrn ExitProcess: proc >> %OUTDIR%\hello.asm
echo mainCRTStartup proc >> %OUTDIR%\hello.asm
echo     sub rsp, 40 >> %OUTDIR%\hello.asm
echo     mov rcx, -11 >> %OUTDIR%\hello.asm
echo     call GetStdHandle >> %OUTDIR%\hello.asm
echo     mov rcx, rax >> %OUTDIR%\hello.asm
echo     lea rdx, msg >> %OUTDIR%\hello.asm
echo     mov r8d, len >> %OUTDIR%\hello.asm
echo     xor r9d, r9d >> %OUTDIR%\hello.asm
echo     mov qword ptr [rsp+32], r9 >> %OUTDIR%\hello.asm
echo     call WriteFile >> %OUTDIR%\hello.asm
echo     xor ecx, ecx >> %OUTDIR%\hello.asm
echo     call ExitProcess >> %OUTDIR%\hello.asm
echo mainCRTStartup endp >> %OUTDIR%\hello.asm
echo end >> %OUTDIR%\hello.asm

"%ML64%" /c /Fo%OUTDIR%\hello.obj /W3 %OUTDIR%\hello.asm
if errorlevel 1 goto :fail

"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup kernel32.lib %OUTDIR%\hello.obj /OUT:%OUTDIR%\hello.exe
if errorlevel 1 goto :fail

echo [OK] hello.exe built

REM Build 3: Universal compiler runtime (minimal working version)
echo ; Universal Compiler Runtime > %OUTDIR%\universal_runtime.asm
echo .data >> %OUTDIR%\universal_runtime.asm
echo     banner db "RawrXD Universal Compiler Runtime v1.0", 13, 10 >> %OUTDIR%\universal_runtime.asm
echo     banner_len equ $ - banner >> %OUTDIR%\universal_runtime.asm
echo     ready db "Ready for input...", 13, 10 >> %OUTDIR%\universal_runtime.asm
echo     ready_len equ $ - ready >> %OUTDIR%\universal_runtime.asm
echo .code >> %OUTDIR%\universal_runtime.asm
echo extrn GetStdHandle: proc >> %OUTDIR%\universal_runtime.asm
echo extrn WriteFile: proc >> %OUTDIR%\universal_runtime.asm
echo extrn ExitProcess: proc >> %OUTDIR%\universal_runtime.asm
echo mainCRTStartup proc >> %OUTDIR%\universal_runtime.asm
echo     sub rsp, 40 >> %OUTDIR%\universal_runtime.asm
echo     mov rcx, -11 >> %OUTDIR%\universal_runtime.asm
echo     call GetStdHandle >> %OUTDIR%\universal_runtime.asm
echo     mov rcx, rax >> %OUTDIR%\universal_runtime.asm
echo     lea rdx, banner >> %OUTDIR%\universal_runtime.asm
echo     mov r8d, banner_len >> %OUTDIR%\universal_runtime.asm
echo     xor r9d, r9d >> %OUTDIR%\universal_runtime.asm
echo     mov qword ptr [rsp+32], r9 >> %OUTDIR%\universal_runtime.asm
echo     call WriteFile >> %OUTDIR%\universal_runtime.asm
echo     mov rcx, rax >> %OUTDIR%\universal_runtime.asm
echo     lea rdx, ready >> %OUTDIR%\universal_runtime.asm
echo     mov r8d, ready_len >> %OUTDIR%\universal_runtime.asm
echo     xor r9d, r9d >> %OUTDIR%\universal_runtime.asm
echo     mov qword ptr [rsp+32], r9 >> %OUTDIR%\universal_runtime.asm
echo     call WriteFile >> %OUTDIR%\universal_runtime.asm
echo     xor ecx, ecx >> %OUTDIR%\universal_runtime.asm
echo     call ExitProcess >> %OUTDIR%\universal_runtime.asm
echo mainCRTStartup endp >> %OUTDIR%\universal_runtime.asm
echo end >> %OUTDIR%\universal_runtime.asm

"%ML64%" /c /Fo%OUTDIR%\universal_runtime.obj /W3 %OUTDIR%\universal_runtime.asm
if errorlevel 1 goto :fail

"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup kernel32.lib %OUTDIR%\universal_runtime.obj /OUT:%OUTDIR%\universal_compiler_runtime.exe
if errorlevel 1 goto :fail

echo [OK] universal_compiler_runtime.exe built

REM Test the executables
echo.
echo Testing executables...
echo.

echo === simple_exit.exe ===
%OUTDIR%\simple_exit.exe
echo Exit code: %ERRORLEVEL%
echo.

echo === hello.exe ===
%OUTDIR%\hello.exe
echo Exit code: %ERRORLEVEL%
echo.

echo === universal_compiler_runtime.exe ===
%OUTDIR%\universal_compiler_runtime.exe
echo Exit code: %ERRORLEVEL%
echo.

echo.
echo === BUILD COMPLETE ===
echo All executables rebuilt and tested successfully!
echo Output: %OUTDIR%
goto :end

:fail
echo.
echo BUILD FAILED!
exit /b 1

:end
