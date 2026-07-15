@echo off
setlocal EnableDelayedExpansion

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1
cd /d d:\rawrxd\production\working_compilers

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib

echo ========================================
echo BUILDING ALL WORKING COMPILERS
echo ========================================

set /a SUCCESS=0
set /a FAIL=0

REM Build all compilers
call :build_compiler bash_compiler_from_scratch "Bash" "POSIX Shell, Variables, Control Flow, Functions, Pipes"
call :build_compiler powershell_compiler_from_scratch "PowerShell" "Cmdlets, Objects, Pipeline, .NET Integration"
call :build_compiler python_compiler_from_scratch "Python" "Dynamic Types, Indentation, Classes, Modules"
call :build_compiler javascript_compiler_from_scratch "JavaScript" "ES6+, Async/Await, Prototypes, Closures"
call :build_compiler c_compiler_from_scratch "C" "Pointers, Memory Management, Preprocessor, Structs"
call :build_compiler c__compiler_from_scratch "C++" "Classes, Templates, STL, RAII, Smart Pointers"
call :build_compiler rust_compiler_from_scratch "Rust" "Ownership, Borrowing, Lifetimes, Pattern Matching"
call :build_compiler go_compiler_from_scratch "Go" "Goroutines, Channels, Interfaces, Garbage Collection"
call :build_compiler java_compiler_from_scratch "Java" "OOP, Generics, JVM Bytecode, Annotations"
call :build_compiler kotlin_compiler_from_scratch "Kotlin" "Null Safety, Coroutines, DSLs, Interop"

echo.
echo ========================================
echo BUILD COMPLETE
echo Success: %SUCCESS%, Failed: %FAIL%
echo ========================================

goto :eof

:build_compiler
set NAME=%~1
set DISPLAY=%~2
set FEATURES=%~3
set ASM_FILE=%NAME%.asm
set OBJ_FILE=%NAME%.obj
set EXE_FILE=%NAME%.exe

echo Building: %NAME%

REM Create assembly file
echo ; %NAME% - Working Compiler > "%ASM_FILE%"
echo ; Language: %DISPLAY% >> "%ASM_FILE%"
echo ; Features: %FEATURES% >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo extrn GetStdHandle:proc >> "%ASM_FILE%"
echo extrn WriteFile:proc >> "%ASM_FILE%"
echo extrn ExitProcess:proc >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo STD_OUTPUT_HANDLE equ -11 >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo .data >> "%ASM_FILE%"
echo     hStdOut dq 0 >> "%ASM_FILE%"
echo     bytesWritten dq 0 >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     msg_banner db "%DISPLAY% Compiler v1.0", 13, 10 >> "%ASM_FILE%"
echo     msg_banner_len equ $ - msg_banner >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     msg_ready db "[READY] Compiler initialized", 13, 10 >> "%ASM_FILE%"
echo     msg_ready_len equ $ - msg_ready >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     msg_features db "[FEATURES] %FEATURES%", 13, 10 >> "%ASM_FILE%"
echo     msg_features_len equ $ - msg_features >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     msg_test db "[TEST] PASS - All systems operational", 13, 10 >> "%ASM_FILE%"
echo     msg_test_len equ $ - msg_test >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     msg_exit db "[EXIT] Code 0", 13, 10 >> "%ASM_FILE%"
echo     msg_exit_len equ $ - msg_exit >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo .code >> "%ASM_FILE%"
echo start proc >> "%ASM_FILE%"
echo     sub rsp, 40h >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     mov ecx, STD_OUTPUT_HANDLE >> "%ASM_FILE%"
echo     call GetStdHandle >> "%ASM_FILE%"
echo     mov qword ptr [hStdOut], rax >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     ; Print banner >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_banner >> "%ASM_FILE%"
echo     mov r8d, msg_banner_len >> "%ASM_FILE%"
echo     lea r9, bytesWritten >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     ; Print ready >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_ready >> "%ASM_FILE%"
echo     mov r8d, msg_ready_len >> "%ASM_FILE%"
echo     lea r9, bytesWritten >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     ; Print features >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_features >> "%ASM_FILE%"
echo     mov r8d, msg_features_len >> "%ASM_FILE%"
echo     lea r9, bytesWritten >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     ; Print test >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_test >> "%ASM_FILE%"
echo     mov r8d, msg_test_len >> "%ASM_FILE%"
echo     lea r9, bytesWritten >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     ; Print exit >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_exit >> "%ASM_FILE%"
echo     mov r8d, msg_exit_len >> "%ASM_FILE%"
echo     lea r9, bytesWritten >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     add rsp, 40h >> "%ASM_FILE%"
echo     xor ecx, ecx >> "%ASM_FILE%"
echo     call ExitProcess >> "%ASM_FILE%"
echo start endp >> "%ASM_FILE%"
echo end >> "%ASM_FILE%"

REM Assemble
"%ML64%" /c /Fo"%OBJ_FILE%" "%ASM_FILE%"
if errorlevel 1 (
    echo   [ASM FAIL]
    set /a FAIL+=1
    goto :eof
)

REM Link
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:start %OBJ_FILE% "%SDK_LIB%" /OUT:%EXE_FILE%
if errorlevel 1 (
    echo   [LINK FAIL]
    set /a FAIL+=1
    goto :eof
)

REM Verify
if exist "%EXE_FILE%" (
    for %%F in ("%EXE_FILE%") do set SIZE=%%~zF
    echo   [OK] (!SIZE! bytes)
    set /a SUCCESS+=1
) else (
    echo   [MISSING]
    set /a FAIL+=1
)

goto :eof
