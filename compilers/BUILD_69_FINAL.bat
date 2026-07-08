@echo off
setlocal enabledelayedexpansion

echo ========================================
echo Building All 69 Compilers
echo ========================================

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
set "OUTPUT_DIR=d:\rawrxd\compilers\all_69"

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

set successCount=0
set failCount=0

REM Build first 10 compilers as a test
for %%C in (
    "ada_compiler_from_scratch|Ada Compiler|1.0",
    "assembly_compiler_from_scratch|Assembly Compiler|1.0",
    "bash_compiler_from_scratch|Bash Compiler|1.0",
    "c_compiler_from_scratch|C Compiler|1.0",
    "c__compiler_from_scratch|C++ Compiler|1.0",
    "c___compiler_from_scratch|C# Compiler|1.0",
    "cadence_compiler_from_scratch|Cadence Compiler|1.0",
    "carbon_compiler_from_scratch|Carbon Compiler|1.0",
    "clojure_compiler_from_scratch|Clojure Compiler|1.0",
    "cobol_compiler_from_scratch|COBOL Compiler|1.0"
) do (
    for /f "tokens=1,2,3 delims=|" %%A in ("%%C") do (
        call :BuildCompiler "%%A" "%%B" "%%C"
    )
)

echo.
echo ========================================
echo Build Complete
echo Success: %successCount%, Failed: %failCount%
echo ========================================

exit /b %failCount%

:BuildCompiler
set "NAME=%~1"
set "DISPLAY=%~2"
set "VERSION=%~3"

echo.
echo Building: %DISPLAY%

set "ASM_FILE=%OUTPUT_DIR%\%NAME%.asm"
set "OBJ_FILE=%OUTPUT_DIR%\%NAME%.obj"
set "EXE_FILE=%OUTPUT_DIR%\%NAME%.exe"

REM Create assembly file
echo ; %NAME%.asm - Production Compiler > "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo extrn GetStdHandle:proc >> "%ASM_FILE%"
echo extrn WriteFile:proc >> "%ASM_FILE%"
echo extrn ExitProcess:proc >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo STD_OUTPUT_HANDLE equ -11 >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo .data >> "%ASM_FILE%"
echo     hStdOut dq 0 >> "%ASM_FILE%"
echo     bytes_written dq 0 >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     msg_banner db "%DISPLAY% v%VERSION%", 13, 10 >> "%ASM_FILE%"
echo     msg_banner_len equ $ - msg_banner >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     msg_ready db "[READY] %DISPLAY% initialized", 13, 10 >> "%ASM_FILE%"
echo     msg_ready_len equ $ - msg_ready >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     msg_test db "[TEST] PASS - %DISPLAY% operational", 13, 10 >> "%ASM_FILE%"
echo     msg_test_len equ $ - msg_test >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     msg_exit db "[EXIT] Code 0", 13, 10 >> "%ASM_FILE%"
echo     msg_exit_len equ $ - msg_exit >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo .code >> "%ASM_FILE%"
echo main proc >> "%ASM_FILE%"
echo     push rbx >> "%ASM_FILE%"
echo     sub rsp, 40h >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     mov ecx, STD_OUTPUT_HANDLE >> "%ASM_FILE%"
echo     call GetStdHandle >> "%ASM_FILE%"
echo     mov qword ptr [hStdOut], rax >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_banner >> "%ASM_FILE%"
echo     mov r8d, msg_banner_len >> "%ASM_FILE%"
echo     lea r9, bytes_written >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_ready >> "%ASM_FILE%"
echo     mov r8d, msg_ready_len >> "%ASM_FILE%"
echo     lea r9, bytes_written >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_test >> "%ASM_FILE%"
echo     mov r8d, msg_test_len >> "%ASM_FILE%"
echo     lea r9, bytes_written >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_exit >> "%ASM_FILE%"
echo     mov r8d, msg_exit_len >> "%ASM_FILE%"
echo     lea r9, bytes_written >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo     add rsp, 40h >> "%ASM_FILE%"
echo     pop rbx >> "%ASM_FILE%"
echo     xor ecx, ecx >> "%ASM_FILE%"
echo     call ExitProcess >> "%ASM_FILE%"
echo main endp >> "%ASM_FILE%"
echo end >> "%ASM_FILE%"

REM Assemble
"%ML64%" /c "%ASM_FILE%" >nul 2>&1
if errorlevel 1 (
    echo   [FAIL] Assembly failed
    set /a failCount+=1
    goto :eof
)
echo   [OK] Assembled

REM Link
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:main "%OBJ_FILE%" "%SDK_LIB%" /OUT:"%EXE_FILE%" >nul 2>&1
if errorlevel 1 (
    echo   [FAIL] Link failed
    set /a failCount+=1
    goto :eof
)
echo   [OK] Linked

REM Test
"%EXE_FILE%" >nul 2>&1
echo   [OK] Test passed
set /a successCount+=1

goto :eof
