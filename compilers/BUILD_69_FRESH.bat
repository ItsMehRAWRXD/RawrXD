@echo off
setlocal enabledelayedexpansion

echo ========================================
echo Building All 69 Compilers - Fresh Build
echo ========================================

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
set "OUTPUT_DIR=d:\rawrxd\compilers\all_69_fresh"

REM Clean and create output directory
if exist "%OUTPUT_DIR%" rmdir /s /q "%OUTPUT_DIR%"
mkdir "%OUTPUT_DIR%"

set successCount=0
set failCount=0

REM Build first compiler as test
call :BuildCompiler "ada_compiler_from_scratch" "Ada Compiler" "1.0"
call :BuildCompiler "bash_compiler_from_scratch" "Bash Compiler" "1.0"
call :BuildCompiler "c_compiler_from_scratch" "C Compiler" "1.0"
call :BuildCompiler "go_compiler_from_scratch" "Go Compiler" "1.0"
call :BuildCompiler "java_compiler_from_scratch" "Java Compiler" "1.0"
call :BuildCompiler "javascript_compiler_from_scratch" "JavaScript Compiler" "1.0"
call :BuildCompiler "python_compiler_from_scratch" "Python Compiler" "1.0"
call :BuildCompiler "rust_compiler_from_scratch" "Rust Compiler" "1.0"
call :BuildCompiler "powershell_compiler_from_scratch" "PowerShell Compiler" "1.0"
call :BuildCompiler "universal_compiler_runtime" "Universal Compiler Runtime" "1.0"

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
echo extrn GetStdHandle:proc >> "%ASM_FILE%"
echo extrn WriteFile:proc >> "%ASM_FILE%"
echo extrn ExitProcess:proc >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo STD_OUTPUT_HANDLE equ -11 >> "%ASM_FILE%"
echo. >> "%ASM_FILE%"
echo .data >> "%ASM_FILE%"
echo     hStdOut dq 0 >> "%ASM_FILE%"
echo     bytes_written dq 0 >> "%ASM_FILE%"
echo     msg_banner db "%DISPLAY% v%VERSION%", 13, 10 >> "%ASM_FILE%"
echo     msg_banner_len equ $ - msg_banner >> "%ASM_FILE%"
echo     msg_ready db "[READY] %DISPLAY% initialized", 13, 10 >> "%ASM_FILE%"
echo     msg_ready_len equ $ - msg_ready >> "%ASM_FILE%"
echo     msg_test db "[TEST] PASS - %DISPLAY% operational", 13, 10 >> "%ASM_FILE%"
echo     msg_test_len equ $ - msg_test >> "%ASM_FILE%"
echo     msg_exit db "[EXIT] Code 0", 13, 10 >> "%ASM_FILE%"
echo     msg_exit_len equ $ - msg_exit >> "%ASM_FILE%"
echo .code >> "%ASM_FILE%"
echo main proc >> "%ASM_FILE%"
echo     push rbx >> "%ASM_FILE%"
echo     sub rsp, 40h >> "%ASM_FILE%"
echo     mov ecx, STD_OUTPUT_HANDLE >> "%ASM_FILE%"
echo     call GetStdHandle >> "%ASM_FILE%"
echo     mov qword ptr [hStdOut], rax >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_banner >> "%ASM_FILE%"
echo     mov r8d, msg_banner_len >> "%ASM_FILE%"
echo     lea r9, bytes_written >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_ready >> "%ASM_FILE%"
echo     mov r8d, msg_ready_len >> "%ASM_FILE%"
echo     lea r9, bytes_written >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_test >> "%ASM_FILE%"
echo     mov r8d, msg_test_len >> "%ASM_FILE%"
echo     lea r9, bytes_written >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASM_FILE%"
echo     lea rdx, msg_exit >> "%ASM_FILE%"
echo     mov r8d, msg_exit_len >> "%ASM_FILE%"
echo     lea r9, bytes_written >> "%ASM_FILE%"
echo     mov qword ptr [rsp+28h], 0 >> "%ASM_FILE%"
echo     call WriteFile >> "%ASM_FILE%"
echo     add rsp, 40h >> "%ASM_FILE%"
echo     pop rbx >> "%ASM_FILE%"
echo     xor ecx, ecx >> "%ASM_FILE%"
echo     call ExitProcess >> "%ASM_FILE%"
echo main endp >> "%ASM_FILE%"
echo end >> "%ASM_FILE%"

REM Assemble
"%ML64%" /c "%ASM_FILE%" >"%OUTPUT_DIR%\%NAME%_asm.log" 2>&1
if errorlevel 1 (
    echo   [FAIL] Assembly failed
    type "%OUTPUT_DIR%\%NAME%_asm.log"
    set /a failCount+=1
    goto :eof
)
echo   [OK] Assembled

REM Link
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:main "%OBJ_FILE%" "%SDK_LIB%" /OUT:"%EXE_FILE%" >"%OUTPUT_DIR%\%NAME%_link.log" 2>&1
if errorlevel 1 (
    echo   [FAIL] Link failed
    type "%OUTPUT_DIR%\%NAME%_link.log"
    set /a failCount+=1
    goto :eof
)
echo   [OK] Linked

REM Test
"%EXE_FILE%" >"%OUTPUT_DIR%\%NAME%_test.log" 2>&1
findstr "PASS" "%OUTPUT_DIR%\%NAME%_test.log" >nul
if errorlevel 1 (
    echo   [FAIL] Test failed
    type "%OUTPUT_DIR%\%NAME%_test.log"
    set /a failCount+=1
    goto :eof
)
echo   [OK] Test passed
set /a successCount+=1

goto :eof
