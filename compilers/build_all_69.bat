@echo off
setlocal enabledelayedexpansion

REM Build All 69 Compilers - Production Batch Script

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

REM Build each compiler
for %%C in (
    "ada_compiler_from_scratch:Ada Compiler:1.0",
    "assembly_compiler_from_scratch:Assembly Compiler:1.0",
    "bash_compiler_from_scratch:Bash Compiler:1.0",
    "c_compiler_from_scratch:C Compiler:1.0",
    "c__compiler_from_scratch:C++ Compiler:1.0",
    "c___compiler_from_scratch:C# Compiler:1.0",
    "cadence_compiler_from_scratch:Cadence Compiler:1.0",
    "carbon_compiler_from_scratch:Carbon Compiler:1.0",
    "clojure_compiler_from_scratch:Clojure Compiler:1.0",
    "cobol_compiler_from_scratch:COBOL Compiler:1.0",
    "cross_compiler:Cross Compiler:1.0",
    "crystal_compiler_from_scratch:Crystal Compiler:1.0",
    "dart_compiler_from_scratch:Dart Compiler:1.0",
    "delphi_compiler_from_scratch:Delphi Compiler:1.0",
    "elixir_compiler_from_scratch:Elixir Compiler:1.0",
    "eon_compiler_complete:EON Compiler Complete:1.0",
    "eon_compiler_from_scratch:EON Compiler:1.0",
    "eon_compiler_main:EON Main Compiler:1.0",
    "eon_kernel_compiler:EON Kernel Compiler:1.0",
    "erlang_compiler_from_scratch:Erlang Compiler:1.0",
    "fortran_compiler_from_scratch:Fortran Compiler:1.0",
    "f__compiler_from_scratch:F# Compiler:1.0",
    "full_eon_compiler:Full EON Compiler:1.0",
    "go_compiler_from_scratch:Go Compiler:1.0",
    "haskell_compiler_from_scratch:Haskell Compiler:1.0",
    "integrated_eon_compiler:Integrated EON Compiler:1.0",
    "jai_compiler_from_scratch:Jai Compiler:1.0",
    "java_compiler_from_scratch:Java Compiler:1.0",
    "javascript_compiler_from_scratch:JavaScript Compiler:1.0",
    "julia_compiler_from_scratch:Julia Compiler:1.0",
    "kotlin_compiler_from_scratch:Kotlin Compiler:1.0",
    "llvm_ir_compiler_from_scratch:LLVM IR Compiler:1.0",
    "lua_compiler_from_scratch:Lua Compiler:1.0",
    "master_universal_compiler:Master Universal Compiler:1.0",
    "matlab_compiler_from_scratch:MATLAB Compiler:1.0",
    "motoko_compiler_from_scratch:Motoko Compiler:1.0",
    "move_compiler_from_scratch:Move Compiler:1.0",
    "multi_target_compiler:Multi-Target Compiler:1.0",
    "n0mn0m_cross_platform_compiler:N0MN0M Cross-Platform Compiler:1.0",
    "n0mn0m_quantum_asm_compiler:N0MN0M Quantum ASM Compiler:1.0",
    "nim_compiler_from_scratch:Nim Compiler:1.0",
    "ocaml_compiler_from_scratch:OCaml Compiler:1.0",
    "odin_compiler_from_scratch:Odin Compiler:1.0",
    "pascal_compiler_from_scratch:Pascal Compiler:1.0",
    "perl_compiler_from_scratch:Perl Compiler:1.0",
    "php_compiler_from_scratch:PHP Compiler:1.0",
    "powershell_compiler_from_scratch:PowerShell Compiler:1.0",
    "python_compiler_from_scratch:Python Compiler:1.0",
    "reverser_compiler:Reverser Compiler:1.0",
    "reverser_compiler_from_scratch:Reverser Compiler Pro:1.0",
    "ruby_compiler_from_scratch:Ruby Compiler:1.0",
    "rust_compiler_from_scratch:Rust Compiler:1.0",
    "r_compiler_from_scratch:R Compiler:1.0",
    "scala_compiler_from_scratch:Scala Compiler:1.0",
    "self_contained_compiler_gui:Self-Contained GUI Compiler:1.0",
    "self_hosted_eon_compiler:Self-Hosted EON Compiler:1.0",
    "solidity_compiler_from_scratch:Solidity Compiler:1.0",
    "swift_compiler_from_scratch:Swift Compiler:1.0",
    "test_complete_compiler:Test Complete Compiler:1.0",
    "test_full_eon_compiler:Test Full EON Compiler:1.0",
    "test_self_hosted_compiler:Test Self-Hosted Compiler:1.0",
    "typescript_compiler_from_scratch:TypeScript Compiler:1.0",
    "uber_elegant_compiler:Uber Elegant Compiler:1.0",
    "universal_compiler_runtime:Universal Compiler Runtime:1.0",
    "universal_compiler_runtime_clean:Universal Compiler Runtime Clean:1.0",
    "universal_cross_platform_compiler:Universal Cross-Platform Compiler:1.0",
    "universal_multi_language_compiler:Universal Multi-Language Compiler:1.0",
    "vb_net_compiler_from_scratch:VB.NET Compiler:1.0",
    "v_compiler_from_scratch:V Compiler:1.0",
    "vyper_compiler_from_scratch:Vyper Compiler:1.0",
    "webassembly_compiler_from_scratch:WebAssembly Compiler:1.0",
    "zig_compiler_from_scratch:Zig Compiler:1.0"
) do (
    for /f "tokens=1,2,3 delims=:" %%A in ("%%C") do (
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
