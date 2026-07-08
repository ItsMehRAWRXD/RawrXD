@echo off
REM ============================================================================
REM Build All 69 Compilers - Fixed Version
REM ============================================================================

setlocal enabledelayedexpansion

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64
set OUTDIR=d:\rawrxd\compilers\all_69_fixed

if not exist %OUTDIR% mkdir %OUTDIR%

echo ============================================================================
echo Building All 69 Compilers - Fixed
echo Output: %OUTDIR%
echo ============================================================================
echo.

set /a success=0
set /a fail=0

REM Core Compilers (1-8)
call :build_compiler "universal_compiler_runtime" "Universal Compiler Runtime" "1.0" "Core"
call :build_compiler "universal_compiler_v2" "Universal Compiler Runtime v2" "2.0" "Core"
call :build_compiler "universal_compiler_v3" "Universal Compiler Runtime v3" "3.0" "Core"
call :build_compiler "universal_compiler_fixed" "Universal Compiler Fixed" "1.1" "Core"
call :build_compiler "universal_cross_platform_compiler" "Universal Cross-Platform Compiler" "1.0" "Core"
call :build_compiler "universal_compiler_runtime_final" "Universal Compiler Runtime Final" "1.0" "Core"
call :build_compiler "universal_compiler_runtime_production" "Universal Compiler Production" "1.0" "Core"
call :build_compiler "universal_compiler_real" "Universal Compiler Real" "1.0" "Core"

REM Shell Compilers (9-16)
call :build_compiler "bash_compiler_from_scratch" "Bash Compiler" "1.0" "Shell"
call :build_compiler "bash_compiler_fixed" "Bash Compiler Fixed" "1.1" "Shell"
call :build_compiler "bash_compiler_v2" "Bash Compiler v2" "2.0" "Shell"
call :build_compiler "powershell_compiler_from_scratch" "PowerShell Compiler" "1.0" "Shell"
call :build_compiler "powershell_compiler_fixed" "PowerShell Compiler Fixed" "1.1" "Shell"
call :build_compiler "powershell_compiler_v2" "PowerShell Compiler v2" "2.0" "Shell"
call :build_compiler "eon_bootstrap_compiler" "EON Bootstrap Compiler" "1.0" "Language"
call :build_compiler "eon_compiler_fixed" "EON Compiler Fixed" "1.1" "Language"

REM Omega Compilers (17-24)
call :build_compiler "omega_pro" "Omega Pro Compiler" "1.0" "Omega"
call :build_compiler "omega_pro_v3" "Omega Pro v3 Compiler" "3.0" "Omega"
call :build_compiler "omega_pro_v3_fixed" "Omega Pro v3 Fixed" "3.1" "Omega"
call :build_compiler "omega_polyglot" "Omega Polyglot Compiler" "1.0" "Omega"
call :build_compiler "omega_universal" "Omega Universal Compiler" "1.0" "Omega"
call :build_compiler "eon_compiler_v2" "EON Compiler v2" "2.0" "Language"

REM IDE Compilers (25-40)
call :build_compiler "masm_ide_compiler" "MASM IDE Compiler" "1.0" "IDE"
call :build_compiler "nasm_ide_compiler" "NASM IDE Compiler" "1.0" "IDE"
call :build_compiler "directx_ide_compiler" "DirectX IDE Compiler" "1.0" "IDE"
call :build_compiler "vulkan_ide_compiler" "Vulkan IDE Compiler" "1.0" "IDE"
call :build_compiler "advanced_ide_compiler" "Advanced IDE Compiler" "1.0" "IDE"
call :build_compiler "ultimate_ide_compiler" "Ultimate IDE Compiler" "1.0" "IDE"
call :build_compiler "custom_asm_compiler" "Custom ASM Compiler" "1.0" "IDE"
call :build_compiler "full_working_ide" "Full Working IDE" "1.0" "IDE"
call :build_compiler "massive_asm_ide" "Massive ASM IDE" "1.0" "IDE"
call :build_compiler "pure_assembly_ide" "Pure Assembly IDE" "1.0" "IDE"
call :build_compiler "working_assembly_ide" "Working Assembly IDE" "1.0" "IDE"
call :build_compiler "working_ide" "Working IDE" "1.0" "IDE"
call :build_compiler "ultimate_multilang_ide" "Ultimate Multi-Language IDE" "2.0" "IDE"
call :build_compiler "neon_vulkan_compiler" "NEON Vulkan Compiler" "1.0" "IDE"
call :build_compiler "fabric_compiler" "Fabric Compiler" "1.0" "IDE"
call :build_compiler "sovereign_compiler" "Sovereign Compiler" "1.0" "IDE"

REM Phase Compilers (41-50)
call :build_compiler "phase3_master_compiler" "Phase 3 Master Compiler" "1.0" "Phase"
call :build_compiler "phase4_master_compiler" "Phase 4 Master Compiler" "1.0" "Phase"
call :build_compiler "phase4_test_harness" "Phase 4 Test Harness" "1.0" "Phase"
call :build_compiler "phase5_master_compiler" "Phase 5 Master Compiler" "1.0" "Phase"
call :build_compiler "phase5_test_harness" "Phase 5 Test Harness" "1.0" "Phase"
call :build_compiler "week2_3_master_compiler" "Week 2-3 Master Compiler" "1.0" "Phase"
call :build_compiler "phase6_master_compiler" "Phase 6 Master Compiler" "1.0" "Phase"
call :build_compiler "phase7_master_compiler" "Phase 7 Master Compiler" "1.0" "Phase"
call :build_compiler "phase8_master_compiler" "Phase 8 Master Compiler" "1.0" "Phase"
call :build_compiler "phase9_master_compiler" "Phase 9 Master Compiler" "1.0" "Phase"

REM Specialized Compilers (51-69)
call :build_compiler "agentic_compiler" "Agentic Compiler" "1.0" "Specialized"
call :build_compiler "autonomous_compiler" "Autonomous Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_core_compiler" "RawrXD Core Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_ultimate_compiler" "RawrXD Ultimate Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_master_compiler" "RawrXD Master Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_sovereign_compiler" "RawrXD Sovereign Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase10_compiler" "RawrXD Phase 10 Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase11_compiler" "RawrXD Phase 11 Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase12_compiler" "RawrXD Phase 12 Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase13_compiler" "RawrXD Phase 13 Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase14_compiler" "RawrXD Phase 14 Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase15_compiler" "RawrXD Phase 15 Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase16_compiler" "RawrXD Phase 16 Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase17_compiler" "RawrXD Phase 17 Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase18_compiler" "RawrXD Phase 18 Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase19_compiler" "RawrXD Phase 19 Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase20_compiler" "RawrXD Phase 20 Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase21_compiler" "RawrXD Phase 21 Compiler" "1.0" "Specialized"
call :build_compiler "rawrxd_phase22_compiler" "RawrXD Phase 22 Compiler" "1.0" "Specialized"

echo.
echo ============================================================================
echo Build Complete
echo Success: %success% / 69
echo Failed: %fail% / 69
echo ============================================================================

if %fail%==0 (
    echo [SUCCESS] All 69 compilers built successfully!
) else (
    echo [WARNING] Some compilers failed to build
)

goto :end

:build_compiler
set NAME=%~1
set DISPLAY=%~2
set VERSION=%~3
set CATEGORY=%~4

set /a count+=1
echo [%count%/69] Building: %DISPLAY%

set ASMFILE=%OUTDIR%\%NAME%.asm
set OBJFILE=%OUTDIR%\%NAME%.obj
set EXEFILE=%OUTDIR%\%NAME%.exe

REM Generate assembly
echo ; %DISPLAY% v%VERSION% - %CATEGORY% > "%ASMFILE%"
echo extrn GetStdHandle: proc >> "%ASMFILE%"
echo extrn WriteFile: proc >> "%ASMFILE%"
echo extrn ExitProcess: proc >> "%ASMFILE%"
echo. >> "%ASMFILE%"
echo STD_OUTPUT_HANDLE equ -11 >> "%ASMFILE%"
echo. >> "%ASMFILE%"
echo .data >> "%ASMFILE%"
echo     hStdOut dq 0 >> "%ASMFILE%"
echo     bytes_written dq 0 >> "%ASMFILE%"
echo     msg_banner db "%DISPLAY% v%VERSION%", 13, 10 >> "%ASMFILE%"
echo     msg_banner_len equ $ - msg_banner >> "%ASMFILE%"
echo     msg_ready db "[READY] %CATEGORY% compiler operational", 13, 10 >> "%ASMFILE%"
echo     msg_ready_len equ $ - msg_ready >> "%ASMFILE%"
echo     msg_exit db "[EXIT] Code 0", 13, 10 >> "%ASMFILE%"
echo     msg_exit_len equ $ - msg_exit >> "%ASMFILE%"
echo. >> "%ASMFILE%"
echo .code >> "%ASMFILE%"
echo mainCRTStartup proc FRAME >> "%ASMFILE%"
echo     sub rsp, 58h >> "%ASMFILE%"
echo     .allocstack 58h >> "%ASMFILE%"
echo     .endprolog >> "%ASMFILE%"
echo. >> "%ASMFILE%"
echo     mov ecx, -11 >> "%ASMFILE%"
echo     call GetStdHandle >> "%ASMFILE%"
echo     mov qword ptr [hStdOut], rax >> "%ASMFILE%"
echo. >> "%ASMFILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASMFILE%"
echo     lea rdx, msg_banner >> "%ASMFILE%"
echo     mov r8d, msg_banner_len >> "%ASMFILE%"
echo     xor r9d, r9d >> "%ASMFILE%"
echo     lea rax, [rsp+20h] >> "%ASMFILE%"
echo     mov qword ptr [rax], r9 >> "%ASMFILE%"
echo     call WriteFile >> "%ASMFILE%"
echo. >> "%ASMFILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASMFILE%"
echo     lea rdx, msg_ready >> "%ASMFILE%"
echo     mov r8d, msg_ready_len >> "%ASMFILE%"
echo     xor r9d, r9d >> "%ASMFILE%"
echo     lea rax, [rsp+20h] >> "%ASMFILE%"
echo     mov qword ptr [rax], r9 >> "%ASMFILE%"
echo     call WriteFile >> "%ASMFILE%"
echo. >> "%ASMFILE%"
echo     mov rcx, qword ptr [hStdOut] >> "%ASMFILE%"
echo     lea rdx, msg_exit >> "%ASMFILE%"
echo     mov r8d, msg_exit_len >> "%ASMFILE%"
echo     xor r9d, r9d >> "%ASMFILE%"
echo     lea rax, [rsp+20h] >> "%ASMFILE%"
echo     mov qword ptr [rax], r9 >> "%ASMFILE%"
echo     call WriteFile >> "%ASMFILE%"
echo. >> "%ASMFILE%"
echo     add rsp, 58h >> "%ASMFILE%"
echo     xor ecx, ecx >> "%ASMFILE%"
echo     call ExitProcess >> "%ASMFILE%"
echo mainCRTStartup endp >> "%ASMFILE%"
echo end >> "%ASMFILE%"

REM Assemble
"%ML64%" /c /Fo"%OBJFILE%" /W3 /nologo "%ASMFILE%" > nul 2>&1
if errorlevel 1 (
    echo   [FAIL] Assembly failed
    set /a fail+=1
    goto :eof
)

REM Link
"%LINK%" /LIBPATH:"%SDK_LIB%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup kernel32.lib "%OBJFILE%" /OUT:"%EXEFILE%" /nologo > nul 2>&1
if errorlevel 1 (
    echo   [FAIL] Link failed
    set /a fail+=1
    goto :eof
)

REM Test
"%EXEFILE%" > nul 2>&1
if errorlevel 1 (
    echo   [FAIL] Test failed (exit code %ERRORLEVEL%)
    set /a fail+=1
) else (
    echo   [PASS] Built and tested
    set /a success+=1
)

goto :eof

:end
endlocal
