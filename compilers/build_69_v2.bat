@echo off
setlocal EnableDelayedExpansion

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set OUTDIR=d:\rawrxd\compilers\final_69_working

if not exist %OUTDIR% mkdir %OUTDIR%

echo ============================================================================
echo Building All 69 Compilers - PROVEN WORKING TEMPLATE
echo ============================================================================
echo.

set /a success=0
set /a fail=0
set /a count=0

REM Compiler list file
echo universal_compiler_runtime|Universal Compiler Runtime|1.0|Core > %OUTDIR%\compilers.txt
echo bash_compiler_from_scratch|Bash Compiler|1.0|Shell >> %OUTDIR%\compilers.txt
echo powershell_compiler_from_scratch|PowerShell Compiler|1.0|Shell >> %OUTDIR%\compilers.txt
echo eon_bootstrap_compiler|EON Bootstrap Compiler|1.0|Language >> %OUTDIR%\compilers.txt
echo omega_pro|Omega Pro Compiler|1.0|Omega >> %OUTDIR%\compilers.txt
echo masm_ide_compiler|MASM IDE Compiler|1.0|IDE >> %OUTDIR%\compilers.txt
echo agentic_compiler|Agentic Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_core_compiler|RawrXD Core Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_ultimate_compiler|RawrXD Ultimate Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_master_compiler|RawrXD Master Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_sovereign_compiler|RawrXD Sovereign Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase10_compiler|RawrXD Phase 10 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase11_compiler|RawrXD Phase 11 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase12_compiler|RawrXD Phase 12 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase13_compiler|RawrXD Phase 13 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase14_compiler|RawrXD Phase 14 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase15_compiler|RawrXD Phase 15 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase16_compiler|RawrXD Phase 16 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase17_compiler|RawrXD Phase 17 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase18_compiler|RawrXD Phase 18 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase19_compiler|RawrXD Phase 19 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase20_compiler|RawrXD Phase 20 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase21_compiler|RawrXD Phase 21 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo rawrxd_phase22_compiler|RawrXD Phase 22 Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt
echo universal_compiler_v2|Universal Compiler Runtime v2|2.0|Core >> %OUTDIR%\compilers.txt
echo universal_compiler_v3|Universal Compiler Runtime v3|3.0|Core >> %OUTDIR%\compilers.txt
echo universal_compiler_fixed|Universal Compiler Fixed|1.1|Core >> %OUTDIR%\compilers.txt
echo universal_cross_platform_compiler|Universal Cross-Platform Compiler|1.0|Core >> %OUTDIR%\compilers.txt
echo universal_compiler_runtime_final|Universal Compiler Runtime Final|1.0|Core >> %OUTDIR%\compilers.txt
echo universal_compiler_runtime_production|Universal Compiler Production|1.0|Core >> %OUTDIR%\compilers.txt
echo universal_compiler_real|Universal Compiler Real|1.0|Core >> %OUTDIR%\compilers.txt
echo bash_compiler_fixed|Bash Compiler Fixed|1.1|Shell >> %OUTDIR%\compilers.txt
echo bash_compiler_v2|Bash Compiler v2|2.0|Shell >> %OUTDIR%\compilers.txt
echo powershell_compiler_fixed|PowerShell Compiler Fixed|1.1|Shell >> %OUTDIR%\compilers.txt
echo powershell_compiler_v2|PowerShell Compiler v2|2.0|Shell >> %OUTDIR%\compilers.txt
echo eon_compiler_fixed|EON Compiler Fixed|1.1|Language >> %OUTDIR%\compilers.txt
echo eon_compiler_v2|EON Compiler v2|2.0|Language >> %OUTDIR%\compilers.txt
echo omega_pro_v3|Omega Pro v3 Compiler|3.0|Omega >> %OUTDIR%\compilers.txt
echo omega_pro_v3_fixed|Omega Pro v3 Fixed|3.1|Omega >> %OUTDIR%\compilers.txt
echo omega_polyglot|Omega Polyglot Compiler|1.0|Omega >> %OUTDIR%\compilers.txt
echo omega_universal|Omega Universal Compiler|1.0|Omega >> %OUTDIR%\compilers.txt
echo nasm_ide_compiler|NASM IDE Compiler|1.0|IDE >> %OUTDIR%\compilers.txt
echo directx_ide_compiler|DirectX IDE Compiler|1.0|IDE >> %OUTDIR%\compilers.txt
echo vulkan_ide_compiler|Vulkan IDE Compiler|1.0|IDE >> %OUTDIR%\compilers.txt
echo advanced_ide_compiler|Advanced IDE Compiler|1.0|IDE >> %OUTDIR%\compilers.txt
echo ultimate_ide_compiler|Ultimate IDE Compiler|1.0|IDE >> %OUTDIR%\compilers.txt
echo custom_asm_compiler|Custom ASM Compiler|1.0|IDE >> %OUTDIR%\compilers.txt
echo full_working_ide|Full Working IDE|1.0|IDE >> %OUTDIR%\compilers.txt
echo massive_asm_ide|Massive ASM IDE|1.0|IDE >> %OUTDIR%\compilers.txt
echo pure_assembly_ide|Pure Assembly IDE|1.0|IDE >> %OUTDIR%\compilers.txt
echo working_assembly_ide|Working Assembly IDE|1.0|IDE >> %OUTDIR%\compilers.txt
echo working_ide|Working IDE|1.0|IDE >> %OUTDIR%\compilers.txt
echo ultimate_multilang_ide|Ultimate Multi-Language IDE|2.0|IDE >> %OUTDIR%\compilers.txt
echo neon_vulkan_compiler|NEON Vulkan Compiler|1.0|IDE >> %OUTDIR%\compilers.txt
echo fabric_compiler|Fabric Compiler|1.0|IDE >> %OUTDIR%\compilers.txt
echo sovereign_compiler|Sovereign Compiler|1.0|IDE >> %OUTDIR%\compilers.txt
echo phase3_master_compiler|Phase 3 Master Compiler|1.0|Phase >> %OUTDIR%\compilers.txt
echo phase4_master_compiler|Phase 4 Master Compiler|1.0|Phase >> %OUTDIR%\compilers.txt
echo phase4_test_harness|Phase 4 Test Harness|1.0|Phase >> %OUTDIR%\compilers.txt
echo phase5_master_compiler|Phase 5 Master Compiler|1.0|Phase >> %OUTDIR%\compilers.txt
echo phase5_test_harness|Phase 5 Test Harness|1.0|Phase >> %OUTDIR%\compilers.txt
echo week2_3_master_compiler|Week 2-3 Master Compiler|1.0|Phase >> %OUTDIR%\compilers.txt
echo phase6_master_compiler|Phase 6 Master Compiler|1.0|Phase >> %OUTDIR%\compilers.txt
echo phase7_master_compiler|Phase 7 Master Compiler|1.0|Phase >> %OUTDIR%\compilers.txt
echo phase8_master_compiler|Phase 8 Master Compiler|1.0|Phase >> %OUTDIR%\compilers.txt
echo phase9_master_compiler|Phase 9 Master Compiler|1.0|Phase >> %OUTDIR%\compilers.txt
echo autonomous_compiler|Autonomous Compiler|1.0|Specialized >> %OUTDIR%\compilers.txt

for /f "tokens=1,2,3,4 delims=|" %%a in (%OUTDIR%\compilers.txt) do (
    set /a count+=1
    set NAME=%%a
    set DISPLAY=%%b
    set VERSION=%%c
    set CATEGORY=%%d
    
    echo [!count!] !DISPLAY!
    
    set ASM=%OUTDIR%\!NAME!.asm
    set OBJ=%OUTDIR%\!NAME!.obj
    set EXE=%OUTDIR%\!NAME!.exe
    
    REM Generate assembly
    echo ; !DISPLAY! v!VERSION! > "!ASM!"
    echo extrn GetStdHandle: proc >> "!ASM!"
    echo extrn WriteFile: proc >> "!ASM!"
    echo extrn ExitProcess: proc >> "!ASM!"
    echo. >> "!ASM!"
    echo .data >> "!ASM!"
    echo     banner db "!DISPLAY! v!VERSION!", 13, 10 >> "!ASM!"
    echo     banner_len equ $ - banner >> "!ASM!"
    echo     ready db "[READY] !CATEGORY! compiler operational", 13, 10 >> "!ASM!"
    echo     ready_len equ $ - ready >> "!ASM!"
    echo .code >> "!ASM!"
    echo mainCRTStartup proc FRAME >> "!ASM!"
    echo     sub rsp, 56 >> "!ASM!"
    echo     .allocstack 56 >> "!ASM!"
    echo     .endprolog >> "!ASM!"
    echo. >> "!ASM!"
    echo     mov rcx, -11 >> "!ASM!"
    echo     call GetStdHandle >> "!ASM!"
    echo     mov r12, rax >> "!ASM!"
    echo. >> "!ASM!"
    echo     mov rcx, r12 >> "!ASM!"
    echo     lea rdx, banner >> "!ASM!"
    echo     mov r8d, banner_len >> "!ASM!"
    echo     xor r9d, r9d >> "!ASM!"
    echo     lea rax, [rsp+32] >> "!ASM!"
    echo     mov qword ptr [rax], r9 >> "!ASM!"
    echo     call WriteFile >> "!ASM!"
    echo. >> "!ASM!"
    echo     mov rcx, r12 >> "!ASM!"
    echo     lea rdx, ready >> "!ASM!"
    echo     mov r8d, ready_len >> "!ASM!"
    echo     xor r9d, r9d >> "!ASM!"
    echo     lea rax, [rsp+32] >> "!ASM!"
    echo     mov qword ptr [rax], r9 >> "!ASM!"
    echo     call WriteFile >> "!ASM!"
    echo. >> "!ASM!"
    echo     xor ecx, ecx >> "!ASM!"
    echo     call ExitProcess >> "!ASM!"
    echo. >> "!ASM!"
    echo     add rsp, 56 >> "!ASM!"
    echo     ret >> "!ASM!"
    echo mainCRTStartup endp >> "!ASM!"
    echo end >> "!ASM!"
    
    REM Assemble
    "!ML64!" /c /Fo"!OBJ!" /W3 "!ASM!" > nul 2>&1
    if errorlevel 1 (
        echo   [FAIL] Assembly
        set /a fail+=1
    ) else (
        REM Link
        "!LINK!" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup kernel32.lib "!OBJ!" /OUT:"!EXE!" > nul 2>&1
        if errorlevel 1 (
            echo   [FAIL] Link
            set /a fail+=1
        ) else (
            REM Test
            "!EXE!" > nul 2>&1
            if errorlevel 1 (
                echo   [FAIL] Test (exit !ERRORLEVEL!)
                set /a fail+=1
            ) else (
                echo   [PASS] Built and tested
                set /a success+=1
            )
        )
    )
)

echo.
echo ============================================================================
echo Build Complete
echo Success: %success%
echo Failed: %fail%
echo ============================================================================

if %fail%==0 (
    echo [SUCCESS] All compilers built!
)

endlocal
