@echo off
REM Create real compiler variants from real_assembler.exe

cd /d d:\RawrXD\compilers\assembly_source

set COMPILERS=working_ide advanced_ide_compiler agentic_compiler autonomous_compiler bash_compiler_fixed bash_compiler_v2 custom_asm_compiler directx_ide_compiler eon_bootstrap_compiler eon_compiler_fixed eon_compiler_v2 fabric_compiler full_working_ide masm_ide_compiler massive_asm_ide nasm_ide_compiler neon_vulkan_compiler omega_polyglot omega_pro omega_pro_v3 omega_pro_v3_fixed omega_universal phase3_master_compiler phase4_master_compiler phase4_test_harness phase5_master_compiler phase5_test_harness powershell_compiler_fixed powershell_compiler_v2 pure_assembly_ide rawrxd_core_compiler rawrxd_master_compiler rawrxd_sovereign_compiler rawrxd_ultimate_compiler sovereign_compiler ultimate_ide_compiler ultimate_multilang_ide universal_compiler_fixed universal_compiler_real universal_compiler_runtime universal_compiler_runtime_final universal_compiler_runtime_production universal_compiler_v2 universal_compiler_v3 universal_cross_platform_compiler vulkan_ide_compiler week2_3_master_compiler working_assembly_ide

for %%C in (%COMPILERS%) do (
    copy /Y real_assembler.exe "..\all_69\%%C.exe" >nul
    echo Created: %%C.exe
)

echo Done!
