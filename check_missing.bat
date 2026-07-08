@echo off
echo Checking for missing compilers...
echo.

set "DIR=d:\rawrxd\compilers\all_69_final"

setlocal enabledelayedexpansion
set MISSING=0

for %%n in (
    ada_compiler_from_scratch
    assembly_compiler_from_scratch
    c_compiler_from_scratch
    c__compiler_from_scratch
    rust_compiler_from_scratch
    go_compiler_from_scratch
    zig_compiler_from_scratch
    odin_compiler_from_scratch
    nim_compiler_from_scratch
    v_compiler_from_scratch
    python_compiler_from_scratch
    javascript_compiler_from_scratch
    typescript_compiler_from_scratch
    ruby_compiler_from_scratch
    perl_compiler_from_scratch
    lua_compiler_from_scratch
    php_compiler_from_scratch
    bash_compiler_from_scratch
    powershell_compiler_from_scratch
    java_compiler_from_scratch
    kotlin_compiler_from_scratch
    scala_compiler_from_scratch
    clojure_compiler_from_scratch
    c___compiler_from_scratch
    f__compiler_from_scratch
    vb_net_compiler_from_scratch
    haskell_compiler_from_scratch
    ocaml_compiler_from_scratch
    erlang_compiler_from_scratch
    elixir_compiler_from_scratch
    dart_compiler_from_scratch
    webassembly_compiler_from_scratch
    swift_compiler_from_scratch
    julia_compiler_from_scratch
    r_compiler_from_scratch
    matlab_compiler_from_scratch
    fortran_compiler_from_scratch
    cobol_compiler_from_scratch
    pascal_compiler_from_scratch
    jai_compiler_from_scratch
    cadence_compiler_from_scratch
    carbon_compiler_from_scratch
    crystal_compiler_from_scratch
    eon_compiler_from_scratch
    eon_compiler_complete
    eon_compiler_main
    eon_kernel_compiler
    full_eon_compiler
    integrated_eon_compiler
    self_hosted_eon_compiler
    solidity_compiler_from_scratch
    vyper_compiler_from_scratch
    move_compiler_from_scratch
    motoko_compiler_from_scratch
    llvm_ir_compiler_from_scratch
    cross_compiler
    multi_target_compiler
    master_universal_compiler
    n0mn0m_cross_platform_compiler
    n0mn0m_quantum_asm_compiler
    reverser_compiler
    reverser_compiler_from_scratch
    delphi_compiler_from_scratch
    self_contained_compiler_gui
    universal_compiler_runtime
    universal_compiler_runtime_clean
    universal_cross_platform_compiler
    universal_multi_language_compiler
    uber_elegant_compiler
) do (
    if not exist "%DIR%\%%n.exe" (
        echo [MISSING] %%n.exe
        set /a MISSING+=1
    )
)

echo.
echo Total missing: %MISSING%
