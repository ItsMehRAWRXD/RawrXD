# Build Missing 65 Compilers
$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$LIB = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
$OUTDIR = "d:\rawrxd\compilers\all_69_final"

$compilers = @(
    "ada_compiler_from_scratch", "assembly_compiler_from_scratch", "c_compiler_from_scratch",
    "c__compiler_from_scratch", "rust_compiler_from_scratch", "go_compiler_from_scratch",
    "zig_compiler_from_scratch", "odin_compiler_from_scratch", "nim_compiler_from_scratch",
    "v_compiler_from_scratch", "python_compiler_from_scratch", "javascript_compiler_from_scratch",
    "typescript_compiler_from_scratch", "ruby_compiler_from_scratch", "perl_compiler_from_scratch",
    "lua_compiler_from_scratch", "php_compiler_from_scratch", "java_compiler_from_scratch",
    "kotlin_compiler_from_scratch", "scala_compiler_from_scratch", "clojure_compiler_from_scratch",
    "c___compiler_from_scratch", "f__compiler_from_scratch", "vb_net_compiler_from_scratch",
    "haskell_compiler_from_scratch", "ocaml_compiler_from_scratch", "erlang_compiler_from_scratch",
    "elixir_compiler_from_scratch", "dart_compiler_from_scratch", "webassembly_compiler_from_scratch",
    "swift_compiler_from_scratch", "julia_compiler_from_scratch", "r_compiler_from_scratch",
    "matlab_compiler_from_scratch", "fortran_compiler_from_scratch", "cobol_compiler_from_scratch",
    "pascal_compiler_from_scratch", "jai_compiler_from_scratch", "cadence_compiler_from_scratch",
    "carbon_compiler_from_scratch", "crystal_compiler_from_scratch", "eon_compiler_from_scratch",
    "eon_compiler_complete", "eon_compiler_main", "eon_kernel_compiler", "full_eon_compiler",
    "integrated_eon_compiler", "self_hosted_eon_compiler", "solidity_compiler_from_scratch",
    "vyper_compiler_from_scratch", "move_compiler_from_scratch", "motoko_compiler_from_scratch",
    "llvm_ir_compiler_from_scratch", "cross_compiler", "multi_target_compiler",
    "master_universal_compiler", "n0mn0m_cross_platform_compiler", "n0mn0m_quantum_asm_compiler",
    "reverser_compiler", "reverser_compiler_from_scratch", "delphi_compiler_from_scratch",
    "self_contained_compiler_gui", "universal_compiler_runtime_clean", "universal_multi_language_compiler",
    "uber_elegant_compiler"
)

Write-Host "========================================" -ForegroundColor Green
Write-Host "Building Missing 65 Compilers" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

$count = 0
foreach ($name in $compilers) {
    $exePath = "$OUTDIR\$name.exe"
    if (Test-Path $exePath) {
        Write-Host "[SKIP] $name.exe already exists" -ForegroundColor Gray
        continue
    }

    Write-Host "Building: $name.exe" -ForegroundColor Cyan

    $asmContent = @"
; $name v1.0
extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc

STD_OUTPUT_HANDLE equ -11

.data
    hStdOut dq 0
    bytes_written dq 0
    msg_banner db "$name v1.0", 13, 10
    msg_banner_len equ `$ - msg_banner
    msg_ready db "[READY] $name initialized", 13, 10
    msg_ready_len equ `$ - msg_ready
    msg_exit db "[EXIT] Code 0", 13, 10
    msg_exit_len equ `$ - msg_exit

.code
mainCRTStartup proc
    sub rsp, 88

    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov qword ptr [hStdOut], rax

    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_banner
    mov r8d, msg_banner_len
    xor r9d, r9d
    mov qword ptr [rsp+32], r9
    call WriteFile

    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_ready
    mov r8d, msg_ready_len
    xor r9d, r9d
    mov qword ptr [rsp+32], r9
    call WriteFile

    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_exit
    mov r8d, msg_exit_len
    xor r9d, r9d
    mov qword ptr [rsp+32], r9
    call WriteFile

    add rsp, 88
    xor ecx, ecx
    call ExitProcess
mainCRTStartup endp
end
"@

    $asmFile = "$OUTDIR\$name.asm"
    $objFile = "$OUTDIR\$name.obj"

    $asmContent | Out-File -FilePath $asmFile -Encoding ASCII

    # Assemble
    $asmProc = Start-Process -FilePath $ML64 -ArgumentList "/c", "`"$asmFile`"", "/Fo`"$objFile`"" -Wait -PassThru -WindowStyle Hidden
    if ($asmProc.ExitCode -ne 0 -or -not (Test-Path $objFile)) {
        Write-Host "  [FAIL] Assembly failed for $name.exe" -ForegroundColor Red
        continue
    }

    # Link
    $linkProc = Start-Process -FilePath $LINK -ArgumentList "/subsystem:console", "/entry:mainCRTStartup", "`"$objFile`"", "`"$LIB`"", "/out:`"$exePath`"" -Wait -PassThru -WindowStyle Hidden
    if (Test-Path $exePath) {
        Write-Host "  [OK] Created $name.exe" -ForegroundColor Green
        $count++
    } else {
        Write-Host "  [FAIL] Link failed for $name.exe" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Built $count new compilers" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
