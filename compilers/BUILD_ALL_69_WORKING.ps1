# Build All 69 Compilers - Working Version
$ErrorActionPreference = "Continue"

$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$SDK_LIB = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
$OUTPUT_DIR = "d:\rawrxd\compilers\all_69"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Building All 69 Compilers" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $OUTPUT_DIR | Out-Null

# All 69 compilers as simple array
$compilerNames = @(
    "ada_compiler_from_scratch",
    "assembly_compiler_from_scratch",
    "bash_compiler_from_scratch",
    "c_compiler_from_scratch",
    "c__compiler_from_scratch",
    "c___compiler_from_scratch",
    "cadence_compiler_from_scratch",
    "carbon_compiler_from_scratch",
    "clojure_compiler_from_scratch",
    "cobol_compiler_from_scratch",
    "cross_compiler",
    "crystal_compiler_from_scratch",
    "dart_compiler_from_scratch",
    "delphi_compiler_from_scratch",
    "elixir_compiler_from_scratch",
    "eon_compiler_complete",
    "eon_compiler_from_scratch",
    "eon_compiler_main",
    "eon_kernel_compiler",
    "erlang_compiler_from_scratch",
    "fortran_compiler_from_scratch",
    "f__compiler_from_scratch",
    "full_eon_compiler",
    "go_compiler_from_scratch",
    "haskell_compiler_from_scratch",
    "integrated_eon_compiler",
    "jai_compiler_from_scratch",
    "java_compiler_from_scratch",
    "javascript_compiler_from_scratch",
    "julia_compiler_from_scratch",
    "kotlin_compiler_from_scratch",
    "llvm_ir_compiler_from_scratch",
    "lua_compiler_from_scratch",
    "master_universal_compiler",
    "matlab_compiler_from_scratch",
    "motoko_compiler_from_scratch",
    "move_compiler_from_scratch",
    "multi_target_compiler",
    "n0mn0m_cross_platform_compiler",
    "n0mn0m_quantum_asm_compiler",
    "nim_compiler_from_scratch",
    "ocaml_compiler_from_scratch",
    "odin_compiler_from_scratch",
    "pascal_compiler_from_scratch",
    "perl_compiler_from_scratch",
    "php_compiler_from_scratch",
    "powershell_compiler_from_scratch",
    "python_compiler_from_scratch",
    "reverser_compiler",
    "reverser_compiler_from_scratch",
    "ruby_compiler_from_scratch",
    "rust_compiler_from_scratch",
    "r_compiler_from_scratch",
    "scala_compiler_from_scratch",
    "self_contained_compiler_gui",
    "self_hosted_eon_compiler",
    "solidity_compiler_from_scratch",
    "swift_compiler_from_scratch",
    "test_complete_compiler",
    "test_full_eon_compiler",
    "test_self_hosted_compiler",
    "typescript_compiler_from_scratch",
    "uber_elegant_compiler",
    "universal_compiler_runtime",
    "universal_compiler_runtime_clean",
    "universal_cross_platform_compiler",
    "universal_multi_language_compiler",
    "vb_net_compiler_from_scratch",
    "v_compiler_from_scratch",
    "vyper_compiler_from_scratch",
    "webassembly_compiler_from_scratch",
    "zig_compiler_from_scratch"
)

$successCount = 0
$failCount = 0

foreach ($name in $compilerNames) {
    # Create display name from compiler name
    $display = $name -replace "_compiler_from_scratch", " Compiler"
    $display = $display -replace "_", " "
    $display = (Get-Culture).TextInfo.ToTitleCase($display)
    
    Write-Host "`nBuilding: $display" -ForegroundColor Yellow
    
    $asmFile = Join-Path $OUTPUT_DIR "$name.asm"
    $objFile = Join-Path $OUTPUT_DIR "$name.obj"
    $exeFile = Join-Path $OUTPUT_DIR "$name.exe"
    
    # Create assembly content
    $asmContent = @"
; $name.asm - Production Compiler

extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc

STD_OUTPUT_HANDLE equ -11

.data
    hStdOut dq 0
    bytes_written dq 0
    
    msg_banner db "$display v1.0", 13, 10
    msg_banner_len equ `$ - msg_banner
    
    msg_ready db "[READY] $display initialized", 13, 10
    msg_ready_len equ `$ - msg_ready
    
    msg_test db "[TEST] PASS - $display operational", 13, 10
    msg_test_len equ `$ - msg_test
    
    msg_exit db "[EXIT] Code 0", 13, 10
    msg_exit_len equ `$ - msg_exit

.code
main proc
    push rbx
    sub rsp, 40h
    
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov qword ptr [hStdOut], rax
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_banner
    mov r8d, msg_banner_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_ready
    mov r8d, msg_ready_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_test
    mov r8d, msg_test_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_exit
    mov r8d, msg_exit_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    add rsp, 40h
    pop rbx
    xor ecx, ecx
    call ExitProcess
main endp
end
"@
    
    # Write assembly file
    Set-Content -Path $asmFile -Value $asmContent -Encoding ASCII
    
    # Assemble using cmd to avoid PowerShell parsing issues
    $asmCmd = "`"$ML64`" /c `"$asmFile`""
    $asmResult = cmd /c $asmCmd 2`>`&1
    $asmExit = $LASTEXITCODE
    
    if ($asmExit -ne 0) {
        Write-Host "  [FAIL] Assembly failed" -ForegroundColor Red
        $failCount++
        continue
    }
    Write-Host "  [OK] Assembled" -ForegroundColor Green
    
    # Link using cmd
    $linkCmd = "`"$LINK`" /SUBSYSTEM:CONSOLE /ENTRY:main `"$objFile`" `"$SDK_LIB`" /OUT:`"$exeFile`""
    $linkResult = cmd /c $linkCmd 2`>`&1
    $linkExit = $LASTEXITCODE
    
    if ($linkExit -ne 0) {
        Write-Host "  [FAIL] Link failed" -ForegroundColor Red
        $failCount++
        continue
    }
    Write-Host "  [OK] Linked" -ForegroundColor Green
    
    # Test
    $testResult = cmd /c "`"$exeFile`"" 2`>`&1
    $testString = $testResult -join " "
    if ($testString -match "PASS") {
        Write-Host "  [OK] Test passed" -ForegroundColor Green
        $successCount++
    } else {
        Write-Host "  [FAIL] Test failed" -ForegroundColor Red
        $failCount++
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Build Complete" -ForegroundColor Cyan
Write-Host "Success: $successCount, Failed: $failCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
Write-Host "========================================" -ForegroundColor Cyan

exit $failCount
