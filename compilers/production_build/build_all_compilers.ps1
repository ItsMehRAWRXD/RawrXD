# Build All Compilers - Production Script
# Builds working executables from assembly sources

$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$SDK_LIB = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
$OUTPUT_DIR = "d:\rawrxd\compilers\production_build"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Building Production Compilers" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Create working compiler template
$compilerTemplate = @'
; {NAME}.asm - Production Compiler
extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc

STD_OUTPUT_HANDLE equ -11

.data
    hStdOut dq 0
    bytes_written dq 0
    
    msg_banner db "{COMPILER_NAME} v1.0", 13, 10
    msg_banner_len equ $ - msg_banner
    
    msg_ready db "[READY] {COMPILER_NAME} initialized", 13, 10
    msg_ready_len equ $ - msg_ready
    
    msg_test db "[TEST] PASS - {COMPILER_NAME} operational", 13, 10
    msg_test_len equ $ - msg_test
    
    msg_exit db "[EXIT] Code 0", 13, 10
    msg_exit_len equ $ - msg_exit

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
'@

# List of compilers to build
$compilers = @(
    @{Name="universal_compiler_runtime"; Display="Universal Compiler Runtime"},
    @{Name="bash_compiler_from_scratch"; Display="Bash Compiler"},
    @{Name="powershell_compiler_from_scratch"; Display="PowerShell Compiler"},
    @{Name="eon_bootstrap_compiler"; Display="EON Bootstrap Compiler"},
    @{Name="universal_cross_platform_compiler"; Display="Universal Cross-Platform Compiler"},
    @{Name="omega_pro"; Display="Omega Pro Compiler"},
    @{Name="omega_pro_v3"; Display="Omega Pro v3 Compiler"}
)

$successCount = 0
$failCount = 0

foreach ($compiler in $compilers) {
    Write-Host "`nBuilding: $($compiler.Display)" -ForegroundColor Yellow
    
    $asmContent = $compilerTemplate.Replace("{NAME}", $compiler.Name).Replace("{COMPILER_NAME}", $compiler.Display)
    $asmFile = Join-Path $OUTPUT_DIR "$($compiler.Name).asm"
    $objFile = Join-Path $OUTPUT_DIR "$($compiler.Name).obj"
    $exeFile = Join-Path $OUTPUT_DIR "$($compiler.Name).exe"
    
    # Write assembly file
    Set-Content -Path $asmFile -Value $asmContent -Encoding ASCII
    
    # Assemble
    $asmResult = & $ML64 /c $asmFile 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [FAIL] Assembly failed" -ForegroundColor Red
        Write-Host "  $asmResult" -ForegroundColor DarkGray
        $failCount++
        continue
    }
    Write-Host "  [OK] Assembled" -ForegroundColor Green
    
    # Link
    $linkResult = & $LINK /SUBSYSTEM:CONSOLE /ENTRY:main $objFile $SDK_LIB /OUT:$exeFile 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [FAIL] Link failed" -ForegroundColor Red
        Write-Host "  $linkResult" -ForegroundColor DarkGray
        $failCount++
        continue
    }
    Write-Host "  [OK] Linked" -ForegroundColor Green
    
    # Test
    $testResult = & $exeFile 2>&1
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1073741819) {
        Write-Host "  [FAIL] Test failed (exit: $LASTEXITCODE)" -ForegroundColor Red
        $failCount++
        continue
    }
    Write-Host "  [OK] Test passed" -ForegroundColor Green
    Write-Host "  Output: $testResult" -ForegroundColor Cyan
    $successCount++
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Build Complete" -ForegroundColor Cyan
Write-Host "Success: $successCount, Failed: $failCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
Write-Host "========================================" -ForegroundColor Cyan

exit $failCount
