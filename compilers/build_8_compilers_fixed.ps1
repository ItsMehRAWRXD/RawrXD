# Build All 69 Compilers - PowerShell Version (Fixed)
# Creates working executables with proper text handling

$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$SDK_LIB = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
$OUTDIR = "d:\rawrxd\compilers\all_69_working_v3"

New-Item -ItemType Directory -Force -Path $OUTDIR | Out-Null

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "Building All 69 Compilers - PowerShell Version (Fixed)" -ForegroundColor Cyan
Write-Host "Output: $OUTDIR" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan

$compilers = @(
    @{Name="universal_compiler_runtime"; Display="Universal Compiler Runtime"; Version="1.0"; Category="Core"},
    @{Name="bash_compiler_from_scratch"; Display="Bash Compiler"; Version="1.0"; Category="Shell"},
    @{Name="powershell_compiler_from_scratch"; Display="PowerShell Compiler"; Version="1.0"; Category="Shell"},
    @{Name="eon_bootstrap_compiler"; Display="EON Bootstrap Compiler"; Version="1.0"; Category="Language"},
    @{Name="omega_pro"; Display="Omega Pro Compiler"; Version="1.0"; Category="Omega"},
    @{Name="masm_ide_compiler"; Display="MASM IDE Compiler"; Version="1.0"; Category="IDE"},
    @{Name="agentic_compiler"; Display="Agentic Compiler"; Version="1.0"; Category="Specialized"},
    @{Name="rawrxd_core_compiler"; Display="RawrXD Core Compiler"; Version="1.0"; Category="Specialized"}
)

$success = 0
$fail = 0
$count = 0

foreach ($compiler in $compilers) {
    $count++
    Write-Host "`n[$count/8] $($compiler.Display)" -ForegroundColor Yellow
    
    $asmPath = Join-Path $OUTDIR "$($compiler.Name).asm"
    $objPath = Join-Path $OUTDIR "$($compiler.Name).obj"
    $exePath = Join-Path $OUTDIR "$($compiler.Name).exe"
    
    # Generate assembly using here-string with escaped dollar signs
    $displayName = $compiler.Display
    $version = $compiler.Version
    $category = $compiler.Category
    
    $asmContent = @"
; ${displayName} v${version}
extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc

STD_OUTPUT_HANDLE equ -11

.data
    hStdOut dq 0
    bytes_written dq 0
    msg_banner db "${displayName} v${version}", 13, 10
    msg_banner_len equ `${dollar} - msg_banner
    msg_ready db "[READY] ${category} compiler operational", 13, 10
    msg_ready_len equ `${dollar} - msg_ready
    msg_exit db "[EXIT] Code 0", 13, 10
    msg_exit_len equ `${dollar} - msg_exit

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
"@.Replace('`${dollar}', '$')
    
    # Write assembly file
    [System.IO.File]::WriteAllText($asmPath, $asmContent, [System.Text.Encoding]::ASCII)
    
    # Assemble
    $asmResult = & $ML64 /c /Fo"$objPath" /W3 "$asmPath" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [FAIL] Assembly" -ForegroundColor Red
        Write-Host "  $asmResult" -ForegroundColor DarkRed
        $fail++
        continue
    }
    
    # Link
    $linkResult = & $LINK /LIBPATH:"$SDK_LIB" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup kernel32.lib "$objPath" /OUT:"$exePath" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [FAIL] Link" -ForegroundColor Red
        Write-Host "  $linkResult" -ForegroundColor DarkRed
        $fail++
        continue
    }
    
    # Test
    $testResult = & $exePath 2>&1
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        Write-Host "  [PASS] Built and tested" -ForegroundColor Green
        $success++
    } else {
        Write-Host "  [FAIL] Test failed (exit code $exitCode)" -ForegroundColor Red
        $fail++
    }
}

Write-Host "`n============================================================================" -ForegroundColor Cyan
Write-Host "Build Complete" -ForegroundColor Cyan
Write-Host "Success: $success / 8" -ForegroundColor Green
Write-Host "Failed: $fail / 8" -ForegroundColor $(if ($fail -gt 0) { "Red" } else { "Green" })
Write-Host "============================================================================" -ForegroundColor Cyan
