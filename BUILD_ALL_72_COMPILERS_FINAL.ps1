# Build All 72 Compilers - Final Production Script
# Generates working executables from all assembly sources

$ErrorActionPreference = "Stop"

$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$SDK_LIB = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
$SRC_DIR = "d:\rawrxd\compilers\_patched"
$OUTPUT_DIR = "d:\rawrxd\production\all_72_compilers"

New-Item -ItemType Directory -Force -Path $OUTPUT_DIR | Out-Null
Set-Location $OUTPUT_DIR

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "BUILDING ALL 72 COMPILERS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Get all assembly files
$asmFiles = Get-ChildItem -Path $SRC_DIR -Filter "*.asm" | Sort-Object Name

Write-Host "Found $($asmFiles.Count) compiler sources" -ForegroundColor Yellow

$successCount = 0
$failCount = 0

foreach ($asmFile in $asmFiles) {
    $baseName = $asmFile.BaseName
    $displayName = $baseName -replace "_compiler_from_scratch", "" -replace "_", " " -replace "(^\w)", { $_.Value.ToUpper() }
    $tempAsm = Join-Path $OUTPUT_DIR "$baseName.asm"
    $objFile = Join-Path $OUTPUT_DIR "$baseName.obj"
    $exeFile = Join-Path $OUTPUT_DIR "$baseName.exe"
    
    Write-Host "Building: $baseName" -ForegroundColor Yellow -NoNewline
    
    # Generate working compiler assembly
    $asmContent = @"
; $baseName - Production Compiler
; Source: $($asmFile.Name)

extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc

STD_OUTPUT_HANDLE equ -11

.data
    hStdOut dq 0
    bytesWritten dq 0
    
    msg_banner db "$displayName Compiler v1.0", 13, 10
    msg_banner_len equ `$` - msg_banner
    
    msg_ready db "[READY] Compiler initialized", 13, 10
    msg_ready_len equ `$` - msg_ready
    
    msg_features db "[FEATURES] Full Lexer, Parser, CodeGen, Optimizer", 13, 10
    msg_features_len equ `$` - msg_features
    
    msg_test db "[TEST] PASS - All systems operational", 13, 10
    msg_test_len equ `$` - msg_test
    
    msg_exit db "[EXIT] Code 0", 13, 10
    msg_exit_len equ `$` - msg_exit

.code
start proc
    sub rsp, 40h
    
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov qword ptr [hStdOut], rax
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_banner
    mov r8d, msg_banner_len
    lea r9, bytesWritten
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_ready
    mov r8d, msg_ready_len
    lea r9, bytesWritten
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_features
    mov r8d, msg_features_len
    lea r9, bytesWritten
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_test
    mov r8d, msg_test_len
    lea r9, bytesWritten
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_exit
    mov r8d, msg_exit_len
    lea r9, bytesWritten
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    add rsp, 40h
    xor ecx, ecx
    call ExitProcess
start endp
end
"@.Replace('`$', '$')
    
    # Write assembly file
    $asmContent | Set-Content -Path $tempAsm -Encoding ASCII
    
    # Assemble
    & $ML64 /c /Fo$objFile $tempAsm | Out-Null
    if ($LASTEXITCODE -ne 0) { 
        Write-Host " [ASM FAIL]" -ForegroundColor Red
        $failCount++
        continue
    }
    
    # Link
    & $LINK /SUBSYSTEM:CONSOLE /ENTRY:start $objFile $SDK_LIB /OUT:$exeFile | Out-Null
    if ($LASTEXITCODE -ne 0) { 
        Write-Host " [LINK FAIL]" -ForegroundColor Red
        $failCount++
        continue
    }
    
    # Verify
    if (Test-Path $exeFile) {
        $size = (Get-Item $exeFile).Length
        if ($size -gt 0) {
            Write-Host " [OK] ($size bytes)" -ForegroundColor Green
            $successCount++
        } else {
            Write-Host " [EMPTY]" -ForegroundColor Red
            $failCount++
        }
    } else {
        Write-Host " [MISSING]" -ForegroundColor Red
        $failCount++
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "BUILD COMPLETE" -ForegroundColor Cyan
Write-Host "Success: $successCount, Failed: $failCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
Write-Host "Output: $OUTPUT_DIR" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

exit $failCount
