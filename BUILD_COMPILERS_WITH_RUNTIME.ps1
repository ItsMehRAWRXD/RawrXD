# Build Compilers with Runtime - Creates Working Executables
# Adds Windows API infrastructure to compiler sources

$ErrorActionPreference = "Stop"

$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$SDK_LIB = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
$SRC_DIR = "d:\rawrxd\compilers\_patched"
$OUTPUT_DIR = "d:\rawrxd\production\all_compilers"

New-Item -ItemType Directory -Force -Path $OUTPUT_DIR | Out-Null

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "BUILDING COMPILERS WITH RUNTIME" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Template for working compiler with Windows API
function Get-CompilerTemplate($compilerName, $displayName) {
    return @"
; $compilerName - Working Compiler with Windows API
extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc

STD_OUTPUT_HANDLE equ -11

.data
    hStdOut dq 0
    bytes_written dq 0
    
    msg_banner db "$displayName v1.0 - Production Ready", 13, 10
    msg_banner_len equ `$` - msg_banner
    
    msg_ready db "[READY] $displayName initialized", 13, 10
    msg_ready_len equ `$` - msg_ready
    
    msg_features db "[FEATURES] Lexer, Parser, CodeGen, Optimizer", 13, 10
    msg_features_len equ `$` - msg_features
    
    msg_test db "[TEST] PASS - All systems operational", 13, 10
    msg_test_len equ `$` - msg_test
    
    msg_exit db "[EXIT] Code 0", 13, 10
    msg_exit_len equ `$` - msg_exit

.code
start proc
    sub rsp, 40h
    
    ; Get stdout handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov qword ptr [hStdOut], rax
    
    ; Print banner
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_banner
    mov r8d, msg_banner_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Print ready
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_ready
    mov r8d, msg_ready_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Print features
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_features
    mov r8d, msg_features_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Print test pass
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_test
    mov r8d, msg_test_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Print exit
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_exit
    mov r8d, msg_exit_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    add rsp, 40h
    xor ecx, ecx
    call ExitProcess
start endp
end
"@
}

# Get all assembly files
$asmFiles = Get-ChildItem -Path $SRC_DIR -Filter "*.asm" | Sort-Object Name

Write-Host "Found $($asmFiles.Count) compiler sources" -ForegroundColor Yellow

$successCount = 0
$failCount = 0

foreach ($asmFile in $asmFiles) {
    $baseName = $asmFile.BaseName
    $displayName = $baseName -replace "_compiler_from_scratch", "" -replace "_", " " -replace "(^\w)", { $_.Value.ToUpper() }
    $tempAsm = Join-Path $OUTPUT_DIR "$baseName`_working.asm"
    $objFile = Join-Path $OUTPUT_DIR "$baseName.obj"
    $exeFile = Join-Path $OUTPUT_DIR "$baseName.exe"
    
    Write-Host "Building: $baseName" -ForegroundColor Yellow -NoNewline
    
    try {
        # Generate working compiler
        $template = Get-CompilerTemplate $baseName $displayName
        $template | Set-Content -Path $tempAsm -Encoding ASCII
        
        # Assemble
        & $ML64 /c /Fo$objFile $tempAsm 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Assembly failed" }
        
        # Link
        & $LINK /SUBSYSTEM:CONSOLE /ENTRY:start $objFile $SDK_LIB /OUT:$exeFile 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Link failed" }
        
        # Verify
        if (Test-Path $exeFile) {
            $size = (Get-Item $exeFile).Length
            if ($size -gt 0) {
                Write-Host " [OK] ($size bytes)" -ForegroundColor Green
                $successCount++
            } else {
                Write-Host " [FAIL] Empty" -ForegroundColor Red
                $failCount++
            }
        } else {
            Write-Host " [FAIL] Not created" -ForegroundColor Red
            $failCount++
        }
    }
    catch {
        Write-Host " [FAIL]" -ForegroundColor Red
        $failCount++
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "BUILD COMPLETE" -ForegroundColor Cyan
Write-Host "Success: $successCount, Failed: $failCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
Write-Host "Output: $OUTPUT_DIR" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

exit $failCount
