# Build All 72 Compilers - Production Script
# Builds working compilers from all assembly sources

$ErrorActionPreference = "Stop"

$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$SDK_LIB = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
$SRC_DIR = "d:\rawrxd\compilers\_patched"
$OUTPUT_DIR = "d:\rawrxd\production\all_compilers"

New-Item -ItemType Directory -Force -Path $OUTPUT_DIR | Out-Null

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
    $objFile = Join-Path $OUTPUT_DIR "$baseName.obj"
    $exeFile = Join-Path $OUTPUT_DIR "$baseName.exe"
    
    Write-Host "`nBuilding: $baseName" -ForegroundColor Yellow -NoNewline
    
    try {
        # Assemble
        & $ML64 /c /Fo$objFile $asmFile.FullName 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Assembly failed" }
        
        # Link
        & $LINK /SUBSYSTEM:CONSOLE /ENTRY:start $objFile $SDK_LIB /OUT:$exeFile 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Link failed" }
        
        # Verify it exists and has content
        if (Test-Path $exeFile) {
            $size = (Get-Item $exeFile).Length
            if ($size -gt 0) {
                Write-Host " [OK] ($size bytes)" -ForegroundColor Green
                $successCount++
            } else {
                Write-Host " [FAIL] Empty executable" -ForegroundColor Red
                $failCount++
            }
        } else {
            Write-Host " [FAIL] Not created" -ForegroundColor Red
            $failCount++
        }
    }
    catch {
        Write-Host " [FAIL] $_" -ForegroundColor Red
        $failCount++
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "BUILD COMPLETE" -ForegroundColor Cyan
Write-Host "Success: $successCount, Failed: $failCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
Write-Host "Output: $OUTPUT_DIR" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

exit $failCount
