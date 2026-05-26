$ml64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$srcDir = "D:\rawrxd\src"

Write-Host "[1] Assembling Sovereign_Linker_Glue..." -ForegroundColor Cyan
& $ml64 /nologo /c /Fo "$srcDir\Sovereign_Linker_Glue.obj" "$srcDir\Sovereign_Linker_Glue.asm"
Write-Host "Exit code: $LASTEXITCODE"

Write-Host "[2] Assembling Sovereign_Intrinsics..." -ForegroundColor Cyan  
& $ml64 /nologo /c /Fo "$srcDir\Sovereign_Intrinsics.obj" "$srcDir\Sovereign_Intrinsics.asm"
Write-Host "Exit code: $LASTEXITCODE"

if (Test-Path "D:\rawrxd\src\Sovereign_Linker_Glue.obj") {
    Write-Host "SUCCESS: Objects created" -ForegroundColor Green
} else {
    Write-Host "FAILED: Objects not found" -ForegroundColor Red
}
