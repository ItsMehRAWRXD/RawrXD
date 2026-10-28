@echo off
setlocal
cd /d "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_002"
REM raw.log = original stdout (35386) + stderr (31276381)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_002'; $b=[IO.File]::ReadAllBytes((Join-Path $p 'raw.log')); [IO.File]::WriteAllBytes((Join-Path $p 'raw_stdout.log'), $b[0..35385]); [IO.File]::WriteAllBytes((Join-Path $p 'raw_stderr.log'), $b[35386..($b.Length-1)]); Write-Host ('stdout=' + (Get-Item (Join-Path $p 'raw_stdout.log')).Length); Write-Host ('stderr=' + (Get-Item (Join-Path $p 'raw_stderr.log')).Length)"
findstr /c:"GENERATED_TOKENS=1997" "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_002\raw_stderr.log" >nul && echo STDERR_HAS_1997=1 || echo STDERR_HAS_1997=0
endlocal
