$exe = 'F:\rawrxd\build_reap\bin\rawrxd_deep2_engine.exe'
$model = 'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf'
$log = 'F:\rawrxd\evidence\kimi_ps.log'
$env:DEEP2_L1_DIAG = '1'
& $exe $model 'Hello' 1 > $log 2>&1
$exit = $LASTEXITCODE
Remove-Item Env:\DEEP2_L1_DIAG -ErrorAction SilentlyContinue
"EXIT=$exit"
Select-String -Path $log -Pattern 'L1_DIAG|LAYER_VETO|ERROR|fatal' | Select-Object LineNumber, Line | Select-Object -First 10