$ErrorActionPreference = 'Continue'
$EV = 'F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039'
$out = Join-Path $EV 'cpu_llama\batch11_gpu_residual'
$SMOKE = 'F:\rawrxd\build_reap\bin\aggregate_decode_single_smoke.exe'
$GGUF = 'F:\OllamaModels\blobs\sha256-6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e'
$PROMPT = 'Write one short sentence about aggregate decode throughput.'
Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
$env:RAWRXD_DEEP2_SHADER_DIR = Join-Path $EV 'shaders_sealed'
$env:DEEP2_BATCHED_PREFILL = '0'
Push-Location $EV
Write-Host "START GPU nobatch $(Get-Date -Format o)"
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out 'gpu_t16_nobatch.stdout.txt')
Write-Host "DONE exit=$LASTEXITCODE $(Get-Date -Format o)"
Pop-Location
Remove-Item Env:DEEP2_BATCHED_PREFILL -ErrorAction SilentlyContinue
$lines = Get-Content (Join-Path $out 'gpu_t16_nobatch.stdout.txt')
$toks = @(); $seen16 = 0
foreach ($ln in $lines) {
  if ($ln -match 'LAYER_COUNT=28 TOKENS=16') { $seen16++; if ($seen16 -eq 1) { $toks = @() } }
  if ($seen16 -ge 1 -and $ln -match '\[DBG\] sampled token=(\d+)') { $toks += [int]$Matches[1] }
  if ($toks.Count -ge 16 -and $ln -match 'DECODE: 16 tok') { break }
}
$gpu16 = ($toks | Select-Object -First 16) -join ','
Write-Host "GPU_16_NOBATCH=$gpu16"
"GPU_16_NOBATCH=$gpu16" | Set-Content -Encoding ascii (Join-Path $out 'GPU_16_NOBATCH.txt')
Select-String -Path (Join-Path $out 'gpu_t16_nobatch.stdout.txt') -Pattern 'PREFILL_BATCHED|batchedMatMulCount|DEEP2_REAL_GPU_FORWARD=|GPU_FORWARD_LAYERS_PER_TOKEN=' |
  Select-Object -Last 20 | ForEach-Object { $_.Line.Trim() }
