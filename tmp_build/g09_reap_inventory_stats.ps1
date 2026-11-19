$ErrorActionPreference = 'Stop'
$invPath = 'F:\rawrxd\evidence\reap_kimi_k2_full_inventory.json'
$d = Get-Content $invPath -Raw | ConvertFrom-Json
$ex = @($d.tensors | Where-Object { $_.name -match 'ffn_(gate|up|down)_exps' })
$gate = @($ex | Where-Object { $_.name -match 'ffn_gate_exps' })
$shared = @($d.tensors | Where-Object { $_.name -match 'ffn_.*shexp|shared' })
Write-Output ("exps_tensors=" + $ex.Count)
Write-Output ("gate_layers=" + $gate.Count)
if ($gate.Count -gt 0) {
  Write-Output ("expert_count_sample=" + $gate[0].expert_count)
  Write-Output ("dims=" + ($gate[0].dims -join 'x'))
  Write-Output ("size0=" + $gate[0].size_bytes)
}
$totalEx = ($ex | Measure-Object -Property size_bytes -Sum).Sum
Write-Output ("expert_proj_bytes=" + $totalEx)
Write-Output ("shared_tensors=" + $shared.Count)
Write-Output ("shard_count=" + $d.shard_count)
$modelDir = 'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M'
$paths = @(Get-ChildItem $modelDir -Filter '*.gguf' -ErrorAction SilentlyContinue)
if ($paths.Count -gt 0) {
  $tb = ($paths | Measure-Object Length -Sum).Sum
  Write-Output ("original_model_bytes=" + $tb)
  Write-Output ("shard_files=" + $paths.Count)
  $s1 = $paths | Where-Object { $_.Name -match '00001-of-' } | Select-Object -First 1
  if ($s1) { Write-Output ("shard1_path=" + $s1.FullName); Write-Output ("shard1_bytes=" + $s1.Length) }
}
