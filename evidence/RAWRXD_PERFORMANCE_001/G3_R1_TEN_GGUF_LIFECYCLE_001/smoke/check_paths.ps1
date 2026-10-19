$t = [IO.File]::ReadAllText('G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\run_r1_matrix.ps1')
$m = [regex]::Match($t, '02_phi3_mini.{0,25}')
Write-Host $m.Value
Write-Host ([System.BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($m.Value)))
$paths = @(
  (Join-Path 'G:\~dev\rawrxd\_r1_iso\02_phi3_mini' 'Phi-3-mini-4k-instruct-q8_0.gguf'),
  (Join-Path 'G:\~dev\rawrxd\_r1_iso\06_phi3_med' 'Phi-3-medium-128k-instruct-Q4_K_M.gguf'),
  'G:\~dev\rawrxd\_r1_iso\03_nemotron\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf',
  'G:\~dev\rawrxd\_r1_iso\07_codestral\Codestral-22B-v0.1-Q4_K_M.gguf',
  'G:\~dev\rawrxd\_r1_iso\08_qwen_coder\qwen2.5-coder-14b-instruct-q8_0.gguf',
  'G:\~dev\rawrxd\_r1_iso\09_bigdaddy_ultra\BigDaddyG-Q2_K-ULTRA.gguf',
  'G:\~dev\rawrxd\_r1_iso\10_glm47\GLM-4.7-Flash-Q4_K_M.gguf'
)
foreach ($x in $paths) { Write-Host ("$(Test-Path -LiteralPath $x) $x") }
