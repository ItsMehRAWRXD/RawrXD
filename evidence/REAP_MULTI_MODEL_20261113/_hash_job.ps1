$ErrorActionPreference='Continue'
$ev='F:\rawrxd\evidence\REAP_MULTI_MODEL_20261113'
$manifest=@{}
$files=@(
  Get-ChildItem 'F:\OllamaModels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M\*.gguf' | Sort-Object Name
  Get-ChildItem 'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\*.gguf' | Sort-Object Name
  Get-Item 'F:\OllamaModels\Qwen3.6-35B-A3B-GGUF\Qwen3.6-35B-A3B-Q4_K_M.gguf'
  Get-ChildItem 'F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE\*.gguf' | Sort-Object Name
  Get-Item 'F:\OllamaModels\Qwen3.8-27B-AD-Q4_K_M\Qwen3.8-27B-AD-Q4_K_M.gguf'
  Get-Item 'F:\OllamaModels\Qwen2.5-Coder-14B-Instruct-Q8_0\qwen2.5-coder-14b-instruct-q8_0.gguf'
  Get-Item 'F:\OllamaModels\GLM-4.7-Flash-GGUF\GLM-4.7-Flash-Q4_K_M.gguf'
  Get-ChildItem 'F:\OllamaModels\Qwen3.8-Flash-Next-GGUF\Qwen3.8-Flash-Next-AD-IQ1_M-M64\*.gguf' | Sort-Object Name
)
$i=0
foreach ($f in $files) {
  $i++
  Write-Host ("HASH {0}/{1} {2} bytes={3}" -f $i, $files.Count, $f.Name, $f.Length)
  $h = Get-FileHash $f.FullName -Algorithm SHA256
  $manifest[$f.FullName] = @{ sha256=$h.Hash; bytes=$f.Length; name=$f.Name }
  # incremental write
  $manifest | ConvertTo-Json -Depth 6 | Set-Content "$ev\MANIFEST_SHA256.json" -Encoding UTF8
}
Write-Host 'HASH_COMPLETE'
