$Logs='F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\BATCH_3_model_resolution.log'
"=== Ollama /api/show for nemotron + qwen3 ===" | Out-File $Logs -Append
$names = @('nemotron-3.5-lightning:30b','qwen3-next:80b')
foreach ($m in $names) {
    try {
        $info = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/show' -Method POST -Body (@{name=$m} | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 30
        "model=$m" | Out-File $Logs -Append
        "  details_format=$($info.details.format)" | Out-File $Logs -Append
        "  details_family=$($info.details.family)" | Out-File $Logs -Append
        "  details_param_size=$($info.details.parameter_size)" | Out-File $Logs -Append
        "  details_quantization_level=$($info.details.quantization_level)" | Out-File $Logs -Append
        "  model_info_keys=$($info.model_info.PSObject.Properties.Name -join ',')" | Out-File $Logs -Append
    } catch {
        "model=$m ERROR: $_" | Out-File $Logs -Append
    }
    "----" | Out-File $Logs -Append
}
"=== find manifests by digest prefix ===" | Out-File $Logs -Append
$nemDigest='e7a64ff15fb174c42b4f463e5c888c4f2c7b9cabf9e8d65a1c0874405426c1b2'
$qwenDigest='b2ebb986e4e960bb3f2d636472a466b4027939c4d8d9a62fc82bed8ebfd1ae19'
$nemManifest = Get-ChildItem 'F:\OllamaModels\manifests\registry.ollama.ai' -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$nemDigest*" }
$qwenManifest = Get-ChildItem 'F:\OllamaModels\manifests\registry.ollama.ai' -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$qwenDigest*" }
"nem_manifest_count=$($nemManifest.Count)" | Out-File $Logs -Append
"qwen_manifest_count=$($qwenManifest.Count)" | Out-File $Logs -Append
foreach ($m in $nemManifest) { "  nem=$($m.FullName) size=$($m.Length)" | Out-File $Logs -Append }
foreach ($m in $qwenManifest) { "  qwen=$($m.FullName) size=$($m.Length)" | Out-File $Logs -Append }
"=== read nemotron manifest contents ===" | Out-File $Logs -Append
foreach ($m in $nemManifest) {
    "--- $($m.FullName) ---" | Out-File $Logs -Append
    Get-Content $m.FullName | Out-File $Logs -Append
}
"=== read qwen3 manifest contents ===" | Out-File $Logs -Append
foreach ($m in $qwenManifest) {
    "--- $($m.FullName) ---" | Out-File $Logs -Append
    Get-Content $m.FullName | Out-File $Logs -Append
}
"log=$Logs"
