# Real all-shard structural verification for the three model assets.
# This test never writes model directories.  Use --full-hash separately when
# archival SHA-256 of every shard is required; the default is structural-only.
$ErrorActionPreference = 'Stop'
$exe = 'F:\rawrxd\build_reap\bin-msvc\rawr-reap.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "rawr-reap not found: $exe" }

$models = @(
    @{ Name='DeepSeek'; First='F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf'; Shards=11; Tensors=1025; Architecture='deepseek2'; Calibratable=$true },
    @{ Name='MiniMax'; First='F:\OllamaModels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf'; Shards=3; Tensors=809; Architecture='minimax-m2'; Calibratable=$false },
    @{ Name='Kimi-K2'; First='F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf'; Shards=13; Tensors=1096; Architecture='deepseek2'; Calibratable=$true }
)

$fullHash = $args -contains '--full-hash'
$failures = 0
foreach ($model in $models) {
    $receipt = Join-Path 'F:\rawrxd\evidence' ("reap_shard_verification_{0}_20261026.json" -f $model.Name.ToLower())
    $verifyArgs = @('verify', $model.First, '--receipt', $receipt)
    if (-not $fullHash) { $verifyArgs += '--structural-only' }
    $raw = & $exe @verifyArgs 2>&1 | Out-String
    $code = $LASTEXITCODE
    if ($code -ne 0) { Write-Host "[FAIL] $($model.Name): verify exit $code"; $failures++; continue }
    $doc = $raw | ConvertFrom-Json
    $ok = $doc.all_shards_present -and ($doc.shards -eq $model.Shards) -and
          ($doc.loader_shards -eq $model.Shards) -and ($doc.loader_tensors -eq $model.Tensors) -and
          $doc.originals_unchanged
    if ($fullHash) { $ok = $ok -and ($doc.hash_scope -eq 'all_shards_sha256') -and
                              (($doc.records | Where-Object { [string]::IsNullOrEmpty($_.sha256) }).Count -eq 0) }
    if ($ok) { Write-Host "[PASS] $($model.Name): $($doc.shards) shards, $($doc.loader_tensors) tensors, $($doc.hash_scope)" }
    else { Write-Host "[FAIL] $($model.Name): receipt validation failed"; $failures++ }
}
foreach ($model in $models) {
    $capRaw = & $exe capabilities $model.First 2>&1 | Out-String
    $capCode = $LASTEXITCODE
    $cap = $capRaw | ConvertFrom-Json
    $capOk = ($cap.format -eq 'gguf') -and $cap.inspectable -and
             ($cap.architecture -eq $model.Architecture) -and
             ($cap.calibratable -eq $model.Calibratable) -and ($cap.transformable -eq $false)
    # Unsupported runtime architectures are expected to deny calibration; the
    # denial must be explicit rather than a false positive.
    if (-not $model.Calibratable) { $capOk = $capOk -and ($capCode -eq 4) -and ($cap.reason -like 'architecture_runtime_not_supported:*') }
    else { $capOk = $capOk -and ($capCode -eq 0) }
    if ($capOk) { Write-Host "[PASS] $($model.Name): capability $($cap.architecture), calibratable=$($cap.calibratable)" }
    else { Write-Host "[FAIL] $($model.Name): capability report mismatch"; $failures++ }
}
if ($failures) { exit 1 }
Write-Host 'ALL REAP SHARD AND CAPABILITY VERIFICATION TESTS PASSED'
exit 0
