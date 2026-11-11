$exe = "F:\rawrxd\_e2e\bin\Release\deep2_runtime_dispatch.exe"

$models = @(
    "gemma3_latest.gguf",
    "nemotron-3-nano_4b.gguf",
    "kiminoto_T0.0.1_latest.gguf",
    "deepseek-coder-v2_16b.gguf"
)

foreach ($m in $models) {
    $path = "F:\rawrxd\models\$m"
    if (!(Test-Path $path)) { continue }

    Write-Host "`n========== $m =========="

    $log = "F:\rawrxd\diag_$m.log"

    & $exe --model $path --tokens 4 *> $log

    Write-Host "EXIT=$LASTEXITCODE"

    Select-String -Path $log -Pattern `
      "\[FAIL\]|failed:|error:|BIND_FAILED|GRAPH_BIND|gpu fail|cpu fail|GPU_TARGET_FORWARD|REFERENCE_FORWARD|GPU_ONLY_VERDICT|PARITY_VERDICT|VERDICT=" |
      ForEach-Object { $_.Line.Trim() } |
      Select-Object -First 35
}
