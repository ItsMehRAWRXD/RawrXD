$Logs = 'F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\BATCH_3_model_resolution.log'
"=== qwen3 fetch retry ===" | Out-File $Logs -Append
try {
    $body = @{name='qwen3-next:80b'; verbose=$true} | ConvertTo-Json
    $info = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/show' -Method POST -Body $body -ContentType 'application/json' -TimeoutSec 60
    "ok, modelfile_len=$($info.modelfile.Length)" | Out-File $Logs -Append
    $lines = ($info.modelfile -split "`n")
    "  modelfile lines=$($lines.Count)" | Out-File $Logs -Append
    $i = 0
    foreach ($l in $lines) {
        if ($i -ge 10) { break }
        "  $l" | Out-File $Logs -Append
        $i++
    }
} catch {
    "ERROR: $_" | Out-File $Logs -Append
}
"done"
