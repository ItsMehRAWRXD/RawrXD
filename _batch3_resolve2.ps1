$Logs = 'F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\BATCH_3_model_resolution.log'
"=== /api/show with verbose=true for nemotron ===" | Out-File $Logs -Append
$body = @{name='nemotron-3.5-lightning:30b'; verbose=$true} | ConvertTo-Json
$info = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/show' -Method POST -Body $body -ContentType 'application/json' -TimeoutSec 30
"keys=$($info.PSObject.Properties.Name -join ',')" | Out-File $Logs -Append
foreach ($k in @('manifest','blob','modelfile','model_info','details')) {
    if ($info.PSObject.Properties.Name -contains $k) {
        $v = $info.$k
        "  --- $k (truncated) ---" | Out-File $Logs -Append
        $s = ($v | Out-String)
        if ($s.Length -gt 800) { $s.Substring(0,800) + '...[truncated]' } else { $s }
        $s | Out-File $Logs -Append
    }
}
"=== /api/show with verbose=true for qwen3 ===" | Out-File $Logs -Append
$body = @{name='qwen3-next:80b'; verbose=$true} | ConvertTo-Json
$info = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/show' -Method POST -Body $body -ContentType 'application/json' -TimeoutSec 30
foreach ($k in @('manifest','blob','modelfile','model_info','details')) {
    if ($info.PSObject.Properties.Name -contains $k) {
        $v = $info.$k
        "  --- $k (truncated) ---" | Out-File $Logs -Append
        $s = ($v | Out-String)
        if ($s.Length -gt 800) { $s.Substring(0,800) + '...[truncated]' } else { $s }
        $s | Out-File $Logs -Append
    }
}
"log=$Logs"
