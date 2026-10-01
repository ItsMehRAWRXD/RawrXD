$Logs = 'F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\BATCH_3_model_resolution.log'
"=== /api/show with verbose=true for qwen3 ===" | Out-File $Logs -Append
$body = @{name='qwen3-next:80b'; verbose=$true} | ConvertTo-Json
$info = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/show' -Method POST -Body $body -ContentType 'application/json' -TimeoutSec 30
"keys=$($info.PSObject.Properties.Name -join ',')" | Out-File $Logs -Append
"  --- modelfile (head 30 lines) ---" | Out-File $Logs -Append
$mfLines = ($info.modelfile -split "`n")
$i = 0
foreach ($l in $mfLines) {
    if ($i -ge 30) { break }
    "  $l" | Out-File $Logs -Append
    $i++
}
"=== confirm both blobs on disk ===" | Out-File $Logs -Append
$nemBlob = 'F:\OllamaModels\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3'
"nem_blob_exists=$((Test-Path $nemBlob) -as [string]) size=$((Get-Item $nemBlob -ErrorAction SilentlyContinue).Length)" | Out-File $Logs -Append
"log=$Logs"
