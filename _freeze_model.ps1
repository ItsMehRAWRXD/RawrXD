$path = "F:\~dev\Qwen3.5-40B-Q4_K_M.gguf"
$hash = Get-FileHash $path -Algorithm SHA256
$file = Get-Item $path
Write-Output "Path: $($file.FullName)"
Write-Output "Size: $($file.Length) bytes ($([math]::Round($file.Length/1GB,2)) GB)"
Write-Output "SHA256: $($hash.Hash)"
Write-Output "Modified: $($file.LastWriteTime.ToString('o'))"