# Create minimal GGUF file
$magic = [byte[]](0x47, 0x47, 0x55, 0x46)  # 'GGUF'
$version = [System.BitConverter]::GetBytes([uint32]3)
$tensorCount = [System.BitConverter]::GetBytes([uint64]0)
$metadataCount = [System.BitConverter]::GetBytes([uint64]0)

$ggufData = $magic + $version + $tensorCount + $metadataCount
$outPath = 'D:\temp\test-model.gguf'
[System.IO.File]::WriteAllBytes($outPath, $ggufData)
Write-Host "Created GGUF file: $($ggufData.Length) bytes at $outPath"
