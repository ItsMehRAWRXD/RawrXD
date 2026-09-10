$phi = 'G:/~dev/rawrxd/_r1_iso/02_phi3_mini/Phi-3-mini-4k-instruct-q8_0.gguf'
Write-Output "PATH=$phi"
Write-Output "EXISTS=$([IO.File]::Exists($phi))"
Get-Item -LiteralPath $phi | Format-List FullName, Length
