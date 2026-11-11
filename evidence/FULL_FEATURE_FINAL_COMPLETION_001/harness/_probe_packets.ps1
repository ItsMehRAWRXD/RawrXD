$ErrorActionPreference = 'Continue'
$base = 'F:\rawrxd\evidence\CC79_RUNTIME_001'
Write-Host "BASE_EXISTS=$([IO.Directory]::Exists($base))"
cmd /c "dir /a `"$base`""
Write-Host '---'
$pkt = Join-Path $base 'packets'
Write-Host "PKT_EXISTS_IO=$([IO.Directory]::Exists($pkt))"
Write-Host "PKT_EXISTS_TP=$(Test-Path -LiteralPath $pkt)"
cmd /c "dir /a `"$pkt`""
Write-Host '---'
$src = Join-Path $pkt 'issue49_product_final_tip002.ps1'
Write-Host "SRC_EXISTS_IO=$([IO.File]::Exists($src))"
cmd /c "dir /a `"$src`""
cmd /c "cd /d `"$pkt`" && dir /a && copy /Y issue49_product_final_tip002.ps1 F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\harness\issue49_ORIG.ps1"
Write-Host "DST_EXISTS=$([IO.File]::Exists('F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\harness\issue49_ORIG.ps1'))"
