$ErrorActionPreference = 'Stop'
$src = 'F:\rawrxd\evidence\CC79_RUNTIME_001\packets\issue49_product_final_tip002.ps1'
$dst = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\harness\issue49_ORIG.ps1'
Write-Host "SRC_EXISTS=$([IO.File]::Exists($src))"
Write-Host "SRC_DIR_EXISTS=$([IO.Directory]::Exists((Split-Path $src)))"
if (-not [IO.File]::Exists($src)) {
  Get-ChildItem -LiteralPath (Split-Path $src) -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
  throw "missing src"
}
[IO.File]::Copy($src, $dst, $true)
Write-Host "COPIED=$dst LEN=$((Get-Item -LiteralPath $dst).Length)"
