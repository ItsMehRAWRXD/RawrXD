$ErrorActionPreference = "Stop"
$root = Join-Path $PSScriptRoot "src\remote64"
$asm = Get-ChildItem $root -Filter *.asm
if (-not $asm) { throw "No ASM sources" }
$bad = Select-String -Path $asm.FullName -Pattern 'TODO|FIXME|placeholder|not implemented' -SimpleMatch:$false
if ($bad) { $bad | Format-Table; throw "Placeholder markers found" }
Write-Host "ASM_TU_COUNT=$($asm.Count)"
Write-Host "STATIC_PLACEHOLDER_SCAN=PASS"
Write-Host "NOTE=Static scan is not build/runtime certification."
