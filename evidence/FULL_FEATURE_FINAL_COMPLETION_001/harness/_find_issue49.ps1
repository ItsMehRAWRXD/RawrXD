$roots = @(
  'F:\rawrxd\evidence\CC79_RUNTIME_001',
  'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001',
  'F:\rawrxd\evidence'
)
foreach ($r in $roots) {
  Write-Host "SCAN $r"
  cmd /c "dir /s /b `"$r\*issue49*.ps1`" 2>nul"
}
Write-Host '--- ARTIFACTS ---'
cmd /c "dir /a F:\rawrxd\evidence\CC79_RUNTIME_001\artifacts"
Write-Host '--- FIXTURE ---'
cmd /c "dir /s /b F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\*"
