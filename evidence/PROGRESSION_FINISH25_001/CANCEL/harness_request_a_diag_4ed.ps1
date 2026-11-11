#Requires -Version 5.1
$ErrorActionPreference = "Continue"
$OutDir = "F:\rawrxd\evidence\PROGRESSION_FINISH25_001\CANCEL"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$DiagLog = Join-Path $OutDir ("logs\request_a_ctrl_diag_{0}.log" -f $Stamp)
$env:RAWRXD_REQUEST_A_DIAG_LOG = $DiagLog
New-Item -ItemType Directory -Force -Path (Split-Path $DiagLog) | Out-Null
if (Test-Path $DiagLog) { Remove-Item $DiagLog -Force }
Write-Output "WRAPPER_DIAG_LOG=$DiagLog"
& "F:\rawrxd\evidence\PROGRESSION_FINISH25_001\CANCEL\harness_request_a_survival_progression.ps1"
$code = $LASTEXITCODE
"WRAPPER_EXIT=$code"
"WRAPPER_DIAG_BYTES=$((if (Test-Path $DiagLog) { (Get-Item $DiagLog).Length } else { 0 }))"
if (Test-Path $DiagLog) {
  Copy-Item $DiagLog (Join-Path $OutDir "logs\request_a_ctrl_diag_LATEST.log") -Force
}
exit $code
