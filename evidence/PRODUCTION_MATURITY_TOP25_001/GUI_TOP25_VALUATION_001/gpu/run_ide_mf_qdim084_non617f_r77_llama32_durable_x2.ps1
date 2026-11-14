# Durable TOK x2 remasure for NON617F 67350F71. PROMOTE=0. No tip overwrite. No SPV clobber.
$ErrorActionPreference = "Continue"
$script = "G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\gpu\run_ide_mf_qdim084_non617f_r77_llama32.ps1"
$ev = "G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\gpu"
$agg = Join-Path $ev ("ide_mf_qdim084_non617f_r77_llama32_DURABLE_X2_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".agg.txt")
$results = @()
Write-Output "DURABLE_X2_BEGIN ASOF=$((Get-Date).ToString('o'))"
for ($i = 1; $i -le 2; $i++) {
  Write-Output "==== RUN $i / 2 ===="
  $out = & $script -MaxTok 8 -RunIndex $i 2>&1 | ForEach-Object { "$_" }
  $out | ForEach-Object { Write-Output $_ }
  $line = ($out | Where-Object { $_ -match "^META=" } | Select-Object -Last 1)
  if (-not $line) { $line = "META=MISSING OPEN=0 ENTER=0 STREAM_SEH=0 TOK=0 TOKEN_SURVIVED=0 META_WRITE=FAIL" }
  $results += "RUN$i $line"
  Start-Sleep -Seconds 3
}
$passN = 0
foreach ($r in $results) {
  $ok = ($r -match "OPEN=1") -and ($r -match "ENTER=1") -and ($r -match "STREAM_SEH=0") -and ($r -match "TOK=([1-9]\d*)") -and ($r -match "META_WRITE=OK")
  # OPEN_SEH not in summary line; TOKEN_SURVIVED implies OPEN_SEH=0 and STREAM_SEH=0 when TOK>0
  if ($ok -and ($r -match "TOKEN_SURVIVED=1")) { $passN++ }
}
$durable = if ($passN -eq 2) { 1 } else { 0 }
$aggLines = @(
  "ASOF_LOCAL=$((Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz'))",
  "LANE=NON617F_67350F71_REMEASURE_TOK_X2_DURABLE",
  "PASS_N=$passN/2",
  "DURABLE=$durable",
  "PROMOTE=0",
  "TIP_CLIMB=HOLD",
  "INVENT_PASS=0",
  "CROSS_SHA_CREDIT=0",
  "SPV_CLOBBER=0",
  $results[0],
  $results[1]
)
[System.IO.File]::WriteAllText($agg, (($aggLines -join "`r`n") + "`r`n"), [System.Text.UTF8Encoding]::new($false))
Write-Output "==== AGG ===="
$aggLines | ForEach-Object { Write-Output $_ }
Write-Output "AGG_FILE=$agg"
Write-Output "DURABLE_X2_END DURABLE=$durable PASS_N=$passN/2"
