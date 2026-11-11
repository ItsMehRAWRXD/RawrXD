$ErrorActionPreference = 'Continue'
$cli = 'F:\rawrxd\build_repair_candidate\bin-msvc\rawr.exe'
$ws  = 'F:\rawrxd\evidence\REPAIR_FINISH25_001\AGENT\T15_ARG_CONTRACT'
$marker = 'T15ARG_da5080bd'
$rel = "t15_contract_$marker.cpp"
$fixture = Join-Path $ws $rel
$edited = "T15_EDITED_$marker"
$stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$runlog = 'F:\rawrxd\evidence\REPAIR_FINISH25_001\AGENT\T15_ARG_CONTRACT_RUNLOG.txt'
$cliSha = (Get-FileHash $cli -Algorithm SHA256).Hash

$motdDir = Join-Path $ws '.cursor\rules'
New-Item -ItemType Directory -Force -Path $motdDir | Out-Null
Copy-Item -Force 'F:\rawrxd\.cursor\rules\PassiveRoleNotRoleplay.mdc' (Join-Path $motdDir 'PassiveRoleNotRoleplay.mdc')

function Reset-Fixture {
  [System.IO.File]::WriteAllText($fixture, "// EDIT_ME $marker`r`nint before = 0;`r`n")
}

function Log([string]$m) {
  $line = "[$((Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK'))] $m"
  Add-Content -Path $runlog -Value $line
  Write-Host $line
}

Add-Content -Path $runlog -Value ''
Log "==== T15 WORKSPACE-SCOPED APPLY REBUILD TRIALS ===="
Log "CLI=$cli SHA=$cliSha"
Log "WS=$ws FIXTURE=$fixture MARKER=$marker EDITED=$edited CMD_SHAPE=tools run ... --workspace <dir>"

# DENY
Reset-Fixture
Remove-Item Env:RAWRXD_TOOLS_APPROVE_MUTATIONS -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_GUI_APPROVE_MUTATIONS -ErrorAction SilentlyContinue
$denyOut = & $cli tools run editFiles --workspace $ws --mode autonomous "path=$rel" "old=int before = 0;" "new=int after = 1; // $edited" 2>&1 | Out-String
$denyExit = $LASTEXITCODE
$denyDisk = [System.IO.File]::ReadAllText($fixture)
$denyImproved = ($denyOut -match 'mutation approval missing')
Log "TRIAL=DENY_NO_APPROVE EXIT=$denyExit IMPROVED=$denyImproved"
Log "DENY_STDOUT<<$($denyOut.Trim())>>"
Log "DENY_DISK<<$($denyDisk.Trim())>>"

# APPROVE FLAG
Reset-Fixture
Remove-Item Env:RAWRXD_TOOLS_APPROVE_MUTATIONS -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_GUI_APPROVE_MUTATIONS -ErrorAction SilentlyContinue
$flagOut = & $cli tools run editFiles --workspace $ws --mode autonomous --approve-mutations "path=$rel" "old=int before = 0;" "new=int after = 1; // $edited" 2>&1 | Out-String
$flagExit = $LASTEXITCODE
$flagDisk = [System.IO.File]::ReadAllText($fixture)
$fileShaFlag = (Get-FileHash $fixture -Algorithm SHA256).Hash
$flagOk = ($flagExit -eq 0) -and $flagDisk.Contains($edited) -and $flagDisk.Contains($marker)
Log "TRIAL=APPROVE_FLAG EXIT=$flagExit FILE_SHA=$fileShaFlag OK=$flagOk"
Log "FLAG_STDOUT<<$($flagOut.Trim())>>"
Log "FLAG_DISK<<$($flagDisk.Trim())>>"

# GUI ENV ALIAS
Reset-Fixture
Remove-Item Env:RAWRXD_TOOLS_APPROVE_MUTATIONS -ErrorAction SilentlyContinue
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$guiOut = & $cli tools run editFiles --workspace $ws --mode autonomous "path=$rel" "old=int before = 0;" "new=int after = 1; // $edited" 2>&1 | Out-String
$guiExit = $LASTEXITCODE
$guiDisk = [System.IO.File]::ReadAllText($fixture)
$fileShaGui = (Get-FileHash $fixture -Algorithm SHA256).Hash
$guiOk = ($guiExit -eq 0) -and $guiDisk.Contains($edited) -and $guiDisk.Contains($marker)
Remove-Item Env:RAWRXD_GUI_APPROVE_MUTATIONS -ErrorAction SilentlyContinue
Log "TRIAL=GUI_ENV_ALIAS EXIT=$guiExit FILE_SHA=$fileShaGui OK=$guiOk"
Log "GUI_STDOUT<<$($guiOut.Trim())>>"
Log "GUI_DISK<<$($guiDisk.Trim())>>"

# FINAL SEAL = approve-flag disk
Reset-Fixture
Remove-Item Env:RAWRXD_TOOLS_APPROVE_MUTATIONS -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_GUI_APPROVE_MUTATIONS -ErrorAction SilentlyContinue
$finalOut = & $cli tools run editFiles --workspace $ws --mode autonomous --approve-mutations "path=$rel" "old=int before = 0;" "new=int after = 1; // $edited" 2>&1 | Out-String
$finalExit = $LASTEXITCODE
$finalDisk = [System.IO.File]::ReadAllText($fixture)
$finalSha = (Get-FileHash $fixture -Algorithm SHA256).Hash
Log "TRIAL=FINAL_SEAL EXIT=$finalExit FILE_SHA=$finalSha"
Log "FINAL_DISK<<$($finalDisk.Trim())>>"
Log "FINAL_STDOUT<<$($finalOut.Trim())>>"

$t15Auto = if (($denyExit -ne 0) -and $denyImproved -and (-not $denyDisk.Contains($edited))) { 'DENIED_IMPROVED' } else { 'CHECK' }
$t15Flag = if ($flagOk) { 'PASS' } else { "FAIL exit=$flagExit" }
$t15Gui  = if ($guiOk) { 'PASS' } else { "FAIL exit=$guiExit" }
$diskMarker = if (($finalExit -eq 0) -and $finalDisk.Contains($marker) -and $finalDisk.Contains($edited)) { $edited } else { 'MISSING' }

$lines = @(
  "ASOF_UTC=$stamp"
  "CLI=$cli"
  "CLI_SHA=$cliSha"
  "WORKSPACE=$ws"
  "FIXTURE=$fixture"
  "MARKER=$marker"
  "EDITED=$edited"
  "T15_AUTONOMOUS_APPLY=$t15Auto"
  "T15_APPROVE_FLAG_APPLY=$t15Flag"
  "T15_GUI_ENV_ALIAS=$t15Gui"
  "DISK_MARKER=$diskMarker"
  "FILE_SHA=$finalSha"
  "FINAL_EXIT=$finalExit"
  "DENY_IMPROVED=$denyImproved"
  "DENY_EXIT=$denyExit"
  "FLAG_EXIT=$flagExit"
  "GUI_EXIT=$guiExit"
  "CMD_SHAPE=rawr tools run editFiles --workspace <dir> ..."
  "PROMOTE=0"
  "FINISH_25_PASS=19"
  "T24_INSTALLER=NOT_RUN"
)
$lines | Set-Content -Path (Join-Path $ws 'T15_APPLY_SUMMARY.txt') -Encoding ascii
$lines | ForEach-Object { Write-Host $_ }
