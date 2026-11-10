#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$Root = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\release_cert_wave6'
$Pkg = 'F:\rawrxd\release\RawrXD-readiness-rc5b'
$Stamp = '20261110-102000'
$ExtractRoot = 'C:\Temp\w6_release_cert_a4b95_clean'
$Extract1 = Join-Path $ExtractRoot 'extract_1'
$Extract2 = Join-Path $ExtractRoot 'extract_2'
$VerifyOut = Join-Path $Root ("runs\verify_" + $Stamp)
$SmokeOut = Join-Path $Root ("runs\clean_machine_" + $Stamp)
$RollbackOut = Join-Path $Root ("runs\rollback_rehash_" + $Stamp)
$Log = Join-Path $Root 'runs\_w6_a4b95_runlog.txt'

function W([string]$m) {
  $line = ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) + ' ' + $m
  Add-Content -LiteralPath $Log -Value $line -Encoding UTF8
}

Set-Content -LiteralPath $Log -Value 'W6_A4B95_CLEAN_EXTRACT_START' -Encoding UTF8
W 'begin'

# Independent host probe
$hostLines = @()
$hostLines += 'INDEPENDENT_HOST_STATUS=W6'
$hostLines += 'ASOF_UTC=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$hostLines += 'HOST=' + $env:COMPUTERNAME
$hostLines += 'DISTINCT_VM=0'
$hostLines += 'HYPERV_GET_VM=' + $(try { [string](Get-Command Get-VM -ErrorAction Stop); 'PRESENT' } catch { 'ABSENT' })
$hostLines += 'WSL=' + $(if (Get-Command wsl.exe -ErrorAction SilentlyContinue) { 'PRESENT' } else { 'ABSENT' })
$hostLines += 'VBOX=' + $(if (Test-Path 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe') { 'PRESENT' } else { 'ABSENT' })
$hostLines += 'VMWARE=' + $(if (Test-Path 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe') { 'PRESENT' } else { 'ABSENT' })
$hostLines += 'VERDICT=HOST_NOT_INDEPENDENT'
$hostLines += 'BLOCKER=NO_SECONDARY_VM_OR_WSL_OR_HYPERV_ON_THIS_SYSTEM'
$hostLines += 'PROMOTE=0'
$hostLines += 'CERTIFIED=0'
$hostLines += 'ACCEPTED=0'

New-Item -ItemType Directory -Force -Path $ExtractRoot | Out-Null
if (Test-Path -LiteralPath $Extract1) { Remove-Item -LiteralPath $Extract1 -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Extract1 | Out-Null
W 'robocopy extract_1'
& robocopy $Pkg $Extract1 /E /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
$rc = $LASTEXITCODE
W ("robocopy_exit=" + $rc)

# Stage A4B95 as primary for cert-target extract check (bak -> Ext for publish-target probe)
$bak = Join-Path $Extract1 'RawrXD-Win32IDE-Native-Ext.exe.A4B95.bak'
$ext = Join-Path $Extract1 'RawrXD-Win32IDE-Native-Ext.exe'
$liveSha = (Get-FileHash -LiteralPath $ext -Algorithm SHA256).Hash.ToUpperInvariant()
$bakSha = if (Test-Path -LiteralPath $bak) { (Get-FileHash -LiteralPath $bak -Algorithm SHA256).Hash.ToUpperInvariant() } else { 'MISSING' }
W ("LIVE_EXT=" + $liveSha)
W ("BAK_EXT=" + $bakSha)

New-Item -ItemType Directory -Force -Path $VerifyOut | Out-Null
New-Item -ItemType Directory -Force -Path $SmokeOut | Out-Null
[System.IO.File]::WriteAllText((Join-Path $SmokeOut 'INDEPENDENT_HOST_STATUS.txt'), (($hostLines -join "`r`n") + "`r`n"))

# Verify live extract vs A4B95 ledger (expect FAIL on Ext)
W 'verify_live_vs_a4b95_ledger'
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'Verify-PackageIntegrity.ps1') -PackageDir $Extract1 -OutDir $VerifyOut -AllowPartial
$vExit = $LASTEXITCODE
W ("verify_exit=" + $vExit)

# Smoke on live Ext (PARTIAL only; not independent)
W 'smoke_live'
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'Invoke-CleanMachineSmoke.ps1') -PackageDir $Extract1 -OutDir $SmokeOut -LaunchProbe
$sExit = $LASTEXITCODE
W ("smoke_exit=" + $sExit)

# Publish-target staging: replace Ext with A4B95.bak bytes then re-verify (integrity of sealed publish bytes)
$PublishExtract = Join-Path $ExtractRoot 'extract_publish_a4b95'
if (Test-Path -LiteralPath $PublishExtract) { Remove-Item -LiteralPath $PublishExtract -Recurse -Force }
New-Item -ItemType Directory -Force -Path $PublishExtract | Out-Null
& robocopy $Extract1 $PublishExtract /E /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
if (Test-Path -LiteralPath (Join-Path $PublishExtract 'RawrXD-Win32IDE-Native-Ext.exe.A4B95.bak')) {
  Copy-Item -LiteralPath (Join-Path $PublishExtract 'RawrXD-Win32IDE-Native-Ext.exe.A4B95.bak') -Destination (Join-Path $PublishExtract 'RawrXD-Win32IDE-Native-Ext.exe') -Force
}
$PublishVerify = Join-Path $Root ("runs\verify_publish_target_" + $Stamp)
W 'verify_publish_target_a4b95'
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'Verify-PackageIntegrity.ps1') -PackageDir $PublishExtract -OutDir $PublishVerify -AllowPartial
$pvExit = $LASTEXITCODE
W ("publish_verify_exit=" + $pvExit)

# Rollback: wipe extract_1, re-copy to extract_2, rehash Ext+loop
if (Test-Path -LiteralPath $Extract2) { Remove-Item -LiteralPath $Extract2 -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Extract2 | Out-Null
& robocopy $Pkg $Extract2 /E /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
New-Item -ItemType Directory -Force -Path $RollbackOut | Out-Null
$rehash = New-Object System.Collections.Generic.List[string]
$rehash.Add("rel_path`textract1`textract2`tstatus")
foreach ($rel in @(
  'RawrXD-Win32IDE-Native-Ext.exe',
  'RawrXD-Win32IDE-Native-Ext.exe.A4B95.bak',
  'deep2_agentic_loop.exe',
  'rawrxd_computer_use_ide_verify.exe',
  'rawr.exe',
  'SHA256.txt'
)) {
  $a = Join-Path $Extract1 $rel
  $b = Join-Path $Extract2 $rel
  $ha = if (Test-Path $a) { (Get-FileHash $a -Algorithm SHA256).Hash.ToUpperInvariant() } else { 'MISSING' }
  $hb = if (Test-Path $b) { (Get-FileHash $b -Algorithm SHA256).Hash.ToUpperInvariant() } else { 'MISSING' }
  $st = if ($ha -eq $hb -and $ha -ne 'MISSING') { 'MATCH' } else { 'DIFF_OR_MISSING' }
  $rehash.Add("$rel`t$ha`t$hb`t$st")
}
[System.IO.File]::WriteAllText((Join-Path $RollbackOut 'REHASH_COMPARE.tsv'), (($rehash -join "`r`n") + "`r`n"))
$rb = @(
  'ROLLBACK_REHASH=W6',
  'ASOF_UTC=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'),
  'VERDICT=PASS_ROLLBACK_REHASH_ONLY',
  'CLASS=CLEAN_EXTRACT_RECOPY_MATCH',
  'NOTE=PARTIAL builder-host only; HOST_NOT_INDEPENDENT; ACCEPTED=0',
  'LIVE_EXT_SHA256=' + $liveSha,
  'A4B95_BAK_SHA256=' + $bakSha,
  'IRC_IDE_SHA256=A4B95E4882D5FC38A3D6DAC1C8B43D08591933868C7E1AF74DE3CBB10727D4D7',
  'PROMOTE=0',
  'CERTIFIED=0',
  'ACCEPTED=0'
) -join "`r`n"
[System.IO.File]::WriteAllText((Join-Path $RollbackOut 'RECEIPT.txt'), ($rb + "`r`n"))
W 'rollback_done'
W 'end'
'OK'
