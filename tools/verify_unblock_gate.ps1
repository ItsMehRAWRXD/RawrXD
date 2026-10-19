# verify_unblock_gate.ps1 — G3_GPU1_AMDVLK_UNBLOCK_001 verification gate
# Run after P1 reboot (or after any unblock phase). Earns INCLUSION only on PASS.
param(
  [string]$PhaseTag = 'POST_P1',
  [int]$N = 5
)

$ErrorActionPreference = 'Continue'
$root = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_UNBLOCK_001'
$outDir = Join-Path $root $PhaseTag
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$exe = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_DIRECT_ICD_001\g3_amdvlk_direct_icd.exe'
$icd = 'C:\Windows\System32\DriverStore\FileRepository\amdvlk.inf_amd64_914ba89eaaafdf60\amdvlk64.dll'
$report = New-Object System.Collections.Generic.List[string]
$report.Add("GATE=G3_GPU1_AMDVLK_UNBLOCK_001")
$report.Add("VERIFY_PHASE=$PhaseTag")
$report.Add("ASOF=$(Get-Date -Format o)")
$report.Add("PROMOTE=0")
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$report.Add("LAST_BOOT=$($boot.ToString('o'))")
$p1f = Join-Path $root 'P1\P1_UNBLOCK_APPLIED.txt'
if (Test-Path $p1f) {
  $p1t = (Get-Item $p1f).LastWriteTime
  $report.Add("P1_APPLIED=$($p1t.ToString('o'))")
  $report.Add("POST_REBOOT=$([int]($boot -gt $p1t))")
}

$wmi = Get-CimInstance Win32_VideoController | Where-Object { $_.PNPDeviceID -match '747E|7551' }
foreach ($v in $wmi) {
  $report.Add("WMI_$($v.Name -replace '[^A-Za-z0-9]','_')_Availability=$($v.Availability) Status=$($v.Status)")
}

# 1) vulkaninfo --summary (SDK or System32)
$vinfo = $null
foreach ($c in @(
  'C:\Windows\System32\vulkaninfo.exe',
  'C:\VulkanSDK\1.4.341.0\Bin\vulkaninfo.exe',
  'C:\VulkanSDK\1.4.357.0\Bin\vulkaninfo.exe'
)) {
  if (Test-Path $c) { $vinfo = $c; break }
}
$cmd = Get-Command vulkaninfo.exe -ErrorAction SilentlyContinue
if (-not $vinfo -and $cmd) { $vinfo = $cmd.Source }
$report.Add("VULKANINFO_PATH=$vinfo")

$env:DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1 = '1'
Remove-Item Env:VK_LOADER_DEBUG -ErrorAction SilentlyContinue
$viOut = Join-Path $outDir 'vulkaninfo_summary.txt'
$viErr = Join-Path $outDir 'vulkaninfo_summary.err.txt'
$viExit = -1
$has7800 = $false
if (-not $vinfo) {
  $report.Add('VULKANINFO_PATH=MISSING')
} else {
  $p = Start-Process -FilePath $vinfo -ArgumentList '--summary' -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $viOut -RedirectStandardError $viErr
  $viExit = $p.ExitCode
  $viText = Get-Content $viOut -Raw -ErrorAction SilentlyContinue
  if ($null -eq $viText) { $viText = '' }
  $has7800 = [bool]([regex]::IsMatch([string]$viText, '7800'))
}
$report.Add("VULKANINFO_EXIT=$viExit")
$report.Add("VULKANINFO_LISTS_7800=$(if ($has7800) {1} else {0})")
$vinfoPass = ($viExit -eq 0 -and $has7800)
$report.Add("VULKANINFO=$(if ($vinfoPass) {'PASS'} else {'FAIL'})")

# 2) solo A0 direct ICD 5/5
$passN = 0
$a0Pass = $false
if (!(Test-Path $exe)) {
  $report.Add('SOLO_PROBE_EXE=MISSING')
} else {
  for ($i = 1; $i -le $N; $i++) {
    $o = Join-Path $outDir ("solo_a0_{0:D2}.txt" -f $i)
    $pr = Start-Process -FilePath $exe -ArgumentList @('7800', $icd) -NoNewWindow -Wait -PassThru `
      -RedirectStandardOutput $o -RedirectStandardError "$o.err"
    $t = [string](Get-Content $o -Raw -ErrorAction SilentlyContinue)
    $ok = ($t -match 'DIRECT_ICD_A0_RESULT=0\b') -or ($t -match 'DIRECT_ICD_A0=PASS\b') -or ($t -match 'DIRECT_ICD_A0_STR=VK_SUCCESS')
    if ($ok) { $passN++ }
    $report.Add("SOLO_A0_RUN_$i=exit=$($pr.ExitCode) ok=$([int][bool]$ok)")
  }
  $a0Pass = ($passN -eq $N)
  $report.Add("SOLO_RX7800XT_A0=$(if ($a0Pass) {"PASS_${passN}_OF_$N"} else {"FAIL_${passN}_OF_$N"})")
}

# 3) R9700 control
if (Test-Path $exe) {
  $o = Join-Path $outDir 'solo_a0_r9700.txt'
  $pr = Start-Process -FilePath $exe -ArgumentList @('R9700', $icd) -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $o -RedirectStandardError "$o.err"
  $t = [string](Get-Content $o -Raw -ErrorAction SilentlyContinue)
  $rOk = ($t -match 'DIRECT_ICD_A0_RESULT=0\b') -or ($t -match 'DIRECT_ICD_A0=PASS\b') -or ($t -match 'DIRECT_ICD_A0_STR=VK_SUCCESS')
  $report.Add("SOLO_R9700_A0=$(if ($rOk) {'PASS'} else {'FAIL'})")
}

$gatePass = $vinfoPass -and $a0Pass
if ($gatePass) {
  $report.Add('GATE_RESULT=PASS')
  $report.Add('RX7800XT_POOL_STATUS=INCLUDED')
  if ($PhaseTag -match 'P1|ULPS|POST_P1') {
    $report.Add('INCLUSION_MODE=NATIVE')
    $report.Add('BLOCKER_A=RESOLVED_VIA_ULPS_OFF')
    $report.Add('UNBLOCK_PHASE=P1')
  } elseif ($PhaseTag -match 'P2|WAKE') {
    $report.Add('INCLUSION_MODE=WAKE_LEASE')
    $report.Add('BLOCKER_A=MITIGATED_WAKE_LEASE')
    $report.Add('UNBLOCK_PHASE=P2')
  } else {
    $report.Add('INCLUSION_MODE=PENDING_LABEL')
    $report.Add("UNBLOCK_PHASE=$PhaseTag")
  }
} else {
  $report.Add('GATE_RESULT=FAIL')
  $report.Add('RX7800XT_POOL_STATUS=EXCLUDED')
}
$report.Add('PROMOTE=0')

$receipt = Join-Path $outDir 'RECEIPT.txt'
$report | Set-Content $receipt -Encoding ASCII
Get-Content $receipt
if ($gatePass) { exit 0 } else { exit 1 }
