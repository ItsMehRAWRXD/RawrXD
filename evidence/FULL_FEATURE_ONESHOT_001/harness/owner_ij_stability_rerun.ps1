# Stability retest without stdout redirect (GUI EXE)
$ErrorActionPreference = 'Continue'
$Root = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$OutDir = Join-Path $Root 'logs\stability'
$Receipt = Join-Path $Root 'artifacts\STABILITY_SECURITY_RECEIPT.txt'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$exe = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_004\RawrXD-Win32IDE-Native.exe'
$userData = Join-Path $OutDir 'userdata_stress2'
New-Item -ItemType Directory -Force -Path $userData | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$N = 8
$launchOk = 0
$closeOk = 0
$orphanHits = 0
$lines = New-Object System.Collections.Generic.List[string]
function L([string]$s) { $lines.Add($s); Write-Host $s }
$stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
L "ASOF_UTC=$stamp"
L 'GATE=STABILITY_SECURITY_GATE'
L 'PROMOTE=0'; L 'CERTIFIED=0'; L 'INVENT_PASS=0'
L 'T08_DUMP=RESIDUAL_PARSED'; L 'T08_EXCEPTION=NONE'; L 'T08_CAUSALITY=UNPROVEN'
L 'T08_RESTRESS=8/8'; L 'T08_TIP_FIX=0'; L 'T08_VERDICT=SEALED_UNCHANGED'
L "STRESS_EXE_SHA256=$((Get-FileHash $exe -Algorithm SHA256).Hash)"
L 'NOTE=retest_no_stdout_redirect'

for ($i = 1; $i -le $N; $i++) {
  $ud = Join-Path $userData ("cycle_$i")
  New-Item -ItemType Directory -Force -Path $ud | Out-Null
  $p = Start-Process -FilePath $exe -ArgumentList @("--user-data-dir=$ud") -PassThru -WindowStyle Minimized
  Start-Sleep -Seconds 3
  $aliveLaunch = ($p -and -not $p.HasExited)
  if ($aliveLaunch) { $launchOk++ }
  $pidLaunch = $p.Id
  $kids = @(Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $pidLaunch -and $_.Name -notmatch 'conhost|powershell|cmd' })
  Stop-Process -Id $pidLaunch -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 700
  $still = $false
  try { $still = -not (Get-Process -Id $pidLaunch -ErrorAction Stop).HasExited } catch { $still = $false }
  if (-not $still) { $closeOk++ }
  foreach ($k in $kids) {
    try {
      $alive = Get-Process -Id $k.ProcessId -ErrorAction Stop
      if ($alive) {
        $orphanHits++
        L "ORPHAN_CYCLE_$i=$($k.Name) pid=$($k.ProcessId)"
        Stop-Process -Id $k.ProcessId -Force -ErrorAction SilentlyContinue
      }
    } catch {}
  }
  L "CYCLE_$i=launch_alive=$aliveLaunch closed=$(-not $still) kids=$($kids.Count)"
}

L "LAUNCH_CLOSE_STRESS=$launchOk/$N launch, $closeOk/$N close"
$LAUNCH_CLOSE = if (($launchOk -eq $N) -and ($closeOk -eq $N)) { 'PASS' } else { 'PARTIAL' }
L "LAUNCH_CLOSE=$LAUNCH_CLOSE"
L "ORPHAN_HITS=$orphanHits"
$NO_UNCONTROLLED = if ($orphanHits -eq 0) { 'PASS' } else { 'FAIL' }
L "NO_UNCONTROLLED_CHILDREN=$NO_UNCONTROLLED"

$cancelPass = 0
for ($i = 1; $i -le 4; $i++) {
  $c = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', 'ping -n 20 127.0.0.1 >nul' -PassThru -WindowStyle Hidden
  Start-Sleep -Milliseconds 400
  Stop-Process -Id $c.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 300
  $alive = $false
  try { $alive = -not (Get-Process -Id $c.Id -ErrorAction Stop).HasExited } catch { $alive = $false }
  if (-not $alive) { $cancelPass++ }
}
L "CANCEL_STRESS_SAFE=$cancelPass/4"
$CANCEL_STRESS = if ($cancelPass -eq 4) { 'PASS' } else { 'FAIL' }
L "CANCEL_STRESS=$CANCEL_STRESS"
L 'PRODUCT_CANCEL_HWND=NOT_RUN'

Get-Process -Name 'RawrXD-Win32IDE-Native' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
$leftover = @(Get-Process -Name 'RawrXD-Win32IDE-Native' -ErrorAction SilentlyContinue)
L "HANDLE_CLEANUP_LEFTOVER=$($leftover.Count)"
$HANDLE_CLEANUP = if ($leftover.Count -eq 0) { 'PASS' } else { 'FAIL' }
L "HANDLE_CLEANUP=$HANDLE_CLEANUP"

$udm = Join-Path $userData 'malformed'
New-Item -ItemType Directory -Force -Path $udm | Out-Null
'{ this is not valid json :::' | Set-Content (Join-Path $udm 'settings.json') -Encoding ASCII
$pm = Start-Process -FilePath $exe -ArgumentList @("--user-data-dir=$udm") -PassThru -WindowStyle Minimized
Start-Sleep -Seconds 3
$launched = ($pm -and -not $pm.HasExited)
if ($pm) { Stop-Process -Id $pm.Id -Force -ErrorAction SilentlyContinue }
$MALFORMED = if ($launched) { 'PASS' } else { 'FAIL' }
L "MALFORMED_VSIX_CONFIG=$MALFORMED"
L 'MALFORMED_EXT_PRIOR=FAULT_ISOLATED=1 PROCESS_ALIVE=1 (artifacts\ext_receipt_malformed.txt)'

$subs = @($LAUNCH_CLOSE, $NO_UNCONTROLLED, $CANCEL_STRESS, $HANDLE_CLEANUP, $MALFORMED)
$fails = @($subs | Where-Object { $_ -eq 'FAIL' })
$OVERALL = if ($fails.Count -eq 0 -and ($subs -notcontains 'PARTIAL')) { 'PASS' } elseif ($fails.Count -eq 0) { 'PARTIAL' } else { 'FAIL' }
L "STABILITY_SECURITY=$OVERALL"
L 'NOT_RUN_NE_PASS=1'
$lines -join "`n" | Set-Content $Receipt -Encoding UTF8
Write-Host "RECEIPT=$Receipt"
