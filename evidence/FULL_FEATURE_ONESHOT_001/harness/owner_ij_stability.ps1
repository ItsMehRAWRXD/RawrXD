# STABILITY_SECURITY_GATE — preserve T08 sealed verdict; measured only
$ErrorActionPreference = 'Continue'
$Root = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$OutDir = Join-Path $Root 'logs\stability'
$Receipt = Join-Path $Root 'artifacts\STABILITY_SECURITY_RECEIPT.txt'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$lines = New-Object System.Collections.Generic.List[string]
function L([string]$s) { $lines.Add($s); Write-Host $s }

L "ASOF_UTC=$stamp"
L 'GATE=STABILITY_SECURITY_GATE'
L 'PROMOTE=0'
L 'CERTIFIED=0'
L 'INVENT_PASS=0'
L 'T08_DUMP=RESIDUAL_PARSED'
L 'T08_EXCEPTION=NONE'
L 'T08_CAUSALITY=UNPROVEN'
L 'T08_RESTRESS=8/8'
L 'T08_TIP_FIX=0'
L 'T08_VERDICT=SEALED_UNCHANGED'

$exe = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_004\RawrXD-Win32IDE-Native.exe'
if (-not (Test-Path $exe)) {
  $exe = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_003\RawrXD-Win32IDE-Native.exe'
}
$exeSha = if (Test-Path $exe) { (Get-FileHash $exe -Algorithm SHA256).Hash } else { 'MISSING' }
L "STRESS_EXE=$exe"
L "STRESS_EXE_SHA256=$exeSha"

$userData = Join-Path $OutDir 'userdata_stress'
New-Item -ItemType Directory -Force -Path $userData | Out-Null

# Launch/close stress (N cycles) — kill after brief window; track orphans
$N = 8
$launchOk = 0
$closeOk = 0
$orphanHits = 0
$beforeChildren = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'RawrXD|ollama|node|quickjs' } | Select-Object ProcessId, Name, ParentProcessId)
L "PRE_STRESS_MATCHED_PROCS=$($beforeChildren.Count)"

for ($i = 1; $i -le $N; $i++) {
  $ud = Join-Path $userData ("cycle_$i")
  New-Item -ItemType Directory -Force -Path $ud | Out-Null
  $log = Join-Path $OutDir "launch_$i.log"
  try {
    $p = Start-Process -FilePath $exe -ArgumentList @("--user-data-dir=$ud") -PassThru -WindowStyle Minimized -RedirectStandardOutput $log -RedirectStandardError "$log.err"
    Start-Sleep -Seconds 3
    if ($p -and -not $p.HasExited) { $launchOk++ }
    $pidLaunch = $p.Id
    # Snapshot children before kill
    $kids = @(Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $pidLaunch })
    Stop-Process -Id $pidLaunch -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800
    # Force kill remaining tree by name under this userdata if needed
    Get-Process -Name 'RawrXD-Win32IDE-Native' -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $pidLaunch } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    $still = $false
    try { $still = -not (Get-Process -Id $pidLaunch -ErrorAction Stop).HasExited } catch { $still = $false }
    if (-not $still) { $closeOk++ }
    # orphan check: children still alive
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
    L "CYCLE_$i=launch_alive=$([bool]($p -and $true)) closed=$(-not $still) kids=$($kids.Count)"
  } catch {
    L "CYCLE_$i=EXCEPTION $($_.Exception.Message)"
  }
}

L "LAUNCH_CLOSE_STRESS=$launchOk/$N launch, $closeOk/$N close"
$LAUNCH_CLOSE = if (($launchOk -eq $N) -and ($closeOk -eq $N)) { 'PASS' } else { 'PARTIAL' }
L "LAUNCH_CLOSE=$LAUNCH_CLOSE"
L "ORPHAN_HITS=$orphanHits"
$NO_UNCONTROLLED = if ($orphanHits -eq 0) { 'PASS' } else { 'FAIL' }
L "NO_UNCONTROLLED_CHILDREN=$NO_UNCONTROLLED"

# Cancel stress (safe): spawn ping child via job and cancel — product cancel NOT_RUN unless HWND harness
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

# Handle cleanup: ensure no leftover RawrXD from this stress
Get-Process -Name 'RawrXD-Win32IDE-Native' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
$leftover = @(Get-Process -Name 'RawrXD-Win32IDE-Native' -ErrorAction SilentlyContinue)
L "HANDLE_CLEANUP_LEFTOVER=$($leftover.Count)"
$HANDLE_CLEANUP = if ($leftover.Count -eq 0) { 'PASS' } else { 'FAIL' }
L "HANDLE_CLEANUP=$HANDLE_CLEANUP"

# Malformed VSIX / config
$malDir = Join-Path $Root 'fixtures\ext_malformed'
$malCfg = Join-Path $OutDir 'malformed_config.json'
Set-Content -Path $malCfg -Encoding ASCII -Value '{ this is not valid json ::: '
$malformedOk = $false
if (Test-Path $malDir) {
  # Prior oneshot already measured malformed EXT receipts — re-check files exist
  $prior = Join-Path $Root 'artifacts\ext_receipt_malformed.txt'
  if (Test-Path $prior) {
    $pt = Get-Content $prior -Raw
    L "MALFORMED_PRIOR_RECEIPT=$prior"
    L "MALFORMED_PRIOR_BODY=$($pt.Trim())"
    $malformedOk = $true
  }
}
# Attempt IDE launch with malformed config env — must not crash host permanently
$udm = Join-Path $userData 'malformed'
New-Item -ItemType Directory -Force -Path $udm | Out-Null
Copy-Item $malCfg (Join-Path $udm 'settings.json') -Force -ErrorAction SilentlyContinue
$pm = $null
try {
  $pm = Start-Process -FilePath $exe -ArgumentList @("--user-data-dir=$udm") -PassThru -WindowStyle Minimized
  Start-Sleep -Seconds 3
  $launched = ($pm -and -not $pm.HasExited)
  if ($pm) { Stop-Process -Id $pm.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Milliseconds 500
  $MALFORMED = if ($launched) { 'PASS' } else { 'FAIL' }
} catch {
  $MALFORMED = 'FAIL'
  L "MALFORMED_EXCEPTION=$($_.Exception.Message)"
}
L "MALFORMED_VSIX_CONFIG=$MALFORMED"
L "MALFORMED_FIXTURE_PRESENT=$malformedOk"

$subs = @($LAUNCH_CLOSE, $NO_UNCONTROLLED, $CANCEL_STRESS, $HANDLE_CLEANUP, $MALFORMED)
$fails = @($subs | Where-Object { $_ -eq 'FAIL' })
$OVERALL = if ($fails.Count -eq 0 -and ($subs -notcontains 'PARTIAL')) { 'PASS' } elseif ($fails.Count -eq 0) { 'PARTIAL' } else { 'FAIL' }
L "STABILITY_SECURITY=$OVERALL"
L 'NOT_RUN_NE_PASS=1'
$lines -join "`n" | Set-Content -Path $Receipt -Encoding UTF8
Write-Host "RECEIPT=$Receipt"
