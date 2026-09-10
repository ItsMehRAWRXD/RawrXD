# run_phase0.ps1 — witness only; zero system mutation
$ErrorActionPreference = 'Continue'
$gate = Split-Path -Parent $MyInvocation.MyCommand.Path
$p0 = Join-Path $gate 'P0'
New-Item -ItemType Directory -Force -Path $p0 | Out-Null

$report = New-Object System.Collections.Generic.List[string]
$report.Add('PHASE=G3_GPU1_AMDVLK_UNBLOCK_001/P0')
$report.Add("ASOF=$(Get-Date -Format o)")
$report.Add('SYSTEM_MUTATION=0')
$report.Add('PROMOTE=0')

# WMI Availability snapshot (correlated only)
try {
  $gpus = Get-CimInstance Win32_VideoController | Select-Object Name, Availability, Status, PNPDeviceID
  $gpus | Format-List | Out-String | Set-Content (Join-Path $p0 'wmi_videocontroller.txt') -Encoding ASCII
  foreach ($g in $gpus) {
    $report.Add("WMI_NAME=$($g.Name)|Availability=$($g.Availability)|Status=$($g.Status)")
  }
} catch {
  $report.Add("WMI_ERR=$($_.Exception.Message)")
}

# VK_LOADER_DEBUG=all vulkaninfo --summary
$env:VK_LOADER_DEBUG = 'all'
$vkOut = Join-Path $p0 'loader_trace_stdout.txt'
$vkErr = Join-Path $p0 'loader_trace.txt'
$vi = 'C:\Windows\System32\vulkaninfo.exe'
$p = Start-Process -FilePath $vi -ArgumentList '--summary' -NoNewWindow -Wait -PassThru `
  -RedirectStandardOutput $vkOut -RedirectStandardError $vkErr
$report.Add("VULKANINFO_EXIT=$($p.ExitCode)")
Remove-Item Env:VK_LOADER_DEBUG -ErrorAction SilentlyContinue

# Grep loader_trace for ICD / create / error
$errBody = Get-Content $vkErr -Raw -ErrorAction SilentlyContinue
$hits = @()
if ($errBody -match 'amdvlk') { $hits += 'amdvlk_mentioned' }
if ($errBody -match 'CreateDevice|create_device|vkCreateDevice') { $hits += 'create_device_mentioned' }
if ($errBody -match 'ERROR|error|failed|Failed') { $hits += 'error_tokens' }
$report.Add("LOADER_TRACE_FLAGS=$($hits -join ',')")
$report.Add("LOADER_TRACE_BYTES=$((Get-Item $vkErr -ErrorAction SilentlyContinue).Length)")

# Event Viewer: Display / amdkmdap / amdkmdag around now (±10 min)
$start = (Get-Date).AddMinutes(-10)
$evtOut = Join-Path $p0 'evt_display_amdkmd.txt'
try {
  $logs = @('System', 'Application')
  $lines = New-Object System.Collections.Generic.List[string]
  foreach ($log in $logs) {
    Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start } -ErrorAction SilentlyContinue |
      Where-Object {
        $_.ProviderName -match 'Display|amdkmdap|amdkmdag|AMD|DxgKrnl|Kernel-PnP' -or
        $_.Message -match '7800|amdvlk|amdkmd'
      } |
      Select-Object -First 80 TimeCreated, Id, ProviderName, LevelDisplayName, Message |
      ForEach-Object {
        $lines.Add("$($_.TimeCreated) [$($_.ProviderName)] id=$($_.Id) $($_.LevelDisplayName)")
        $msg = ($_.Message -replace '\r?\n', ' ')
        if ($msg.Length -gt 240) { $msg = $msg.Substring(0, 240) + '...' }
        $lines.Add("  $msg")
      }
  }
  if ($lines.Count -eq 0) { $lines.Add('NO_MATCHING_EVENTS_IN_WINDOW') }
  $lines | Set-Content $evtOut -Encoding ASCII
  $report.Add("EVT_LINES=$($lines.Count)")
} catch {
  $report.Add("EVT_ERR=$($_.Exception.Message)")
  "EVT_CAPTURE_FAILED=$($_.Exception.Message)" | Set-Content $evtOut -Encoding ASCII
}

# Baseline solo A0 fail (1 run) — preserves pre-mutation witness
$exe = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_DIRECT_ICD_001\g3_amdvlk_direct_icd.exe'
$icd = 'C:\Windows\System32\DriverStore\FileRepository\amdvlk.inf_amd64_914ba89eaaafdf60\amdvlk64.dll'
$a0 = Join-Path $p0 'baseline_A0_7800.txt'
if (Test-Path $exe) {
  $ap = Start-Process -FilePath $exe -ArgumentList @('7800', $icd) -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $a0 -RedirectStandardError (Join-Path $p0 'baseline_A0_7800.err.txt')
  $body = Get-Content $a0 -Raw
  $report.Add("BASELINE_A0_EXIT=$($ap.ExitCode)")
  if ($body -match 'DIRECT_ICD_A0_RESULT=(-?\d+)') { $report.Add("BASELINE_A0_RESULT=$($Matches[1])") }
  if ($body -match 'DIRECT_ICD_A0_STR=(\S+)') { $report.Add("BASELINE_A0_STR=$($Matches[1])") }
} else {
  $report.Add('BASELINE_A0=EXE_MISSING')
}

$report.Add('WINDBG=SKIPPED_OPTIONAL')
$report.Add('PHASE0_WITNESS={VK_LOADER_TRACE,EVT_LOG,BASELINE_A0,WMI}')
$report.Add('NEXT=P1_unblock_phase1.ps1_AS_ADMIN_THEN_REBOOT')

$out = Join-Path $p0 'PHASE0_WITNESS.txt'
$report | Set-Content $out -Encoding ASCII
Get-Content $out
