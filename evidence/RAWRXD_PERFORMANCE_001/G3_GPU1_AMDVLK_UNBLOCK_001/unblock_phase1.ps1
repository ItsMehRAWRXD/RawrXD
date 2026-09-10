# unblock_phase1.ps1 -- G3_GPU1_AMDVLK_UNBLOCK_001 Phase 1
# Zero-cost state resets. Run as Administrator. REBOOT afterward, then
# verification_gate.ps1 -PhaseDir P1. Idempotent; safe to re-run.

$ErrorActionPreference = 'Continue'
$gate = Split-Path -Parent $MyInvocation.MyCommand.Path
$p1 = Join-Path $gate 'P1'
New-Item -ItemType Directory -Force -Path $p1 | Out-Null

$report = New-Object System.Collections.Generic.List[string]
$report.Add('PHASE=G3_GPU1_AMDVLK_UNBLOCK_001/P1')
$report.Add("ASOF=$(Get-Date -Format o)")
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$report.Add("IS_ADMIN=$isAdmin")
if (-not $isAdmin) {
  $report.Add('STATUS=NEED_ADMIN')
  $report.Add('NEXT=Re-run elevated: Start-Process powershell -Verb RunAs -ArgumentList ...')
  $out = Join-Path $p1 'P1_UNBLOCK_APPLIED.txt'
  $report | Set-Content $out -Encoding ASCII
  Get-Content $out
  exit 2
}

function Set-DwordChecked([string]$Path, [string]$Name, [int]$Value, [string]$Tag) {
  try {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
    $got = [int](Get-ItemProperty -Path $Path -Name $Name).$Name
    if ($got -eq $Value) { $script:report.Add("$Tag=OK value=$got"); return $true }
    $script:report.Add("$Tag=VERIFY_FAIL want=$Value got=$got"); return $false
  } catch {
    $script:report.Add("$Tag=FAIL $($_.Exception.Message)"); return $false
  }
}

# --- 1. Purge AMD caches -----------------------------------------------------
foreach ($p in @("$env:LOCALAPPDATA\AMD\VkCache", "$env:LOCALAPPDATA\AMD\DxCache")) {
  if (Test-Path $p) {
    Remove-Item -Recurse -Force $p -ErrorAction SilentlyContinue
    $report.Add("PURGED=$p")
  } else {
    $report.Add("ABSENT=$p")
  }
}

# --- 2. Disable ULPS on every AMD display-class subkey -----------------------
$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
$hit = 0
Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
  if ($_.Property -contains 'EnableUlps') {
    if (Set-DwordChecked $_.PSPath 'EnableUlps' 0 "ULPS_$($_.PSChildName)") { $hit++ }
  }
}
if ($hit -eq 0) { $report.Add('ULPS_KEY_NOT_FOUND_OR_ALL_FAILED') }

# --- 3. Disable MPO ---
[void](Set-DwordChecked 'HKLM:\SOFTWARE\Microsoft\Windows\Dwm' 'OverlayTestMode' 5 'MPO')

# --- 4. HAGS off ---
[void](Set-DwordChecked 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode' 1 'HAGS')

# --- 5. PCIe ASPM off ---
powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0 2>$null
powercfg /setdcvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0 2>$null
powercfg /setactive SCHEME_CURRENT
$report.Add('ASPM=OFF_SCHEME_CURRENT')

$report.Add('STATUS=APPLIED')
$report.Add('NEXT=REBOOT_THEN_verification_gate.ps1_-PhaseDir_P1')
$out = Join-Path $p1 'P1_UNBLOCK_APPLIED.txt'
$report | Set-Content $out -Encoding ASCII
Get-Content $out
