# unblock_phase1.ps1 -- G3_GPU1_AMDVLK_UNBLOCK_001 Phase 1
# Zero-cost state resets. Run as Administrator. REBOOT afterward, then run
# verify_unblock_gate.ps1 (vulkaninfo --summary + solo A0 probe 5/5).
# Idempotent; safe to re-run.

$ErrorActionPreference = 'Continue'
$root = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_UNBLOCK_001'
$p1 = Join-Path $root 'P1'
New-Item -ItemType Directory -Force -Path $p1 | Out-Null

$report = New-Object System.Collections.Generic.List[string]
$report.Add('PHASE=G3_GPU1_AMDVLK_UNBLOCK_001/P1')
$report.Add("ASOF=$(Get-Date -Format o)")
$report.Add("ELEVATED=$([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")

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
  $props = $_.GetValueNames()
  if ($props -contains 'EnableUlps') {
    Set-ItemProperty -Path $_.PSPath -Name 'EnableUlps' -Value 0 -Type DWord
    $report.Add("ULPS_DISABLED=$($_.PSChildName)")
    $hit++
  }
  if ($props -contains 'PP_GPUPowerDownEnabled') {
    Set-ItemProperty -Path $_.PSPath -Name 'PP_GPUPowerDownEnabled' -Value 0 -Type DWord
    $report.Add("PP_GPUPowerDownEnabled_0=$($_.PSChildName)")
  }
}
if ($hit -eq 0) { $report.Add('ULPS_KEY_NOT_FOUND (card may not expose it; not fatal)') }

# --- 3. Disable MPO (overlay test mode) --------------------------------------
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Dwm' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Dwm' -Name 'OverlayTestMode' -Value 5 -Type DWord
$report.Add('MPO_DISABLED=OverlayTestMode_5')

# --- 4. HAGS off --------------------------------------------------------------
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name 'HwSchMode' -Value 1 -Type DWord -ErrorAction SilentlyContinue
$report.Add('HAGS=HwSchMode_1_OFF')

# --- 5. PCIe ASPM off on active power plan ------------------------------------
powercfg /setacvalueindex scheme_current SUB_PCIEXPRESS ASPM 0 2>$null
powercfg /setdcvalueindex scheme_current SUB_PCIEXPRESS ASPM 0 2>$null
powercfg /setactive scheme_current
$report.Add('ASPM=OFF_SCHEME_CURRENT')

$report.Add('NEXT=REBOOT_THEN_VERIFICATION_GATE')
$out = Join-Path $p1 'P1_UNBLOCK_APPLIED.txt'
$report | Set-Content $out -Encoding ASCII
Get-Content $out
Write-Host ''
Write-Host 'P1 applied. REBOOT now, then run:'
Write-Host '  powershell -NoProfile -ExecutionPolicy Bypass -File G:\~dev\rawrxd\tools\verify_unblock_gate.ps1'
