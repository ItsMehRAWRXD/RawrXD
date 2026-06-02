# ==============================================================================
# Sovereign_CleanRoom_Surgical.ps1
# Self-elevating script to neutralize AMD/OBS Vulkan hooks
# ==============================================================================
param(
    [switch]$Restore,
    [switch]$WhatIf
)

# Self-elevation block
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    if ($Restore) { $arguments += " -Restore" }
    if ($WhatIf) { $arguments += " -WhatIf" }
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    exit
}

$amdHook = "C:\Windows\System32\amdihk64.dll"
$amdBak  = "C:\Windows\System32\amdihk64.dll.bak"
$obsHook = "C:\ProgramData\obs-studio-hook\graphics-hook64.dll"
$obsBak  = "C:\ProgramData\obs-studio-hook\graphics-hook64.dll.bak"

Write-Host "=== Sovereign Clean-Room Surgical Protocol ===" -ForegroundColor Cyan
Write-Host "Mode: $(if ($Restore) { 'RESTORE' } else { 'NEUTRALIZE' })" -ForegroundColor $(if ($Restore) { 'Yellow' } else { 'Red' })
Write-Host ""

if ($WhatIf) {
    Write-Host "[WHATIF] No changes will be made." -ForegroundColor Magenta
}

# AMD Hook
if ($Restore) {
    if (Test-Path $amdBak) {
        Write-Host "[RESTORE] AMD hook: $amdBak -> $amdHook" -ForegroundColor Yellow
        if (-not $WhatIf) { Rename-Item $amdBak $amdHook -Force }
    } else {
        Write-Host "[SKIP] AMD backup not found: $amdBak" -ForegroundColor DarkGray
    }
} else {
    if (Test-Path $amdHook) {
        Write-Host "[NEUTRALIZE] AMD hook: $amdHook -> $amdBak" -ForegroundColor Red
        if (-not $WhatIf) { Rename-Item $amdHook $amdBak -Force }
    } else {
        Write-Host "[SKIP] AMD hook already neutralized" -ForegroundColor Green
    }
}

# OBS Hook
if ($Restore) {
    if (Test-Path $obsBak) {
        Write-Host "[RESTORE] OBS hook: $obsBak -> $obsHook" -ForegroundColor Yellow
        if (-not $WhatIf) { Rename-Item $obsBak $obsHook -Force }
    } else {
        Write-Host "[SKIP] OBS backup not found: $obsBak" -ForegroundColor DarkGray
    }
} else {
    if (Test-Path $obsHook) {
        Write-Host "[NEUTRALIZE] OBS hook: $obsHook -> $obsBak" -ForegroundColor Red
        if (-not $WhatIf) { Rename-Item $obsHook $obsBak -Force }
    } else {
        Write-Host "[SKIP] OBS hook already neutralized" -ForegroundColor Green
    }
}

# Verification
Write-Host ""
Write-Host "=== Verification ===" -ForegroundColor Cyan
$amdActive = Test-Path $amdHook
$obsActive = Test-Path $obsHook
Write-Host "AMD hook active : $amdActive ($(if ($amdActive) { 'CONTAMINATED' } else { 'CLEAN' }))" -ForegroundColor $(if ($amdActive) { 'Red' } else { 'Green' })
Write-Host "OBS hook active : $obsActive ($(if ($obsActive) { 'CONTAMINATED' } else { 'CLEAN' }))" -ForegroundColor $(if ($obsActive) { 'Red' } else { 'Green' })

if (-not $Restore -and -not $WhatIf) {
    Write-Host ""
    Write-Host "REBOOT REQUIRED for changes to take full effect." -ForegroundColor Yellow
    Write-Host "After reboot, run benchmarks with Invoke-CleanRoomCapture.ps1" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Rollback anytime with:" -ForegroundColor Cyan
Write-Host "  .\Sovereign_CleanRoom_Surgical.ps1 -Restore" -ForegroundColor White
