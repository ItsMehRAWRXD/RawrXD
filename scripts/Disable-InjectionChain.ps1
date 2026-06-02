#!/usr/bin/env pwsh
$ErrorActionPreference = "Continue"

function Resolve-ServiceName {
    param([string]$Hint)

    $svc = Get-Service -Name $Hint -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($svc) { return $svc.Name }

    $svc = Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $Hint -or $_.Name -eq $Hint } |
        Select-Object -First 1
    if ($svc) { return $svc.Name }

    return $null
}

$tasks = @("\StartCN", "\StartDVR")
$serviceHints = @(
    "AMD External Events Utility",
    "AMD Crash Defender Service",
    "AmdPpkgSvc"
)
$processes = @("atiesrxx", "amdfendrsr", "AMDRSServ", "amdow", "AmdPpkgSvc", "RadeonSoftware", "obs64", "obs")

Write-Host "[Phase1] Disabling AMD scheduled tasks..." -ForegroundColor Cyan
foreach ($t in $tasks) {
    schtasks /change /tn $t /disable | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Disabled Task: $t" -ForegroundColor Yellow
    } else {
        Write-Host "Task not disabled (possibly missing): $t" -ForegroundColor DarkYellow
    }
}

Write-Host "[Phase1] Disabling/stopping services..." -ForegroundColor Cyan
foreach ($hint in $serviceHints) {
    $name = Resolve-ServiceName -Hint $hint
    if (-not $name) {
        Write-Host "Service not found: $hint" -ForegroundColor DarkYellow
        continue
    }

    sc.exe config "$name" start= disabled | Out-Null
    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    Write-Host "Disabled+Stopped Service: $name" -ForegroundColor Yellow
}

Write-Host "[Phase1] Killing injector/runtime processes..." -ForegroundColor Cyan
foreach ($p in $processes) {
    Stop-Process -Name $p -Force -ErrorAction SilentlyContinue
}

Write-Host "[Phase1] Completed. Reboot before running clean-room gate." -ForegroundColor Green
