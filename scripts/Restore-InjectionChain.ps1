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

Write-Host "[Restore] Re-enabling AMD scheduled tasks..." -ForegroundColor Cyan
foreach ($t in $tasks) {
    schtasks /change /tn $t /enable | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Enabled Task: $t" -ForegroundColor Yellow
    } else {
        Write-Host "Task not enabled (possibly missing): $t" -ForegroundColor DarkYellow
    }
}

Write-Host "[Restore] Restoring service startup and starting services..." -ForegroundColor Cyan
foreach ($hint in $serviceHints) {
    $name = Resolve-ServiceName -Hint $hint
    if (-not $name) {
        Write-Host "Service not found: $hint" -ForegroundColor DarkYellow
        continue
    }

    sc.exe config "$name" start= auto | Out-Null
    Start-Service -Name $name -ErrorAction SilentlyContinue
    Write-Host "Restored Service: $name" -ForegroundColor Yellow
}

Write-Host "[Restore] Completed." -ForegroundColor Green
