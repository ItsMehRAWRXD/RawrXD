# RawrXD Configuration Drift Detector
# Detects configuration drift from baseline across environments
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Check", "Baseline", "Compare", "Sync", "Report")]
    [string]$Action = "Check",
    
    [Parameter()]
    [string]$Environment = "production",
    
    [Parameter()]
    [string]$BaselinePath = "config\baseline",
    
    [Parameter()]
    [string]$CurrentPath = "config\current",
    
    [Parameter()]
    [string[]]$ConfigFiles = @("*.json", "*.yaml", "*.yml", "*.config", "*.xml"),
    
    [Parameter()]
    [switch]$AutoFix,
    
    [Parameter()]
    [switch]$FailOnDrift
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-FileHashSafe {
    param([string]$Path)
    if (Test-Path $Path) {
        return (Get-FileHash $Path -Algorithm SHA256).Hash
    }
    return $null
}

function Compare-Configurations {
    $drifts = @()
    
    Write-Status "Checking configuration drift for environment: $Environment"
    
    if (-not (Test-Path $BaselinePath)) {
        Write-Warning "Baseline path not found: $BaselinePath"
        return $drifts
    }
    
    if (-not (Test-Path $CurrentPath)) {
        Write-Warning "Current path not found: $CurrentPath"
        return $drifts
    }
    
    $baselineFiles = Get-ChildItem -Path $BaselinePath -Include $ConfigFiles -Recurse
    $currentFiles = Get-ChildItem -Path $CurrentPath -Include $ConfigFiles -Recurse
    
    foreach ($baseFile in $baselineFiles) {
        $relativePath = $baseFile.FullName.Substring($BaselinePath.Length + 1)
        $currentFile = $currentFiles | Where-Object { $_.FullName.EndsWith($relativePath) }
        
        if (-not $currentFile) {
            $drifts += [PSCustomObject]@{
                Type = "Missing"
                File = $relativePath
                BaselineHash = (Get-FileHashSafe -Path $baseFile.FullName)
                CurrentHash = $null
                Severity = "High"
            }
        } else {
            $baseHash = Get-FileHashSafe -Path $baseFile.FullName
            $currentHash = Get-FileHashSafe -Path $currentFile.FullName
            
            if ($baseHash -ne $currentHash) {
                $drifts += [PSCustomObject]@{
                    Type = "Modified"
                    File = $relativePath
                    BaselineHash = $baseHash
                    CurrentHash = $currentHash
                    Severity = "Medium"
                }
            }
        }
    }
    
    # Check for extra files in current
    foreach ($currFile in $currentFiles) {
        $relativePath = $currFile.FullName.Substring($CurrentPath.Length + 1)
        $baseFile = $baselineFiles | Where-Object { $_.FullName.EndsWith($relativePath) }
        
        if (-not $baseFile) {
            $drifts += [PSCustomObject]@{
                Type = "Extra"
                File = $relativePath
                BaselineHash = $null
                CurrentHash = (Get-FileHashSafe -Path $currFile.FullName)
                Severity = "Low"
            }
        }
    }
    
    return $drifts
}

function Show-DriftReport {
    param([array]$Drifts)
    
    Write-Host "`nConfiguration Drift Report: $Environment" -ForegroundColor Cyan
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($Drifts.Count -eq 0) {
        Write-Success "No configuration drift detected!"
        return
    }
    
    $missing = ($Drifts | Where-Object { $_.Type -eq "Missing" }).Count
    $modified = ($Drifts | Where-Object { $_.Type -eq "Modified" }).Count
    $extra = ($Drifts | Where-Object { $_.Type -eq "Extra" }).Count
    
    Write-Host "Summary:" -ForegroundColor Yellow
    Write-Host "  Missing files: $missing" -ForegroundColor $(if ($missing -gt 0) { "Red" } else { "Green" })
    Write-Host "  Modified files: $modified" -ForegroundColor $(if ($modified -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Extra files: $extra" -ForegroundColor $(if ($extra -gt 0) { "Cyan" } else { "Green" })
    Write-Host "  Total drift: $($Drifts.Count)"
    Write-Host ""
    
    Write-Host "Detailed Drift:" -ForegroundColor Yellow
    Write-Host "--------------"
    
    foreach ($drift in ($Drifts | Sort-Object Severity -Descending)) {
        $color = switch ($drift.Severity) {
            "High" { "Red" }
            "Medium" { "Yellow" }
            default { "Cyan" }
        }
        
        $symbol = switch ($drift.Type) {
            "Missing" { "❌" }
            "Modified" { "⚠️" }
            "Extra" { "➕" }
        }
        
        Write-Host "$symbol [$($drift.Severity)] $($drift.Type): $($drift.File)" -ForegroundColor $color
    }
    Write-Host ""
}

function Set-ConfigBaseline {
    Write-Status "Setting configuration baseline from: $CurrentPath"
    
    if (-not (Test-Path $CurrentPath)) {
        throw "Current path not found: $CurrentPath"
    }
    
    if (Test-Path $BaselinePath) {
        Remove-Item -Path $BaselinePath -Recurse -Force
    }
    
    Copy-Item -Path $CurrentPath -Destination $BaselinePath -Recurse
    Write-Success "Baseline set from $CurrentPath to $BaselinePath"
}

function Sync-Configuration {
    param([array]$Drifts)
    
    if (-not $AutoFix) {
        $confirm = Read-Host "Sync configuration to match baseline? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Status "Sync cancelled"
            return
        }
    }
    
    Write-Status "Syncing configuration..."
    
    foreach ($drift in $Drifts) {
        $currentFile = Join-Path $CurrentPath $drift.File
        $baselineFile = Join-Path $BaselinePath $drift.File
        
        switch ($drift.Type) {
            "Missing" {
                if (Test-Path $baselineFile) {
                    $targetDir = Split-Path $currentFile -Parent
                    if (-not (Test-Path $targetDir)) {
                        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                    }
                    Copy-Item $baselineFile $currentFile
                    Write-Success "Restored: $($drift.File)"
                }
            }
            "Modified" {
                Copy-Item $baselineFile $currentFile -Force
                Write-Success "Synced: $($drift.File)"
            }
            "Extra" {
                Remove-Item $currentFile -Force
                Write-Success "Removed extra: $($drift.File)"
            }
        }
    }
    
    Write-Success "Configuration sync complete"
}

# Main execution
try {
    switch ($Action) {
        "Check" {
            $drifts = Compare-Configurations
            Show-DriftReport -Drifts $drifts
            
            if ($FailOnDrift -and $drifts.Count -gt 0) {
                exit 1
            }
        }
        "Baseline" { Set-ConfigBaseline }
        "Compare" {
            $drifts = Compare-Configurations
            Show-DriftReport -Drifts $drifts
        }
        "Sync" {
            $drifts = Compare-Configurations
            Sync-Configuration -Drifts $drifts
        }
        "Report" {
            $drifts = Compare-Configurations
            $report = @{
                Environment = $Environment
                Timestamp = (Get-Date).ToString("o")
                DriftCount = $drifts.Count
                Drifts = $drifts
            }
            $report | ConvertTo-Json -Depth 5 | Set-Content "drift-report.json"
            Write-Success "Report saved to drift-report.json"
        }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
