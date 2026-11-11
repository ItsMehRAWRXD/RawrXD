# RawrXD Troubleshooter
# Automated troubleshooting and diagnostic repair

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Diagnose", "Repair", "Reset", "Clean", "Verify")]
    [string]$Action = "Diagnose",
    
    [string]$Issue = "",
    [string[]]$Components = @(),
    [switch]$AutoFix,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

$script:IssuesFound = @()
$script:RepairsMade = @()

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-Troubleshooter {
    Write-Status "RawrXD Troubleshooter initialized"
    Write-Status "Action: $Action"
}

function Add-Issue {
    param([string]$Component, [string]$Description, [string]$Severity)
    
    $script:IssuesFound += [PSCustomObject]@{
        Component = $Component
        Description = $Description
        Severity = $Severity
        Timestamp = Get-Date -Format "HH:mm:ss"
    }
    
    $color = switch ($Severity) {
        "Critical" { "Red" }
        "Warning" { "Yellow" }
        default { "White" }
    }
    
    Write-Host "  [$Severity] $Component`: $Description" -ForegroundColor $color
}

function Add-Repair {
    param([string]$Component, [string]$Action)
    
    $script:RepairsMade += [PSCustomObject]@{
        Component = $Component
        Action = $Action
        Timestamp = Get-Date -Format "HH:mm:ss"
    }
    
    Write-Success "Repaired: $Component - $Action"
}

function Test-CommonIssues {
    Write-Status "Running diagnostics..."
    
    # Check if RawrXD is installed
    if (-not (Test-Path "./bin/rawrxd.exe")) {
        Add-Issue -Component "Installation" -Description "RawrXD binary not found" -Severity "Critical"
    }
    
    # Check configuration file
    if (-not (Test-Path "./config.json")) {
        Add-Issue -Component "Configuration" -Description "Configuration file missing" -Severity "Warning"
    } else {
        try {
            $config = Get-Content "./config.json" | ConvertFrom-Json
            if (-not $config.version) {
                Add-Issue -Component "Configuration" -Description "Configuration version missing" -Severity "Warning"
            }
        }
        catch {
            Add-Issue -Component "Configuration" -Description "Configuration file is corrupted" -Severity "Critical"
        }
    }
    
    # Check models directory
    if (-not (Test-Path "./models")) {
        Add-Issue -Component "Models" -Description "Models directory missing" -Severity "Warning"
    } else {
        $models = Get-ChildItem "./models" -Filter "*.gguf" -ErrorAction SilentlyContinue
        if ($models.Count -eq 0) {
            Add-Issue -Component "Models" -Description "No models found in models directory" -Severity "Warning"
        }
    }
    
    # Check logs directory
    if (-not (Test-Path "./logs")) {
        Add-Issue -Component "Logging" -Description "Logs directory missing" -Severity "Warning"
    }
    
    # Check disk space
    $drive = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq (Get-Location).Drive.Name + ":" }
    $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
    if ($freeSpaceGB -lt 1) {
        Add-Issue -Component "Disk" -Description "Low disk space: $freeSpaceGB GB remaining" -Severity "Critical"
    } elseif ($freeSpaceGB -lt 5) {
        Add-Issue -Component "Disk" -Description "Disk space running low: $freeSpaceGB GB remaining" -Severity "Warning"
    }
    
    # Check for crash dumps
    $crashDumps = Get-ChildItem "./crash_dumps" -Filter "*.dmp" -ErrorAction SilentlyContinue
    if ($crashDumps.Count -gt 0) {
        Add-Issue -Component "Stability" -Description "Found $($crashDumps.Count) crash dump(s)" -Severity "Warning"
    }
    
    # Check environment variables
    if (-not $env:RAWRXD_HOME) {
        Add-Issue -Component "Environment" -Description "RAWRXD_HOME environment variable not set" -Severity "Warning"
    }
}

function Repair-Issues {
    Write-Status "Attempting repairs..."
    
    foreach ($issue in $script:IssuesFound) {
        switch ($issue.Component) {
            "Configuration" {
                if ($issue.Description -like "*missing*") {
                    # Create default config
                    $defaultConfig = @{
                        version = "3.2.0"
                        debug = $false
                        logLevel = "info"
                        modelsPath = "./models"
                    }
                    $defaultConfig | ConvertTo-Json | Out-File "./config.json"
                    Add-Repair -Component "Configuration" -Action "Created default configuration file"
                }
            }
            "Models" {
                if ($issue.Description -like "*directory missing*") {
                    New-Item -ItemType Directory -Path "./models" -Force | Out-Null
                    Add-Repair -Component "Models" -Action "Created models directory"
                }
            }
            "Logging" {
                if ($issue.Description -like "*directory missing*") {
                    New-Item -ItemType Directory -Path "./logs" -Force | Out-Null
                    Add-Repair -Component "Logging" -Action "Created logs directory"
                }
            }
            "Environment" {
                if ($issue.Description -like "*RAWRXD_HOME*") {
                    $installPath = Resolve-Path "."
                    [Environment]::SetEnvironmentVariable("RAWRXD_HOME", $installPath, "User")
                    Add-Repair -Component "Environment" -Action "Set RAWRXD_HOME environment variable"
                }
            }
        }
    }
}

function Reset-Configuration {
    Write-Status "Resetting configuration to defaults..."
    
    if (-not $Force) {
        $confirm = Read-Host "This will reset all configuration to defaults. Continue? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Status "Reset cancelled"
            return
        }
    }
    
    # Backup existing config
    if (Test-Path "./config.json") {
        $backupName = "config.json.bak.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Copy-Item "./config.json" "./$backupName"
        Write-Status "Backed up existing config to $backupName"
    }
    
    # Create default config
    $defaultConfig = @{
        version = "3.2.0"
        debug = $false
        logLevel = "info"
        modelsPath = "./models"
        cachePath = "./cache"
        logPath = "./logs"
        maxLogSizeMB = 100
        maxCacheSizeMB = 1024
    }
    
    $defaultConfig | ConvertTo-Json -Depth 3 | Out-File "./config.json"
    Write-Success "Configuration reset to defaults"
}

function Clear-TempFiles {
    Write-Status "Cleaning temporary files..."
    
    $tempPaths = @(
        "$env:TEMP/rawrxd-*"
        "./cache/*"
        "./logs/*.old"
    )
    
    $cleared = 0
    foreach ($pattern in $tempPaths) {
        $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            try {
                Remove-Item $file.FullName -Recurse -Force
                $cleared++
            }
            catch {
                Write-Warning "Could not remove: $($file.FullName)"
            }
        }
    }
    
    Write-Success "Cleared $cleared temporary files"
}

function Verify-Installation {
    Write-Status "Verifying installation..."
    
    $checks = @(
        @{ Path = "./bin/rawrxd.exe"; Description = "Main executable" }
        @{ Path = "./config.json"; Description = "Configuration file" }
        @{ Path = "./models"; Description = "Models directory" }
        @{ Path = "./logs"; Description = "Logs directory" }
    )
    
    $passed = 0
    $failed = 0
    
    foreach ($check in $checks) {
        if (Test-Path $check.Path) {
            Write-Success "$($check.Description): OK"
            $passed++
        } else {
            Write-Error "$($check.Description): MISSING"
            $failed++
        }
    }
    
    Write-Host ""
    Write-Host "Verification Results:" -ForegroundColor Cyan
    Write-Host "  Passed: $passed"
    Write-Host "  Failed: $failed"
    
    if ($failed -eq 0) {
        Write-Success "Installation verified successfully"
    }
}

function Show-TroubleshooterSummary {
    Write-Host ""
    Write-Host "Troubleshooting Summary" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    
    Write-Host "Issues Found: $($script:IssuesFound.Count)"
    Write-Host "Repairs Made: $($script:RepairsMade.Count)"
    
    if ($script:IssuesFound.Count -gt 0) {
        Write-Host ""
        Write-Host "Issues:" -ForegroundColor Yellow
        foreach ($issue in $script:IssuesFound) {
            Write-Host "  [$($issue.Severity)] $($issue.Component): $($issue.Description)"
        }
    }
    
    if ($script:RepairsMade.Count -gt 0) {
        Write-Host ""
        Write-Host "Repairs:" -ForegroundColor Green
        foreach ($repair in $script:RepairsMade) {
            Write-Host "  [$($repair.Component)] $($repair.Action)"
        }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Troubleshooter" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Troubleshooter
    
    switch ($Action) {
        "Diagnose" {
            Test-CommonIssues
            Show-TroubleshooterSummary
            
            if ($AutoFix -and $script:IssuesFound.Count -gt 0) {
                Repair-Issues
            }
        }
        "Repair" {
            Test-CommonIssues
            Repair-Issues
            Show-TroubleshooterSummary
        }
        "Reset" { Reset-Configuration }
        "Clean" { Clear-TempFiles }
        "Verify" { Verify-Installation }
    }
    
    Write-Host ""
}

Main
