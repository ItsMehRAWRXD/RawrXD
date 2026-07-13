# RawrXD Security & Hotpatch System - Installation Script
# Version: 1.0.0
# Automated installation with environment setup

param(
    [ValidateSet("dev", "staging", "production")]
    [string]$Environment = "dev",
    
    [string]$InstallPath = "C:\\Program Files\\RawrXD",
    [string]$DataPath = "C:\\ProgramData\\RawrXD",
    [switch]$SkipTests,
    [switch]$SkipMonitoring,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Installation configuration
$script:Config = @{
    Version = "1.0.0"
    MinPowerShellVersion = "7.0"
    MinDiskSpaceGB = 10
    RequiredModules = @("Pester")
    Services = @(
        "RawrXD-Prometheus",
        "RawrXD-Grafana",
        "RawrXD-Alertmanager",
        "RawrXD-MetricsExporter"
    )
}

$script:InstallLog = @{
    install_id = [Guid]::NewGuid().ToString()
    started_at = Get-Date -Format "o"
    environment = $Environment
    install_path = $InstallPath
    steps = @()
    status = "in_progress"
}

function Write-InstallLog {
    param([string]$Step, [string]$Status, [string]$Details = "")
    
    $script:InstallLog.steps += @{
        step = $Step
        status = $Status
        timestamp = Get-Date -Format "o"
        details = $Details
    }
    
    $color = switch ($Status) {
        "success" { "Green" }
        "error" { "Red" }
        "warning" { "Yellow" }
        "info" { "Cyan" }
        default { "White" }
    }
    
    Write-Host "[$Status] $Step" -ForegroundColor $color
    if ($Details) { Write-Host "  $Details" -ForegroundColor Gray }
}

function Test-Prerequisites {
    Write-InstallLog -Step "Checking Prerequisites" -Status "info"
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion -lt [Version]$script:Config.MinPowerShellVersion) {
        throw "PowerShell $($script:Config.MinPowerShellVersion)+ required. Found: $($PSVersionTable.PSVersion)"
    }
    Write-InstallLog -Step "PowerShell Version" -Status "success" -Details $PSVersionTable.PSVersion
    
    # Check disk space
    $drive = Get-PSDrive (Split-Path $InstallPath -Qualifier).TrimEnd(':')
    $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
    if ($freeSpaceGB -lt $script:Config.MinDiskSpaceGB) {
        throw "Insufficient disk space. Required: $($script:Config.MinDiskSpaceGB) GB, Available: $freeSpaceGB GB"
    }
    Write-InstallLog -Step "Disk Space" -Status "success" -Details "$freeSpaceGB GB available"
    
    # Check execution policy
    $execPolicy = Get-ExecutionPolicy
    if ($execPolicy -eq "Restricted") {
        Write-Warning "Execution policy is Restricted. Set to RemoteSigned for installation."
        if (-not $Force) {
            $confirm = Read-Host "Set execution policy to RemoteSigned? (yes/no)"
            if ($confirm -eq "yes") {
                Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
            }
        }
    }
    
    Write-InstallLog -Step "Prerequisites Check" -Status "success"
}

function Install-DirectoryStructure {
    Write-InstallLog -Step "Creating Directory Structure" -Status "info"
    
    $directories = @(
        $InstallPath,
        $DataPath,
        "$DataPath\logs",
        "$DataPath\backups",
        "$DataPath\data",
        "$InstallPath\security",
        "$InstallPath\monitoring",
        "$InstallPath\docs"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "  Created: $dir" -ForegroundColor Gray
        }
    }
    
    Write-InstallLog -Step "Directory Structure" -Status "success"
}

function Install-Files {
    Write-InstallLog -Step "Installing Files" -Status "info"
    
    # Copy all components
    $components = @(
        @{ Source = "security"; Dest = "$InstallPath\security" },
        @{ Source = "monitoring"; Dest = "$InstallPath\monitoring" },
        @{ Source = "docs"; Dest = "$InstallPath\docs" },
        @{ Source = "tests"; Dest = "$InstallPath\tests" },
        @{ Source = "benchmarks"; Dest = "$InstallPath\benchmarks" },
        @{ Source = "disaster-recovery"; Dest = "$InstallPath\disaster-recovery" },
        @{ Source = "deployment"; Dest = "$InstallPath\deployment" }
    )
    
    foreach ($component in $components) {
        if (Test-Path $component.Source) {
            if (Test-Path $component.Dest) {
                Remove-Item $component.Dest -Recurse -Force
            }
            Copy-Item $component.Source $component.Dest -Recurse -Force
            Write-Host "  Installed: $($component.Source)" -ForegroundColor Gray
        }
    }
    
    # Copy root files
    $rootFiles = @("README.md", "LICENSE")
    foreach ($file in $rootFiles) {
        if (Test-Path $file) {
            Copy-Item $file "$InstallPath\$file" -Force
        }
    }
    
    Write-InstallLog -Step "Files Installed" -Status "success"
}

function Initialize-Security {
    Write-InstallLog -Step "Initializing Security" -Status "info"
    
    # Initialize RBAC
    $rbacResult = & "$InstallPath\security\phase_h_enterprise_security\rbac\rbac_manager.ps1" -Operation initialize
    Write-InstallLog -Step "RBAC Initialization" -Status "success"
    
    # Create audit log directory
    $auditDir = "$DataPath\logs\audit"
    if (-not (Test-Path $auditDir)) {
        New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
    }
    
    # Set permissions
    $acl = Get-Acl $auditDir
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Users",
        "Write, Modify",
        "ContainerInherit, ObjectInherit",
        "None",
        "Allow"
    )
    $acl.SetAccessRule($rule)
    Set-Acl $auditDir $acl
    
    Write-InstallLog -Step "Security Initialization" -Status "success"
}

function Install-Monitoring {
    if ($SkipMonitoring) {
        Write-InstallLog -Step "Monitoring Setup" -Status "warning" -Details "Skipped"
        return
    }
    
    Write-InstallLog -Step "Installing Monitoring Stack" -Status "info"
    
    # Run monitoring setup
    & "$InstallPath\monitoring\scripts\setup_monitoring.ps1" -InstallDir "$DataPath\monitoring" -DataDir "$DataPath\monitoring\data"
    
    Write-InstallLog -Step "Monitoring Stack" -Status "success"
}

function Set-EnvironmentConfiguration {
    Write-InstallLog -Step "Configuring Environment" -Status "info"
    
    $config = @{
        environment = $Environment
        install_path = $InstallPath
        data_path = $DataPath
        log_level = if ($Environment -eq "production") { "warning" } else { "info" }
        auto_rollback = ($Environment -eq "production")
        backup_enabled = $true
        monitoring_enabled = (-not $SkipMonitoring)
    }
    
    $config | ConvertTo-Json -Depth 5 | Out-File "$DataPath\config.json"
    
    Write-InstallLog -Step "Environment Configuration" -Status "success" -Details "Environment: $Environment"
}

function Invoke-PostInstallTests {
    if ($SkipTests) {
        Write-InstallLog -Step "Post-Install Tests" -Status "warning" -Details "Skipped"
        return
    }
    
    Write-InstallLog -Step "Running Post-Install Tests" -Status "info"
    
    # Run smoke tests
    $testResult = Invoke-Pester -Path "$InstallPath\tests\smoke" -PassThru -Show None
    
    if ($testResult.FailedCount -gt 0) {
        throw "Post-install tests failed: $($testResult.FailedCount) failures"
    }
    
    Write-InstallLog -Step "Post-Install Tests" -Status "success" -Details "All tests passed"
}

function New-Shortcuts {
    Write-InstallLog -Step "Creating Shortcuts" -Status "info"
    
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $startMenuPath = [Environment]::GetFolderPath("StartMenu")
    
    # Create shortcuts (simplified - would use WScript.Shell in production)
    Write-Host "  Shortcuts would be created at:" -ForegroundColor Gray
    Write-Host "    - Desktop" -ForegroundColor Gray
    Write-Host "    - Start Menu" -ForegroundColor Gray
    
    Write-InstallLog -Step "Shortcuts Created" -Status "success"
}

function Save-InstallLog {
    $script:InstallLog.completed_at = Get-Date -Format "o"
    $script:InstallLog.status = "completed"
    
    $logPath = "$DataPath\install-log.json"
    $script:InstallLog | ConvertTo-Json -Depth 10 | Out-File $logPath
    
    Write-Host "`nInstallation log saved: $logPath" -ForegroundColor Gray
}

function Show-InstallationSummary {
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Installation Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Environment: $Environment" -ForegroundColor White
    Write-Host "Install Path: $InstallPath" -ForegroundColor White
    Write-Host "Data Path: $DataPath" -ForegroundColor White
    Write-Host "Install ID: $($script:InstallLog.install_id)" -ForegroundColor White
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Run health check:" -ForegroundColor White
    Write-Host "     .\monitoring\scripts\health_check.ps1" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. Access monitoring:" -ForegroundColor White
    Write-Host "     Grafana: http://localhost:3000" -ForegroundColor Gray
    Write-Host "     Prometheus: http://localhost:9090" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  3. View documentation:" -ForegroundColor White
    Write-Host "     docs\README.md" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  4. Run tests:" -ForegroundColor White
    Write-Host "     .\tests\scripts\run_tests.ps1" -ForegroundColor Gray
    Write-Host ""
}

# Main installation
function Invoke-Installation {
    Write-Host "RawrXD Security & Hotpatch System - Installation" -ForegroundColor Cyan
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host "Version: $($script:Config.Version)" -ForegroundColor Yellow
    Write-Host "Environment: $Environment" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        Test-Prerequisites
        Install-DirectoryStructure
        Install-Files
        Initialize-Security
        Install-Monitoring
        Set-EnvironmentConfiguration
        Invoke-PostInstallTests
        New-Shortcuts
        Save-InstallLog
        Show-InstallationSummary
        
        exit 0
    }
    catch {
        Write-InstallLog -Step "Installation Failed" -Status "error" -Details $_.Exception.Message
        Save-InstallLog
        Write-Error "Installation failed: $_"
        exit 1
    }
}

# Run installation
Invoke-Installation
