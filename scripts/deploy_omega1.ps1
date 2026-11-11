# RawrXD OMEGA-1 Deployment Script
# Automates installation and configuration for production deployment

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\RawrXD\OMEGA1",
    [string]$SourceDir = "d:\rawrxd\releases\RawrXD-OMEGA1-v1.0.0",
    [switch]$CreateShortcuts = $true,
    [switch]$AddToPath = $true,
    [switch]$ConfigureFirewall = $true
)

$ErrorActionPreference = 'Stop'
$StartTime = Get-Date

function Write-Header {
    param($Text)
    Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Write-Status {
    param($Text, $Status)
    $color = switch ($Status) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        default { "White" }
    }
    Write-Host "  [$Status] $Text" -ForegroundColor $color
}

Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD OMEGA-1 Deployment                                                  ║" -ForegroundColor Cyan
Write-Host "║     Install Directory: $InstallDir" -NoNewline -ForegroundColor Cyan
Write-Host "$(' ' * (63 - $InstallDir.Length))║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# =============================================================================
# Phase 1: Pre-Deployment Checks
# =============================================================================
Write-Header "Phase 1: Pre-Deployment Checks"

# Check if source exists
if (!(Test-Path $SourceDir)) {
    Write-Status "Source directory not found: $SourceDir" "FAIL"
    Write-Host "`n  Please run create_release_package.ps1 first." -ForegroundColor Yellow
    exit 1
}
Write-Status "Source directory found" "OK"

# Check system requirements
Write-Status "Checking system requirements..." "OK"

# Check OS
$os = Get-CimInstance Win32_OperatingSystem
if ($os.OSArchitecture -notmatch "64") {
    Write-Status "64-bit Windows required" "FAIL"
    exit 1
}
Write-Status "OS: $($os.Caption) ($($os.OSArchitecture))" "OK"

# Check RAM
$ram = [math]::Round($os.TotalVisibleMemorySize / 1MB, 0)
if ($ram -lt 32) {
    Write-Status "RAM: ${ram}GB (32GB+ recommended)" "WARN"
} else {
    Write-Status "RAM: ${ram}GB" "OK"
}

# Check GPUs
$gpus = Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | 
    Where-Object { $_.Name -match "AMD|NVIDIA|Intel" -and $_.Status -eq "OK" }
Write-Status "GPUs detected: $($gpus.Count)" "OK"
foreach ($gpu in $gpus) {
    Write-Host "    - $($gpu.Name)" -ForegroundColor Gray
}

# =============================================================================
# Phase 2: Create Installation Directory
# =============================================================================
Write-Header "Phase 2: Creating Installation Directory"

if (Test-Path $InstallDir) {
    Write-Status "Existing installation found, backing up..." "WARN"
    $backupDir = "$InstallDir.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Move-Item $InstallDir $backupDir
    Write-Status "Backed up to: $backupDir" "OK"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\bin" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\config" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\logs" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\models" | Out-Null

Write-Status "Created installation directory: $InstallDir" "OK"

# =============================================================================
# Phase 3: Copy Files
# =============================================================================
Write-Header "Phase 3: Installing Files"

# Copy binaries
$binaries = Get-ChildItem "$SourceDir\bin\*" -Include "*.exe", "*.dll"
$binCount = 0
foreach ($bin in $binaries) {
    Copy-Item $bin.FullName "$InstallDir\bin\" -Force
    $binCount++
}
Write-Status "Installed $binCount binaries" "OK"

# Copy documentation
if (Test-Path "$SourceDir\docs") {
    Copy-Item "$SourceDir\docs" "$InstallDir\" -Recurse -Force
    Write-Status "Installed documentation" "OK"
}

# Copy scripts
if (Test-Path "$SourceDir\scripts") {
    Copy-Item "$SourceDir\scripts" "$InstallDir\" -Recurse -Force
    Write-Status "Installed scripts" "OK"
}

# Copy test results
if (Test-Path "$SourceDir\test_results") {
    Copy-Item "$SourceDir\test_results" "$InstallDir\" -Recurse -Force
    Write-Status "Installed test results" "OK"
}

# Copy README
if (Test-Path "$SourceDir\README.txt") {
    Copy-Item "$SourceDir\README.txt" "$InstallDir\" -Force
}

# =============================================================================
# Phase 4: Create Configuration
# =============================================================================
Write-Header "Phase 4: Creating Configuration"

$configContent = @"
{
    "version": "1.0.0",
    "installDate": "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "installDir": "$InstallDir",
    "dualGpu": {
        "enabled": true,
        "primaryGpu": "AMD Radeon AI PRO R9700",
        "secondaryGpu": "AMD Radeon RX 7800 XT",
        "layerSplit": {
            "primary": 22,
            "secondary": 10
        }
    },
    "ipc": {
        "pipeName": "\\\\.\\pipe\\RawrXD_Omega1_v2",
        "bufferSize": 65536
    },
    "performance": {
        "targetPromptTps": 557,
        "targetGenerationTps": 344
    },
    "paths": {
        "models": "$InstallDir\\models",
        "logs": "$InstallDir\\logs",
        "temp": "$env:TEMP\\RawrXD"
    }
}
"@

$configContent | Out-File "$InstallDir\config\omega1.json" -Encoding UTF8
Write-Status "Created configuration file" "OK"

# Create startup script
$startupScript = @"
@echo off
REM RawrXD OMEGA-1 Startup Script

echo Starting RawrXD OMEGA-1...
echo.

REM Set environment
set RAWRXD_HOME=$InstallDir
set RAWRXD_CONFIG=$InstallDir\config\omega1.json
set PATH=$InstallDir\bin;%PATH%

REM Start Inference Engine in background
start /B "" "$InstallDir\bin\RawrXD-InferenceEngine.exe" --daemon

REM Start IDE
"$InstallDir\bin\RawrXD-Win32IDE.exe"
"@

$startupScript | Out-File "$InstallDir\start_omega1.bat" -Encoding ASCII
Write-Status "Created startup script" "OK"

# =============================================================================
# Phase 5: Create Shortcuts
# =============================================================================
if ($CreateShortcuts) {
    Write-Header "Phase 5: Creating Shortcuts"
    
    $WshShell = New-Object -ComObject WScript.Shell
    
    # Desktop shortcut
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcut = $WshShell.CreateShortcut("$desktopPath\RawrXD OMEGA-1.lnk")
    $shortcut.TargetPath = "$InstallDir\bin\RawrXD-Win32IDE.exe"
    $shortcut.WorkingDirectory = "$InstallDir\bin"
    $shortcut.IconLocation = "$InstallDir\bin\RawrXD-Win32IDE.exe,0"
    $shortcut.Description = "RawrXD OMEGA-1 Local LLM IDE"
    $shortcut.Save()
    Write-Status "Created desktop shortcut" "OK"
    
    # Start Menu shortcut
    $startMenuPath = [Environment]::GetFolderPath("StartMenu")
    $appFolder = "$startMenuPath\Programs\RawrXD"
    if (!(Test-Path $appFolder)) {
        New-Item -ItemType Directory -Force -Path $appFolder | Out-Null
    }
    
    $shortcut = $WshShell.CreateShortcut("$appFolder\RawrXD OMEGA-1.lnk")
    $shortcut.TargetPath = "$InstallDir\bin\RawrXD-Win32IDE.exe"
    $shortcut.WorkingDirectory = "$InstallDir\bin"
    $shortcut.IconLocation = "$InstallDir\bin\RawrXD-Win32IDE.exe,0"
    $shortcut.Description = "RawrXD OMEGA-1 Local LLM IDE"
    $shortcut.Save()
    Write-Status "Created Start Menu shortcut" "OK"
    
    # Uninstall shortcut
    $shortcut = $WshShell.CreateShortcut("$appFolder\Uninstall RawrXD OMEGA-1.lnk")
    $shortcut.TargetPath = "powershell.exe"
    $shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$InstallDir\scripts\uninstall.ps1`""
    $shortcut.IconLocation = "%SystemRoot%\System32\shell32.dll,31"
    $shortcut.Save()
    Write-Status "Created uninstall shortcut" "OK"
}

# =============================================================================
# Phase 6: Add to PATH
# =============================================================================
if ($AddToPath) {
    Write-Header "Phase 6: Updating PATH"
    
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($currentPath -notlike "*$InstallDir\bin*") {
        $newPath = "$InstallDir\bin;$currentPath"
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
        Write-Status "Added to user PATH" "OK"
    } else {
        Write-Status "Already in PATH" "OK"
    }
}

# =============================================================================
# Phase 7: Configure Firewall
# =============================================================================
if ($ConfigureFirewall) {
    Write-Header "Phase 7: Configuring Firewall"
    
    try {
        # Allow Win32IDE
        $ruleName = "RawrXD OMEGA-1 Win32IDE"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (!$existing) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound `
                -Program "$InstallDir\bin\RawrXD-Win32IDE.exe" `
                -Action Allow | Out-Null
            Write-Status "Created firewall rule for Win32IDE" "OK"
        } else {
            Write-Status "Firewall rule for Win32IDE exists" "OK"
        }
        
        # Allow InferenceEngine
        $ruleName = "RawrXD OMEGA-1 InferenceEngine"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (!$existing) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound `
                -Program "$InstallDir\bin\RawrXD-InferenceEngine.exe" `
                -Action Allow | Out-Null
            Write-Status "Created firewall rule for InferenceEngine" "OK"
        } else {
            Write-Status "Firewall rule for InferenceEngine exists" "OK"
        }
    } catch {
        Write-Status "Firewall configuration requires admin rights" "WARN"
    }
}

# =============================================================================
# Phase 8: Create Uninstaller
# =============================================================================
Write-Header "Phase 8: Creating Uninstaller"

$uninstallScript = @"
# RawrXD OMEGA-1 Uninstaller
param([switch]`$KeepConfig = `$false)

`$installDir = "$InstallDir"

Write-Host "Uninstalling RawrXD OMEGA-1..." -ForegroundColor Cyan

# Remove shortcuts
`$desktop = [Environment]::GetFolderPath("Desktop")
Remove-Item "`$desktop\RawrXD OMEGA-1.lnk" -ErrorAction SilentlyContinue

`$startMenu = [Environment]::GetFolderPath("StartMenu")
Remove-Item "`$startMenu\Programs\RawrXD\" -Recurse -ErrorAction SilentlyContinue

# Remove from PATH
`$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
`$newPath = (`$currentPath -split ';' | Where-Object { `$_ -ne "$InstallDir\bin" }) -join ';'
[Environment]::SetEnvironmentVariable("PATH", `$newPath, "User")

# Remove firewall rules
Get-NetFirewallRule -DisplayName "RawrXD OMEGA-1*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

# Remove installation directory
if (Test-Path `$installDir) {
    Remove-Item `$installDir -Recurse -Force
}

Write-Host "RawrXD OMEGA-1 has been uninstalled." -ForegroundColor Green
"@

$uninstallScript | Out-File "$InstallDir\scripts\uninstall.ps1" -Encoding UTF8
Write-Status "Created uninstaller" "OK"

# =============================================================================
# Phase 9: Post-Installation Validation
# =============================================================================
Write-Header "Phase 9: Post-Installation Validation"

# Verify binaries
$binaries = @("RawrXD-Win32IDE.exe", "RawrXD-InferenceEngine.exe")
$allPresent = $true
foreach ($bin in $binaries) {
    $path = "$InstallDir\bin\$bin"
    if (Test-Path $path) {
        Write-Status "Verified: $bin" "OK"
    } else {
        Write-Status "Missing: $bin" "FAIL"
        $allPresent = $false
    }
}

# Verify config
if (Test-Path "$InstallDir\config\omega1.json") {
    Write-Status "Verified: configuration" "OK"
} else {
    Write-Status "Missing: configuration" "FAIL"
}

# Run quick test
Write-Status "Running quick validation..." "OK"
try {
    $output = & "$InstallDir\bin\RawrXD-InferenceEngine.exe" --help 2>&1 | Out-String
    if ($output -match "RawrXD-InferenceEngine") {
        Write-Status "InferenceEngine validation passed" "OK"
    } else {
        Write-Status "InferenceEngine validation failed" "WARN"
    }
} catch {
    Write-Status "InferenceEngine validation error" "WARN"
}

# =============================================================================
# Summary
# =============================================================================
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

Write-Header "Deployment Complete"

Write-Status "Installation directory: $InstallDir" "OK"
Write-Status "Duration: $($Duration.ToString('hh\:mm\:ss'))" "OK"

Write-Host "`n  Next Steps:" -ForegroundColor Cyan
Write-Host "    1. Run: $InstallDir\start_omega1.bat" -ForegroundColor Gray
Write-Host "    2. Or use the desktop shortcut" -ForegroundColor Gray
Write-Host "    3. Place GGUF models in: $InstallDir\models" -ForegroundColor Gray
Write-Host "`n  Documentation:" -ForegroundColor Cyan
Write-Host "    - $InstallDir\README.txt" -ForegroundColor Gray
Write-Host "    - $InstallDir\docs\BUILD_SUMMARY.md" -ForegroundColor Gray

Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║     ✅ RawrXD OMEGA-1 Deployed Successfully                                      ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

exit 0
