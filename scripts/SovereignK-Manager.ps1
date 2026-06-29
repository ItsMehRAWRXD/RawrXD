# =============================================================================
# SovereignK Driver Automation Script
# =============================================================================
# Automates driver installation, testing, and verification
# Run as Administrator
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$DriverPath = "D:\rawrxd\build-ninja\bin\SovereignK.sys",
    
    [Parameter(Mandatory=$false)]
    [switch]$Install,
    
    [Parameter(Mandatory=$false)]
    [switch]$Uninstall,
    
    [Parameter(Mandatory=$false)]
    [switch]$Test,
    
    [Parameter(Mandatory=$false)]
    [switch]$Status,
    
    [Parameter(Mandatory=$false)]
    [string]$Bar0Address = ""
)

# Requires elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

$ServiceName = "SovereignK"
$DeviceName = "SovereignK"

function Write-Header($text) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Write-Success($text) {
    Write-Host "[SUCCESS] $text" -ForegroundColor Green
}

function Write-Error($text) {
    Write-Host "[ERROR] $text" -ForegroundColor Red
}

function Write-Warning($text) {
    Write-Host "[WARNING] $text" -ForegroundColor Yellow
}

function Write-Info($text) {
    Write-Host "[INFO] $text" -ForegroundColor White
}

# =============================================================================
# Test Signing Check
# =============================================================================
function Check-TestSigning {
    Write-Header "Checking Test Signing Status"
    
    $bcdOutput = bcdedit /enum | Select-String "testsigning"
    if ($bcdOutput -match "Yes") {
        Write-Success "Test signing is ENABLED"
        return $true
    } else {
        Write-Error "Test signing is DISABLED"
        Write-Info "Run: bcdedit /set testsigning on"
        Write-Info "Then reboot and try again"
        return $false
    }
}

# =============================================================================
# Driver Installation
# =============================================================================
function Install-Driver {
    Write-Header "Installing SovereignK Driver"
    
    if (-not (Test-Path $DriverPath)) {
        Write-Error "Driver not found at: $DriverPath"
        Write-Info "Build the driver first using Visual Studio or WDK"
        return $false
    }
    
    Write-Info "Driver path: $DriverPath"
    
    # Stop existing service if running
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Warning "Existing service found. Stopping..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }
    
    # Copy driver to system directory
    $systemDriverPath = "C:\Windows\System32\drivers\SovereignK.sys"
    Write-Info "Copying driver to system directory..."
    Copy-Item -Path $DriverPath -Destination $systemDriverPath -Force
    
    # Create service
    Write-Info "Creating service..."
    $result = sc.exe create $ServiceName type= kernel binPath= $systemDriverPath start= demand
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create service"
        return $false
    }
    
    # Start service
    Write-Info "Starting service..."
    $result = sc.exe start $ServiceName
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to start service"
        Write-Info "Check Event Viewer for details"
        return $false
    }
    
    Start-Sleep -Seconds 2
    
    # Verify
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Success "Driver installed and running!"
        return $true
    } else {
        Write-Error "Driver installation verification failed"
        return $false
    }
}

# =============================================================================
# Driver Uninstallation
# =============================================================================
function Uninstall-Driver {
    Write-Header "Uninstalling SovereignK Driver"
    
    # Stop service
    Write-Info "Stopping service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    
    # Delete service
    Write-Info "Deleting service..."
    $result = sc.exe delete $ServiceName
    
    # Remove driver file
    $systemDriverPath = "C:\Windows\System32\drivers\SovereignK.sys"
    if (Test-Path $systemDriverPath) {
        Write-Info "Removing driver file..."
        Remove-Item -Path $systemDriverPath -Force -ErrorAction SilentlyContinue
    }
    
    Write-Success "Driver uninstalled"
}

# =============================================================================
# Status Check
# =============================================================================
function Get-DriverStatus {
    Write-Header "SovereignK Driver Status"
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-Info "Service Name: $($service.Name)"
        Write-Info "Display Name: $($service.DisplayName)"
        Write-Info "Status: $($service.Status)"
        Write-Info "Start Type: $($service.StartType)"
        
        if ($service.Status -eq "Running") {
            Write-Success "Driver is RUNNING"
            
            # Check if device exists
            $device = Get-ChildItem "\\.\$DeviceName" -ErrorAction SilentlyContinue
            if ($device) {
                Write-Success "Device object exists: \\.\$DeviceName"
            } else {
                Write-Warning "Device object not accessible (may require admin)"
            }
        } else {
            Write-Warning "Driver is NOT running"
        }
    } else {
        Write-Error "Service not found - driver is not installed"
    }
    
    # Check test signing
    $bcdOutput = bcdedit /enum | Select-String "testsigning"
    Write-Info "Test Signing: $($bcdOutput)"
}

# =============================================================================
# Run Tests
# =============================================================================
function Run-Tests {
    Write-Header "Running Hardware Aperture Probe"
    
    # Check if driver is running
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service -or $service.Status -ne "Running") {
        Write-Error "Driver is not running. Install and start the driver first."
        return
    }
    
    # Find probe executable
    $probePaths = @(
        "D:\rawrxd\build-ninja\bin\HardwareApertureProbe.exe",
        "D:\rawrxd\build\bin\HardwareApertureProbe.exe",
        ".\HardwareApertureProbe.exe"
    )
    
    $probePath = $null
    foreach ($path in $probePaths) {
        if (Test-Path $path) {
            $probePath = $path
            break
        }
    }
    
    if (-not $probePath) {
        Write-Error "HardwareApertureProbe.exe not found"
        Write-Info "Build the probe first: cmake --build . --target HardwareApertureProbe"
        return
    }
    
    Write-Info "Found probe at: $probePath"
    
    # Set BAR0 address if provided
    if ($Bar0Address) {
        Write-Info "Setting BAR0 address: $Bar0Address"
        $env:SOVEREIGN_BAR0_PHYS = $Bar0Address
    } else {
        Write-Warning "BAR0 address not provided. Probe may fail."
        Write-Info "Use -Bar0Address parameter or set SOVEREIGN_BAR0_PHYS environment variable"
    }
    
    # Run probe
    Write-Info "Starting probe..."
    Write-Info "Press Ctrl+C to abort within 3 seconds..."
    Start-Sleep -Seconds 3
    
    & $probePath
    
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        Write-Success "All tests passed!"
    } else {
        Write-Error "Tests failed with exit code: $exitCode"
    }
}

# =============================================================================
# Main Execution
# =============================================================================

if ($Install) {
    if (-not (Check-TestSigning)) {
        exit 1
    }
    Install-Driver
} elseif ($Uninstall) {
    Uninstall-Driver
} elseif ($Test) {
    Run-Tests
} elseif ($Status) {
    Get-DriverStatus
} else {
    # Default: show status
    Get-DriverStatus
    
    Write-Host "`nUsage:" -ForegroundColor Cyan
    Write-Host "  .\SovereignK-Manager.ps1 -Install              # Install driver"
    Write-Host "  .\SovereignK-Manager.ps1 -Uninstall            # Remove driver"
    Write-Host "  .\SovereignK-Manager.ps1 -Test               # Run probe tests"
    Write-Host "  .\SovereignK-Manager.ps1 -Test -Bar0Address 0x...  # With BAR address"
    Write-Host "  .\SovereignK-Manager.ps1 -Status               # Show status"
}
