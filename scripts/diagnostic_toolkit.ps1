# RawrXD OMEGA-1 Diagnostic Toolkit
# Comprehensive system diagnostics and troubleshooting

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("full", "quick", "gpu", "ipc", "system", "network")]
    [string]$Mode = "full",
    
    [string]$OutputDir = "d:\rawrxd\diagnostics",
    [switch]$GenerateReport = $true,
    [switch]$FixIssues = $false
)

$ErrorActionPreference = 'Continue'
$script:IssuesFound = 0
$script:IssuesFixed = 0
$script:Diagnostics = @{}

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
        "INFO" { "White" }
        default { "Gray" }
    }
    Write-Host "  [$Status] $Text" -ForegroundColor $color
}

function Add-DiagnosticResult {
    param($Category, $Test, $Status, $Details = "")
    
    if (!$script:Diagnostics.ContainsKey($Category)) {
        $script:Diagnostics[$Category] = @()
    }
    
    $script:Diagnostics[$Category] += [PSCustomObject]@{
        Test = $Test
        Status = $Status
        Details = $Details
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    if ($Status -eq "FAIL") { $script:IssuesFound++ }
}

# =============================================================================
# System Diagnostics
# =============================================================================
function Test-SystemRequirements {
    Write-Header "System Requirements Check"
    
    # OS Check
    $os = Get-CimInstance Win32_OperatingSystem
    $osVersion = [System.Environment]::OSVersion.Version
    $is64Bit = $os.OSArchitecture -eq "64-bit"
    
    if ($is64Bit -and $osVersion.Major -ge 10) {
        Write-Status "OS: $($os.Caption) ($($os.OSArchitecture))" "OK"
        Add-DiagnosticResult "System" "OS Version" "OK" "$($os.Caption)"
    } else {
        Write-Status "OS: $($os.Caption) - Windows 10+ 64-bit required" "FAIL"
        Add-DiagnosticResult "System" "OS Version" "FAIL" "Windows 10+ 64-bit required"
    }
    
    # RAM Check
    $ramGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 0)
    if ($ramGB -ge 32) {
        Write-Status "RAM: ${ramGB}GB" "OK"
        Add-DiagnosticResult "System" "Memory" "OK" "${ramGB}GB"
    } elseif ($ramGB -ge 16) {
        Write-Status "RAM: ${ramGB}GB (32GB+ recommended)" "WARN"
        Add-DiagnosticResult "System" "Memory" "WARN" "${ramGB}GB (32GB+ recommended)"
    } else {
        Write-Status "RAM: ${ramGB}GB (insufficient)" "FAIL"
        Add-DiagnosticResult "System" "Memory" "FAIL" "${ramGB}GB (minimum 16GB required)"
    }
    
    # Disk Space
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    if ($freeGB -ge 10) {
        Write-Status "Disk Space: ${freeGB}GB free" "OK"
        Add-DiagnosticResult "System" "Disk Space" "OK" "${freeGB}GB free"
    } else {
        Write-Status "Disk Space: ${freeGB}GB free (10GB+ recommended)" "WARN"
        Add-DiagnosticResult "System" "Disk Space" "WARN" "${freeGB}GB free"
    }
    
    # PowerShell Version
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        Write-Status "PowerShell: $($PSVersionTable.PSVersion)" "OK"
        Add-DiagnosticResult "System" "PowerShell" "OK" "Version $($PSVersionTable.PSVersion)"
    } else {
        Write-Status "PowerShell: $($PSVersionTable.PSVersion) (5.0+ required)" "FAIL"
        Add-DiagnosticResult "System" "PowerShell" "FAIL" "Version $($PSVersionTable.PSVersion)"
    }
}

# =============================================================================
# GPU Diagnostics
# =============================================================================
function Test-GpuConfiguration {
    Write-Header "GPU Configuration Check"
    
    $gpus = Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -match "AMD|NVIDIA|Intel" -and $_.Status -eq "OK" }
    
    if ($gpus.Count -eq 0) {
        Write-Status "No GPUs detected!" "FAIL"
        Add-DiagnosticResult "GPU" "Detection" "FAIL" "No GPUs found"
        return
    }
    
    Write-Status "GPUs detected: $($gpus.Count)" "OK"
    Add-DiagnosticResult "GPU" "Count" "OK" "$($gpus.Count) GPUs"
    
    $discreteGpus = $gpus | Where-Object { $_.Name -notmatch "Graphics\(TM\)|Integrated" }
    
    if ($discreteGpus.Count -ge 2) {
        Write-Status "Dual GPU configuration detected" "OK"
        Add-DiagnosticResult "GPU" "Dual GPU" "OK" "$($discreteGpus.Count) discrete GPUs"
        
        foreach ($gpu in $discreteGpus) {
            Write-Status "  - $($gpu.Name)" "INFO"
            
            # Try to get driver version
            try {
                $gpuInfo = Get-CimInstance Win32_VideoController | Where-Object { $_.Name -eq $gpu.Name }
                if ($gpuInfo) {
                    Write-Status "    Driver: $($gpuInfo.DriverVersion)" "INFO"
                    Add-DiagnosticResult "GPU" "$($gpu.Name) Driver" "OK" "Version $($gpuInfo.DriverVersion)"
                }
            } catch {
                Write-Status "    Driver info unavailable" "WARN"
            }
        }
    } elseif ($discreteGpus.Count -eq 1) {
        Write-Status "Single GPU detected (dual GPU recommended)" "WARN"
        Add-DiagnosticResult "GPU" "Dual GPU" "WARN" "Only 1 discrete GPU"
    } else {
        Write-Status "No discrete GPUs detected" "WARN"
        Add-DiagnosticResult "GPU" "Discrete GPU" "WARN" "Using integrated graphics"
    }
    
    # Check for AMD GPUs specifically
    $amdGpus = $gpus | Where-Object { $_.Name -match "AMD|Radeon" }
    if ($amdGpus.Count -gt 0) {
        Write-Status "AMD GPUs: $($amdGpus.Count)" "OK"
        Add-DiagnosticResult "GPU" "AMD Support" "OK" "$($amdGpus.Count) AMD GPUs"
    }
}

# =============================================================================
# Binary Diagnostics
# =============================================================================
function Test-BinaryIntegrity {
    Write-Header "Binary Integrity Check"
    
    $binDir = "d:\rawrxd\build\bin"
    $requiredBinaries = @(
        "RawrXD-Win32IDE.exe",
        "RawrXD-InferenceEngine.exe"
    )
    
    foreach ($bin in $requiredBinaries) {
        $path = Join-Path $binDir $bin
        if (Test-Path $path) {
            $size = [math]::Round((Get-Item $path).Length / 1MB, 2)
            Write-Status "$bin`: $size MB" "OK"
            Add-DiagnosticResult "Binaries" $bin "OK" "${size}MB"
        } else {
            Write-Status "$bin`: Not found" "FAIL"
            Add-DiagnosticResult "Binaries" $bin "FAIL" "File not found"
        }
    }
    
    # Check if binaries are running
    $ideProcess = Get-Process "RawrXD-Win32IDE" -ErrorAction SilentlyContinue
    $engineProcess = Get-Process "RawrXD-InferenceEngine" -ErrorAction SilentlyContinue
    
    if ($ideProcess) {
        Write-Status "Win32IDE is running (PID: $($ideProcess.Id))" "OK"
        Add-DiagnosticResult "Binaries" "Win32IDE Status" "OK" "Running (PID $($ideProcess.Id))"
    } else {
        Write-Status "Win32IDE is not running" "INFO"
        Add-DiagnosticResult "Binaries" "Win32IDE Status" "INFO" "Not running"
    }
    
    if ($engineProcess) {
        Write-Status "InferenceEngine is running (PID: $($engineProcess.Id))" "OK"
        Add-DiagnosticResult "Binaries" "InferenceEngine Status" "OK" "Running (PID $($engineProcess.Id))"
    } else {
        Write-Status "InferenceEngine is not running" "INFO"
        Add-DiagnosticResult "Binaries" "InferenceEngine Status" "INFO" "Not running"
    }
}

# =============================================================================
# IPC Diagnostics
# =============================================================================
function Test-IpcConfiguration {
    Write-Header "IPC Configuration Check"
    
    # Check named pipes
    try {
        $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match "RawrXD" }
        if ($pipes.Count -gt 0) {
            Write-Status "Named pipes: $($pipes.Count)" "OK"
            Add-DiagnosticResult "IPC" "Named Pipes" "OK" "$($pipes.Count) pipes found"
            
            foreach ($pipe in $pipes) {
                $pipeName = Split-Path $pipe -Leaf
                Write-Status "  - $pipeName" "INFO"
            }
        } else {
            Write-Status "No RawrXD named pipes found" "INFO"
            Add-DiagnosticResult "IPC" "Named Pipes" "INFO" "No pipes (processes not running)"
        }
    } catch {
        Write-Status "Cannot enumerate named pipes" "WARN"
        Add-DiagnosticResult "IPC" "Named Pipes" "WARN" "Access denied"
    }
    
    # Check pipe name format
    $pipeName = "\\.\pipe\RawrXD_Omega1_v2"
    if ($pipeName -match "^\\\\\.\\pipe\\[A-Za-z0-9_]+$") {
        Write-Status "Pipe name format: Valid" "OK"
        Add-DiagnosticResult "IPC" "Pipe Format" "OK" "Valid format"
    } else {
        Write-Status "Pipe name format: Invalid" "FAIL"
        Add-DiagnosticResult "IPC" "Pipe Format" "FAIL" "Invalid format"
    }
}

# =============================================================================
# Network Diagnostics
# =============================================================================
function Test-NetworkConfiguration {
    Write-Header "Network Configuration Check"
    
    # Check if firewall rules exist
    try {
        $rules = Get-NetFirewallRule -DisplayName "RawrXD*" -ErrorAction SilentlyContinue
        if ($rules) {
            Write-Status "Firewall rules: $($rules.Count)" "OK"
            Add-DiagnosticResult "Network" "Firewall" "OK" "$($rules.Count) rules"
            
            foreach ($rule in $rules) {
                Write-Status "  - $($rule.DisplayName): $($rule.Enabled)" "INFO"
            }
        } else {
            Write-Status "No RawrXD firewall rules found" "WARN"
            Add-DiagnosticResult "Network" "Firewall" "WARN" "No rules configured"
        }
    } catch {
        Write-Status "Cannot check firewall rules" "WARN"
        Add-DiagnosticResult "Network" "Firewall" "WARN" "Access denied"
    }
    
    # Check localhost connectivity
    try {
        $ping = Test-Connection -ComputerName "localhost" -Count 1 -ErrorAction SilentlyContinue
        if ($ping) {
            Write-Status "Localhost connectivity: OK" "OK"
            Add-DiagnosticResult "Network" "Localhost" "OK" "Responding"
        } else {
            Write-Status "Localhost connectivity: Failed" "FAIL"
            Add-DiagnosticResult "Network" "Localhost" "FAIL" "Not responding"
        }
    } catch {
        Write-Status "Localhost connectivity: Error" "WARN"
    }
}

# =============================================================================
# Configuration Diagnostics
# =============================================================================
function Test-Configuration {
    Write-Header "Configuration Check"
    
    $configPaths = @(
        "d:\rawrxd\config\omega1.json",
        "d:\rawrxd\releases\RawrXD-OMEGA1-v1.0.0\config\omega1.json"
    )
    
    $configFound = $false
    foreach ($path in $configPaths) {
        if (Test-Path $path) {
            Write-Status "Configuration found: $path" "OK"
            Add-DiagnosticResult "Config" "File" "OK" $path
            $configFound = $true
            
            try {
                $config = Get-Content $path -Raw | ConvertFrom-Json
                Write-Status "  Version: $($config.version)" "INFO"
                Write-Status "  Dual GPU: $($config.dualGpu.enabled)" "INFO"
                Add-DiagnosticResult "Config" "Version" "OK" $config.version
            } catch {
                Write-Status "  Config parse error" "WARN"
                Add-DiagnosticResult "Config" "Parse" "WARN" "Invalid JSON"
            }
            break
        }
    }
    
    if (!$configFound) {
        Write-Status "Configuration file not found" "WARN"
        Add-DiagnosticResult "Config" "File" "WARN" "Not found"
    }
}

# =============================================================================
# Report Generation
# =============================================================================
function Export-DiagnosticReport {
    if (!$GenerateReport) { return }
    
    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }
    
    $reportFile = Join-Path $OutputDir "diagnostic_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    $report = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Mode = $Mode
        IssuesFound = $script:IssuesFound
        IssuesFixed = $script:IssuesFixed
        Diagnostics = $script:Diagnostics
        System = @{
            OS = (Get-CimInstance Win32_OperatingSystem).Caption
            Architecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
            PowerShell = $PSVersionTable.PSVersion.ToString()
        }
    }
    
    $report | ConvertTo-Json -Depth 4 | Out-File $reportFile
    Write-Host "`n  Report saved to: $reportFile" -ForegroundColor Gray
}

function Show-Summary {
    Write-Header "Diagnostic Summary"
    
    $totalTests = 0
    $passedTests = 0
    $failedTests = 0
    $warningTests = 0
    
    foreach ($category in $script:Diagnostics.Keys) {
        foreach ($test in $script:Diagnostics[$category]) {
            $totalTests++
            switch ($test.Status) {
                "OK" { $passedTests++ }
                "FAIL" { $failedTests++ }
                "WARN" { $warningTests++ }
            }
        }
    }
    
    Write-Status "Total Tests: $totalTests" "INFO"
    Write-Status "Passed: $passedTests" "OK"
    Write-Status "Warnings: $warningTests" $(if($warningTests -gt 0){"WARN"}else{"OK"})
    Write-Status "Failed: $failedTests" $(if($failedTests -gt 0){"FAIL"}else{"OK"})
    
    if ($failedTests -eq 0 -and $warningTests -eq 0) {
        Write-Host "`n  ✅ All diagnostics passed!" -ForegroundColor Green
    } elseif ($failedTests -eq 0) {
        Write-Host "`n  ⚠️  Diagnostics completed with warnings" -ForegroundColor Yellow
    } else {
        Write-Host "`n  ❌ Diagnostics completed with failures" -ForegroundColor Red
    }
}

# =============================================================================
# Main Execution
# =============================================================================
Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD OMEGA-1 Diagnostic Toolkit                                          ║" -ForegroundColor Cyan
Write-Host "║     Mode: $Mode" -NoNewline -ForegroundColor Cyan
Write-Host "$(' ' * (63 - $Mode.Length))║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

switch ($Mode) {
    "full" {
        Test-SystemRequirements
        Test-GpuConfiguration
        Test-BinaryIntegrity
        Test-IpcConfiguration
        Test-NetworkConfiguration
        Test-Configuration
    }
    "quick" {
        Test-SystemRequirements
        Test-BinaryIntegrity
    }
    "gpu" {
        Test-GpuConfiguration
    }
    "ipc" {
        Test-IpcConfiguration
    }
    "system" {
        Test-SystemRequirements
        Test-Configuration
    }
    "network" {
        Test-NetworkConfiguration
    }
}

Show-Summary
Export-DiagnosticReport

Write-Host "`nDiagnostic complete!`n" -ForegroundColor Cyan
