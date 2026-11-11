# RawrXD OMEGA-1 Configuration Wizard
# Interactive setup and configuration tool

param(
    [string]$ConfigPath = "$env:LOCALAPPDATA\RawrXD\OMEGA1\config\omega1.json",
    [switch]$Reset = $false
)

$ErrorActionPreference = 'Stop'

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

function Read-UserInput {
    param($Prompt, $Default = "")
    
    if ($Default) {
        $fullPrompt = "$Prompt [$Default]: "
    } else {
        $fullPrompt = "$Prompt: "
    }
    
    $input = Read-Host $fullPrompt
    if ([string]::IsNullOrWhiteSpace($input) -and $Default) {
        return $Default
    }
    return $input
}

function Read-YesNo {
    param($Prompt, $Default = $true)
    
    $defaultStr = if ($Default) { "Y/n" } else { "y/N" }
    $response = Read-Host "$Prompt [$defaultStr]"
    
    if ([string]::IsNullOrWhiteSpace($response)) {
        return $Default
    }
    
    return $response -match "^[Yy]"
}

function Get-DefaultConfig {
    return @{
        version = "1.0.0"
        installDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        installDir = "$env:LOCALAPPDATA\RawrXD\OMEGA1"
        dualGpu = @{
            enabled = $true
            primaryGpu = "AMD Radeon AI PRO R9700"
            secondaryGpu = "AMD Radeon RX 7800 XT"
            layerSplit = @{
                primary = 22
                secondary = 10
            }
            thermal = @{
                failoverTemp = 95
                recoveryTemp = 85
            }
        }
        ipc = @{
            pipeName = "\\\\.\\pipe\\RawrXD_Omega1_v2"
            bufferSize = 65536
            timeoutMs = 30000
        }
        performance = @{
            targetPromptTps = 557
            targetGenerationTps = 344
            maxTokens = 2048
            temperature = 0.7
        }
        paths = @{
            models = "$env:LOCALAPPDATA\RawrXD\OMEGA1\models"
            logs = "$env:LOCALAPPDATA\RawrXD\OMEGA1\logs"
            temp = "$env:TEMP\RawrXD"
        }
        logging = @{
            level = "INFO"
            maxFileSizeMB = 100
            maxFiles = 10
            retentionDays = 30
        }
    }
}

function Show-Welcome {
    Clear-Host
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                                ║" -ForegroundColor Cyan
    Write-Host "║           RawrXD OMEGA-1 Configuration Wizard                                  ║" -ForegroundColor Cyan
    Write-Host "║                                                                                ║" -ForegroundColor Cyan
    Write-Host "║           This wizard will help you configure RawrXD OMEGA-1                   ║" -ForegroundColor Cyan
    Write-Host "║           for optimal performance on your system.                              ║" -ForegroundColor Cyan
    Write-Host "║                                                                                ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Write-Host "`n  Press Enter to continue..." -ForegroundColor Gray
    Read-Host
}

function Step-SystemDetection {
    Write-Header "Step 1: System Detection"
    
    Write-Status "Detecting system configuration..." "INFO"
    
    # Detect GPUs
    $gpus = Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -match "AMD|NVIDIA" -and $_.Status -eq "OK" }
    
    Write-Status "GPUs detected: $($gpus.Count)" "OK"
    foreach ($gpu in $gpus) {
        Write-Host "    - $($gpu.Name)" -ForegroundColor Gray
    }
    
    # Detect RAM
    $ram = Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | 
        Measure-Object -Property Capacity -Sum
    $ramGB = [math]::Round($ram.Sum / 1GB, 0)
    Write-Status "Memory detected: ${ramGB}GB" $(if($ramGB -ge 32){"OK"}else{"WARN"})
    
    # Detect CPU
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    Write-Status "CPU detected: $($cpu.Name)" "OK"
    
    Write-Host "`n  Press Enter to continue..." -ForegroundColor Gray
    Read-Host
    
    return @{
        GpuCount = $gpus.Count
        MemoryGB = $ramGB
        CpuName = $cpu.Name
    }
}

function Step-DualGpuConfig {
    param($SystemInfo)
    
    Write-Header "Step 2: Dual GPU Configuration"
    
    $config = @{}
    
    if ($SystemInfo.GpuCount -ge 2) {
        Write-Status "Dual GPU configuration detected!" "OK"
        $config.Enabled = Read-YesNo "Enable dual GPU support?" $true
        
        if ($config.Enabled) {
            $config.PrimaryLayers = [int](Read-UserInput "Primary GPU layers (default: 22)" "22")
            $config.SecondaryLayers = [int](Read-UserInput "Secondary GPU layers (default: 10)" "10")
            $config.FailoverTemp = [int](Read-UserInput "Failover temperature °C (default: 95)" "95")
            $config.RecoveryTemp = [int](Read-UserInput "Recovery temperature °C (default: 85)" "85")
        }
    } else {
        Write-Status "Single GPU configuration detected" "WARN"
        $config.Enabled = $false
        Write-Host "`n  Dual GPU features will be disabled." -ForegroundColor Yellow
    }
    
    Write-Host "`n  Press Enter to continue..." -ForegroundColor Gray
    Read-Host
    
    return $config
}

function Step-PerformanceConfig {
    Write-Header "Step 3: Performance Configuration"
    
    $config = @{}
    
    Write-Status "Configure performance targets..." "INFO"
    
    $config.MaxTokens = [int](Read-UserInput "Maximum tokens per generation (default: 2048)" "2048")
    $config.Temperature = [double](Read-UserInput "Default temperature (default: 0.7)" "0.7")
    
    $advanced = Read-YesNo "Configure advanced performance settings?" $false
    if ($advanced) {
        $config.TargetPromptTps = [int](Read-UserInput "Target prompt TPS (default: 557)" "557")
        $config.TargetGenTps = [int](Read-UserInput "Target generation TPS (default: 344)" "344")
    } else {
        $config.TargetPromptTps = 557
        $config.TargetGenTps = 344
    }
    
    Write-Host "`n  Press Enter to continue..." -ForegroundColor Gray
    Read-Host
    
    return $config
}

function Step-PathsConfig {
    Write-Header "Step 4: Paths Configuration"
    
    $config = @{}
    
    $defaultInstallDir = "$env:LOCALAPPDATA\RawrXD\OMEGA1"
    $config.InstallDir = Read-UserInput "Installation directory" $defaultInstallDir
    $config.ModelsDir = Read-UserInput "Models directory" "$($config.InstallDir)\models"
    $config.LogsDir = Read-UserInput "Logs directory" "$($config.InstallDir)\logs"
    
    Write-Host "`n  Press Enter to continue..." -ForegroundColor Gray
    Read-Host
    
    return $config
}

function Step-LoggingConfig {
    Write-Header "Step 5: Logging Configuration"
    
    $config = @{}
    
    Write-Status "Configure logging settings..." "INFO"
    
    $levels = @("DEBUG", "INFO", "WARN", "ERROR")
    Write-Host "`n  Available log levels: $($levels -join ', ')" -ForegroundColor Gray
    $config.Level = Read-UserInput "Log level (default: INFO)" "INFO"
    
    $config.MaxFileSize = [int](Read-UserInput "Max log file size MB (default: 100)" "100")
    $config.MaxFiles = [int](Read-UserInput "Max log files (default: 10)" "10")
    $config.RetentionDays = [int](Read-UserInput "Log retention days (default: 30)" "30")
    
    Write-Host "`n  Press Enter to continue..." -ForegroundColor Gray
    Read-Host
    
    return $config
}

function Step-Review {
    param($ConfigData)
    
    Write-Header "Step 6: Review Configuration"
    
    Write-Status "Please review your configuration:" "INFO"
    
    Write-Host "`n  Dual GPU:" -ForegroundColor Cyan
    Write-Host "    Enabled: $($ConfigData.DualGpu.Enabled)" -ForegroundColor Gray
    if ($ConfigData.DualGpu.Enabled) {
        Write-Host "    Primary layers: $($ConfigData.DualGpu.PrimaryLayers)" -ForegroundColor Gray
        Write-Host "    Secondary layers: $($ConfigData.DualGpu.SecondaryLayers)" -ForegroundColor Gray
    }
    
    Write-Host "`n  Performance:" -ForegroundColor Cyan
    Write-Host "    Max tokens: $($ConfigData.Performance.MaxTokens)" -ForegroundColor Gray
    Write-Host "    Temperature: $($ConfigData.Performance.Temperature)" -ForegroundColor Gray
    
    Write-Host "`n  Paths:" -ForegroundColor Cyan
    Write-Host "    Install: $($ConfigData.Paths.InstallDir)" -ForegroundColor Gray
    Write-Host "    Models: $($ConfigData.Paths.ModelsDir)" -ForegroundColor Gray
    Write-Host "    Logs: $($ConfigData.Paths.LogsDir)" -ForegroundColor Gray
    
    Write-Host "`n  Logging:" -ForegroundColor Cyan
    Write-Host "    Level: $($ConfigData.Logging.Level)" -ForegroundColor Gray
    Write-Host "    Max file size: $($ConfigData.Logging.MaxFileSize) MB" -ForegroundColor Gray
    
    $confirm = Read-YesNo "`nSave this configuration?" $true
    
    return $confirm
}

function Save-Configuration {
    param($ConfigData)
    
    Write-Header "Saving Configuration"
    
    $config = Get-DefaultConfig
    
    # Apply user settings
    $config.dualGpu.enabled = $ConfigData.DualGpu.Enabled
    if ($ConfigData.DualGpu.Enabled) {
        $config.dualGpu.layerSplit.primary = $ConfigData.DualGpu.PrimaryLayers
        $config.dualGpu.layerSplit.secondary = $ConfigData.DualGpu.SecondaryLayers
        $config.dualGpu.thermal.failoverTemp = $ConfigData.DualGpu.FailoverTemp
        $config.dualGpu.thermal.recoveryTemp = $ConfigData.DualGpu.RecoveryTemp
    }
    
    $config.performance.maxTokens = $ConfigData.Performance.MaxTokens
    $config.performance.temperature = $ConfigData.Performance.Temperature
    $config.performance.targetPromptTps = $ConfigData.Performance.TargetPromptTps
    $config.performance.targetGenerationTps = $ConfigData.Performance.TargetGenTps
    
    $config.paths.models = $ConfigData.Paths.ModelsDir
    $config.paths.logs = $ConfigData.Paths.LogsDir
    $config.installDir = $ConfigData.Paths.InstallDir
    
    $config.logging.level = $ConfigData.Logging.Level
    $config.logging.maxFileSizeMB = $ConfigData.Logging.MaxFileSize
    $config.logging.maxFiles = $ConfigData.Logging.MaxFiles
    $config.logging.retentionDays = $ConfigData.Logging.RetentionDays
    
    # Create directories
    $configDir = Split-Path $ConfigPath -Parent
    if (!(Test-Path $configDir)) {
        New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    }
    
    foreach ($path in @($ConfigData.Paths.ModelsDir, $ConfigData.Paths.LogsDir)) {
        if (!(Test-Path $path)) {
            New-Item -ItemType Directory -Force -Path $path | Out-Null
        }
    }
    
    # Save configuration
    $config | ConvertTo-Json -Depth 4 | Out-File $ConfigPath -Encoding UTF8
    
    Write-Status "Configuration saved to: $ConfigPath" "OK"
    
    # Display summary
    Write-Host "`n  Configuration Summary:" -ForegroundColor Cyan
    Write-Host "    Config file: $ConfigPath" -ForegroundColor Gray
    Write-Host "    Models dir: $($ConfigData.Paths.ModelsDir)" -ForegroundColor Gray
    Write-Host "    Logs dir: $($ConfigData.Paths.LogsDir)" -ForegroundColor Gray
}

# =============================================================================
# Main Execution
# =============================================================================
if ($Reset) {
    Write-Header "Reset Configuration"
    
    if (Test-Path $ConfigPath) {
        $backupPath = "$ConfigPath.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item $ConfigPath $backupPath
        Write-Status "Backed up existing config to: $backupPath" "OK"
    }
    
    $defaultConfig = Get-DefaultConfig
    $defaultConfig | ConvertTo-Json -Depth 4 | Out-File $ConfigPath -Encoding UTF8
    Write-Status "Configuration reset to defaults" "OK"
    exit 0
}

Show-Welcome

$systemInfo = Step-SystemDetection

$configData = @{
    SystemInfo = $systemInfo
    DualGpu = Step-DualGpuConfig -SystemInfo $systemInfo
    Performance = Step-PerformanceConfig
    Paths = Step-PathsConfig
    Logging = Step-LoggingConfig
}

$confirmed = Step-Review -ConfigData $configData

if ($confirmed) {
    Save-Configuration -ConfigData $configData
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║           ✅ Configuration Complete!                                           ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    Write-Host "`n  Next steps:" -ForegroundColor Cyan
    Write-Host "    1. Run validation: scripts\dual_gpu_live_test.ps1" -ForegroundColor Gray
    Write-Host "    2. Start IDE: bin\RawrXD-Win32IDE.exe" -ForegroundColor Gray
    Write-Host "    3. Download models: scripts\model_manager.ps1 -Action download" -ForegroundColor Gray
} else {
    Write-Host "`n  Configuration cancelled. No changes were saved." -ForegroundColor Yellow
}

Write-Host "`nConfiguration wizard complete!`n" -ForegroundColor Cyan
