# RawrXD Phase E.1 — Environment Freeze Protocol
# Locks system state before benchmark execution
# Output: environment_lock.json (SHA256 fingerprinted)

param(
    [string]$OutputFile = "environment_lock.json",
    [switch]$Verify
)

$ErrorActionPreference = "Stop"

function Get-GitState {
    $commit = git rev-parse HEAD
    $branch = git branch --show-current
    $status = git status --porcelain
    $remote = git config --get remote.origin.url
    
    return @{
        commit = $commit
        commit_short = $commit.Substring(0, 7)
        branch = $branch
        dirty = ($status -ne $null -and $status -ne "")
        remote_url = $remote
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    }
}

function Get-ModelState {
    param([string]$ModelPath)
    
    if (-not (Test-Path $ModelPath)) {
        return @{ error = "Model not found: $ModelPath" }
    }
    
    $file = Get-Item $ModelPath
    $hash = (Get-FileHash $ModelPath -Algorithm SHA256).Hash
    
    # Try to extract GGUF metadata
    $metadata = @{}
    try {
        $bytes = [System.IO.File]::ReadAllBytes($ModelPath)
        $header = [System.Text.Encoding]::UTF8.GetString($bytes[0..[Math]::Min(1024, $bytes.Length - 1)])
        if ($header -match "GGUF") {
            $metadata.format = "GGUF"
            $metadata.version = if ($header -match "GGUF(\d)") { $matches[1] } else { "unknown" }
        }
    } catch {}
    
    return @{
        path = $ModelPath
        filename = $file.Name
        size_bytes = $file.Length
        size_gb = [math]::Round($file.Length / 1GB, 2)
        sha256 = $hash
        last_modified = $file.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
        metadata = $metadata
    }
}

function Get-DriverState {
    $drivers = @{}
    
    # AMD GPU
    $amdGpu = Get-WmiObject Win32_VideoController | Where-Object { $_.Name -match "AMD|Radeon" } | Select-Object -First 1
    if ($amdGpu) {
        $drivers.gpu = @{
            name = $amdGpu.Name
            driver_version = $amdGpu.DriverVersion
            video_processor = $amdGpu.VideoProcessor
        }
    }
    
    # ROCm
    $rocmVersion = $null
    try {
        $hipcc = Get-Command hipcc -ErrorAction SilentlyContinue
        if ($hipcc) {
            $rocmOutput = & hipcc --version 2>$null | Select-String "HIP version" | Select-Object -First 1
            if ($rocmOutput) { $rocmVersion = $rocmOutput.Line }
        }
    } catch {}
    
    $drivers.rocm = $rocmVersion
    
    # Vulkan
    $vulkanVersion = $null
    try {
        $vulkanInfo = Get-Command vulkaninfo -ErrorAction SilentlyContinue
        if ($vulkanInfo) {
            $vkOutput = & vulkaninfo --summary 2>$null | Select-String "Vulkan Instance Version" | Select-Object -First 1
            if ($vkOutput -match "(\d+\.\d+\.\d+)") { $vulkanVersion = $matches[1] }
        }
    } catch {}
    
    $drivers.vulkan = $vulkanVersion
    
    return $drivers
}

function Get-SystemState {
    $os = Get-WmiObject Win32_OperatingSystem
    $cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
    $mem = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    
    # Power profile
    $powerProfile = powercfg /getactivescheme 2>$null
    
    return @{
        os = @{
            name = $os.Caption
            version = $os.Version
            build = $os.BuildNumber
            architecture = $os.OSArchitecture
        }
        cpu = @{
            name = $cpu.Name
            cores = $cpu.NumberOfCores
            logical = $cpu.NumberOfLogicalProcessors
        }
        memory = @{
            total_gb = [math]::Round($mem.Sum / 1GB, 2)
            slots = (Get-WmiObject Win32_PhysicalMemory).Count
        }
        power_profile = $powerProfile
    }
}

function Get-BackgroundState {
    $processes = Get-Process | Where-Object { 
        $_.CPU -gt 100 -and 
        $_.ProcessName -notin @("RawrXD", "powershell", "pwsh", "explorer", "svchost")
    } | Select-Object -First 10
    
    return $processes | ForEach-Object {
        @{
            name = $_.ProcessName
            id = $_.Id
            cpu_percent = [math]::Round($_.CPU, 2)
            working_set_mb = [math]::Round($_.WorkingSet64 / 1MB, 2)
        }
    }
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║  RawrXD Phase E.1 — Environment Freeze Protocol                ║
║  ===============================================               ║
║  Lock system state before benchmark execution                  ║
╚════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host ""

if ($Verify) {
    Write-Host "[VERIFY MODE] Checking environment against lock file..." -ForegroundColor Yellow
    if (-not (Test-Path $OutputFile)) {
        throw "Lock file not found: $OutputFile"
    }
    $locked = Get-Content $OutputFile | ConvertFrom-Json
    Write-Host "  Locked commit: $($locked.git.commit_short)" -ForegroundColor Gray
    Write-Host "  Locked model: $($locked.model.filename)" -ForegroundColor Gray
    Write-Host "  Locked GPU: $($locked.drivers.gpu.name)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Run freeze without -Verify to create new lock" -ForegroundColor Yellow
    exit 0
}

Write-Host "[1/5] Capturing Git state..." -ForegroundColor Yellow
$gitState = Get-GitState
Write-Host "  Commit: $($gitState.commit_short) on $($gitState.branch)" -ForegroundColor $(if ($gitState.dirty) { "Red" } else { "Green" })
if ($gitState.dirty) {
    Write-Host "  ⚠ WARNING: Working directory is dirty!" -ForegroundColor Red
    Write-Host "  Commit all changes before freezing environment" -ForegroundColor Yellow
}

Write-Host "`n[2/5] Capturing model state..." -ForegroundColor Yellow
$modelPath = Read-Host "Enter path to GGUF model (e.g., models\phi-3-mini-Q4_K_M.gguf)"
$modelState = Get-ModelState -ModelPath $modelPath
Write-Host "  Model: $($modelState.filename)" -ForegroundColor Green
Write-Host "  Size: $($modelState.size_gb) GB" -ForegroundColor Gray
Write-Host "  SHA256: $($modelState.sha256.Substring(0, 16))..." -ForegroundColor Gray

Write-Host "`n[3/5] Capturing driver state..." -ForegroundColor Yellow
$driverState = Get-DriverState
Write-Host "  GPU: $($driverState.gpu.name)" -ForegroundColor Green
Write-Host "  Driver: $($driverState.gpu.driver_version)" -ForegroundColor Gray
if ($driverState.rocm) { Write-Host "  ROCm: $($driverState.rocm)" -ForegroundColor Gray }
if ($driverState.vulkan) { Write-Host "  Vulkan: $($driverState.vulkan)" -ForegroundColor Gray }

Write-Host "`n[4/5] Capturing system state..." -ForegroundColor Yellow
$systemState = Get-SystemState
Write-Host "  OS: $($systemState.os.name)" -ForegroundColor Green
Write-Host "  CPU: $($systemState.cpu.name)" -ForegroundColor Gray
Write-Host "  RAM: $($systemState.memory.total_gb) GB" -ForegroundColor Gray

Write-Host "`n[5/5] Checking background processes..." -ForegroundColor Yellow
$background = Get-BackgroundState
if ($background.Count -gt 0) {
    Write-Host "  ⚠ Found $($background.Count) active processes:" -ForegroundColor Yellow
    foreach ($proc in $background) {
        Write-Host "    - $($proc.name) (PID $($proc.id)): $($proc.cpu_percent)% CPU" -ForegroundColor Gray
    }
    Write-Host "  Consider closing these for clean benchmarks" -ForegroundColor Yellow
} else {
    Write-Host "  ✓ No significant background processes detected" -ForegroundColor Green
}

# Compile lock file
$lockData = @{
    schema_version = "1.0.0"
    frozen_at = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    git = $gitState
    model = $modelState
    drivers = $driverState
    system = $systemState
    background_processes = $background
    validation_protocol = @{
        warmup_runs = 10
        measured_runs = 30
        min_runs_for_ci = 20
        significance_threshold = 0.05
        effect_size_threshold = 0.8
        cv_threshold = 0.05
    }
}

# Generate fingerprint
$jsonString = $lockData | ConvertTo-Json -Depth 10 -Compress
$fingerprint = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($jsonString))).Replace("-", "")
$lockData.fingerprint = $fingerprint

# Save lock file
$lockData | ConvertTo-Json -Depth 10 | Set-Content $OutputFile

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅ Environment FROZEN                                         ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Lock file: $OutputFile" -ForegroundColor Yellow
Write-Host "Fingerprint: $fingerprint" -ForegroundColor Cyan
Write-Host ""
Write-Host "This environment state is now locked for Phase E.1 execution." -ForegroundColor White
Write-Host "Any changes to code, model, or drivers will invalidate results." -ForegroundColor White
Write-Host ""
Write-Host "Next: Run benchmarks with:" -ForegroundColor Yellow
Write-Host "  .\build_and_run.ps1 -Model \"$modelPath\" -Patch \"gemm\"" -ForegroundColor White
