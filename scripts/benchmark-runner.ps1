# RawrXD Benchmark Runner
# Comprehensive performance benchmarking suite

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Quick", "Standard", "Extended", "Stress")]
    [string]$Suite = "Standard",
    
    [string]$ModelPath = "",
    [string]$OutputPath = "benchmarks/results",
    [switch]$CompareBaseline,
    [string]$BaselinePath = "",
    [switch]$UploadResults,
    [string]$Device = "auto",  # auto, cpu, cuda, vulkan
    [int]$Iterations = 3
)

$ErrorActionPreference = "Stop"

# Configuration
$script:Config = @{
    ResultsDir = $OutputPath
    Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    Suite = $Suite
}

# Benchmark definitions
$Benchmarks = @{
    Quick = @(
        @{ Name = "tokenization"; Duration = 30 },
        @{ Name = "inference_small"; Duration = 60 }
    )
    Standard = @(
        @{ Name = "tokenization"; Duration = 60 },
        @{ Name = "inference_small"; Duration = 120 },
        @{ Name = "inference_medium"; Duration = 180 },
        @{ Name = "throughput"; Duration = 120 }
    )
    Extended = @(
        @{ Name = "tokenization"; Duration = 120 },
        @{ Name = "inference_small"; Duration = 180 },
        @{ Name = "inference_medium"; Duration = 300 },
        @{ Name = "inference_large"; Duration = 600 },
        @{ Name = "throughput"; Duration = 300 },
        @{ Name = "memory"; Duration = 180 },
        @{ Name = "context_scaling"; Duration = 300 }
    )
    Stress = @(
        @{ Name = "thermal"; Duration = 1800 },
        @{ Name = "memory_pressure"; Duration = 1200 },
        @{ Name = "concurrent"; Duration = 900 },
        @{ Name = "long_context"; Duration = 1800 }
    )
}

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

function Initialize-Environment {
    Write-Status "Initializing benchmark environment..."
    
    if (-not (Test-Path $script:Config.ResultsDir)) {
        New-Item -ItemType Directory -Path $script:Config.ResultsDir -Force | Out-Null
    }
    
    # Check for required binaries
    $requiredBinaries = @("rawrxd-bench.exe", "rawrxd-cli.exe")
    $foundBinaries = @()
    
    foreach ($binary in $requiredBinaries) {
        $path = Get-Command $binary -ErrorAction SilentlyContinue
        if ($path) {
            $foundBinaries += $binary
        }
    }
    
    if ($foundBinaries.Count -eq 0) {
        Write-Error "No benchmark binaries found. Please build the project first."
        exit 1
    }
    
    Write-Success "Found binaries: $($foundBinaries -join ', ')"
    
    # Detect hardware
    $script:Hardware = @{
        CPU = (Get-WmiObject Win32_Processor).Name
        Cores = $env:NUMBER_OF_PROCESSORS
        Memory = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    }
    
    # Detect GPU
    $gpu = Get-WmiObject Win32_VideoController | Where-Object { $_.Name -like "*NVIDIA*" } | Select-Object -First 1
    if ($gpu) {
        $script:Hardware.GPU = $gpu.Name
        $script:Hardware.GPUMemory = [math]::Round($gpu.AdapterRAM / 1GB, 2)
    }
    
    Write-Success "Hardware detected: $($script:Hardware.CPU)"
}

function Invoke-Benchmark {
    param(
        [string]$Name,
        [int]$Duration
    )
    
    Write-Status "Running benchmark: $Name (${Duration}s)..."
    
    $resultFile = "$($script:Config.ResultsDir)\$Name-$($script:Config.Timestamp).json"
    
    $benchArgs = @(
        "--benchmark", $Name,
        "--duration", $Duration,
        "--iterations", $Iterations,
        "--device", $Device,
        "--output", $resultFile
    )
    
    if ($ModelPath) {
        $benchArgs += "--model"
        $benchArgs += $ModelPath
    }
    
    $startTime = Get-Date
    
    try {
        $output = & rawrxd-bench.exe @benchArgs 2>&1
        $exitCode = $LASTEXITCODE
    }
    catch {
        Write-Error "Benchmark failed: $_"
        return $null
    }
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    if ($exitCode -ne 0) {
        Write-Error "Benchmark exited with code $exitCode"
        return $null
    }
    
    # Parse results
    $result = @{
        Name = $Name
        Duration = $duration
        Timestamp = Get-Date -Format "o"
        Hardware = $script:Hardware
        RawOutput = $output
    }
    
    # Try to load JSON results
    if (Test-Path $resultFile) {
        $jsonResults = Get-Content $resultFile | ConvertFrom-Json
        $result.Results = $jsonResults
    }
    
    Write-Success "Benchmark completed in $([math]::Round($duration, 2))s"
    
    return $result
}

function Show-Results {
    param([array]$Results)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Benchmark Results Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($result in $Results) {
        Write-Host "$($result.Name):" -ForegroundColor White
        
        if ($result.Results) {
            if ($result.Results.tokens_per_second) {
                Write-Host "  Tokens/sec: $($result.Results.tokens_per_second)" -ForegroundColor Green
            }
            if ($result.Results.latency_ms) {
                Write-Host "  Latency: $($result.Results.latency_ms) ms" -ForegroundColor Green
            }
            if ($result.Results.memory_mb) {
                Write-Host "  Memory: $($result.Results.memory_mb) MB" -ForegroundColor Green
            }
        }
        
        Write-Host ""
    }
}

function Export-Report {
    param([array]$Results)
    
    $reportFile = "$($script:Config.ResultsDir)\report-$($script:Config.Timestamp).json"
    
    $report = @{
        Timestamp = Get-Date -Format "o"
        Suite = $script:Config.Suite
        Hardware = $script:Hardware
        Results = $Results
        Summary = @{
            TotalBenchmarks = $Results.Count
            Passed = ($Results | Where-Object { $_.Results -ne $null }).Count
            Failed = ($Results | Where-Object { $_.Results -eq $null }).Count
        }
    }
    
    $report | ConvertTo-Json -Depth 10 | Out-File $reportFile
    
    Write-Success "Report saved to: $reportFile"
    
    # Generate HTML report
    $htmlReport = "$($script:Config.ResultsDir)\report-$($script:Config.Timestamp).html"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Benchmark Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .pass { color: green; }
        .fail { color: red; }
    </style>
</head>
<body>
    <h1>RawrXD Benchmark Report</h1>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p>Suite: $($script:Config.Suite)</p>
    <h2>Hardware</h2>
    <ul>
        <li>CPU: $($script:Hardware.CPU)</li>
        <li>Cores: $($script:Hardware.Cores)</li>
        <li>Memory: $($script:Hardware.Memory) GB</li>
        $(if ($script:Hardware.GPU) { "<li>GPU: $($script:Hardware.GPU)</li>" })
    </ul>
    <h2>Results</h2>
    <table>
        <tr>
            <th>Benchmark</th>
            <th>Status</th>
            <th>Duration</th>
            <th>Tokens/sec</th>
        </tr>
"@
    
    foreach ($result in $Results) {
        $status = if ($result.Results) { "PASS" } else { "FAIL" }
        $statusClass = if ($result.Results) { "pass" } else { "fail" }
        $tps = if ($result.Results.tokens_per_second) { $result.Results.tokens_per_second } else { "N/A" }
        
        $html += @"
        <tr>
            <td>$($result.Name)</td>
            <td class="$statusClass">$status</td>
            <td>$([math]::Round($result.Duration, 2))s</td>
            <td>$tps</td>
        </tr>
"@
    }
    
    $html += @"
    </table>
</body>
</html>
"@
    
    $html | Out-File $htmlReport
    Write-Success "HTML report saved to: $htmlReport"
}

function Main {
    Write-Host "RawrXD Benchmark Runner" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Suite: $Suite" -ForegroundColor Gray
    Write-Host "Iterations: $Iterations" -ForegroundColor Gray
    Write-Host "Device: $Device" -ForegroundColor Gray
    Write-Host ""
    
    Initialize-Environment
    
    $results = @()
    $benchmarkList = $Benchmarks[$Suite]
    
    foreach ($benchmark in $benchmarkList) {
        $result = Invoke-Benchmark -Name $benchmark.Name -Duration $benchmark.Duration
        $results += $result
    }
    
    Show-Results -Results $results
    Export-Report -Results $results
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Success "Benchmark suite completed!"
    Write-Host "Results saved to: $($script:Config.ResultsDir)" -ForegroundColor Gray
}

Main
