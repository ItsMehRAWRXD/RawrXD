# ============================================================================
# BenchmarkHarness.ps1
# Head-to-head telemetry capture: Ollama baseline vs RawrXD
# Captures: GPU util, VRAM, RAM, disk I/O, pages/sec, process stats
# Writes: CSV for analysis + live TPS estimate
# ============================================================================
param(
    [string]$ModelName = "bluehawana/deepseek-v4-flash:iq2_m",
    [string]$Prompt = "Explain quantum computing in simple terms.",
    [int]$DurationSec = 60,
    [int]$SampleIntervalMs = 500,
    [string]$OutputDir = "$PWD\benchmark_results"
)

$ErrorActionPreference = "SilentlyContinue"
Import-Module -Name CimCmdlets

# Ensure output directory
if (!(Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = "$OutputDir\telemetry_$timestamp.csv"

# CSV header
$header = "Timestamp,ElapsedMs,AvailableMB,PagesPerSec,G_ReadMBps,F_ReadMBps,Total_ReadMBps," +
          "GPU_ComputePct,GPU_CopyPct,GPU_DedicatedMB,GPU_SharedMB," +
          "Ollama_CPU,Ollama_RAM_MB,Ollama_PrivateMB,Ollama_WorkingMB," +
          "TokensGenerated,TPS_Estimate,Phase"
$header | Out-File -FilePath $csvPath -Encoding ASCII

Write-Host "========================================"
Write-Host "RawrXD Benchmark Harness"
Write-Host "Model: $ModelName"
Write-Host "Prompt: $($Prompt.Substring(0,[Math]::Min(50,$Prompt.Length)))..."
Write-Host "Duration: ${DurationSec}s"
Write-Host "Output: $csvPath"
Write-Host "========================================"

# Find Ollama process
function Get-OllamaProcess {
    Get-Process | Where-Object { $_.ProcessName -like "*ollama*" -or $_.ProcessName -like "*runner*" } |
        Sort-Object WorkingSet64 -Descending | Select-Object -First 1
}

# Find GPU engine counter instance for Ollama
function Get-OllamaGpuInstance {
    $samples = (Get-Counter "\GPU Engine(*)\Utilization Percentage" -MaxSamples 1).CounterSamples
    $ollamaPid = (Get-OllamaProcess).Id
    $samples | Where-Object { $_.InstanceName -like "*pid_${ollamaPid}*" -and $_.InstanceName -like "*engtype_compute*" } |
        Select-Object -First 1
}

# Main capture loop
$startTime = Get-Date
$tokens = 0
$phase = "PREFILL"
$sampleCount = 0

while ($true) {
    $elapsed = ([DateTime]::Now - $startTime).TotalMilliseconds
    if ($elapsed -gt ($DurationSec * 1000)) { break }

    $now = Get-Date
    $t = $now.ToString("HH:mm:ss.fff")

    # Memory
    $os = Get-CimInstance Win32_OperatingSystem
    $availMB = [math]::Round($os.FreePhysicalMemory / 1024, 2)
    $pages = (Get-Counter "\Memory\Pages/sec" -MaxSamples 1).CounterSamples[0].CookedValue

    # Disk
    $diskSamples = (Get-Counter "\PhysicalDisk(*)\Disk Read Bytes/sec" -MaxSamples 1).CounterSamples
    $gRead = ($diskSamples | Where-Object { $_.InstanceName -eq "4 g:" }).CookedValue
    $fRead = ($diskSamples | Where-Object { $_.InstanceName -eq "3 f:" }).CookedValue
    $totalRead = ($diskSamples | Where-Object { $_.InstanceName -eq "_total" }).CookedValue
    if ($null -eq $gRead) { $gRead = 0 }
    if ($null -eq $fRead) { $fRead = 0 }
    if ($null -eq $totalRead) { $totalRead = 0 }

    # GPU
    $gpuCompute = 0
    $gpuCopy = 0
    $gpuDedicated = 0
    $gpuShared = 0
    try {
        $gpuSamples = (Get-Counter "\GPU Engine(*)\Utilization Percentage" -MaxSamples 1).CounterSamples
        $computeSamples = $gpuSamples | Where-Object { $_.InstanceName -like "*engtype_compute*" }
        $copySamples = $gpuSamples | Where-Object { $_.InstanceName -like "*engtype_copy*" }
        if ($computeSamples) {
            $gpuCompute = [math]::Round(($computeSamples | Measure-Object CookedValue -Sum).Sum, 2)
        }
        if ($copySamples) {
            $gpuCopy = [math]::Round(($copySamples | Measure-Object CookedValue -Sum).Sum, 2)
        }
        $gpuMem = (Get-Counter "\GPU Process Memory(*)\Dedicated Usage" -MaxSamples 1).CounterSamples
        $ollamaGpu = $gpuMem | Where-Object { $_.InstanceName -like "*ollama*" } | Select-Object -First 1
        if ($ollamaGpu) { $gpuDedicated = [math]::Round($ollamaGpu.CookedValue / 1MB, 2) }
    } catch {}

    # Ollama process
    $proc = Get-OllamaProcess
    $cpuPct = 0
    $ramMB = 0
    $privateMB = 0
    $workingMB = 0
    if ($proc) {
        $cpuPct = [math]::Round($proc.CPU, 2)
        $ramMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
        $privateMB = [math]::Round($proc.PrivateMemorySize64 / 1MB, 2)
        $workingMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
    }

    # Phase detection heuristic
    if ($phase -eq "PREFILL" -and $elapsed -gt 5000 -and $gpuCompute -gt 5) {
        $phase = "DECODE"
    }

    # TPS estimate (very rough: assume ~4 tokens/sec baseline for this model)
    $tps = 0
    if ($phase -eq "DECODE" -and $gpuCompute -gt 10) {
        $tps = [math]::Round($gpuCompute / 3.0, 2)  # heuristic: ~3% GPU per TPS
    }
    $tokens += [math]::Round($tps * ($SampleIntervalMs / 1000.0), 0)

    # Write CSV
    $line = "$t,${elapsed},${availMB},$([math]::Round($pages,2)),$([math]::Round($gRead/1MB,2)),$([math]::Round($fRead/1MB,2)),$([math]::Round($totalRead/1MB,2))," +
            "${gpuCompute},${gpuCopy},${gpuDedicated},${gpuShared}," +
            "${cpuPct},${ramMB},${privateMB},${workingMB},${tokens},${tps},${phase}"
    $line | Out-File -FilePath $csvPath -Append -Encoding ASCII

    $sampleCount++
    if ($sampleCount % 10 -eq 0) {
        Write-Host "$t | Avail:${availMB}MB | Pages:$([math]::Round($pages,0)) | G:$([math]::Round($gRead/1MB,1))MB/s | GPU:${gpuCompute}% | Phase:$phase | TPS:~$tps"
    }

    Start-Sleep -Milliseconds $SampleIntervalMs
}

Write-Host ""
Write-Host "========================================"
Write-Host "Benchmark complete: $sampleCount samples"
Write-Host "Output: $csvPath"
Write-Host "========================================"

# Quick summary
$csv = Import-Csv $csvPath
$avgPages = ($csv | Measure-Object PagesPerSec -Average).Average
$maxPages = ($csv | Measure-Object PagesPerSec -Maximum).Maximum
$avgGpu = ($csv | Measure-Object GPU_ComputePct -Average).Average
$maxGpu = ($csv | Measure-Object GPU_ComputePct -Maximum).Maximum
$avgG = ($csv | Measure-Object G_ReadMBps -Average).Average
$maxG = ($csv | Measure-Object G_ReadMBps -Maximum).Maximum

Write-Host ""
Write-Host "Summary:"
Write-Host "  Avg Pages/sec:  $([math]::Round($avgPages,0)) (max: $([math]::Round($maxPages,0)))"
Write-Host "  Avg GPU:        $([math]::Round($avgGpu,1))% (max: $([math]::Round($maxGpu,1))%)"
Write-Host "  Avg G: read:    $([math]::Round($avgG,1)) MB/s (max: $([math]::Round($maxG,1)) MB/s)"
Write-Host "  Total tokens:   $($csv[-1].TokensGenerated)"
