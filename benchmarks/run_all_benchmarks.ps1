# =============================================================================
# RawrXD Comprehensive TPS Benchmark Suite
# Master runner for all TPS benchmarks
# =============================================================================

param(
    [switch]$BuildOnly,
    [switch]$RunOnly,
    [string]$Filter = "*",
    [int]$Iterations = 3,
    [string]$OutputDir = "benchmark_results"
)

$ErrorActionPreference = "Stop"

# Configuration
$BenchmarkDir = $PSScriptRoot
$BuildDir = "$BenchmarkDir\build"
$ResultsDir = "$BenchmarkDir\$OutputDir"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Benchmark executables
$Benchmarks = @(
    @{ Name = "MASM Hello World"; File = "masm_hello_world.exe"; Type = "MASM" },
    @{ Name = "C++ Hello World"; File = "cpp_hello_world.exe"; Type = "CPP" },
    @{ Name = "Swarm TPS"; File = "swarm_tps_benchmark.exe"; Type = "CPP" },
    @{ Name = "Chat TPS"; File = "chat_tps_benchmark.exe"; Type = "CPP" },
    @{ Name = "Agentic TPS"; File = "agentic_tps_benchmark.exe"; Type = "CPP" }
)

# Colors
$Colors = @{
    Header = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Info = "White"
}

# =============================================================================
# Helper Functions
# =============================================================================

function Write-Header($text) {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor $Colors.Header
    Write-Host $text -ForegroundColor $Colors.Header
    Write-Host "================================================================================" -ForegroundColor $Colors.Header
}

function Write-Section($text) {
    Write-Host ""
    Write-Host "[$text]" -ForegroundColor $Colors.Warning
}

function Test-Executable($path) {
    return Test-Path $path -PathType Leaf
}

function Run-Benchmark($benchmark, $iteration) {
    $exePath = "$BuildDir\$($benchmark.File)"
    
    if (-not (Test-Executable $exePath)) {
        Write-Host "  ERROR: Executable not found: $exePath" -ForegroundColor $Colors.Error
        return $null
    }
    
    Write-Host "  Run $iteration/$Iterations..." -NoNewline
    
    $output = & $exePath 2>&1
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -ne 0) {
        Write-Host " FAILED (exit code $exitCode)" -ForegroundColor $Colors.Error
        return $null
    }
    
    Write-Host " OK" -ForegroundColor $Colors.Success
    
    # Parse TPS from output
    $tps = 0
    foreach ($line in $output) {
        if ($line -match "TPS[:\s]+([\d,]+(?:\.\d+)?)") {
            $tps = [double]($matches[1] -replace ',', '')
            break
        }
    }
    
    return @{
        Output = $output
        TPS = $tps
        ExitCode = $exitCode
    }
}

function Build-MASM($name, $asmFile) {
    Write-Host "  Building $name..." -NoNewline
    
    $ml64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
    $objFile = "$BuildDir\$([System.IO.Path]::GetFileNameWithoutExtension($asmFile)).obj"
    $exeFile = "$BuildDir\$([System.IO.Path]::GetFileNameWithoutExtension($asmFile)).exe"
    
    # Assemble
    $asmOutput = & $ml64 "/c", "/W3", "/nologo", "/Fo$objFile", "$BenchmarkDir\$asmFile" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host " FAILED" -ForegroundColor $Colors.Error
        $asmOutput | Write-Host
        return $false
    }
    
    # Link
    $link = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
    $linkOutput = & $link "/SUBSYSTEM:CONSOLE", "/ENTRY:mainCRTStartup", "/NODEFAULTLIB", "/LARGEADDRESSAWARE:NO", "/OUT:$exeFile", $objFile 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host " FAILED" -ForegroundColor $Colors.Error
        $linkOutput | Write-Host
        return $false
    }
    
    Write-Host " OK" -ForegroundColor $Colors.Success
    return $true
}

function Build-CPP($name, $cppFile) {
    Write-Host "  Building $name..." -NoNewline
    
    $cl = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
    $exeFile = "$BuildDir\$([System.IO.Path]::GetFileNameWithoutExtension($cppFile)).exe"
    
    $flags = @(
        "/O2",                    # Optimize for speed
        "/arch:AVX2",            # Enable AVX2
        "/EHsc",                 # Exception handling
        "/MT",                   # Static runtime
        "/std:c++17",            # C++17
        "/W3",                   # Warning level 3
        "/nologo",               # No logo
        "/Fe$exeFile"           # Output executable
    )
    
    $compileOutput = & $cl $flags "$BenchmarkDir\$cppFile" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host " FAILED" -ForegroundColor $Colors.Error
        $compileOutput | Write-Host
        return $false
    }
    
    Write-Host " OK" -ForegroundColor $Colors.Success
    return $true
}

# =============================================================================
# Main Script
# =============================================================================

Write-Header "RawrXD Comprehensive TPS Benchmark Suite"

# Create directories
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
}
if (-not (Test-Path $ResultsDir)) {
    New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
}

# Build phase
if (-not $RunOnly) {
    Write-Section "BUILD"
    
    # Build MASM benchmark
    Build-MASM "MASM Hello World" "masm_hello_world.asm"
    
    # Build C++ benchmarks
    Build-CPP "C++ Hello World" "cpp_hello_world.cpp"
    Build-CPP "Swarm TPS" "swarm_tps_benchmark.cpp"
    Build-CPP "Chat TPS" "chat_tps_benchmark.cpp"
    Build-CPP "Agentic TPS" "agentic_tps_benchmark.cpp"
    
    Write-Host ""
    Write-Host "Build complete." -ForegroundColor $Colors.Success
}

# Run phase
if (-not $BuildOnly) {
    Write-Section "BENCHMARK"
    
    $results = @()
    $summaryFile = "$ResultsDir\benchmark_summary_$Timestamp.txt"
    $csvFile = "$ResultsDir\benchmark_results_$Timestamp.csv"
    
    # CSV header
    "Benchmark,Type,Iteration,TPS,Status" | Out-File $csvFile
    
    foreach ($benchmark in $Benchmarks) {
        if ($benchmark.Name -notlike $Filter) {
            continue
        }
        
        Write-Header $benchmark.Name
        
        $benchmarkResults = @()
        $success = $true
        
        for ($i = 1; $i -le $Iterations; $i++) {
            $result = Run-Benchmark $benchmark $i
            
            if ($result -eq $null) {
                $success = $false
                break
            }
            
            $benchmarkResults += $result.TPS
            
            # Save to CSV
            "$($benchmark.Name),$($benchmark.Type),$i,$($result.TPS),SUCCESS" | Out-File $csvFile -Append
            
            # Save detailed output
            $outputFile = "$ResultsDir\$([System.IO.Path]::GetFileNameWithoutExtension($benchmark.File))_run$i.txt"
            $result.Output | Out-File $outputFile
        }
        
        if ($success -and $benchmarkResults.Count -gt 0) {
            $avgTPS = ($benchmarkResults | Measure-Object -Average).Average
            $minTPS = ($benchmarkResults | Measure-Object -Minimum).Minimum
            $maxTPS = ($benchmarkResults | Measure-Object -Maximum).Maximum
            
            $results += [PSCustomObject]@{
                Name = $benchmark.Name
                Type = $benchmark.Type
                AvgTPS = $avgTPS
                MinTPS = $minTPS
                MaxTPS = $maxTPS
                Iterations = $benchmarkResults.Count
            }
            
            Write-Host ""
            Write-Host "  Summary:" -ForegroundColor $Colors.Info
            Write-Host "    Average TPS: $([math]::Round($avgTPS, 2))" -ForegroundColor $Colors.Success
            Write-Host "    Min/Max TPS: $([math]::Round($minTPS, 2)) / $([math]::Round($maxTPS, 2))" -ForegroundColor $Colors.Info
        }
    }
    
    # Summary
    Write-Header "BENCHMARK SUMMARY"
    
    if ($results.Count -eq 0) {
        Write-Host "No benchmarks completed successfully." -ForegroundColor $Colors.Error
    } else {
        Write-Host ""
        Write-Host "Results:" -ForegroundColor $Colors.Info
        Write-Host "--------------------------------------------------------------------------------"
        
        foreach ($result in $results) {
            Write-Host "$($result.Name.PadRight(25)) | $($result.Type.PadRight(6)) | Avg: $([math]::Round($result.AvgTPS, 2).ToString().PadLeft(12)) TPS | Range: $([math]::Round($result.MinTPS, 2)) - $([math]::Round($result.MaxTPS, 2))"
        }
        
        Write-Host "--------------------------------------------------------------------------------"
        
        # Save summary
        $summary = @"
RawrXD TPS Benchmark Summary
Generated: $(Get-Date)
Iterations: $Iterations

Results:
$($results | Format-Table -AutoSize | Out-String)

Raw Results:
$($results | ConvertTo-Csv -NoTypeInformation | Out-String)
"@
        $summary | Out-File $summaryFile
        
        Write-Host ""
        Write-Host "Results saved to:" -ForegroundColor $Colors.Info
        Write-Host "  Summary: $summaryFile"
        Write-Host "  CSV:     $csvFile"
        Write-Host "  Details: $ResultsDir"
    }
}

Write-Host ""
Write-Host "Benchmark suite complete." -ForegroundColor $Colors.Success
