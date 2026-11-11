#Requires -Version 5.1
param(
    [string]$BuildConfig = "Release",
    [string]$OutputDir = "ci-reports",
    [switch]$AutoRepair,
    [switch]$SkipBuild,
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

function Write-Header($text) {
    Write-Host "`n=== $text ===" -ForegroundColor Cyan
}

function Test-Build {
    if ($SkipBuild) {
        Write-Header "Skipping Build (using existing binaries)"
        return
    }
    
    Write-Header "Building RawrXD ($BuildConfig)"
    
    if (-not (Test-Path "build_rawrxd.bat")) {
        throw "build_rawrxd.bat not found"
    }
    
    $buildOutput = "$OutputDir\build.log"
    & .\build_rawrxd.bat $BuildConfig 2>&1 | Tee-Object $buildOutput
    
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with exit code $LASTEXITCODE. See $buildOutput"
    }
    
    if (-not (Test-Path "bin\rawrxd.exe")) {
        throw "rawrxd.exe not found after build"
    }
    
    Write-Host "✅ Build successful" -ForegroundColor Green
}

function Test-Smoketest {
    Write-Header "Running Sovereign Smoketest"
    
    $exePath = "bin\rawrxd.exe"
    if (-not (Test-Path $exePath)) {
        throw "$exePath not found"
    }
    
    $stdoutPath = "$OutputDir\smoketest.log"
    $stderrPath = "$OutputDir\smoketest.err"
    
    $proc = Start-Process -FilePath $exePath `
        -ArgumentList "--run-smoketest", "--emit-beacons", "--emit-telemetry" `
        -PassThru `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath
    
    Write-Host "Started smoketest (PID: $($proc.Id)), timeout: ${TimeoutSeconds}s"
    
    try {
        $completed = $proc | Wait-Process -Timeout $TimeoutSeconds -ErrorAction Stop
        
        if ($proc.ExitCode -ne 0) {
            throw "Smoketest failed with exit code $($proc.ExitCode)"
        }
        
        Write-Host "✅ Smoketest passed" -ForegroundColor Green
    }
    catch {
        Stop-Process $proc -Force -ErrorAction SilentlyContinue
        throw "Smoketest timed out after ${TimeoutSeconds}s"
    }
}

function Generate-Dashboard {
    Write-Header "Generating Health Dashboard"
    
    $dashboardExe = "bin\GenerateHealthDashboard.exe"
    if (-not (Test-Path $dashboardExe)) {
        Write-Warning "GenerateHealthDashboard.exe not found, skipping dashboard generation"
        return
    }
    
    $jsonPath = "health.json"
    if (-not (Test-Path $jsonPath)) {
        Write-Warning "health.json not found, cannot generate dashboard"
        return
    }
    
    & $dashboardExe $jsonPath
    
    if (Test-Path "health.html") {
        Copy-Item "health.html" "$OutputDir\health.html" -Force
        Write-Host "✅ Dashboard generated: $OutputDir\health.html" -ForegroundColor Green
    }
}

function Collect-Beacons {
    Write-Header "Collecting Beaconism Events"
    
    $beaconFile = "beacons.bin"
    if (Test-Path $beaconFile) {
        Copy-Item $beaconFile "$OutputDir\beacons.bin" -Force
        Write-Host "✅ Beacons collected" -ForegroundColor Green
    } else {
        Write-Warning "No beacon file found at $beaconFile"
    }
}

function Collect-Telemetry {
    Write-Header "Collecting Telemetry"
    
    $telemetryFile = "telemetry.bin"
    if (Test-Path $telemetryFile) {
        Copy-Item $telemetryFile "$OutputDir\telemetry.bin" -Force
        Write-Host "✅ Telemetry collected" -ForegroundColor Green
    } else {
        Write-Warning "No telemetry file found"
    }
}

function Collect-HealthReports {
    Write-Header "Collecting Health Reports"
    
    $files = @("health.html", "health.json")
    foreach ($file in $files) {
        if (Test-Path $file) {
            Copy-Item $file "$OutputDir\$file" -Force
            Write-Host "✅ Collected $file" -ForegroundColor Green
        }
    }
}

function Generate-Report {
    Write-Header "Generating Health Report"
    
    $jsonPath = "health.json"
    if (-not (Test-Path $jsonPath)) {
        Write-Warning "health.json not found, skipping report generation"
        return $null
    }
    
    $report = Get-Content $jsonPath | ConvertFrom-Json
    return $report
}

function Check-Health($report) {
    if (-not $report) {
        Write-Warning "No report generated"
        return 0
    }
    
    Write-Header "Checking Health Status"
    
    $rate = $report.overallScore
    
    $color = if ($rate -ge 90) { "Green" } elseif ($rate -ge 70) { "Yellow" } else { "Red" }
    Write-Host "Overall Score: $rate%" -ForegroundColor $color
    
    # Check subsystems
    $subsystems = $report.subsystems
    $failed = 0
    foreach ($sub in $subsystems.PSObject.Properties) {
        $state = $sub.Value.state
        if ($state -eq "broken") {
            $failed++
            Write-Host "  ❌ $($sub.Name): $($sub.Value.message)" -ForegroundColor Red
        } elseif ($state -eq "degraded") {
            Write-Host "  ⚠️ $($sub.Name): $($sub.Value.message)" -ForegroundColor Yellow
        } else {
            Write-Host "  ✅ $($sub.Name): $($sub.Value.message)" -ForegroundColor Green
        }
    }
    
    if ($failed -gt 0) {
        Write-Warning "$failed subsystems failed"
    }
    
    return $rate
}

function Upload-Artifacts {
    Write-Header "CI Artifacts"
    
    $artifacts = @(
        "$OutputDir\health.html",
        "$OutputDir\health.json",
        "$OutputDir\beacons.bin",
        "$OutputDir\telemetry.bin",
        "$OutputDir\build.log",
        "$OutputDir\smoketest.log",
        "$OutputDir\smoketest.err"
    )
    
    $found = 0
    foreach ($artifact in $artifacts) {
        if (Test-Path $artifact) {
            $found++
            $size = (Get-Item $artifact).Length
            Write-Host "  📄 $artifact ($size bytes)"
        }
    }
    
    Write-Host "`n$found artifacts ready for upload" -ForegroundColor Green
}

# Main execution
try {
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    
    $startTime = Get-Date
    
    Test-Build
    Test-Smoketest
    Generate-Dashboard
    Collect-Beacons
    Collect-Telemetry
    Collect-HealthReports
    $report = Generate-Report
    $health = Check-Health $report
    Upload-Artifacts
    
    $duration = (Get-Date) - $startTime
    Write-Host "`n⏱️ Total time: $($duration.ToString('mm\:ss'))" -ForegroundColor Gray
    
    if ($health -lt 70) {
        Write-Error "Health check failed ($health% < 70%)"
        exit 1
    }
    
    Write-Host "`n✅ CI Pipeline completed successfully" -ForegroundColor Green
    Write-Host "Dashboard available at: $OutputDir\health.html" -ForegroundColor Cyan
    exit 0
}
catch {
    Write-Error "CI Pipeline failed: $_"
    exit 1
}
