# run_validation.ps1
# Execute VAL-019 validation and generate evidence

param(
    [string]$MetadataPath = "val-019/metadata.json",
    [string]$ReportPath = "val-019/evidence/report.json",
    [string]$CompilerPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RawrXD Validation Runner (VAL-019)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if compiler exists
if (-not (Test-Path $CompilerPath)) {
    Write-Error "Compiler not found at: $CompilerPath"
    Write-Host "Please specify correct path with -CompilerPath parameter"
    exit 1
}

# Ensure evidence directory exists
$evidenceDir = Split-Path $ReportPath -Parent
if (-not (Test-Path $evidenceDir)) {
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
    Write-Host "[SETUP] Created evidence directory: $evidenceDir"
}

# Build if needed
if (-not (Test-Path "val_runner.exe")) {
    Write-Host "[BUILD] Building validation runner..."
    
    $buildArgs = @(
        "/EHsc",
        "/O2",
        "/W4",
        "/nologo",
        "val_runner.cpp",
        "/Fe:val_runner.exe"
    )
    
    $process = Start-Process -FilePath $CompilerPath -ArgumentList $buildArgs -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -ne 0) {
        Write-Error "Build failed with exit code: $($process.ExitCode)"
        exit 1
    }
    
    Write-Host "[BUILD] SUCCESS" -ForegroundColor Green
}

# Run validation
Write-Host ""
Write-Host "[RUN] Executing validation stages..." -ForegroundColor Yellow
Write-Host "----------------------------------------"

$runArgs = @($MetadataPath, $ReportPath)
$process = Start-Process -FilePath "val_runner.exe" -ArgumentList $runArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput "val_stdout.txt" -RedirectStandardError "val_stderr.txt"

# Display output
if (Test-Path "val_stdout.txt") {
    Get-Content "val_stdout.txt"
}
if (Test-Path "val_stderr.txt") {
    $stderr = Get-Content "val_stderr.txt" -Raw
    if ($stderr) {
        Write-Host $stderr -ForegroundColor Red
    }
}

# Cleanup temp files
Remove-Item "val_stdout.txt" -ErrorAction SilentlyContinue
Remove-Item "val_stderr.txt" -ErrorAction SilentlyContinue

if ($process.ExitCode -eq 0) {
    Write-Host ""
    Write-Host "[RESULT] All validation stages PASSED" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "[RESULT] Some validation stages FAILED" -ForegroundColor Red
}

# Display report location
if (Test-Path $ReportPath) {
    Write-Host ""
    Write-Host "[OUTPUT] Evidence report: $ReportPath" -ForegroundColor Cyan
    
    # Show summary from report
    $report = Get-Content $ReportPath -Raw | ConvertFrom-Json
    Write-Host ""
    Write-Host "Summary:"
    Write-Host "  Total:   $($report.summary.total)"
    Write-Host "  Passed:  $($report.summary.passed)" -ForegroundColor Green
    Write-Host "  Failed:  $($report.summary.failed)" -ForegroundColor $(if($report.summary.failed -gt 0){"Red"}else{"Green"})
}

exit $process.ExitCode
