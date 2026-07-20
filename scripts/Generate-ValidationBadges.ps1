#=============================================================================
# Generate-ValidationBadges.ps1
# Generates validation badges for README based on measurement results
#=============================================================================

param(
    [string]$ResultsDir = "reports",
    [string]$OutputDir = "badges"
)

$ErrorActionPreference = "Stop"

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Badge templates (shields.io format)
function Generate-Badge($label, $message, $color) {
    $encodedLabel = [System.Web.HttpUtility]::UrlEncode($label)
    $encodedMessage = [System.Web.HttpUtility]::UrlEncode($message)
    return "https://img.shields.io/badge/$encodedLabel-$encodedMessage-$color"
}

# Parse results from log files
function Parse-Results($logFile) {
    if (-not (Test-Path $logFile)) {
        return @{ Status = "unknown"; Value = "N/A" }
    }
    
    $content = Get-Content $logFile -Raw
    
    # Check for pass/fail
    $status = if ($content -match "PASS|VALIDATED") { "pass" } else { "fail" }
    
    # Extract specific metrics
    $metrics = @{}
    
    if ($content -match "Speedup.*?([\d.]+)x") {
        $metrics.Speedup = $matches[1]
    }
    if ($content -match "Break-even at:\s*([\d.]+)") {
        $metrics.BreakEven = $matches[1]
    }
    if ($content -match "Gates passed:\s*(\d+/\d+)") {
        $metrics.Gates = $matches[1]
    }
    
    return @{ 
        Status = $status
        Metrics = $metrics
    }
}

Write-Host "Generating validation badges..." -ForegroundColor Cyan

# Parse each test result
$dispatch = Parse-Results "$ResultsDir\dispatch_benchmark.log"
$planner = Parse-Results "$ResultsDir\planner_benchmark.log"
$validation = Parse-Results "$ResultsDir\validation_gates.log"
$determinism = Parse-Results "$ResultsDir\determinism_test.log"

# Generate badge URLs
$badges = @{
    Dispatch = if ($dispatch.Status -eq "pass") { 
        Generate-Badge "dispatch" "$($dispatch.Metrics.Speedup)x" "brightgreen"
    } else { 
        Generate-Badge "dispatch" "failed" "red"
    }
    
    Planner = if ($planner.Status -eq "pass") { 
        Generate-Badge "planner" "$($planner.Metrics.BreakEven)tok" "brightgreen"
    } else { 
        Generate-Badge "planner" "failed" "red"
    }
    
    Validation = if ($validation.Status -eq "pass") { 
        Generate-Badge "validation" "$($validation.Metrics.Gates)" "brightgreen"
    } else { 
        Generate-Badge "validation" "failed" "red"
    }
    
    Determinism = if ($determinism.Status -eq "pass") { 
        Generate-Badge "determinism" "pass" "brightgreen"
    } else { 
        Generate-Badge "determinism" "failed" "red"
    }
}

# Save badge URLs to file
$badgeData = @{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    badges = $badges
    results = @{
        dispatch = $dispatch
        planner = $planner
        validation = $validation
        determinism = $determinism
    }
}

$badgeData | ConvertTo-Json -Depth 10 | Out-File "$OutputDir\badges.json"

# Generate Markdown for README
$readmeSection = @"
## Validation Status

| Component | Status | Metric |
|-----------|--------|--------|
| Dispatch Overhead | ![Dispatch]($($badges.Dispatch)) | $($dispatch.Metrics.Speedup)x speedup |
| Planner Amortization | ![Planner]($($badges.Planner)) | $($planner.Metrics.BreakEven) tokens break-even |
| Four Gates | ![Validation]($($badges.Validation)) | $($validation.Metrics.Gates) gates passed |
| Determinism | ![Determinism]($($badges.Determinism)) | Strict |

*Last updated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@

$readmeSection | Out-File "$OutputDir\README_SECTION.md" -Encoding UTF8

Write-Host "Badges generated:" -ForegroundColor Green
Write-Host "  - $OutputDir\badges.json" -ForegroundColor Gray
Write-Host "  - $OutputDir\README_SECTION.md" -ForegroundColor Gray

# Output summary
Write-Host "`nValidation Summary:" -ForegroundColor Cyan
Write-Host "  Dispatch:    $($dispatch.Status) ($($dispatch.Metrics.Speedup)x)" -ForegroundColor $(if ($dispatch.Status -eq "pass") { "Green" } else { "Red" })
Write-Host "  Planner:     $($planner.Status) ($($planner.Metrics.BreakEven) tokens)" -ForegroundColor $(if ($planner.Status -eq "pass") { "Green" } else { "Red" })
Write-Host "  Validation:  $($validation.Status) ($($validation.Metrics.Gates))" -ForegroundColor $(if ($validation.Status -eq "pass") { "Green" } else { "Red" })
Write-Host "  Determinism: $($determinism.Status)" -ForegroundColor $(if ($determinism.Status -eq "pass") { "Green" } else { "Red" })
