# RawrXD Code Quality Gate
# Pre-commit and CI quality checks with configurable thresholds

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("pre-commit", "ci", "full", "quick")]
    [string]$Mode = "quick",
    
    [string[]]$Files = @(),
    [switch]$Fix,
    [switch]$FailOnWarning,
    [string]$ReportFormat = "console", # console, json, junit
    [string]$OutputPath = "quality-report"
)

$ErrorActionPreference = "Stop"

# Quality thresholds
$QualityConfig = @{
    MaxComplexity = 15
    MaxLineLength = 120
    MaxFunctionLength = 50
    MinCodeCoverage = 80
    MaxWarnings = 10
    MaxErrors = 0
    RequiredChecks = @("syntax", "style", "complexity", "security")
}

# Quality checks
$QualityChecks = @{
    Syntax = @{
        Name = "Syntax Validation"
        Weight = 10
        Enabled = $true
    }
    Style = @{
        Name = "Code Style"
        Weight = 5
        Enabled = $true
    }
    Complexity = @{
        Name = "Complexity Analysis"
        Weight = 8
        Enabled = $true
    }
    Security = @{
        Name = "Security Scan"
        Weight = 10
        Enabled = $true
    }
    Performance = @{
        Name = "Performance Hints"
        Weight = 5
        Enabled = $false
    }
    Documentation = @{
        Name = "Documentation Check"
        Weight = 3
        Enabled = $true
    }
}

$script:QualityState = @{
    StartTime = Get-Date
    Results = @()
    Score = 100
    Passed = $true
    Warnings = 0
    Errors = 0
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }

function Get-FilesToCheck {
    if ($Files.Count -gt 0) {
        return $Files | Where-Object { Test-Path $_ }
    }
    
    # Auto-detect files based on mode
    switch ($Mode) {
        "pre-commit" {
            # Get staged files
            $staged = git diff --cached --name-only --diff-filter=ACM 2>$null
            return $staged | Where-Object { $_ -match "\.(cpp|c|h|hpp|asm)$" }
        }
        "ci" {
            # Get changed files in PR
            $changed = git diff --name-only HEAD~1 2>$null
            return $changed | Where-Object { $_ -match "\.(cpp|c|h|hpp|asm)$" }
        }
        "full" {
            # All source files
            return Get-ChildItem -Path "src" -Recurse -File | 
                Where-Object { $_.Extension -in @(".cpp", ".c", ".h", ".hpp", ".asm") } |
                Select-Object -ExpandProperty FullName
        }
        "quick" {
            # Recently modified files
            return Get-ChildItem -Path "src" -Recurse -File | 
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) -and 
                              $_.Extension -in @(".cpp", ".c", ".h", ".hpp") } |
                Select-Object -ExpandProperty FullName
        }
    }
    
    return @()
}

function Test-Syntax {
    param([string]$FilePath)
    
    $issues = @()
    $content = Get-Content $FilePath -Raw -ErrorAction SilentlyContinue
    
    if (-not $content) {
        return @{ Passed = $false; Issues = @("Could not read file") }
    }
    
    # Check for basic syntax issues
    $openBraces = ($content -split "{").Count - 1
    $closeBraces = ($content -split "}").Count - 1
    if ($openBraces -ne $closeBraces) {
        $issues += "Brace mismatch: $openBraces open, $closeBraces close"
    }
    
    $openParens = ($content -split "\(").Count - 1
    $closeParens = ($content -split "\)").Count - 1
    if ($openParens -ne $closeParens) {
        $issues += "Parenthesis mismatch: $openParens open, $closeParens close"
    }
    
    # Check for unclosed strings
    $inString = $false
    $stringChar = $null
    for ($i = 0; $i -lt $content.Length; $i++) {
        $char = $content[$i]
        if (-not $inString -and ($char -eq '"' -or $char -eq "'")) {
            $inString = $true
            $stringChar = $char
        } elseif ($inString -and $char -eq $stringChar -and $content[$i-1] -ne '\') {
            $inString = $false
        }
    }
    if ($inString) {
        $issues += "Unclosed string literal"
    }
    
    return @{
        Passed = $issues.Count -eq 0
        Issues = $issues
        Score = if ($issues.Count -eq 0) { 100 } else { [math]::Max(0, 100 - ($issues.Count * 20)) }
    }
}

function Test-Style {
    param([string]$FilePath)
    
    $issues = @()
    $lines = Get-Content $FilePath -ErrorAction SilentlyContinue
    
    if (-not $lines) {
        return @{ Passed = $false; Issues = @("Could not read file") }
    }
    
    $lineNum = 0
    foreach ($line in $lines) {
        $lineNum++
        
        # Check line length
        if ($line.Length -gt $QualityConfig.MaxLineLength) {
            $issues += "Line $lineNum exceeds $($QualityConfig.MaxLineLength) characters ($($line.Length))"
        }
        
        # Check for tabs (should use spaces)
        if ($line -match "\t") {
            $issues += "Line $lineNum contains tabs (use spaces)"
        }
        
        # Check for trailing whitespace
        if ($line -match "\s$") {
            $issues += "Line $lineNum has trailing whitespace"
        }
        
        # Check for proper header guards in .h files
        if ($FilePath -match "\.h$" -and $lineNum -eq 1) {
            if ($line -notmatch "#ifndef|#pragma once") {
                $issues += "Missing header guard or #pragma once"
            }
        }
    }
    
    return @{
        Passed = $issues.Count -eq 0
        Issues = $issues
        Score = if ($issues.Count -eq 0) { 100 } else { [math]::Max(0, 100 - ($issues.Count * 5)) }
    }
}

function Test-Complexity {
    param([string]$FilePath)
    
    $issues = @()
    $content = Get-Content $FilePath -Raw -ErrorAction SilentlyContinue
    
    if (-not $content) {
        return @{ Passed = $false; Issues = @("Could not read file") }
    }
    
    # Count cyclomatic complexity indicators
    $complexityKeywords = @("if", "else", "while", "for", "switch", "case", "catch", "&&", "||", "?")
    $totalComplexity = 0
    
    foreach ($keyword in $complexityKeywords) {
        $matches = [regex]::Matches($content, "\b$keyword\b")
        $totalComplexity += $matches.Count
    }
    
    if ($totalComplexity -gt $QualityConfig.MaxComplexity * 5) {
        $issues += "High cyclomatic complexity detected ($totalComplexity branches)"
    }
    
    # Check function length
    $functions = [regex]::Matches($content, "(\w+[\s*]+)+(\w+)\s*\([^)]*\)\s*\{([^}]|\n)*\}")
    foreach ($func in $functions) {
        $funcLines = $func.Value -split "`n"
        if ($funcLines.Count -gt $QualityConfig.MaxFunctionLength) {
            $funcName = if ($func.Groups[2]) { $func.Groups[2].Value } else { "unknown" }
            $issues += "Function '$funcName' is too long ($($funcLines.Count) lines)"
        }
    }
    
    return @{
        Passed = $issues.Count -eq 0
        Issues = $issues
        Score = if ($issues.Count -eq 0) { 100 } else { [math]::Max(0, 100 - ($issues.Count * 10)) }
    }
}

function Test-Security {
    param([string]$FilePath)
    
    $issues = @()
    $content = Get-Content $FilePath -Raw -ErrorAction SilentlyContinue
    
    if (-not $content) {
        return @{ Passed = $false; Issues = @("Could not read file") }
    }
    
    # Security patterns to check
    $securityPatterns = @{
        "strcpy|strcat|sprintf" = "Unsafe string function (use strncpy, strncat, snprintf)"
        "gets\s*\(" = "Dangerous gets() function (use fgets)"
        "system\s*\(" = "system() call (potential command injection)"
        "malloc\s*\(" = "Raw malloc (consider using smart pointers or containers)"
        "printf\s*\([^,]+\)" = "printf with single argument (potential format string vulnerability)"
        "//\s*TODO.*security|//\s*FIXME.*security" = "Security-related TODO/FIXME found"
    }
    
    foreach ($pattern in $securityPatterns.GetEnumerator()) {
        if ($content -match $pattern.Key) {
            $issues += $pattern.Value
        }
    }
    
    return @{
        Passed = $issues.Count -eq 0
        Issues = $issues
        Score = if ($issues.Count -eq 0) { 100 } else { [math]::Max(0, 100 - ($issues.Count * 15)) }
    }
}

function Test-Documentation {
    param([string]$FilePath)
    
    $issues = @()
    $content = Get-Content $FilePath -Raw -ErrorAction SilentlyContinue
    
    if (-not $content) {
        return @{ Passed = $false; Issues = @("Could not read file") }
    }
    
    # Check for file header
    if ($content -notmatch "\/\*[\s\S]*?\*\/\s*\n|^\/\/.*\n" -and $content -notmatch "^\s*#") {
        $issues += "Missing file header comment"
    }
    
    # Check for function documentation
    $functions = [regex]::Matches($content, "(\w+[\s*]+)+(\w+)\s*\([^)]*\)\s*\{")
    $documented = [regex]::Matches($content, "\/\*\*[\s\S]*?\*\/\s*\n\s*(\w+[\s*]+)+(\w+)\s*\(").Count
    
    if ($functions.Count -gt 0 -and $documented -lt ($functions.Count * 0.3)) {
        $issues += "Low documentation coverage ($documented/$($functions.Count) functions documented)"
    }
    
    return @{
        Passed = $issues.Count -eq 0
        Issues = $issues
        Score = if ($issues.Count -eq 0) { 100 } else { [math]::Max(0, 100 - ($issues.Count * 10)) }
    }
}

function Invoke-QualityCheck {
    param([string]$FilePath)
    
    $fileResults = @{
        File = $FilePath
        Checks = @{}
        OverallScore = 100
        Passed = $true
    }
    
    Write-Status "Checking: $([System.IO.Path]::GetFileName($FilePath))"
    
    # Run enabled checks
    if ($QualityChecks.Syntax.Enabled) {
        $fileResults.Checks.Syntax = Test-Syntax -FilePath $FilePath
    }
    
    if ($QualityChecks.Style.Enabled) {
        $fileResults.Checks.Style = Test-Style -FilePath $FilePath
    }
    
    if ($QualityChecks.Complexity.Enabled) {
        $fileResults.Checks.Complexity = Test-Complexity -FilePath $FilePath
    }
    
    if ($QualityChecks.Security.Enabled) {
        $fileResults.Checks.Security = Test-Security -FilePath $FilePath
    }
    
    if ($QualityChecks.Documentation.Enabled) {
        $fileResults.Checks.Documentation = Test-Documentation -FilePath $FilePath
    }
    
    # Calculate overall score
    $totalWeight = 0
    $weightedScore = 0
    
    foreach ($check in $fileResults.Checks.GetEnumerator()) {
        $weight = $QualityChecks[$check.Key].Weight
        $totalWeight += $weight
        $weightedScore += $check.Value.Score * $weight
        
        if (-not $check.Value.Passed) {
            $fileResults.Passed = $false
        }
    }
    
    if ($totalWeight -gt 0) {
        $fileResults.OverallScore = [math]::Round($weightedScore / $totalWeight)
    }
    
    # Update global state
    $script:QualityState.Results += $fileResults
    
    foreach ($check in $fileResults.Checks.GetEnumerator()) {
        foreach ($issue in $check.Value.Issues) {
            if ($check.Key -eq "Security" -or $check.Key -eq "Syntax") {
                $script:QualityState.Errors++
            } else {
                $script:QualityState.Warnings++
            }
        }
    }
    
    # Display results
    $color = if ($fileResults.Passed) { 'Green' } else { 'Yellow' }
    Write-Host "  Score: $($fileResults.OverallScore)/100" -ForegroundColor $color
    
    foreach ($check in $fileResults.Checks.GetEnumerator()) {
        if ($check.Value.Issues.Count -gt 0) {
            Write-Host "  $($check.Key):" -ForegroundColor Yellow
            foreach ($issue in $check.Value.Issues | Select-Object -First 3) {
                Write-Host "    - $issue" -ForegroundColor DarkYellow
            }
        }
    }
    
    return $fileResults
}

function Export-Report {
    $report = @{
        Timestamp = Get-Date -Format "o"
        Mode = $Mode
        Summary = @{
            TotalFiles = $script:QualityState.Results.Count
            PassedFiles = ($script:QualityState.Results | Where-Object { $_.Passed }).Count
            FailedFiles = ($script:QualityState.Results | Where-Object { -not $_.Passed }).Count
            AverageScore = if ($script:QualityState.Results.Count -gt 0) { 
                [math]::Round(($script:QualityState.Results | Measure-Object -Property OverallScore -Average).Average)
            } else { 0 }
            TotalWarnings = $script:QualityState.Warnings
            TotalErrors = $script:QualityState.Errors
        }
        Results = $script:QualityState.Results
    }
    
    switch ($ReportFormat) {
        "json" {
            $outputFile = "$OutputPath-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            $report | ConvertTo-Json -Depth 10 | Out-File $outputFile
            Write-Success "JSON report: $outputFile"
        }
        "junit" {
            $xml = "<?xml version=`"1.0`" encoding=`"UTF-8`"?>`n<testsuites>`n"
            $xml += "  <testsuite name=`"CodeQuality`" tests=`"$($report.Summary.TotalFiles)`" failures=`"$($report.Summary.FailedFiles)`">`n"
            
            foreach ($result in $report.Results) {
                $xml += "    <testcase name=`"$($result.File)`">`n"
                if (-not $result.Passed) {
                    foreach ($check in $result.Checks.GetEnumerator()) {
                        if (-not $check.Value.Passed) {
                            $xml += "      <failure message=`"$($check.Value.Issues -join '; ')`"/>`n"
                        }
                    }
                }
                $xml += "    </testcase>`n"
            }
            
            $xml += "  </testsuite>`n</testsuites>"
            
            $outputFile = "$OutputPath-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
            $xml | Out-File $outputFile
            Write-Success "JUnit report: $outputFile"
        }
        default {
            # Console output already done during execution
        }
    }
}

function Show-Summary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Quality Gate Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $summary = @{
        TotalFiles = $script:QualityState.Results.Count
        PassedFiles = ($script:QualityState.Results | Where-Object { $_.Passed }).Count
        FailedFiles = ($script:QualityState.Results | Where-Object { -not $_.Passed }).Count
        AverageScore = if ($script:QualityState.Results.Count -gt 0) { 
            [math]::Round(($script:QualityState.Results | Measure-Object -Property OverallScore -Average).Average)
        } else { 0 }
    }
    
    Write-Host "Files Checked: $($summary.TotalFiles)" -ForegroundColor White
    Write-Host "Passed: $($summary.PassedFiles)" -ForegroundColor Green
    Write-Host "Failed: $($summary.FailedFiles)" -ForegroundColor Red
    Write-Host "Average Score: $($summary.AverageScore)/100" -ForegroundColor $(if ($summary.AverageScore -ge 80) { 'Green' } elseif ($summary.AverageScore -ge 60) { 'Yellow' } else { 'Red' })
    Write-Host "Warnings: $($script:QualityState.Warnings)" -ForegroundColor Yellow
    Write-Host "Errors: $($script:QualityState.Errors)" -ForegroundColor Red
    
    # Quality gate decision
    $passed = $true
    
    if ($summary.AverageScore -lt 60) {
        $passed = $false
        Write-Host "`n❌ Quality gate FAILED: Average score below 60" -ForegroundColor Red
    }
    
    if ($script:QualityState.Errors -gt $QualityConfig.MaxErrors) {
        $passed = $false
        Write-Host "❌ Quality gate FAILED: Too many errors ($($script:QualityState.Errors) > $($QualityConfig.MaxErrors))" -ForegroundColor Red
    }
    
    if ($FailOnWarning -and $script:QualityState.Warnings -gt $QualityConfig.MaxWarnings) {
        $passed = $false
        Write-Host "❌ Quality gate FAILED: Too many warnings ($($script:QualityState.Warnings) > $($QualityConfig.MaxWarnings))" -ForegroundColor Red
    }
    
    if ($passed) {
        Write-Host "`n✅ Quality gate PASSED" -ForegroundColor Green
        return 0
    } else {
        return 1
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Code Quality Gate" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host "Mode: $Mode" -ForegroundColor Gray
    Write-Host ""
    
    $filesToCheck = Get-FilesToCheck
    
    if ($filesToCheck.Count -eq 0) {
        Write-Warning "No files to check"
        exit 0
    }
    
    Write-Status "Checking $($filesToCheck.Count) file(s)..."
    Write-Host ""
    
    foreach ($file in $filesToCheck) {
        Invoke-QualityCheck -FilePath $file
    }
    
    Write-Host ""
    Export-Report
    
    $exitCode = Show-Summary
    exit $exitCode
}

Main
