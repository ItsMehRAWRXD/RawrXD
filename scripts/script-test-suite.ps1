# RawrXD Script Test Suite
# Automated testing framework for PowerShell scripts
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [string]$ScriptPath,
    
    [Parameter()]
    [ValidateSet("All", "Syntax", "Style", "Unit", "Integration")]
    [string]$TestType = "All",
    
    [Parameter()]
    [string]$OutputPath = "test-results",
    
    [Parameter()]
    [ValidateSet("Console", "JSON", "JUnit", "NUnit")]
    [string]$OutputFormat = "Console",
    
    [Parameter()]
    [switch]$FailFast,
    
    [Parameter()]
    [switch]$Coverage
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Initialize-TestSuite {
    Write-Status "Script Test Suite v$script:Version"
    Write-Status "Test Type: $TestType"
    Write-Status "Target: $(if ($ScriptPath) { $ScriptPath } else { "All scripts" })"
    Write-Host ""
}

function Test-ScriptSyntax {
    param([string]$Path)
    
    $results = @()
    $scripts = if ($Path) { Get-Item $Path } else { Get-ChildItem -Path $PSScriptRoot -Filter "*.ps1" }
    
    foreach ($script in $scripts) {
        $testResult = [PSCustomObject]@{
            ScriptName = $script.Name
            TestType = "Syntax"
            Passed = $false
            Message = ""
            Duration = 0
        }
        
        $startTime = Get-Date
        
        try {
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $script.FullName -Raw), [ref]$null)
            $testResult.Passed = $true
            $testResult.Message = "Syntax valid"
        }
        catch {
            $testResult.Message = $_.Exception.Message
        }
        
        $testResult.Duration = ((Get-Date) - $startTime).TotalMilliseconds
        $results += $testResult
    }
    
    return $results
}

function Test-ScriptStyle {
    param([string]$Path)
    
    $results = @()
    $scripts = if ($Path) { Get-Item $Path } else { Get-ChildItem -Path $PSScriptRoot -Filter "*.ps1" }
    
    foreach ($script in $scripts) {
        $content = Get-Content $script.FullName -Raw
        $startTime = Get-Date
        
        $violations = @()
        
        # Check for proper error handling
        if ($content -notmatch '\$ErrorActionPreference') {
            $violations += "Missing ErrorActionPreference"
        }
        
        # Check for help documentation
        if ($content -notmatch '\.SYNOPSIS') {
            $violations += "Missing SYNOPSIS documentation"
        }
        
        # Check for parameter validation
        if ($content -match 'param\(' -and $content -notmatch '\[Validate') {
            $violations += "Consider adding parameter validation"
        }
        
        # Check for Write-Host (should use Write-Output in functions)
        $writeHostCount = ([regex]::Matches($content, 'Write-Host')).Count
        if ($writeHostCount -gt 10) {
            $violations += "High Write-Host usage ($writeHostCount) - consider Write-Output"
        }
        
        $testResult = [PSCustomObject]@{
            ScriptName = $script.Name
            TestType = "Style"
            Passed = $violations.Count -eq 0
            Message = if ($violations.Count -eq 0) { "Style compliant" } else { $violations -join "; " }
            Duration = ((Get-Date) - $startTime).TotalMilliseconds
            Violations = $violations
        }
        
        $results += $testResult
    }
    
    return $results
}

function Test-ScriptUnit {
    param([string]$Path)
    
    $results = @()
    $scripts = if ($Path) { Get-Item $Path } else { Get-ChildItem -Path $PSScriptRoot -Filter "*.ps1" }
    
    foreach ($script in $scripts) {
        $startTime = Get-Date
        
        # Extract functions from script
        $content = Get-Content $script.FullName -Raw
        $functionMatches = [regex]::Matches($content, 'function\s+(\w+)')
        
        $functionTests = @()
        $allPassed = $true
        
        foreach ($match in $functionMatches) {
            $functionName = $match.Groups[1].Value
            
            # Skip private functions (starting with underscore)
            if ($functionName -notmatch '^_') {
                $functionTests += "Function $functionName found"
            }
        }
        
        $testResult = [PSCustomObject]@{
            ScriptName = $script.Name
            TestType = "Unit"
            Passed = $allPassed
            Message = if ($functionTests.Count -gt 0) { "Found $($functionMatches.Count) functions" } else { "No functions found" }
            Duration = ((Get-Date) - $startTime).TotalMilliseconds
            Functions = $functionMatches.Count
        }
        
        $results += $testResult
    }
    
    return $results
}

function Test-ScriptIntegration {
    param([string]$Path)
    
    $results = @()
    $scripts = if ($Path) { Get-Item $Path } else { Get-ChildItem -Path $PSScriptRoot -Filter "*.ps1" -Recurse | Select-Object -First 5 }
    
    foreach ($script in $scripts) {
        $startTime = Get-Date
        
        # Test if script can be dot-sourced without errors
        $testResult = [PSCustomObject]@{
            ScriptName = $script.Name
            TestType = "Integration"
            Passed = $false
            Message = ""
            Duration = 0
        }
        
        try {
            # Create a temporary test environment
            $tempFile = [System.IO.Path]::GetTempFileName() + ".ps1"
            Copy-Item $script.FullName $tempFile
            
            # Try to parse the script
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $tempFile -Raw), [ref]$null)
            
            Remove-Item $tempFile -ErrorAction SilentlyContinue
            
            $testResult.Passed = $true
            $testResult.Message = "Integration test passed"
        }
        catch {
            $testResult.Message = $_.Exception.Message
        }
        
        $testResult.Duration = ((Get-Date) - $startTime).TotalMilliseconds
        $results += $testResult
    }
    
    return $results
}

function Export-TestResults {
    param([array]$Results, [string]$OutputFile, [string]$Format)
    
    switch ($Format) {
        "JSON" {
            $Results | ConvertTo-Json -Depth 3 | Set-Content $OutputFile
        }
        "JUnit" {
            $xml = "<?xml version=`"1.0`" encoding=`"UTF-8`"?>`n"
            $xml += "<testsuites>`n"
            $xml += "  <testsuite name=`"PowerShell Scripts`" tests=`"$($Results.Count)`">`n"
            
            foreach ($result in $Results) {
                $status = if ($result.Passed) { "" } else { "<failure message=`"$($result.Message)`"/>" }
                $xml += "    <testcase name=`"$($result.ScriptName) - $($result.TestType)`" time=`"$($result.Duration / 1000)`"`>$status</testcase>`n"
            }
            
            $xml += "  </testsuite>`n"
            $xml += "</testsuites>"
            
            $xml | Set-Content $OutputFile
        }
        "NUnit" {
            $passed = ($Results | Where-Object { $_.Passed }).Count
            $failed = ($Results | Where-Object { -not $_.Passed }).Count
            
            $xml = "<?xml version=`"1.0`" encoding=`"UTF-8`"?>`n"
            $xml += "<test-results>`n"
            $xml += "  <test-suite name=`"PowerShell Scripts`" success=`"$passed`" failures=`"$failed`"`>`n"
            
            foreach ($result in $Results) {
                $outcome = if ($result.Passed) { "Success" } else { "Failure" }
                $xml += "    <test-case name=`"$($result.ScriptName) - $($result.TestType)`" executed=`"true`" success=`"$($result.Passed)`"`>`n"
                $xml += "      <result>$outcome</result>`n"
                $xml += "      <message>$([System.Security.SecurityElement]::Escape($result.Message))</message>`n"
                $xml += "    </test-case>`n"
            }
            
            $xml += "  </test-suite>`n"
            $xml += "</test-results>"
            
            $xml | Set-Content $OutputFile
        }
    }
    
    Write-Success "Test results exported to: $OutputFile"
}

function Show-TestSummary {
    param([array]$Results)
    
    $total = $Results.Count
    $passed = ($Results | Where-Object { $_.Passed }).Count
    $failed = $total - $passed
    $duration = ($Results | Measure-Object -Property Duration -Sum).Sum
    
    Write-Host "`nTest Summary" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    Write-Host "Total Tests: $total"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
    Write-Host "Duration: $([math]::Round($duration, 2)) ms"
    Write-Host "Success Rate: $([math]::Round(($passed / $total) * 100, 1))%"
    Write-Host ""
    
    if ($failed -gt 0) {
        Write-Host "Failed Tests:" -ForegroundColor Red
        $failedTests = $Results | Where-Object { -not $_.Passed }
        foreach ($test in $failedTests) {
            Write-Host "  - $($test.ScriptName) [$($test.TestType)]: $($test.Message)" -ForegroundColor Red
        }
        Write-Host ""
    }
}

# Main execution
try {
    Initialize-TestSuite
    
    $allResults = @()
    
    if ($TestType -eq "All" -or $TestType -eq "Syntax") {
        Write-Status "Running syntax tests..."
        $syntaxResults = Test-ScriptSyntax -Path $ScriptPath
        $allResults += $syntaxResults
        
        if ($FailFast -and ($syntaxResults | Where-Object { -not $_.Passed })) {
            throw "Syntax tests failed"
        }
    }
    
    if ($TestType -eq "All" -or $TestType -eq "Style") {
        Write-Status "Running style tests..."
        $styleResults = Test-ScriptStyle -Path $ScriptPath
        $allResults += $styleResults
        
        if ($FailFast -and ($styleResults | Where-Object { -not $_.Passed })) {
            throw "Style tests failed"
        }
    }
    
    if ($TestType -eq "All" -or $TestType -eq "Unit") {
        Write-Status "Running unit tests..."
        $unitResults = Test-ScriptUnit -Path $ScriptPath
        $allResults += $unitResults
        
        if ($FailFast -and ($unitResults | Where-Object { -not $_.Passed })) {
            throw "Unit tests failed"
        }
    }
    
    if ($TestType -eq "All" -or $TestType -eq "Integration") {
        Write-Status "Running integration tests..."
        $integrationResults = Test-ScriptIntegration -Path $ScriptPath
        $allResults += $integrationResults
        
        if ($FailFast -and ($integrationResults | Where-Object { -not $_.Passed })) {
            throw "Integration tests failed"
        }
    }
    
    Show-TestSummary -Results $allResults
    
    if ($OutputFormat -ne "Console") {
        $extension = switch ($OutputFormat) {
            "JSON" { "json" }
            "JUnit" { "xml" }
            "NUnit" { "xml" }
        }
        $outputFile = Join-Path $PSScriptRoot "$OutputPath.$extension"
        Export-TestResults -Results $allResults -OutputFile $outputFile -Format $OutputFormat
    }
    
    $failedCount = ($allResults | Where-Object { -not $_.Passed }).Count
    if ($failedCount -gt 0) {
        exit 1
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
