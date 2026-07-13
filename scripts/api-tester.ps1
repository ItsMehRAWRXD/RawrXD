# RawrXD API Tester
# Comprehensive API endpoint testing and validation

param(
    [Parameter(Mandatory=$false)]
    [string]$BaseUrl = "http://localhost:8080",
    
    [string]$ApiKey = "",
    [ValidateSet("All", "Health", "Models", "Generate", "System", "Custom")]
    [string]$TestSuite = "All",
    
    [string]$CustomEndpoint = "",
    [string]$CustomMethod = "GET",
    [string]$CustomBody = "",
    [int]$Timeout = 30,
    [switch]$VerboseOutput,
    [string]$OutputFormat = "Console",  # Console, Json, Html
    [string]$OutputPath = "api-test-results"
)

$ErrorActionPreference = "Stop"

# Test results
$script:Results = @{
    Timestamp = Get-Date -Format "o"
    BaseUrl = $BaseUrl
    Tests = @()
    Summary = @{
        Total = 0
        Passed = 0
        Failed = 0
        Duration = 0
    }
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

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Get-Headers {
    $headers = @{
        "Content-Type" = "application/json"
        "Accept" = "application/json"
    }
    
    if ($ApiKey) {
        $headers["X-API-Key"] = $ApiKey
    }
    
    return $headers
}

function Invoke-ApiTest {
    param(
        [string]$Name,
        [string]$Method,
        [string]$Endpoint,
        [hashtable]$Body = $null,
        [int]$ExpectedStatus = 200,
        [scriptblock]$Validation = $null
    )
    
    $url = "$BaseUrl$Endpoint"
    $startTime = Get-Date
    
    Write-Status "Testing: $Name"
    if ($VerboseOutput) {
        Write-Host "  URL: $Method $url" -ForegroundColor Gray
    }
    
    $testResult = @{
        Name = $Name
        Method = $Method
        Endpoint = $Endpoint
        ExpectedStatus = $ExpectedStatus
        Timestamp = Get-Date -Format "o"
    }
    
    try {
        $params = @{
            Uri = $url
            Method = $Method
            Headers = Get-Headers
            TimeoutSec = $Timeout
            ErrorAction = "Stop"
        }
        
        if ($Body -and ($Method -in @("POST", "PUT", "PATCH"))) {
            $params.Body = ($Body | ConvertTo-Json -Depth 10)
            if ($VerboseOutput) {
                Write-Host "  Body: $($params.Body)" -ForegroundColor Gray
            }
        }
        
        $response = Invoke-RestMethod @params
        $statusCode = 200  # PowerShell converts successful responses automatically
        
        $testResult.StatusCode = $statusCode
        $testResult.Response = $response
        $testResult.Success = $true
        
        # Run custom validation if provided
        if ($Validation) {
            $validationResult = & $Validation $response
            if (-not $validationResult) {
                $testResult.Success = $false
                $testResult.Error = "Custom validation failed"
            }
        }
    }
    catch {
        $testResult.Success = $false
        $testResult.Error = $_.Exception.Message
        
        # Try to extract status code from error
        if ($_.Exception.Response) {
            $testResult.StatusCode = [int]$_.Exception.Response.StatusCode
        }
    }
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalMilliseconds
    $testResult.Duration = [math]::Round($duration, 2)
    
    # Check status code
    if ($testResult.StatusCode -ne $ExpectedStatus) {
        $testResult.Success = $false
        if (-not $testResult.Error) {
            $testResult.Error = "Expected status $ExpectedStatus, got $($testResult.StatusCode)"
        }
    }
    
    $script:Results.Tests += $testResult
    $script:Results.Summary.Total++
    
    if ($testResult.Success) {
        $script:Results.Summary.Passed++
        Write-Success "$Name ($([math]::Round($duration, 2))ms)"
    } else {
        $script:Results.Summary.Failed++
        Write-Error "$Name - $($testResult.Error)"
    }
    
    if ($VerboseOutput -and $testResult.Response) {
        Write-Host "  Response: $($testResult.Response | ConvertTo-Json -Depth 3 -Compress)" -ForegroundColor Gray
    }
}

# Test suites
function Test-HealthEndpoints {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Health Endpoints" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Invoke-ApiTest -Name "Health Check" -Method "GET" -Endpoint "/health" -ExpectedStatus 200 -Validation {
        param($response)
        return $response.status -eq "healthy"
    }
    
    Invoke-ApiTest -Name "Readiness Check" -Method "GET" -Endpoint "/ready" -ExpectedStatus 200
    
    Invoke-ApiTest -Name "Liveness Check" -Method "GET" -Endpoint "/live" -ExpectedStatus 200
}

function Test-ModelEndpoints {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Model Endpoints" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Invoke-ApiTest -Name "List Models" -Method "GET" -Endpoint "/api/v1/models" -ExpectedStatus 200 -Validation {
        param($response)
        return $response -is [array]
    }
    
    Invoke-ApiTest -Name "Get Model (if exists)" -Method "GET" -Endpoint "/api/v1/models/default" -ExpectedStatus 200
}

function Test-GenerateEndpoints {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Generation Endpoints" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Image generation test
    Invoke-ApiTest -Name "Generate Image" -Method "POST" -Endpoint "/api/v1/generate/image" -Body @{
        prompt = "A simple test image"
        width = 256
        height = 256
        steps = 10
    } -ExpectedStatus 200
    
    # Video generation test
    Invoke-ApiTest -Name "Generate Video" -Method "POST" -Endpoint "/api/v1/generate/video" -Body @{
        prompt = "A simple test video"
        frames = 8
        fps = 4
    } -ExpectedStatus 200
}

function Test-SystemEndpoints {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "System Endpoints" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Invoke-ApiTest -Name "System Status" -Method "GET" -Endpoint "/api/v1/system/status" -ExpectedStatus 200 -Validation {
        param($response)
        return $response.version -and $response.status
    }
    
    Invoke-ApiTest -Name "System Metrics" -Method "GET" -Endpoint "/api/v1/system/metrics" -ExpectedStatus 200
    
    Invoke-ApiTest -Name "System Info" -Method "GET" -Endpoint "/api/v1/system/info" -ExpectedStatus 200
}

function Test-CustomEndpoint {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Custom Endpoint" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $body = $null
    if ($CustomBody) {
        try {
            $body = $CustomBody | ConvertFrom-Json
        }
        catch {
            $body = @{ data = $CustomBody }
        }
    }
    
    Invoke-ApiTest -Name "Custom: $CustomEndpoint" -Method $CustomMethod -Endpoint $CustomEndpoint -Body $body
}

function Test-ErrorHandling {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Error Handling" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Test 404
    Invoke-ApiTest -Name "404 Not Found" -Method "GET" -Endpoint "/api/v1/nonexistent" -ExpectedStatus 404
    
    # Test 401 (if no API key)
    if (-not $ApiKey) {
        Invoke-ApiTest -Name "401 Unauthorized" -Method "POST" -Endpoint "/api/v1/generate/image" -Body @{
            prompt = "test"
        } -ExpectedStatus 401
    }
    
    # Test 400 Bad Request
    Invoke-ApiTest -Name "400 Bad Request" -Method "POST" -Endpoint "/api/v1/generate/image" -Body @{
        invalid_field = "test"
    } -ExpectedStatus 400
}

function Show-Summary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Test Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Total Tests: $($script:Results.Summary.Total)" -ForegroundColor White
    Write-Host "Passed: $($script:Results.Summary.Passed)" -ForegroundColor Green
    Write-Host "Failed: $($script:Results.Summary.Failed)" -ForegroundColor Red
    Write-Host "Success Rate: $([math]::Round(($script:Results.Summary.Passed / $script:Results.Summary.Total) * 100, 1))%" -ForegroundColor White
    Write-Host ""
    
    if ($script:Results.Summary.Failed -gt 0) {
        Write-Host "Failed Tests:" -ForegroundColor Red
        $failedTests = $script:Results.Tests | Where-Object { -not $_.Success }
        foreach ($test in $failedTests) {
            Write-Host "  ✗ $($test.Name): $($test.Error)" -ForegroundColor Red
        }
    }
}

function Export-Results {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    
    switch ($OutputFormat) {
        "Json" {
            $outputFile = "$OutputPath\api-test-$timestamp.json"
            $script:Results | ConvertTo-Json -Depth 10 | Out-File $outputFile
            Write-Success "Results exported to: $outputFile"
        }
        
        "Html" {
            $outputFile = "$OutputPath\api-test-$timestamp.html"
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD API Test Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 8px; }
        .pass { color: #4CAF50; }
        .fail { color: #f44336; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background: #4CAF50; color: white; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .metric { padding: 15px; background: #f0f0f0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RawrXD API Test Results</h1>
        <p>Base URL: $($script:Results.BaseUrl)</p>
        <div class="summary">
            <div class="metric"><strong>Total:</strong> $($script:Results.Summary.Total)</div>
            <div class="metric"><strong>Passed:</strong> <span class="pass">$($script:Results.Summary.Passed)</span></div>
            <div class="metric"><strong>Failed:</strong> <span class="fail">$($script:Results.Summary.Failed)</span></div>
        </div>
        <table>
            <tr><th>Test</th><th>Method</th><th>Status</th><th>Duration</th></tr>
"@
            foreach ($test in $script:Results.Tests) {
                $statusClass = if ($test.Success) { "pass" } else { "fail" }
                $status = if ($test.Success) { "PASS" } else { "FAIL" }
                $html += "<tr><td>$($test.Name)</td><td>$($test.Method)</td><td class='$statusClass'>$status</td><td>$($test.Duration)ms</td></tr>"
            }
            
            $html += @"
        </table>
    </div>
</body>
</html>
"@
            $html | Out-File $outputFile
            Write-Success "HTML report exported to: $outputFile"
        }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD API Tester" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Base URL: $BaseUrl" -ForegroundColor Gray
    Write-Host "Test Suite: $TestSuite" -ForegroundColor Gray
    Write-Host ""
    
    $startTime = Get-Date
    
    switch ($TestSuite) {
        "All" {
            Test-HealthEndpoints
            Test-ModelEndpoints
            Test-GenerateEndpoints
            Test-SystemEndpoints
            Test-ErrorHandling
        }
        "Health" { Test-HealthEndpoints }
        "Models" { Test-ModelEndpoints }
        "Generate" { Test-GenerateEndpoints }
        "System" { Test-SystemEndpoints }
        "Custom" { Test-CustomEndpoint }
    }
    
    $endTime = Get-Date
    $script:Results.Summary.Duration = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
    
    Show-Summary
    Export-Results
    
    # Exit code
    if ($script:Results.Summary.Failed -gt 0) {
        exit 1
    } else {
        exit 0
    }
}

Main
