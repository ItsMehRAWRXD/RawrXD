# RawrXD Final Integration Test Suite
# Phase O.1 - Final Integration & Production Readiness
# Comprehensive end-to-end testing before production release

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TargetUrl = "http://localhost:8080",

    [Parameter(Mandatory=$false)]
    [string]$ApiKey = "",

    [Parameter(Mandatory=$false)]
    [ValidateSet("smoke", "integration", "e2e", "performance", "all")]
    [string]$TestSuite = "all",

    [Parameter(Mandatory=$false)]
    [switch]$GenerateReport,

    [Parameter(Mandatory=$false)]
    [switch]$FailFast
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Test results tracking
$script:TestResults = @{
    Passed = 0
    Failed = 0
    Skipped = 0
    Total = 0
    Duration = [TimeSpan]::Zero
    Tests = @()
}

# Logging
function Write-TestLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "PASS" = "Green"; "FAIL" = "Red"; "SKIP" = "Yellow"; "WARN" = "DarkYellow" }
    Write-Host "[$timestamp] [TEST] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Test case class
class TestCase {
    [string]$Name
    [string]$Category
    [string]$Status  # passed, failed, skipped
    [TimeSpan]$Duration
    [string]$ErrorMessage
    [hashtable]$Details

    TestCase([string]$name, [string]$category) {
        $this.Name = $name
        $this.Category = $category
        $this.Status = "pending"
        $this.Details = @{}
    }
}

# Execute test with timing and error handling
function Invoke-TestCase {
    param(
        [string]$Name,
        [string]$Category,
        [scriptblock]$TestScript
    )

    $test = [TestCase]::new($Name, $Category)
    $script:TestResults.Total++

    Write-TestLog "Running: $Name" "INFO"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $result = & $TestScript
        $test.Status = "passed"
        $test.Details = $result
        Write-TestLog "✓ PASSED: $Name" "PASS"
        $script:TestResults.Passed++
    } catch {
        $test.Status = "failed"
        $test.ErrorMessage = $_.Exception.Message
        Write-TestLog "✗ FAILED: $Name - $($_.Exception.Message)" "FAIL"
        $script:TestResults.Failed++

        if ($FailFast) {
            throw "Test failed and FailFast enabled: $Name"
        }
    } finally {
        $sw.Stop()
        $test.Duration = $sw.Elapsed
        $script:TestResults.Duration += $test.Duration
        $script:TestResults.Tests += $test
    }

    return $test
}

# Smoke Tests
function Start-SmokeTests {
    Write-TestLog "Starting Smoke Tests..." "INFO"

    # Test 1: Health Check
    Invoke-TestCase -Name "Health Endpoint" -Category "Smoke" -TestScript {
        $response = Invoke-WebRequest -Uri "$TargetUrl/health" -TimeoutSec 5
        if ($response.StatusCode -ne 200) {
            throw "Health check failed with status $($response.StatusCode)"
        }
        $content = $response.Content | ConvertFrom-Json
        if ($content.status -ne "healthy") {
            throw "Service reports status: $($content.status)"
        }
        return @{ status = $content.status; version = $content.version }
    }

    # Test 2: Metrics Endpoint
    Invoke-TestCase -Name "Metrics Endpoint" -Category "Smoke" -TestScript {
        $response = Invoke-WebRequest -Uri "$TargetUrl/metrics" -TimeoutSec 5
        if ($response.StatusCode -ne 200) {
            throw "Metrics endpoint failed"
        }
        if ($response.Content -notmatch "rawrxd") {
            throw "Metrics content invalid"
        }
        return @{ content_length = $response.Content.Length }
    }

    # Test 3: Model List
    Invoke-TestCase -Name "List Models" -Category "Smoke" -TestScript {
        $headers = @{}
        if ($ApiKey) { $headers["Authorization"] = "Bearer $ApiKey" }

        $response = Invoke-WebRequest -Uri "$TargetUrl/v1/models" -Headers $headers -TimeoutSec 10
        if ($response.StatusCode -ne 200) {
            throw "Model list failed"
        }
        $content = $response.Content | ConvertFrom-Json
        return @{ model_count = $content.data.Count }
    }

    # Test 4: Simple Completion
    Invoke-TestCase -Name "Basic Completion" -Category "Smoke" -TestScript {
        $headers = @{
            "Content-Type" = "application/json"
        }
        if ($ApiKey) { $headers["Authorization"] = "Bearer $ApiKey" }

        $body = @{
            model = "llama3.1-8b"
            prompt = "Hello"
            max_tokens = 10
        } | ConvertTo-Json

        $response = Invoke-WebRequest -Uri "$TargetUrl/v1/completions" -Method POST -Headers $headers -Body $body -TimeoutSec 30
        if ($response.StatusCode -ne 200) {
            throw "Completion request failed"
        }
        $content = $response.Content | ConvertFrom-Json
        if (-not $content.choices) {
            throw "No choices in response"
        }
        return @{ tokens_generated = $content.choices[0].text.Length }
    }

    Write-TestLog "Smoke Tests Complete" "INFO"
}

# Integration Tests
function Start-IntegrationTests {
    Write-TestLog "Starting Integration Tests..." "INFO"

    # Test 5: Authentication
    Invoke-TestCase -Name "Authentication Required" -Category "Integration" -TestScript {
        if (-not $ApiKey) {
            Write-TestLog "Skipping - no API key provided" "SKIP"
            return @{ skipped = $true }
        }

        # Request without auth should fail
        try {
            $response = Invoke-WebRequest -Uri "$TargetUrl/v1/completions" -Method POST -TimeoutSec 5
            throw "Request without auth should have failed"
        } catch {
            if ($_.Exception.Response.StatusCode -ne 401) {
                throw "Expected 401, got $($_.Exception.Response.StatusCode)"
            }
        }
        return @{ auth_enforced = $true }
    }

    # Test 6: Rate Limiting
    Invoke-TestCase -Name "Rate Limiting" -Category "Integration" -TestScript {
        $headers = @{
            "Content-Type" = "application/json"
        }
        if ($ApiKey) { $headers["Authorization"] = "Bearer $ApiKey" }

        $body = @{
            model = "llama3.1-8b"
            prompt = "Test"
            max_tokens = 5
        } | ConvertTo-Json

        # Send multiple rapid requests
        $responses = @()
        for ($i = 0; $i -lt 10; $i++) {
            try {
                $response = Invoke-WebRequest -Uri "$TargetUrl/v1/completions" -Method POST -Headers $headers -Body $body -TimeoutSec 5
                $responses += $response.StatusCode
            } catch {
                $responses += $_.Exception.Response.StatusCode.value__
            }
        }

        $rateLimited = $responses | Where-Object { $_ -eq 429 }
        return @{ requests_sent = 10; rate_limited = $rateLimited.Count }
    }

    # Test 7: Chat Completion
    Invoke-TestCase -Name "Chat Completion" -Category "Integration" -TestScript {
        $headers = @{
            "Content-Type" = "application/json"
        }
        if ($ApiKey) { $headers["Authorization"] = "Bearer $ApiKey" }

        $body = @{
            model = "llama3.1-8b"
            messages = @(
                @{ role = "system"; content = "You are helpful." }
                @{ role = "user"; content = "Hello!" }
            )
            max_tokens = 50
        } | ConvertTo-Json -Depth 10

        $response = Invoke-WebRequest -Uri "$TargetUrl/v1/chat/completions" -Method POST -Headers $headers -Body $body -TimeoutSec 30
        $content = $response.Content | ConvertFrom-Json
        return @{ response_length = $content.choices[0].message.content.Length }
    }

    # Test 8: Embeddings
    Invoke-TestCase -Name "Embeddings Generation" -Category "Integration" -TestScript {
        $headers = @{
            "Content-Type" = "application/json"
        }
        if ($ApiKey) { $headers["Authorization"] = "Bearer $ApiKey" }

        $body = @{
            model = "nomic-embed-text"
            input = "Test sentence for embedding"
        } | ConvertTo-Json

        $response = Invoke-WebRequest -Uri "$TargetUrl/v1/embeddings" -Method POST -Headers $headers -Body $body -TimeoutSec 30
        $content = $response.Content | ConvertFrom-Json
        return @{ embedding_dimensions = $content.data[0].embedding.Count }
    }

    Write-TestLog "Integration Tests Complete" "INFO"
}

# End-to-End Tests
function Start-E2ETests {
    Write-TestLog "Starting End-to-End Tests..." "INFO"

    # Test 9: Full Conversation Flow
    Invoke-TestCase -Name "Multi-turn Conversation" -Category "E2E" -TestScript {
        $headers = @{
            "Content-Type" = "application/json"
        }
        if ($ApiKey) { $headers["Authorization"] = "Bearer $ApiKey" }

        $conversation = @()

        # Turn 1
        $body1 = @{
            model = "llama3.1-8b"
            messages = @(
                @{ role = "user"; content = "What is the capital of France?" }
            )
            max_tokens = 50
        } | ConvertTo-Json -Depth 10

        $response1 = Invoke-WebRequest -Uri "$TargetUrl/v1/chat/completions" -Method POST -Headers $headers -Body $body1 -TimeoutSec 30
        $content1 = $response1.Content | ConvertFrom-Json
        $assistantResponse = $content1.choices[0].message.content

        # Turn 2 - Follow up
        $body2 = @{
            model = "llama3.1-8b"
            messages = @(
                @{ role = "user"; content = "What is the capital of France?" }
                @{ role = "assistant"; content = $assistantResponse }
                @{ role = "user"; content = "What is the population?" }
            )
            max_tokens = 50
        } | ConvertTo-Json -Depth 10

        $response2 = Invoke-WebRequest -Uri "$TargetUrl/v1/chat/completions" -Method POST -Headers $headers -Body $body2 -TimeoutSec 30
        $content2 = $response2.Content | ConvertFrom-Json

        return @{
            turn1_response = $assistantResponse.Substring(0, [Math]::Min(50, $assistantResponse.Length))
            turn2_response = $content2.choices[0].message.content.Substring(0, [Math]::Min(50, $content2.choices[0].message.content.Length))
        }
    }

    # Test 10: Model Load/Unload Cycle
    Invoke-TestCase -Name "Model Lifecycle" -Category "E2E" -TestScript {
        $headers = @{}
        if ($ApiKey) { $headers["Authorization"] = "Bearer $ApiKey" }

        # List models
        $listResponse = Invoke-WebRequest -Uri "$TargetUrl/v1/models" -Headers $headers -TimeoutSec 10
        $models = $listResponse.Content | ConvertFrom-Json

        # Get specific model
        if ($models.data.Count -gt 0) {
            $modelId = $models.data[0].id
            $modelResponse = Invoke-WebRequest -Uri "$TargetUrl/v1/models/$modelId" -Headers $headers -TimeoutSec 10
            $modelDetails = $modelResponse.Content | ConvertFrom-Json

            return @{
                models_available = $models.data.Count
                first_model = $modelId
                model_loaded = $modelDetails.loaded
            }
        }

        return @{ models_available = 0 }
    }

    Write-TestLog "End-to-End Tests Complete" "INFO"
}

# Performance Tests
function Start-PerformanceTests {
    Write-TestLog "Starting Performance Tests..." "INFO"

    # Test 11: Latency Benchmark
    Invoke-TestCase -Name "Latency Benchmark" -Category "Performance" -TestScript {
        $headers = @{
            "Content-Type" = "application/json"
        }
        if ($ApiKey) { $headers["Authorization"] = "Bearer $ApiKey" }

        $body = @{
            model = "llama3.1-8b"
            prompt = "Count from 1 to 10"
            max_tokens = 50
        } | ConvertTo-Json

        $latencies = @()
        for ($i = 0; $i -lt 5; $i++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $response = Invoke-WebRequest -Uri "$TargetUrl/v1/completions" -Method POST -Headers $headers -Body $body -TimeoutSec 60
            $sw.Stop()
            $latencies += $sw.ElapsedMilliseconds
            Start-Sleep -Milliseconds 100
        }

        $avgLatency = ($latencies | Measure-Object -Average).Average
        $p95Latency = $latencies | Sort-Object | Select-Object -Index ([Math]::Floor($latencies.Count * 0.95))

        return @{
            avg_latency_ms = [Math]::Round($avgLatency, 2)
            p95_latency_ms = $p95Latency
            min_latency_ms = ($latencies | Measure-Object -Minimum).Minimum
            max_latency_ms = ($latencies | Measure-Object -Maximum).Maximum
        }
    }

    # Test 12: Throughput Test
    Invoke-TestCase -Name "Throughput Test" -Category "Performance" -TestScript {
        $headers = @{
            "Content-Type" = "application/json"
        }
        if ($ApiKey) { $headers["Authorization"] = "Bearer $ApiKey" }

        $body = @{
            model = "llama3.1-8b"
            prompt = "Hi"
            max_tokens = 10
        } | ConvertTo-Json

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $completed = 0

        # Run concurrent requests
        $jobs = @()
        for ($i = 0; $i -lt 10; $i++) {
            $jobs += Start-Job -ScriptBlock {
                param($url, $hdrs, $bdy)
                try {
                    Invoke-WebRequest -Uri "$url/v1/completions" -Method POST -Headers $hdrs -Body $bdy -TimeoutSec 30 | Out-Null
                    return $true
                } catch {
                    return $false
                }
            } -ArgumentList $TargetUrl, $headers, $body
        }

        $jobs | Wait-Job -Timeout 60 | Out-Null
        $sw.Stop()

        $results = $jobs | Receive-Job
        $completed = ($results | Where-Object { $_ -eq $true }).Count
        $jobs | Remove-Job

        $rps = [Math]::Round($completed / ($sw.ElapsedMilliseconds / 1000), 2)

        return @{
            requests_completed = $completed
            duration_ms = $sw.ElapsedMilliseconds
            requests_per_second = $rps
        }
    }

    Write-TestLog "Performance Tests Complete" "INFO"
}

# Generate test report
function Export-TestReport {
    param([string]$OutputPath)

    $report = @{
        test_run_id = [Guid]::NewGuid().ToString()
        timestamp = Get-Date -Format "o"
        target_url = $TargetUrl
        summary = @{
            total_tests = $script:TestResults.Total
            passed = $script:TestResults.Passed
            failed = $script:TestResults.Failed
            skipped = $script:TestResults.Skipped
            pass_rate = if ($script:TestResults.Total -gt 0) {
                [Math]::Round(($script:TestResults.Passed / $script:TestResults.Total) * 100, 2)
            } else { 0 }
            duration_seconds = [Math]::Round($script:TestResults.Duration.TotalSeconds, 2)
        }
        tests = $script:TestResults.Tests | ForEach-Object {
            @{
                name = $_.Name
                category = $_.Category
                status = $_.Status
                duration_ms = [Math]::Round($_.Duration.TotalMilliseconds, 2)
                error = $_.ErrorMessage
                details = $_.Details
            }
        }
    }

    $report | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
    Write-TestLog "Report saved to $OutputPath" "SUCCESS"

    return $report
}

# Main execution
Write-TestLog "RawrXD Final Integration Test Suite" "INFO"
Write-TestLog "Target: $TargetUrl" "INFO"
Write-TestLog "Test Suite: $TestSuite" "INFO"

$startTime = Get-Date

# Run selected test suites
switch ($TestSuite) {
    "smoke" { Start-SmokeTests }
    "integration" { Start-SmokeTests; Start-IntegrationTests }
    "e2e" { Start-SmokeTests; Start-IntegrationTests; Start-E2ETests }
    "performance" { Start-PerformanceTests }
    "all" {
        Start-SmokeTests
        Start-IntegrationTests
        Start-E2ETests
        Start-PerformanceTests
    }
}

$endTime = Get-Date

# Display summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Tests: $($script:TestResults.Total)" -ForegroundColor White
Write-Host "Passed: $($script:TestResults.Passed)" -ForegroundColor Green
Write-Host "Failed: $($script:TestResults.Failed)" -ForegroundColor $(if ($script:TestResults.Failed -gt 0) { "Red" } else { "Green" })
Write-Host "Skipped: $($script:TestResults.Skipped)" -ForegroundColor Yellow
Write-Host "Duration: $([Math]::Round($script:TestResults.Duration.TotalSeconds, 2))s" -ForegroundColor White
Write-Host "Pass Rate: $([Math]::Round(($script:TestResults.Passed / [Math]::Max(1, $script:TestResults.Total)) * 100, 2))%" -ForegroundColor $(if ($script:TestResults.Failed -eq 0) { "Green" } else { "Yellow" })
Write-Host "========================================" -ForegroundColor Cyan

# Generate report if requested
if ($GenerateReport) {
    $reportPath = "integration_test_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $report = Export-TestReport -OutputPath $reportPath
}

# Exit with appropriate code
if ($script:TestResults.Failed -gt 0) {
    Write-TestLog "Test suite completed with failures" "FAIL"
    exit 1
} else {
    Write-TestLog "All tests passed!" "PASS"
    exit 0
}
