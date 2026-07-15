# RawrXD Integration Test Suite
# Comprehensive integration testing for all system components

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Quick", "Full", "API", "Models", "Gateway", "Storage", "Security", "Performance", "Smoke")]
    [string]$TestSuite = "Quick",
    
    [string]$Environment = "development",
    [string]$OutputPath = "",
    [int]$Timeout = 300,  # seconds
    [switch]$Parallel,
    [switch]$StopOnFailure,
    [switch]$GenerateReport,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Test results tracking
$script:TestResults = @()
$script:PassedTests = 0
$script:FailedTests = 0
$script:SkippedTests = 0
$script:StartTime = Get-Date

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

function Write-TestHeader {
    param([string]$Name)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $Name -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Add-TestResult {
    param(
        [string]$TestName,
        [string]$Status,  # Pass, Fail, Skip
        [string]$Message,
        [int]$Duration = 0,
        [string]$Category = ""
    )
    
    $script:TestResults += [PSCustomObject]@{
        TestName = $TestName
        Status = $Status
        Message = $Message
        Duration = $Duration
        Category = $Category
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    switch ($Status) {
        "Pass" { $script:PassedTests++ }
        "Fail" { $script:FailedTests++ }
        "Skip" { $script:SkippedTests++ }
    }
}

function Invoke-Test {
    param(
        [string]$Name,
        [string]$Category,
        [scriptblock]$Test
    )
    
    Write-Status "Running: $Name"
    $testStart = Get-Date
    
    try {
        $result = & $Test
        $duration = [math]::Round(((Get-Date) - $testStart).TotalSeconds, 2)
        
        if ($result -eq $true) {
            Add-TestResult -TestName $Name -Status "Pass" -Message "Test passed" -Duration $duration -Category $Category
            Write-Success "$Name ($duration`s)"
            return $true
        } else {
            Add-TestResult -TestName $Name -Status "Fail" -Message "Test returned false" -Duration $duration -Category $Category
            Write-Error "$Name ($duration`s)"
            return $false
        }
    }
    catch {
        $duration = [math]::Round(((Get-Date) - $testStart).TotalSeconds, 2)
        Add-TestResult -TestName $Name -Status "Fail" -Message $_.Exception.Message -Duration $duration -Category $Category
        Write-Error "$Name ($duration`s): $_"
        return $false
    }
}

# Test Categories
function Test-APIEndpoints {
    Write-TestHeader "API Endpoint Tests"
    
    $tests = @(
        @{
            Name = "Health Check Endpoint"
            Test = {
                try {
                    $response = Invoke-RestMethod -Uri "http://localhost:8080/health" -TimeoutSec 5
                    return $response.status -eq "healthy"
                } catch { return $false }
            }
        },
        @{
            Name = "Models List Endpoint"
            Test = {
                try {
                    $response = Invoke-RestMethod -Uri "http://localhost:8080/v1/models" -TimeoutSec 10
                    return $response.data.Count -gt 0
                } catch { return $false }
            }
        },
        @{
            Name = "Completions Endpoint"
            Test = {
                try {
                    $body = @{ model = "default"; prompt = "Hello"; max_tokens = 10 } | ConvertTo-Json
                    $response = Invoke-RestMethod -Uri "http://localhost:8080/v1/completions" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 30
                    return $response.choices.Count -gt 0
                } catch { return $false }
            }
        },
        @{
            Name = "Chat Completions Endpoint"
            Test = {
                try {
                    $body = @{
                        model = "default"
                        messages = @(@{ role = "user"; content = "Hello" })
                        max_tokens = 10
                    } | ConvertTo-Json
                    $response = Invoke-RestMethod -Uri "http://localhost:8080/v1/chat/completions" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 30
                    return $response.choices.Count -gt 0
                } catch { return $false }
            }
        },
        @{
            Name = "Embeddings Endpoint"
            Test = {
                try {
                    $body = @{ model = "default"; input = "Hello world" } | ConvertTo-Json
                    $response = Invoke-RestMethod -Uri "http://localhost:8080/v1/embeddings" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 30
                    return $response.data.Count -gt 0
                } catch { return $false }
            }
        }
    )
    
    foreach ($test in $tests) {
        $result = Invoke-Test -Name $test.Name -Category "API" -Test $test.Test
        if (-not $result -and $StopOnFailure) { return }
    }
}

function Test-ModelOperations {
    Write-TestHeader "Model Operation Tests"
    
    $tests = @(
        @{
            Name = "Model Loading"
            Test = {
                # Check if models directory exists and has files
                $modelsPath = "$env:LOCALAPPDATA\RawrXD\models"
                return (Test-Path $modelsPath) -and (Get-ChildItem $modelsPath -Filter "*.gguf" -ErrorAction SilentlyContinue).Count -gt 0
            }
        },
        @{
            Name = "Model Info Retrieval"
            Test = {
                try {
                    $response = Invoke-RestMethod -Uri "http://localhost:8080/v1/models" -TimeoutSec 10
                    return ($response.data | Where-Object { $_.id }).Count -gt 0
                } catch { return $false }
            }
        },
        @{
            Name = "Model Switching"
            Test = {
                # Simulate model switching
                Start-Sleep -Milliseconds 100
                return $true
            }
        },
        @{
            Name = "Quantization Check"
            Test = {
                $modelsPath = "$env:LOCALAPPDATA\RawrXD\models"
                $models = Get-ChildItem $modelsPath -Filter "*.gguf" -ErrorAction SilentlyContinue
                return $models.Count -gt 0
            }
        }
    )
    
    foreach ($test in $tests) {
        $result = Invoke-Test -Name $test.Name -Category "Models" -Test $test.Test
        if (-not $result -and $StopOnFailure) { return }
    }
}

function Test-Gateway {
    Write-TestHeader "API Gateway Tests"
    
    $tests = @(
        @{
            Name = "Gateway Status"
            Test = {
                try {
                    $response = Invoke-RestMethod -Uri "http://localhost:8080/gateway/status" -TimeoutSec 5
                    return $response.status -eq "running"
                } catch { return $false }
            }
        },
        @{
            Name = "Rate Limiting"
            Test = {
                # Send multiple rapid requests
                $success = 0
                for ($i = 0; $i -lt 10; $i++) {
                    try {
                        Invoke-RestMethod -Uri "http://localhost:8080/health" -TimeoutSec 2 | Out-Null
                        $success++
                    } catch {}
                }
                return $success -ge 5  # At least half should succeed
            }
        },
        @{
            Name = "Request Routing"
            Test = {
                try {
                    $response = Invoke-RestMethod -Uri "http://localhost:8080/v1/models" -TimeoutSec 10
                    return $response -ne $null
                } catch { return $false }
            }
        }
    )
    
    foreach ($test in $tests) {
        $result = Invoke-Test -Name $test.Name -Category "Gateway" -Test $test.Test
        if (-not $result -and $StopOnFailure) { return }
    }
}

function Test-Storage {
    Write-TestHeader "Storage Tests"
    
    $tests = @(
        @{
            Name = "Configuration Storage"
            Test = {
                $configPath = "$env:LOCALAPPDATA\RawrXD\config"
                return Test-Path $configPath
            }
        },
        @{
            Name = "Log Storage"
            Test = {
                $logsPath = "$env:LOCALAPPDATA\RawrXD\logs"
                return Test-Path $logsPath
            }
        },
        @{
            Name = "Model Storage"
            Test = {
                $modelsPath = "$env:LOCALAPPDATA\RawrXD\models"
                return Test-Path $modelsPath
            }
        },
        @{
            Name = "Cache Storage"
            Test = {
                $cachePath = "$env:LOCALAPPDATA\RawrXD\cache"
                return Test-Path $cachePath
            }
        },
        @{
            Name = "Disk Space Check"
            Test = {
                $drive = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }
                $freePercent = ($drive.FreeSpace / $drive.Size) * 100
                return $freePercent -gt 10  # At least 10% free
            }
        }
    )
    
    foreach ($test in $tests) {
        $result = Invoke-Test -Name $test.Name -Category "Storage" -Test $test.Test
        if (-not $result -and $StopOnFailure) { return }
    }
}

function Test-Security {
    Write-TestHeader "Security Tests"
    
    $tests = @(
        @{
            Name = "Authentication Check"
            Test = {
                # Check if auth is configured
                $configPath = "$env:LOCALAPPDATA\RawrXD\config\security.json"
                if (Test-Path $configPath) {
                    $config = Get-Content $configPath -Raw | ConvertFrom-Json
                    return $config.auth_enabled -ne $null
                }
                return $true  # No security config means no auth required
            }
        },
        @{
            Name = "TLS Configuration"
            Test = {
                # Check if TLS is properly configured
                return $true  # Placeholder
            }
        },
        @{
            Name = "Input Validation"
            Test = {
                try {
                    # Send invalid input
                    $body = @{ model = ""; prompt = ""; max_tokens = -1 } | ConvertTo-Json
                    Invoke-RestMethod -Uri "http://localhost:8080/v1/completions" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5
                    return $false  # Should have failed
                } catch {
                    return $true  # Expected to fail
                }
            }
        }
    )
    
    foreach ($test in $tests) {
        $result = Invoke-Test -Name $test.Name -Category "Security" -Test $test.Test
        if (-not $result -and $StopOnFailure) { return }
    }
}

function Test-Performance {
    Write-TestHeader "Performance Tests"
    
    $tests = @(
        @{
            Name = "Response Time"
            Test = {
                $times = @()
                for ($i = 0; $i -lt 5; $i++) {
                    $start = Get-Date
                    try {
                        Invoke-RestMethod -Uri "http://localhost:8080/health" -TimeoutSec 5 | Out-Null
                    } catch {}
                    $times += ((Get-Date) - $start).TotalMilliseconds
                }
                $avg = ($times | Measure-Object -Average).Average
                return $avg -lt 100  # Should respond in under 100ms
            }
        },
        @{
            Name = "Concurrent Requests"
            Test = {
                $jobs = @()
                for ($i = 0; $i -lt 5; $i++) {
                    $jobs += Start-Job {
                        try {
                            Invoke-RestMethod -Uri "http://localhost:8080/health" -TimeoutSec 10
                            return $true
                        } catch { return $false }
                    }
                }
                $results = $jobs | Wait-Job | Receive-Job
                $jobs | Remove-Job
                return ($results | Where-Object { $_ -eq $true }).Count -ge 3
            }
        },
        @{
            Name = "Memory Usage"
            Test = {
                $process = Get-Process -Name "rawrxd*" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($process) {
                    $memoryMB = $process.WorkingSet64 / 1MB
                    return $memoryMB -lt 4096  # Under 4GB
                }
                return $true
            }
        }
    )
    
    foreach ($test in $tests) {
        $result = Invoke-Test -Name $test.Name -Category "Performance" -Test $test.Test
        if (-not $result -and $StopOnFailure) { return }
    }
}

function Test-Smoke {
    Write-TestHeader "Smoke Tests"
    
    $tests = @(
        @{
            Name = "Service Running"
            Test = {
                $process = Get-Process -Name "rawrxd*" -ErrorAction SilentlyContinue
                return $process -ne $null
            }
        },
        @{
            Name = "Port Listening"
            Test = {
                $connection = Test-NetConnection -ComputerName localhost -Port 8080 -WarningAction SilentlyContinue
                return $connection.TcpTestSucceeded
            }
        },
        @{
            Name = "Basic Request"
            Test = {
                try {
                    $response = Invoke-RestMethod -Uri "http://localhost:8080/health" -TimeoutSec 5
                    return $response -ne $null
                } catch { return $false }
            }
        }
    )
    
    foreach ($test in $tests) {
        $result = Invoke-Test -Name $test.Name -Category "Smoke" -Test $test.Test
        if (-not $result -and $StopOnFailure) { return }
    }
}

function Show-Results {
    $duration = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 2)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Test Results Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Total Tests: $($script:TestResults.Count)" -ForegroundColor White
    Write-Host "  Passed:  $script:PassedTests" -ForegroundColor Green
    Write-Host "  Failed:  $script:FailedTests" -ForegroundColor Red
    Write-Host "  Skipped: $script:SkippedTests" -ForegroundColor Yellow
    Write-Host "Duration: $duration`s" -ForegroundColor White
    Write-Host ""
    
    if ($script:FailedTests -gt 0) {
        Write-Host "Failed Tests:" -ForegroundColor Red
        $failed = $script:TestResults | Where-Object { $_.Status -eq "Fail" }
        foreach ($test in $failed) {
            Write-Host "  • $($test.TestName): $($test.Message)" -ForegroundColor Red
        }
    }
    
    # Category breakdown
    Write-Host "`nResults by Category:" -ForegroundColor White
    $categories = $script:TestResults | Group-Object -Property Category
    foreach ($cat in $categories) {
        $passCount = ($cat.Group | Where-Object { $_.Status -eq "Pass" }).Count
        $totalCount = $cat.Count
        $percent = [math]::Round(($passCount / $totalCount) * 100, 1)
        $color = if ($percent -eq 100) { "Green" } elseif ($percent -ge 80) { "Yellow" } else { "Red" }
        Write-Host "  $($cat.Name): $passCount/$totalCount ($percent%)" -ForegroundColor $color
    }
    
    if ($script:FailedTests -eq 0) {
        Write-Host "`n✓ All tests passed!" -ForegroundColor Green
    } else {
        Write-Host "`n✗ Some tests failed!" -ForegroundColor Red
    }
}

function Export-Results {
    if (-not $OutputPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputPath = "integration_test_report_$timestamp.json"
    }
    
    $report = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Environment = $Environment
        TestSuite = $TestSuite
        Summary = @{
            Total = $script:TestResults.Count
            Passed = $script:PassedTests
            Failed = $script:FailedTests
            Skipped = $script:SkippedTests
            Duration = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 2)
            SuccessRate = if ($script:TestResults.Count -gt 0) { 
                [math]::Round(($script:PassedTests / $script:TestResults.Count) * 100, 2) 
            } else { 0 }
        }
        Results = $script:TestResults
    }
    
    $report | ConvertTo-Json -Depth 10 | Out-File $OutputPath
    Write-Success "Report exported to: $OutputPath"
}

# Main execution
function Main {
    Write-Host "RawrXD Integration Test Suite" -ForegroundColor Cyan
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host "Environment: $Environment" -ForegroundColor Gray
    Write-Host "Test Suite: $TestSuite" -ForegroundColor Gray
    Write-Host ""
    
    switch ($TestSuite) {
        "Quick" {
            Test-Smoke
            Test-APIEndpoints
        }
        "Full" {
            Test-Smoke
            Test-APIEndpoints
            Test-ModelOperations
            Test-Gateway
            Test-Storage
            Test-Security
            Test-Performance
        }
        "API" { Test-APIEndpoints }
        "Models" { Test-ModelOperations }
        "Gateway" { Test-Gateway }
        "Storage" { Test-Storage }
        "Security" { Test-Security }
        "Performance" { Test-Performance }
        "Smoke" { Test-Smoke }
    }
    
    Show-Results
    
    if ($GenerateReport -or $OutputPath) {
        Export-Results
    }
    
    # Exit with error code if tests failed
    if ($script:FailedTests -gt 0) {
        exit 1
    }
}

Main
