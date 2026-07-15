#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Batch Processing Example for RawrXD

.DESCRIPTION
    Demonstrates how to process multiple prompts in batch
    using the RawrXD API from PowerShell.

.EXAMPLE
    .\batch_processing.ps1 -InputFile prompts.txt -OutputFile results.json
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$InputFile = "prompts.txt",

    [Parameter()]
    [string]$OutputFile = "results.json",

    [Parameter()]
    [string]$ApiBase = "http://localhost:8080/v1",

    [Parameter()]
    [string]$Model = "llama-2-7b"
)

# Configuration
$script:Results = @()

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Invoke-RawrXDRequest {
    param([string]$Prompt)

    $body = @{
        model = $Model
        prompt = $Prompt
        max_tokens = 256
        temperature = 0.7
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri "$ApiBase/completions" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 60
        return $response.choices[0].text
    } catch {
        Write-Status "Request failed: $_" "Error"
        return $null
    }
}

function Start-BatchProcessing {
    Write-Status "Starting batch processing..." "Info"
    Write-Status "Input file: $InputFile" "Info"
    Write-Status "Output file: $OutputFile" "Info"
    Write-Status ""

    # Check input file
    if (-not (Test-Path $InputFile)) {
        Write-Status "Input file not found: $InputFile" "Error"
        
        # Create sample input file
        Write-Status "Creating sample input file..." "Info"
        @"
What is the capital of France?
Explain quantum computing in simple terms.
Write a Python function to calculate fibonacci numbers.
What are the benefits of renewable energy?
How does machine learning work?
"@ | Out-File -FilePath $InputFile -Encoding UTF8
        Write-Status "Sample file created: $InputFile" "Success"
    }

    # Read prompts
    $prompts = Get-Content -Path $InputFile | Where-Object { $_.Trim() -ne "" }
    Write-Status "Loaded $($prompts.Count) prompts" "Success"
    Write-Status ""

    # Process each prompt
    $counter = 0
    foreach ($prompt in $prompts) {
        $counter++
        Write-Status "Processing [$counter/$($prompts.Count)]: $($prompt.Substring(0, [Math]::Min(50, $prompt.Length)))..." "Info"
        
        $startTime = Get-Date
        $response = Invoke-RawrXDRequest -Prompt $prompt
        $endTime = Get-Date
        
        $result = [PSCustomObject]@{
            Prompt = $prompt
            Response = $response
            ProcessingTime = ($endTime - $startTime).TotalSeconds
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            Success = ($response -ne $null)
        }
        
        $script:Results += $result
        
        if ($response) {
            Write-Status "Response: $($response.Substring(0, [Math]::Min(100, $response.Length)))..." "Success"
        }
        Write-Status ""
    }

    # Save results
    $output = [ordered]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        TotalPrompts = $prompts.Count
        Successful = ($script:Results | Where-Object { $_.Success }).Count
        Failed = ($script:Results | Where-Object { -not $_.Success }).Count
        AverageTime = ($script:Results | Measure-Object -Property ProcessingTime -Average).Average
        Results = $script:Results
    }

    $output | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Status "Results saved to: $OutputFile" "Success"

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Batch Processing Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total prompts:    $($output.TotalPrompts)" -ForegroundColor White
    Write-Host "Successful:       $($output.Successful)" -ForegroundColor Green
    Write-Host "Failed:           $($output.Failed)" -ForegroundColor $(if ($output.Failed -eq 0) { "Green" } else { "Red" })
    Write-Host "Average time:     $([math]::Round($output.AverageTime, 2))s" -ForegroundColor White
}

# Main execution
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Batch Processing Example" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Start-BatchProcessing
