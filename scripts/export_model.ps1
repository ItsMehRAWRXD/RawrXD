#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Model Export Script for RawrXD

.DESCRIPTION
    Export fine-tuned models to various formats (GGUF, Safetensors, ONNX).

.EXAMPLE
    .\scripts\export_model.ps1 -Checkpoint checkpoints/best -Output model.gguf -Format GGUF
    .\scripts\export_model.ps1 -Checkpoint checkpoints/best -Output model.onnx -Format ONNX

.NOTES
    Part of RawrXD Phase AT: Fine-Tuning Infrastructure
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Checkpoint,

    [Parameter(Mandatory = $true)]
    [string]$Output,

    [Parameter(Mandatory = $true)]
    [ValidateSet("GGUF", "Safetensors", "ONNX", "PyTorch")]
    [string]$Format,

    [Parameter()]
    [ValidateSet("Q4_0", "Q4_1", "Q5_0", "Q5_1", "Q8_0", "F16", "F32")]
    [string]$Quantization = "Q4_0",

    [Parameter()]
    [switch]$MergeAdapter,

    [Parameter()]
    [string]$Author = "",

    [Parameter()]
    [string]$Description = "",

    [Parameter()]
    [string]$License = ""
)

# ============================================================================
# Configuration
# ============================================================================

$QuantMap = @{
    "Q4_0" = "q4_0"
    "Q4_1" = "q4_1"
    "Q5_0" = "q5_0"
    "Q5_1" = "q5_1"
    "Q8_0" = "q8_0"
    "F16" = "f16"
    "F32" = "f32"
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Test-Prerequisites {
    if (-not (Test-Path $Checkpoint)) {
        Write-Status "Checkpoint not found: $Checkpoint" "Error"
        exit 1
    }

    $exportExe = "./build/export_model.exe"
    if (-not (Test-Path $exportExe)) {
        Write-Status "Export executable not found" "Error"
        exit 1
    }

    return $exportExe
}

# ============================================================================
# Main
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Model Export" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Status "Checkpoint: $Checkpoint" "Info"
    Write-Status "Output: $Output" "Info"
    Write-Status "Format: $Format" "Info"
    Write-Status "Quantization: $Quantization" "Info"
    Write-Status "Merge Adapter: $($MergeAdapter.IsPresent)" "Info"
    Write-Host ""

    $exportExe = Test-Prerequisites

    # Build arguments
    $args = @(
        "--checkpoint", $Checkpoint
        "--output", $Output
        "--format", $Format
        "--quantization", $QuantMap[$Quantization]
    )

    if ($MergeAdapter) { $args += "--merge-adapter" }
    if ($Author) { $args += "--author", $Author }
    if ($Description) { $args += "--description", $Description }
    if ($License) { $args += "--license", $License }

    # Run export
    Write-Status "Exporting model..." "Info"
    & $exportExe @args

    if ($LASTEXITCODE -eq 0) {
        Write-Status "Export completed successfully!" "Success"

        if (Test-Path $Output) {
            $size = (Get-Item $Output).Length / 1MB
            Write-Status "Output size: $([math]::Round($size, 2)) MB" "Info"
        }
    } else {
        Write-Status "Export failed with exit code: $LASTEXITCODE" "Error"
        exit 1
    }
}

# Run
Main
