#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    LoRA Training Script for RawrXD

.DESCRIPTION
    Simplified interface for fine-tuning models with LoRA.

.EXAMPLE
    .\scripts\train_lora.ps1 -Model models/llama-7b.gguf -Data data/alpaca.jsonl
    .\scripts\train_lora.ps1 -Model models/llama-7b.gguf -Data data/alpaca.jsonl -Rank 16 -Epochs 5

.NOTES
    Part of RawrXD Phase AT: Fine-Tuning Infrastructure
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Model,

    [Parameter(Mandatory = $true)]
    [string]$Data,

    [Parameter()]
    [string]$Output = "./output",

    [Parameter()]
    [int]$Rank = 8,

    [Parameter()]
    [int]$Alpha = 16,

    [Parameter()]
    [float]$LearningRate = 5e-5,

    [Parameter()]
    [int]$BatchSize = 4,

    [Parameter()]
    [int]$Epochs = 3,

    [Parameter()]
    [int]$MaxLength = 2048,

    [Parameter()]
    [switch]$FP16,

    [Parameter()]
    [switch]$QLoRA,

    [Parameter()]
    [string]$TargetModules = "q_proj,k_proj,v_proj,o_proj",

    [Parameter()]
    [int]$SaveSteps = 500,

    [Parameter()]
    [int]$LoggingSteps = 10,

    [Parameter()]
    [int]$Seed = 42
)

# ============================================================================
# Configuration
# ============================================================================

$Config = @{
    model = $Model
    data = $Data
    output = $Output
    rank = $Rank
    alpha = $Alpha
    learning_rate = $LearningRate
    batch_size = $BatchSize
    epochs = $Epochs
    max_length = $MaxLength
    fp16 = $FP16.IsPresent
    qlora = $QLoRA.IsPresent
    target_modules = $TargetModules
    save_steps = $SaveSteps
    logging_steps = $LoggingSteps
    seed = $Seed
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
    Write-Status "Checking prerequisites..." "Info"

    if (-not (Test-Path $Model)) {
        Write-Status "Model not found: $Model" "Error"
        exit 1
    }

    if (-not (Test-Path $Data)) {
        Write-Status "Dataset not found: $Data" "Error"
        exit 1
    }

    # Check for training executable
    $trainExe = "./build/train_lora.exe"
    if (-not (Test-Path $trainExe)) {
        $trainExe = "./build/examples/fine_tune_lora.exe"
    }

    if (-not (Test-Path $trainExe)) {
        Write-Status "Training executable not found. Building..." "Warning"
        # Build
        cmake --build build --target fine_tune_lora
        if (-not (Test-Path $trainExe)) {
            Write-Status "Failed to build training executable" "Error"
            exit 1
        }
    }

    return $trainExe
}

function Show-Config {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "LoRA Training Configuration" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Model:           $Model" -ForegroundColor White
    Write-Host "Dataset:         $Data" -ForegroundColor White
    Write-Host "Output:          $Output" -ForegroundColor White
    Write-Host "Rank:            $Rank" -ForegroundColor White
    Write-Host "Alpha:           $Alpha" -ForegroundColor White
    Write-Host "Learning Rate:   $LearningRate" -ForegroundColor White
    Write-Host "Batch Size:      $BatchSize" -ForegroundColor White
    Write-Host "Epochs:          $Epochs" -ForegroundColor White
    Write-Host "Max Length:      $MaxLength" -ForegroundColor White
    Write-Host "FP16:            $($FP16.IsPresent)" -ForegroundColor White
    Write-Host "QLoRA:           $($QLoRA.IsPresent)" -ForegroundColor White
    Write-Host "Target Modules:  $TargetModules" -ForegroundColor White
    Write-Host "========================================`n" -ForegroundColor Cyan
}

# ============================================================================
# Main
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD LoRA Training" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Show-Config

    $trainExe = Test-Prerequisites

    # Create output directory
    New-Item -ItemType Directory -Force -Path $Output | Out-Null
    New-Item -ItemType Directory -Force -Path "$Output/checkpoints" | Out-Null
    New-Item -ItemType Directory -Force -Path "$Output/logs" | Out-Null

    Write-Status "Starting training..." "Info"

    # Build command arguments
    $args = @(
        $Model
        $Data
        $Output
        "--rank", $Rank
        "--alpha", $Alpha
        "--lr", $LearningRate
        "--batch-size", $BatchSize
        "--epochs", $Epochs
        "--max-length", $MaxLength
        "--target-modules", $TargetModules
        "--save-steps", $SaveSteps
        "--logging-steps", $LoggingSteps
        "--seed", $Seed
    )

    if ($FP16) { $args += "--fp16" }
    if ($QLoRA) { $args += "--qlora" }

    # Run training
    & $trainExe @args

    if ($LASTEXITCODE -eq 0) {
        Write-Status "Training completed successfully!" "Success"
        Write-Status "Output saved to: $Output" "Success"

        # Show output files
        if (Test-Path "$Output/fine_tuned_model.gguf") {
            $size = (Get-Item "$Output/fine_tuned_model.gguf").Length / 1MB
            Write-Status "Model size: $([math]::Round($size, 2)) MB" "Info"
        }
    } else {
        Write-Status "Training failed with exit code: $LASTEXITCODE" "Error"
        exit 1
    }
}

# Run
Main
