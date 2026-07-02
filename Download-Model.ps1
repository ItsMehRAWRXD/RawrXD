# Sovereign Engine - Model Setup Script
# Downloads compatible Q4_K_M model and verifies setup

param(
    [string]$ModelDir = "$PSScriptRoot\models",
    [string]$ModelName = "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
)

$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Sovereign Engine Model Setup" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Create models directory
if (!(Test-Path $ModelDir)) {
    New-Item -ItemType Directory -Path $ModelDir -Force | Out-Null
    Write-Host "Created models directory: $ModelDir" -ForegroundColor Green
}

$modelPath = Join-Path $ModelDir $ModelName

# Check if model already exists
if (Test-Path $modelPath) {
    $size = (Get-Item $modelPath).Length / 1MB
    Write-Host "Model already exists: $ModelName ($([math]::Round($size,2)) MB)" -ForegroundColor Green
    Write-Host "Path: $modelPath" -ForegroundColor Gray
} else {
    Write-Host "Model not found. Downloading..." -ForegroundColor Yellow
    Write-Host ""
    
    # Model download URL (HuggingFace)
    $url = "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/$ModelName"
    
    Write-Host "Downloading from: $url" -ForegroundColor Gray
    Write-Host "This may take a few minutes..." -ForegroundColor Gray
    Write-Host ""
    
    try {
        # Use BITS for reliable download
        Import-Module BitsTransfer -ErrorAction SilentlyContinue
        if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
            Start-BitsTransfer -Source $url -Destination $modelPath -DisplayName "Model Download"
        } else {
            # Fallback to Invoke-WebRequest
            Invoke-WebRequest -Uri $url -OutFile $modelPath -UseBasicParsing
        }
        
        $size = (Get-Item $modelPath).Length / 1MB
        Write-Host "Download complete: $([math]::Round($size,2)) MB" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR: Failed to download model" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host ""
        Write-Host "Manual download instructions:" -ForegroundColor Yellow
        Write-Host "1. Visit: https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF" -ForegroundColor White
        Write-Host "2. Download: $ModelName" -ForegroundColor White
        Write-Host "3. Place in: $ModelDir" -ForegroundColor White
        exit 1
    }
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Setup Complete" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Model path: $modelPath" -ForegroundColor White
Write-Host ""
Write-Host "To run Sovereign Engine with this model:" -ForegroundColor Yellow
Write-Host "  .\SovereignOrchestrator.exe `"$modelPath`"" -ForegroundColor White
Write-Host ""
Write-Host "Or in your code:" -ForegroundColor Yellow
Write-Host "  config.model_path = `"$modelPath`";" -ForegroundColor White
Write-Host ""

# Verify the model file
Write-Host "Verifying model file..." -ForegroundColor Gray
$bytes = Get-Content $modelPath -Encoding Byte -TotalCount 4
$magic = [BitConverter]::ToUInt32($bytes, 0)
if ($magic -eq 0x46554747 -or $magic -eq 0x47475546) {
    Write-Host "✓ Valid GGUF file detected" -ForegroundColor Green
} else {
    Write-Host "⚠ Warning: File may not be a valid GGUF model" -ForegroundColor Yellow
}
