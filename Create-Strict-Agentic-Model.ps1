# Create the strict agentic model variant (from base model)
# This script creates a new model with strict JSON compliance
# For the q5_k_m quantized version, use Create-Strict-Q5-Model.ps1 instead

param(
    [Parameter(Mandatory=$false)]
    [string]$ModelName = "bigdaddyg-personalized-agentic:strict"
)

Write-Host "Creating strict agentic model variant..." -ForegroundColor Cyan

$modelfile = "Modelfiles/bigdaddyg-personalized-agentic-strict.Modelfile"

if (-not (Test-Path $modelfile)) {
    Write-Host "❌ Modelfile not found: $modelfile" -ForegroundColor Red
    exit 1
}

Write-Host "`nStep 1: Creating model with strict prompt..." -ForegroundColor Yellow
Write-Host "Model Name: $ModelName" -ForegroundColor Gray
Write-Host "Modelfile: $modelfile" -ForegroundColor Gray
Write-Host "`nRunning..." -ForegroundColor Cyan

& ollama create $ModelName -f $modelfile

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ Model created successfully!" -ForegroundColor Green
    Write-Host "`nStep 2: Testing the strict model..." -ForegroundColor Yellow
    Write-Host "Run this to test:" -ForegroundColor Cyan
    Write-Host "  .\Test-Agentic-Raw.ps1 -Model '$ModelName' -MaxIter 10" -ForegroundColor White
} else {
    Write-Host "`n❌ Model creation failed" -ForegroundColor Red
    exit 1
}

