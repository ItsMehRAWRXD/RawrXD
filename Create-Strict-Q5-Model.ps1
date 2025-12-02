# Create strict agentic model from quantized q5_k_m file
# Run this AFTER moving bigdaddyg-q5_k_m.gguf to D drive

param(
    [Parameter(Mandatory=$false)]
    [string]$ModelPath = "D:\BigDaddyG-Standalone-40GB\model\bigdaddyg-q5_k_m.gguf",

    [Parameter(Mandatory=$false)]
    [string]$ModelName = "bigdaddyg-personalized-agentic:strict-q5_k_m"
)

Write-Host "Creating strict agentic model variant..." -ForegroundColor Cyan
Write-Host "Model Path: $ModelPath" -ForegroundColor Gray
Write-Host "Model Name: $ModelName" -ForegroundColor Gray
Write-Host ""

# Check if file exists
if (-not (Test-Path $ModelPath)) {
    Write-Host "❌ Model file not found: $ModelPath" -ForegroundColor Red
    Write-Host "`nPlease update the path or move the file first." -ForegroundColor Yellow
    exit 1
}

# Create modelfile content
$modelfileContent = @"
FROM $ModelPath
SYSTEM "After every tool call you MUST write exactly:
ANSWER: {\"result\":\"<return-value>\"}
with no extra commentary."
"@

Write-Host "Creating model with strict JSON compliance..." -ForegroundColor Yellow
Write-Host "`nModelfile content:" -ForegroundColor Cyan
Write-Host $modelfileContent -ForegroundColor Gray
Write-Host ""

# Create model using pipe
$modelfileContent | ollama create $ModelName -f -

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ Model created successfully: $ModelName" -ForegroundColor Green
    Write-Host "`nNext step: Test the strict model" -ForegroundColor Yellow
    Write-Host "  .\Test-Agentic-Raw.ps1 -Model '$ModelName' -MaxIter 10" -ForegroundColor Cyan
} else {
    Write-Host "`n❌ Model creation failed" -ForegroundColor Red
    exit 1
}

