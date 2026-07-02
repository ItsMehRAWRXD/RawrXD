# Sovereign Engine Launcher
# Wires everything together and launches the IDE

param(
    [string]$ModelPath = "F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf",
    [switch]$CopyModel,
    [switch]$TestOnly
)

$ErrorActionPreference = "Stop"
$RootDir = "D:\rawrxd-ci-bootstrap"
$ModelsDir = "$RootDir\models"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SOVEREIGN ENGINE - FULL INTEGRATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verify model exists
if (-not (Test-Path $ModelPath)) {
    Write-Host "❌ Model not found: $ModelPath" -ForegroundColor Red
    Write-Host "Available models in F:\OllamaModels:" -ForegroundColor Yellow
    Get-ChildItem "F:\OllamaModels" -Filter "*.gguf" | 
        Select-Object Name, @{N="SizeGB";E={[math]::Round($_.Length/1GB,2)}} |
        Format-Table -AutoSize
    exit 1
}

$ModelSize = (Get-Item $ModelPath).Length / 1GB
Write-Host "✅ Model found: $ModelPath" -ForegroundColor Green
Write-Host "   Size: $([math]::Round($ModelSize,2)) GB" -ForegroundColor Gray
Write-Host ""

# Setup models directory
if (-not (Test-Path $ModelsDir)) {
    New-Item -ItemType Directory -Path $ModelsDir -Force | Out-Null
    Write-Host "✅ Created models directory: $ModelsDir" -ForegroundColor Green
}

# Link or copy model
$TargetModel = "$ModelsDir\$(Split-Path $ModelPath -Leaf)"
if ($CopyModel) {
    Write-Host "📋 Copying model (this may take a few minutes)..." -ForegroundColor Yellow
    Copy-Item $ModelPath $TargetModel -Force
    Write-Host "✅ Model copied to: $TargetModel" -ForegroundColor Green
} else {
    # Create symlink
    if (-not (Test-Path $TargetModel)) {
        cmd /c mklink "$TargetModel" "$ModelPath" | Out-Null
        Write-Host "✅ Model linked: $TargetModel -> $ModelPath" -ForegroundColor Green
    } else {
        Write-Host "✅ Model already linked" -ForegroundColor Green
    }
}

# Verify SovereignOrchestrator exists
$SovereignExe = "$RootDir\SovereignOrchestrator.exe"
if (-not (Test-Path $SovereignExe)) {
    Write-Host "❌ SovereignOrchestrator.exe not found!" -ForegroundColor Red
    Write-Host "   Expected: $SovereignExe" -ForegroundColor Gray
    exit 1
}
Write-Host "✅ SovereignOrchestrator.exe found" -ForegroundColor Green

# Verify VS Code extension
$VSIXPath = "$RootDir\rawrxd-test-0.0.1.vsix"
if (Test-Path $VSIXPath) {
    Write-Host "✅ VS Code extension found: rawrxd-test-0.0.1.vsix" -ForegroundColor Green
} else {
    Write-Host "⚠️ VS Code extension not found (optional)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  LAUNCHING SOVEREIGN ENGINE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($TestOnly) {
    Write-Host "🧪 TEST MODE - Would launch:" -ForegroundColor Yellow
    Write-Host "   $SovereigenExe `"$TargetModel`"" -ForegroundColor Gray
    exit 0
}

# Launch Sovereign Engine
Write-Host "🚀 Starting Sovereign Engine..." -ForegroundColor Green
Write-Host "   Model: $(Split-Path $TargetModel -Leaf)" -ForegroundColor Gray
Write-Host "   Pipe: \\.\pipe\RawrXD_Sovereign" -ForegroundColor Gray
Write-Host ""

# Set working directory and launch
Set-Location $RootDir
& $SovereignExe "$TargetModel"
