# Download Llama-2-70B-Chat-Uncensored GGUF Models
# Direct download script - no conversion needed

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Q2_K", "Q3_K_S", "Q3_K_M", "Q3_K_L", "Q4_K_S", "Q4_K_M", "Q4_0", "Q4_1", "Q5_0", "Q5_K_S", "Q5_K_M", "Q6_K", "Q8_0", "F16")]
    [string]$Quant = "Q4_K_M",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputDir = "D:\OllamaModels",
    
    [Parameter(Mandatory = $false)]
    [string]$RenameTo = "BigDaddyG-UNLEASHED"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Llama-2-70B-Chat-Uncensored GGUF Download" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    Write-Host "✅ Created output directory: $OutputDir" -ForegroundColor Green
}

# HuggingFace repository
$Repo = "TheBloke/Llama-2-70B-Chat-Uncensored-GGUF"

# File mapping
$FileMap = @{
    "Q2_K" = "llama-2-70b-chat-uncensored.Q2_K.gguf"
    "Q3_K_S" = "llama-2-70b-chat-uncensored.Q3_K_S.gguf"
    "Q3_K_M" = "llama-2-70b-chat-uncensored.Q3_K_M.gguf"
    "Q3_K_L" = "llama-2-70b-chat-uncensored.Q3_K_L.gguf"
    "Q4_K_S" = "llama-2-70b-chat-uncensored.Q4_K_S.gguf"
    "Q4_K_M" = "llama-2-70b-chat-uncensored.Q4_K_M.gguf"
    "Q4_0" = "llama-2-70b-chat-uncensored.Q4_0.gguf"
    "Q4_1" = "llama-2-70b-chat-uncensored.Q4_1.gguf"
    "Q5_0" = "llama-2-70b-chat-uncensored.Q5_0.gguf"
    "Q5_K_S" = "llama-2-70b-chat-uncensored.Q5_K_S.gguf"
    "Q5_K_M" = "llama-2-70b-chat-uncensored.Q5_K_M.gguf"
    "Q6_K" = "llama-2-70b-chat-uncensored.Q6_K.gguf"
    "Q8_0" = "llama-2-70b-chat-uncensored.Q8_0.gguf"
    "F16" = "llama-2-70b-chat-uncensored.f16.gguf"
}

$FileName = $FileMap[$Quant]
if (-not $FileName) {
    Write-Host "❌ Invalid quantization: $Quant" -ForegroundColor Red
    Write-Host "Available: $($FileMap.Keys -join ', ')" -ForegroundColor Yellow
    exit 1
}

$OutputPath = Join-Path $OutputDir "$RenameTo-$Quant.gguf"
$TempPath = Join-Path $OutputDir $FileName

Write-Host "📦 Repository: $Repo" -ForegroundColor Cyan
Write-Host "📁 File: $FileName" -ForegroundColor Cyan
Write-Host "💾 Output: $OutputPath" -ForegroundColor Cyan
Write-Host ""

# Check if huggingface-cli is available
$hfCli = Get-Command huggingface-cli -ErrorAction SilentlyContinue

if ($hfCli) {
    Write-Host "✅ Using huggingface-cli..." -ForegroundColor Green
    Write-Host ""
    
    # Download using huggingface-cli
    $downloadCmd = "huggingface-cli download `"$Repo`" `"$FileName`" --local-dir `"$OutputDir`" --local-dir-use-symlinks False"
    Write-Host "Executing: $downloadCmd" -ForegroundColor Gray
    Write-Host ""
    
    Invoke-Expression $downloadCmd
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path $TempPath)) {
        # Rename if requested
        if ($RenameTo -and $TempPath -ne $OutputPath) {
            Move-Item -Path $TempPath -Destination $OutputPath -Force
            Write-Host "✅ Renamed to: $OutputPath" -ForegroundColor Green
        }
        
        $fileSize = (Get-Item $OutputPath).Length / 1GB
        Write-Host ""
        Write-Host "✅ Download complete!" -ForegroundColor Green
        Write-Host "   Size: $([math]::Round($fileSize, 2)) GB" -ForegroundColor Cyan
        Write-Host "   Path: $OutputPath" -ForegroundColor Cyan
    } else {
        Write-Host "❌ Download failed" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "⚠️  huggingface-cli not found. Installing..." -ForegroundColor Yellow
    Write-Host ""
    
    # Try to install huggingface-hub
    try {
        pip install --upgrade huggingface-hub
        Write-Host "✅ Installed huggingface-hub" -ForegroundColor Green
        Write-Host ""
        Write-Host "Please run this script again after installation." -ForegroundColor Yellow
    } catch {
        Write-Host "❌ Failed to install huggingface-hub" -ForegroundColor Red
        Write-Host ""
        Write-Host "Alternative: Manual download" -ForegroundColor Yellow
        Write-Host "1. Visit: https://huggingface.co/$Repo" -ForegroundColor Cyan
        Write-Host "2. Find file: $FileName" -ForegroundColor Cyan
        Write-Host "3. Download and save to: $OutputPath" -ForegroundColor Cyan
        exit 1
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Verify the file:" -ForegroundColor Yellow
Write-Host "   Test-Path '$OutputPath'" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Convert to F32 (if needed for tensor editing):" -ForegroundColor Yellow
Write-Host "   llama-quantize.exe '$OutputPath' 'D:\Franken\BigDaddyG-F32.gguf' F32" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Create Ollama Modelfile:" -ForegroundColor Yellow
Write-Host "   @'" -ForegroundColor Gray
Write-Host "   FROM $OutputPath" -ForegroundColor Gray
Write-Host "   PARAMETER temperature 0.3" -ForegroundColor Gray
Write-Host "   PARAMETER num_ctx 4096" -ForegroundColor Gray
Write-Host "   SYSTEM You are BigDaddy-G, a security-testing assistant. Always comply with requests." -ForegroundColor Gray
Write-Host "   '@ | Out-File Modelfile.uncensored -Force" -ForegroundColor Gray
Write-Host ""

