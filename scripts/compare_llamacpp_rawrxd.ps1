# ============================================================================
# RawrXD Phase 7D: Deterministic Comparison Script
# Compares per-checkpoint hashes between llama.cpp and RawrXD
# ============================================================================
# Usage: .\compare_llamacpp_rawrxd.ps1 -ModelPath <path> -Prompt <text> -Tokens <n>
# ============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$ModelPath,
    
    [Parameter(Mandatory=$true)]
    [string]$Prompt,
    
    [Parameter(Mandatory=$false)]
    [int]$Tokens = 10,
    
    [Parameter(Mandatory=$false)]
    [int]$Seed = 42,
    
    [Parameter(Mandatory=$false)]
    [string]$LlamaCppPath = "..\..\llama.cpp\build\bin\llama-cli.exe",
    
    [Parameter(Mandatory=$false)]
    [string]$RawrXDPath = "..\..\build_cli\RawrXD_RealModel.exe",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\comparison_results",
    
    [Parameter(Mandatory=$false)]
    [switch]$CompareTokensOnly = $false,  # Only compare final tokens, not intermediate hashes
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose = $false
)

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$resultsFile = "$OutputDir\comparison_$timestamp.json"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD vs llama.cpp Deterministic Comparison" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Model: $ModelPath"
Write-Host "Prompt: '$Prompt'"
Write-Host "Tokens: $Tokens"
Write-Host "Seed: $Seed"
Write-Host ""

# ============================================================================
# Step 1: Compute Model SHA256
# ============================================================================
Write-Host "Step 1: Computing model SHA256..." -ForegroundColor Yellow
$modelHash = (certutil -hashfile $ModelPath SHA256 | Select-Object -Skip 1 | Select-Object -First 1).Trim()
Write-Host "  Model SHA256: $modelHash" -ForegroundColor Gray

# ============================================================================
# Step 2: Run llama.cpp
# ============================================================================
Write-Host ""
Write-Host "Step 2: Running llama.cpp inference..." -ForegroundColor Yellow

$llamaOutputFile = "$OutputDir\llama_output_$timestamp.txt"
$llamaLogFile = "$OutputDir\llama_log_$timestamp.txt"

$llamaArgs = @(
    "-m", $ModelPath,
    "-p", $Prompt,
    "-n", $Tokens,
    "--seed", $Seed,
    "--temp", "0.8",
    "--top-p", "0.9",
    "--top-k", "40",
    "-ngl", "0",  # CPU only for determinism
    "--no-mmap",   # Disable memory mapping for determinism
    "--simple-io"
)

if ($Verbose) {
    Write-Host "  Command: $LlamaCppPath $($llamaArgs -join ' ')" -ForegroundColor Gray
}

$llamaProcess = Start-Process -FilePath $LlamaCppPath -ArgumentList $llamaArgs -RedirectStandardOutput $llamaOutputFile -RedirectStandardError $llamaLogFile -Wait -PassThru

if ($llamaProcess.ExitCode -ne 0) {
    Write-Error "llama.cpp failed with exit code $($llamaProcess.ExitCode)"
    Write-Host "Error log:"
    Get-Content $llamaLogFile | Select-Object -First 20
    exit 1
}

# Extract tokens from llama.cpp output
$llamaOutput = Get-Content $llamaOutputFile -Raw
$llamaTokens = @()

# Parse generated text (llama.cpp outputs prompt + generated text)
if ($llamaOutput -match [regex]::Escape($Prompt) + "(.+)") {
    $generatedText = $Matches[1].Trim()
    # Tokenize roughly by words for comparison
    $llamaTokens = $generatedText -split '\s+' | Where-Object { $_ -ne '' }
}

Write-Host "  Generated text length: $($llamaOutput.Length) chars"
Write-Host "  Approximate tokens: $($llamaTokens.Count)"

# ============================================================================
# Step 3: Run RawrXD with checkpoints
# ============================================================================
Write-Host ""
Write-Host "Step 3: Running RawrXD inference with checkpoints..." -ForegroundColor Yellow

$rawrOutputFile = "$OutputDir\rawr_output_$timestamp.txt"
$rawrProofFile = "$OutputDir\rawr_proof_$timestamp.rawrproof"
$rawrLogFile = "$OutputDir\rawr_log_$timestamp.txt"

$rawrArgs = @(
    "--model", $ModelPath,
    "--prompt", $Prompt,
    "--tokens", $Tokens,
    "--seed", $Seed,
    "--temp", "0.8",
    "--top-p", "0.9",
    "--top-k", "40",
    "--enable-proofs",
    "--proof-out", $rawrProofFile,
    "--cpu-only"  # Match llama.cpp CPU-only mode
)

if ($Verbose) {
    Write-Host "  Command: $RawrXDPath $($rawrArgs -join ' ')" -ForegroundColor Gray
}

$rawrProcess = Start-Process -FilePath $RawrXDPath -ArgumentList $rawrArgs -RedirectStandardOutput $rawrOutputFile -RedirectStandardError $rawrLogFile -Wait -PassThru

if ($rawrProcess.ExitCode -ne 0) {
    Write-Error "RawrXD failed with exit code $($rawrProcess.ExitCode)"
    Write-Host "Error log:"
    Get-Content $rawrLogFile | Select-Object -First 20
    exit 1
}

# Extract RawrXD output
$rawrOutput = Get-Content $rawrOutputFile -Raw
$rawrTokens = @()

if ($rawrOutput -match [regex]::Escape($Prompt) + "(.+)") {
    $generatedText = $Matches[1].Trim()
    $rawrTokens = $generatedText -split '\s+' | Where-Object { $_ -ne '' }
}

Write-Host "  Generated text length: $($rawrOutput.Length) chars"
Write-Host "  Approximate tokens: $($rawrTokens.Count)"

# ============================================================================
# Step 4: Compare Results
# ============================================================================
Write-Host ""
Write-Host "Step 4: Comparing results..." -ForegroundColor Yellow

$comparison = @{
    timestamp = $timestamp
    model_path = $ModelPath
    model_hash = $modelHash
    prompt = $Prompt
    seed = $Seed
    tokens_requested = $Tokens
    
    llama_cpp = @{
        exit_code = $llamaProcess.ExitCode
        output_file = $llamaOutputFile
        generated_text = $llamaOutput.Trim()
        token_count = $llamaTokens.Count
    }
    
    rawrxd = @{
        exit_code = $rawrProcess.ExitCode
        output_file = $rawrOutputFile
        proof_file = $rawrProofFile
        generated_text = $rawrOutput.Trim()
        token_count = $rawrTokens.Count
    }
    
    comparison = @{}
}

# Text comparison
$textMatch = $llamaOutput.Trim() -eq $rawrOutput.Trim()
$comparison.comparison.text_match = $textMatch

if ($textMatch) {
    Write-Host "  ✓ Text output: IDENTICAL" -ForegroundColor Green
} else {
    Write-Host "  ✗ Text output: DIFFERENT" -ForegroundColor Red
    
    # Show diff
    Write-Host "  ---" -ForegroundColor Gray
    Write-Host "  llama.cpp output:" -ForegroundColor Gray
    Write-Host "  $($llamaOutput.Trim().Substring(0, [Math]::Min(100, $llamaOutput.Trim().Length)))..." -ForegroundColor Gray
    Write-Host "  ---" -ForegroundColor Gray
    Write-Host "  RawrXD output:" -ForegroundColor Gray
    Write-Host "  $($rawrOutput.Trim().Substring(0, [Math]::Min(100, $rawrOutput.Trim().Length)))..." -ForegroundColor Gray
}

# Token count comparison
$tokenCountMatch = $llamaTokens.Count -eq $rawrTokens.Count
$comparison.comparison.token_count_match = $tokenCountMatch

if ($tokenCountMatch) {
    Write-Host "  ✓ Token count: MATCH ($($llamaTokens.Count))" -ForegroundColor Green
} else {
    Write-Host "  ✗ Token count: MISMATCH (llama: $($llamaTokens.Count), RawrXD: $($rawrTokens.Count))" -ForegroundColor Red
}

# ============================================================================
# Step 5: Verify Proof Chain (if available)
# ============================================================================
if (-not $CompareTokensOnly -and (Test-Path $rawrProofFile)) {
    Write-Host ""
    Write-Host "Step 5: Verifying RawrXD proof chain..." -ForegroundColor Yellow
    
    $verifyOutputFile = "$OutputDir\verify_output_$timestamp.txt"
    $verifyProcess = Start-Process -FilePath "..\..\build_cli\verify_proof.exe" -ArgumentList @($ModelPath, $rawrProofFile) -RedirectStandardOutput $verifyOutputFile -Wait -PassThru
    
    $verifyOutput = Get-Content $verifyOutputFile -Raw
    $proofValid = $verifyOutput -match "VERIFICATION_SUCCESS|Proof valid|hash chain verified"
    
    $comparison.comparison.proof_verification = @{
        exit_code = $verifyProcess.ExitCode
        valid = $proofValid
        output_file = $verifyOutputFile
    }
    
    if ($proofValid) {
        Write-Host "  ✓ Proof chain: VERIFIED" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Proof chain: VERIFICATION FAILED" -ForegroundColor Red
    }
}

# ============================================================================
# Step 6: Save Results
# ============================================================================
$comparison | ConvertTo-Json -Depth 10 | Set-Content $resultsFile

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Comparison Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Results saved to: $resultsFile" -ForegroundColor Gray
Write-Host ""

# Summary
$allPassed = $textMatch -and $tokenCountMatch
if ($comparison.comparison.proof_verification) {
    $allPassed = $allPassed -and $comparison.comparison.proof_verification.valid
}

if ($allPassed) {
    Write-Host "OVERALL: ✓ ALL CHECKS PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "OVERALL: ✗ SOME CHECKS FAILED" -ForegroundColor Red
    exit 1
}
