# ============================================================================
# tests/test_reap_boundaries.ps1
# Fail-closed regression suite for rawr-reap --size resolver.
#
# Asserts exact exit codes and JSON field values for every boundary case:
#   - model fits target          -> exit 0, FITS_UNMODIFIED_NO_PRUNING
#   - exceeds target + experts   -> exit 4, PRUNING_CANDIDATE_REQUIRES_CALIBRATION_MASK
#   - exceeds target, dense      -> exit 4, NOT_PRUNABLE_DENSE_EXCEEDS_TARGET
#   - malformed size             -> exit 2 (usage)
#   - size overflow              -> exit 2 (usage)
#   - missing shard / bad GGUF   -> exit 1 (load failed)
#
# Run: pwsh -File tests/test_reap_boundaries.ps1
# ============================================================================
$ErrorActionPreference = "Continue"

$ReapExe = "C:\Users\Garrett\AppData\Local\Temp\kilo\rawr-reap-test.exe"
$Models  = @{
    FitSmall   = "F:\OllamaModels\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf"
    MoeLarge   = "F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf"
    DenseMed   = "F:\OllamaModels\Phi-3-medium-128k-instruct-14B-Q4_K_M\Phi-3-medium-128k-instruct-Q4_K_M.gguf"
    Missing    = "F:\ollamamodels\does-not-exist.gguf"
}

$failures = 0

function Assert-ExitCode {
    param(
        [string[]]$Arguments,
        [int]$ExpectedCode,
        [string]$TestName
    )
    $null = & $ReapExe $Arguments 2>$null
    $code = $LASTEXITCODE
    if ($code -eq $ExpectedCode) {
        Write-Host "[PASS] $TestName (Exit Code: $code)" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $TestName (Expected: $ExpectedCode, Got: $code)" -ForegroundColor Red
        $script:failures++
    }
}

function Assert-JsonField {
    param(
        [string[]]$Arguments,
        [string]$FieldName,
        [string]$ExpectedValue,
        [string]$TestName
    )
    $output = & $ReapExe $Arguments 2>&1 | Out-String
    # Extract the JSON object (line starting with {"source")
    $jsonLine = ($output -split "`n" | Where-Object { $_ -match '^\{"source"' } | Select-Object -Last 1)
    if (-not $jsonLine) {
        Write-Host "[FAIL] $TestName (no JSON object found in output)" -ForegroundColor Red
        Write-Host "  Output tail: $(($output -split "`n" | Select-Object -Last 3 -Join ' | '))" -ForegroundColor Yellow
        $script:failures++
        return
    }
    # Use regex to extract the field value (avoids ConvertFrom-Json issues with
    # unescaped backslashes in Windows file paths like F:\OllamaModels\...)
    # Handles both quoted strings ("value") and unquoted booleans/numbers (true/false/42)
    $pattern = '"' + [regex]::Escape($FieldName) + '"\s*:\s*"?([^",\s}]+)"?'
    $match = $jsonLine | Select-String -Pattern $pattern
    if (-not $match) {
        Write-Host "[FAIL] $TestName (field '$FieldName' not found in JSON)" -ForegroundColor Red
        Write-Host "  JSON: $jsonLine" -ForegroundColor Yellow
        $script:failures++
        return
    }
    $actual = $match.Matches[0].Groups[1].Value
    if ($actual -eq $ExpectedValue) {
        Write-Host "[PASS] $TestName ($FieldName = '$ExpectedValue')" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $TestName ($FieldName expected '$ExpectedValue', got '$actual')" -ForegroundColor Red
        Write-Host "  JSON: $jsonLine" -ForegroundColor Yellow
        $script:failures++
    }
}

# ---------------------------------------------------------------------------
# Case 1: Model already fits target boundary -> exit 0, no pruning
# ---------------------------------------------------------------------------
Assert-ExitCode @("plan", $Models.FitSmall, "--size", "50GB") 0 "Model Already Fits Target Boundary"
Assert-JsonField @("plan", $Models.FitSmall, "--size", "50GB") "selection" "FITS_UNMODIFIED_NO_PRUNING" "Fit Model Selection String"
Assert-JsonField @("plan", $Models.FitSmall, "--size", "50GB") "writable_output" "false" "Fit Model Not Writable"

# ---------------------------------------------------------------------------
# Case 2: Exceeds target, contains prunable MoE experts -> exit 4, calibration required
# ---------------------------------------------------------------------------
Assert-ExitCode @("plan", $Models.MoeLarge, "--size", "30GB") 4 "Pruning Candidate Requires Calibration Mask"
Assert-JsonField @("plan", $Models.MoeLarge, "--size", "30GB") "selection" "PRUNING_CANDIDATE_REQUIRES_CALIBRATION_MASK" "Moe Selection String"
Assert-JsonField @("plan", $Models.MoeLarge, "--size", "30GB") "writable_output" "false" "MoE Not Writable"

# ---------------------------------------------------------------------------
# Case 3: Exceeds target, no prunable experts (dense) -> exit 4, cannot reduce
# ---------------------------------------------------------------------------
Assert-ExitCode @("plan", $Models.DenseMed, "--size", "1GB") 4 "Dense Model Cannot Meet Target"
Assert-JsonField @("plan", $Models.DenseMed, "--size", "1GB") "selection" "NOT_PRUNABLE_DENSE_EXCEEDS_TARGET" "Dense Selection String"
Assert-JsonField @("plan", $Models.DenseMed, "--size", "1GB") "writable_output" "false" "Dense Not Writable"

# ---------------------------------------------------------------------------
# Case 4: Malformed size argument (negative) -> exit 2, usage
# ---------------------------------------------------------------------------
Assert-ExitCode @("plan", $Models.FitSmall, "--size", "-30GB") 2 "Negative Size Parsing Trap"

# ---------------------------------------------------------------------------
# Case 5: Size arithmetic overflow -> exit 2, usage
# ---------------------------------------------------------------------------
Assert-ExitCode @("plan", $Models.FitSmall, "--size", "999999999999GB") 2 "Arithmetic Size Overflow Prevention"

# ---------------------------------------------------------------------------
# Case 6: Missing GGUF / bad file -> exit 1, load failed
# ---------------------------------------------------------------------------
Assert-ExitCode @("inspect", $Models.Missing) 1 "Missing GGUF Load Failure"

# ---------------------------------------------------------------------------
# Case 7: Malformed size unit -> exit 2, usage
# ---------------------------------------------------------------------------
Assert-ExitCode @("plan", $Models.FitSmall, "--size", "30ZZ") 2 "Invalid Size Unit Rejection"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
if ($failures -eq 0) {
    Write-Host "ALL BOUNDARY TESTS PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "$failures TEST(S) FAILED" -ForegroundColor Red
    exit 1
}
