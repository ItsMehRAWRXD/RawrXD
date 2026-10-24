# ============================================================================
# tests/test_reap_boundaries.ps1
# Fail-closed regression suite for rawr-reap --size resolver.
#
# Asserts exact exit codes and JSON selection strings for every boundary case:
#   - model fits target          -> exit 0, FITS_UNMODIFIED_NO_PRUNING
#   - exceeds target + experts   -> exit 4, PRUNING_CANDIDATE_REQUIRES_CALIBRATION_MASK
#   - exceeds target, dense      -> exit 4, NOT_PRUNABLE_DENSE_EXCEEDS_TARGET
#   - malformed size             -> exit 2 (usage)
#   - size overflow              -> exit 2 (usage)
#   - missing shard / bad GGUF   -> exit 1 (load failed)
#
# Run: pwsh -File tests/test_reap_boundaries.ps1
# ============================================================================
$ErrorActionPreference = "Stop"

$ReapExe = "F:\rawrxd\build_reap\bin-msvc\rawr-reap.exe"
$Models  = @{
    FitSmall   = "F:\OllamaModels\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf"
    MoeLarge   = "F:\OllamaModels\DeepSeek-R1-Q4_K_M-COMPLETE\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf"
    DenseMed   = "F:\OllamaModels\Phi-3-medium-128k-instruct-14B-Q4_K_M\Phi-3-medium-128k-instruct-Q4_K_M.gguf"
    Missing    = "F:\ollamamodels\does-not-exist.gguf"
}

$failures = 0

function Assert-ExitCode {
    param(
        [string]$Arguments,
        [int]$ExpectedCode,
        [string]$TestName
    )
    try {
        $proc = Start-Process -FilePath $ReapExe -ArgumentList $Arguments -NoNewWindow -Wait -Passthru
        if ($proc.ExitCode -eq $ExpectedCode) {
            Write-Host "[PASS] $TestName (Exit Code: $($proc.ExitCode))" -ForegroundColor Green
        } else {
            Write-Host "[FAIL] $TestName (Expected: $ExpectedCode, Got: $($proc.ExitCode))" -ForegroundColor Red
            $script:failures++
        }
    } catch {
        Write-Host "[FAIL] $TestName (exception: $($_.Exception.Message))" -ForegroundColor Red
        $script:failures++
    }
}

function Assert-JsonContains {
    param(
        [string]$Arguments,
        [string]$ExpectedSubstring,
        [string]$TestName
    )
    try {
        $output = & $ReapExe $Arguments 2>&1 | Out-String
        if ($output -like "*$ExpectedSubstring*") {
            Write-Host "[PASS] $TestName (contains '$ExpectedSubstring')" -ForegroundColor Green
        } else {
            Write-Host "[FAIL] $TestName (expected '$ExpectedSubstring' in output)" -ForegroundColor Red
            Write-Host "  Output: $output" -ForegroundColor Yellow
            $script:failures++
        }
    } catch {
        Write-Host "[FAIL] $TestName (exception: $($_.Exception.Message))" -ForegroundColor Red
        $script:failures++
    }
}

# ---------------------------------------------------------------------------
# Case 1: Model already fits target boundary -> exit 0, no pruning
# ---------------------------------------------------------------------------
Assert-ExitCode `"plan `"$($Models.FitSmall)`" --size 50GB`" 0 "Model Already Fits Target Boundary"
Assert-JsonContains `"plan `"$($Models.FitSmall)`" --size 50GB`" "FITS_UNMODIFIED_NO_PRUNING" "Fit Model Selection String"

# ---------------------------------------------------------------------------
# Case 2: Exceeds target, contains prunable MoE experts -> exit 4, calibration required
# ---------------------------------------------------------------------------
Assert-ExitCode `"plan `"$($Models.MoeLarge)`" --size 30GB`" 4 "Pruning Candidate Requires Calibration Mask"
Assert-JsonContains `"plan `"$($Models.MoeLarge)`" --size 30GB`" "PRUNING_CANDIDATE_REQUIRES_CALIBRATION_MASK" "Moe Selection String"

# ---------------------------------------------------------------------------
# Case 3: Exceeds target, no prunable experts (dense) -> exit 4, cannot reduce
# ---------------------------------------------------------------------------
Assert-ExitCode `"plan `"$($Models.DenseMed)`" --size 1GB`" 4 "Dense Model Cannot Meet Target"
Assert-JsonContains `"plan `"$($Models.DenseMed)`" --size 1GB`" "NOT_PRUNABLE_DENSE_EXCEEDS_TARGET" "Dense Selection String"

# ---------------------------------------------------------------------------
# Case 4: Malformed size argument (negative) -> exit 2, usage
# ---------------------------------------------------------------------------
Assert-ExitCode `"plan `"$($Models.FitSmall)`" --size -30GB`" 2 "Negative Size Parsing Trap"

# ---------------------------------------------------------------------------
# Case 5: Size arithmetic overflow -> exit 2, usage
# ---------------------------------------------------------------------------
Assert-ExitCode `"plan `"$($Models.FitSmall)`" --size 999999999999GB`" 2 "Arithmetic Size Overflow Prevention"

# ---------------------------------------------------------------------------
# Case 6: Missing shard / bad GGUF -> exit 1, load failed
# ---------------------------------------------------------------------------
Assert-ExitCode `"inspect `"$($Models.Missing)`"`" 1 "Missing GGUF Load Failure"

# ---------------------------------------------------------------------------
# Case 7: Malformed size unit -> exit 2, usage
# ---------------------------------------------------------------------------
Assert-ExitCode `"plan `"$($Models.FitSmall)`" --size 30ZZ`" 2 "Invalid Size Unit Rejection"

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
