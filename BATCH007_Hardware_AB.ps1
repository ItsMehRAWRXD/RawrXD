# BATCH007_Hardware_AB.ps1 — 313-token regression + strict CACHE OFF vs ON A/B
# Usage: .\BATCH007_Hardware_AB.ps1
# Requires: rawrxd.exe in build\bin\Release, model at D:\rawrxd\gemma3-1b-Q2_K.gguf

$ErrorActionPreference = "Stop"
$modelPath = "D:\rawrxd\gemma3-1b-Q2_K.gguf"
# Use the deterministic 313-token regression binary, not rawrxd.exe; the latter does not emit
# the token stream required for an actual A/B output comparison.
$exe = "F:\~dev\rawrxd\build\bin\Release\test_generate_313_tokens.exe"
$prompt = "Hello"
$tokenCount = 313
$seed = 42

function Write-Sep { param($label) Write-Host "`n========== $label ==========" -ForegroundColor Cyan }

function Run-Generation {
    param($envMigration, $envPrefetchDepth)

    # Set env vars for this process only
    if ($envMigration -ne $null) { $env:DEEP2_EXPERT_MIGRATION = $envMigration }
    else { Remove-Item Env:\DEEP2_EXPERT_MIGRATION -ErrorAction SilentlyContinue }

    if ($envPrefetchDepth -ne $null) { $env:DEEP2_EXPERT_PREFETCH_DEPTH = $envPrefetchDepth }
    else { Remove-Item Env:\DEEP2_EXPERT_PREFETCH_DEPTH -ErrorAction SilentlyContinue }

    # test_generate_313_tokens.exe expects exactly one argument: model path.
    # It emits the deterministic 313-token stream to stdout and the verification markers to stderr.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = "`"$modelPath`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    Write-Host "  Running: $($psi.FileName) $($psi.Arguments)"
    Write-Host "  DEEP2_EXPERT_MIGRATION=$envMigration DEEP2_EXPERT_PREFETCH_DEPTH=$envPrefetchDepth"

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    # Capture the generated text (stdout is the streamed tokens, stderr has receipts)
    $generatedText = $stdout.Trim()

    return @{
        exitCode      = $proc.ExitCode
        stdout        = $stdout
        stderr        = $stderr
        generatedText = $generatedText
    }
}

# --- Step 1: Baseline CACHE OFF (DEEP2_EXPERT_MIGRATION=0, prefetch disabled) ---
Write-Sep "A/B Test A: CACHE OFF (migration=0, prefetch=0)"
$resultA = Run-Generation -envMigration 0 -envPrefetchDepth 0
if ($resultA.exitCode -ne 0) {
    Write-Host "FAIL: CACHE OFF run exited with code $($resultA.exitCode)" -ForegroundColor Red
    Write-Host $resultA.stderr
    exit 1
}
$textA = $resultA.generatedText
Write-Host "  Generated text length: $($textA.Length) chars"

# --- Step 2: CACHE ON (DEEP2_EXPERT_MIGRATION=1, prefetch=1) ---
Write-Sep "A/B Test B: CACHE ON (migration=1, prefetch=1)"
$resultB = Run-Generation -envMigration 1 -envPrefetchDepth 1
if ($resultB.exitCode -ne 0) {
    Write-Host "FAIL: CACHE ON run exited with code $($resultB.exitCode)" -ForegroundColor Red
    Write-Host $resultB.stderr
    exit 1
}
$textB = $resultB.generatedText
Write-Host "  Generated text length: $($textB.Length) chars"

# --- Step 3: Compare ---
Write-Sep "Comparison"
if ($textA -eq $textB) {
    Write-Host "PASS: CACHE OFF vs ON outputs match (bit-exact)" -ForegroundColor Green
} else {
    Write-Host "FAIL: Outputs differ!" -ForegroundColor Red
    Write-Host "  OFF length: $($textA.Length)"
    Write-Host "  ON  length: $($textB.Length)"
    # Find first difference
    $minLen = [Math]::Min($textA.Length, $textB.Length)
    for ($i = 0; $i -lt $minLen; $i++) {
        if ($textA[$i] -ne $textB[$i]) {
            Write-Host "  First diff at char $i : OFF='$($textA[$i])' ON='$($textB[$i])'"
            $offSnippet = $textA.Substring([Math]::Max(0, $i-20), [Math]::Min(40, $textA.Length - [Math]::Max(0, $i-20)))
            $onSnippet  = $textB.Substring([Math]::Max(0, $i-20), [Math]::Min(40, $textB.Length - [Math]::Max(0, $i-20)))
            Write-Host "  OFF snippet: ...$offSnippet..."
            Write-Host "  ON  snippet: ...$onSnippet..."
            break
        }
    }
    exit 1
}

# --- Step 4: Seed determinism check (same config twice) ---
Write-Sep "Determinism Check (CACHE OFF x2)"
$resultA2 = Run-Generation -envMigration 0 -envPrefetchDepth 0
$textA2 = $resultA2.generatedText
if ($textA -eq $textA2) {
    Write-Host "PASS: Deterministic output with same seed" -ForegroundColor Green
} else {
    Write-Host "FAIL: Non-deterministic!" -ForegroundColor Red
    Write-Host "  Run 1 length: $($textA.Length)"
    Write-Host "  Run 2 length: $($textA2.Length)"
    exit 1
}

Write-Sep "RESULT"
Write-Host "BATCH007 Hardware A/B: ALL PASS" -ForegroundColor Green
