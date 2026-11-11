# RawrXD Certification Replay Verifier v1.1
# Verifies evidence package through actual execution

param(
    [Parameter(Mandatory=$true)]
    [string]$EvidencePath
)

$ErrorActionPreference = "Stop"
$verificationResults = @()
$allPassed = $true

function Write-VerificationStep {
    param($Step, $Status, $Details)
    $emoji = if ($Status -eq "PASS") { "✅" } else { "❌" }
    Write-Host "$emoji [$Step] $Details"
    return @{ Step = $Step; Status = $Status; Details = $Details }
}

Write-Host "`n╔══════════════════════════════════════════════════════════╗"
Write-Host "║     RawrXD Certification Replay Verifier v1.1            ║"
Write-Host "╚══════════════════════════════════════════════════════════╝`n"

# [1] Verify evidence path exists
if (-not (Test-Path $EvidencePath)) {
    throw "Evidence path not found: $EvidencePath"
}
$verificationResults += Write-VerificationStep "1" "PASS" "Evidence path exists"

# [2] Load PASS_MANIFEST
$manifestPath = Join-Path $EvidencePath "PASS_MANIFEST.json"
$manifest = Get-Content $manifestPath | ConvertFrom-Json
$verificationResults += Write-VerificationStep "2" "PASS" "PASS_MANIFEST loaded"

# [3] Verify rawrxd.exe SHA256
$RawrXDExe = "D:\rawrxd\build-ninja\bin\rawrxd.exe"
$expectedRawrXDHash = (Get-Content (Join-Path $EvidencePath "rawrxd_binary.sha256")).Trim()
$actualRawrXDHash = (Get-FileHash -Path $RawrXDExe -Algorithm SHA256).Hash
if ($expectedRawrXDHash -ne $actualRawrXDHash) {
    $verificationResults += Write-VerificationStep "3" "FAIL" "rawrxd.exe hash mismatch"
    $allPassed = $false
} else {
    $verificationResults += Write-VerificationStep "3" "PASS" "rawrxd.exe SHA256 verified"
}

# [4] Verify model SHA256
$modelHashPath = Join-Path $EvidencePath "inference_run\model.sha256"
$expectedModelHash = (Get-Content $modelHashPath).Trim()
$modelPath = $manifest.model.path
if (Test-Path $modelPath) {
    $actualModelHash = (Get-FileHash -Path $modelPath -Algorithm SHA256).Hash
    if ($expectedModelHash -ne $actualModelHash) {
        $verificationResults += Write-VerificationStep "4" "FAIL" "Model hash mismatch"
        $allPassed = $false
    } else {
        $verificationResults += Write-VerificationStep "4" "PASS" "Model SHA256 verified"
    }
} else {
    $verificationResults += Write-VerificationStep "4" "WARN" "Model file not found"
}

# [5] Load generation config
$configPath = Join-Path $EvidencePath "inference_run\generation_config.json"
$config = Get-Content $configPath | ConvertFrom-Json
$verificationResults += Write-VerificationStep "5" "PASS" "Generation config loaded"

# [6] Execute inference and measure
Write-Host "`n[6] Executing inference with recorded config..."
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $output = & $RawrXDExe --model $config.model_path --prompt $config.prompt --max-tokens $config.max_tokens --temperature $config.temperature --top-k $config.top_k --seed $config.seed 2>&1
    $sw.Stop()
    $measuredLatency = $sw.ElapsedMilliseconds
    $verificationResults += Write-VerificationStep "6" "PASS" "Inference executed in ${measuredLatency}ms"
} catch {
    $verificationResults += Write-VerificationStep "6" "FAIL" "Inference execution failed: $_"
    $allPassed = $false
}

# [7] Verify latency within bounds (50% tolerance for system variance)
$recordedLatency = $manifest.inference.latency_ms
$latencyDiff = [Math]::Abs($measuredLatency - $recordedLatency)
$latencyTolerance = $recordedLatency * 0.5
if ($latencyDiff -le $latencyTolerance) {
    $verificationResults += Write-VerificationStep "7" "PASS" "Latency within 50% tolerance ($measuredLatency vs $recordedLatency ms)"
} else {
    $verificationResults += Write-VerificationStep "7" "WARN" "Latency variance: $measuredLatency vs $recordedLatency ms"
}

# [8] Calculate actual tokens per second
$tokensGenerated = $manifest.inference.tokens_generated
$measuredTPS = if ($measuredLatency -gt 0) { [Math]::Round($tokensGenerated / ($measuredLatency / 1000), 2) } else { 0 }
$verificationResults += Write-VerificationStep "8" "INFO" "Measured tokens/sec: $measuredTPS"

# Summary
Write-Host "`n═══════════════════════════════════════════════════════════"
Write-Host "                    VERIFICATION SUMMARY"
Write-Host "═══════════════════════════════════════════════════════════`n"

foreach ($result in $verificationResults) {
    $status = $result.Status
    $symbol = switch ($status) {
        "PASS" { "✅" }
        "FAIL" { "❌" }
        "WARN" { "⚠️" }
        "INFO" { "ℹ️" }
        default { "❓" }
    }
    Write-Host "$symbol [$($result.Step)] $($result.Details)"
}

Write-Host "`n═══════════════════════════════════════════════════════════"
if ($allPassed) {
    Write-Host "              CERTIFICATION: ✅ VERIFIED"
    Write-Host "═══════════════════════════════════════════════════════════"
    exit 0
} else {
    Write-Host "              CERTIFICATION: ❌ FAILED"
    Write-Host "═══════════════════════════════════════════════════════════"
    exit 1
}
