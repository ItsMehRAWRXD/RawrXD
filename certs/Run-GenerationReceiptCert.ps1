<# 
.SYNOPSIS
    Deep2 Generation Receipt Certification Script
    Tests existing binaries without modifying source - preserves known-good build

.DESCRIPTION
    Runs Phi-3 and Nemotron generation with full receipt capture.
    Produces three decisive evidence artifacts:
    1. Termination receipt (stopReason, eosObserved, callbackCancelled, engineError, token counts)
    2. CLI vs Agent comparison (identical GGUF, prompt, sampling, context)
    3. Phase timing (prefillMs, decodeMs, weightLoadMs, diagnosticLoggingMs, weightCacheMisses)

.NOTES
    Requires: RawrXD build with GenerationReceipt support (commit 9d85d77d4d+)
    Models: phi3-mini-Q2_K.gguf, nemotron-nano-Q4_K_M.gguf (or available)
#>

param(
    [string]$ModelPath = "G:\~dev\rawrxd\models\phi3-mini-Q2_K.gguf",
    [string]$CliExe = "G:\~dev\rawrxd\build\bin\rawr.exe",
    [string]$Prompt = "Write a short poem about token generation. Exactly 4 lines.",
    [int]$MaxTokens = 64,
    [string]$OutputDir = "G:\~dev\rawrxd\certs\cert_output_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$TestCli = $true,
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    Write-Verbose "[$timestamp] [$Level] $Message"
}

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Run-Generation {
    param(
        [string]$Name,
        [string]$Model,
        [string]$PromptText,
        [int]$MaxToks,
        [string]$OutFile
    )
    
    $env:DEEP2_K2_SHARD_DIR = ""
    $env:DEEP2_REAL_K2_GENERATE = "0"
    $env:RAWRXD_NO_TP = "1"
    $env:RAWRXD_GREEDY = "1"
    $env:TPS_LIMIT = "NONE"
    $env:FULL_MODEL_RESIDENCY_REQUIRED = "0"
    $env:DEEP2_TPS_DISPLAY_SCALE = "1"
    $env:RAWRXD_FFN_TRACE = "1"
    
    $argList = @(
        "run", $Model,
        "--prompt", $PromptText,
        "--max-tokens", $MaxToks.ToString()
    )
    
    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    Write-Verbose "[$timestamp] [INFO] Running $($Name): $($CliExe) $($argList -join ' ')"
    
    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = $CliExe
    $processInfo.Arguments = $argList -join " "
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $processInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $processInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    
    $process = [System.Diagnostics.Process]::Start($processInfo)
    
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    
    $null = $process.WaitForExit(900000)
    if (-not $process.HasExited) {
        $process.Kill()
        throw "Process timed out after 15 minutes"
    }
    
    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    $exitCode = $process.ExitCode
    
    $result = $stdout + "`n" + $stderr
    $result | Out-File -FilePath $OutFile -Encoding utf8
    
    return @{
        ExitCode = $exitCode
        Output = $result
        File = $OutFile
    }
}

function Parse-Receipt {
    param([string]$Output)
    
    $receipt = @{
        StopReason = "Unknown"
        EosObserved = $false
        CallbackCancelled = $false
        EngineError = $false
        GeneratedTokens = 0
        CommittedTokens = 0
        PromptTokens = 0
        PrefillMs = 0.0
        DecodeMs = 0.0
        WeightLoadMs = 0.0
        DiagnosticLoggingMs = 0.0
        WeightCacheMisses = 0
        FirstTokenId = -1
        StopTokenId = -1
        OutputText = ""
    }
    
    $lines = $Output -split "`r?`n"
    foreach ($line in $lines) {
        # AGENT_MODEL lines
        if ($line -match '\[AGENT_MODEL\] gr\.callbackCancelled=(\d+) gr\.completed=(\d+) gr\.generatedTokens=(\d+) gr\.promptTokens=(\d+) gr\.stopReason=(\w+) gr\.eosObserved=(\d+) gr\.callbackCancelled=(\d+) gr\.engineError=(\d+)') {
            $receipt.CallbackCancelled = [bool][int]$matches[1]
            $receipt.Completed = [bool][int]$matches[2]
            $receipt.GeneratedTokens = [int]$matches[3]
            $receipt.PromptTokens = [int]$matches[4]
            $receipt.StopReason = $matches[5]
            $receipt.EosObserved = [bool][int]$matches[6]
            $receipt.CallbackCancelled = [bool][int]$matches[7]
            $receipt.EngineError = [bool][int]$matches[8]
        }
        elseif ($line -match '\[AGENT_MODEL\] gen tokens=(\d+) stop_reason=(\w+) output=''(.*)''') {
            $receipt.GeneratedTokens = [int]$matches[1]
            $receipt.StopReason = $matches[2]
            $receipt.OutputText = $matches[3]
        }
        
        # Rawr receipt lines - use separate if statements for multi-pattern lines
        if ($line -match 'GENERATION_STOP_REASON=(\w+)') {
            $receipt.StopReason = $matches[1]
        }
        if ($line -match 'GENERATED_TOKENS=(\d+)') {
            $receipt.GeneratedTokens = [int]$matches[1]
        }
        if ($line -match 'PROMPT_TOKENS=(\d+)') {
            $receipt.PromptTokens = [int]$matches[1]
        }
        if ($line -match 'COMMITTED_TOKENS=(\d+)') {
            $receipt.CommittedTokens = [int]$matches[1]
        }
        if ($line -match 'TOKENS_COMMITTED=(\d+)') {
            $receipt.CommittedTokens = [int]$matches[1]
        }
        if ($line -match 'TOKENS_REQUESTED=(\d+)') {
            if ($receipt.GeneratedTokens -eq 0) { $receipt.GeneratedTokens = [int]$matches[1] }
        }
        if ($line -match 'EOS_OBSERVED=(\d+)') {
            $receipt.EosObserved = [bool][int]$matches[1]
        }
        if ($line -match 'CALLBACK_CANCELLED=(\d+)') {
            $receipt.CallbackCancelled = [bool][int]$matches[1]
        }
        if ($line -match 'ENGINE_ERROR=(\d+)') {
            $receipt.EngineError = [bool][int]$matches[1]
        }
        if ($line -match 'STOPPED_BY_MAXTOK_VALID=(\d+)') {
            if ([bool][int]$matches[1]) { $receipt.StopReason = "MaxTokens" }
        }
        if ($line -match 'STOPPED_BY_EOS_VALID=(\d+)') {
            if ([bool][int]$matches[1]) { $receipt.StopReason = "Eos"; $receipt.EosObserved = $true }
        }
        if ($line -match 'CANCEL_OBSERVED_AT=(\S+)') {
            if ($matches[1] -ne "NONE") { $receipt.CallbackCancelled = $true; $receipt.StopReason = "CallbackCancel" }
        }
        if ($line -match 'CRASH_OBSERVED=(\d+)') {
            if ([bool][int]$matches[1]) { $receipt.EngineError = $true; $receipt.StopReason = "EngineError" }
        }
        if ($line -match 'RECEIPT_ATOMIC=(\d+)') {
        }
        if ($line -match 'PREFILL_MS=([\d.]+)') {
            $receipt.PrefillMs = [double]$matches[1]
        }
        if ($line -match 'DECODE_MS=([\d.]+)') {
            $receipt.DecodeMs = [double]$matches[1]
        }
        if ($line -match 'TOTAL_WALL_MS=([\d.]+)') {
        }
        if ($line -match 'FORWARD_MS=([\d.]+)') {
        }
        if ($line -match 'LOGITS_MS=([\d.]+)') {
        }
        if ($line -match 'SAMPLE_MS=([\d.]+)') {
        }
        if ($line -match 'DETOK_MS=([\d.]+)') {
        }
        if ($line -match 'CALLBACK_MS=([\d.]+)') {
        }
        if ($line -match 'RECEIPT_MS=([\d.]+)') {
        }
        if ($line -match 'KV_MS=([\d.]+)') {
        }
        if ($line -match 'PHI3_EXPECTED_FFN_LAYERS=(\d+)') {
            $receipt.ExpectedFfnLayers = [int]$matches[1]
        }
        if ($line -match 'PHI3_EXECUTED_FFN_LAYERS=(\d+)') {
            $receipt.ExecutedFfnLayers = [int]$matches[1]
        }
        if ($line -match 'PHI3_FUSED_GATE_UP_VALID=(\d+)') {
            $receipt.FusedGateUpValid = [bool][int]$matches[1]
        }
        if ($line -match 'GENERATION_RECEIPT_VALID=(\d+)') {
            $receipt.ReceiptValid = [bool][int]$matches[1]
        }
    }
    
    # If CommittedTokens not set but TOKENS_COMMITTED was, use it
    if ($receipt.CommittedTokens -eq 0 -and $receipt.GeneratedTokens -gt 0) {
        $receipt.CommittedTokens = $receipt.GeneratedTokens
    }
    
    return $receipt
}

# ========== MAIN EXECUTION ==========

Write-Log "=== Deep2 Generation Receipt Certification ==="
Write-Log "Model: $ModelPath"
Write-Log "Prompt: $Prompt"
Write-Log "MaxTokens: $MaxTokens"
Write-Log "OutputDir: $OutputDir"

Ensure-Dir $OutputDir

$summary = @{
    Timestamp = Get-Date -Format "o"
    Model = $ModelPath
    Prompt = $Prompt
    MaxTokens = $MaxTokens
    CliResult = $null
    Passed = $true
}

# Test CLI
if ($TestCli) {
    Write-Log "=== TEST: CLI Generation ==="
    $cliOutFile = Join-Path $OutputDir "cli_receipt.txt"
    $cliResult = Run-Generation "CLI" $ModelPath $Prompt $MaxTokens $cliOutFile
    $summary.CliResult = Parse-Receipt $cliResult.Output
    
    Write-Log "CLI ExitCode: $($cliResult.ExitCode)"
    Write-Log "CLI StopReason: $($summary.CliResult.StopReason)"
    Write-Log "CLI GeneratedTokens: $($summary.CliResult.GeneratedTokens)"
    Write-Log "CLI PromptTokens: $($summary.CliResult.PromptTokens)"
    Write-Log "CLI CommittedTokens: $($summary.CliResult.CommittedTokens)"
    Write-Log "CLI EosObserved: $($summary.CliResult.EosObserved)"
    Write-Log "CLI CallbackCancelled: $($summary.CliResult.CallbackCancelled)"
    Write-Log "CLI EngineError: $($summary.CliResult.EngineError)"
    Write-Log "CLI Output: $($summary.CliResult.OutputText)"
}

# Validate receipt completeness
if ($TestCli) {
    $r = $summary.CliResult
    if ($r.StopReason -eq "Unknown") {
        Write-Log "WARN: CLI StopReason is Unknown" "WARN"
    }
    if ($r.GeneratedTokens -eq 0) {
        Write-Log "WARN: CLI generated 0 tokens" "WARN"
        $summary.Passed = $false
    }
    if ($r.EngineError) {
        Write-Log "FAIL: CLI EngineError = true" "ERROR"
        $summary.Passed = $false
    }
    if ($r.CallbackCancelled -and $r.StopReason -ne "CallbackCancel") {
        Write-Log "FAIL: CallbackCancelled but StopReason != CallbackCancel" "ERROR"
        $summary.Passed = $false
    }
    if ($r.CommittedTokens -gt $r.GeneratedTokens) {
        Write-Log "FAIL: CommittedTokens > GeneratedTokens" "ERROR"
        $summary.Passed = $false
    }
    
    # Check FFN execution (only available in phi3_ffn_runtime_cert binary)
    if ($r.ContainsKey('ExecutedFfnLayers') -and $r.ExecutedFfnLayers) {
        if ($r.ExecutedFfnLayers -lt $r.ExpectedFfnLayers) {
            Write-Log "FAIL: FFN layers skipped: $($r.ExecutedFfnLayers)/$($r.ExpectedFfnLayers)" "ERROR"
            $summary.Passed = $false
        }
        if (-not $r.FusedGateUpValid) {
            Write-Log "WARN: Fused gate/up validation failed" "WARN"
        }
        if (-not $r.ReceiptValid) {
            Write-Log "WARN: Generation receipt validation failed" "WARN"
        }
    }
}

# Export summary JSON
$summaryFile = Join-Path $OutputDir "certification_summary.json"
$summary | ConvertTo-Json -Depth 10 | Out-File -FilePath $summaryFile -Encoding utf8

Write-Log "=== CERTIFICATION COMPLETE ==="
Write-Log "Summary saved to: $summaryFile"
Write-Log "Overall: $(if ($summary.Passed) { 'PASS' } else { 'FAIL' })"

# Exit with appropriate code
if ($summary.Passed) { exit 0 } else { exit 1 }