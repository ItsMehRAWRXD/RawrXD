<#
RAWRXD_AGENT_HARNESS_GATE_001

Binding prerequisite: the autonomous agent harness may not be reported complete,
certified, or promoted until native Deep2 inference meets a declared performance
floor on the GPU path.

Rationale
---------
The only end-to-end agent steps demonstrated so far ran on Ollama/llama.cpp
(reap16-qwen3_6-35b), not on Deep2. Wiring, token generation, and tool protocol
are therefore proven against a backend that is not RawrXD's native engine.
Declaring the harness finished on that basis would rest a green agent loop on a
fast third-party runtime while the native engine is unusable.

This script is the enforcement point. It exits non-zero unless a native-Deep2
evidence receipt exists that satisfies every clause. It performs no cleanup,
no benchmarking, and no mutation.

Usage
-----
  pwsh -File scripts/check_agent_harness_gate.ps1
  pwsh -File scripts/check_agent_harness_gate.ps1 -EvidenceDir F:\rawrxd\evidence -MinDecodeTps 5

Exit codes
----------
  0  gate satisfied (native perf floor met, evidence valid)
  1  gate blocked (one or more clauses unmet)
  2  usage or input error
#>

[CmdletBinding()]
param(
    [string] $EvidenceDir  = 'F:\rawrxd\evidence',
    [double] $MinDecodeTps = 5.0,
    [string] $Receipt      = 'DEEP2_NATIVE_PERF_RECEIPT.md'
)

$ErrorActionPreference = 'Continue'

function Fail([string]$Clause, [string]$Detail) {
    Write-Host ("BLOCKED  {0,-34} {1}" -f $Clause, $Detail)
    $script:blocked++
}

function Pass([string]$Clause, [string]$Detail) {
    Write-Host ("PASS     {0,-34} {1}" -f $Clause, $Detail)
}

$script:blocked = 0

Write-Host '=== RAWRXD AGENT HARNESS GATE ==='
Write-Host ("policy      : DEEP2_NATIVE_PERF_IS_PREREQUISITE_FOR_AGENT_HARNESS=1")
Write-Host ("min decode  : {0} tok/s (native GPU, real model)" -f $MinDecodeTps)
Write-Host ''

# --- Clause 1: a native perf receipt must exist ---------------------------
$receiptPath = Join-Path $EvidenceDir $Receipt
if (Test-Path -LiteralPath $receiptPath) {
    Pass 'RECEIPT_PRESENT' $receiptPath
} else {
    Fail 'RECEIPT_PRESENT' "missing: $receiptPath"
}

# --- Clauses 2..n: parse the receipt -------------------------------------
if (Test-Path -LiteralPath $receiptPath) {

    $text = Get-Content -LiteralPath $receiptPath -Raw

    function Field([string]$name) {
        $m = [regex]::Match($script:text, ('(?im)^\s*' + [regex]::Escape($name) + '\s*=\s*(.+?)\s*$'))
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
        return $null
    }

    $backend   = Field 'BACKEND'
    $device    = Field 'DEVICE'
    $decodeTps = Field 'DECODE_TPS_NATIVE'
    $cpuCalls  = Field 'CPU_CALLS'
    $submits   = Field 'GPU_SUBMITS'
    $verdict   = Field 'VERDICT'
    $model     = Field 'MODEL'
    $exeSha    = 'EXE_SHA256'
    $srcSha    = Field 'SOURCE_SHA'

    # 2. must be the native engine
    if ($backend -eq 'deep2-vulkan') { Pass 'BACKEND_NATIVE' $backend }
    else { Fail 'BACKEND_NATIVE' "BACKEND='$backend' (expected deep2-vulkan; ollama does not satisfy this gate)" }

    # 3. must be the GPU path
    if ($device -eq 'vulkan' -or $device -eq 'gpu') { Pass 'DEVICE_GPU' $device }
    else { Fail 'DEVICE_GPU' "DEVICE='$device'" }

    # 4. decode throughput at or above the floor
    $tps = 0.0
    if ($decodeTps -and [double]::TryParse($decodeTps, [ref]$tps) -and $tps -ge $MinDecodeTps) {
        Pass 'DECODE_TPS_FLOOR' ("{0} >= {1}" -f $tps, $MinDecodeTps)
    } else {
        Fail 'DECODE_TPS_FLOOR' ("DECODE_TPS_NATIVE='$decodeTps' (need >= $MinDecodeTps)")
    }

    # 5. zero CPU fallback on the GPU path
    $cc = 0
    if ($cpuCalls -and [int]::TryParse($cpuCalls, [ref]$cc) -and $cc -eq 0) { Pass 'ZERO_CPU_REPLAY' '0' }
    else { Fail 'ZERO_CPU_REPLAY' "CPU_CALLS='$cpuCalls'" }

    # 6. real GPU submissions
    $sb = 0
    if ($submits -and [int]::TryParse($submits, [ref]$sb) -and $sb -gt 0) { Pass 'GPU_SUBMITS' "$sb" }
    else { Fail 'GPU_SUBMITS' "GPU_SUBMITS='$submits'" }

    # 7. explicit PASS verdict
    if ($verdict -eq 'PASS') { Pass 'RECEIPT_VERDICT' 'PASS' }
    else { Fail 'RECEIPT_VERDICT' "VERDICT='$verdict'" }

    # 8. provenance present
    if ($exeSha) { Pass 'EXE_SHA_PRESENT' $exeSha } else { Fail 'EXE_SHA_PRESENT' 'missing EXE_SHA256' }
    if ($srcSha) { Pass 'SOURCE_SHA_PRESENT' $srcSha } else { Fail 'SOURCE_SHA_PRESENT' 'missing SOURCE_SHA' }

    # 9. model identity
    if ($model) { Pass 'MODEL_IDENTIFIED' $model } else { Fail 'MODEL_IDENTIFIED' 'missing MODEL' }
}

Write-Host ''
if ($script:blocked -eq 0) {
    Write-Host 'GATE=SATISFIED  AGENT_HARNESS_MAY_BE_FINALISED=1'
    exit 0
}

Write-Host ("GATE=BLOCKED  clauses_failed={0}" -f $script:blocked)
Write-Host 'AGENT_HARNESS_MAY_BE_FINALISED=0'
Write-Host 'HANDOFF_TO_AGENT != DONE; OLLAMA_RESULT != NATIVE_RESULT'
exit 1