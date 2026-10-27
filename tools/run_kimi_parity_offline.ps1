# RawrXD Kimi numerical parity: local, fail-closed, dependency-light offline gate.
# Run from a VS2022 x64 Developer PowerShell:
# powershell -NoProfile -ExecutionPolicy Bypass -File tools\run_kimi_parity_offline.ps1 -EvidenceDir F:\rawrxd\evidence\KIMI_OFFLINE_001
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string] $EvidenceDir,
    [string] $Python = 'python'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$tests = @(
    'test_k2_gpu_moe_vector_parity.py',
    'test_k2_q6k_scalar_oracle.py',
    'test_k2_q4k_scalar_oracle.py',
    'test_k2_scalar_expert_oracle.py',
    'test_k2_scalar_input_audit.py',
    'test_k2_moe_capture_audit.py',
    'test_k2_stick_partial_repeatability.py',
    'test_k2_fused_parity_safety.py'
)
$steps = New-Object 'System.Collections.Generic.List[object]'
$exitCode = 0
$started = (Get-Date).ToUniversalTime().ToString('o')
$commit = 'UNKNOWN'
try {
    if (-not (Test-Path -LiteralPath $EvidenceDir -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
    }
    $receiptPath = Join-Path $EvidenceDir 'KIMI_OFFLINE_RECEIPT.json'
    if (Test-Path -LiteralPath $receiptPath) {
        throw "Refusing to replace previous receipt: $receiptPath"
    }
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        $commitOut = & git -C $root rev-parse HEAD 2>$null
        if ($LASTEXITCODE -eq 0) { $commit = ($commitOut | Select-Object -First 1).Trim() }
    }
    $py = Get-Command $Python -ErrorAction Stop
    foreach ($test in $tests) {
        $path = Join-Path $PSScriptRoot $test
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Missing expected regression test: $test"
        }
        $out = & $py.Source $path 2>&1 | Out-String
        $status = [int]$LASTEXITCODE
        $steps.Add([ordered]@{
            name = $test
            exit_code = $status
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            output = $out.Trim()
        })
        if ($status -ne 0) { $exitCode = 2 }
    }
    $compiler = Get-Command cl.exe -ErrorAction Stop
    $source = Join-Path $PSScriptRoot 'test_k2_moe_parity_capture.cpp'
    $includePath = Join-Path $root 'src\deep2'
    $exe = Join-Path $EvidenceDir 'k2_parity_capture_smoke.exe'
    $buildOutput = & $compiler.Source /nologo /std:c++17 /EHsc /W4 /WX "/I$includePath" $source "/Fe:$exe" 2>&1 | Out-String
    $buildCode = [int]$LASTEXITCODE
    $steps.Add([ordered]@{
        name = 'msvc_capture_compile'
        exit_code = $buildCode
        source_sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        output = $buildOutput.Trim()
    })
    if ($buildCode -ne 0) { $exitCode = 2 }
    else {
        $smokeOutput = & $exe 2>&1 | Out-String
        $smokeCode = [int]$LASTEXITCODE
        $steps.Add([ordered]@{
            name = 'msvc_capture_smoke'
            exit_code = $smokeCode
            executable_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
            output = $smokeOutput.Trim()
        })
        if ($smokeCode -ne 0) { $exitCode = 2 }
    }
}
catch {
    $exitCode = 3
    $steps.Add([ordered]@{ name = 'harness_error'; exit_code = 3; error = $_.Exception.Message })
}
finally {
    if (Test-Path -LiteralPath $EvidenceDir -PathType Container) {
        $receiptPath = Join-Path $EvidenceDir 'KIMI_OFFLINE_RECEIPT.json'
        if (-not (Test-Path -LiteralPath $receiptPath)) {
            $receipt = [ordered]@{
                schema = 'DEEP2_KIMI_OFFLINE_GATE_001/v1'
                started_utc = $started
                finished_utc = (Get-Date).ToUniversalTime().ToString('o')
                repo_commit = $commit
                status = $(if ($exitCode -eq 0) { 'PASS_OFFLINE_ONLY' } else { 'FAIL' })
                certified = $false
                gpu_numerical_parity = 'NOT_CERTIFIED'
                release_promote = 0
                steps = @($steps)
            }
            $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding UTF8
            Write-Host "Receipt: $receiptPath"
        }
    }
}
Write-Host "KIMI_OFFLINE_EXIT=$exitCode"
exit $exitCode
