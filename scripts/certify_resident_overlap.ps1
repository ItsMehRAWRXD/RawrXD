# ============================================================================
# File: scripts/certify_resident_overlap.ps1
#
# DEEP2_RESIDENT_OVERLAP_001 certification harness.
#
# Certifies the resident dual-GPU path with the two devices overlapped, and
# certifies it against the series path it replaced. The gate is a table, and
# every row of it is checked against what the run actually printed. Nothing
# here is hand-written into the manifest: a value in the manifest is a value
# that was parsed out of a run.
#
#   A  kernel overlap      the three dispatch forms agree bit for bit, and
#                          the overlapped form is not slower
#   B  full resident pass  all 32 layers complete on the resident path, and
#                          the CPU and device paths agree on the quantized
#                          projection
#   C  stability           N consecutive runs, every one of them clean
#   D  decode throughput   the same model, prompt, context and token count
#                          in both dispatch modes, with the generated text
#                          identical
#   E  memory residency    the resident path was used and the per-call
#                          staging allocation did not come back
#
# Usage:
#   pwsh -File scripts\certify_resident_overlap.ps1
#   pwsh -File scripts\certify_resident_overlap.ps1 -StabilityRuns 16
#
# Outputs (under certification\):
#   DEEP2_RESIDENT_OVERLAP_001.log            the full run log
#   DEEP2_RESIDENT_OVERLAP_001.manifest.json  the gate results
# ============================================================================

param(
    [string]$Model = "G:\~dev\rawrxd\models\phi3-mini-Q2_K.gguf",
    [string]$Exe = "",
    [int]$StabilityRuns = 8,
    [int]$Tokens = 12,
    [string]$Prompt = "The capital of France is",
    [int]$GemvIterations = 20,
    [string]$CertId = "DEEP2_RESIDENT_OVERLAP_001"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

# The binary is the one the build tree produced. It is not rebuilt here: a
# certification that builds its own subject cannot be compared against an
# earlier run, and the build is a separate step with its own failure modes.
if (-not $Exe) {
    $candidate = Join-Path $repo "build\bin\Release\Deep2Engine_Benchmark.exe"
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "The engine binary is not at $candidate. Build it first: cmake --build build --config Release --target Deep2Engine_Benchmark"
    }
    $Exe = $candidate
}
if (-not (Test-Path -LiteralPath $Model)) {
    throw "The model is not at $Model. Pass -Model <path to the gguf or the rom>."
}

$certDir = Join-Path $repo "certification"
if (-not (Test-Path -LiteralPath $certDir)) {
    New-Item -ItemType Directory -Path $certDir | Out-Null
}
$log = Join-Path $certDir "$CertId.log"
Start-Transcript -Path $log -Force | Out-Null

function Log([string]$m) { Write-Host "[certify] $m" }

# Run the engine and capture everything it printed, plus its exit code.
#
# The capture goes through a file rather than a PowerShell pipeline. The
# engine writes its narration to stdout and its diagnostics to stderr, and
# a merged pipeline reformats the two into something the gate would then
# have to parse around. A file keeps the bytes as they were written, which
# is what the gate has to reason about.
#
# The exit code matters: the stability gate is about the process surviving,
# and a run that dies has no output worth reading.
$captureDir = Join-Path $repo "build\bin\Release"
function Invoke-Engine([string[]]$EngineArgs) {
    $capture = Join-Path $captureDir ("cert-capture-" + [Guid]::NewGuid().ToString("N") + ".txt")
    # The engine writes its progress to stderr, and in Windows PowerShell 5.1 a
    # native command's stderr becomes error records. With ErrorActionPreference
    # set to Stop, the first such line aborts the run before any gate is
    # checked. Running the engine through cmd keeps both streams in the file
    # and out of the error stream.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $quoted = @($Exe) + @($EngineArgs | ForEach-Object { '"' + $_ + '"' })
        $line = $quoted[0] + " " + ($quoted[1..($quoted.Count - 1)] -join " ") +
                ' > "' + $capture + '" 2>&1'
        cmd /c $line
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    $text = ""
    if (Test-Path -LiteralPath $capture) {
        $text = Get-Content -LiteralPath $capture -Raw -ErrorAction SilentlyContinue
    }
    return @{ Output = $text; ExitCode = $code; Capture = $capture }
}

# The gate rows. Each is a fact that has to be true, and the evidence that
# proves it. A row with no evidence is a failure: the run did not prove it.
$gates = [ordered]@{}

function Add-Gate([string]$name, [bool]$passed, [string]$detail, [string]$evidence) {
    $gates[$name] = [ordered]@{
        passed   = $passed
        detail   = $detail
        evidence = $evidence
    }
    Log ("gate {0,-18} {1}  {2}" -f $name, $(if ($passed) { "PASS" } else { "FAIL" }), $detail)
}

try {
    Log "=== $CertId ==="
    Log "executable : $Exe"
    Log "model      : $Model"
    Log "commit     : $((& git rev-parse HEAD).Trim())"

    # ------------------------------------------------------------------
    # A. The kernel overlap: the three dispatch forms, and the gate that
    #    they agree bit for bit.
    # ------------------------------------------------------------------
    Log "--- A: resident GEMV overlap ---"
    $gemv = Invoke-Engine @("--gemv-benchmark", $Model, "$GemvIterations")
    if ($gemv.ExitCode -ne 0) { throw "The GEMV benchmark exited with $($gemv.ExitCode)" }

    $gemvGate = $gemv.Output -match "\[GEMVBENCH\] gate: PASSED"
    $gemvLines = [regex]::Matches($gemv.Output, "\[GEMVBENCH\]\s+(blk\.[^\r\n]+)").Count
    Add-Gate "kernel_overlap" ($gemvGate -and $gemvLines -gt 0) `
        "the three dispatch forms are bit-identical over $gemvLines projections" `
        (($gemv.Output -split "`r?`n" | Where-Object { $_ -like "*GEMVBENCH*" }) -join " | ")

    # The overlap has to be worth something, or the complexity is not
    # justified. The overlapped form must beat the series form.
    $overlapFaster = $false
    $formRows = [regex]::Matches($gemv.Output, "overlapped\s+([0-9.]+)\s+ms/call")
    $serialRows = [regex]::Matches($gemv.Output, "serial\s+([0-9.]+)\s+ms/call")
    if ($formRows.Count -gt 0 -and $formRows.Count -eq $serialRows.Count) {
        $overlapFaster = $true
        for ($i = 0; $i -lt $formRows.Count; $i++) {
            if ([double]$formRows[$i].Groups[1].Value -ge [double]$serialRows[$i].Groups[1].Value) {
                $overlapFaster = $false
            }
        }
    }
    Add-Gate "overlap_is_faster" $overlapFaster `
        "the overlapped form is faster than the series form on every projection" `
        (($gemv.Output -split "`r?`n" | Where-Object { $_ -like "*ms/call*" }) -join " | ")

    # ------------------------------------------------------------------
    # B. The full resident pass: 32 layers on the devices, and the CPU
    #    and device paths agreeing on the quantized projection.
    # ------------------------------------------------------------------
    Log "--- B: full resident forward pass ---"
    $parity = Invoke-Engine @("--forward-parity", $Model)
    $parityOut = $parity.Output

    # The forward pass's own narration is captured by the engine into a
    # trace buffer, so it never reaches stdout. What reaches stdout is the
    # summary the engine builds from that trace, and the summary is the
    # evidence: the per-layer comparison counts one entry per layer per
    # token, so its count is the number of layers the pass actually ran.
    $layerCount = 0
    if ($parityOut -match "geometry:[^\r\n]*layers=(\d+)") { $layerCount = [int]$Matches[1] }
    $comparedLayers = 0
    if ($parityOut -match "per-layer:\s*(\d+)\s+layers compared") { $comparedLayers = [int]$Matches[1] }
    $residentPathOk = $parityOut -match "\[PARITY\] resident path: OK"
    $cpuPathOk = $parityOut -match "\[PARITY\] cpu path: OK"
    # The pass runs three tokens, so a pass that reached every layer
    # compares three entries per layer.
    $expectedComparisons = $layerCount * 3
    Add-Gate "all_layers_complete" `
        ($parity.ExitCode -eq 0 -and $residentPathOk -and $cpuPathOk -and
         $layerCount -gt 0 -and $comparedLayers -ge $expectedComparisons) `
        "the pass compared $comparedLayers layer entries ($layerCount layers x 3 tokens) and both paths reported OK" `
        (($parityOut -split "`r?`n" | Where-Object { $_ -like "*resident path:*" -or $_ -like "*cpu path:*" -or $_ -like "*per-layer:*" }) -join " | ")

    $tparityPass = [regex]::Matches($parityOut, "\[TPARITY\][^\r\n]*PASS")
    $qparityPass = [regex]::Matches($parityOut, "\[QPARITY\][^\r\n]*PASS")
    Add-Gate "quantized_parity" ($tparityPass.Count -ge 4 -and $qparityPass.Count -ge 1) `
        "$($tparityPass.Count) device/CPU tensor comparisons and $($qparityPass.Count) quantization checks passed" `
        (($parityOut -split "`r?`n" | Where-Object { $_ -like "*TPARITY*" -or $_ -like "*QPARITY*" }) -join " | ")

    $execGate = $parityOut -match "\[PARITY\] gate \(execution path, first layer\): PASSED"
    Add-Gate "execution_path" $execGate `
        "the resident path and the CPU path agree at the first layer" `
        (($parityOut -split "`r?`n" | Where-Object { $_ -like "*per-layer:*" -or $_ -like "*execution path*" }) -join " | ")

    # The resident path has to be the one that ran. A pass that quietly fell
    # back to the CPU would pass every comparison above and still be the
    # wrong thing. The proof is the tensor comparison: it puts the device's
    # GEMV against the CPU's, on the resident weights.
    Add-Gate "resident_path_used" ($tparityPass.Count -ge 4 -and $comparedLayers -gt 0) `
        "$($tparityPass.Count) resident projections matched the CPU on the device, over $comparedLayers layer entries" `
        (($parityOut -split "`r?`n" | Where-Object { $_ -like "*TPARITY*" }) -join " | ")

    # ------------------------------------------------------------------
    # C. Stability: N consecutive runs, every one of them clean.
    # ------------------------------------------------------------------
    Log "--- C: stability ($StabilityRuns runs) ---"
    $crashes = @()
    for ($i = 1; $i -le $StabilityRuns; $i++) {
        $run = Invoke-Engine @("--move10-validate", $Model)
        if ($run.ExitCode -ne 0) {
            $crashes += "run $i exited $($run.ExitCode)"
            Log "  run $i FAILED with exit code $($run.ExitCode)"
            # The tail of the output is what says where it died.
            $tail = ($run.Output -split "`r?`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -Last 1)
            if ($tail) { Log "  last line: $tail" }
        } else {
            Log "  run $i clean"
        }
    }
    Add-Gate "stability" ($crashes.Count -eq 0) `
        "$($StabilityRuns - $crashes.Count)/$StabilityRuns runs exited cleanly" `
        $(if ($crashes.Count) { $crashes -join "; " } else { "no failures" })

    # ------------------------------------------------------------------
    # D. Decode throughput, series against overlapped, with the same model,
    #    prompt, context and token count, and the same text out.
    # ------------------------------------------------------------------
    Log "--- D: decode throughput, series against overlapped ---"
    $genArgs = @("--generate", "--prompt", $Prompt, "--max-tokens", "$Tokens", $Model)
    $genOverlapped = Invoke-Engine $genArgs
    $genSerial = Invoke-Engine ($genArgs + @("--no-gemv-overlap"))

    function Read-DecodeRate([string]$out) {
        if ($out -match "decode time\s*:\s*([0-9.]+)\s*ms\s*\(([0-9.]+)\s*tok/s\)") {
            return @{ Ms = [double]$Matches[1]; TokPerSec = [double]$Matches[2] }
        }
        return $null
    }
    function Read-GeneratedText([string]$out) {
        if ($out -match "(?s)=== GENERATION ===.*?text\s*:\s*(.*?)\r?\n") { return $Matches[1].Trim() }
        return $null
    }
    function Read-GeneratedTokens([string]$out) {
        if ($out -match "generated\s*:\s*(\d+)\s*token") { return [int]$Matches[1] }
        return 0
    }

    $rateOverlapped = Read-DecodeRate $genOverlapped.Output
    $rateSerial = Read-DecodeRate $genSerial.Output
    $textOverlapped = Read-GeneratedText $genOverlapped.Output
    $textSerial = Read-GeneratedText $genSerial.Output
    $tokOverlapped = Read-GeneratedTokens $genOverlapped.Output
    $tokSerial = Read-GeneratedTokens $genSerial.Output

    $bothRan = ($rateOverlapped -ne $null -and $rateSerial -ne $null)
    Add-Gate "decode_measured" $bothRan `
        $(if ($bothRan) { "series $([math]::Round($rateSerial.TokPerSec,2)) tok/s, overlapped $([math]::Round($rateOverlapped.TokPerSec,2)) tok/s" } else { "one of the two modes did not report a decode rate" }) `
        "overlapped: $($rateOverlapped.TokPerSec) tok/s; series: $($rateSerial.TokPerSec) tok/s"

    $sameText = ($null -ne $textOverlapped -and $textOverlapped -eq $textSerial)
    Add-Gate "same_text_both_modes" $sameText `
        $(if ($sameText) { "both modes emitted the same text" } else { "the two modes emitted different text" }) `
        "overlapped: `"$textOverlapped`"; series: `"$textSerial`""

    # The overlap has to be worth something end to end, not only at the
    # kernel level. A kernel speedup that the forward pass cannot cash in
    # is a kernel speedup that does not matter.
    $speedup = 0.0
    if ($rateOverlapped -and $rateSerial -and $rateSerial.TokPerSec -gt 0) {
        $speedup = $rateOverlapped.TokPerSec / $rateSerial.TokPerSec
    }
    Add-Gate "decode_speedup" ($speedup -gt 1.0) `
        $(if ($speedup -gt 0) { "the overlapped decode rate is $([math]::Round($speedup,2))x the series rate" } else { "the decode rates could not be compared" }) `
        "series $([math]::Round($rateSerial.TokPerSec,4)) tok/s, overlapped $([math]::Round($rateOverlapped.TokPerSec,4)) tok/s"

    $enoughTokens = ($tokOverlapped -ge 3 -and $tokSerial -ge 3)
    Add-Gate "generated_tokens" $enoughTokens `
        "overlapped produced $tokOverlapped token(s), series produced $tokSerial" `
        "tokens: $tokOverlapped / $tokSerial"

    # ------------------------------------------------------------------
    # E. Memory residency: the staging was placed once and the per-call
    #    allocation did not come back.
    # ------------------------------------------------------------------
    $stagingFallback = @()
    if ($gemv.Output -like "*could not be placed*") { $stagingFallback += "gemv-benchmark" }
    if ($parityOut -like "*could not be placed*") { $stagingFallback += "forward-parity" }
    $noFallback = ($stagingFallback.Count -eq 0)
    Add-Gate "no_staging_fallback" $noFallback `
        $(if ($noFallback) { "the persistent staging was used on every call" } else { "the transient staging fallback was used" }) `
        $(if ($noFallback) { "no fallback message" } else { $stagingFallback -join " | " })

    # ------------------------------------------------------------------
    # The manifest. Facts only, every one of them parsed out of a run.
    # ------------------------------------------------------------------
    $allPassed = -not ($gates.Values | Where-Object { -not $_.passed })

    $manifest = [ordered]@{
        certification_id = $CertId
        generated_utc    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        subject = [ordered]@{
            executable = $Exe
            model     = $Model
            commit    = (& git rev-parse HEAD).Trim()
        }
        gates = $gates
        result = [ordered]@{
            passed   = $allPassed
            of       = $gates.Count
            failures = @($gates.Values | Where-Object { -not $_.passed } | ForEach-Object { $_.detail })
        }
    }
    $manifestPath = Join-Path $certDir "$CertId.manifest.json"
    ($manifest | ConvertTo-Json -Depth 8) | Out-File -FilePath $manifestPath -Encoding utf8
    Log "manifest : $manifestPath"

    Log "=== $CertId : $(if ($allPassed) { "PASSED" } else { "FAILED" }) ==="
    foreach ($k in $gates.Keys) {
        Log ("  {0,-22} {1}" -f $k, $(if ($gates[$k].passed) { "PASS" } else { "FAIL" }))
    }
}
finally {
    Stop-Transcript | Out-Null
}

if (-not $allPassed) { exit 1 }
exit 0
