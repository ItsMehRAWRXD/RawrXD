#Requires -Version 5.1
<#
.SYNOPSIS
    RAWRXD_NQB_CHAIN_SELFTEST_001 -- fast end-to-end rehearsal of the whole NQB
    certification chain, in under two seconds, on the smallest real GGUF in the tree.

.DESCRIPTION
    Every measurement of the real 12.85 GB artifact costs roughly 90 seconds of
    conversion plus ~130 seconds of verification, and needs the model present.
    That is the right cost for a real claim and the wrong cost for answering
    "did my edit break the chain?".

    So the identical chain is rehearsed on src/core/test_tiny_with_vocab.gguf --
    21 tensors, 363,456 bytes -- exercising every link that can silently break:

      converter    transactional write, provisional header, census accumulation,
                   derived bitsPerWeight, codec census, vocab domain derivation,
                   verdict, atomic promote
      reopen gate  reverse footer chain, exact byte coverage, per-tensor digests,
                   whole-file SHA-256, production F32 reader path, negative controls
      comparator   name-keyed join, geometry, both digests, manifest root,
                   conservation, negative controls

    WHAT IT DOES NOT CLAIM
    ----------------------
    Nothing about the real model. 21 tensors of a synthetic fixture cannot speak
    for 3,212,749,888 elements of llama3.2-3b. The only claim is that the
    instruments are still wired to each other and still able to fail.

.PARAMETER Bin
    Directory holding the built instruments (gguf_to_nqb_converter.exe plus the
    three nqb_* certification executables).

.PARAMETER Gguf
    Override the source GGUF. Must have the tensor/element/size counts this
    script asserts; the default fixture does.

.EXAMPLE
    .\raqrxd_nqb_chain_selftest.ps1 -Bin C:\path\to\bin\Release
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Bin,
    [string]$Gguf = 'F:\~dev\rawrxd\src\core\test_tiny_with_vocab.gguf',
    [switch]$Keep
)

# Native tools here write their receipts to stderr by design. Under 'Stop', PowerShell
# turns any native stderr line into a TERMINATING error and the harness dies before it
# can read an exit code. The exit code is the authority; stderr is data.
$ErrorActionPreference = 'Continue'

$script:Failures = @()

function Get-Field([string]$text, [string]$key) {
    foreach ($line in ($text -split "`r?`n")) {
        if ($line.StartsWith("$key=")) { return $line.Substring($key.Length + 1) }
    }
    return $null
}

function Expect([bool]$cond, [string]$label, [string]$detail = '') {
    $tag = if ($cond) { 'PASS' } else { 'FAIL' }
    $pad = $label.PadRight(46)
    Write-Host "$pad $tag $detail"
    if (-not $cond) { $script:Failures += $label }
}

function Invoke-Tool([string]$exe, [string[]]$toolArgs, [string]$cwd) {
    $full = Join-Path $Bin $exe
    $out = & $full @toolArgs 2>&1 | ForEach-Object { $_.ToString() } | Out-String
    return @{ Exit = $LASTEXITCODE; Text = $out }
}

$required = @(
    'gguf_to_nqb_converter.exe',
    'nqb_source_f32_manifest.exe',
    'nqb_production_reopen.exe',
    'nqb_manifest_compare.exe'
)
foreach ($r in $required) {
    if (-not (Test-Path (Join-Path $Bin $r))) {
        Write-Host "MISSING_EXE=$r"
        Write-Host 'VERDICT=INVALID_NO_RESULT'
        exit 2
    }
}
if (-not (Test-Path $Gguf)) {
    Write-Host "MISSING_GGUF=$Gguf"
    Write-Host 'VERDICT=INVALID_NO_RESULT'
    exit 2
}

$EXPECT_TENSORS = 21
$EXPECT_ELEMENTS = 90432
$EXPECT_SIZE = 364840

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("nqbchain_" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$nqb = Join-Path $work 'selftest.nqb'
$srcManifest = Join-Path $work 'source.manifest'
$payManifest = Join-Path $work 'payload.manifest'
$nc = Join-Path $work 'nc'
New-Item -ItemType Directory -Path $nc -Force | Out-Null

Write-Host 'GATE=RAWRXD_NQB_CHAIN_SELFTEST_001'
Write-Host "WORK=$work"
Write-Host "GGUF=$Gguf"
Write-Host ''
Write-Host 'SCOPE=INSTRUMENT_WIRING_ONLY'
Write-Host 'NOT_CLAIMED=ANYTHING_ABOUT_THE_REAL_12.85GB_ARTIFACT'
Write-Host ''

# ---- 1. converter -----------------------------------------------------------
$r = Invoke-Tool 'gguf_to_nqb_converter.exe' @($Gguf, $nqb) $work
Expect ($r.Exit -eq 0) 'CONVERTER_VERDICT' "exit=$($r.Exit)"
Expect ((Get-Field $r.Text 'VERDICT') -eq 'PASS') 'CONVERTER_REPORTED_PASS'
Expect ((Get-Field $r.Text 'TRANSACTIONAL_WRITE') -eq '1') 'CONVERTER_TRANSACTIONAL'
Expect ((Get-Field $r.Text 'CODEC_REQUEST_APPLIED') -eq '1') 'CONVERTER_CODEC_REQUEST_APPLIED'
Expect ($null -ne (Get-Field $r.Text 'PROMOTED_TO')) 'CONVERTER_PROMOTED'
Expect ((Get-Field $r.Text 'HEADER_BITS_FIELD_RAW') -eq '3200') `
    'CONVERTER_DERIVED_BITS_PER_WEIGHT' ("raw=" + (Get-Field $r.Text 'HEADER_BITS_FIELD_RAW'))
Expect ((Get-Field $r.Text 'HEADER_PARAM_COUNT') -eq "$EXPECT_ELEMENTS") `
    'CONVERTER_PARAM_COUNT_FROM_CENSUS' ("value=" + (Get-Field $r.Text 'HEADER_PARAM_COUNT'))
Expect (Test-Path $nqb) 'ARTIFACT_PRESENT_AFTER_PROMOTE'
Expect (-not (Test-Path ($nqb + '.building'))) 'NO_BUILDING_FILE_AFTER_PROMOTE'

# ---- 2. payload side --------------------------------------------------------
$r = Invoke-Tool 'nqb_production_reopen.exe' @(
    $nqb,
    '--expect-tensors', "$EXPECT_TENSORS",
    '--expect-elements', "$EXPECT_ELEMENTS",
    '--expect-file-bytes', "$EXPECT_SIZE",
    '--f32-manifest', $payManifest,
    '--negative-controls', $nc
) $work
Expect ($r.Exit -eq 0) 'REOPEN_VERDICT' "exit=$($r.Exit)"
Expect ((Get-Field $r.Text 'ARTIFACT_VERDICT') -eq 'PASS') 'REOPEN_ARTIFACT_VERDICT'
Expect ((Get-Field $r.Text 'ARTIFACT_CHECKS_FAIL') -eq '0') 'REOPEN_NO_ARTIFACT_FAILURES'
Expect ($r.Text -match 'READER_F32_FAIL=0') 'REOPEN_PRODUCTION_F32_PATH_LOSSLESS'
Expect ((Get-Field $r.Text 'NEGATIVE_CONTROLS_HAVE_POWER') -eq '1') 'REOPEN_NEGATIVE_CONTROLS_HAVE_POWER'

# ---- 3. source side ---------------------------------------------------------
$r = Invoke-Tool 'nqb_source_f32_manifest.exe' @($Gguf, $srcManifest) $work
Expect ($r.Exit -eq 0) 'SOURCE_MANIFEST_VERDICT' "exit=$($r.Exit)"
Expect ((Get-Field $r.Text 'SOURCE_TENSORS') -eq "$EXPECT_TENSORS") `
    'SOURCE_TENSOR_COUNT' ("value=" + (Get-Field $r.Text 'SOURCE_TENSORS'))

# ---- 4. comparator ----------------------------------------------------------
$r = Invoke-Tool 'nqb_manifest_compare.exe' @($srcManifest, $payManifest, '--nc', $nc) $work
Expect ($r.Exit -eq 0) 'COMPARATOR_VERDICT' "exit=$($r.Exit)"
Expect ((Get-Field $r.Text 'GGUF_PRODUCTION_DEQUANT_TO_NQB_PAYLOAD_FIDELITY') -eq 'PASS') `
    'COMPARATOR_FIDELITY'
Expect ((Get-Field $r.Text 'NEGATIVE_CONTROL_STATUS') -eq 'PASS') 'COMPARATOR_CONTROLS_PASS'
Expect ((Get-Field $r.Text 'OVERALL_RUN_STATUS') -eq 'VALID_TARGET_PASS') `
    'COMPARATOR_RUN_STATUS' ("status=" + (Get-Field $r.Text 'OVERALL_RUN_STATUS'))
Expect ($r.Text -match "FNV1A64_MATCH=$EXPECT_TENSORS(\s|$)") 'COMPARATOR_FNV_ALL_MATCH'
# SHA256_MATCH is the LAST field on the line, so a trailing-space pattern would
# never match it. That produced a harness FAIL on a passing comparator -- the same
# class of defect as an instrument reporting FAIL on a passing target.
Expect ($r.Text -match "SHA256_MATCH=$EXPECT_TENSORS(\s|$)") 'COMPARATOR_SHA_ALL_MATCH'
Expect ($r.Text -match 'MANIFEST_ROOT_MATCH=1') 'COMPARATOR_MANIFEST_ROOT_MATCH'
Expect ($r.Text -match 'MISMATCHES=0') 'COMPARATOR_ZERO_MISMATCHES'
Expect ($r.Text -match 'CANONICAL_QUANT_DECODER_NUMERICAL_CORRECTNESS') 'COMPARATOR_CLAIM_BOUNDARY_STATED'

Write-Host ''
Write-Host "FAILURES=$($script:Failures.Count)"
foreach ($f in $script:Failures) { Write-Host "  FAILED=$f" }
Write-Host "VERDICT=$(if ($script:Failures.Count -eq 0) { 'PASS' } else { 'FAIL' })"

if ($Keep) {
    Write-Host "KEPT=$work"
} else {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
exit $(if ($script:Failures.Count -eq 0) { 0 } else { 1 })