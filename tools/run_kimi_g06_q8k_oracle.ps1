# G06 Q6_K×Q8_K oracle harness runner (fail-closed diagnostic).
# Does NOT modify official 25-gate ledger. PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0.
# Leaves KIMI_LAYER39_FIRST_FAIL_001 and KIMI_LAYER39_SINGLE_002 pristine.

param(
    [string]$CaptureDir = "F:\rawrxd\evidence\KIMI_LAYER39_SINGLE_002",
    [string]$ManifestName = "k2_l39_e108_s0.manifest.txt",
    [string]$EvidenceRoot = "F:\rawrxd\evidence",
    [double]$PrimaryMaxAbs = 1e-6
)

$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outName = "KIMI_G06_Q8K_ORACLE_HARNESS_001_$stamp"
$outDir = Join-Path $EvidenceRoot $outName

if (Test-Path $outDir) {
    Write-Error "Refusing to reuse existing evidence dir: $outDir"
    exit 2
}
New-Item -ItemType Directory -Path $outDir | Out-Null

$law = @"
GATE=KIMI_G06_Q8K_ORACLE_HARNESS_001
ASOF=$stamp
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
OFFICIAL_LEDGER=UNCHANGED
NOT_RUN!=PASS
PRIMARY=gpu_vs_q6k_q8k_oracle band_max_abs=$PrimaryMaxAbs
SECONDARY=gpu_vs_fp32_scalar contract_delta_telemetry
SOURCE_CAPTURE=$CaptureDir\$ManifestName
ANCHORS_PRISTINE=KIMI_LAYER39_FIRST_FAIL_001;KIMI_LAYER39_SINGLE_002
"@
Set-Content -Path (Join-Path $outDir "LAW.txt") -Value $law -Encoding utf8

$manifest = Join-Path $CaptureDir $ManifestName
if (-not (Test-Path $manifest)) {
    Write-Error "Missing sealed manifest: $manifest"
    exit 3
}

$pyCmd = $null
foreach ($c in @("py", "python", "python3")) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd) { $pyCmd = $cmd; break }
}
if (-not $pyCmd) {
    Write-Error "No Python interpreter found (py/python/python3)"
    exit 4
}

$harness = Join-Path $PSScriptRoot "k2_g06_q8k_oracle_harness.py"
Write-Host "[*] OUT_DIR=$outDir"
Write-Host "[*] PRIMARY_MAX_ABS=$PrimaryMaxAbs"
Write-Host "[*] PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0"

if ($pyCmd.Name -eq "py.exe" -or $pyCmd.Name -eq "py") {
    & $pyCmd.Source -3 $harness --manifest $manifest --out-dir $outDir --primary-max-abs $PrimaryMaxAbs
} else {
    & $pyCmd.Source $harness --manifest $manifest --out-dir $outDir --primary-max-abs $PrimaryMaxAbs
}
$code = $LASTEXITCODE

Set-Content -Path (Join-Path $outDir "OUT_DIR.txt") -Value $outDir -Encoding utf8
Write-Host "[*] harness_exit=$code"
Write-Host "[*] evidence=$outDir"
exit $code
