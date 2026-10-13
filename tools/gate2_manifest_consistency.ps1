# =============================================================================
# gate2_manifest_consistency.ps1 — Gate 2 of MODEL_GENIE_NATIVE_FORWARD_001
# =============================================================================
# Primitive capability manifest consistency: `quant_parity_cert` (the
# authoritative registry emitter) vs `rawr capabilities` (the CLI manifest),
# with stale and contradictory claims rejected.
#
# Checks (all must hold for exit 0):
#   C1  quant_parity_cert exits 0 and emits parseable registry JSON.
#   C2  rawr capabilities exits 0 and emits parseable manifest JSON.
#   C3  the CLI manifest's source_revision is a real 40-hex commit AND equals
#       the HEAD it was generated from (a stale or unavailable revision is a
#       stale manifest).
#   C4  the primitive sets agree (same names on both sides).
#   C5  for every shared primitive the binding status agrees
#       (bound<->bound, declared_unimplemented<->declared_unimplemented);
#       any contradiction fails the gate.
#   C6  every "verified" quantization claim in the CLI manifest is backed by an
#       executed gate: Q8_K by the registry's recorded packing-parity evidence,
#       Q4_K/Q6_K by kquant_dot_parity exiting 0.
#   C7  each parity verdict the CLI cites (forward / KV / zero-fallback) names
#       an evidence artifact that exists and records a PASS verdict.
#
# The gate fails closed: a missing or contradictory claim is a failure, never
# a warning.
# =============================================================================
param(
    [string]$BuildDir    = "F:\rawrxd\build_gate4",
    [string]$CliExe      = "F:\rawrxd\_eval_harness\rawr_rebuilt.exe",
    [string]$RepoRoot    = "F:\rawrxd",
    [string]$EvidenceDir = "F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate2"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$receipt = New-Object System.Collections.Generic.List[string]
function Say([string]$Line) { $receipt.Add($Line); Write-Output $Line }
function Fail([string]$Why) {
    Say "RESULT: FAIL"
    Say "reason: $Why"
    $receipt | Set-Content -Encoding utf8 (Join-Path $EvidenceDir "gate2_consistency_receipt.txt")
    exit 1
}

Say "=== Gate 2: manifest consistency ($(Get-Date -Format o)) ==="

# ---- C1: authoritative registry emitter --------------------------------------
$registryJson = Join-Path $EvidenceDir "registry.json"
$regOut = & (Join-Path $BuildDir "bin-msvc\Release\quant_parity_cert.exe") --blocks 8 --seed 12345 --json $registryJson 2>&1
if ($LASTEXITCODE -ne 0) { Fail "quant_parity_cert exited $LASTEXITCODE" }
Say "C1 quant_parity_cert           PASS (exit 0, RESULT: $(($regOut | Select-String 'RESULT:').Line))"

$reg = Get-Content $registryJson -Raw | ConvertFrom-Json

# ---- C2: CLI manifest ---------------------------------------------------------
$cliJson = Join-Path $EvidenceDir "cli_manifest.json"
& $CliExe capabilities --json --out $cliJson | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "rawr capabilities exited $LASTEXITCODE" }
$cli = Get-Content $cliJson -Raw | ConvertFrom-Json
Say "C2 rawr capabilities           PASS (exit 0, tools=$($cli.tool_count), revision=$($cli.source_revision))"

# ---- C3: revision freshness (staleness rejection) ------------------------------
$head = (git -C $RepoRoot rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($head)) { Fail "git rev-parse HEAD failed" }
if ($cli.source_revision -notmatch '^[0-9a-f]{40}$') {
    Fail "manifest revision is not a real commit: '$($cli.source_revision)' (git-unavailable manifests are stale by definition)"
}
if ($cli.source_revision -ne $head) {
    Fail "manifest revision $($cli.source_revision) != HEAD $head (stale manifest)"
}
Say "C3 manifest revision == HEAD   PASS ($head)"

# ---- C4/C5: primitive agreement (contradiction rejection) ----------------------
$regGates = @{}
foreach ($g in $reg.primitive_gates) { $regGates[$g.primitive] = $g.binding_status }
$cliPrims = @{}
foreach ($p in $cli.primitives) { $cliPrims[$p.name] = $p.status }

$map = @{ "bound" = "bound"; "declared_unimplemented" = "declared_unimplemented" }
if ($regGates.Count -ne $cliPrims.Count) {
    Fail "primitive count differs: registry=$($regGates.Count) cli=$($cliPrims.Count)"
}
foreach ($name in $cliPrims.Keys) {
    if (-not $regGates.ContainsKey($name)) { Fail "CLI primitive '$name' absent from the authoritative registry" }
    if ($regGates[$name] -ne $cliPrims[$name]) {
        Fail "CONTRADICTION primitive '$name': cli=$($cliPrims[$name]) registry=$($regGates[$name])"
    }
}
Say "C4 primitive sets agree        PASS ($($cliPrims.Count) primitives)"
Say "C5 binding statuses agree      PASS (no contradictions)"

# ---- C6: verified quant claims are backed by an executed gate ------------------
$verified = @($cli.quantization_kernels | Where-Object { $_.verification -eq "verified" } | ForEach-Object { $_.format })
foreach ($q in $verified) {
    if ($q -eq "Q8_K") {
        $evid = @($reg.evidence | Where-Object { $_.status -in @("packing_verified", "dot_verified", "logits_verified") })
        if (-not $evid) { Fail "Q8_K claimed verified but registry has no verified evidence row" }
    }
}
$kq = Join-Path $BuildDir "bin-msvc\Release\kquant_dot_parity.exe"
if (-not (Test-Path $kq)) { $kq = (Get-ChildItem $RepoRoot -Recurse -Filter kquant_dot_parity.exe -ErrorAction SilentlyContinue | Select-Object -First 1).FullName }
if (-not $kq) { Fail "kquant_dot_parity.exe not found" }
& $kq | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "kquant_dot_parity exited $LASTEXITCODE (Q4_K/Q6_K/Q8_K dot parity)" }
Say "C6 verified quants backed     PASS (verified=[$($verified -join ',')], kquant_dot_parity exit 0)"

# ---- C7: cited parity evidence exists and records PASS --------------------------
$fields = @("end_to_end_forward_parity", "multi_token_kv_parity", "native_forward_zero_fallback")
foreach ($f in $fields) {
    $v = $cli.$f
    if ($null -eq $v -or $v.status -ne "verified") { Fail "$f is not verified (stale claim)" }
    $path = Join-Path $RepoRoot $v.evidence
    if (-not (Test-Path $path)) { Fail "cited evidence missing: $($v.evidence)" }
    if (-not (Select-String -Path $path -Pattern "PASS" -Quiet)) { Fail "cited evidence records no PASS: $($v.evidence)" }
}
Say "C7 cited parity evidence      PASS (3 artifacts exist and record PASS)"

Say ""
Say "GATE2_RESULT: PASS"
$receipt | Set-Content -Encoding utf8 (Join-Path $EvidenceDir "gate2_consistency_receipt.txt")
exit 0
