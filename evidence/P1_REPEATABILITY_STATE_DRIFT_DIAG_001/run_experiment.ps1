# P1_REPEATABILITY_STATE_DRIFT_DIAG_001 — A/B/D/E orchestrator
$ErrorActionPreference = "Stop"
$exe = "F:\~dev\rawrxd\build-p1-speedup\bin\p1_repeatability_state_drift_diag_001.exe"
$model = "F:\~dev\tinyllama_fresh.gguf"
$ev = "F:\~dev\rawrxd\evidence\P1_REPEATABILITY_STATE_DRIFT_DIAG_001"
$ws = Join-Path $ev "profiles_workspace"
$pristine = Join-Path $ev "profiles_pristine"
$exp = Join-Path $ev "EXPERIMENT.txt"

New-Item -ItemType Directory -Force $ev, $pristine | Out-Null
if (Test-Path $ws) { Remove-Item $ws -Recurse -Force }
New-Item -ItemType Directory -Force $ws | Out-Null
"" | Set-Content $exp

function Invoke-Phase($phase) {
    $out = Join-Path $ev "phase_$phase.txt"
    if (Test-Path $out) { Remove-Item $out -Force }
    Write-Host "=== PHASE $phase ==="
    Push-Location "F:\~dev\rawrxd"
    cmd /c "`"$exe`" --phase $phase --profiles-dir `"$ws`" --model `"$model`" --out `"$out`" > `"$out.log`" 2>&1"
    Pop-Location
    Get-Content $out
    Add-Content $exp "===== PHASE $phase ====="
    Get-Content $out | Add-Content $exp
}

# A: pristine (empty workspace)
Invoke-Phase "A"

# B: SESSION_01 workload → writes profile into workspace
Invoke-Phase "B"

# Capture profile after B
$profFiles = Get-ChildItem $ws -Filter "*.yaml" -ErrorAction SilentlyContinue
Add-Content $exp "PROFILE_FILES_AFTER_B=$($profFiles.Count)"
foreach ($f in $profFiles) {
    $h = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
    Add-Content $exp "PROFILE=$($f.Name) SHA=$h SIZE=$($f.Length)"
}

# D: fresh process, retained profile (same workspace)
Invoke-Phase "D"

# E: restore pristine (empty) workspace
Remove-Item $ws -Recurse -Force
New-Item -ItemType Directory -Force $ws | Out-Null
Invoke-Phase "E"

# Also record production profile from repeatability sessions (read-only)
$prodProf = "F:\~dev\rawrxd\profiles\g0_gpu0_12884901888_ram_42949672960__name_tinyllama_fresh.gguf.yaml"
if (Test-Path $prodProf) {
    $ph = (Get-FileHash $prodProf -Algorithm SHA256).Hash
    Add-Content $exp "PRODUCTION_PROFILE_PATH=$prodProf"
    Add-Content $exp "PRODUCTION_PROFILE_SHA=$ph"
    Add-Content $exp "PRODUCTION_PROFILE_RUNS=$(Select-String -Path $prodProf -Pattern 'runs:' | Select-Object -First 1)"
}

Write-Host "=== EXPERIMENT COMPLETE ==="
Get-Content $exp
