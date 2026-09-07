# RKC source-contract smoke (no MSVC required)
# Verifies first-slice wiring before binary rkc_smoke is available.

$ErrorActionPreference = "Stop"
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not (Test-Path "$root\src\rkc\RKCTypes.hpp")) {
    $root = "g:\~dev\rawrxd"
}

$fails = @()

function Assert-FileContains($path, $pattern, $label) {
    $full = Join-Path $root $path
    if (-not (Test-Path $full)) { $script:fails += "MISSING $path"; return }
    $t = Get-Content -Raw $full
    if ($t -notmatch $pattern) { $script:fails += "FAIL $label ($path)" }
    else { Write-Host "OK $label" }
}

Assert-FileContains "src\rkc\RKCValidator.cpp" "SYNTHETIC_TO_REAL_FORBIDDEN" "validator rejects SYNTHETIC→REAL"
Assert-FileContains "src\win32app\Win32IDE_CommandSurface.cpp" "CompileQueryToProof" "ScreenPilot uses RKC"
Assert-FileContains "src\win32app\Win32IDE_CommandSurface.cpp" "RKCSession" "RKCSession included"
$cs = Get-Content -Raw (Join-Path $root "src\win32app\Win32IDE_CommandSurface.cpp")
if ($cs -match "assembleCommandInferenceContext[\s\S]{0,2500}## Open:") {
    $fails += "FAIL assemble still stuffs ## Open: tabs"
} else {
    Write-Host "OK assemble no longer stuffs open tabs"
}

Assert-FileContains "src\rkc\RKCRecipes.cpp" "model_complete" "recipe model_complete"
Assert-FileContains "src\rkc\RKCRecipes.cpp" "local_generation_proven" "recipe local_generation_proven"
Assert-FileContains "src\rkc\RKCRecipes.cpp" "gpu_fit" "recipe gpu_fit"
Assert-FileContains "src\rkc\RKCCompiler.cpp" "model_executable_locally" "local-exec goal"
Assert-FileContains "CMakeLists.txt" "src/rkc/RKC_C_ABI.cpp" "CMake links RKC"
Assert-FileContains "CMakeLists.txt" "rkc_smoke" "CMake rkc_smoke target"

# Expected emit shape sample (decision state, not RAG)
$sample = @"
[GOAL]
model_executable_locally

[TASK]
Can Deep2 execute this model entirely locally?

[KNOWN]
FACT compute_backend_exists  REAL  1
FACT live_generation_path_exists  REAL  1
FACT no_remote_dependency  REAL  1

[MISSING]
NEED all_required_shards_exist  UNKNOWN

[NEGATIVE]
(none)

[CONSTRAINT]
- SYNTHETIC must not become REAL.

[INSTRUCTION]
Answer from KNOWN/NEGATIVE only. Resolve MISSING via observe/derive.
Do not invent REAL facts. SYNTHETIC cannot become REAL.
"@

$ev = Join-Path $root "evidence\RKC_FIRST_SLICE_001"
New-Item -ItemType Directory -Force -Path $ev | Out-Null
Set-Content -Path (Join-Path $ev "EXPECTED_PROOF_STATE.txt") -Value $sample -Encoding utf8
Set-Content -Path (Join-Path $ev "GATE_CONTRACT.txt") -Value @"
RKC_FIRST_SLICE_001
PRIMARY_PROMPT=proof_state_not_tab_stuffing
SYNTHETIC_TO_REAL=FORBIDDEN
HOOK=Win32IDE::assembleCommandInferenceContext
RECIPES=model_complete,local_generation_proven,gpu_fit
BINARY_SMOKE=rkc_smoke (link InferenceEngine when MSVC available)
"@ -Encoding utf8

if ($fails.Count -gt 0) {
    Write-Host "RKC_SOURCE_SMOKE=FAIL"
    $fails | ForEach-Object { Write-Host $_ }
    exit 1
}
Write-Host "RKC_SOURCE_SMOKE=PASS"
exit 0
