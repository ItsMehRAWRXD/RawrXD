# Native RawrXD REAP/GPU certification preflight. Read-only, no dependencies.
# Usage: pwsh -File scripts/reap_gpu_preflight.ps1 -BuildDir build_msvc
param([string]$BuildDir = "build_msvc", [switch]$Strict)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$checks = [System.Collections.Generic.List[object]]::new()
function Check([string]$Id, [string]$Name, [bool]$Pass, [string]$Detail) {
    $checks.Add([pscustomobject]@{ id=$Id; name=$Name; pass=$Pass; detail=$Detail })
}
$paths = @(
    @("P01","Vulkan adapter","src/deep2/vulkan_compute_engine_adapter.cpp"),
    @("P02","Residency cache","src/deep2/TensorResidencyCache.hpp"),
    @("P03","QGEMV shader","src/deep2/shaders/deep2_qgemv.comp"),
    @("P04","Deep2 engine","src/deep2/Deep2Engine.cpp"),
    @("P05","Native CLI","src/rawr_cli.cpp"),
    @("P06","REAP writer","src/deep2/ReapWriter.cpp"),
    @("P07","REAP writer interface","src/deep2/ReapWriter.hpp"),
    @("P08","REAP CLI","src/reap_cli.cpp"),
    @("P09","REAP regression tests","tests/test_reap_cli_contract.py"),
    @("P10","CMake project","CMakeLists.txt")
)
foreach ($item in $paths) {
    $file = Join-Path $root $item[2]
    Check $item[0] $item[1] (Test-Path -LiteralPath $file -PathType Leaf) $item[2]
}
$shader = Join-Path $root "src/deep2/shaders/deep2_qgemv.comp"
$shaderText = if (Test-Path $shader) { Get-Content -Raw -LiteralPath $shader } else { "" }
Check "P11" "Q5_0 shader dispatch" ($shaderText -match 'pc\.type\s*==\s*6u') "Type 6 branch required; source presence alone does not prove parity"
$exeCandidates = @(
    (Join-Path $root "$BuildDir/bin/rawr-reap.exe"),
    (Join-Path $root "$BuildDir/rawr-reap.exe"),
    (Join-Path $root "$BuildDir/bin/Release/rawr-reap.exe"),
    (Join-Path $root "$BuildDir/Release/rawr-reap.exe")
)
$exe = $exeCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
Check "P12" "Built REAP executable" ([bool]$exe) ($(if ($exe) {$exe} else {"not found"}))
$python = Get-Command python -ErrorAction SilentlyContinue
Check "P13" "Python regression runner" ([bool]$python) ($(if ($python) {$python.Source} else {"not found"}))
$glslang = Get-Command glslangValidator -ErrorAction SilentlyContinue
Check "P14" "Shader validator" ([bool]$glslang) ($(if ($glslang) {$glslang.Source} else {"not found"}))
$ctest = Get-Command ctest -ErrorAction SilentlyContinue
Check "P15" "CTest runner" ([bool]$ctest) ($(if ($ctest) {$ctest.Source} else {"not found"}))
$failed = @($checks | Where-Object { -not $_.pass })
$receipt = [pscustomobject]@{
    schema = "RAWRXD_REAP_GPU_PREFLIGHT_001"
    root = $root
    checked = $checks.Count
    passed = $checks.Count - $failed.Count
    failed = $failed.Count
    checks = $checks
    production_ready = $false
    note = "Preflight checks only; GPU memory, numerical parity, MLA certification and REAP pruning remain unverified."
}
$receipt | ConvertTo-Json -Depth 6
if ($Strict -and $failed.Count -gt 0) { exit 4 }
