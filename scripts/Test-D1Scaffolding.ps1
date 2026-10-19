# ============================================================================
# File: scripts/Test-D1Scaffolding.ps1
#
# The DEEP2_BATCHED_PREFILL_001 scaffolding, tested and checked.
#
# Two things, in one run, because they are the same question asked twice:
#
#   1. Does the scaffolding do what it says? The test is compiled from the
#      header the worktree actually has, not from a copy of it, so a test
#      that passes is a statement about this tree.
#
#   2. Is the commit pure? The worktree of this project is shared with
#      other work. The script reports what is modified and what is
#      untracked, and it says which of the untracked paths are build
#      output rather than source. A commit that carries the scaffolding and
#      nothing else can be evaluated on its own; a commit that carries
#      somebody else's work in flight cannot.
#
# Usage:
#   pwsh -File scripts\Test-D1Scaffolding.ps1
#   pwsh -File scripts\Test-D1Scaffolding.ps1 -NoBuild
#
# Exit code 0 when the test passes and the scaffolding is the only thing
# staged; 1 otherwise.
# ============================================================================

param(
    [string]$Vcpu = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools",
    [string]$TestSource = "tests\test_d1_batched_prefill.cpp",
    [string]$HeaderUnderTest = "src\deep2\BatchedPrefill.hpp",
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Log([string]$m) { Write-Host "[d1] $m" }

# ---------------------------------------------------------------------------
# 1. The test.
# ---------------------------------------------------------------------------
$buildDir = Join-Path $repo "build-d1-test"
if (-not $NoBuild) {
    if (-not (Test-Path -LiteralPath $HeaderUnderTest)) {
        throw "The header under test is not at $HeaderUnderTest"
    }
    if (-not (Test-Path -LiteralPath $TestSource)) {
        throw "The test source is not at $TestSource"
    }

    $vcvars = Join-Path $Vcpu "VC\Auxiliary\Build\vcvars64.bat"
    if (-not (Test-Path -LiteralPath $vcvars)) {
        throw "vcvars64.bat not found at $vcvars. Pass -Vcpu <VS path>."
    }
    if (-not (Test-Path -LiteralPath $buildDir)) {
        New-Item -ItemType Directory -Path $buildDir | Out-Null
    }

    $bat = Join-Path $buildDir "build.bat"
    @"
@echo off
call "$vcvars" >nul 2>&1
cd /d "$repo"
cl /nologo /EHsc /std:c++17 /W3 /O2 /I "$repo\src" /Fe:"$buildDir\test_d1_batched_prefill.exe" /Fo:"$buildDir\\" "$repo\$TestSource"
echo BUILD_EXITCODE=%ERRORLEVEL%
"@ | Out-File -FilePath $bat -Encoding ascii

    Log "building the test..."
    $out = & cmd /c $bat 2>&1 | Out-String
    Write-Host $out
    if ($out -notmatch "BUILD_EXITCODE=0") {
        throw "The test did not build. See the output above."
    }

    $exe = Join-Path $buildDir "test_d1_batched_prefill.exe"
    if (-not (Test-Path -LiteralPath $exe)) {
        throw "The test binary is not at $exe"
    }
    Log "running the test..."
    $testOut = & $exe 2>&1 | Out-String
    Write-Host $testOut
    $testExit = $LASTEXITCODE
    if ($testExit -ne 0) {
        throw "The D1 scaffolding test failed with exit code $testExit"
    }
    Log "the scaffolding test passed"
}
else {
    $exe = Join-Path $buildDir "test_d1_batched_prefill.exe"
    if (-not (Test-Path -LiteralPath $exe)) {
        throw "There is no built test at $exe and -NoBuild was given."
    }
    $testOut = & $exe 2>&1 | Out-String
    Write-Host $testOut
    if ($LASTEXITCODE -ne 0) { throw "The D1 scaffolding test failed" }
    Log "the scaffolding test passed"
}

# ---------------------------------------------------------------------------
# 2. The worktree.
# ---------------------------------------------------------------------------
Log ""
Log "worktree state:"

$staged = @(& git diff --cached --name-only 2>$null)
$modified = @(& git diff --name-only 2>$null)
$untracked = @(& git ls-files --others --exclude-standard 2>$null)

# The paths that are build output or a model file rather than source. They
# are not in the commit, and the point of listing them is that a reviewer
# should be able to see that the commit is not carrying them.
$contaminantPattern = '(^|/)(build[^/]*|out|bin|obj)/|\.gguf$|\.gguf\.pruned$|\.exe$|\.obj$|\.pdb$|\.log$'

$contaminants = @($untracked | Where-Object { $_ -match $contaminantPattern })
$sources = @($untracked | Where-Object { $_ -notmatch $contaminantPattern })

if ($staged.Count) { Log "  staged:"; $staged | ForEach-Object { Log "    $_" } }
if ($modified.Count) { Log "  modified, not staged:"; $modified | ForEach-Object { Log "    $_" } }
if ($sources.Count) { Log "  untracked source:"; $sources | ForEach-Object { Log "    $_" } }
if ($contaminants.Count) { Log "  untracked build output and model files (not source, not in the commit):"; $contaminants | ForEach-Object { Log "    $_" } }

# The scaffolding has to be in the commit, and the commit has to be the
# scaffolding.
$scaffolding = @("src/deep2/BatchedPrefill.hpp")
$missing = @($scaffolding | Where-Object { $staged -notcontains $_ })
$extra = @($staged | Where-Object { $_ -notlike "src/deep2/BatchedPrefill.hpp" -and
                                    $_ -notlike "tests/test_d1_batched_prefill.cpp" -and
                                    $_ -notlike "scripts/Test-D1Scaffolding.ps1" -and
                                    $_ -notlike ".gitignore" })

if ($missing.Count) {
    throw "The D1 scaffolding is not staged: $($missing -join ', ')"
}
if ($extra.Count) {
    throw "The commit carries more than the D1 scaffolding: $($extra -join ', ')"
}

Log ""
Log "the commit is the D1 scaffolding and nothing else"
Log "  staged      : $($staged -join ', ')"
Log "  not staged  : $($modified.Count) modified file(s) left for their owners"
Log "  contaminants: $($contaminants.Count) untracked build/model path(s), not in the commit"
exit 0
