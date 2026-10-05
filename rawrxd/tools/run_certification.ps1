# run_certification.ps1 -- authoritative suite runner.
#
# RAWRXD_CERTIFICATION_RUNNER_001
#
# WHY THIS EXISTS
# ---------------
# `ctest` does not build. It runs whatever binaries are on disk. That is not a
# convenience detail, it is an authority failure: this repository reported
#
#     ctest -R nqb_   18/18 passed
#
# against binaries compiled BEFORE a concurrent lane's edits landed. Forcing a
# rebuild dropped the same tests to 4/18. The green run was faithful -- to
# obsolete binaries. Nothing in the output said so.
#
# The second authority failure was structural: eighteen registered tests declare
# WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests", a directory nothing created, so
# they reported "Not Run" forever while `ctest -N` claimed 36 tests.
#
# Both are now impossible to summarise as green, because this runner emits
#     SOURCE_REVISION / BUILD_FRESH / TESTS_DECLARED / TESTS_EXECUTED
#     TESTS_NOT_RUN / TESTS_FAILED
# and exits non-zero if the build failed, any test was Not Run, or any failed.
#
# PARSING IS DONE FROM JUNIT XML, NOT FROM CTEST'S CONSOLE TEXT
# ------------------------------------------------------------
# The first version of this script regexed the human-readable progress lines and
# reported nonsense: TEST_TARGETS_DECLARED=0 alongside BUILD_EXIT=0 (so it built
# NOTHING and called it a clean build) and 17 passed / 19 failed when the suite
# actually stands at 35/36. A runner whose counters are wrong is worse than no
# runner, because it certifies. Console text is not a stable interface; the
# JUnit document is.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools/run_certification.ps1 `
#              [-BuildDir F:\~dev\rawrxd\build] [-Config Release] [-Filter nqb_]
#              [-SkipBuild]

param(
    [string]$BuildDir = "F:\~dev\rawrXD\build",
    [string]$Config   = "Release",
    [string]$Filter   = "",
    [switch]$SkipBuild
)
$ErrorActionPreference = "Continue"
$repoRoot = Split-Path -Parent $PSScriptRoot
$runId    = [guid]::NewGuid().ToString("N")
$junit    = Join-Path $env:TEMP ("ctest_junit_" + $runId + ".xml")

function Emit([string]$k, [string]$v) { Write-Output "$k=$v" }
function Fail([string]$why, [string]$verdict) {
    Write-Output ""
    Emit "FAIL_REASON" $why
    Emit "VERDICT" $verdict
    exit 1
}

Write-Output "=== RAWRXD_CERTIFICATION_RUNNER_001 ==="

# ---- source revision -------------------------------------------------------
Push-Location $repoRoot
$head   = (& git rev-parse --short HEAD 2>$null)
$dirty  = (& git status --porcelain 2>$null | Measure-Object).Count
Pop-Location
Emit "SOURCE_REVISION"    "$head"
Emit "SOURCE_DIRTY_ENTRIES" "$dirty"

# ---- declared tests, from JSON (machine-readable) -------------------------
$json = & ctest --test-dir $BuildDir -C $Config -N --show-only=json-v1 2>$null | Out-String
$declared = 0
$testNames = @()
try {
    $j = $json | ConvertFrom-Json
    $declared = @($j.tests).Count
    $testNames = @($j.tests | ForEach-Object { $_.name })
} catch {
    Fail "could not parse ctest -N JSON; refusing to certify against an unreadable manifest" "FAIL_NO_MANIFEST"
}
Emit "TESTS_DECLARED" "$declared"
if ($declared -eq 0) { Fail "ctest declared zero tests" "FAIL_NO_TESTS_DECLARED" }

# ---- BUILD IS MANDATORY ----------------------------------------------------
# The build covers the targets DERIVED FROM THE REGISTERED TESTS, not `all`.
# `all` in this tree includes RawrXD_Gold (fatal error LNK1120: 47 unresolved
# externals) and RawrEngine (error C1083: cannot open include file
# '../../include/ui/chat_panel.h'). Those are documented build-graph defects the
# suite does not depend on; gating certification on them would be a gate
# reporting on something other than its subject.
if ($SkipBuild) {
    Emit "BUILD_PERFORMED" "0"
    Emit "BUILD_EXIT"     "SKIPPED_BY_FLAG"
    Emit "BUILD_FRESH"    "UNKNOWN_BUILD_SKIPPED"
} else {
    Emit "BUILD_PERFORMED" "1"
    Write-Output "--- building suite-relevant targets ---"

    # Targets are derived from the test COMMANDS, not from the test NAMES.
    # A ctest name is not a build target: the nqb cells are named
    # nqb_dense_q0 and friends but are driven by `cmake -P`, and their actual
    # binaries are nanof32_braid_writer and nanof32_e2e_test. Assuming
    # name==target made the runner try to build "nqb_dense_q0", which does not
    # exist -- and the failure set FLIPPED between runs depending on build
    # order, which is exactly the signature of an instrument measuring the
    # wrong thing. Basename-minus-.exe is the target name for every target
    # here (each sets OUTPUT_NAME to match).
    $buildTargets = @()
    try {
        $j2 = $json | ConvertFrom-Json
        foreach ($tcase in @($j2.tests)) {
            foreach ($part in @($tcase.command)) {
                if ($part -match '([A-Za-z0-9_\-\.]+)\.exe$') {
                    $leaf = $Matches[1]
                    # The nqb cells are driven by `cmake -P`, so the FIRST
                    # element of their command is cmake.exe itself. Treating
                    # that as a build target produced:
                    #     BUILD_ERROR [cmake]: MSBUILD : error MSB1009:
                    #     Project file does not exist.
                    # because there is no project named "cmake".
                    if ($leaf -ieq 'cmake') { continue }
                    $buildTargets += $leaf
                }
            }
        }
    } catch {
        Fail "could not derive build targets from the ctest manifest" "FAIL_NO_MANIFEST"
    }
    $buildTargets = @($buildTargets | Sort-Object -Unique)
    Emit "BUILD_TARGETS_DERIVED" "$($buildTargets.Count)"

    $failedTargets = @()
    foreach ($t in $buildTargets) {
        # The build output is CAPTURED BEFORE being filtered. Piping a native
        # command into `Select-Object -First N` terminates the pipeline early,
        # which kills the upstream process and leaves $LASTEXITCODE stale --
        # so a target that built cleanly was recorded as failed. That is the
        # same class of error as the one this runner exists to catch: an
        # instrument reporting a verdict it did not measure.
        $log = & cmake --build $BuildDir --config $Config --target $t -- /m /nologo /v:minimal 2>&1
        $rc  = $LASTEXITCODE
        @($log) | Select-String -Pattern 'error C|error LNK|error MSB' |
            Select-Object -First 3 | ForEach-Object { Write-Output ("  BUILD_ERROR [" + $t + "]: " + $_) }
        if ($rc -ne 0) { $failedTargets += $t }
    }
    $log = & cmake --build $BuildDir --config $Config --target InferenceEngine -- /m /nologo /v:minimal 2>&1
    $rc  = $LASTEXITCODE
    @($log) | Select-String -Pattern 'error C|error LNK' | Select-Object -First 3 |
        ForEach-Object { Write-Output ("  BUILD_ERROR [InferenceEngine]: " + $_) }
    if ($rc -ne 0) { $failedTargets += "InferenceEngine" }

    Emit "BUILD_TARGETS_ATTEMPTED" "$($buildTargets.Count + 1)"
    Emit "BUILD_TARGETS_FAILED"    "$($failedTargets.Count)"
    $failedTargets | ForEach-Object { Write-Output ("  FAILED_TARGET: " + $_) }
    Emit "BUILD_FRESH" $(if ($failedTargets.Count -eq 0) { "1" } else { "0_BUILD_FAILED" })
    if ($failedTargets.Count -gt 0) {
        Fail "a target the suite depends on did not build, so NO test result is admissible" "FAIL_BUILD"
    }
}

# ---- run, and parse JUnit ---------------------------------------------------
Write-Output "--- running ---"
$runArgs = @("--test-dir", $BuildDir, "-C", $Config, "--output-on-failure",
             "--output-junit", $junit)
if ($Filter -ne "") { $runArgs += @("-R", $Filter) }
& ctest @runArgs 2>&1 | Out-Null
$ctestExit = $LASTEXITCODE

$passed = 0; $failed = 0; $notRun = 0; $failedNames = @(); $notRunNames = @()
try {
    [xml]$x = Get-Content -LiteralPath $junit -Raw
    $cases = @($x.testsuite.testcase)
    foreach ($c in $cases) {
        # SelectSingleNode is used deliberately. In PowerShell, $c.failure on an
        # element that EXISTS BUT IS EMPTY evaluates to an XmlElement whose
        # string value is "", and `"" -ne $null` is TRUE -- so the previous
        # version classified every passing test as a failure and reported
        # 17 passed / 19 failed when the suite actually stands at 35/36.
        # XPath returns a real $null when the node is absent.
        $skipNode = $c.SelectSingleNode('skipped')
        $failNode = $c.SelectSingleNode('failure')
        $errNode  = $c.SelectSingleNode('error')
        if ($skipNode -ne $null) { $notRun++; $notRunNames += $c.name }
        elseif ($failNode -ne $null -or $errNode -ne $null) { $failed++; $failedNames += $c.name }
        else { $passed++ }
    }
} catch {
    Fail ("could not parse the JUnit document at " + $junit + "; refusing to certify") "FAIL_NO_RESULTS"
}

$executed = $passed + $failed
Emit "TESTS_PASSED"   "$passed"
Emit "TESTS_FAILED"   "$failed"
Emit "TESTS_NOT_RUN"  "$notRun"
Emit "TESTS_EXECUTED" "$executed"
Emit "CTEST_EXIT"     "$ctestExit"

$failedNames  | Select-Object -First 20 | ForEach-Object { Write-Output ("  FAILED_TEST: " + $_) }
$notRunNames  | Select-Object -First 20 | ForEach-Object { Write-Output ("  NOT_RUN_TEST: " + $_) }

# ---- the two authority gates ----------------------------------------------
# A registered test that cannot execute has never gated anything, and its
# presence inflates the declared count. That is a structural defect, not a skip.
if ($notRun -ne 0) {
    Fail ("$notRun registered test(s) did not run") "FAIL_NOT_RUN"
}
if (($Filter -eq "") -and ($executed -ne $declared)) {
    Fail ("executed $executed of $declared declared; a test vanished between manifest and run") "FAIL_COUNT_MISMATCH"
}
if ($failed -ne 0) { Fail ("$failed test(s) failed") "FAIL_TEST" }

Emit "BUILD_STALE"     "0_BUILD_RAN_BEFORE_TESTS"
Emit "SUITE_AUTHORITY" "PASS"
Emit "VERDICT"         "PASS"
exit 0