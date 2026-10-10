# ============================================================================
# File: scripts/certify_agent_reliability.ps1
#
# RAWRXD_AGENT_RELIABILITY_001 certification harness.
#
# Reproduces, from a clean build, the executable, the test log, the executable
# hash, and the source commit, then writes a verification manifest. Every value
# is captured from the actual run — nothing is hand-written.
#
# Usage:
#   pwsh -File scripts\certify_agent_reliability.ps1
#
# Outputs (under build-certification\):
#   agentic-resilience-tests.exe   the certified executable
#   certification.log             full build + test output
#   manifest.json                 hashes, commit, counters, timestamps
#   verify.csr / verify.sha256     reproducibility anchors
# ============================================================================

param(
    [string]$Vcpu = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools",
    [string]$CertId = "RAWRXD_AGENT_RELIABILITY_001",
    [switch]$SkipPush
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$vcvars = Join-Path $Vcpu "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path -LiteralPath $vcvars)) {
    throw "vcvars64.bat not found at $vcvars. Pass -Vcpu <VS path>."
}

$outDir = Join-Path $repo "build-certification"
if (Test-Path -LiteralPath $outDir) { Remove-Item -LiteralPath $outDir -Recurse -Force }
New-Item -ItemType Directory -Path $outDir | Out-Null

$log = Join-Path $outDir "certification.log"
Start-Transcript -Path $log -Force | Out-Null

function Log([string]$m) { Write-Host "[certify] $m" }

try {
    Log "=== $CertId certification run ==="

    # ------------------------------------------------------------------
    # 1. Capture source state
    # ------------------------------------------------------------------
    $commit = (& git rev-parse HEAD).Trim()
    $branch = (& git branch --show-current).Trim()

    # Only the files this certification covers count toward "dirty"; the repo
    # has thousands of pre-existing untracked artifacts that are out of scope
    # and must not be misread as affecting reproducibility.
    $scopeFiles = @(
        "src/agent/adaptive_retry.hpp",
        "src/agent/adaptive_retry.cpp",
        "src/agent/delegated_agents.hpp",
        "src/agent/delegated_agents.cpp",
        "src/agentic/conflict_resolution.hpp",
        "src/agentic/conflict_resolution.cpp",
        "tests/agentic_resilience_test.cpp",
        "CMakeLists.txt",
        ".github/workflows/resilience.yml",
        "scripts/certify_agent_reliability.ps1"
    )
    $dirtyInScope = @()
    foreach ($f in $scopeFiles) {
        $st = (& git status --porcelain -- $f 2>$null)
        if ($st) { $dirtyInScope += $f }
    }

    Log "source commit : $commit"
    Log "branch        : $branch"
    Log "in-scope dirty: $($dirtyInScope.Count) file(s)"
    if ($dirtyInScope.Count -gt 0) {
        $dirtyInScope | ForEach-Object { Log "   - $_" }
    }

    # ------------------------------------------------------------------
    # 2. Clean configure + build via CMake (same path CI uses)
    # ------------------------------------------------------------------
    $batch = @"
@echo off
call "$vcvars" >nul 2>&1
cd /d "$repo"
cmake -B build-certification -G "Visual Studio 17 2022" -A x64 -DRAWRXD_BUILD_TESTS=ON -DENABLE_VULKAN=OFF -DGGML_VULKAN=OFF -DUSE_ZLIB_FETCHCONTENT=OFF
echo CONFIG_EXITCODE=%ERRORLEVEL%
cmake --build build-certification --config Release --target agentic-resilience-tests
echo BUILD_EXITCODE=%ERRORLEVEL%
"@
    $batchPath = Join-Path $outDir "build.bat"
    $batch | Out-File -FilePath $batchPath -Encoding ascii

    Log "configuring + building..."
    $buildOut = & cmd /c $batchPath 2>&1 | Out-String
    Write-Host $buildOut
    if ($buildOut -notmatch "CONFIG_EXITCODE=0" -or $buildOut -notmatch "BUILD_EXITCODE=0") {
        throw "Build failed. See $log"
    }

    # ------------------------------------------------------------------
    # 3. Locate the executable
    # ------------------------------------------------------------------
    $exe = Get-ChildItem -Path (Join-Path $outDir "bin") -Filter "agentic-resilience-tests.exe" -Recurse |
           Select-Object -First 1
    if (-not $exe) {
        $exe = Get-ChildItem -Path $outDir -Filter "agentic-resilience-tests.exe" -Recurse |
               Select-Object -First 1
    }
    if (-not $exe) { throw "Executable not found after build" }
    Log "executable    : $($exe.FullName)"

    $hash = (Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash.ToLower()
    $size = $exe.Length
    Log "sha256        : $hash"
    Log "size          : $size bytes"

    # ------------------------------------------------------------------
    # 4. Run the tests
    # ------------------------------------------------------------------
    Log "running tests..."
    $testOut = & $exe.FullName 2>&1 | Out-String
    Write-Host $testOut
    $exitCode = $LASTEXITCODE
    Log "test exit code: $exitCode"

    if ($exitCode -ne 0) { throw "Tests failed (exit code $exitCode)" }

    # Parse the authoritative counters from the executable's own output.
    if ($testOut -match "RESULTS:\s*(\d+)\s+passed,\s*(\d+)\s+failed") {
        $passed = [int]$Matches[1]
        $failed = [int]$Matches[2]
    } else {
        throw "Could not parse test counters from output"
    }
    if ($failed -ne 0) { throw "$failed test(s) failed" }
    Log "counters      : passed=$passed failed=$failed"

    # ------------------------------------------------------------------
    # 5. Extract per-area evidence from the run output
    # ------------------------------------------------------------------
    $areas = [ordered]@{
        "retry_recovery"           = 'recovered on attempt \d+'
        "retry_exhaustion"         = 'gave up after \d+ attempts'
        "retry_non_retryable"      = 'non-retryable error returned after \d+ attempt'
        "circuit_breaker"          = 'breaker state after \d+ failures: open'
        "policy_serialization"      = 'round-trip preserved \d+ retryable'
        "conflict_detection"       = 'detected \d+ conflict'
        "three_way_merge"          = 'merged cleanly|combined both element types'
        "cancellation_propagates"  = 'cancel token observed by worker: yes'
        "fail_closed_unwired"      = 'no work function configured'
        "concurrent_delegation"    = '\d+/12 concurrent tasks succeeded'
    }

    $evidence = [ordered]@{}
    foreach ($k in $areas.Keys) {
        $pattern = $areas[$k]
        $match = [regex]::Match($testOut, $pattern)
        $evidence[$k] = [ordered]@{
            verified = $match.Success
            detail   = if ($match.Success) { $match.Value.Trim() } else { "NOT FOUND IN OUTPUT" }
        }
        # A certification must not claim an area that the output does not prove.
        if (-not $match.Success) {
            throw "Certification failed: no evidence for '$k' (pattern: $pattern)"
        }
    }

    # ------------------------------------------------------------------
    # 6. Write the manifest (facts only, all machine-captured)
    # ------------------------------------------------------------------
    $manifest = [ordered]@{
        certification_id = $CertId
        generated_utc    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        environment      = [ordered]@{
            os            = [System.Environment]::OSVersion.VersionString
            architecture  = $env:PROCESSOR_ARCHITECTURE
            generator     = "Visual Studio 17 2022 / x64 / Release"
            compiler     = "MSVC (from VS BuildTools)"
        }
        source = [ordered]@{
            commit = $commit
            branch = $branch
            dirty_in_scope = $dirtyInScope
            note = "Only files covered by this certification are checked; the workspace contains many pre-existing untracked artifacts outside this scope."
        }
        artifact = [ordered]@{
            name        = "agentic-resilience-tests.exe"
            sha256      = $hash
            size_bytes  = $size
            path        = $exe.FullName.Replace("$repo\","").Replace("\","/")
        }
        results = [ordered]@{
            tests_passed = $passed
            tests_failed = $failed
            exit_code    = $exitCode
        }
        evidence = $evidence
        reproduction = @(
            "pwsh -File scripts\certify_agent_reliability.ps1"
            "cmake -B build-certification -G `"Visual Studio 17 2022`" -A x64 -DRAWRXD_BUILD_TESTS=ON -DENABLE_VULKAN=OFF -DGGML_VULKAN=OFF -DUSE_ZLIB_FETCHCONTENT=OFF"
            "cmake --build build-certification --config Release --target agentic-resilience-tests"
            "build-certification\bin\Release\agentic-resilience-tests.exe"
        )
    }

    $manifestPath = Join-Path $outDir "manifest.json"
    ($manifest | ConvertTo-Json -Depth 8) | Out-File -FilePath $manifestPath -Encoding utf8
    Log "manifest      : $manifestPath"

    # Reproducibility anchors
    "$hash  agentic-resilience-tests.exe" | Out-File -FilePath (Join-Path $outDir "verify.sha256") -Encoding ascii

    # Preserve the run log inside the repo so the evidence survives the build dir.
    $certDir = Join-Path $repo "certification"
    if (-not (Test-Path -LiteralPath $certDir)) {
        New-Item -ItemType Directory -Path $certDir | Out-Null
    }
    Stop-Transcript | Out-Null
    Copy-Item -LiteralPath $log -Destination (Join-Path $certDir "$CertId.log") -Force
    Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $certDir "$CertId.manifest.json") -Force
    Start-Transcript -Path $log -Append | Out-Null
    Log "preserved     : certification\$CertId.log, certification\$CertId.manifest.json"

    Log "=== CERTIFICATION PASSED: $CertId ==="
    Log "  passed=$passed failed=$failed sha256=$hash commit=$commit"
}
finally {
    Stop-Transcript | Out-Null
    # Keep the raw output alongside the transcript.
    Copy-Item -LiteralPath $log -Destination (Join-Path $outDir "certification.log") -Force -ErrorAction SilentlyContinue
}
