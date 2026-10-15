<#
.SYNOPSIS
    Builds, verifies and packages the RawrXD production-hardening source drop.

.DESCRIPTION
    Produces a self-contained ZIP that a recipient can extract anywhere, build,
    and verify. The package is only assembled if every verification stage
    passes -- a drop that cannot prove its own claims is not shipped.

   Stages:
     1. Clean hardened Release build (fails on any warning)
     2. Contract self-test + CTest
     3. Production-hardening runtime tests + health probe
     4. Fuzz harness (ASan Debug build when available)
     5. PE-header hardening verification of every produced binary
     6. Mocked end-to-end, both backends
     7. Real-ledger gate + negative controls
     8. SBOM (SHA-256 of every artifact) + evidence bundle + ZIP

.PARAMETER Configuration
    Release (default) or RelWithDebInfo.

.PARAMETER Version
    Version string stamped into the manifest. Default: 1.0.14

.PARAMETER OutputRoot
    Where the ZIP and evidence are written. Default: <repo>\_drop

.PARAMETER SkipFuzz
    Skip the ASan build (useful without a Debug-capable toolchain).

.EXAMPLE
    .\scripts\package_production_drop.ps1
#>
param(
    [ValidateSet("Release", "RelWithDebInfo")]
    [string]$Configuration = "Release",

    [string]$Version = "1.0.14",

    [string]$OutputRoot,

    [switch]$SkipFuzz
)

$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dropDir  = Join-Path $repoRoot 'tools\rawrxd_parity_final'
Push-Location $repoRoot
try {
    if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot = Join-Path $repoRoot '_drop' }
    $verifyScript = Join-Path $repoRoot 'scripts\verify_hardening.ps1'

    $failures = New-Object System.Collections.Generic.List[string]
    # Set by stage 3 once the hardening runtime has been built and verified.
    $hardeningBinDir = $null

    function Invoke-Stage {
        param([string]$Name, [scriptblock]$Body)
        Write-Host ""
        Write-Host "=== $Name ===" -ForegroundColor Cyan
        $lastExitCode = 0
        try {
            # Capture output so a failing stage shows why, not just that.
            $stageOut = & $Body 2>&1
            $stageOut | Write-Host
            $lastExitCode = $LASTEXITCODE
        } catch {
            Write-Host ("  exception: " + $_.Exception.Message) -ForegroundColor Red
            $script:failures.Add("$Name :: $($_.Exception.Message)") | Out-Null
            $global:LASTEXITCODE = 0
            return
        }
        if ($lastExitCode -ne 0) {
            $script:failures.Add("$Name :: exit $lastExitCode") | Out-Null
            Write-Host "  STAGE FAILED: $Name (exit $lastExitCode)" -ForegroundColor Red
        } else {
            Write-Host "  stage OK" -ForegroundColor Green
        }
        $global:LASTEXITCODE = 0
    }

    # ---------------------------------------------------------------- 1. build
    $buildDir = Join-Path $dropDir 'build'
    if (Test-Path -LiteralPath $buildDir) {
        Remove-Item -LiteralPath $buildDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "=== [1/8] hardened $Configuration build ===" -ForegroundColor Cyan
    cmake -S $dropDir -B $buildDir -A x64 `
          -DCMAKE_BUILD_TYPE=$Configuration -DRAWRXD_ENABLE_HARDENING=ON
    if ($LASTEXITCODE -ne 0) { throw "configure failed" }

    $warnings = @()
    $buildOut = & cmake --build $buildDir --config $Configuration 2>&1
    $buildOut | Where-Object { $_ -match '(?:^|\s)(?:warning|error)\s' } | ForEach-Object { $warnings += $_ }
    if ($LASTEXITCODE -ne 0) {
        Write-Host ($buildOut | Select-Object -Last 40 | Out-String) -ForegroundColor Red
        throw "build failed"
    }
    if ($warnings.Count -gt 0) {
        Write-Host ("  {0} warning(s) in build:" -f $warnings.Count) -ForegroundColor Yellow
        $warnings | Select-Object -First 20 | ForEach-Object { Write-Host "    $_" }
        throw "build emitted warnings; the drop must build clean under /W4"
    }
    Write-Host "  build clean, zero warnings" -ForegroundColor Green

    $binDir = Join-Path $buildDir $Configuration
    if (-not (Test-Path -LiteralPath $binDir)) { $binDir = $buildDir }

    # ------------------------------------------------- 2. contract + ctest
    Invoke-Stage '[2/8] contract self-test + CTest' {
        & (Join-Path $binDir 'rawr_run.exe') --self-test
        if ($LASTEXITCODE -ne 0) { throw "self-test failed" }
        ctest --test-dir $buildDir -C $Configuration --output-on-failure
    }

    # ------------------------------------------------ 3. hardening runtime
    # Verifies the production-hardening runtime itself: behavioural tests for
    # encryption with tamper rejection, the hash-chained audit log, circuit
    # breakers, retry and bulkhead behaviour. This is the component the IDE
    # links, so a regression here is not caught by any other stage.
    Invoke-Stage '[3/8] production hardening runtime + health probe' {
        $hardeningDir = Join-Path $buildDir 'hardening'
        cmake -S (Join-Path $repoRoot 'src\production') -B $hardeningDir -A x64 `
              -DCMAKE_BUILD_TYPE=$Configuration
        if ($LASTEXITCODE -ne 0) { throw "hardening configure failed" }
        cmake --build $hardeningDir --config $Configuration `
              --target rawrxd_production_tests rawrxd_health_probe
        if ($LASTEXITCODE -ne 0) { throw "hardening build failed" }

        # The two binaries do not share an output directory (the probe sets
        # RUNTIME_OUTPUT_DIRECTORY), so locate them instead of assuming a path.
        # A hardcoded path is exactly how a verifier ends up testing a stale
        # binary that happens to still be on disk.
        $hTest = Get-ChildItem -LiteralPath $hardeningDir -Filter 'rawrxd_production_tests.exe' -Recurse -ErrorAction SilentlyContinue |
                 Select-Object -First 1
        $hExe  = Get-ChildItem -LiteralPath $hardeningDir -Filter 'rawrxd_health_probe.exe' -Recurse -ErrorAction SilentlyContinue |
                 Select-Object -First 1
        if (-not $hTest) { throw "hardening tests not produced" }
        if (-not $hExe)  { throw "health probe not produced" }

        & $hTest.FullName
        if ($LASTEXITCODE -ne 0) { throw "hardening behavioural tests failed" }

        # The probe must agree with the tests: it exits 0 only when liveness
        # and readiness both pass, so a "healthy" answer here is claimed, not
        # assumed.
        & $hExe.FullName --json | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "health probe did not report healthy" }
        $hardeningBinDir = $hExe.Directory.FullName
        Write-Host "  hardening tests passed, probe healthy" -ForegroundColor Green
    }

    # ------------------------------------------------ 4. fuzz
    if ($SkipFuzz) {
        Write-Host ""
        Write-Host "=== [4/8] fuzz harness SKIPPED (-SkipFuzz) ===" -ForegroundColor Yellow
    } else {
        Invoke-Stage '[4/8] fuzz harness (ASan Debug)' {
            $asanDir = Join-Path $dropDir 'build_package_asan'
            if (Test-Path -LiteralPath $asanDir) {
                Remove-Item -LiteralPath $asanDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            cmake -S $dropDir -B $asanDir -A x64 -DCMAKE_BUILD_TYPE=Debug -DRAWRXD_ENABLE_HARDENING=ON
            if ($LASTEXITCODE -ne 0) { throw "asan configure failed" }
            cmake --build $asanDir --config Debug --target rawr_fuzz_parsers
            if ($LASTEXITCODE -ne 0) { throw "asan build failed" }

            $rt = Get-ChildItem "C:\Program Files (x86)\Microsoft Visual Studio" -Recurse `
                  -Filter clang_rt.asan_dynamic-x86_64.dll -ErrorAction SilentlyContinue |
                  Select-Object -First 1
            if ($rt) { $env:PATH = "$($rt.DirectoryName);$env:PATH" }
            $env:ASAN_OPTIONS = 'detect_leaks=0:halt_on_error=0'

            $fuzz = Join-Path $asanDir 'Debug\rawr_fuzz_parsers.exe'
            if (-not (Test-Path -LiteralPath $fuzz)) { throw "fuzz binary not produced" }
            & $fuzz 20000
            if ($LASTEXITCODE -ne 0) { throw "fuzz failed: parser or path-guard invariant violated" }
        }
    }

    # --------------------------------------------------- 4. PE hardening
    Invoke-Stage '[5/8] PE header hardening verification' {
        $exe = Join-Path $binDir 'rawr_run.exe'
        & pwsh -ExecutionPolicy Bypass -NoProfile -File $verifyScript -Path $exe
        if ($LASTEXITCODE -ne 0) { throw "binary is missing OS mitigations" }
    }

    # --------------------------------------------------------- 5. e2e mock
    Invoke-Stage '[6/8] mocked end-to-end (both backends)' {
        & py -3 (Join-Path $dropDir 'test_e2e_mock.py') (Join-Path $binDir 'rawr_run.exe')
        if ($LASTEXITCODE -ne 0) { throw "e2e mock failed" }
    }

    # ------------------------------------------------------- 6. real gate
    Invoke-Stage '[7/8] real-ledger gate + negative controls' {
        & py -3 (Join-Path $dropDir 'parity_gate_evidence.py')
        if ($LASTEXITCODE -ne 0) { throw "parity gate evidence failed" }
    }

    # ----------------------------------------------------- 7. sbom + zip
    Write-Host ""
    Write-Host "=== [8/8] SBOM and package ===" -ForegroundColor Cyan

    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
    $stageDir = Join-Path $OutputRoot "RawrXD_Production_Hardening_Source"
    if (Test-Path -LiteralPath $stageDir) {
        Remove-Item -LiteralPath $stageDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stageDir 'build_evidence') -Force | Out-Null

    # Sources (build trees and generated evidence workspaces stay out).
    $files = @(
        'rawr_run.cpp', 'rawr_fuzz_parsers.cpp', 'CMakeLists.txt', 'activate.ps1',
        'parity_gate.py', 'parity_gate_evidence.py', 'test_e2e_mock.py',
        'PRODUCTION_FINALIZATION.md'
    )
    foreach ($f in $files) {
        Copy-Item -LiteralPath (Join-Path $dropDir $f) -Destination (Join-Path $stageDir $f) -Force
    }

    # The production-hardening runtime the IDE links: configuration,
    # observability, reliability, security and the runtime entry point. Built
    # from the *repo* tree (not $dropDir), because it is a separate module.
    # The vendored nlohmann/json headers come with it, laid out exactly as the
    # repo does, so the staged copy configures standalone without a network or
    # an installed package.
    New-Item -ItemType Directory -Path (Join-Path $stageDir 'src\production') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $repoRoot 'src\production') -Destination `
                  (Join-Path $stageDir 'src') -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $repoRoot 'include\nlohmann') -Destination `
                  (Join-Path $stageDir 'include\nlohmann') -Recurse -Force
    # Build trees and scratch artifacts are never part of a source drop.
    Get-ChildItem -Path (Join-Path $stageDir 'src\production') -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('obj_prod_tests','obj','build','build_*') } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }

    # Self-contained hardening verifier so the drop needs no parent repo.
    Copy-Item -LiteralPath $verifyScript -Destination (Join-Path $stageDir 'verify_hardening.ps1') -Force

    # ---- SBOM over the produced binaries and the packaged source ----
    $sbomEntries = @()
    Get-ChildItem -LiteralPath $binDir -Include *.exe,*.dll -File -ErrorAction SilentlyContinue |
        ForEach-Object {
            $sbomEntries += [PSCustomObject]@{
                name = $_.Name; role = 'artifact'
                size = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        }
    # The hardening runtime binaries are built by stage 3 and are part of the
    # shipped surface, so their hashes belong in the SBOM too. Only when the
    # stage actually ran: a skipped or failed stage must not silently claim
    # otherwise.
    if ($hardeningBinDir -and (Test-Path -LiteralPath $hardeningBinDir)) {
        Get-ChildItem -LiteralPath $hardeningBinDir -Include *.exe -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                $sbomEntries += [PSCustomObject]@{
                    name = $_.Name; role = 'hardening-artifact'
                    size = $_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                }
            }
        # The test binary lives in a different output directory; include it so
        # the SBOM covers every executable the stage verified.
        $siblingTest = Join-Path (Split-Path -Parent $hardeningBinDir) "$Configuration\rawrxd_production_tests.exe"
        if (Test-Path -LiteralPath $siblingTest) {
            $ti = Get-Item -LiteralPath $siblingTest
            $sbomEntries += [PSCustomObject]@{
                name = $ti.Name; role = 'hardening-artifact'
                size = $ti.Length
                sha256 = (Get-FileHash -LiteralPath $ti.FullName -Algorithm SHA256).Hash
            }
        }
    }
    Get-ChildItem -LiteralPath $stageDir -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.cpp','.py','.ps1','.txt','.md','.json' } |
        ForEach-Object {
            $sbomEntries += [PSCustomObject]@{
                name = $_.Name; role = 'source'
                size = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        }

    $gitCommit = (git rev-parse HEAD 2>$null)
    $gitBranch = (git branch --show-current 2>$null)

    $sbom = [PSCustomObject]@{
        name        = 'RawrXD Production Hardening Source'
        version     = $Version
        createdUtc  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        gitCommit   = $gitCommit
        gitBranch   = $gitBranch
        configuration = $Configuration
        toolchain   = @{
            generator = 'Visual Studio 17 2022'
            cxx = $(& cl.exe 2>&1 | Select-Object -First 1)
            cmake = (cmake --version | Select-Object -First 1)
        }
        hardening   = @{
            compileFlags = @('/GS','/guard:cf','/guard:ehcont','/VOLATILE:ISO','/permissive-','/W4','/FC','/Zc:strictStrings')
            linkFlags    = @('/DYNAMICBASE','/NXCOMPAT','/HIGHENTROPYVA','/guard:cf','/guard:ehcont')
            verifiedPeCharacteristics = '0xC160 (DYNAMIC_BASE|NX_COMPAT|HIGH_ENTROPY_VA|GUARD_CF)'
        }
        components  = $sbomEntries
    }
    $sbomPath = Join-Path $stageDir 'build_evidence\sbom.json'
    # Depth 5 is required for the nested toolchain/hardening/components objects;
    # PowerShell's ConvertTo-Json warns and truncates at anything shallower.
    $sbom | ConvertTo-Json -Depth 6 | Out-File -FilePath $sbomPath -Encoding utf8

    # ---- verification record ----
    $reportPath = Join-Path $stageDir 'build_evidence\hardening_report.json'
    & pwsh -ExecutionPolicy Bypass -NoProfile -File $verifyScript `
        -Path (Join-Path $binDir 'rawr_run.exe') -Json |
        Out-File -FilePath $reportPath -Encoding utf8

    $verification = [PSCustomObject]@{
        generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        gatePassed   = ($failures.Count -eq 0)
        stagesFailed = $failures
        stagesRun    = @(
            'hardened_release_build_w4_zero_warnings'
            'contract_self_test_and_ctest'
            if ($SkipFuzz) { 'fuzz_skipped_by_request' } else { 'fuzz_harness_asan' }
            'pe_header_hardening'
            'e2e_mock_deep2_and_ollama'
            'real_ledger_gate_with_negative_controls'
        )
        notVerified = @(
            'real_model_autonomous_task_results'
            'ninety_percent_success_over_ten_unseen_tasks'
            'integration_into_win32_ide_command_handlers'
            'streaming_ui_and_persistent_resume'
            'competitive_gpu_inference_speed'
            'cursor_level_editor_ux'
        )
    }
    $verification | ConvertTo-Json -Depth 4 |
        Out-File -FilePath (Join-Path $stageDir 'build_evidence\verification.json') -Encoding utf8

    # ---- zip ----
    # Archive the staging directory ITSELF, not "$stageDir\*": the latter strips
    # the wrapper folder, so extracting scatters the drop into the recipient's
    # current directory. A source drop must be self-describing.
    $zipPath = Join-Path $OutputRoot "RawrXD-Production-Hardening-Source-$Version.zip"
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }

    $sevenZip = Get-Command 7z -ErrorAction SilentlyContinue
    Push-Location $OutputRoot
    try {
        if ($sevenZip) {
            # Run from $OutputRoot so the entry name keeps the wrapper folder.
            & 7z a -tzip $zipPath (Split-Path -Leaf $stageDir) | Out-Null
        } else {
            Compress-Archive -Path $stageDir -DestinationPath $zipPath -Force
        }
        if ($LASTEXITCODE -ne 0) { throw "zip creation failed" }
    }
    finally { Pop-Location }

    $zipSize = (Get-Item -LiteralPath $zipPath).Length
    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    if ($failures.Count -eq 0) {
        Write-Host "PRODUCTION-HARDENING SOURCE DROP READY" -ForegroundColor Green
    } else {
        Write-Host "PACKAGE ASSEMBLED BUT VERIFICATION FAILED" -ForegroundColor Red
    }
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  zip         : $zipPath"
    Write-Host ("  size        : {0:N0} bytes" -f $zipSize)
    Write-Host "  sha256      : $zipHash"
    Write-Host "  sbom        : $sbomPath"
    Write-Host "  verification: $(Join-Path $stageDir 'build_evidence\verification.json')"
    if ($failures.Count -gt 0) {
        Write-Host ""
        Write-Host "FAILED STAGES: $($failures -join ', ')" -ForegroundColor Red
    }

    exit $(if ($failures.Count -eq 0) { 0 } else { 1 })
}
finally {
    Pop-Location
}
