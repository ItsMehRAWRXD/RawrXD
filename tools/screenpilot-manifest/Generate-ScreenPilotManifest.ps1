#Requires -Version 5.1
<#
.SYNOPSIS
  Scan RawrXD + ScreenPilot sources and emit a real deployment manifest (no stubs).
.EXAMPLE
  .\Generate-ScreenPilotManifest.ps1 -RepoRoot 'F:\~dev\rawrxd' -OutPath 'F:\~dev\screenpilot-universal-manifest.json'
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [Parameter()]
    [string]$SiteRoot = '',
    [Parameter()]
    [string]$OutPath = (Join-Path (Split-Path $RepoRoot -Parent) 'screenpilot-universal-manifest.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $SiteRoot) {
    $candidate = Join-Path $RepoRoot 'sites\screenpilot.tech'
    if (Test-Path -LiteralPath $candidate) { $SiteRoot = $candidate }
}

function Get-FileSha256Hex {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256
    return $hash.Hash.ToLowerInvariant()
}

function Read-LogTextShared {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $stream = $null
    $reader = $null
    try {
        $stream = [IO.File]::Open(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite)
        $reader = New-Object IO.StreamReader($stream)
        return $reader.ReadToEnd()
    } catch {
        return ''
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}

function Get-InventorySha256Hex {
    param(
        [string]$Root,
        [string[]]$Extensions = @('.cpp', '.h', '.hpp', '.c', '.asm', '.ps1', '.html', '.js', '.md', '.json')
    )
    if (-not (Test-Path -LiteralPath $Root)) { return '' }
    $lines = [System.Collections.Generic.List[string]]::new()
    Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -notmatch '\\(build-|\.git|node_modules|Full Source|history|reconstructed)\\'
        } |
        ForEach-Object {
            if ($Extensions -contains $_.Extension.ToLowerInvariant()) {
                $rel = $_.FullName.Substring($Root.Length).TrimStart('\')
                [void]$lines.Add(('{0}|{1}' -f $rel, $_.Length))
            }
        }
    $sorted = $lines | Sort-Object
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($sorted -join "`n"))
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-GitProvenance {
    param([string]$Root)
    $commit = ''
    $dirty = $false
    Push-Location -LiteralPath $Root
    try {
        $commit = (& git rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -ne 0) { $commit = '' }
        $status = (& git status --porcelain 2>$null)
        $dirty = [bool]($status -and $status.Length -gt 0)
    } finally {
        Pop-Location
    }
    return @{ commit = $commit; dirty = $dirty }
}

function Get-StringSha256Hex {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-CMakeOptions {
    param([string]$CmakeFile)
    if (-not (Test-Path -LiteralPath $CmakeFile)) { return @() }
    $text = [IO.File]::ReadAllText($CmakeFile)
    $opts = [regex]::Matches($text, '(?m)^option\s*\(\s*([A-Z0-9_]+)\s+"([^"]*)"') |
        ForEach-Object {
            [ordered]@{
                name = $_.Groups[1].Value
                description = $_.Groups[2].Value
                source = 'CMakeLists.txt'
            }
        }
    return @($opts)
}

function Get-EnvVarsFromSources {
    param([string]$Root)
    $patterns = @(
        'getenv\s*\(\s*"([A-Z0-9_]+)"',
        'readEnvFlag\s*\(\s*"([A-Z0-9_]+)"',
        'std::getenv\s*\(\s*"([A-Z0-9_]+)"'
    )
    $found = @{}
    $glob = @('*.cpp', '*.h', '*.hpp', '*.c', '*.asm')
    foreach ($ext in $glob) {
        Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $ext -ErrorAction SilentlyContinue |
            Where-Object {
                $_.FullName -notmatch '\\(build-|\.git|node_modules|Full Source|history|reconstructed)\\'
            } |
            ForEach-Object {
                $content = [IO.File]::ReadAllText($_.FullName)
                foreach ($pat in $patterns) {
                    foreach ($m in [regex]::Matches($content, $pat)) {
                        $name = $m.Groups[1].Value
                        if ($name -match '^RAWR') {
                            if (-not $found.ContainsKey($name)) {
                                $found[$name] = @{
                                    name = $name
                                    files = [System.Collections.Generic.List[string]]::new()
                                }
                            }
                            $rel = $_.FullName.Substring($Root.Length).TrimStart('\')
                            if ($found[$name].files -notcontains $rel) {
                                [void]$found[$name].files.Add($rel)
                            }
                        }
                    }
                }
            }
    }
    return @($found.Values | Sort-Object name)
}

function Get-CertGates {
    param([string]$CmakeFile)
    if (-not (Test-Path -LiteralPath $CmakeFile)) { return @() }
    $text = [IO.File]::ReadAllText($CmakeFile)
    $gates = [regex]::Matches($text, 'BUILD_([A-Z0-9_]+)_CERT|local_only_001_cert|k2_runtime_validation|command_home_smoke') |
        ForEach-Object { $_.Value } | Sort-Object -Unique
    return @($gates)
}

function Get-SiteInventory {
    param([string]$Root)
    if (-not (Test-Path -LiteralPath $Root)) { return @{ html = @(); js = @() } }
    @{
        html = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.html' -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName.Substring($Root.Length).TrimStart('\') })
        js = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.js' -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName.Substring($Root.Length).TrimStart('\') })
    }
}

function Get-K2RuntimeEvidence {
    param([string]$Root)
    $gate10Dir = Join-Path $Root 'evidence\K2-008-PARTIAL-FORWARD-STREAM-PASS'
    $gate11Dir = Join-Path $Root 'evidence\K2-GATE-11-DEEP2-NATIVE-STREAM-BRIDGE'
    $gate10Pass = 0
    $gate11Pass = 0
    if (Test-Path -LiteralPath $gate10Dir) {
        Get-ChildItem -LiteralPath $gate10Dir -Filter 'gate10_run*.log' -ErrorAction SilentlyContinue |
            ForEach-Object {
                $raw = Read-LogTextShared -Path $_.FullName
                if ($raw -match 'EXIT_CODE\s*=\s*0') { $gate10Pass++ }
            }
    }
    if (Test-Path -LiteralPath $gate11Dir) {
        Get-ChildItem -LiteralPath $gate11Dir -Filter 'gate11_run*.log' -ErrorAction SilentlyContinue |
            ForEach-Object {
                $raw = Read-LogTextShared -Path $_.FullName
                if ($raw -match 'EXIT_CODE\s*=\s*0') { $gate11Pass++ }
            }
    }
    return @{
        gate10PassCount = $gate10Pass
        gate11PassCount = $gate11Pass
        frozenBaseline = Test-Path -LiteralPath (Join-Path $gate10Dir 'BASELINE_FROZEN.md')
        gate11Frozen = Test-Path -LiteralPath (Join-Path $gate11Dir 'BASELINE_FROZEN.md')
    }
}

function Get-P1ManifestTruthEvidence {
    param([string]$Root)
    $dir = Join-Path $Root 'evidence\P1_SCREENPILOT_MANIFEST_TRUTH_001'
    $pass = 0
    if (Test-Path -LiteralPath $dir) {
        Get-ChildItem -LiteralPath $dir -Filter 'run*.log' -ErrorAction SilentlyContinue |
            ForEach-Object {
                $raw = Read-LogTextShared -Path $_.FullName
                if ($raw -match 'P1_SCREENPILOT_MANIFEST_TRUTH_001 PASSED') { $pass++ }
            }
    }
    return @{
        passCount = $pass
        frozen = Test-Path -LiteralPath (Join-Path $dir 'BASELINE_FROZEN.md')
    }
}

function Get-EvidenceDerivedCertification {
    param([string]$Root)
    $k2 = Get-K2RuntimeEvidence -Root $Root
    $p1 = Get-P1ManifestTruthEvidence -Root $Root
    $k2Status = 'BUILD_PASS_RUNTIME_PENDING'
    $k2Note = 'k2_runtime_validation.exe builds; runtime proof requires shard dir'
    if ($k2.gate10PassCount -ge 2 -and $k2.gate11PassCount -ge 2 -and $k2.frozenBaseline -and $k2.gate11Frozen) {
        $k2Status = 'RUNTIME_PARTIAL_PASS_G10_G11'
        $k2Note = ('Gate 10+11 partial-forward PASS ({0}/2 G10, {1}/2 G11); 4-layer bounded — not full K2' -f $k2.gate10PassCount, $k2.gate11PassCount)
    } elseif ($k2.gate10PassCount -ge 2 -and $k2.frozenBaseline) {
        $k2Status = 'RUNTIME_PARTIAL_PASS_G10'
        $k2Note = ('Gate 10 PASS ({0}/2); Gate 11 pending' -f $k2.gate10PassCount)
    } elseif ($k2.gate10PassCount -ge 1) {
        $k2Status = 'RUNTIME_PARTIAL_PENDING'
        $k2Note = ('Gate 10 evidence {0}/2; repeat run required' -f $k2.gate10PassCount)
    }

    $g10Status = if ($k2.gate10PassCount -ge 2 -and $k2.frozenBaseline) { 'PASS_RETAINED' } else { 'PENDING' }
    $g11Status = if ($k2.gate11PassCount -ge 2 -and $k2.gate11Frozen) { 'PASS_CLOSED' } else { 'NOT_PROVEN' }
    $p1Status = if ($p1.passCount -ge 2 -and $p1.frozen) { 'PASS_CLOSED' } elseif ($p1.passCount -ge 1) { 'PARTIAL' } else { 'OPEN' }

    return [ordered]@{
        LOCAL_ONLY_001 = @{ status = 'CERTIFIED'; harness = 'local_only_001_cert.exe'; source = 'manifest-default' }
        STREAMER_CERT_001 = @{ status = 'PASS'; harness = 'hexmag / streamer cert targets'; source = 'manifest-default' }
        EGRESS_001 = @{ status = 'OPEN'; note = 'Cloud egress and remote steering not certified'; source = 'manifest-default' }
        K2_GATE_10 = [ordered]@{
            status = $g10Status
            harness = 'k2_runtime_validation.exe --run-generation'
            gate10PassCount = $k2.gate10PassCount
            note = 'Direct validator -> K2NativeStreamGate; 4-layer bounded'
            source = 'evidence-scan'
        }
        K2_GATE_11 = [ordered]@{
            status = $g11Status
            harness = 'k2_runtime_validation.exe --run-generation-deep2'
            gate11PassCount = $k2.gate11PassCount
            note = 'Deep2Bridge -> Deep2Engine -> K2NativeStreamGate'
            source = 'evidence-scan'
        }
        K2_001 = [ordered]@{
            status = $k2Status
            harness = 'build-ninja/tests/k2_runtime_validation.exe'
            shardPattern = 'Kimi-K2-Instruct-0905-Q4_K_M-{0:D5}-of-00013.gguf'
            modelRoot = 'G:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M'
            gate10PassCount = $k2.gate10PassCount
            gate11PassCount = $k2.gate11PassCount
            frozenBaseline = $k2.frozenBaseline
            note = $k2Note
            source = 'evidence-scan'
        }
        P1_SCREENPILOT_MANIFEST_TRUTH_001 = [ordered]@{
            status = $p1Status
            harness = 'tools/screenpilot-manifest/Test-P1-ScreenPilot-Manifest-Truth-001.ps1'
            passCount = $p1.passCount
            note = if ($p1.frozen) { 'Manifest scanner truth invariants' } else { 'Run logs or BASELINE_FROZEN.md missing' }
            source = 'evidence-scan'
        }
        STATIC_DEP_001 = @{ status = 'OPEN'; note = 'Record only when SSL active and egress closed'; source = 'manifest-default' }
        P1_UI_MENU_E2E_001 = @{ status = 'IN_PROGRESS'; env = 'RAWRXD_P1_UI_MENU_E2E'; source = 'manifest-default' }
        HOSTED_GATEWAY = @{ status = 'COMMANDS_PRESENT'; note = 'Smoke not certified — commands present only'; source = 'manifest-default' }
        HEXMAG_IDE_INTEGRATION = @{ status = 'NOT_CLOSED'; note = 'Menu dispatch OPEN; MASM control plane retained PASS'; source = 'manifest-default' }
    }
}

$cmakePath = Join-Path $RepoRoot 'CMakeLists.txt'
$srcRoot = Join-Path $RepoRoot 'src'
$evidenceRoot = Join-Path $RepoRoot 'evidence'
$generatorPath = $PSCommandPath

$cmakeOptions = Get-CMakeOptions -CmakeFile $cmakePath
$envVars = Get-EnvVarsFromSources -Root $srcRoot
$certGates = Get-CertGates -CmakeFile $cmakePath
$site = Get-SiteInventory -Root $SiteRoot
$git = Get-GitProvenance -Root $RepoRoot
$generatedUtc = (Get-Date).ToUniversalTime().ToString('o')

$manifest = [ordered]@{
    name = 'ScreenPilot Universal Manifest'
    version = '2.1.0'
    generated = $generatedUtc
    generator = 'Generate-ScreenPilotManifest.ps1'
    provenance = [ordered]@{
        manifestVersion = 1
        generatedUtc = $generatedUtc
        repoRoot = $RepoRoot
        gitCommit = $git.commit
        gitDirty = $git.dirty
        generatorSha256 = (Get-FileSha256Hex -Path $generatorPath)
        cmakeSha256 = (Get-FileSha256Hex -Path $cmakePath)
        sourceInventorySha256 = (Get-InventorySha256Hex -Root $srcRoot)
        evidenceInventorySha256 = (Get-InventorySha256Hex -Root $evidenceRoot -Extensions @('.md', '.json', '.txt'))
        manifestSha256 = ''
    }
    projects = @(
        [ordered]@{
            name = 'rawrxd'
            root = $RepoRoot
            filesScanned = ($envVars | ForEach-Object { $_.files.Count } | Measure-Object -Sum).Sum
            cmakeOptions = $cmakeOptions
            envVars = $envVars
            certGates = $certGates
        }
        [ordered]@{
            name = 'screenpilot.tech'
            root = $SiteRoot
            staticSite = $site
        }
    )
    certification = Get-EvidenceDerivedCertification -Root $RepoRoot
    deploymentProfiles = [ordered]@{
        local_desktop_preview = [ordered]@{
            description = 'Win32 Command-home + Work Mode; LOCAL_ONLY_001 enforced'
            cmake = @{
                RAWRXD_BUILD_WIN32IDE = 'ON'
                RAWRXD_OPTIONAL_OLLAMA = 'OFF'
                RAWRXD_OPTIONAL_CLOUD = 'OFF'
                RAWRXD_OPTIONAL_TELEMETRY = 'OFF'
            }
            env = @{
                RAWRXD_MODELS_PATH = 'F:\OllamaModels'
            }
            excluded = @('cloud_egress', 'remote_steering', 'ads_in_win32_app')
        }
        hosted_gateway = [ordered]@{
            description = 'HeadlessIDE on api.screenpilot.tech; auth + CORS + fail-closed cloud'
            cmake = @{
                RAWRXD_BUILD_CLI = 'ON'
                RAWRXD_BUILD_WIN32IDE = 'OFF'
                RAWRXD_OPTIONAL_OLLAMA = 'OFF'
                RAWRXD_OPTIONAL_CLOUD = 'OFF'
            }
            env = @{
                RAWRXD_HOSTED_API_KEY = '<from-secret-store>'
                RAWRXD_ALLOWED_ORIGINS = 'https://screenpilot.tech'
            }
            buildTarget = 'rawrxd'
            smoke = @('/status', '/api/metrics', 'OPTIONS preflight', 'SSE Accept: text/event-stream')
            smokeStatus = 'NOT_CERTIFIED'
        }
        k2_runtime_validation = [ordered]@{
            description = 'Prove K2 partial-forward via K2NativeStream (--run-generation Gate 10)'
            exe = 'build-ninja/tests/k2_runtime_validation.exe'
            cmd = 'k2_runtime_validation.exe --run-generation --prompt hello <shard-dir>'
            requiredTelemetry = @(
                'K2_GENERATION_REQUESTED=YES'
                'ENGINE_PATH=K2NativeStream'
                'GENERATION=REAL'
                'STREAMING=YES'
                'FALLBACK=NONE'
                'SHARDS_DISCOVERED=13'
                'LAYER_DEPTH=4'
                'PEAK_RESIDENCY_MIB<=256'
                'FINAL_RESIDENCY_MIB=0'
                'OUTPUT_NONEMPTY=PASS'
                'EXIT_CODE=0'
            )
        }
        sovereign_pro = [ordered]@{
            price = '$599 one-time'
            includes = @(
                'Ad-free screenpilot.tech public docs'
                'Perpetual license current major version'
                'Local Deep2/GGUF + MASM acceleration'
                'Workspace/Git + agentic plan/build/test'
                'One user multiple owned devices'
            )
            excludes = @('unlimited cloud inference', 'remote steering until EGRESS_001')
        }
    }
    e2eChecklist = @(
        [ordered]@{ id = 'build_rawrxd'; cmd = 'cmake --build build-hosted --target rawrxd'; gate = 'link' }
        [ordered]@{ id = 'local_only_cert'; cmd = '.\build-hosted\bin\local_only_001_cert.exe'; gate = 'LOCAL_ONLY_001' }
        [ordered]@{ id = 'hosted_auth_smoke'; cmd = 'rawrxd --hosted --port 18086'; gate = 'HOSTED_GATEWAY' }
        [ordered]@{ id = 'k2_runtime'; cmd = '.\build-ninja\tests\k2_runtime_validation.exe --run-generation <shard-dir>'; gate = 'K2_001' }
        [ordered]@{ id = 'push_static_site'; cmd = 'git push screenpilot.tech repo'; gate = 'STATIC_DEP_001' }
    )
    powershell = [ordered]@{
        generateManifest = "& '$PSCommandPath' -RepoRoot '$RepoRoot' -OutPath '$OutPath'"
        manifestTruthCert = "& '$PSScriptRoot\Test-P1-ScreenPilot-Manifest-Truth-001.ps1' -RepoRoot '$RepoRoot'"
        k2Validation = @"
`$shard='G:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M'
`$exe=Join-Path '$RepoRoot' 'build-ninja\tests\k2_runtime_validation.exe'
& `$exe --run-generation --prompt hello `$shard
"@
        ciNativeHosted = @"
cmake -S '$RepoRoot' -B build-hosted -G Ninja -DCMAKE_BUILD_TYPE=Release `
  -DRAWRXD_BUILD_CLI=ON -DRAWRXD_BUILD_WIN32IDE=OFF `
  -DRAWRXD_OPTIONAL_OLLAMA=OFF -DRAWRXD_OPTIONAL_CLOUD=OFF -DRAWRXD_OPTIONAL_TELEMETRY=OFF
cmake --build build-hosted --target rawrxd local_only_001_cert -- -j2
"@
    }
}

# Serialize; manifestSha256 = SHA256(JSON with manifestSha256 empty)
$manifest.provenance.manifestSha256 = ''
$jsonPass1 = $manifest | ConvertTo-Json -Depth 16
$manifest.provenance.manifestSha256 = Get-StringSha256Hex -Text $jsonPass1
$jsonFinal = $manifest | ConvertTo-Json -Depth 16
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($OutPath, $jsonFinal, $utf8)

Write-Host "Wrote manifest: $OutPath"
Write-Host "CMake options: $($cmakeOptions.Count)"
Write-Host "RAWR* env vars: $($envVars.Count)"
Write-Host "Cert references: $($certGates.Count)"
Write-Host "Provenance manifestSha256: $($manifest.provenance.manifestSha256)"
Write-Host "Git commit: $($git.commit) dirty=$($git.dirty)"
