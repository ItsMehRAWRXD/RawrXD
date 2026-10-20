[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MutationScript,
    [Parameter(Mandatory = $false)]
    [string[]]$Files = @(),
    [Parameter(Mandatory = $false)]
    [string]$FilesJson,
    [Parameter(Mandatory = $true)]
    [string]$BuildCommand,
    [Parameter(Mandatory = $false)]
    [string[]]$BuildArguments = @(),
    [Parameter(Mandatory = $false)]
    [string]$BuildArgumentsJson,
    [Parameter(Mandatory = $false)]
    [string]$ValidationCommand,
    [Parameter(Mandatory = $false)]
    [string[]]$ValidationArguments = @(),
    [Parameter(Mandatory = $false)]
    [string]$ValidationArgumentsJson,
    [Parameter(Mandatory = $true)]
    [string]$BenchmarkScript,
    [Parameter(Mandatory = $false)]
    [string[]]$BenchmarkArguments = @(),
    [Parameter(Mandatory = $false)]
    [string]$BenchmarkArgumentsJson,
    [Parameter(Mandatory = $true)]
    [double]$BaselineMedianTps,
    [Parameter(Mandatory = $false)]
    [double]$MinRelativeGain = 0.01,
    [Parameter(Mandatory = $false)]
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [Parameter(Mandatory = $false)]
    [string]$ReportPath,
    [Parameter(Mandatory = $false)]
    [string[]]$GeneratedPaths = @(),
    [Parameter(Mandatory = $false)]
    [switch]$KeepRejectedSnapshot,
    [Parameter(Mandatory = $false)]
    [switch]$SkipRebuildAfterReject,
    [Parameter(Mandatory = $false)]
    [string]$GatekeeperScript = (Join-Path $PSScriptRoot 'deep2_gatekeeper.ps1'),
    [Parameter(Mandatory = $false)]
    [string]$LedgerScript = (Join-Path $PSScriptRoot 'deep2_mutation_ledger.ps1'),
    [Parameter(Mandatory = $false)]
    [string]$LedgerPath,
    [Parameter(Mandatory = $false)]
    [switch]$Promote,
    [Parameter(Mandatory = $false)]
    [switch]$ResumeBenchmarks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertFrom-JsonStringArray([string]$Json, [string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Json)) { return @() }
    try {
        $value = ConvertFrom-Json -InputObject $Json
    } catch {
        throw "$Name must be a JSON array of strings."
    }
    if ($value -is [System.Array]) { return @($value | ForEach-Object { [string]$_ }) }
    return @([string]$value)
}

if ($FilesJson) { $Files = @(ConvertFrom-JsonStringArray $FilesJson 'FilesJson') }
if ($BuildArgumentsJson) { $BuildArguments = @(ConvertFrom-JsonStringArray $BuildArgumentsJson 'BuildArgumentsJson') }
if ($ValidationArgumentsJson) { $ValidationArguments = @(ConvertFrom-JsonStringArray $ValidationArgumentsJson 'ValidationArgumentsJson') }
if ($BenchmarkArgumentsJson) { $BenchmarkArguments = @(ConvertFrom-JsonStringArray $BenchmarkArgumentsJson 'BenchmarkArgumentsJson') }
if ($Files.Count -eq 0) { throw 'At least one candidate file is required.' }

function Resolve-RepoPath([string]$Path) {
    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $script:root $Path }
    return [System.IO.Path]::GetFullPath($candidate)
}

function Get-RelativeRepoPath([string]$Path) {
    $full = [System.IO.Path]::GetFullPath($Path)
    $prefix = $script:root.TrimEnd('\') + '\'
    if (-not $full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside the repository: $Path"
    }
    return $full.Substring($prefix.Length).Replace('\', '/')
}

function Get-FileIdentity([string]$Path) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $item = Get-Item -LiteralPath $Path
        return [pscustomobject]@{
            exists = $true
            bytes = $item.Length
            sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        }
    }
    return [pscustomobject]@{ exists = $false; bytes = 0; sha256 = $null }
}

function Get-ChangedPaths([string]$Root = $script:root) {
    $tracked = @(& git -C $Root diff --name-only; & git -C $Root diff --cached --name-only)
    $untracked = @(& git -C $Root ls-files --others --exclude-standard)
    return @($tracked + $untracked | Where-Object { $_ } | Sort-Object -Unique)
}

function Get-ChangedFingerprints([string[]]$Paths, [string]$Root = $script:root) {
    $fingerprints = [ordered]@{}
    foreach ($relative in @($Paths | Sort-Object -Unique)) {
        $full = Join-Path $Root ($relative -replace '/', '\')
        $fingerprints[$relative] = Get-FileIdentity $full
    }
    return $fingerprints
}

function Get-RootRelative([string]$Root, [string]$Path) {
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) { throw "Path is outside root: $Path" }
    return $fullPath.Substring($fullRoot.Length).Replace('\', '/')
}

function ConvertTo-CandidateArgument([string]$Root, [string]$CandidateRoot, [string]$Argument) {
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    if ([System.IO.Path]::IsPathRooted($Argument)) {
        $fullArgument = [System.IO.Path]::GetFullPath($Argument)
        if ($fullArgument.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            return (Join-Path $CandidateRoot $fullArgument.Substring($fullRoot.Length))
        }
        return $Argument
    }
    $source = Join-Path $Root $Argument
    if (Test-Path -LiteralPath $source) { return (Join-Path $CandidateRoot $Argument) }
    return $Argument
}

function Invoke-CheckedCommand([string]$Command, [string[]]$Arguments, [string]$LogPath) {
    $invokeCommand = $Command
    $invokeArguments = @($Arguments)
    if ([System.IO.Path]::GetExtension($Command) -ieq '.ps1') {
        $invokeCommand = 'pwsh'
        $invokeArguments = @('-NoProfile', '-File', $Command) + @($Arguments)
    }
    $output = @(& $invokeCommand @invokeArguments 2>&1 | Tee-Object -FilePath $LogPath)
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
    return [pscustomobject]@{ command = $invokeCommand; arguments = @($invokeArguments); exitCode = $exitCode; output = ($output -join [Environment]::NewLine); log = $LogPath }
}

function Get-Median([double[]]$Values) {
    $ordered = @($Values | Sort-Object)
    if ($ordered.Count -eq 0) { throw 'Benchmark produced no finite TPS values.' }
    $middle = [int][Math]::Floor($ordered.Count / 2)
    if (($ordered.Count % 2) -eq 1) { return [double]$ordered[$middle] }
    return ([double]$ordered[$middle - 1] + [double]$ordered[$middle]) / 2.0
}

$script:root = (Resolve-Path -LiteralPath $RepoRoot).Path
$mutationPath = Resolve-RepoPath $MutationScript
$benchmarkPath = Resolve-RepoPath $BenchmarkScript
$gatekeeperPath = Resolve-RepoPath $GatekeeperScript
$ledgerScriptPath = Resolve-RepoPath $LedgerScript
if (-not (Test-Path -LiteralPath $mutationPath -PathType Leaf)) { throw "Mutation script not found: $mutationPath" }
if (-not (Test-Path -LiteralPath $benchmarkPath -PathType Leaf)) { throw "Benchmark script not found: $benchmarkPath" }
if (-not (Test-Path -LiteralPath $gatekeeperPath -PathType Leaf)) { throw "Gatekeeper script not found: $gatekeeperPath" }
if (-not (Test-Path -LiteralPath $ledgerScriptPath -PathType Leaf)) { throw "Ledger script not found: $ledgerScriptPath" }
if ($BaselineMedianTps -le 0) { throw 'BaselineMedianTps must be positive.' }
if ($MinRelativeGain -lt 0) { throw 'MinRelativeGain cannot be negative.' }

$resolvedFiles = @($Files | ForEach-Object { Resolve-RepoPath $_ } | Sort-Object -Unique)
$allowedRelative = @($resolvedFiles | ForEach-Object { Get-RelativeRepoPath $_ })
$generatedRelative = @($GeneratedPaths | ForEach-Object { Get-RelativeRepoPath $_ })
$initialChanged = @(Get-ChangedPaths)
$initialFingerprints = Get-ChangedFingerprints $initialChanged
$trialRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('rawrxd_tps_trial_' + [guid]::NewGuid().ToString('N'))
$candidateRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('rawrxd_tps_candidate_' + [guid]::NewGuid().ToString('N'))
$snapshotRoot = Join-Path $trialRoot 'snapshot'
$baselinePath = Join-Path $trialRoot 'baseline.json'
$recoveryPath = Join-Path $trialRoot 'recovery.json'
if ([string]::IsNullOrWhiteSpace($LedgerPath)) {
    $ledgerPath = Join-Path (Split-Path -Parent $script:root) 'deep2_mutation_ledger.jsonl'
} else {
    $ledgerPath = [System.IO.Path]::GetFullPath($LedgerPath)
}
$ledgerHeadPath = "$ledgerPath.head"
$report = [ordered]@{
    schema = 'RAWRXD_DEEP2_TPS_MUTATION_GATE_001'
    verdict = 'REJECTED'
    repoRoot = $script:root
    mutationScript = $mutationPath
    files = $allowedRelative
    baselineMedianTps = $BaselineMedianTps
    minRelativeGain = $MinRelativeGain
    initialChangedPaths = $initialChanged
    initialChangedFingerprints = $initialFingerprints
    commands = [ordered]@{}
    candidate = [ordered]@{}
    restoration = [ordered]@{ required = -not $Promote; attempted = $false; verified = $false }
    snapshot = [ordered]@{}
    rebuildAfterReject = -not $SkipRebuildAfterReject
    gatekeeper = $gatekeeperPath
    ledger = $ledgerPath
    promote = [bool]$Promote
    candidateRoot = $candidateRoot
    benchmarkStatus = 'PAUSED'
    resumeBenchmarks = [bool]$ResumeBenchmarks
}

New-Item -ItemType Directory -Path $snapshotRoot,$trialRoot -Force | Out-Null

$accepted = $false
$baselineCaptured = $false
$candidateCreated = $false
$candidateLocationPushed = $false
$candidateInitialChanged = @()
$candidateInitialFingerprints = [ordered]@{}
$ledgerEvents = [System.Collections.Generic.List[string]]::new()
Push-Location $script:root
try {
    function Invoke-Gatekeeper([string]$GateAction, [string]$LogName) {
        $arguments = @(
            '-NoProfile', '-File', $gatekeeperPath,
            '-Action', $GateAction,
            '-RepoRoot', $script:root,
            '-BaselinePath', $baselinePath,
            '-SnapshotRoot', $snapshotRoot,
            '-RecoveryPath', $recoveryPath
        )
        if ($GateAction -eq 'CaptureBaseline') { $arguments += @('-PathsJson', ($allowedRelative | ConvertTo-Json -Compress)) }
        $result = Invoke-CheckedCommand -Command 'pwsh' -Arguments $arguments -LogPath (Join-Path $trialRoot $LogName)
        if ($result.exitCode -ne 0) { throw "Gatekeeper $GateAction failed with exit $($result.exitCode)." }
        return $result
    }
    function Append-LedgerRecord([string]$State, [hashtable]$Fields = @{}) {
        $record = [ordered]@{
            schema = 'RAWRXD_DEEP2_MUTATION_EVENT_001'
            candidate = [System.IO.Path]::GetFileNameWithoutExtension($mutationPath)
            state = $State
            baseline = $baselinePath
            baseline_inventory_sha256 = $null
            files = $allowedRelative
            generated_utc = [DateTime]::UtcNow.ToString('o')
        }
        if (Test-Path -LiteralPath $baselinePath -PathType Leaf) {
            $record.baseline_inventory_sha256 = (Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json).inventory_sha256
        }
        foreach ($key in $Fields.Keys) { $record[$key] = $Fields[$key] }
        $ledgerArguments = @(
            '-NoProfile', '-File', $ledgerScriptPath,
            '-Action', 'Append',
            '-LedgerPath', $ledgerPath,
            '-HeadPath', $ledgerHeadPath,
            '-RecordJson', ($record | ConvertTo-Json -Depth 20 -Compress)
        )
        $result = Invoke-CheckedCommand -Command 'pwsh' -Arguments $ledgerArguments -LogPath (Join-Path $trialRoot ('ledger_' + $State.ToLowerInvariant() + '.log'))
        if ($result.exitCode -ne 0) { throw "Ledger append failed for state $State." }
        [void]$ledgerEvents.Add($result.output)
    }

    $captureResult = Invoke-Gatekeeper 'CaptureBaseline' 'gate21_capture.log'
    $baselineCaptured = $true
    $report.commands.gate21Capture = $captureResult
    $report.baseline = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
    Append-LedgerRecord 'BASELINE_CAPTURED' @{ artifact_fingerprint = $report.baseline.inventory_sha256 }
    $worktreeResult = Invoke-CheckedCommand -Command 'git' -Arguments @('-C', $script:root, 'worktree', 'add', '--detach', $candidateRoot, 'HEAD') -LogPath (Join-Path $trialRoot 'candidate_worktree.log')
    if ($worktreeResult.exitCode -ne 0) { throw "Candidate worktree creation failed with exit $($worktreeResult.exitCode)." }
    $candidateCreated = $true
    $overlayPaths = @($allowedRelative + $initialChanged | Where-Object { $_ -like 'rawrxd/src/*' -or $_ -like 'rawrxd/scripts/*' -or $_ -like 'rawrxd/tools/*' -or $_ -like 'rawrxd/docs/*' } | Sort-Object -Unique)
    foreach ($relative in $overlayPaths) {
        $source = Join-Path $script:root ($relative -replace '/', '\')
        $destination = Join-Path $candidateRoot ($relative -replace '/', '\')
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
            Copy-Item -LiteralPath $source -Destination $destination -Force
        }
    }
    $candidateMutationPath = Join-Path $candidateRoot (Get-RootRelative $script:root $mutationPath)
    $candidateBenchmarkPath = Join-Path $candidateRoot (Get-RootRelative $script:root $benchmarkPath)
    $candidateBuildArguments = @($BuildArguments | ForEach-Object { ConvertTo-CandidateArgument $script:root $candidateRoot ([string]$_) })
    $candidateValidationArguments = @($ValidationArguments | ForEach-Object { ConvertTo-CandidateArgument $script:root $candidateRoot ([string]$_) })
    $candidateBenchmarkArguments = @($BenchmarkArguments | ForEach-Object { ConvertTo-CandidateArgument $script:root $candidateRoot ([string]$_) })
    $candidateInitialChanged = @(Get-ChangedPaths $candidateRoot)
    $candidateInitialFingerprints = Get-ChangedFingerprints $candidateInitialChanged $candidateRoot
    Push-Location $candidateRoot
    $candidateLocationPushed = $true
    $env:RAWRXD_MUTATION_ROOT = $candidateRoot
    $env:RAWRXD_MUTATION_ALLOWED_FILES = ($allowedRelative -join ';')
    $mutationResult = Invoke-CheckedCommand -Command $candidateMutationPath -Arguments @() -LogPath (Join-Path $trialRoot 'mutation.log')
    $report.commands.mutation = $mutationResult
    if ($mutationResult.exitCode -ne 0) { throw "Mutation script failed with exit $($mutationResult.exitCode)." }

    $afterMutation = Get-ChangedPaths $candidateRoot
    $afterFingerprints = Get-ChangedFingerprints @($candidateInitialChanged + $afterMutation) $candidateRoot
    $modifiedExisting = @($candidateInitialChanged | Where-Object {
        $before = $candidateInitialFingerprints[$_]
        $after = $afterFingerprints[$_]
        $_ -notin $allowedRelative -and ($before.exists -ne $after.exists -or $before.bytes -ne $after.bytes -or $before.sha256 -ne $after.sha256)
    })
    if ($modifiedExisting.Count -gt 0) {
        $report.candidate.modifiedPreexistingPaths = $modifiedExisting
        throw "Mutation modified pre-existing dirty paths: $($modifiedExisting -join ', ')"
    }
    $unexpected = @($afterMutation | Where-Object {
        $_ -notin $initialChanged -and
        $_ -notin $allowedRelative -and
        $_ -notin $generatedRelative
    })
    if ($unexpected.Count -gt 0) {
        $report.candidate.unexpectedChangedPaths = $unexpected
        throw "Mutation touched undeclared paths: $($unexpected -join ', ')"
    }

    $buildResult = Invoke-CheckedCommand -Command $BuildCommand -Arguments $candidateBuildArguments -LogPath (Join-Path $trialRoot 'build.log')
    $report.commands.build = $buildResult
    if ($buildResult.exitCode -ne 0) { throw "Build failed with exit $($buildResult.exitCode)." }

    if ($ValidationCommand) {
        $validationResult = Invoke-CheckedCommand -Command $ValidationCommand -Arguments $candidateValidationArguments -LogPath (Join-Path $trialRoot 'validation.log')
        $report.commands.validation = $validationResult
        if ($validationResult.exitCode -ne 0) { throw "Validation failed with exit $($validationResult.exitCode)." }
    }

    if (-not $ResumeBenchmarks) {
        $report.verdict = 'DRY_RUN_ONLY'
        $report.benchmarkStatus = 'PAUSED'
        Append-LedgerRecord 'DRY_RUN_ONLY' @{ benchmark_launched = $false }
        throw 'Benchmark execution is paused; source-only validation completed without launching a model.'
    }
    if ([Environment]::GetEnvironmentVariable('RAWRXD_D2_BENCHMARK_AUTHORIZATION', 'Process') -ne 'EXPLICIT_USER_RESUME') {
        $report.verdict = 'HARD_HALT'
        $report.benchmarkStatus = 'PAUSED'
        Append-LedgerRecord 'HARD_HALT' @{ benchmark_launched = $false; reason = 'missing explicit user resume authorization' }
        throw 'Benchmark execution requires RAWRXD_D2_BENCHMARK_AUTHORIZATION=EXPLICIT_USER_RESUME.'
    }
    $report.benchmarkStatus = 'AUTHORIZED'

    $benchmarkArgs = @($candidateBenchmarkArguments + @('-OutputDir', (Join-Path $trialRoot 'benchmark')))
    $report.commands.benchmarkArguments = @($benchmarkArgs)
    $benchmarkResult = Invoke-CheckedCommand -Command $candidateBenchmarkPath -Arguments $benchmarkArgs -LogPath (Join-Path $trialRoot 'benchmark.log')
    $report.commands.benchmark = $benchmarkResult
    if ($benchmarkResult.exitCode -ne 0) { throw "Benchmark failed with exit $($benchmarkResult.exitCode)." }

    $benchmarkReportPath = Join-Path $trialRoot 'benchmark\flight_recorder_report.json'
    if (-not (Test-Path -LiteralPath $benchmarkReportPath -PathType Leaf)) { throw 'Benchmark report was not produced.' }
    $benchmarkReport = Get-Content -LiteralPath $benchmarkReportPath -Raw | ConvertFrom-Json
    $results = @($benchmarkReport.results | Where-Object { $_.pass -and $null -ne $_.decode_tps })
    if ($benchmarkReport.verdict -ne 'PASS' -or $results.Count -ne [int]$benchmarkReport.runs) {
        throw 'Benchmark certification gate did not pass all runs.'
    }
    $candidateMedian = Get-Median @($results | ForEach-Object { [double]$_.decode_tps })
    $requiredMedian = $BaselineMedianTps * (1.0 + $MinRelativeGain)
    $report.candidate = [ordered]@{
        medianTps = $candidateMedian
        requiredMedianTps = $requiredMedian
        speedup = $candidateMedian / $BaselineMedianTps
        runTps = @($results | ForEach-Object { [double]$_.decode_tps })
        benchmarkReport = $benchmarkReportPath
    }
    if ($candidateMedian -le $requiredMedian) {
        throw "Candidate median $candidateMedian did not exceed required $requiredMedian."
    }
    if ($Promote) {
        $promotionFiles = [ordered]@{}
        foreach ($path in $resolvedFiles) {
            $relative = Get-RelativeRepoPath $path
            $candidateFile = Join-Path $candidateRoot ($relative -replace '/', '\')
            if (-not (Test-Path -LiteralPath $candidateFile -PathType Leaf)) { throw "Promotion source is missing: $relative" }
            New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
            Copy-Item -LiteralPath $candidateFile -Destination $path -Force
            $sourceIdentity = Get-FileIdentity $candidateFile
            $destinationIdentity = Get-FileIdentity $path
            if ($sourceIdentity.sha256 -ne $destinationIdentity.sha256 -or $sourceIdentity.bytes -ne $destinationIdentity.bytes) { throw "Promotion verification failed: $relative" }
            $promotionFiles[$relative] = $destinationIdentity
        }
        $report.promotion = [ordered]@{ verified = $true; files = $promotionFiles }
    }
    $accepted = $true
    $report.verdict = 'ACCEPTED'
    if ($Promote) { Append-LedgerRecord 'PROMOTED' @{ median_tps = $candidateMedian; benchmark_report = $benchmarkReportPath } }
}
catch {
    $report.failure = $_.Exception.Message
}
finally {
    if ($baselineCaptured -and (-not ($accepted -and $Promote))) {
        $report.restoration.attempted = $true
        $restored = $false
        try {
            $verifyResult = Invoke-Gatekeeper 'VerifyBaseline' 'gate21_verify.log'
            $report.commands.restoreVerify = $verifyResult
            $restored = $true
        } catch {
            $report.restoration.failure = $_.Exception.Message
        }
        $report.restoration.verified = $restored
        $report.restoration.rebuild = 'NOT_REQUIRED_ISOLATED_CANDIDATE'
        try {
            $restoreState = if ($restored) { 'RESTORED' } else { 'RESTORE_FAILED' }
            Append-LedgerRecord $restoreState @{ restore_verified = $restored }
        } catch { $report.restoration.ledgerFailure = $_.Exception.Message }
    } elseif ($baselineCaptured -and $accepted -and $Promote) {
        try { Append-LedgerRecord 'PROMOTION_LEFT_LIVE' @{ restore_verified = $false } } catch { $report.promotionLedgerFailure = $_.Exception.Message }
    }
    if ($candidateLocationPushed) { Pop-Location; $candidateLocationPushed = $false }
    if ($candidateCreated) {
        $removeLogPath = Join-Path $trialRoot 'candidate_worktree_remove.log'
        if (Test-Path -LiteralPath $candidateRoot -PathType Container) {
            $removeResult = Invoke-CheckedCommand -Command 'git' -Arguments @('-C', $script:root, 'worktree', 'remove', '--force', $candidateRoot) -LogPath $removeLogPath
            $report.commands.candidateWorktreeRemove = $removeResult
            $report.candidateWorktreeRemoved = $removeResult.exitCode -eq 0 -and -not (Test-Path -LiteralPath $candidateRoot)
        } else {
            $pruneResult = Invoke-CheckedCommand -Command 'git' -Arguments @('-C', $script:root, 'worktree', 'prune', '--expire', 'now') -LogPath $removeLogPath
            $report.commands.candidateWorktreePrune = $pruneResult
            $report.candidateWorktreeRemoved = $pruneResult.exitCode -eq 0 -and -not (Test-Path -LiteralPath $candidateRoot)
        }
    }
    if ($ReportPath) {
        $destination = Resolve-RepoPath $ReportPath
    } else {
        $destination = Join-Path ([System.IO.Path]::GetTempPath()) ('rawrxd_tps_mutation_' + [guid]::NewGuid().ToString('N') + '.json')
    }
    $report.generatedUtc = [DateTime]::UtcNow.ToString('o')
    $report.trialRoot = $trialRoot
    $report.snapshotRoot = if ($accepted -or $KeepRejectedSnapshot) { $snapshotRoot } else { $null }
    $report.ledgerEvents = @($ledgerEvents)
    $reportJson = $report | ConvertTo-Json -Depth 12
    $destinationParent = Split-Path -Parent $destination
    if ($destinationParent) { New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null }
    Set-Content -LiteralPath $destination -Value $reportJson -Encoding UTF8
    Write-Output "VERDICT=$($report.verdict)"
    Write-Output "REPORT=$destination"
    if ($report.restoration.attempted) { Write-Output "RESTORE_VERIFIED=$($report.restoration.verified)" }
    if (-not $KeepRejectedSnapshot -and (Test-Path -LiteralPath $snapshotRoot)) { Remove-Item -LiteralPath $snapshotRoot -Recurse -Force }
    Pop-Location
}

if (-not $accepted) { exit 2 }
