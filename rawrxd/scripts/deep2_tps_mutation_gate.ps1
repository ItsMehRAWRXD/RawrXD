[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MutationScript,
    [Parameter(Mandatory = $true)]
    [string[]]$Files,
    [Parameter(Mandatory = $true)]
    [string]$BuildCommand,
    [Parameter(Mandatory = $false)]
    [string[]]$BuildArguments = @(),
    [Parameter(Mandatory = $false)]
    [string]$ValidationCommand,
    [Parameter(Mandatory = $false)]
    [string[]]$ValidationArguments = @(),
    [Parameter(Mandatory = $true)]
    [string]$BenchmarkScript,
    [Parameter(Mandatory = $false)]
    [string[]]$BenchmarkArguments = @(),
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
    [switch]$KeepRejectedSnapshot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Get-ChangedPaths {
    $tracked = @(& git -C $script:root diff --name-only; & git -C $script:root diff --cached --name-only)
    $untracked = @(& git -C $script:root ls-files --others --exclude-standard)
    return @($tracked + $untracked | Where-Object { $_ } | Sort-Object -Unique)
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
if (-not (Test-Path -LiteralPath $mutationPath -PathType Leaf)) { throw "Mutation script not found: $mutationPath" }
if (-not (Test-Path -LiteralPath $benchmarkPath -PathType Leaf)) { throw "Benchmark script not found: $benchmarkPath" }
if ($BaselineMedianTps -le 0) { throw 'BaselineMedianTps must be positive.' }
if ($MinRelativeGain -lt 0) { throw 'MinRelativeGain cannot be negative.' }

$resolvedFiles = @($Files | ForEach-Object { Resolve-RepoPath $_ } | Sort-Object -Unique)
if ($resolvedFiles.Count -eq 0) { throw 'At least one candidate file is required.' }
$allowedRelative = @($resolvedFiles | ForEach-Object { Get-RelativeRepoPath $_ })
$generatedRelative = @($GeneratedPaths | ForEach-Object { Get-RelativeRepoPath $_ })
$initialChanged = @(Get-ChangedPaths)
$snapshotRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('rawrxd_tps_snapshot_' + [guid]::NewGuid().ToString('N'))
$trialRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('rawrxd_tps_trial_' + [guid]::NewGuid().ToString('N'))
$report = [ordered]@{
    schema = 'RAWRXD_DEEP2_TPS_MUTATION_GATE_001'
    verdict = 'REJECTED'
    repoRoot = $script:root
    mutationScript = $mutationPath
    files = $allowedRelative
    baselineMedianTps = $BaselineMedianTps
    minRelativeGain = $MinRelativeGain
    initialChangedPaths = $initialChanged
    commands = [ordered]@{}
    candidate = [ordered]@{}
    restoration = [ordered]@{ attempted = $false; verified = $false }
    snapshot = [ordered]@{}
}
$snapshotIdentities = [ordered]@{}

New-Item -ItemType Directory -Path $snapshotRoot,$trialRoot -Force | Out-Null
foreach ($path in $resolvedFiles) {
    $relative = Get-RelativeRepoPath $path
    $snapshotPath = Join-Path $snapshotRoot $relative
    $parent = Split-Path -Parent $snapshotPath
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $identity = Get-FileIdentity $path
    $snapshotIdentities[$relative] = $identity
    $report.snapshot[$relative] = $identity
    $report.candidate[$relative] = $identity
    if ($identity.exists) { Copy-Item -LiteralPath $path -Destination $snapshotPath -Force }
}

$accepted = $false
Push-Location $script:root
try {
    $env:RAWRXD_MUTATION_ROOT = $script:root
    $env:RAWRXD_MUTATION_ALLOWED_FILES = ($allowedRelative -join ';')
    $mutationResult = Invoke-CheckedCommand -Command $mutationPath -Arguments @() -LogPath (Join-Path $trialRoot 'mutation.log')
    $report.commands.mutation = $mutationResult
    if ($mutationResult.exitCode -ne 0) { throw "Mutation script failed with exit $($mutationResult.exitCode)." }

    $afterMutation = Get-ChangedPaths
    $unexpected = @($afterMutation | Where-Object {
        $_ -notin $initialChanged -and
        $_ -notin $allowedRelative -and
        $_ -notin $generatedRelative
    })
    if ($unexpected.Count -gt 0) {
        $report.candidate.unexpectedChangedPaths = $unexpected
        throw "Mutation touched undeclared paths: $($unexpected -join ', ')"
    }

    $buildResult = Invoke-CheckedCommand -Command $BuildCommand -Arguments $BuildArguments -LogPath (Join-Path $trialRoot 'build.log')
    $report.commands.build = $buildResult
    if ($buildResult.exitCode -ne 0) { throw "Build failed with exit $($buildResult.exitCode)." }

    if ($ValidationCommand) {
        $validationResult = Invoke-CheckedCommand -Command $ValidationCommand -Arguments $ValidationArguments -LogPath (Join-Path $trialRoot 'validation.log')
        $report.commands.validation = $validationResult
        if ($validationResult.exitCode -ne 0) { throw "Validation failed with exit $($validationResult.exitCode)." }
    }

    $benchmarkArgs = @($BenchmarkArguments + @('-OutputDir', (Join-Path $trialRoot 'benchmark')))
    $report.commands.benchmarkArguments = @($benchmarkArgs)
    $benchmarkResult = Invoke-CheckedCommand -Command $benchmarkPath -Arguments $benchmarkArgs -LogPath (Join-Path $trialRoot 'benchmark.log')
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
    $accepted = $true
    $report.verdict = 'ACCEPTED'
}
catch {
    $report.failure = $_.Exception.Message
}
finally {
    if (-not $accepted) {
        $report.restoration.attempted = $true
        foreach ($path in $resolvedFiles) {
            $relative = Get-RelativeRepoPath $path
            $snapshotPath = Join-Path $snapshotRoot $relative
            $identity = $snapshotIdentities[$relative]
            if ($identity.exists) {
                Copy-Item -LiteralPath $snapshotPath -Destination $path -Force
            } elseif (Test-Path -LiteralPath $path -PathType Leaf) {
                Remove-Item -LiteralPath $path -Force
            }
        }
        $restored = $true
        foreach ($path in $resolvedFiles) {
            $relative = Get-RelativeRepoPath $path
            $before = $snapshotIdentities[$relative]
            $after = Get-FileIdentity $path
            if ($before.exists -ne $after.exists -or $before.sha256 -ne $after.sha256) { $restored = $false }
        }
        $report.restoration.verified = $restored
    }
    if ($ReportPath) {
        $destination = Resolve-RepoPath $ReportPath
    } else {
        $destination = Join-Path ([System.IO.Path]::GetTempPath()) ('rawrxd_tps_mutation_' + [guid]::NewGuid().ToString('N') + '.json')
    }
    $report.generatedUtc = [DateTime]::UtcNow.ToString('o')
    $report.trialRoot = $trialRoot
    $report.snapshotRoot = if ($accepted -or $KeepRejectedSnapshot) { $snapshotRoot } else { $null }
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
