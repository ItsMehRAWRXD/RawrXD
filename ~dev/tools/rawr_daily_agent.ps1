[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Prompt,
    [string]$Model = 'llama3.2:3b',
    [string]$Workspace = (Get-Location).Path,
    [ValidateSet('cpu','gpu','auto')]
    [string]$Device = 'gpu',
    [ValidateRange(1,4096)]
    [int]$MaxSteps = 8,
    [ValidateRange(1,4096)]
    [int]$MaxTokensPerStep = 128,
    [ValidateRange(1,1048576)]
    [int]$Context = 8192,
    [ValidateRange(1,86400)]
    [int]$TimeoutSeconds = 1800,
    [string]$RawrPath = (Join-Path $PSScriptRoot '..\build\Release\rawr.exe'),
    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot '..\evidence\daily-agent')
)

$ErrorActionPreference = 'Stop'
$workspacePath = [System.IO.Path]::GetFullPath($Workspace)
$rawrPath = [System.IO.Path]::GetFullPath($RawrPath)
$evidencePath = [System.IO.Path]::GetFullPath($EvidenceDirectory)

if (-not (Test-Path -LiteralPath $workspacePath -PathType Container)) {
    throw "Workspace does not exist: $workspacePath"
}
if (-not (Test-Path -LiteralPath $rawrPath -PathType Leaf)) {
    throw "rawr.exe does not exist: $rawrPath"
}

New-Item -ItemType Directory -Force -Path $evidencePath | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$stdoutPath = Join-Path $evidencePath "agent_${stamp}.stdout.log"
$stderrPath = Join-Path $evidencePath "agent_${stamp}.stderr.log"
$receiptPath = Join-Path $evidencePath "agent_${stamp}.json"

$args = @(
    'run', $Model, $Prompt,
    '--agent', "--device=$Device", "--context=$Context",
    "--max-steps=$MaxSteps", "--max-tokens-per-step=$MaxTokensPerStep",
    "--workspace=$workspacePath"
)

$started = Get-Date
$process = Start-Process -FilePath $rawrPath -ArgumentList $args `
    -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
$completed = $process.WaitForExit($TimeoutSeconds * 1000)
$timedOut = -not $completed
if ($timedOut) {
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    $exitCode = 124
} else {
    $exitCode = $process.ExitCode
}

$receipt = [ordered]@{
    schema = 'RAWR_DAILY_AGENT_001'
    started_utc = $started.ToUniversalTime().ToString('o')
    finished_utc = (Get-Date).ToUniversalTime().ToString('o')
    model = $Model
    workspace = $workspacePath
    device = $Device
    timeout_seconds = $TimeoutSeconds
    timed_out = $timedOut
    exit_code = $exitCode
    stdout = $stdoutPath
    stderr = $stderrPath
    rawr = $rawrPath
}
$receipt | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $receiptPath -Encoding UTF8
Write-Output "RAWR_DAILY_AGENT_RECEIPT=$receiptPath"
Write-Output "RAWR_DAILY_AGENT_EXIT=$exitCode"
exit $exitCode
