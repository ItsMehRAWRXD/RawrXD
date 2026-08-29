# Run AFTER Smart App Control is fully Off (VerifiedAndReputablePolicyState must be 0).
# Windows Security → App & browser control → Smart App Control → Off, then reboot.

[CmdletBinding()]
param(
    [string]$Model = 'F:\~dev\tinyllama_fresh.gguf',
    [string]$ModelRoot = 'G:\OllamaModels',
    [string]$RepoRoot = 'F:\~dev\rawrxd',
    [int]$LifecycleIterations = 3,
    [switch]$Also25x,
    [switch]$AlsoAgentHello
)

$ErrorActionPreference = 'Continue'
$bin = Join-Path $RepoRoot 'build-ninja\bin'
$ev = Join-Path $RepoRoot 'evidence\SOVEREIGN_FINISH_HOUR'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

function Invoke-CertExe {
    param(
        [Parameter(Mandatory=$true)][string]$Exe,
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$OutFile
    )
    # Native stderr must NOT become a terminating PowerShell error.
    $oldEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @Arguments 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                $_.ToString()
            } else {
                $_
            }
        } | Tee-Object -FilePath $OutFile
        return [int]$LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldEap
    }
}

$sac = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue
if ($sac -and $sac.VerifiedAndReputablePolicyState -ne 0) {
    throw "SAC still ON (VerifiedAndReputablePolicyState=$($sac.VerifiedAndReputablePolicyState)). Set Smart App Control to Off and reboot before running this script."
}

$env:RAWRXD_MODEL_ROOT = $ModelRoot
$env:RAWRXD_BLOB_ROOT = Join-Path $ModelRoot 'blobs'

$catalog = Join-Path $bin 'rawrxd_model_catalog_cert.exe'
$lifecycle = Join-Path $bin 'deep2_lifecycle_cert_candidate.exe'
$agent = Join-Path $bin 'RawrXD-Agentic.exe'
foreach ($p in @($catalog, $lifecycle, $agent)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "Missing $p" }
}

$code = Invoke-CertExe -Exe $catalog -Arguments @('--root', $ModelRoot, '--list') -OutFile (Join-Path $ev 'model_catalog_list.txt')
"CATALOG_LIST_EXIT=$code" | Tee-Object (Join-Path $ev 'exit_codes.txt')
if ($code -ne 0) { throw "catalog --list failed: $code" }

$code = Invoke-CertExe -Exe $catalog -Arguments @('--model', $Model) -OutFile (Join-Path $ev 'model_catalog_resolve.txt')
"MODEL_CATALOG_EXIT=$code" | Tee-Object (Join-Path $ev 'exit_codes.txt') -Append
if ($code -ne 0) { throw "MODEL-CATALOG resolve failed: $code" }

$code = Invoke-CertExe -Exe $lifecycle -Arguments @('--model', $Model, '--iterations', "$LifecycleIterations", '--tokens', '8', '--prompt', 'Hello') -OutFile (Join-Path $ev "lifecycle_${LifecycleIterations}x.txt")
"LIFECYCLE_${LifecycleIterations}X_EXIT=$code" | Tee-Object (Join-Path $ev 'exit_codes.txt') -Append
if ($code -ne 0) { throw "LIFECYCLE ${LifecycleIterations}x failed: $code" }

if ($Also25x) {
    $code = Invoke-CertExe -Exe $lifecycle -Arguments @('--model', $Model, '--iterations', '25', '--tokens', '8', '--prompt', 'Hello') -OutFile (Join-Path $ev 'lifecycle_25x.txt')
    "LIFECYCLE_25X_EXIT=$code" | Tee-Object (Join-Path $ev 'exit_codes.txt') -Append
    if ($code -ne 0) { throw "LIFECYCLE 25x failed: $code" }
}

$code = Invoke-CertExe -Exe $agent -Arguments @('--help') -OutFile (Join-Path $ev 'agent_help.txt')
"AGENT_HELP_EXIT=$code" | Tee-Object (Join-Path $ev 'exit_codes.txt') -Append
if ($code -ne 0) { throw "agent --help failed: $code" }

if ($AlsoAgentHello) {
    $workspace = 'F:\scratch\rawrxd-agent-e2e'
    New-Item -ItemType Directory -Force -Path $workspace | Out-Null
    $code = Invoke-CertExe -Exe $agent -Arguments @(
        '--model', $Model,
        '--workspace', $workspace,
        '--task', 'Inspect this empty workspace. Create a C++ Hello World program, compile it, run it, observe stdout and the exit code, repair any failure, and finish only after the program exits 0 and prints Hello World.'
    ) -OutFile (Join-Path $ev 'agent_hello_world.txt')
    "AGENT_EXIT=$code" | Tee-Object (Join-Path $ev 'exit_codes.txt') -Append
    "AGENT_EXIT=$code" | Set-Content (Join-Path $ev 'agent_hello_world.exit.txt')
}

Write-Host 'RUN_AFTER_SAC_OFF complete.'
# Freeze binary/model hashes + git commit for sovereign runtime baseline packaging.
function Get-Sha256([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return 'MISSING' }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

$commit = ''
try {
    Push-Location $RepoRoot
    $commit = (git rev-parse HEAD 2>$null)
} finally {
    Pop-Location
}

$freeze = @"
SOVEREIGN_RUNTIME_CERT_FREEZE
timestamp=$(Get-Date -Format o)
canonical_repo=$RepoRoot
git_commit=$commit
model=$Model
model_sha256=$(Get-Sha256 $Model)
rawrxd_model_catalog_cert_sha256=$(Get-Sha256 $catalog)
deep2_lifecycle_cert_candidate_sha256=$(Get-Sha256 $lifecycle)
RawrXD-Agentic_sha256=$(Get-Sha256 $agent)
VerifiedAndReputablePolicyState=0
uses__Exit=NO (lifecycle candidate)
Also25x=$Also25x
AlsoAgentHello=$AlsoAgentHello
evidence_dir=$ev
"@
$freeze | Set-Content -LiteralPath (Join-Path $ev 'SOVEREIGN_RUNTIME_CERT_FREEZE.txt')
Write-Host $freeze
