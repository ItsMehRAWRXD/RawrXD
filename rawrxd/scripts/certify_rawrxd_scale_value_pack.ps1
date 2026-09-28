param(
    [Parameter(Mandatory=$true)][string]$Workspace,
    [Parameter(Mandatory=$true)][string]$ScaleExe,
    [string]$AgentExe = "",
    [string]$Model = ""
)

$ErrorActionPreference = "Stop"

function Assert-ExitZero([string]$Name) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

Write-Host "=== RAWRXD SCALE VALUE PACK CERTIFICATION ==="

& $ScaleExe index --workspace $Workspace
Assert-ExitZero "index"

$indexPath = Join-Path $Workspace ".rawrxd\index\workspace.rxidx"
if (-not (Test-Path $indexPath)) { throw "index artifact missing" }

& $ScaleExe search --workspace $Workspace --query "Deep2 Engine" --top 5
Assert-ExitZero "search"

$checkpointOutput = & $ScaleExe checkpoint-create --workspace $Workspace --label scale-cert
Assert-ExitZero "checkpoint-create"
$checkpointOutput | Write-Host
$checkpointId = ($checkpointOutput | Select-String '^CHECKPOINT_ID=' | Select-Object -First 1).Line.Split('=',2)[1]
if (-not $checkpointId) { throw "checkpoint id missing" }

& $ScaleExe checkpoint-list --workspace $Workspace
Assert-ExitZero "checkpoint-list"

if ($AgentExe -and $Model) {
    & $ScaleExe run-isolated `
        --agent-exe $AgentExe `
        --workspace $Workspace `
        --model $Model `
        --task "Inspect the workspace only. Report the build entry points and do not modify files." `
        --max-steps 8 `
        --max-tokens 1024 `
        --timeout-minutes 10
    Assert-ExitZero "run-isolated"
}

Write-Host "GATE=RAWRXD_SCALE_VALUE_PACK_001"
Write-Host "INDEX=PASS"
Write-Host "SEARCH=PASS"
Write-Host "CHECKPOINT=PASS"
if ($AgentExe -and $Model) { Write-Host "ISOLATED_AGENT=PASS" }
Write-Host "VERDICT=PASS"
