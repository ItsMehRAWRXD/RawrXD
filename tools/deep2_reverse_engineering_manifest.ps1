[CmdletBinding()]
param(
    [Parameter(Position=0)] [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [Parameter(Position=1)] [string]$Output = ''
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path $RepoRoot).Path
if (-not $Output) {
    $Output = Join-Path $RepoRoot 'evidence\deep2_reverse_engineering_manifest.json'
}

function Read-Source([string]$RelativePath) {
    $path = Join-Path $RepoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $path)) { return @{ path=$RelativePath; present=$false; text='' } }
    return @{ path=$RelativePath; present=$true; text=(Get-Content -LiteralPath $path -Raw) }
}

function Has([hashtable]$Source, [string]$Pattern) {
    return $Source.present -and ($Source.text -match $Pattern)
}

function Finding([string]$Id, [string]$Boundary, [string]$Status, [string[]]$Evidence, [string]$Next) {
    [pscustomobject]@{
        id=$Id; boundary=$Boundary; status=$Status; evidence=$Evidence; next_action=$Next
    }
}

$graph = Read-Source 'src\deep2\modelgenie\universal_gguf.cpp'
$roles = Read-Source 'src\deep2\modelgenie\universal_gguf.hpp'
$executor = Read-Source 'src\deep2\runtime_graph_executor.cpp'
$agentLoop = Read-Source 'tools\deep2_agentic_loop.cpp'
$auth = Read-Source 'src\agentic\MotdAuthorization.h'
$gdnShader = Read-Source 'src\deep2\shaders\deep2_qwen4exp_gdn.comp'
$gdnSpvPath = Join-Path $RepoRoot 'src\deep2\shaders\deep2_qwen4exp_gdn.spv'
$traceExePath = Join-Path $RepoRoot 'build\bin\Release\deep2_exec_trace.exe'
$agentExeCandidates = @(
    (Join-Path $RepoRoot 'build\bin\Release\deep2_agentic_loop.exe'),
    (Join-Path $RepoRoot 'build\Release\deep2_agentic_loop.exe')
)

$findings = @()
$findings += Finding 'RE-GRAPH-01' 'Qwen hybrid block classification' `
    ($(if ((Has $graph 'qwen35Gdn') -and (Has $graph '!qwen35Gdn')) {'PASS'} else {'BLOCKED'})) `
    @($graph.path, 'qwen35Gdn predicate, exclusive SsmScan and attention lowering') `
    'Keep GDN lowering exclusive and add per-model graph receipt.'
$findings += Finding 'RE-GEOM-02' 'SsmAlpha/SsmBeta role coverage' `
    ($(if ((Has $roles 'SsmAlpha') -and (Has $roles 'SsmBeta')) {'PASS'} else {'BLOCKED'})) `
    @($roles.path, 'SsmAlpha, SsmBeta role declarations') `
    'Reject models whose recurrent coefficient roles are absent or ambiguous.'
$findings += Finding 'RE-SHADER-03' 'GDN shader artifact' `
    ($(if ($gdnShader.present -and (Test-Path -LiteralPath $gdnSpvPath)) {'COMPONENT_PASS'} else {'BLOCKED'})) `
    @($gdnShader.path, 'src/deep2/shaders/deep2_qwen4exp_gdn.spv') `
    'Bind descriptors and submit this shader from ExecuteToken.'
$findings += Finding 'RE-EXEC-04' 'GDN production ExecuteToken dispatch' `
    ($(if (Has $executor 'case OpKind::Gdn') {'BLOCKED'} else {'NOT_FOUND'})) `
    @($executor.path, 'OpKind::Gdn exists but no executable switch arm') `
    'Implement descriptor allocation, queue submission, state publication, and GPU parity.'
$findings += Finding 'RE-EXEC-05' 'QSA/PLE/Hyperconnection/SparseMoE production dispatch' `
    ($(if (Has $executor 'qwen4exp_unbound') {'BLOCKED'} else {'NOT_FOUND'})) `
    @($executor.path, 'Bind fail-closed operator boundary') `
    'Close each operator through ExecuteToken independently before aggregate admission.'
$findings += Finding 'RE-AGENT-06' 'Native agent loop source' `
    ($(if ((Has $agentLoop 'TOOL read') -and (Has $agentLoop 'TOOL bash') -and (Has $agentLoop 'TOOL finish')) {'SOURCE_READY'} else {'BLOCKED'})) `
    @($agentLoop.path, 'read/write/bash/finish action grammar') `
    'Build the binary and run a read-only audit against a real local model.'
$agentExe = $agentExeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$findings += Finding 'RE-AGENT-07' 'Native agent loop executable' `
    ($(if ($agentExe) {'BUILT'} else {'NOT_BUILT'})) `
    @($agentExeCandidates) `
    'Build deep2_agentic_loop before advertising rawr run model audits.'
$findings += Finding 'RE-AUTH-08' 'MOTD authorization boundary' `
    ($(if ($auth.present) {'SOURCE_PRESENT'} else {'BLOCKED'})) `
    @($auth.path, 'session/turn authorization source') `
    'Require a fresh MOTD acknowledgement before executable tool dispatch.'
$findings += Finding 'RE-FULL-09' 'Qwen full-model independent parity' 'NOT_RUN' `
    @('No complete two-shard execution receipt supplied by this scan') `
    'Run every layer and expert path with an independent oracle.'
$findings += Finding 'RE-FULL-10' 'Qwen autoregressive certification' 'BLOCKED' `
    @('Depends on RE-EXEC-04, RE-EXEC-05, and RE-FULL-09') `
    'Require deterministic multi-token generation, cache continuity, and repeated output.'

$open = @($findings | Where-Object { $_.status -notin @('PASS','COMPONENT_PASS','SOURCE_READY','BUILT','SOURCE_PRESENT') }).Count
$manifest = [ordered]@{
    schema='rawrxd.deep2.reverse_engineering_manifest.v1'
    generated_utc=[DateTime]::UtcNow.ToString('o')
    repository=$RepoRoot
    policy='full-model certification only; component evidence never certifies the model'
    open_findings=$open
    certification=($(if ($open -eq 0) {'ELIGIBLE_FOR_REVIEW'} else {'NOT_CERTIFIED'}))
    findings=$findings
}

$parent = Split-Path -Parent $Output
if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Output -Encoding UTF8
Write-Host "MANIFEST=$Output"
Write-Host "OPEN_FINDINGS=$open"
Write-Host "CERTIFICATION=$($manifest.certification)"
if ($open -gt 0) { exit 4 }
exit 0
