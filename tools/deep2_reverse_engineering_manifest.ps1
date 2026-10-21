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
$cmake = Read-Source 'CMakeLists.txt'
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
$gdnCpuReference = (Has $executor 'bool Executor::OpGdn') -and (Has $executor 'GDN reference recurrence')
$findings += Finding 'RE-EXEC-04' 'GDN production ExecuteToken dispatch' `
    ($(if ($gdnCpuReference) {'REFERENCE_ONLY'} elseif (Has $executor 'case OpKind::Gdn') {'COMPONENT_WIRED'} else {'BLOCKED'})) `
    @($executor.path, 'case OpKind::Gdn in ExecuteToken/PrefillBatch', 'OpGdn uses causal state and reference recurrence; increments cpu_calls') `
    'Replace the reference recurrence with descriptor-backed Vulkan submission and prove state parity.'
$gdnTargetLinked = $cmake.present -and ($cmake.text -match '(?s)deep2_agentic_loop.*?src/deep2/op_gdn\.cpp')
$findings += Finding 'RE-WIRE-11' 'Production target operator linkage' `
    ($(if ($gdnTargetLinked) {'GDN_LINKED_COMPONENT_ONLY'} else {'UNLINKED'})) `
    @($cmake.path, 'deep2_agentic_loop includes op_gdn.cpp', 'QSA/PLE/Hyperconnection/SparseMoE sources remain probe-only') `
    'Keep unsupported operators out of production admission until each has a real Executor method and GPU receipt.'
$operatorFiles = @('op_ple.cpp','op_qsa.cpp','op_hyperconnection.cpp','op_sparse_moe.cpp')
$unconnectedOperators = @($operatorFiles | Where-Object {
    $p = Join-Path $RepoRoot "src\deep2\$_"
    (Test-Path -LiteralPath $p) -and -not (Has $executor ("Op" + [IO.Path]::GetFileNameWithoutExtension($_).Substring(3)))
})
$findings += Finding 'RE-EXEC-05' 'PLE/QSA/Hyperconnection/SparseMoE executor reachability' `
    ($(if ($unconnectedOperators.Count -eq 0) {'COMPONENT_WIRED'} else {'UNCONNECTED'})) `
    @($executor.path) + $unconnectedOperators `
    'Add explicit executor methods, tensor-role binding, and production dispatch for each operator.'
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

# Broad connectivity sweep: source can be present and compiled while still
# being disconnected from the production executor.  Keep this mechanical and
# evidence-oriented; a name hit is reported as reachability evidence, never as
# proof of numerical correctness.
$disconnected = @()
$deep2SourceRoot = Join-Path $RepoRoot 'src\deep2'
if (Test-Path -LiteralPath $deep2SourceRoot) {
    foreach ($file in @(Get-ChildItem -LiteralPath $deep2SourceRoot -Filter 'op_*.cpp' -File)) {
        $stem = $file.BaseName.Substring(3)
        $symbol = 'Op' + (($stem -split '_') | ForEach-Object { $_.Substring(0,1).ToUpperInvariant() + $_.Substring(1) } | Join-String)
        $executorHit = [bool](rg -n --fixed-strings $symbol (Join-Path $deep2SourceRoot 'runtime_graph_executor.cpp') 2>$null)
        $cmakeHit = [bool](rg -n --fixed-strings ("src/deep2/" + $file.Name) (Join-Path $RepoRoot 'CMakeLists.txt') 2>$null)
        if (-not $executorHit) {
            $disconnected += [pscustomobject]@{ kind='operator'; file=$file.FullName.Substring($RepoRoot.Length+1); symbol=$symbol; build_included=$cmakeHit; runtime_reference=$false }
        }
    }
    foreach ($shader in @(Get-ChildItem -LiteralPath (Join-Path $deep2SourceRoot 'shaders') -Filter '*.comp' -File -ErrorAction SilentlyContinue)) {
        $spv = [IO.Path]::ChangeExtension($shader.FullName, '.spv')
        $name = $shader.BaseName
        $runtimeHit = [bool](rg -n --fixed-strings $name $deep2SourceRoot (Join-Path $RepoRoot 'src\vulkan_compute.cpp') 2>$null)
        if (-not (Test-Path -LiteralPath $spv) -or -not $runtimeHit) {
            $disconnected += [pscustomobject]@{ kind='shader'; file=$shader.FullName.Substring($RepoRoot.Length+1); spirv_present=(Test-Path -LiteralPath $spv); runtime_reference=$runtimeHit }
        }
    }
}

$findings += Finding 'RE-CONNECT-11' 'Deep2 operator and shader connectivity sweep' `
    ($(if ($disconnected.Count -eq 0) {'PASS'} else {'DISCONNECTED_PIECES'})) `
    @($disconnected | ForEach-Object { "$($_.kind):$($_.file)" }) `
    'Connect every reported operator/shader to a runtime dispatch method or document it as diagnostic-only.'

$open = @($findings | Where-Object { $_.status -notin @('PASS','COMPONENT_PASS','SOURCE_READY','BUILT','SOURCE_PRESENT') }).Count
$manifest = [ordered]@{
    schema='rawrxd.deep2.reverse_engineering_manifest.v1'
    generated_utc=[DateTime]::UtcNow.ToString('o')
    repository=$RepoRoot
    policy='full-model certification only; component evidence never certifies the model'
    reverse_engineered_pattern=[ordered]@{
        family='qwen35_hybrid'
        type_a='attn_qkv[5120,10240] + attn_gate[5120,6144] + recurrent sidecars -> GDN -> ssm_out[6144,5120]'
        type_b='attn_q[5120,12288] + attn_k[5120,1024] + attn_v[5120,1024] -> attn_output[6144,5120]'
        invariant='both block families return a 5120-wide residual stream; never lower Type-A fused GDN as conventional attention'
        confidence='manifest-and-source-backed; not a certification result'
    }
    open_findings=$open
    certification=($(if ($open -eq 0) {'ELIGIBLE_FOR_REVIEW'} else {'NOT_CERTIFIED'}))
    findings=$findings
    disconnected_pieces=$disconnected
}

$parent = Split-Path -Parent $Output
if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Output -Encoding UTF8
Write-Host "MANIFEST=$Output"
Write-Host "OPEN_FINDINGS=$open"
Write-Host "CERTIFICATION=$($manifest.certification)"
if ($open -gt 0) { exit 4 }
exit 0
