[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$GatewayUrl = $(if ($env:RAWRXD_GATEWAY_URL) { $env:RAWRXD_GATEWAY_URL } else { 'http://127.0.0.1:19035' }),
    [string]$OllamaUrl = $(if ($env:OLLAMA_HOST) { $env:OLLAMA_HOST } else { 'http://127.0.0.1:11434' }),
    [string]$NativeUrl = $(if ($env:RAWRXD_NATIVE_URL) { $env:RAWRXD_NATIVE_URL } else { 'http://127.0.0.1:19036' }),
    [string]$OutFile,
    [switch]$ProbeModels,
    [switch]$EnableDeep2
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path -LiteralPath $Root).Path
if (-not $OutFile) {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutFile = Join-Path $Root "evidence\RAWRXD_SELF_MANIFEST_$stamp.json"
}
$outDir = Split-Path -Parent $OutFile
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$findings = [System.Collections.Generic.List[object]]::new()
$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check([string]$Id, [string]$Area, [string]$Status, [string]$Detail, [object]$Evidence = $null) {
    $checks.Add([pscustomobject]@{ id=$Id; area=$Area; status=$Status; detail=$Detail; evidence=$Evidence })
}
function Add-Finding([string]$Kind, [string]$Path, [int]$Line, [string]$Text) {
    $findings.Add([pscustomobject]@{ kind=$Kind; path=$Path; line=$Line; text=$Text.Trim() })
}
function Invoke-Json([string]$Url, [string]$Method = 'GET', [object]$Body = $null, [int]$TimeoutSec = 8) {
    try {
        $params = @{ Uri=$Url; Method=$Method; TimeoutSec=$TimeoutSec; UseBasicParsing=$true }
        if ($null -ne $Body) { $params.ContentType='application/json'; $params.Body=($Body | ConvertTo-Json -Depth 10 -Compress) }
        $r = Invoke-WebRequest @params
        $j = $null; try { $j = $r.Content | ConvertFrom-Json -Depth 20 } catch {}
        return [pscustomobject]@{ ok=$true; status=[int]$r.StatusCode; headers=$r.Headers; json=$j; text=$r.Content }
    } catch {
        $status = 0; if ($_.Exception.Response) { $status=[int]$_.Exception.Response.StatusCode }
        return [pscustomobject]@{ ok=$false; status=$status; headers=$null; json=$null; text=$_.Exception.Message }
    }
}

# 1. Source graph and connection pattern scan.  These are leads, not proof.
# Keep the scan bounded to product source roots.  RawrXD intentionally keeps
# many archived builds, model drops, and historical snapshots beside the live
# tree; recursively walking all of those makes a self-test appear hung and
# produces duplicate, non-actionable leads.
$sourceRoots = @('src/deep2','src/inference','src/runtime','src/cli','src/vulkan_compute.cpp','include','backend','gui','tools','tests') | ForEach-Object {
    $candidate = Join-Path $Root $_
    if (Test-Path -LiteralPath $candidate) { (Resolve-Path -LiteralPath $candidate).Path }
}
$sourceFiles = [System.Collections.Generic.List[object]]::new()
foreach ($sourceRoot in $sourceRoots) {
    Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -Include *.cpp,*.h,*.hpp,*.js,*.ps1,*.cmake,CMakeLists.txt -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '[\\/](build|node_modules|evidence|\.git|archive|archived|backup|backups|lavapath|obj|dist|generated|fixtures)[\\/]' } |
        ForEach-Object { $sourceFiles.Add($_) }
}
$rootCmake = Join-Path $Root 'CMakeLists.txt'
if (Test-Path -LiteralPath $rootCmake) { $sourceFiles.Add((Get-Item -LiteralPath $rootCmake)) }
foreach ($file in $sourceFiles) {
    $lines = Get-Content -LiteralPath $file.FullName -ErrorAction SilentlyContinue
    for ($i=0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '(?i)TODO|FIXME|NOT_IMPLEMENTED|not implemented|stub|placeholder|REFACTOR') { Add-Finding 'source-lead' ($file.FullName.Substring($Root.Length).TrimStart('\\/')) ($i+1) $line }
        if ($line -match '(?i)CPU fallback|fallback.*CPU|NO_DISPATCH|unsupported operator|return false') { Add-Finding 'execution-lead' ($file.FullName.Substring($Root.Length).TrimStart('\\/')) ($i+1) $line }
    }
}
Add-Check 'SRC-001' 'source-scan' 'PASS' "Scanned $($sourceFiles.Count) source files; $($findings.Count) informational leads recorded" @{ files=$sourceFiles.Count; leads=$findings.Count }

# 2. Route registry and live route attachment.
$serverPath = Join-Path $Root 'backend\server.js'
$serverText = Get-Content -LiteralPath $serverPath -Raw
$routeMatches = [regex]::Matches($serverText, "\{ path: '([^']+)', method: '([^']+)' \}")
$routes = foreach ($m in $routeMatches) { [pscustomobject]@{ path=$m.Groups[1].Value; method=$m.Groups[2].Value } }
$routeResults = [System.Collections.Generic.List[object]]::new()
# Routes that can invoke inference, mutate state, or wait on the native
# process are intentionally skipped during the default connectivity sweep.
# They are still recorded in the manifest and can be exercised with
# -ProbeModels.  This keeps the self-test bounded and prevents a missing
# native gateway from turning a route audit into a multi-minute hang.
$activeRoutePaths = @(
    '/api/chat','/v1/chat/completions','/api/generate','/api/cli','/complete',
    '/complete/stream','/ask','/api/tool','/api/agent/execute-tool',
    '/api/chain','/api/subagent','/api/swarm','/api/backends/use',
    '/api/extensions/activate','/api/extensions/deactivate','/api/extensions/disable',
    '/api/extensions/enable','/api/extensions/host/kill','/api/extensions/host/restart',
    '/api/extensions/import','/api/extensions/install','/api/extensions/load-vsix',
    '/api/extensions/marketplace/search','/api/extensions/scan','/api/extensions/uninstall',
    '/api/hotpatch/apply','/api/hotpatch/revert','/api/hotpatch/toggle',
    '/api/policies/apply','/api/policies/import','/api/policies/reject'
)
$modelProbePaths = @('/api/chat','/v1/chat/completions')
foreach ($route in $routes) {
    if ($route.path.Contains('*')) { continue }
    if (($activeRoutePaths -contains $route.path) -and (-not $ProbeModels -or $modelProbePaths -notcontains $route.path)) {
        $routeResults.Add([pscustomobject]@{ path=$route.path; method=$route.method; status=-1; attached=$true; probe='skipped-active'; error=$null })
        continue
    }
    $body = if ($route.method -eq 'POST') { @{ } } else { $null }
    if ($route.path -eq '/api/chat') { $body=@{ model='llama3.2:3b'; messages=@(@{role='user';content='Reply with exactly OK'}); stream=$false; options=@{num_predict=4} } }
    if ($route.path -eq '/v1/chat/completions') { $body=@{ model='llama3.2:3b'; messages=@(@{role='user';content='Reply with exactly OK'}); stream=$false; max_tokens=4 } }
    $rr = Invoke-Json ($GatewayUrl.TrimEnd('/') + $route.path) $route.method $body
    $routeResults.Add([pscustomobject]@{ path=$route.path; method=$route.method; status=$rr.status; attached=($rr.status -ne 404); error=if($rr.status -eq 404){'registered route returned 404'}else{$null} })
}
$missingRoutes = @($routeResults | Where-Object { -not $_.attached })
Add-Check 'ROUTE-001' 'gateway' $(if($missingRoutes.Count -eq 0){'PASS'}else{'FAIL'}) "Registered routes: $($routeResults.Count); 404 routes: $($missingRoutes.Count)" @{ routes=$routeResults }

# 3. Backend admission: keep Deep2 and Ollama visible as separate lanes.
$health = Invoke-Json ($GatewayUrl.TrimEnd('/') + '/health')
$backends = Invoke-Json ($GatewayUrl.TrimEnd('/') + '/api/backends')
$ollama = Invoke-Json ($OllamaUrl.TrimEnd('/') + '/api/tags')
$native = Invoke-Json ($NativeUrl.TrimEnd('/') + '/api/engine/capabilities')
Add-Check 'BACKEND-001' 'gateway' $(if($health.status -eq 200){'PASS'}else{'FAIL'}) "Gateway health HTTP $($health.status)" $health.json
Add-Check 'BACKEND-002' 'ollama' $(if($ollama.status -eq 200){'PASS'}else{'BLOCKED'}) "Ollama tags HTTP $($ollama.status)" $ollama.json
$deep2Status = if($native.status -ge 200 -and $native.status -lt 300){'PASS'}else{'BLOCKED'}
Add-Check 'BACKEND-003' 'deep2' $deep2Status "Deep2 native capability HTTP $($native.status); native execution is never inferred from enumeration" $native.json
$laneIds = @(); if($backends.json -and $backends.json.backends){ $laneIds=@($backends.json.backends | ForEach-Object {$_.id}) }
Add-Check 'BACKEND-004' 'dual-lane' $(if($laneIds -contains 'ollama-direct' -and ($laneIds -contains 'rawrxd-native' -or $laneIds -contains 'rawrxd-node')){'PASS'}else{'FAIL'}) "Advertised lanes: $($laneIds -join ', ')" $backends.json

# 4. Chat, context, CORS and diagnostics.
$chatBody=@{ model='llama3.2:3b'; messages=@(@{role='system';content='Answer briefly.'},@{role='user';content='Remember BLUE-42.'},@{role='assistant';content='I will remember BLUE-42.'},@{role='user';content='What code should you repeat?' }); stream=$false; options=@{num_ctx=4096;num_predict=16;temperature=0} }
if ($ProbeModels) {
    $chat = Invoke-Json ($GatewayUrl.TrimEnd('/') + '/api/chat') 'POST' $chatBody 30
    $chatText = if($chat.json){ [string]($chat.json.message.content) }else{'' }
    Add-Check 'CHAT-001' 'chat' $(if($chat.status -eq 200 -and $chatText.Trim().Length -gt 0){'PASS'}else{'FAIL'}) "Role-preserving chat response chars=$($chatText.Length)" @{ status=$chat.status; chars=$chatText.Length }
} else {
    Add-Check 'CHAT-001' 'chat' 'NOT_PROBED' 'Inference probe skipped; rerun with -ProbeModels for a bounded multi-turn model request' @{ probe_models=$false }
}
$cors = Invoke-Json ($GatewayUrl.TrimEnd('/') + '/api/chat') 'OPTIONS'
Add-Check 'CHAT-002' 'cors' $(if($cors.status -eq 200 -and $cors.headers['Access-Control-Allow-Origin'] -eq '*'){'PASS'}else{'FAIL'}) 'CORS preflight for standalone file:// mode' $cors.headers
$metrics = Invoke-Json ($GatewayUrl.TrimEnd('/') + '/metrics')
Add-Check 'CHAT-003' 'metrics' $(if($metrics.status -eq 200 -and $metrics.json.metrics){'PASS'}else{'FAIL'}) 'Gateway metrics endpoint' $metrics.json

# 5. Filesystem, native compiler and browser reader connections.
$roots = Invoke-Json ($GatewayUrl.TrimEnd('/') + '/api/filesystem/roots')
$compiler = Invoke-Json ($GatewayUrl.TrimEnd('/') + '/api/compiler/capabilities')
$browse = Invoke-Json ($GatewayUrl.TrimEnd('/') + '/api/browse') 'POST' @{url='https://huggingface.co/models?search=gguf'} 20
Add-Check 'IDE-001' 'filesystem' $(if($roots.status -eq 200 -and $roots.json.hidden_included){'PASS'}else{'FAIL'}) 'Drive/hidden-root enumeration' $roots.json
Add-Check 'IDE-002' 'compiler' $(if($compiler.status -eq 200 -and $compiler.json.native_only){'PASS'}else{'BLOCKED'}) 'Native compiler capability probe' $compiler.json
Add-Check 'IDE-003' 'browser' $(if($browse.status -eq 200 -and $browse.json.ok){'PASS'}else{'BLOCKED'}) 'Read-only embedded browser reader' @{status=$browse.status; title=$browse.json.title}

# 6. Certification is intentionally separate from connectivity.
$cert = if(($checks | Where-Object {$_.status -in @('FAIL','BLOCKED')}).Count -eq 0){'PENDING_EXECUTION'}else{'NOT_CERTIFIED'}
$manifest = [pscustomobject]@{
    schema='rawrxd-self-manifest-v1'; generated_at=(Get-Date).ToUniversalTime().ToString('o'); root=$Root
    gateway=$GatewayUrl; ollama=$OllamaUrl; native=$NativeUrl; deep2_requested=[bool]$EnableDeep2
    source=[pscustomobject]@{ files=$sourceFiles.Count; informational_leads=$findings.Count }
    routes=$routeResults; checks=$checks; findings=$findings | Select-Object -First 500
    certification=$cert; policy='Connectivity and component checks never imply FULL_MODEL_CERTIFIED'
}
$manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutFile -Encoding UTF8
$summary = [pscustomobject]@{ manifest=$OutFile; checks=$checks.Count; pass=@($checks|? status -eq PASS).Count; fail=@($checks|? status -eq FAIL).Count; blocked=@($checks|? status -eq BLOCKED).Count; routes=$routeResults.Count; missing_routes=$missingRoutes.Count; certification=$cert }
$summary | ConvertTo-Json -Depth 5
if ($summary.fail -gt 0) { exit 4 }
exit 0

