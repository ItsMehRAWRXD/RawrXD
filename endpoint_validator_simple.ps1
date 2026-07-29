# RawrXD Endpoint Validator - Simple Version
# Validates endpoints in batches of 20

param(
    [string]$BaseUrl = "http://localhost:9090",
    [int]$BatchSize = 20,
    [int]$TimeoutSec = 5
)

# Suppress progress to avoid interactive prompts
$ProgressPreference = 'SilentlyContinue'

# Color codes
$Colors = @{
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Info = "Cyan"
    Header = "Magenta"
}

# Endpoints to validate
$Endpoints = @(
    # Batch 1: Core Health & Status (1-20)
    @{ Method = "GET"; Path = "/api/status"; Category = "Status"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/tags"; Category = "Models"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/full-state"; Category = "State"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/memory/stats"; Category = "Memory"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/memory/status"; Category = "Memory"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/ws-stats"; Category = "WebSocket"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/cot/health"; Category = "CoT"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/cot/metrics"; Category = "CoT"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/agents"; Category = "Agents"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/agents/status"; Category = "Agents"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/agents/history"; Category = "Agents"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/policies"; Category = "Policies"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/policies/suggestions"; Category = "Policies"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/policies/stats"; Category = "Policies"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/policies/heuristics"; Category = "Policies"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/backends"; Category = "Backends"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/backends/status"; Category = "Backends"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/agentic/config"; Category = "Config"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/gpu/status"; Category = "GPU"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/tuner/status"; Category = "Tuner"; ExpectedStatus = 200 },
    
    # Batch 2: Chat & Completion (21-40)
    @{ Method = "POST"; Path = "/api/generate"; Category = "Generation"; ExpectedStatus = 200; Body = '{"model":"test","prompt":"hello"}' },
    @{ Method = "POST"; Path = "/v1/chat/completions"; Category = "Chat"; ExpectedStatus = 200; Body = '{"model":"test","messages":[{"role":"user","content":"hello"}]}' },
    @{ Method = "POST"; Path = "/api/chat"; Category = "Chat"; ExpectedStatus = 200; Body = '{"model":"test","messages":[{"role":"user","content":"hello"}]}' },
    @{ Method = "POST"; Path = "/api/complete"; Category = "Completion"; ExpectedStatus = 200; Body = '{"model":"test","prompt":"hello"}' },
    @{ Method = "POST"; Path = "/api/complete/stream"; Category = "Streaming"; ExpectedStatus = 200; Body = '{"model":"test","prompt":"hello","stream":true}' },
    @{ Method = "POST"; Path = "/api/pull"; Category = "Models"; ExpectedStatus = 200; Body = '{"name":"test"}' },
    @{ Method = "POST"; Path = "/api/command"; Category = "Command"; ExpectedStatus = 200; Body = '{"command":"echo test"}' },
    @{ Method = "POST"; Path = "/api/cot"; Category = "CoT"; ExpectedStatus = 200; Body = '{"message":"hello"}' },
    @{ Method = "POST"; Path = "/api/read-file"; Category = "Files"; ExpectedStatus = 200; Body = '{"path":"test.txt"}' },
    @{ Method = "POST"; Path = "/api/reasoning/depth"; Category = "Reasoning"; ExpectedStatus = 200; Body = '{"depth":4}' },
    @{ Method = "POST"; Path = "/api/reasoning/preset"; Category = "Reasoning"; ExpectedStatus = 200; Body = '{"preset":"normal"}' },
    @{ Method = "POST"; Path = "/api/agent/bulkfix"; Category = "Agents"; ExpectedStatus = 200; Body = '{"strategy":"auto"}' },
    @{ Method = "POST"; Path = "/api/agent/plan"; Category = "Agents"; ExpectedStatus = 200; Body = '{"intent":"test"}' },
    @{ Method = "POST"; Path = "/api/agents/replay"; Category = "Agents"; ExpectedStatus = 200; Body = '{"session_id":"test"}' },
    @{ Method = "POST"; Path = "/api/policies/apply"; Category = "Policies"; ExpectedStatus = 200; Body = '{"id":"test"}' },
    @{ Method = "POST"; Path = "/api/policies/reject"; Category = "Policies"; ExpectedStatus = 200; Body = '{"id":"test"}' },
    @{ Method = "POST"; Path = "/api/policies/import"; Category = "Policies"; ExpectedStatus = 200; Body = '{"data":"test"}' },
    @{ Method = "POST"; Path = "/api/backends/use"; Category = "Backends"; ExpectedStatus = 200; Body = '{"backend":"cpu"}' },
    @{ Method = "POST"; Path = "/api/agentic/config"; Category = "Config"; ExpectedStatus = 200; Body = '{"operationMode":"standard"}' },
    @{ Method = "POST"; Path = "/api/gpu/toggle"; Category = "GPU"; ExpectedStatus = 200; Body = '{"enabled":true}' },
    
    # Batch 3: Tools & Subagents (41-60)
    @{ Method = "POST"; Path = "/api/tool"; Category = "Tools"; ExpectedStatus = 200; Body = '{"name":"list_dir","params":{}}' },
    @{ Method = "POST"; Path = "/api/tools/execute"; Category = "Tools"; ExpectedStatus = 200; Body = '{"tool":"list_dir","args":{}}' },
    @{ Method = "POST"; Path = "/api/subagent"; Category = "Subagents"; ExpectedStatus = 200; Body = '{"prompt":"test"}' },
    @{ Method = "POST"; Path = "/api/subagent/spawn"; Category = "Subagents"; ExpectedStatus = 200; Body = '{"task":"test"}' },
    @{ Method = "GET"; Path = "/api/subagent/list"; Category = "Subagents"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/chain"; Category = "Chains"; ExpectedStatus = 200; Body = '{"steps":["step1"]}' },
    @{ Method = "POST"; Path = "/api/chain/execute"; Category = "Chains"; ExpectedStatus = 200; Body = '{"chain_id":"test"}' },
    @{ Method = "GET"; Path = "/api/chain/status"; Category = "Chains"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/swarm"; Category = "Swarm"; ExpectedStatus = 200; Body = '{"prompts":["test"]}' },
    @{ Method = "POST"; Path = "/api/swarm/launch"; Category = "Swarm"; ExpectedStatus = 200; Body = '{"agents":[]}' },
    @{ Method = "GET"; Path = "/api/swarm/bridge"; Category = "Swarm"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/swarm/status"; Category = "Swarm"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/swarm/start"; Category = "Swarm"; ExpectedStatus = 200; Body = '{}' },
    @{ Method = "POST"; Path = "/api/swarm/stop"; Category = "Swarm"; ExpectedStatus = 200; Body = '{}' },
    @{ Method = "POST"; Path = "/api/tuner/run"; Category = "Tuner"; ExpectedStatus = 200; Body = '{}' },
    @{ Method = "GET"; Path = "/api/hotpatch/model"; Category = "Hotpatch"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/hotpatch/status"; Category = "Hotpatch"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/webrtc/status"; Category = "WebRTC"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/sandbox/list"; Category = "Sandbox"; ExpectedStatus = 200 },
    
    # Batch 4: Advanced Features (61-80)
    @{ Method = "POST"; Path = "/api/sandbox/create"; Category = "Sandbox"; ExpectedStatus = 200; Body = '{"name":"test"}' },
    @{ Method = "GET"; Path = "/api/release/status"; Category = "Release"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/security/dork/status"; Category = "Security"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/security/dork/scan"; Category = "Security"; ExpectedStatus = 200; Body = '{"dork":"test"}' },
    @{ Method = "POST"; Path = "/api/security/dork/universal"; Category = "Security"; ExpectedStatus = 200; Body = '{}' },
    @{ Method = "GET"; Path = "/api/security/dashboard"; Category = "Security"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/thermal"; Category = "Thermal"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/policies/export"; Category = "Policies"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/policies/import"; Category = "Policies"; ExpectedStatus = 200; Body = '{"data":"test"}' },
    @{ Method = "GET"; Path = "/api/gpu/features"; Category = "GPU"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/gpu/memory"; Category = "GPU"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/backend/switch"; Category = "Backends"; ExpectedStatus = 200; Body = '{"backend":"cpu"}' },
    @{ Method = "POST"; Path = "/api/safety/rollback"; Category = "Safety"; ExpectedStatus = 200; Body = '{}' },
    @{ Method = "GET"; Path = "/api/explain/last"; Category = "Explain"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/explain/session"; Category = "Explain"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/explain/snapshot"; Category = "Explain"; ExpectedStatus = 200; Body = '{"file":"test"}' },
    @{ Method = "GET"; Path = "/api/license"; Category = "License"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/license/audit"; Category = "License"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/license/features"; Category = "License"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/tools/dumpbin"; Category = "Tools"; ExpectedStatus = 200; Body = '{"file":"test"}' },
    
    # Batch 5: WebSocket & Misc (81-99)
    @{ Method = "GET"; Path = "/ws"; Category = "WebSocket"; ExpectedStatus = 426 },
    @{ Method = "GET"; Path = "/api/ws"; Category = "WebSocket"; ExpectedStatus = 426 },
    @{ Method = "POST"; Path = "/api/agent/run"; Category = "Agents"; ExpectedStatus = 200; Body = '{"prompt":"test"}' },
    @{ Method = "GET"; Path = "/api/agent/status"; Category = "Agents"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/agent/stop"; Category = "Agents"; ExpectedStatus = 200; Body = '{"id":"test"}' },
    @{ Method = "GET"; Path = "/api/metrics"; Category = "Metrics"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/metrics/prometheus"; Category = "Metrics"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/telemetry"; Category = "Telemetry"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/telemetry/export"; Category = "Telemetry"; ExpectedStatus = 200; Body = '{}' }
)

# Results tracking
$Results = @()

function Test-Endpoint {
    param($Endpoint)
    
    $url = "$BaseUrl$($Endpoint.Path)"
    $startTime = Get-Date
    
    try {
        $headers = @{ "Content-Type" = "application/json" }
        $body = $Endpoint.Body
        
        if ($Endpoint.Method -eq "GET") {
            $response = Invoke-WebRequest -Uri $url -Method GET -Headers $headers -TimeoutSec $TimeoutSec -ErrorAction Stop
        } else {
            $response = Invoke-WebRequest -Uri $url -Method $Endpoint.Method -Headers $headers -Body $body -TimeoutSec $TimeoutSec -ErrorAction Stop
        }
        
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalMilliseconds
        
        $status = if ($response.StatusCode -eq $Endpoint.ExpectedStatus) { "PASS" } else { "UNEXPECTED" }
        
        return @{
            Path = $Endpoint.Path
            Method = $Endpoint.Method
            Category = $Endpoint.Category
            Status = $status
            HttpStatus = $response.StatusCode
            ExpectedStatus = $Endpoint.ExpectedStatus
            Duration = [math]::Round($duration, 2)
            ResponseSize = $response.Content.Length
            Error = $null
        }
    }
    catch {
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalMilliseconds
        
        $errorMsg = $_.Exception.Message
        $httpStatus = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        
        $status = if ($httpStatus -eq $Endpoint.ExpectedStatus) { "PASS" } else { "FAIL" }
        
        return @{
            Path = $Endpoint.Path
            Method = $Endpoint.Method
            Category = $Endpoint.Category
            Status = $status
            HttpStatus = $httpStatus
            ExpectedStatus = $Endpoint.ExpectedStatus
            Duration = [math]::Round($duration, 2)
            ResponseSize = 0
            Error = $errorMsg
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗"
Write-Host "║           RawrXD Endpoint Validator v1.0                       ║"
Write-Host "║           Batch Validation System (Size: $BatchSize)              ║"
Write-Host "╚═══════════════════════════════════════════════════════════════╝"
Write-Host ""
Write-Host "Target: $BaseUrl"
Write-Host "Total Endpoints: $($Endpoints.Count)"
Write-Host "Batch Size: $BatchSize"
Write-Host ""

# Calculate number of batches
$numBatches = [math]::Ceiling($Endpoints.Count / $BatchSize)
Write-Host "Will process in $numBatches batches..."
Write-Host ""

$allResults = @()
$totalPass = 0
$totalFail = 0

for ($batchNum = 1; $batchNum -le $numBatches; $batchNum++) {
    $startIdx = ($batchNum - 1) * $BatchSize
    $endIdx = [math]::Min($startIdx + $BatchSize - 1, $Endpoints.Count - 1)
    $batchEndpoints = $Endpoints[$startIdx..$endIdx]
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════"
    Write-Host "  BATCH $batchNum - Validating $($batchEndpoints.Count) endpoints"
    Write-Host "═══════════════════════════════════════════════════════════════"
    Write-Host ""
    
    $batchResults = @()
    $passCount = 0
    $failCount = 0
    
    for ($i = 0; $i -lt $batchEndpoints.Count; $i++) {
        $endpoint = $batchEndpoints[$i]
        $percent = [math]::Round((($i + 1) / $batchEndpoints.Count) * 100, 0)
        Write-Host "[$percent%] Testing $($endpoint.Method) $($endpoint.Path)" -NoNewline
        
        $result = Test-Endpoint -Endpoint $endpoint
        $batchResults += $result
        
        if ($result.Status -eq "PASS") { 
            $passCount++ 
            Write-Host " - PASS ($($result.Duration)ms)" -ForegroundColor Green
        } else { 
            $failCount++ 
            Write-Host " - FAIL ($($result.Duration)ms) [HTTP $($result.HttpStatus)]" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "───────────────────────────────────────────────────────────────"
    Write-Host "  BATCH $batchNum SUMMARY"
    Write-Host "───────────────────────────────────────────────────────────────"
    
    foreach ($result in $batchResults) {
        $icon = if ($result.Status -eq "PASS") { "[PASS]" } else { "[FAIL]" }
        $color = if ($result.Status -eq "PASS") { "Green" } else { "Red" }
        Write-Host "  $icon [$($result.Method)] $($result.Path) - $($result.Duration)ms" -ForegroundColor $color
    }
    
    Write-Host ""
    Write-Host "  Total: $($batchResults.Count) | Passed: $passCount | Failed: $failCount"
    Write-Host ""
    
    $allResults += $batchResults
    $totalPass += $passCount
    $totalFail += $failCount
    
    if ($batchResult.FailCount -eq 0) {
        Write-Host "BATCH $batchNum COMPLETE - All endpoints passed!" -ForegroundColor Green
    } else {
        Write-Host "BATCH $batchNum COMPLETE - $failCount endpoint(s) failed" -ForegroundColor Yellow
    }
    
    Write-Host ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗"
Write-Host "║                    FINAL VALIDATION REPORT                    ║"
Write-Host "╚═══════════════════════════════════════════════════════════════╝"
Write-Host ""

# Category breakdown
$categories = $allResults | Group-Object -Property Category | Sort-Object Name
Write-Host "Category Breakdown:"
Write-Host "───────────────────────────────────────────────────────────────"

foreach ($cat in $categories) {
    $catPass = ($cat.Group | Where-Object { $_.Status -eq "PASS" }).Count
    $catFail = ($cat.Group | Where-Object { $_.Status -ne "PASS" }).Count
    $catTotal = $cat.Group.Count
    $percent = [math]::Round(($catPass / $catTotal) * 100, 1)
    
    Write-Host "  $($cat.Name.PadRight(15)) : $catPass/$catTotal passed ($percent%)"
}

Write-Host ""
Write-Host "───────────────────────────────────────────────────────────────"
Write-Host "Overall Statistics:"
Write-Host "───────────────────────────────────────────────────────────────"
Write-Host "  Total Endpoints Tested: $($allResults.Count)"
Write-Host "  Passed: $totalPass"
Write-Host "  Failed: $totalFail"
Write-Host "  Success Rate: $([math]::Round(($totalPass / $allResults.Count) * 100, 1))%"

Write-Host ""

if ($totalFail -eq 0) {
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║           ALL ENDPOINTS VALIDATED SUCCESSFULLY              ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
} else {
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║           VALIDATION COMPLETE WITH FAILURES                 ║" -ForegroundColor Red
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    
    Write-Host ""
    Write-Host "Failed Endpoints:" -ForegroundColor Red
    $failed = $allResults | Where-Object { $_.Status -ne "PASS" }
    foreach ($f in $failed) {
        Write-Host "  [FAIL] [$($f.Method)] $($f.Path) - HTTP $($f.HttpStatus)" -ForegroundColor Red
    }
}

Write-Host ""

# Export results to JSON
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "d:\RawrXD\endpoint_validation_$timestamp.json"
$allResults | ConvertTo-Json -Depth 3 | Out-File $outputFile
Write-Host "Results exported to: $outputFile"

# Return exit code
exit $(if ($totalFail -eq 0) { 0 } else { 1 })
