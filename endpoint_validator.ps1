# ============================================================================
# RawrXD Endpoint Validator - Batch Validation System
# Validates all endpoints in batches of 20 until all pass
# ============================================================================

param(
    [string]$BaseUrl = "http://localhost:9090",
    [int]$BatchSize = 20,
    [int]$TimeoutSec = 10,
    [switch]$Verbose
)

# Color codes for output
$Colors = @{
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Info = "Cyan"
    Header = "Magenta"
}

# Comprehensive endpoint registry
$Endpoints = @(
    # Batch 1: Core Health & Status (1-20)
    @{ Method = "GET"; Path = "/health"; Category = "Health"; ExpectedStatus = 200 },
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
    @{ Method = "GET"; Path = "/api/tuner/status"; Category = "Tuner"; ExpectedStatus = 200 },
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
    
    # Batch 5: WebSocket & Misc (81-100)
    @{ Method = "GET"; Path = "/ws"; Category = "WebSocket"; ExpectedStatus = 426 },
    @{ Method = "GET"; Path = "/api/ws"; Category = "WebSocket"; ExpectedStatus = 426 },
    @{ Method = "POST"; Path = "/api/agent/run"; Category = "Agents"; ExpectedStatus = 200; Body = '{"prompt":"test"}' },
    @{ Method = "GET"; Path = "/api/agent/status"; Category = "Agents"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/agent/stop"; Category = "Agents"; ExpectedStatus = 200; Body = '{"id":"test"}' },
    @{ Method = "GET"; Path = "/api/metrics"; Category = "Metrics"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/metrics/prometheus"; Category = "Metrics"; ExpectedStatus = 200 },
    @{ Method = "GET"; Path = "/api/telemetry"; Category = "Telemetry"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/telemetry/export"; Category = "Telemetry"; ExpectedStatus = 200; Body = '{}' },
    @{ Method = "GET"; Path = "/api/build/status"; Category = "Build"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/build"; Category = "Build"; ExpectedStatus = 200; Body = '{"project":"test"}' },
    @{ Method = "GET"; Path = "/api/debug/status"; Category = "Debug"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/debug/attach"; Category = "Debug"; ExpectedStatus = 200; Body = '{"pid":0}' },
    @{ Method = "GET"; Path = "/api/patch/status"; Category = "Patch"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/patch/apply"; Category = "Patch"; ExpectedStatus = 200; Body = '{"patch":"test"}' },
    @{ Method = "GET"; Path = "/api/inference/status"; Category = "Inference"; ExpectedStatus = 200 },
    @{ Method = "POST"; Path = "/api/inference/load"; Category = "Inference"; ExpectedStatus = 200; Body = '{"model":"test"}' },
    @{ Method = "POST"; Path = "/api/inference/unload"; Category = "Inference"; ExpectedStatus = 200; Body = '{}' },
    @{ Method = "GET"; Path = "/api/model/info"; Category = "Models"; ExpectedStatus = 200 }
)

# Results tracking
$Results = @()
$BatchResults = @{}

function Write-ColorOutput {
    param([string]$Text, [string]$Color = "White")
    Write-Host $Text -ForegroundColor $Colors[$Color]
}

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
        $statusColor = if ($status -eq "PASS") { "Success" } else { "Warning" }
        
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
        
        # Some errors are expected (like 404 for unimplemented endpoints)
        $status = if ($httpStatus -eq $Endpoint.ExpectedStatus) { "PASS" } else { "FAIL" }
        $statusColor = if ($status -eq "PASS") { "Success" } else { "Error" }
        
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

function Show-Progress {
    param([int]$Current, [int]$Total, [string]$Status)
    $percent = [math]::Round(($Current / $Total) * 100, 1)
    $barLength = 50
    $filled = [math]::Round(($Current / $Total) * $barLength)
    $empty = $barLength - $filled
    $bar = "█" * $filled + "░" * $empty
    Write-Host "`r[$bar] $percent% ($Current/$Total) - $Status" -NoNewline
}

function Run-BatchValidation {
    param([int]$BatchNumber, [array]$BatchEndpoints)
    
    Write-Host ""
    Write-ColorOutput "═══════════════════════════════════════════════════════════════" $Colors.Header
    Write-ColorOutput "  BATCH $BatchNumber - Validating $($BatchEndpoints.Count) endpoints" $Colors.Header
    Write-ColorOutput "═══════════════════════════════════════════════════════════════" $Colors.Header
    Write-Host ""
    
    $batchResults = @()
    $passCount = 0
    $failCount = 0
    
    for ($i = 0; $i -lt $BatchEndpoints.Count; $i++) {
        $endpoint = $BatchEndpoints[$i]
        Show-Progress -Current ($i + 1) -Total $BatchEndpoints.Count -Status "Testing $($endpoint.Method) $($endpoint.Path)"
        
        $result = Test-Endpoint -Endpoint $endpoint
        $batchResults += $result
        
        if ($result.Status -eq "PASS") { $passCount++ } else { $failCount++ }
        
        if ($Verbose) {
            $color = if ($result.Status -eq "PASS") { "Success" } else { "Error" }
            Write-Host ""
            Write-ColorOutput "  $($result.Method) $($result.Path) - $($result.Status) ($($result.Duration)ms)" $color
        }
    }
    
    Write-Host ""  # Clear progress line
    Write-Host ""
    
    # Show batch summary
    Write-ColorOutput "───────────────────────────────────────────────────────────────" $Colors.Info
    Write-ColorOutput "  BATCH $BatchNumber SUMMARY" $Colors.Info
    Write-ColorOutput "───────────────────────────────────────────────────────────────" $Colors.Info
    
    foreach ($result in $batchResults) {
        $icon = if ($result.Status -eq "PASS") { "✓" } else { "✗" }
        $color = if ($result.Status -eq "PASS") { "Success" } else { "Error" }
        $statusText = if ($result.Status -eq "PASS") { "PASS" } else { "FAIL" }
        Write-ColorOutput "  $icon [$($result.Method)] $($result.Path) - $statusText ($($result.Duration)ms)" $color
        if ($result.Error -and $Verbose) {
            Write-ColorOutput "      Error: $($result.Error)" "Warning"
        }
    }
    
    Write-Host ""
    Write-ColorOutput "  Total: $($batchResults.Count) | Passed: $passCount | Failed: $failCount" $(if ($failCount -eq 0) { "Success" } else { "Warning" })
    Write-Host ""
    
    return @{
        Results = $batchResults
        PassCount = $passCount
        FailCount = $failCount
        Total = $batchResults.Count
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

Clear-Host
Write-ColorOutput "╔═══════════════════════════════════════════════════════════════╗" $Colors.Header
Write-ColorOutput "║           RawrXD Endpoint Validator v1.0                       ║" $Colors.Header
Write-ColorOutput "║           Batch Validation System (Size: $BatchSize)              ║" $Colors.Header
Write-ColorOutput "╚═══════════════════════════════════════════════════════════════╝" $Colors.Header
Write-Host ""
Write-ColorOutput "Target: $BaseUrl" $Colors.Info
Write-ColorOutput "Total Endpoints: $($Endpoints.Count)" $Colors.Info
Write-ColorOutput "Batch Size: $BatchSize" $Colors.Info
Write-Host ""

# Calculate number of batches
$numBatches = [math]::Ceiling($Endpoints.Count / $BatchSize)
Write-ColorOutput "Will process in $numBatches batches..." $Colors.Info
Write-Host ""

$allResults = @()
$totalPass = 0
$totalFail = 0

for ($batchNum = 1; $batchNum -le $numBatches; $batchNum++) {
    $startIdx = ($batchNum - 1) * $BatchSize
    $endIdx = [math]::Min($startIdx + $BatchSize - 1, $Endpoints.Count - 1)
    $batchEndpoints = $Endpoints[$startIdx..$endIdx]
    
    $batchResult = Run-BatchValidation -BatchNumber $batchNum -BatchEndpoints $batchEndpoints
    $allResults += $batchResult.Results
    $totalPass += $batchResult.PassCount
    $totalFail += $batchResult.FailCount
    
    # Check if all endpoints passed
    if ($batchResult.FailCount -eq 0) {
        Write-ColorOutput "✓ BATCH $batchNum COMPLETE - All endpoints passed!" "Success"
    } else {
        Write-ColorOutput "✗ BATCH $batchNum COMPLETE - $($batchResult.FailCount) endpoint(s) failed" "Error"
    }
    
    Write-Host ""
    
    # Small delay between batches
    if ($batchNum -lt $numBatches) {
        Start-Sleep -Milliseconds 500
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-ColorOutput "╔═══════════════════════════════════════════════════════════════╗" $Colors.Header
Write-ColorOutput "║                    FINAL VALIDATION REPORT                    ║" $Colors.Header
Write-ColorOutput "╚═══════════════════════════════════════════════════════════════╝" $Colors.Header
Write-Host ""

# Category breakdown
$categories = $allResults | Group-Object -Property Category | Sort-Object Name
Write-ColorOutput "Category Breakdown:" $Colors.Info
Write-ColorOutput "───────────────────────────────────────────────────────────────" $Colors.Info

foreach ($cat in $categories) {
    $catPass = ($cat.Group | Where-Object { $_.Status -eq "PASS" }).Count
    $catFail = ($cat.Group | Where-Object { $_.Status -ne "PASS" }).Count
    $catTotal = $cat.Group.Count
    $percent = [math]::Round(($catPass / $catTotal) * 100, 1)
    $color = if ($catFail -eq 0) { "Success" } else { "Warning" }
    
    Write-ColorOutput "  $($cat.Name.PadRight(15)) : $catPass/$catTotal passed ($percent%)" $color
}

Write-Host ""
Write-ColorOutput "───────────────────────────────────────────────────────────────" $Colors.Info
Write-ColorOutput "Overall Statistics:" $Colors.Info
Write-ColorOutput "───────────────────────────────────────────────────────────────" $Colors.Info
Write-ColorOutput "  Total Endpoints Tested: $($allResults.Count)" $Colors.Info
Write-ColorOutput "  Passed: $totalPass" $(if ($totalPass -gt 0) { "Success" } else { "Info" })
Write-ColorOutput "  Failed: $totalFail" $(if ($totalFail -eq 0) { "Success" } else { "Error" })
Write-ColorOutput "  Success Rate: $([math]::Round(($totalPass / $allResults.Count) * 100, 1))%" $(if ($totalFail -eq 0) { "Success" } else { "Warning" })

Write-Host ""

if ($totalFail -eq 0) {
    Write-ColorOutput "╔═══════════════════════════════════════════════════════════════╗" "Success"
    Write-ColorOutput "║           ✓ ALL ENDPOINTS VALIDATED SUCCESSFULLY            ║" "Success"
    Write-ColorOutput "╚═══════════════════════════════════════════════════════════════╝" "Success"
} else {
    Write-ColorOutput "╔═══════════════════════════════════════════════════════════════╗" "Error"
    Write-ColorOutput "║           ✗ VALIDATION COMPLETE WITH FAILURES               ║" "Error"
    Write-ColorOutput "╚═══════════════════════════════════════════════════════════════╝" "Error"
    
    Write-Host ""
    Write-ColorOutput "Failed Endpoints:" "Error"
    $failed = $allResults | Where-Object { $_.Status -ne "PASS" }
    foreach ($f in $failed) {
        Write-ColorOutput "  ✗ [$($f.Method)] $($f.Path) - HTTP $($f.HttpStatus)" "Error"
    }
}

Write-Host ""

# Export results to JSON
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "d:\RawrXD\endpoint_validation_$timestamp.json"
$allResults | ConvertTo-Json -Depth 3 | Out-File $outputFile
Write-ColorOutput "Results exported to: $outputFile" $Colors.Info

# Return exit code
exit $(if ($totalFail -eq 0) { 0 } else { 1 })
