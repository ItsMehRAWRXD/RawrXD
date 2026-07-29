# RawrXD Endpoint Validator - Clean Version (No Colors)
param(
    [string]$BaseUrl = "http://localhost:9090",
    [int]$BatchSize = 20,
    [int]$TimeoutSec = 5
)

$ProgressPreference = 'SilentlyContinue'

$Endpoints = @(
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
    @{ Method = "POST"; Path = "/api/gpu/toggle"; Category = "GPU"; ExpectedStatus = 200; Body = '{"enabled":true}' }
)

function Test-Endpoint {
    param($Endpoint)
    $url = "$BaseUrl$($Endpoint.Path)"
    $startTime = Get-Date
    try {
        $headers = @{ "Content-Type" = "application/json" }
        $body = $Endpoint.Body
        if ($Endpoint.Method -eq "GET") {
            $response = Invoke-WebRequest -Uri $url -Method GET -Headers $headers -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
        } else {
            $response = Invoke-WebRequest -Uri $url -Method $Endpoint.Method -Headers $headers -Body $body -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
        }
        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        $status = if ($response.StatusCode -eq $Endpoint.ExpectedStatus) { "PASS" } else { "UNEXPECTED" }
        return @{ Path = $Endpoint.Path; Method = $Endpoint.Method; Category = $Endpoint.Category; Status = $status; HttpStatus = $response.StatusCode; ExpectedStatus = $Endpoint.ExpectedStatus; Duration = [math]::Round($duration, 2); Error = $null }
    }
    catch {
        $duration = ((Get-Date) - $startTime).TotalMilliseconds
        $httpStatus = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        $status = if ($httpStatus -eq $Endpoint.ExpectedStatus) { "PASS" } else { "FAIL" }
        return @{ Path = $Endpoint.Path; Method = $Endpoint.Method; Category = $Endpoint.Category; Status = $status; HttpStatus = $httpStatus; ExpectedStatus = $Endpoint.ExpectedStatus; Duration = [math]::Round($duration, 2); Error = $_.Exception.Message }
    }
}

Write-Host ""
Write-Host "RawrXD Endpoint Validator v1.0 (Clean)"
Write-Host "======================================"
Write-Host "Target: $BaseUrl"
Write-Host "Total Endpoints: $($Endpoints.Count)"
Write-Host "Batch Size: $BatchSize"
Write-Host ""

$numBatches = [math]::Ceiling($Endpoints.Count / $BatchSize)
Write-Host "Processing $numBatches batches..."

$allResults = @()
$totalPass = 0
$totalFail = 0

for ($batchNum = 1; $batchNum -le $numBatches; $batchNum++) {
    $startIdx = ($batchNum - 1) * $BatchSize
    $endIdx = [math]::Min($startIdx + $BatchSize - 1, $Endpoints.Count - 1)
    $batchEndpoints = $Endpoints[$startIdx..$endIdx]
    
    Write-Host ""
    Write-Host "=========================================="
    Write-Host "BATCH $batchNum - $($batchEndpoints.Count) endpoints"
    Write-Host "=========================================="
    
    $batchResults = @()
    $passCount = 0
    $failCount = 0
    
    for ($i = 0; $i -lt $batchEndpoints.Count; $i++) {
        $endpoint = $batchEndpoints[$i]
        $percent = [math]::Round((($i + 1) / $batchEndpoints.Count) * 100, 0)
        Write-Host "[$percent%] $($endpoint.Method) $($endpoint.Path) " -NoNewline
        
        $result = Test-Endpoint -Endpoint $endpoint
        $batchResults += $result
        
        if ($result.Status -eq "PASS") { 
            $passCount++ 
            Write-Host "PASS ($($result.Duration)ms)"
        } else { 
            $failCount++ 
            Write-Host "FAIL ($($result.Duration)ms) [HTTP $($result.HttpStatus)]"
        }
    }
    
    Write-Host ""
    Write-Host "------------------------------------------"
    Write-Host "BATCH $batchNum SUMMARY"
    Write-Host "------------------------------------------"
    
    foreach ($result in $batchResults) {
        $icon = if ($result.Status -eq "PASS") { "[PASS]" } else { "[FAIL]" }
        Write-Host "  $icon [$($result.Method)] $($result.Path) - $($result.Duration)ms"
    }
    
    Write-Host ""
    Write-Host "Total: $($batchResults.Count) | Passed: $passCount | Failed: $failCount"
    
    $allResults += $batchResults
    $totalPass += $passCount
    $totalFail += $failCount
    
    if ($failCount -eq 0) {
        Write-Host "BATCH $batchNum COMPLETE - All passed!"
    } else {
        Write-Host "BATCH $batchNum COMPLETE - $failCount failed"
    }
}

Write-Host ""
Write-Host "=========================================="
Write-Host "FINAL VALIDATION REPORT"
Write-Host "=========================================="

$categories = $allResults | Group-Object -Property Category | Sort-Object Name
Write-Host ""
Write-Host "Category Breakdown:"
Write-Host "------------------------------------------"

foreach ($cat in $categories) {
    $catPass = ($cat.Group | Where-Object { $_.Status -eq "PASS" }).Count
    $catFail = ($cat.Group | Where-Object { $_.Status -ne "PASS" }).Count
    $catTotal = $cat.Group.Count
    $percent = [math]::Round(($catPass / $catTotal) * 100, 1)
    Write-Host "  $($cat.Name.PadRight(15)) : $catPass/$catTotal passed ($percent%)"
}

Write-Host ""
Write-Host "------------------------------------------"
Write-Host "Overall Statistics:"
Write-Host "------------------------------------------"
Write-Host "  Total Endpoints: $($allResults.Count)"
Write-Host "  Passed: $totalPass"
Write-Host "  Failed: $totalFail"
$successRate = [math]::Round(($totalPass / $allResults.Count) * 100, 1)
Write-Host "  Success Rate: $successRate%"

Write-Host ""
if ($totalFail -eq 0) {
    Write-Host "=========================================="
    Write-Host "ALL ENDPOINTS VALIDATED SUCCESSFULLY!"
    Write-Host "=========================================="
} else {
    Write-Host "=========================================="
    Write-Host "VALIDATION COMPLETE WITH FAILURES"
    Write-Host "=========================================="
    Write-Host ""
    Write-Host "Failed Endpoints:"
    $failed = $allResults | Where-Object { $_.Status -ne "PASS" }
    foreach ($f in $failed) {
        Write-Host "  [FAIL] [$($f.Method)] $($f.Path) - HTTP $($f.HttpStatus)"
    }
}

Write-Host ""
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "d:\RawrXD\endpoint_validation_$timestamp.json"
$allResults | ConvertTo-Json -Depth 3 | Out-File $outputFile
Write-Host "Results exported to: $outputFile"

exit $(if ($totalFail -eq 0) { 0 } else { 1 })
