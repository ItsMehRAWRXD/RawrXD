param(
    [string]$Root = "F:\~dev",
    [string]$OutDir = "F:\~dev\evidence\SCREENPILOT_LOCAL_AGENT_E2E_001"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$extensions = @("*.cpp","*.c","*.cc","*.h","*.hpp","*.inl","*.cmake","CMakeLists.txt")
$skip = '\\(build|build_p2|node_modules|\.git|evidence|models?|third_party|_deps)\\'

Write-Host "=== SCREENPILOT_LOCAL_AGENT_E2E_001 SOURCE LOCATOR ===" -ForegroundColor Cyan
Write-Host "Root: $Root"

$files = Get-ChildItem $Root -Recurse -File -Include $extensions -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch $skip }

Write-Host ("Source files scanned: {0}" -f $files.Count)

$patterns = [ordered]@{
    LocalServerNames = 'Win32IDE_LocalServer|tool_server|LocalServer'
    Port11435        = '11435'
    HttpRoutes       = '/api/cli|/api/status|/health|/status|/api/read-file|HTTP/1\.1'
    SocketServer     = '\bbind\s*\(|\blisten\s*\(|\baccept\s*\(|WSAStartup|sockaddr_in'
    CanonAuthority   = 'AgentToolSurface::LocalServer|AgentToolAuthority\(|TryAgentToolAuthority|BindAgentToolAuthority'
    AgentRuntime     = 'AgenticRuntime|run_agent_session|StartAgentLoop|ExecuteAgentCommand'
    LegacyProviders  = 'RegisterLegacyRawrXDToolProviders|LegacyRawrXDToolProviders'
    DirectExec       = 'CreateProcess[A-Z]*\s*\(|ShellExecute[A-Z]*\s*\(|WinExec\s*\(|_popen\s*\(|\bsystem\s*\('
}

$summary = [ordered]@{}

foreach ($name in $patterns.Keys) {
    Write-Host "`n--- $name ---" -ForegroundColor Yellow
    $matches = $files | Select-String -Pattern $patterns[$name] -ErrorAction SilentlyContinue
    $summary[$name] = @($matches).Count
    $matches |
        Select-Object Path,LineNumber,Line |
        Export-Csv (Join-Path $OutDir "$name.csv") -NoTypeInformation -Encoding UTF8
    $matches | Select-Object -First 30 | ForEach-Object {
        "{0}:{1}: {2}" -f $_.Path,$_.LineNumber,$_.Line.Trim()
    }
}

# Exact blocker checks found in the public/default branch audit.
$rawrAgent = Join-Path $Root "src\rawr_agent.cpp"
if (-not (Test-Path $rawrAgent)) { $rawrAgent = Join-Path $Root "~dev\src\rawr_agent.cpp" }

$agentBridge = Join-Path $Root "src\win32app\Win32IDE_AgenticBridge.cpp"
if (-not (Test-Path $agentBridge)) { $agentBridge = Join-Path $Root "~dev\rawrxd\src\win32app\Win32IDE_AgenticBridge.cpp" }

$checks = [ordered]@{}

if (Test-Path $rawrAgent) {
    $txt = Get-Content $rawrAgent -Raw
    $checks["RAWR_AGENT_STACK_LOCAL_AUTHORITY"] =
        ($txt -match 'AgentToolRegistry\s+authority\s*;' -and
         $txt -match 'BindAgentToolAuthority\s*\(\s*authority\s*\)')
    $checks["RAWR_AGENT_HARDCODED_AGENTCORE"] =
        ($txt -match 'request\.surface\s*=\s*AgentToolSurface::AgentCore')
    $checks["RAWR_AGENT_LOOPCERT_DEFAULT_FOR_NONAUDIT"] =
        ($txt -match 'kLoopCertSystemPrompt')
} else {
    $checks["RAWR_AGENT_SOURCE_FOUND"] = $false
}

if (Test-Path $agentBridge) {
    $txt = Get-Content $agentBridge -Raw
    $checks["WIN32_AGENT_LOOP_STUB"] =
        ($txt -match 'StartAgentLoop[^{]*\{[^}]*return\s+false\s*;')
    $checks["WIN32_DEPRECATED_SUCCESS_STUBS"] =
        ($txt -match 'SpawnPowerShellProcess[^{]*\{[^}]*return\s+true\s*;' -or
         $txt -match 'ReadProcessOutput[^{]*\{[^}]*return\s+true\s*;')
} else {
    $checks["WIN32_AGENTIC_BRIDGE_FOUND"] = $false
}

# Identify strongest :11435 candidates.
$serverCandidates = @()
$portMatches = $files | Select-String -Pattern '11435' -ErrorAction SilentlyContinue
foreach ($m in $portMatches) {
    $score = 1
    $body = Get-Content $m.Path -Raw -ErrorAction SilentlyContinue
    if ($body -match '\bbind\s*\(') { $score += 3 }
    if ($body -match '\blisten\s*\(') { $score += 3 }
    if ($body -match '\baccept\s*\(') { $score += 2 }
    if ($body -match '/api/cli|/api/status|/health|/status') { $score += 4 }
    if ($body -match 'AgentToolSurface::LocalServer') { $score += 4 }
    $serverCandidates += [pscustomobject]@{
        Score = $score
        Path  = $m.Path
        Line  = $m.LineNumber
        Text  = $m.Line.Trim()
    }
}
$serverCandidates = $serverCandidates | Sort-Object Score -Descending -Unique
$serverCandidates | Export-Csv (Join-Path $OutDir "SERVER_CANDIDATES.csv") -NoTypeInformation -Encoding UTF8

# Missing-source references from CMake/comments are useful evidence too.
$referencedMissing = @()
$refs = $files | Select-String -Pattern 'Win32IDE_LocalServer\.cpp|tool_server\.cpp|RawrXD_AgentLoop\.cpp|BoundedAgentLoop\.cpp' -ErrorAction SilentlyContinue
foreach ($r in $refs) {
    $name = [regex]::Match($r.Line,'(?:Win32IDE_LocalServer|tool_server|RawrXD_AgentLoop|BoundedAgentLoop)\.cpp').Value
    if ($name) {
        $hits = Get-ChildItem $Root -Recurse -File -Filter $name -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch $skip }
        $referencedMissing += [pscustomobject]@{
            Name = $name
            ReferencedBy = $r.Path
            ReferenceLine = $r.LineNumber
            Found = (@($hits).Count -gt 0)
            FoundPaths = (@($hits.FullName) -join ';')
        }
    }
}
$referencedMissing | Sort-Object Name,ReferencedBy -Unique |
    Export-Csv (Join-Path $OutDir "REFERENCED_SOURCE_STATUS.csv") -NoTypeInformation -Encoding UTF8

$report = [ordered]@{
    Timestamp = (Get-Date).ToString("o")
    Root = $Root
    SourceFileCount = $files.Count
    MatchCounts = $summary
    Checks = $checks
    TopServerCandidates = @($serverCandidates | Select-Object -First 20)
}
$report | ConvertTo-Json -Depth 8 |
    Set-Content (Join-Path $OutDir "locator_report.json") -Encoding UTF8

Write-Host "`n=== BLOCKER CHECKS ===" -ForegroundColor Cyan
foreach ($k in $checks.Keys) {
    $v = $checks[$k]
    if ($v) {
        Write-Host "$k=FAIL_PRESENT" -ForegroundColor Red
    } else {
        Write-Host "$k=NOT_DETECTED" -ForegroundColor Green
    }
}

Write-Host "`n=== TOP :11435 SERVER CANDIDATES ===" -ForegroundColor Cyan
$serverCandidates | Select-Object -First 20 | Format-Table Score,Path,Line,Text -AutoSize

if (@($serverCandidates).Count -eq 0) {
    Write-Host "SCREENPILOT_LOCALSERVER_SOURCE=HOLD_NOT_FOUND" -ForegroundColor Yellow
} else {
    Write-Host "SCREENPILOT_LOCALSERVER_SOURCE=CANDIDATES_FOUND" -ForegroundColor Green
}

Write-Host "SCREENPILOT_LOCAL_LOCATOR=PASS" -ForegroundColor Green
Write-Host "Evidence: $OutDir"
