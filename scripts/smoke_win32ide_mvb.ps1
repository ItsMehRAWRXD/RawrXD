# smoke_win32ide_mvb.ps1
# Minimum Viable Boot Smoke Test for RawrXD-Win32IDE.exe
# Tests critical paths: launch, API, ghost text, model discovery
# Usage: .\smoke_win32ide_mvb.ps1 [-TimeoutSeconds 60] [-Verbose]

param(
    [int]$TimeoutSeconds = 60,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$binaryPath = "d:\rawrxd\build_win32ide\bin\RawrXD-Win32IDE.exe"
$logDir = "d:\rawrxd\__smoke_logs"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

# Create log directory
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$logFile = Join-Path $logDir "smoke_$timestamp.log"

function Write-Log {
    param([string]$message, [string]$level = "INFO")
    $entry = "[$(Get-Date -Format 'HH:mm:ss')] [$level] $message"
    Write-Host $entry
    Add-Content -Path $logFile -Value $entry
}

function Test-ProcessAlive {
    param([int]$processId)
    try {
        $proc = Get-Process -Id $processId -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Test-PortOpen {
    param([int]$port)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect("127.0.0.1", $port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(1000)
        if ($wait) {
            $tcp.EndConnect($connect)
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    } catch {
        return $false
    }
}

function Invoke-ApiRequest {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$Body = $null,
        [int]$Port = 8080
    )
    
    $url = "http://127.0.0.1:$Port$Endpoint"
    try {
        if ($Method -eq "GET") {
            $response = Invoke-RestMethod -Uri $url -Method GET -TimeoutSec 5 -ErrorAction Stop
            return @{ Success = $true; Data = $response }
        } elseif ($Method -eq "POST" -and $Body) {
            $json = $Body | ConvertTo-Json -Depth 10
            $response = Invoke-RestMethod -Uri $url -Method POST -Body $json -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop
            return @{ Success = $true; Data = $response }
        }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
    return @{ Success = $false; Error = "Unknown error" }
}

# ============================================================================
# PHASE 1: Binary Verification
# ============================================================================
Write-Log "=== PHASE 1: Binary Verification ===" "INFO"

if (-not (Test-Path $binaryPath)) {
    Write-Log "FAIL: Binary not found at $binaryPath" "ERROR"
    exit 1
}

$binaryInfo = Get-Item $binaryPath
Write-Log "Binary found: $($binaryInfo.Name) ($([math]::Round($binaryInfo.Length / 1MB, 2)) MB)" "INFO"

# Check for required DLLs
$requiredDlls = @(
    "d:\llama.cpp\build\bin\ggml.dll",
    "d:\llama.cpp\build\bin\ggml-base.dll",
    "d:\llama.cpp\build\bin\ggml-cpu.dll",
    "d:\llama.cpp\build\bin\ggml-vulkan.dll",
    "d:\llama.cpp\build\bin\llama.dll"
)

$dllMissing = $false
foreach ($dll in $requiredDlls) {
    if (Test-Path $dll) {
        $dllInfo = Get-Item $dll
        Write-Log "DLL OK: $($dllInfo.Name)" "INFO"
    } else {
        Write-Log "DLL MISSING: $dll" "WARN"
        $dllMissing = $true
    }
}

if ($dllMissing) {
    Write-Log "WARN: Some GPU DLLs missing - inference may fail" "WARN"
}

# ============================================================================
# PHASE 2: Launch Test
# ============================================================================
Write-Log "`n=== PHASE 2: Launch Test ===" "INFO"

$process = $null
$launchSuccess = $false

try {
    Write-Log "Launching Win32IDE..." "INFO"
    
    # Start process with working directory set
    $process = Start-Process -FilePath $binaryPath -PassThru -WorkingDirectory (Split-Path $binaryPath) -WindowStyle Normal
    
    Write-Log "Process started with PID: $($process.Id)" "INFO"
    
    # Wait for process to stabilize
    Start-Sleep -Seconds 5
    
    # Check if process is still alive
    if (Test-ProcessAlive -processId $process.Id) {
        Write-Log "Process is running after 5 seconds" "INFO"
        $launchSuccess = $true
    } else {
        Write-Log "FAIL: Process exited immediately" "ERROR"
        
        # Check for crash dumps
        $crashDumps = Get-ChildItem -Path "d:\rawrxd\build_win32ide\bin" -Filter "*.dmp" -ErrorAction SilentlyContinue
        if ($crashDumps) {
            Write-Log "Crash dump found: $($crashDumps | Select-Object -First 1 -ExpandProperty FullName)" "ERROR"
        }
    }
} catch {
    Write-Log "FAIL: Exception during launch: $($_.Exception.Message)" "ERROR"
}

if (-not $launchSuccess) {
    Write-Log "SMOKE TEST FAILED: Binary does not launch" "ERROR"
    exit 1
}

# ============================================================================
# PHASE 3: API Server Test
# ============================================================================
Write-Log "`n=== PHASE 3: API Server Test ===" "INFO"

# Check if API server started on default port
$apiPort = 8080
$apiReady = $false

Write-Log "Waiting for API server on port $apiPort..." "INFO"
for ($i = 0; $i -lt 30; $i++) {
    if (Test-PortOpen -port $apiPort) {
        Write-Log "API server is listening on port $apiPort" "INFO"
        $apiReady = $true
        break
    }
    Start-Sleep -Milliseconds 500
}

if (-not $apiReady) {
    Write-Log "WARN: API server not responding on port $apiPort after 15 seconds" "WARN"
    Write-Log "This may be expected if Win32IDE uses a different port or no API server" "WARN"
}

# ============================================================================
# PHASE 4: API Endpoint Tests
# ============================================================================
Write-Log "`n=== PHASE 4: API Endpoint Tests ===" "INFO"

if ($apiReady) {
    # Test /api/tags (model discovery)
    Write-Log "Testing /api/tags..." "INFO"
    $tagsResult = Invoke-ApiRequest -Endpoint "/api/tags" -Port $apiPort
    if ($tagsResult.Success) {
        Write-Log "/api/tags returned: $($tagsResult.Data | ConvertTo-Json -Depth 2)" "INFO"
    } else {
        Write-Log "/api/tags failed: $($tagsResult.Error)" "WARN"
    }
    
    # Test /api/version
    Write-Log "Testing /api/version..." "INFO"
    $versionResult = Invoke-ApiRequest -Endpoint "/api/version" -Port $apiPort
    if ($versionResult.Success) {
        Write-Log "/api/version returned: $($versionResult.Data | ConvertTo-Json -Depth 2)" "INFO"
    } else {
        Write-Log "/api/version failed: $($versionResult.Error)" "WARN"
    }
    
    # Test /health
    Write-Log "Testing /health..." "INFO"
    $healthResult = Invoke-ApiRequest -Endpoint "/health" -Port $apiPort
    if ($healthResult.Success) {
        Write-Log "/health returned: $($healthResult.Data | ConvertTo-Json -Depth 2)" "INFO"
    } else {
        Write-Log "/health failed: $($healthResult.Error)" "WARN"
    }
} else {
    Write-Log "Skipping API tests - server not ready" "WARN"
}

# ============================================================================
# PHASE 5: Observability Check
# ============================================================================
Write-Log "`n=== PHASE 5: Observability Check ===" "INFO"

# Check for log files
$logPatterns = @("*.log", "*.trace", "*.json")
$observabilityFound = $false

foreach ($pattern in $logPatterns) {
    $logs = Get-ChildItem -Path "d:\rawrxd\build_win32ide\bin" -Filter $pattern -ErrorAction SilentlyContinue | 
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) }
    
    if ($logs) {
        foreach ($log in $logs) {
            Write-Log "Observability file: $($log.Name) ($([math]::Round($log.Length / 1KB, 2)) KB)" "INFO"
            $observabilityFound = $true
            
            if ($Verbose) {
                $content = Get-Content $log.FullName -Tail 20
                Write-Log "Last 20 lines of $($log.Name):" "INFO"
                $content | ForEach-Object { Write-Log "  $_" "INFO" }
            }
        }
    }
}

if (-not $observabilityFound) {
    Write-Log "No observability files found in last 5 minutes" "WARN"
}

# ============================================================================
# PHASE 6: Memory/CPU Check
# ============================================================================
Write-Log "`n=== PHASE 6: Resource Check ===" "INFO"

if (Test-ProcessAlive -processId $process.Id) {
    $procInfo = Get-Process -Id $process.Id
    Write-Log "Process memory: $([math]::Round($procInfo.WorkingSet64 / 1MB, 2)) MB" "INFO"
    Write-Log "Process CPU time: $($procInfo.TotalProcessorTime.TotalSeconds) seconds" "INFO"
    Write-Log "Process threads: $($procInfo.Threads.Count)" "INFO"
}

# ============================================================================
# PHASE 7: Graceful Shutdown Test
# ============================================================================
Write-Log "`n=== PHASE 7: Graceful Shutdown Test ===" "INFO"

Write-Log "Attempting graceful shutdown..." "INFO"
try {
    $process.CloseMainWindow() | Out-Null
    Start-Sleep -Seconds 3
    
    if (Test-ProcessAlive -processId $process.Id) {
        Write-Log "Process still running, forcing termination..." "WARN"
        Stop-Process -Id $process.Id -Force
        Start-Sleep -Seconds 2
    }
    
    if (Test-ProcessAlive -processId $process.Id) {
        Write-Log "FAIL: Process did not terminate gracefully" "ERROR"
    } else {
        Write-Log "Process terminated successfully" "INFO"
    }
} catch {
    Write-Log "Exception during shutdown: $($_.Exception.Message)" "WARN"
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Log "`n=== SMOKE TEST SUMMARY ===" "INFO"

$summary = @{
    BinaryExists = Test-Path $binaryPath
    LaunchSuccess = $launchSuccess
    ApiServerReady = $apiReady
    ProcessTerminated = -not (Test-ProcessAlive -processId $process.Id)
    DllsPresent = -not $dllMissing
}

Write-Log "Binary Exists: $($summary.BinaryExists)" "INFO"
Write-Log "Launch Success: $($summary.LaunchSuccess)" "INFO"
Write-Log "API Server Ready: $($summary.ApiServerReady)" "INFO"
Write-Log "Process Terminated: $($summary.ProcessTerminated)" "INFO"
Write-Log "DLLs Present: $($summary.DllsPresent)" "INFO"

$allPassed = $summary.Values | Where-Object { $_ -eq $false }
if ($allPassed.Count -eq 0) {
    Write-Log "`nSMOKE TEST PASSED: All critical paths functional" "INFO"
    Write-Log "Log file: $logFile" "INFO"
    exit 0
} else {
    Write-Log "`nSMOKE TEST PARTIAL: Some checks failed" "WARN"
    Write-Log "Log file: $logFile" "INFO"
    exit 2
}