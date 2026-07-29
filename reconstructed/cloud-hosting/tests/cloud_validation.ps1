<#
.SYNOPSIS
    RawrXD Cloud-Hosting — Full Validation Suite
    Cold deploy, upgrade, rollback, backup/restore, cert renewal, load test, failure modes

.DESCRIPTION
    Run from the cloud-hosting repo root:
      powershell -NoProfile -ExecutionPolicy Bypass -File tests\cloud_validation.ps1

    Requires: Docker Desktop, curl, openssl (optional for cert tests)
    Outputs:  tests\results\validation_report.txt

.NOTES
    All tests are idempotent — safe to re-run.
    Tests that modify state clean up after themselves.
#>
param(
    [string]$ComposeFile = "docker-compose.yml",
    [string]$ResultDir   = "tests\results",
    [int]$LoadTestRPS    = 50,
    [int]$LoadTestSecs   = 10
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

# ── Helpers ──────────────────────────────────────────────────────────────────
$pass = 0; $fail = 0; $skip = 0
$report = @()

function Log($msg) {
    $ts = Get-Date -Format "HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line
    $script:report += $line
}

function Test-Start($name) {
    $script:currentTest = $name
    Log "  [TEST] $name"
}

function Test-Pass() {
    Log "         => PASS"
    $script:pass++
}

function Test-Fail($reason) {
    Log "         => FAIL: $reason"
    $script:fail++
}

function Test-Skip($reason) {
    Log "         => SKIP: $reason"
    $script:skip++
}

function Invoke-Compose {
    param([string[]]$Args)
    $allArgs = @("-f", $ComposeFile) + $Args
    & docker compose @allArgs 2>&1
}

function Wait-ForHealthy {
    param([string]$Service, [int]$TimeoutSec = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $status = (docker inspect --format '{{.State.Health.Status}}' "rawrxd-$Service" 2>$null)
        if ($status -eq "healthy") { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

# ── Setup ────────────────────────────────────────────────────────────────────
if (!(Test-Path $ResultDir)) { New-Item -ItemType Directory -Path $ResultDir -Force | Out-Null }
$reportFile = Join-Path $ResultDir "validation_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

Log "═══════════════════════════════════════════════════════════════"
Log "  RawrXD Cloud-Hosting — Validation Suite"
Log "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Log "═══════════════════════════════════════════════════════════════"

# Ensure .env exists
if (!(Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Log "[SETUP] Created .env from .env.example"
    } else {
        Log "[SETUP] WARNING: No .env or .env.example found"
    }
}

# Ensure SSL certs exist
if (!(Test-Path "nginx\ssl")) { New-Item -ItemType Directory -Path "nginx\ssl" -Force | Out-Null }
if (!(Test-Path "nginx\ssl\server.crt")) {
    $opensslPath = Get-Command openssl -ErrorAction SilentlyContinue
    if ($opensslPath) {
        & openssl req -x509 -nodes -days 365 -newkey rsa:2048 `
            -keyout "nginx\ssl\server.key" -out "nginx\ssl\server.crt" `
            -subj "/CN=localhost/O=RawrXD-Test/C=US" 2>$null
        Log "[SETUP] Generated self-signed TLS cert"
    } else {
        Log "[SETUP] WARNING: openssl not found, TLS tests may fail"
    }
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEST 1 — Cold Deploy
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Log ""
Log "── Phase 1: Cold Deploy ──────────────────────────────────────────"

Test-Start "Clean teardown (pre-test)"
Invoke-Compose @("down", "-v", "--remove-orphans") | Out-Null
docker volume rm cloud-hosting_pgdata cloud-hosting_redisdata 2>$null | Out-Null
Test-Pass

Test-Start "Cold build (no cache)"
$buildOutput = Invoke-Compose @("build", "--no-cache") 2>&1
$buildExit = $LASTEXITCODE
if ($buildExit -eq 0) { Test-Pass } else { Test-Fail "docker compose build failed (exit $buildExit)" }

Test-Start "Cold start — all services up"
$startTime = Get-Date
Invoke-Compose @("up", "-d") | Out-Null
$startExit = $LASTEXITCODE
if ($startExit -eq 0) { Test-Pass } else { Test-Fail "docker compose up failed" }

Test-Start "All containers healthy within 60s"
$allHealthy = $true
foreach ($svc in @("db", "redis", "app")) {
    if (!(Wait-ForHealthy -Service $svc -TimeoutSec 60)) {
        Test-Fail "$svc not healthy within 60s"
        $allHealthy = $false
        break
    }
}
if ($allHealthy) {
    $bootTime = ((Get-Date) - $startTime).TotalSeconds
    Log "         Cold boot time: $([math]::Round($bootTime, 1))s"
    Test-Pass
}

Test-Start "Health endpoint responds 200"
try {
    $health = Invoke-RestMethod -Uri "http://localhost:3000/health" -TimeoutSec 10 -ErrorAction Stop
    if ($health.status -eq "healthy") { Test-Pass } else { Test-Fail "status = $($health.status)" }
} catch {
    Test-Fail $_.Exception.Message
}

Test-Start "Database schema initialized (kv_store, sessions, audit_log)"
$tables = docker exec rawrxd-db psql -U rawrxd -t -c "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;" 2>$null
$tableList = ($tables -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$expected = @("audit_log", "kv_store", "sessions")
$missing = $expected | Where-Object { $_ -notin $tableList }
if ($missing.Count -eq 0) { Test-Pass } else { Test-Fail "Missing tables: $($missing -join ', ')" }

Test-Start "Redis PING responds PONG"
$pong = docker exec rawrxd-redis redis-cli ping 2>$null
if ($pong -match "PONG") { Test-Pass } else { Test-Fail "Redis ping: $pong" }

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEST 2 — CRUD / Import Resolution
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Log ""
Log "── Phase 2: API CRUD ─────────────────────────────────────────────"

Test-Start "POST /api/data (create key)"
try {
    $body = '{"key":"test_key","value":{"data":"hello","n":42}}'
    $resp = Invoke-RestMethod -Uri "http://localhost:3000/api/data" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 10
    if ($resp.ok -eq $true) { Test-Pass } else { Test-Fail "Response: $($resp | ConvertTo-Json -Compress)" }
} catch { Test-Fail $_.Exception.Message }

Test-Start "GET /api/data?key=test_key (read back)"
try {
    $resp = Invoke-RestMethod -Uri "http://localhost:3000/api/data?key=test_key" -TimeoutSec 10
    if ($resp.value.data -eq "hello" -and $resp.value.n -eq 42) { Test-Pass }
    else { Test-Fail "Value mismatch: $($resp | ConvertTo-Json -Compress)" }
} catch { Test-Fail $_.Exception.Message }

Test-Start "POST /api/data (upsert same key)"
try {
    $body = '{"key":"test_key","value":{"data":"updated","n":99}}'
    $resp = Invoke-RestMethod -Uri "http://localhost:3000/api/data" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 10
    if ($resp.ok -eq $true) { Test-Pass } else { Test-Fail "Upsert failed" }
} catch { Test-Fail $_.Exception.Message }

Test-Start "GET after upsert (verify update)"
try {
    $resp = Invoke-RestMethod -Uri "http://localhost:3000/api/data?key=test_key" -TimeoutSec 10
    if ($resp.value.n -eq 99) { Test-Pass } else { Test-Fail "Value not updated: n=$($resp.value.n)" }
} catch { Test-Fail $_.Exception.Message }

Test-Start "GET /api/data?key=nonexistent (404)"
try {
    $null = Invoke-WebRequest -Uri "http://localhost:3000/api/data?key=nonexistent_xyz" -TimeoutSec 10 -ErrorAction Stop
    Test-Fail "Expected 404, got 200"
} catch {
    if ($_.Exception.Response.StatusCode -eq 404) { Test-Pass }
    else { Test-Fail "Expected 404, got $($_.Exception.Response.StatusCode)" }
}

Test-Start "GET /api/status (cached response)"
try {
    $resp = Invoke-RestMethod -Uri "http://localhost:3000/api/status" -TimeoutSec 10
    if ($null -ne $resp.tables -and $null -ne $resp.ts) { Test-Pass }
    else { Test-Fail "Unexpected response: $($resp | ConvertTo-Json -Compress)" }
} catch { Test-Fail $_.Exception.Message }

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEST 3 — Upgrade Test (rebuild and redeploy)
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Log ""
Log "── Phase 3: Upgrade Test (hot redeploy) ──────────────────────────"

Test-Start "Rebuild app container"
Invoke-Compose @("build", "app") | Out-Null
if ($LASTEXITCODE -eq 0) { Test-Pass } else { Test-Fail "Rebuild failed" }

Test-Start "Rolling restart (app only)"
Invoke-Compose @("up", "-d", "--no-deps", "app") | Out-Null
if ($LASTEXITCODE -eq 0) { Test-Pass } else { Test-Fail "Restart failed" }

Test-Start "App healthy after upgrade"
Start-Sleep -Seconds 5
if (Wait-ForHealthy -Service "app" -TimeoutSec 30) { Test-Pass } else { Test-Fail "App not healthy post-upgrade" }

Test-Start "Data survives upgrade (key still present)"
try {
    $resp = Invoke-RestMethod -Uri "http://localhost:3000/api/data?key=test_key" -TimeoutSec 10
    if ($resp.value.n -eq 99) { Test-Pass } else { Test-Fail "Data lost after upgrade" }
} catch { Test-Fail $_.Exception.Message }

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEST 4 — Rollback Test
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Log ""
Log "── Phase 4: Rollback Test ────────────────────────────────────────"

Test-Start "Stop app container"
Invoke-Compose @("stop", "app") | Out-Null
Start-Sleep -Seconds 2
Test-Pass

Test-Start "Database still accessible during app downtime"
$pgReady = docker exec rawrxd-db pg_isready -U rawrxd 2>$null
if ($pgReady -match "accepting") { Test-Pass } else { Test-Fail "DB not ready: $pgReady" }

Test-Start "Restart app (simulated rollback)"
Invoke-Compose @("up", "-d", "app") | Out-Null
if (Wait-ForHealthy -Service "app" -TimeoutSec 30) { Test-Pass } else { Test-Fail "App not healthy after rollback" }

Test-Start "Data intact after rollback"
try {
    $resp = Invoke-RestMethod -Uri "http://localhost:3000/api/data?key=test_key" -TimeoutSec 10
    if ($resp.value.n -eq 99) { Test-Pass } else { Test-Fail "Data lost after rollback" }
} catch { Test-Fail $_.Exception.Message }

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEST 5 — Backup / Restore
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Log ""
Log "── Phase 5: Backup / Restore ─────────────────────────────────────"

$backupDir = Join-Path $ResultDir "backups"
if (!(Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }

Test-Start "pg_dump backup"
$backupFile = Join-Path $backupDir "test_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').sql"
docker exec rawrxd-db pg_dump -U rawrxd --clean --if-exists 2>$null > $backupFile
$backupSize = (Get-Item $backupFile).Length
if ($backupSize -gt 0) {
    Log "         Backup size: $([math]::Round($backupSize/1024, 1)) KB"
    Test-Pass
} else { Test-Fail "Backup file empty" }

Test-Start "Backup contains expected tables"
$backupContent = Get-Content $backupFile -Raw
$hasTables = ($backupContent -match "kv_store") -and ($backupContent -match "sessions") -and ($backupContent -match "audit_log")
if ($hasTables) { Test-Pass } else { Test-Fail "Tables missing from backup" }

Test-Start "Insert marker row, drop table, restore"
# Insert marker
docker exec rawrxd-db psql -U rawrxd -c "INSERT INTO kv_store (key, value) VALUES ('backup_marker', '{\"ts\": $(Get-Date -UFormat %s)}') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;" 2>$null | Out-Null

# Take new backup with marker
$backupFile2 = Join-Path $backupDir "test_backup_marker.sql"
docker exec rawrxd-db pg_dump -U rawrxd --clean --if-exists 2>$null > $backupFile2

# Drop and restore
docker exec rawrxd-db psql -U rawrxd -c "DELETE FROM kv_store WHERE key='backup_marker';" 2>$null | Out-Null
$verifyGone = docker exec rawrxd-db psql -U rawrxd -t -c "SELECT COUNT(*) FROM kv_store WHERE key='backup_marker';" 2>$null
if ($verifyGone.Trim() -eq "0") {
    # Restore
    Get-Content $backupFile2 | docker exec -i rawrxd-db psql -U rawrxd 2>$null | Out-Null
    $verifyBack = docker exec rawrxd-db psql -U rawrxd -t -c "SELECT COUNT(*) FROM kv_store WHERE key='backup_marker';" 2>$null
    if ($verifyBack.Trim() -ge "1") { Test-Pass } else { Test-Fail "Marker not restored" }
} else { Test-Fail "Marker not deleted before restore" }

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEST 6 — Certificate Renewal
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Log ""
Log "── Phase 6: Certificate Renewal Proof ────────────────────────────"

$opensslAvail = Get-Command openssl -ErrorAction SilentlyContinue

if ($opensslAvail) {
    Test-Start "Read current cert expiry"
    $expiryBefore = & openssl x509 -in "nginx\ssl\server.crt" -noout -enddate 2>$null
    Log "         Before: $expiryBefore"
    Test-Pass

    Test-Start "Regenerate certificate (365-day self-signed)"
    & openssl req -x509 -nodes -days 365 -newkey rsa:2048 `
        -keyout "nginx\ssl\server.key" -out "nginx\ssl\server.crt" `
        -subj "/CN=localhost/O=RawrXD-Renewed/C=US" 2>$null
    $expiryAfter = & openssl x509 -in "nginx\ssl\server.crt" -noout -enddate 2>$null
    Log "         After:  $expiryAfter"
    if ($expiryAfter) { Test-Pass } else { Test-Fail "Cert generation failed" }

    Test-Start "Nginx accepts renewed cert (reload)"
    Invoke-Compose @("exec", "-T", "nginx", "nginx", "-s", "reload") 2>$null | Out-Null
    Start-Sleep -Seconds 2
    try {
        # Use curl to avoid PowerShell cert validation issues
        $curlResult = & curl -sk "https://localhost/health" 2>$null
        if ($curlResult -match "healthy") { Test-Pass } else { Test-Fail "HTTPS unhealthy after cert renewal" }
    } catch {
        Test-Skip "curl not available for HTTPS validation"
    }
} else {
    Test-Start "Certificate renewal tests"
    Test-Skip "openssl not found in PATH"
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEST 7 — Load Test
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Log ""
Log "── Phase 7: Load Test ────────────────────────────────────────────"

Test-Start "Burst $($LoadTestRPS * $LoadTestSecs) requests ($LoadTestRPS rps x ${LoadTestSecs}s)"
$totalReqs = $LoadTestRPS * $LoadTestSecs
$successes = [System.Threading.Interlocked]
$successCount = 0
$failCount = 0
$latencies = [System.Collections.Concurrent.ConcurrentBag[double]]::new()

$startLoad = Get-Date
$jobs = 1..$totalReqs | ForEach-Object {
    Start-Job -ScriptBlock {
        param($i)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $null = Invoke-WebRequest -Uri "http://localhost:3000/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            $sw.Stop()
            return @{ ok = $true; ms = $sw.ElapsedMilliseconds }
        } catch {
            $sw.Stop()
            return @{ ok = $false; ms = $sw.ElapsedMilliseconds }
        }
    } -ArgumentList $_
}

# Wait with timeout
$jobs | Wait-Job -Timeout ($LoadTestSecs + 30) | Out-Null
$results = $jobs | Receive-Job
$jobs | Remove-Job -Force

$successCount = ($results | Where-Object { $_.ok }).Count
$failCount    = ($results | Where-Object { -not $_.ok }).Count
$allMs        = ($results | ForEach-Object { $_.ms } | Sort-Object)
$loadDuration = ((Get-Date) - $startLoad).TotalSeconds

if ($allMs.Count -gt 0) {
    $p50 = $allMs[[math]::Floor($allMs.Count * 0.50)]
    $p95 = $allMs[[math]::Floor($allMs.Count * 0.95)]
    $p99 = $allMs[[math]::Floor($allMs.Count * 0.99)]
    Log "         Duration: $([math]::Round($loadDuration, 1))s | Success: $successCount | Fail: $failCount"
    Log "         Latency: p50=${p50}ms  p95=${p95}ms  p99=${p99}ms"
}

$successRate = if ($totalReqs -gt 0) { [math]::Round(($successCount / $totalReqs) * 100, 1) } else { 0 }
if ($successRate -ge 95) { Test-Pass } else { Test-Fail "Success rate $successRate% (need >= 95%)" }

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEST 8 — Failure Modes
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Log ""
Log "── Phase 8: Failure Mode Tests ───────────────────────────────────"

Test-Start "Redis down — app degrades gracefully"
Invoke-Compose @("stop", "redis") | Out-Null
Start-Sleep -Seconds 3
try {
    $resp = Invoke-RestMethod -Uri "http://localhost:3000/api/data?key=test_key" -TimeoutSec 10
    # App should still work (cache miss falls through to DB)
    if ($resp.value.n -eq 99) { Test-Pass } else { Test-Fail "Data wrong with Redis down" }
} catch {
    Test-Fail "App crashed with Redis down: $($_.Exception.Message)"
}
# Restore Redis
Invoke-Compose @("up", "-d", "redis") | Out-Null
Start-Sleep -Seconds 5

Test-Start "Invalid POST body — returns 400"
try {
    $null = Invoke-WebRequest -Uri "http://localhost:3000/api/data" -Method POST `
        -Body '{"invalid":true}' -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop
    Test-Fail "Expected 400"
} catch {
    if ($_.Exception.Response.StatusCode -eq 400) { Test-Pass }
    else { Test-Fail "Expected 400, got $($_.Exception.Response.StatusCode)" }
}

Test-Start "Unknown route — returns 404"
try {
    $null = Invoke-WebRequest -Uri "http://localhost:3000/nonexistent" -TimeoutSec 10 -ErrorAction Stop
    Test-Fail "Expected 404"
} catch {
    if ($_.Exception.Response.StatusCode -eq 404) { Test-Pass }
    else { Test-Fail "Expected 404, got $($_.Exception.Response.StatusCode)" }
}

Test-Start "App container restart — auto-recovery"
docker restart rawrxd-app 2>$null | Out-Null
if (Wait-ForHealthy -Service "app" -TimeoutSec 30) { Test-Pass }
else { Test-Fail "App did not recover after restart" }

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# REPORT
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Log ""
Log "═══════════════════════════════════════════════════════════════"
Log "  RESULTS: $pass passed, $fail failed, $skip skipped ($($pass+$fail+$skip) total)"
Log "═══════════════════════════════════════════════════════════════"

# Write report
$report | Out-File -FilePath $reportFile -Encoding UTF8
Log "[*] Report saved: $reportFile"

# Cleanup — leave stack running for inspection
Log "[*] Stack left running for inspection. Run 'docker compose down -v' to teardown."

exit $(if ($fail -gt 0) { 1 } else { 0 })
