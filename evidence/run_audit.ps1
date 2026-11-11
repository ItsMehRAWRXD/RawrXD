# RAWRXD_SELF_AUDIT_002 runner
# Starts the llama.cpp server, waits for readiness, then runs the agent driver
# against it, and captures everything to a single log.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd'
$ev   = Join-Path $root 'evidence'
$log  = Join-Path $ev 'audit_run.log'

"===== RAWRXD_SELF_AUDIT_002 RUN START $(Get-Date -Format o) =====" |
    Out-File -FilePath $log -Encoding utf8

# --- 1. Start the inference server -----------------------------------------
$serverExe = Join-Path $root 'dist\RawrXD_Enterprise_v3.0\extras\powershield\tools\llama-server.exe'
$modelPath = Join-Path $root 'llama3.2-3b-Q2_K.gguf'
$srvLog    = Join-Path $ev 'llama_server_audit.log'

if (-not (Test-Path -LiteralPath $serverExe)) { "FATAL: server exe missing: $serverExe" | Out-File -FilePath $log -Append -Encoding utf8; exit 10 }
if (-not (Test-Path -LiteralPath $modelPath)) { "FATAL: model missing: $modelPath"    | Out-File -FilePath $log -Append -Encoding utf8; exit 11 }

$srvArgs = @('-m', $modelPath, '--host', '127.0.0.1', '--port', '8080',
             '--no-webui', '--log-file', $srvLog, '--threads', '8',
             '--ctx-size', '8192', '-kvu')
"STARTING SERVER: $serverExe $($srvArgs -join ' ')" | Out-File -FilePath $log -Append -Encoding utf8

$srv = Start-Process -FilePath $serverExe -ArgumentList $srvArgs `
                      -WorkingDirectory $root -PassThru -WindowStyle Hidden
"SERVER_PID=$($srv.Id)" | Out-File -FilePath $log -Append -Encoding utf8

# --- 2. Wait for the server to accept requests (bounded) -------------------
$ready = $false
for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep -Milliseconds 1000
    if ($srv.HasExited) {
        "FATAL: server exited early with code $($srv.ExitCode)" |
            Out-File -FilePath $log -Append -Encoding utf8
        break
    }
    $conn = Test-NetConnection -ComputerName 127.0.0.1 -Port 8080 -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($conn) {
        # Confirm it actually answers an inference request.
        try {
            $body = @{ model='llama3.2-3b'; messages=@(@{role='user';content='ping'}); max_tokens=5 } | ConvertTo-Json -Depth 3
            $resp = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/v1/chat/completions' `
                        -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 30
            "SERVER_READY after $($i+1)s; probe=[$($resp.choices[0].message.content)]" |
                Out-File -FilePath $log -Append -Encoding utf8
            $ready = $true
            break
        } catch {
            # port open but not answering yet; keep waiting
        }
    }
}

if (-not $ready) {
    "FATAL: server never became ready" | Out-File -FilePath $log -Append -Encoding utf8
    if (-not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    exit 20
}

# --- 3. Run the agent driver -------------------------------------------------
$driver = Join-Path $ev 'agent_driver.exe'
if (-not (Test-Path -LiteralPath $driver)) {
    "FATAL: driver missing: $driver" | Out-File -FilePath $log -Append -Encoding utf8
    if (-not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    exit 12
}

"----- AGENT DRIVER OUTPUT -----" | Out-File -FilePath $log -Append -Encoding utf8
& $driver 2>&1 | ForEach-Object { "$_" | Out-File -FilePath $log -Append -Encoding utf8 }
"DRIVER_EXIT_CODE=$LASTEXITCODE" | Out-File -FilePath $log -Append -Encoding utf8

# --- 4. Tidy up ---------------------------------------------------------------
if (-not $srv.HasExited) {
    Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue
    "SERVER_STOPPED" | Out-File -FilePath $log -Append -Encoding utf8
}
"===== RUN END $(Get-Date -Format o) driver_exit=$LASTEXITCODE =====" |
    Out-File -FilePath $log -Append -Encoding utf8
exit $LASTEXITCODE
