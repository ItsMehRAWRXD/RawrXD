# ============================================================================
# ollama_proxy.ps1 -- expose Ollama's OpenAI-compatible API to RawrXD/Copilot
# ============================================================================
# Why this exists:
#   VS Code's GitHub Copilot has a BYOK model stored as "Deep2 Local"
#   (provider "Deep2", vendor "customendpoint"). That entry lives in VS Code's
#   SQLite global state, not in settings.json, so it cannot be repointed from
#   configuration files.
#
#   deep2_openai_server is the intended occupant of the Deep2 port, but it
#   currently runs CPU_NATIVE (GPU never opens) at ~0.028 TPS and exits, so
#   every request failed with ERR_CONNECTION_REFUSED.
#
#   This proxy makes that stored endpoint answer by forwarding to the healthy,
#   GPU-backed Ollama server on 11434.
#
#   DEFAULT PORT IS 11436 because that is the port already stored in the
#   "Deep2 Local" custom-endpoint configuration. Binding it means the existing
#   VS Code configuration works unchanged -- no UI edit, no state.vscdb patch.
#   Pass -ListenPort 8080 to serve the older Deep2 URL instead.
#
# Safeguards:
#   1. MODEL IDENTITY IS PRESERVED IN LOGS. Every request logs the requested
#      model and the effective model sent upstream, so a proxied response can
#      never be mistaken for native Deep2 inference.
#   2. EXPLICIT ALIAS MAP. Unknown models are NOT silently rewritten; only the
#      configured aliases are mapped. Anything else is forwarded verbatim so a
#      misconfigured client produces an observable 404.
#   3. PORT CONFLICT FAILS SAFELY. If the port is already bound, this script
#      reports the owning PID and exits. It never terminates another process.
#   4. STREAMING IS PASSTHROUGH with upstream cancellation when the client
#      disconnects, so a cancelled request cannot leave the GPU busy.
#   5. LOOPBACK ONLY. Binds 127.0.0.1; do not expose to the network without
#      adding authentication.
#
# Usage:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File tools/ollama_proxy.ps1
#   pwsh -NoProfile -ExecutionPolicy Bypass -File tools/ollama_proxy.ps1 -ListenPort 8080
# ============================================================================
[CmdletBinding()]
param(
    # Port the client expects. 11436 = the port stored in the "Deep2 Local"
    # custom endpoint. 8080 = the older deep2_openai_server port.
    [int]$ListenPort = 11436,
    [int]$UpstreamPort = 11434,
    [string]$BindAddress = '127.0.0.1',
    # Explicit alias map. Left = model name a client may request;
    # right = model name sent upstream. Only these are rewritten.
    [hashtable]$ModelAliases = @{
        'deep2-local' = 'reap16-glm-4_7-flash:latest'
    }
)

$ErrorActionPreference = 'Stop'

$prefix       = "http://${BindAddress}:$ListenPort/"
$upstreamBase = "http://127.0.0.1:$UpstreamPort"

# --- Safeguard 3: fail safely on port conflict -------------------------------
$occupied = $null
try {
    $occupied = Get-NetTCPConnection -State Listen -LocalPort $ListenPort -ErrorAction SilentlyContinue
}
catch { }

if ($occupied) {
    $owner = $occupied | Select-Object -First 1
    $pname = 'unknown'
    try { $pname = (Get-Process -Id $owner.OwningProcess -ErrorAction Stop).ProcessName } catch { }
    Write-Host "[proxy] PORT $ListenPort ALREADY IN USE by PID $($owner.OwningProcess) ($pname)."
    Write-Host "[proxy] Refusing to start. Not terminating the existing owner."
    Write-Host "[proxy] If that is the native Deep2 server, stop it first, or pass -ListenPort."
    exit 2
}

Add-Type -AssemblyName System.Net.Http

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)

# The check above is advisory: another process could claim the port between the
# check and this bind. Treat the bind as authoritative and fail closed.
try {
    $listener.Start()
}
catch {
    $m = $_.Exception.Message
    if ($m -match 'conflict|already|in use|0x800700B7|183') {
        Write-Host "[proxy] PORT $ListenPort is already in use (race lost)."
        Write-Host "[proxy] Refusing to start. Not terminating the existing owner."
    }
    else {
        Write-Host "[proxy] FAILED to bind $prefix : $m"
    }
    exit 1
}

$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(1800)

Write-Host "[proxy] listening  $prefix"
Write-Host "[proxy] forwarding -> $upstreamBase"
Write-Host "[proxy] aliases:"
foreach ($k in $ModelAliases.Keys) {
    Write-Host ("[proxy]   {0}  ->  {1}" -f $k, $ModelAliases[$k])
}
Write-Host "[proxy] Ctrl+C to stop."

function Read-BodyBytes([System.Net.HttpListenerRequest]$req) {
    if (-not $req.HasEntityBody) { return $null }
    $ms = [System.IO.MemoryStream]::new()
    $req.InputStream.CopyTo($ms)
    $bytes = $ms.ToArray()
    $ms.Dispose()
    return $bytes
}

while ($listener.IsListening) {

    $ctx = $null
    try { $ctx = $listener.GetContext() }
    catch { break }

    $req  = $ctx.Request
    $res  = $ctx.Response
    $reqId = [guid]::NewGuid().ToString('N').Substring(0, 8)

    try {
        $targetUri = "$upstreamBase$($req.RawUrl)"
        $bodyBytes = Read-BodyBytes $req

        # --- Safeguards 1 + 2: explicit alias resolution, identity logging ---
        $requestedModel = '(none)'
        $effectiveModel = '(none)'

        if ($null -ne $bodyBytes -and $bodyBytes.Length -gt 0) {
            try {
                $json = [System.Text.Encoding]::UTF8.GetString($bodyBytes) | ConvertFrom-Json
                if ($json.PSObject.Properties.Name -contains 'model' -and $json.model) {
                    $requestedModel = [string]$json.model
                    if ($ModelAliases.ContainsKey($requestedModel)) {
                        $effectiveModel = [string]$ModelAliases[$requestedModel]
                        $json.model = $effectiveModel
                        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes(
                            ($json | ConvertTo-Json -Depth 30 -Compress))
                        Write-Host "[proxy][$reqId] ALIAS $requestedModel -> $effectiveModel"
                    }
                    else {
                        $effectiveModel = $requestedModel
                    }
                }
            }
            catch {
                # Body is not JSON or has no model field: forward verbatim.
            }
        }

        $isStream = $false
        try {
            if ($bodyBytes) {
                $probe = [System.Text.Encoding]::UTF8.GetString($bodyBytes)
                if ($probe -match '"stream"\s*:\s*true') { $isStream = $true }
            }
        }
        catch { }

        $msg = [System.Net.Http.HttpRequestMessage]::new()
        $msg.Method     = [System.Net.Http.HttpMethod]::new($req.HttpMethod)
        $msg.RequestUri = [Uri]$targetUri

        if ($null -ne $bodyBytes -and $bodyBytes.Length -gt 0) {
            $msg.Content = [System.Net.Http.ByteArrayContent]::new($bodyBytes)
            $msg.Content.Headers.ContentType =
                [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/json')
        }

        $sw = [Diagnostics.Stopwatch]::StartNew()

        # --- Safeguard 4: streaming with upstream cancellation ---------------
        if ($isStream) {
            $cts = [System.Threading.CancellationTokenSource]::new()
            $token = $cts.Token
            $resp = $null
            $stream = $null

            try {
                $resp = $client.SendAsync($msg, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $token).GetAwaiter().GetResult()
                $sw.Stop()

                $res.StatusCode  = [int]$resp.StatusCode
                $res.ContentType = 'text/event-stream'
                $res.SendChunked = $true

                $stream = $resp.Content.ReadAsStreamAsync($token).GetAwaiter().GetResult()
                $buffer = [byte[]]::new(8192)
                $cancelled = $false

                while ($true) {
                    if ($token.IsCancellationRequested) { $cancelled = $true; break }
                    if (-not $listener.IsListening)     { $cancelled = $true; break }

                    $read = 0
                    try { $read = $stream.Read($buffer, 0, $buffer.Length) }
                    catch { $cancelled = $true; break }

                    if ($read -le 0) { break }

                    try {
                        $res.OutputStream.Write($buffer, 0, $read)
                        $res.OutputStream.Flush()
                    }
                    catch {
                        # Downstream closed. Trip cancellation so the upstream
                        # generation is torn down instead of orphaned.
                        $cancelled = $true
                        break
                    }
                }

                if ($cancelled) {
                    try { $cts.Cancel() } catch { }
                    Write-Host "[proxy][$reqId] CLIENT_GONE -> cancelling upstream after $([math]::Round($sw.Elapsed.TotalSeconds,1))s"
                }
            }
            catch {
                $code = 502
                if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
                Write-Host "[proxy][$reqId] STREAM_ERROR -> $code : $($_.Exception.Message)"
                try {
                    $res.StatusCode  = $code
                    $res.ContentType = 'application/json'
                    $payload = (@{ error = @{ message = "proxy upstream failure: $($_.Exception.Message)"; type = 'proxy_error'; request_id = $reqId } } | ConvertTo-Json -Compress)
                    $b = [System.Text.Encoding]::UTF8.GetBytes($payload)
                    $res.ContentLength64 = $b.Length
                    $res.OutputStream.Write($b, 0, $b.Length)
                }
                catch { }
            }
            finally {
                try { if ($stream) { $stream.Dispose() } } catch { }
                try { if ($resp)   { $resp.Dispose() } }   catch { }
                try { $cts.Cancel() } catch { }
                try { $cts.Dispose() } catch { }
            }

            Write-Host ("[proxy][{0}] STREAM {1} {2} -> {3} model={4} requested={5} {6}s" -f `
                $reqId, $req.HttpMethod, $req.RawUrl, $res.StatusCode, `
                $effectiveModel, $requestedModel, [math]::Round($sw.Elapsed.TotalSeconds,1))
        }
        else {
            $cts = [System.Threading.CancellationTokenSource]::new()
            try {
                $resp = $client.SendAsync($msg, $cts.Token).GetAwaiter().GetResult()
                $sw.Stop()

                $outBytes = $resp.Content.ReadAsByteArrayAsync($cts.Token).GetAwaiter().GetResult()

                $res.StatusCode = [int]$resp.StatusCode
                $ct = $null
                try { $ct = $resp.Content.Headers.ContentType } catch { }
                if ($ct) { $res.ContentType = $ct.MediaType }
                else     { $res.ContentType = 'application/json' }
                $res.ContentLength64 = $outBytes.Length
                $res.OutputStream.Write($outBytes, 0, $outBytes.Length)

                Write-Host ("[proxy][{0}] {1} {2} -> {3} model={4} requested={5} {6}ms {7} bytes" -f `
                    $reqId, $req.HttpMethod, $req.RawUrl, $res.StatusCode, `
                    $effectiveModel, $requestedModel, [math]::Round($sw.Elapsed.TotalMilliseconds), $outBytes.Length)
            }
            finally {
                try { $cts.Cancel() } catch { }
                try { $cts.Dispose() } catch { }
            }
        }
    }
    catch {
        $code = 502
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        Write-Host "[proxy][$reqId] ERROR $($req.HttpMethod) $($req.RawUrl) -> $code : $($_.Exception.Message)"
        try {
            $res.StatusCode  = $code
            $res.ContentType = 'application/json'
            $payload = (@{ error = @{ message = "proxy upstream failure: $($_.Exception.Message)"; type = 'proxy_error'; request_id = $reqId } } | ConvertTo-Json -Compress)
            $b = [System.Text.Encoding]::UTF8.GetBytes($payload)
            $res.ContentLength64 = $b.Length
            $res.OutputStream.Write($b, 0, $b.Length)
        }
        catch { }
    }
    finally {
        try { $res.OutputStream.Close() } catch { }
        try { $res.Close() } catch { }
        try { $ctx.Dispose() } catch { }
    }
}

$listener.Stop()
$listener.Close()
$client.Dispose()
Write-Host "[proxy] stopped."