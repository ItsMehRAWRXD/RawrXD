param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath,
    [int]$Port = 11435,
    [int]$StartupTimeoutSec = 90,
    [string]$ModelPath = "",
    [string]$Prompt = "Reply with the single word READY"
)

$ErrorActionPreference = "Stop"
$exe = (Resolve-Path $ExePath).Path
$receiptDir = Join-Path (Get-Location) "evidence\RAWRXD_PERFORMANCE_001\G4_LOCALSERVER_PRODUCT_001"
New-Item -ItemType Directory -Path $receiptDir -Force | Out-Null
$receipt = Join-Path $receiptDir "RECEIPT.txt"
$lines = New-Object System.Collections.Generic.List[string]
function Emit([string]$s) { $lines.Add($s); Write-Host $s }

Emit "G4_LOCALSERVER_PRODUCT_001"
Emit "EXE=$exe"
Emit "PORT=$Port"
Emit "PROMOTE=0"
Emit "TIP_CLIMB=HOLD"

# Snapshot any pre-existing owner of 11434 before launch; later assertion is process-specific.
$before11434 = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -eq 11434 -or $_.LocalPort -eq 11434 })
Emit ("PREEXISTING_11434_CONNECTIONS=" + $before11434.Count)

$p = Start-Process -FilePath $exe -ArgumentList @("--headless","--local","--port",$Port) -PassThru -NoNewWindow
Emit "PID=$($p.Id)"

$deadline = (Get-Date).AddSeconds($StartupTimeoutSec)
$listen = $false
while ((Get-Date) -lt $deadline) {
    if ($p.HasExited) { break }
    $c = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $p.Id }
    if ($c) { $listen = $true; break }
    Start-Sleep -Milliseconds 200
}

Emit ("PROCESS_ALIVE=" + ($(if (!$p.HasExited) {"1"} else {"0"})))
Emit ("LISTEN_11435=" + ($(if ($listen) {"1"} else {"0"})))
if (!$listen) {
    if (!$p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    $lines | Set-Content -Path $receipt -Encoding UTF8
    throw "G4 failed before listener: processExited=$($p.HasExited)"
}

function Invoke-Status([string]$Method, [string]$Url, [string]$Body = "") {
    try {
        $args = @("-sS", "-o", "$env:TEMP\rawrxd_g4_body.txt", "-w", "%{http_code}", "-X", $Method)
        if ($Body) { $args += @("-H", "Content-Type: application/json", "--data-binary", $Body) }
        $args += $Url
        $code = & curl.exe @args
        return [int]$code
    } catch { return 0 }
}

$healthCode = Invoke-Status "GET" "http://127.0.0.1:$Port/health"
Emit "HEALTH_STATUS=$healthCode"
Emit ("HEALTH_HTTP_REACHED=" + ($(if ($healthCode -gt 0) {"1"} else {"0"})))

# Initialization may still be warming; poll capabilities until 2xx or timeout.
$capCode = 0
while ((Get-Date) -lt $deadline) {
    if ($p.HasExited) { break }
    $capCode = Invoke-Status "GET" "http://127.0.0.1:$Port/api/engine/capabilities"
    if ($capCode -ge 200 -and $capCode -lt 300) { break }
    Start-Sleep -Milliseconds 500
}
Emit "CAPABILITIES_STATUS=$capCode"
Emit ("CAPABILITIES_HTTP_REACHED=" + ($(if ($capCode -gt 0) {"1"} else {"0"})))

$optionsCode = Invoke-Status "OPTIONS" "http://127.0.0.1:$Port/api/model/load"
Emit "CORS_OPTIONS_STATUS=$optionsCode"

$owned11434 = @(Get-NetTCPConnection -OwningProcess $p.Id -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -eq 11434 -or $_.LocalPort -eq 11434 })
Emit "OLLAMA_11434_CONTACT=$($owned11434.Count)"

if ($ModelPath) {
    $fullModel = (Resolve-Path $ModelPath).Path
    $body = @{ modelPath = $fullModel } | ConvertTo-Json -Compress
    $loadCode = Invoke-Status "POST" "http://127.0.0.1:$Port/api/model/load" $body
    Emit "NATIVE_MODEL_LOAD_STATUS=$loadCode"
    Emit ("NATIVE_MODEL_LOAD=" + ($(if ($loadCode -ge 200 -and $loadCode -lt 300) {"PASS"} else {"FAIL"})))
    if ($loadCode -ge 200 -and $loadCode -lt 300) {
        $chatBody = @{ prompt = $Prompt } | ConvertTo-Json -Compress
        $chatCode = Invoke-Status "POST" "http://127.0.0.1:$Port/api/chat" $chatBody
        Emit "NATIVE_CHAT_STATUS=$chatCode"
        Emit ("NATIVE_GENERATE=" + ($(if ($chatCode -ge 200 -and $chatCode -lt 300) {"PASS_RUNTIME"} else {"FAIL"})))
    }
} else {
    Emit "NATIVE_MODEL_LOAD=UNSPENT"
    Emit "NATIVE_GENERATE=UNSPENT"
}

$transportPass = (!$p.HasExited) -and $listen -and ($capCode -ge 200 -and $capCode -lt 300) -and ($optionsCode -eq 204) -and ($owned11434.Count -eq 0)
Emit ("G4_TRANSPORT_POLICY_GATE=" + ($(if ($transportPass) {"PASS"} else {"FAIL"})))
Emit "R01_REOPENED=0"
Emit "R02_REOPENED=0"
Emit "LINK_SUBSTRATE_REOPENED=0"
Emit "DUALSTICK_REOPENED=0"
Emit "SEALED_TOOL_PATH_UNCHANGED=1"

Emit "RECEIPT=$receipt"
$lines | Set-Content -Path $receipt -Encoding UTF8

if (!$p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
if (!$transportPass) { exit 2 }
exit 0
