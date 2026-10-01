# ============================================================================
# tools/gate1_runtime_smoke.ps1
# RAWRXD_GATE_1_RUNTIME_SMOKE
#
# Exercises the two IDE-facing routes that were rebound from the always-empty
# stub registry to the real sandboxed authority:
#     POST /api/agent/execute-tool
#     POST /api/cli
#
# The distinction that matters most is A vs C: a KNOWN tool refused by policy
# must not masquerade as an unknown tool. A is 404. C is a policy refusal with
# a non-404 status and the tool's own error text.
#
# The sentinel is a directory listing, not a process: /api/cli maps to
# execute_command, so under default policy it must be refused WITHOUT spawning
# anything, and that refusal is what proves the policy boundary is real.
# ============================================================================
param(
    [string]$Server = "F:\~dev\rawrxd\build\bin\Release\rawr-server.exe",
    [string]$Model  = "F:\~dev\qwen2.5-coder-1.5b-base.gguf",
    [int]$Port      = 11439,
    [string]$ToolRoot = ""
)

$ErrorActionPreference = "Stop"

function Write-Rec($k, $v) { Write-Output ("{0}={1}" -f $k, $v) }

if (-not (Test-Path $Server)) { throw "server not found: $Server" }
if (-not (Test-Path $Model))  { throw "model not found: $Model" }

$sha = (Get-FileHash $Server -Algorithm SHA256).Hash
Write-Output "RAWRXD_GATE_1_RUNTIME_SMOKE"
Write-Rec "SERVER_BINARY_SHA256" $sha
Write-Rec "SERVER_PATH" $Server
Write-Rec "MODEL" $Model
Write-Rec "TOOL_ROOT" $(if ($ToolRoot) { $ToolRoot } else { "<unset: defaults to CWD>" })
Write-Output ""

# Deterministic, state-free sentinel. Under default policy execute_command must
# refuse it before doing anything at all.
$sentinel = 'echo RAWRXD_GATE1_SENTINEL'

$env:DEEP2_SERVER_PORT = "$Port"
if ($ToolRoot) { $env:RAWRXD_TOOL_ROOT = $ToolRoot }
# Deliberately NOT setting RAWRXD_TOOL_ALLOW_EXECUTE: this run proves denial.
$env:RAWRXD_TOOL_ALLOW_EXECUTE = $env:RAWRXD_TOOL_ALLOW_EXECUTE   # leave as-is / absent

Write-Output "starting server..."
$proc = Start-Process -FilePath $Server -ArgumentList @("--model", $Model, "--port", "$Port") `
        -RedirectStandardOutput "gate1_srv.out" -RedirectStandardError "gate1_srv.err" -NoNewWindow -PassThru

$ready = $false
for ($i = 0; $i -lt 120; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) { break }
    if (Test-Path "gate1_srv.err") {
        $e = Get-Content "gate1_srv.err" -Raw -ErrorAction SilentlyContinue
        if ($e -and $e -match 'Ready\.') { $ready = $true; break }
    }
}
Write-Rec "SERVER_EXIT" $(if ($proc.HasExited) { $proc.ExitCode } else { "running" })
Write-Rec "SERVER_READY" $ready

if (-not $ready) {
    Write-Output "--- stderr tail ---"
    Get-Content "gate1_srv.err" -Tail 25 -ErrorAction SilentlyContinue
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    Write-Output "GATE_1_RUNTIME=FAIL_SERVER_DID_NOT_START"
    exit 1
}

Get-Content "gate1_srv.err" | Select-String -Pattern 'tool authority' | ForEach-Object { $_.Line }

function Post-Json([string]$path, [string]$body) {
    try {
        $c = New-Object System.Net.WebClient
        $c.Headers.Add('Content-Type', 'application/json')
        $resp = $c.UploadString("http://127.0.0.1:$Port$path", 'POST', $body)
        return @{ status = 200; body = $resp }
    } catch [System.Net.WebException] {
        $r = $_.Exception.Response
        if ($r) { return @{ status = [int]$r.StatusCode; body = (New-Object System.IO.StreamReader($r.GetResponseStream())).ReadToEnd() } }
        return @{ status = -1; body = $_.Exception.Message }
    }
}

Write-Output ""
Write-Output "--- A: unknown tool (expect 404, no spawn) ---"
$a = Post-Json "/api/agent/execute-tool" '{"tool":"definitely_nonexistent_tool"}'
Write-Rec "A_UNKNOWN_TOOL_HTTP" $a.status
Write-Output "A_BODY=$($a.body)"

Write-Output ""
Write-Output "--- C: known tool, execute denied (expect !=404, policy refusal) ---"
# Build the JSON with a variable: string-concatenating inside a single-quoted
# literal silently produced invalid JSON, which is why C first reported
# "requires a 'tool' name" instead of a policy refusal.
$cBody = '{"tool":"execute_command","args":{"command":"' + $sentinel + '"}}'
$c = Post-Json "/api/agent/execute-tool" $cBody
Write-Rec "C_KNOWN_DENIED_HTTP" $c.status
Write-Output "C_BODY=$($c.body)"

Write-Output ""
Write-Output "--- B: /api/cli under default policy (expect refusal, no spawn) ---"
$b = Post-Json "/api/cli" ('{"command":"' + $sentinel + '"}')
Write-Rec "B_CLI_DENIED_HTTP" $b.status
Write-Output "B_BODY=$($b.body)"

Write-Output ""
Write-Output "--- E: read_file inside vs outside the tool root ---"
$e1 = Post-Json "/api/agent/execute-tool" '{"tool":"read_file","args":{"path":"gate1_srv.err"}}'
Write-Rec "E_READ_INSIDE_HTTP" $e1.status
Write-Output "E_INSIDE_BODY=$($e1.body)"
# Use an absolute path that exists and is inside the tool root, so the check is
# about the root boundary rather than about a missing file.
$e1b = Post-Json "/api/agent/execute-tool" ('{"tool":"read_file","args":{"path":"' + (Join-Path $PWD 'tools\gate1_runtime_smoke.ps1') + '"}}')
Write-Rec "E_READ_INSIDE_ABS_HTTP" $e1b.status
Write-Output "E_INSIDE_ABS_BODY=$($e1b.body)"
$e2 = Post-Json "/api/agent/execute-tool" '{"tool":"read_file","args":{"path":"..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts"}}'
Write-Rec "E_READ_OUTSIDE_HTTP" $e2.status
Write-Output "E_OUTSIDE_BODY=$($e2.body)"

# Prove no sentinel output appeared anywhere: nothing was executed.
$spawned = 0
if ((Get-Content "gate1_srv.out","gate1_srv.err" -Raw -ErrorAction SilentlyContinue) -match 'RAWRXD_GATE1_SENTINEL') { $spawned = 1 }
Write-Output ""
Write-Rec "SENTINEL_ECHOED_IN_SERVER_LOG" $spawned
Write-Rec "ALLOW_EXECUTE" $(if ($env:RAWRXD_TOOL_ALLOW_EXECUTE) { $env:RAWRXD_TOOL_ALLOW_EXECUTE } else { "<unset>" })

Stop-Process -Id $proc.Id -Force
Write-Output ""
Write-Output "D (execute ENABLED) not run in this invocation."
Write-Output "GATE_1_RUNTIME=PARTIAL"
