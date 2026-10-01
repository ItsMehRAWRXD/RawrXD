# ============================================================================
# tools/gate1_runtime_smoke.ps1
# RAWRXD_GATE_1_RUNTIME_SMOKE  (A/B/C/D/E)
#
# Exercises the two IDE-facing routes rebound from the always-empty stub
# registry to the real sandboxed authority:
#     POST /api/agent/execute-tool
#     POST /api/cli
#
# Two harness bugs were found in the first run and both are fixed here:
#   1. JSON was built by concatenating inside a single-quoted literal, which
#      silently produced malformed JSON and made the SERVER look like it
#      rejected a valid request. All bodies are now produced with
#      ConvertTo-Json so quoting cannot participate in the result.
#   2. The inside-root read used a relative path resolved against the harness
#      CWD rather than the server CWD, producing a false failure. A dedicated
#      file is created under the tool root with deterministic content and read
#      back by absolute path, and the exact bytes are compared.
#
# Spawn evidence is recorded as NO_SPAWN_INDICATOR_OBSERVED, not as proof that
# no child process existed: the authoritative denial evidence is that the
# policy refusal is returned BY THE TOOL, before any execution.
# ============================================================================
param(
    [string]$Server   = "F:\~dev\rawrxd\build\bin\Release\rawr-server.exe",
    [string]$Model    = "F:\~dev\qwen2.5-coder-1.5b-base.gguf",
    [int]$PortA       = 11441,
    [int]$PortD       = 11442
)

$ErrorActionPreference = "Stop"
function Rec($k, $v) { Write-Output ("{0}={1}" -f $k, $v) }

if (-not (Test-Path $Server)) { throw "server not found: $Server" }
if (-not (Test-Path $Model))  { throw "model not found: $Model" }

$sha   = (Get-FileHash $Server -Algorithm SHA256).Hash
$root  = "F:\~dev\rawrxd\.gate1_root"
$inside = Join-Path $root 'inside.txt'
$insideContent = "RAWRXD_GATE1_INSIDE_ROOT_OK"

New-Item -ItemType Directory -Force -Path $root | Out-Null
[System.IO.File]::WriteAllText($inside, $insideContent)

Write-Output "RAWRXD_GATE_1_RUNTIME_SMOKE"
Rec "SERVER_BINARY_SHA256" $sha
Rec "TOOL_ROOT" $root
Rec "INSIDE_FIXTURE" $inside
Rec "INSIDE_FIXTURE_EXPECTED" $insideContent
Rec "ALLOW_EXECUTE_PHASE_A" "0 (default deny)"
Rec "ALLOW_EXECUTE_PHASE_D" "1"
Write-Output ""

# All request bodies are generated, never hand-quoted.
function J([hashtable]$h) { return ($h | ConvertTo-Json -Depth 6 -Compress) }
function Post-Json([int]$port, [string]$path, [string]$body) {
    try {
        $c = New-Object System.Net.WebClient
        $c.Headers.Add('Content-Type', 'application/json')
        $r = $c.UploadString("http://127.0.0.1:$port$path", 'POST', $body)
        return @{ status = 200; body = $r }
    } catch [System.Net.WebException] {
        $r = $_.Exception.Response
        if ($r) {
            return @{ status = [int]$r.StatusCode
                      body = (New-Object System.IO.StreamReader($r.GetResponseStream())).ReadToEnd() }
        }
        return @{ status = -1; body = $_.Exception.Message }
    }
}
function Start-Server([int]$port, [int]$allowExec, [string]$tag) {
    $env:DEEP2_SERVER_PORT = "$port"
    $env:RAWRXD_TOOL_ROOT = $root
    $env:RAWRXD_TOOL_ALLOW_EXECUTE = "$allowExec"
    $p = Start-Process -FilePath $Server -ArgumentList @("--model",$Model,"--port","$port") `
         -RedirectStandardOutput "gate1_$tag.out" -RedirectStandardError "gate1_$tag.err" -NoNewWindow -PassThru
    for ($i = 0; $i -lt 150; $i++) {
        Start-Sleep -Seconds 1
        if ($p.HasExited) { break }
        $e = Get-Content "gate1_$tag.err" -Raw -ErrorAction SilentlyContinue
        if ($e -and $e -match 'Ready\.') { return $p }
    }
    return $p
}

$sentinel = 'echo RAWRXD_GATE1_SENTINEL_D'

# =========================== PHASE A: execute denied ========================
$pA = Start-Server $PortA 0 'A'
if ($pA.HasExited) {
    Get-Content "gate1_A.err" -Tail 20
    Rec "GATE_1_RUNTIME" "FAIL_SERVER_DID_NOT_START"; exit 1
}
Get-Content "gate1_A.err" | Select-String 'tool authority' | ForEach-Object { $_.Line }
Write-Output ""

Write-Output "--- A: unknown tool (expect 404) ---"
$a = Post-Json $PortA "/api/agent/execute-tool" (J @{ tool = 'definitely_nonexistent_tool' })
Rec "A_UNKNOWN_TOOL_HTTP" $a.status
Write-Output "A_BODY=$($a.body)"

Write-Output ""
Write-Output "--- C: known tool, execute denied (expect !=404 + tool refusal) ---"
$c = Post-Json $PortA "/api/agent/execute-tool" (J @{ tool = 'execute_command'
                                                   args = @{ command = $sentinel } })
Rec "C_KNOWN_DENIED_HTTP" $c.status
Write-Output "C_BODY=$($c.body)"

Write-Output ""
Write-Output "--- B: /api/cli, execute denied (expect refusal, no spawn indicator) ---"
$b = Post-Json $PortA "/api/cli" (J @{ command = $sentinel })
Rec "B_CLI_DENIED_HTTP" $b.status
Write-Output "B_BODY=$($b.body)"

Write-Output ""
Write-Output "--- E: read_file inside vs outside the tool root ---"
$eIn = Post-Json $PortA "/api/agent/execute-tool" (J @{ tool = 'read_file'; args = @{ path = $inside } })
Rec "E_READ_INSIDE_HTTP" $eIn.status
Write-Output "E_INSIDE_BODY=$($eIn.body)"
Rec "E_INSIDE_CONTENT_EXACT" $(if ($eIn.body -match [regex]::Escape($insideContent)) { 'YES' } else { 'NO' })
$eOut = Post-Json $PortA "/api/agent/execute-tool" (J @{ tool = 'read_file'
                                                    args = @{ path = '..\..\..\Windows\System32\drivers\etc\hosts' } })
Rec "E_READ_OUTSIDE_HTTP" $eOut.status
Write-Output "E_OUTSIDE_BODY=$($eOut.body)"

$logA = (Get-Content "gate1_A.out","gate1_A.err" -Raw -ErrorAction SilentlyContinue)
Rec "NO_SPAWN_INDICATOR_OBSERVED" $(if ($logA -match 'RAWRXD_GATE1_SENTINEL_D') { 'SENTINEL_PRESENT' } else { 'YES' })
Stop-Process -Id $pA.Id -Force
Start-Sleep -Seconds 2

# =========================== PHASE D: execute enabled =======================
Write-Output ""
$pD = Start-Server $PortD 1 'D'
if ($pD.HasExited) {
    Get-Content "gate1_D.err" -Tail 20
    Rec "GATE_1_RUNTIME" "FAIL_SERVER_D_DID_NOT_START"; exit 1
}
Get-Content "gate1_D.err" | Select-String 'tool authority' | ForEach-Object { $_.Line }
Write-Output ""
Write-Output "--- D: /api/cli with execute ENABLED (expect success + sentinel) ---"
$d = Post-Json $PortD "/api/cli" (J @{ command = $sentinel })
Rec "D_CLI_ENABLED_HTTP" $d.status
Write-Output "D_BODY=$($d.body)"
Rec "D_SENTINEL_IN_TOOL_RESULT" $(if ($d.body -match 'RAWRXD_GATE1_SENTINEL_D') { 'YES' } else { 'NO' })
Rec "D_POLICY_REFUSAL_PRESENT"   $(if ($d.body -match 'disabled by the active tool policy') { 'YES' } else { 'NO' })
Stop-Process -Id $pD.Id -Force

# ================================ VERDICT ==================================
$aPass = ($a.status -eq 404)
$cPass = ($c.status -ne 404 -and $c.body -match 'disabled by the active tool policy')
$bPass = ($b.body -match 'disabled by the active tool policy')
$ePass = ($eIn.body -match [regex]::Escape($insideContent))
$eOutPass = ($eOut.body -match 'rejected by sandbox')
$dPass = ($d.body -match 'RAWRXD_GATE1_SENTINEL_D' -and $d.body -notmatch 'disabled by the active tool policy')

Write-Output ""
Rec "GATE_1_RUNTIME_A" $aPass
Rec "GATE_1_RUNTIME_B" $bPass
Rec "GATE_1_RUNTIME_C" $cPass
Rec "GATE_1_RUNTIME_D" $dPass
Rec "GATE_1_RUNTIME_E" ($ePass -and $eOutPass)
$verdict = 'FAIL'
if ($aPass -and $bPass -and $cPass -and $dPass -and $ePass -and $eOutPass) { $verdict = 'PASS' }
Rec "GATE_1_RUNTIME" $verdict
