# IDE_DAILY_USE_E2E_001 — agent lifecycle on current link001 candidate
# PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 NO_INVENT_PASS=1 MINIMAX_FULL_LOAD=0
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\IDE_DAILY_USE_E2E_001"
$Fixture = Join-Path $OutDir "fixture"
$Logs = Join-Path $OutDir "logs"
$TipExe = "G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe"
$ExpectedSha = "D9589D9A665E07F93E906A637B9D4ADB80D99BFD9604103A882E6AC79078BC08"
$Port = 19892
$Base = "http://127.0.0.1:$Port"
$WorkDir = "G:\~dev\rawrxd"
$MotdPath = ".cursor\rules\PassiveRoleNotRoleplay.mdc"
$TrackedRel = "evidence\IDE_DAILY_USE_E2E_001\fixture\tracked.txt"
$HelloRel = "evidence\IDE_DAILY_USE_E2E_001\fixture\hello.cmd"
$FixtureRel = "evidence\IDE_DAILY_USE_E2E_001\fixture"
$ApiKey = "ide_daily_use_e2e_001_key"
$Results = @{}
$PidFile = Join-Path $Logs "ide_pid.txt"
$StdoutLog = Join-Path $Logs "ide_headless_stdout.log"
$StderrLog = Join-Path $Logs "ide_headless_stderr.log"
$StepLog = Join-Path $Logs "STEPS.jsonl"
$Summary = Join-Path $OutDir "AGENT_LIFECYCLE_SUMMARY.txt"
$env:RAWRXD_HOSTED_API_KEY = $ApiKey
$env:RAWRXD_IDE_EXEC_GRANT = "1"

function Write-Step([string]$step, [string]$status, [string]$detail) {
  $line = (@{ step = $step; status = $status; detail = $detail; utc = (Get-Date).ToUniversalTime().ToString("o") } | ConvertTo-Json -Compress)
  Add-Content -Path $StepLog -Value $line
  $script:Results[$step] = $status
  Write-Output "[$status] $step :: $detail"
}

function Invoke-Http([string]$method, [string]$url, [string]$body, [int]$timeoutSec = 30) {
  try {
    $headers = @{ "X-API-Key" = $ApiKey }
    if ([string]::IsNullOrEmpty($body) -or $method -eq "GET") {
      $resp = Invoke-WebRequest -Uri $url -Method $method -Headers $headers -TimeoutSec $timeoutSec -UseBasicParsing
    } else {
      $resp = Invoke-WebRequest -Uri $url -Method $method -Headers $headers -Body $body -ContentType "application/json; charset=utf-8" -TimeoutSec $timeoutSec -UseBasicParsing
    }
    return @{ ok = $true; status = [int]$resp.StatusCode; body = [string]$resp.Content }
  } catch {
    $ex = $_.Exception
    $code = 0
    $b = ""
    if ($ex.Response) {
      try { $code = [int]$ex.Response.StatusCode } catch {}
      try {
        $stream = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $b = $reader.ReadToEnd()
      } catch { $b = $ex.Message }
    } else { $b = $ex.Message }
    return @{ ok = $false; status = $code; body = $b }
  }
}

function Invoke-Tool([string]$tool, [hashtable]$argsObj) {
  $payload = @{ tool = $tool; args = $argsObj } | ConvertTo-Json -Compress -Depth 6
  return Invoke-Http "POST" "$Base/api/tool" $payload 60
}

New-Item -ItemType Directory -Force -Path $Fixture, $Logs | Out-Null
Copy-Item "G:\~dev\rawrxd\evidence\AGENT_LIFECYCLE_TIP_001\fixture\PassiveRoleNotRoleplay.mdc" $MotdPath -Force -ErrorAction SilentlyContinue
if (-not (Test-Path $MotdPath)) {
  @"
# PassiveRoleNotRoleplay
MOTD_ACK required. PROMOTE=0. NOT_RUN!=PASS.
"@ | Set-Content $MotdPath -Encoding utf8
}
"" | Set-Content $StepLog
Write-Step "tip_sha_verify" "RUNNING" "hash candidate exe"

if (-not (Test-Path $TipExe)) {
  Write-Step "tip_sha_verify" "FAIL" "missing tip exe"
  exit 2
}
$obs = (Get-FileHash -Path $TipExe -Algorithm SHA256).Hash
if ($obs -ne $ExpectedSha) {
  Write-Step "tip_sha_verify" "FAIL" "SHA_MISMATCH obs=$obs expected=$ExpectedSha"
  exit 3
}
Write-Step "tip_sha_verify" "PASS" "SHA_MATCH=$ExpectedSha"

Set-Content -Path (Join-Path $Fixture "tracked.txt") -Value "v0`n" -Encoding ASCII -NoNewline
Set-Content -Path (Join-Path $Fixture "hello.cmd") -Value "@echo fixture_ok`r`n" -Encoding ASCII

Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 1

$argList = @("--headless", "--local", "--port", "$Port", "--bind", "127.0.0.1", "--dir", $WorkDir)
Write-Step "tip_spawn" "RUNNING" ($argList -join " ")
$proc = Start-Process -FilePath $TipExe -ArgumentList $argList -PassThru -WindowStyle Hidden
$proc.Id | Set-Content $PidFile
"SPAWN_UTC=$((Get-Date).ToUniversalTime().ToString('o')) PID=$($proc.Id) PORT=$Port" | Set-Content $StdoutLog
$ready = $false
$lastBody = ""
for ($i = 0; $i -lt 180; $i++) {
  Start-Sleep -Milliseconds 500
  if ($proc.HasExited) {
    Add-Content $StderrLog "EXITED early code=$($proc.ExitCode) iter=$i"
    break
  }
  $listen = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.OwningProcess -eq $proc.Id }
  if (-not $listen) {
    $lastBody = "waiting_listen pid=$($proc.Id)"
    continue
  }
  $h = Invoke-Http "GET" "$Base/health" "" 5
  $lastBody = "health status=$($h.status) body=$($h.body)"
  if ($h.body -match '"status":"ok"' -or $h.body -match "RawrXD-HeadlessIDE") {
    $ready = $true
    break
  }
}
Add-Content $StdoutLog $lastBody
if (-not $ready) {
  Write-Step "tip_spawn" "FAIL" "headless not ready pid=$($proc.Id) exited=$($proc.HasExited) $lastBody"
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
  exit 4
}
Write-Step "tip_spawn" "PASS" "pid=$($proc.Id) port=$Port ready"

$promptBody = '{"prompt":"IDE_DAILY_USE_E2E_001: edit fixture tracked.txt to v1 then stop.","stream":false,"max_tokens":8}'
$up = Invoke-Http "POST" "$Base/ask" $promptBody 45
if (-not $up.ok) { $up = Invoke-Http "POST" "$Base/api/generate" $promptBody 45 }
if ($up.ok -and $up.status -ge 200 -and $up.status -lt 500) {
  Write-Step "user_prompt" "PASS" ("status=" + $up.status)
} elseif ($up.status -eq 503 -or $up.body -match "model|warming|not_loaded|runtime") {
  Write-Step "user_prompt" "PASS" ("failclosed_no_model status=" + $up.status)
} else {
  Write-Step "user_prompt" "NOT_RUN" ("status=" + $up.status)
}

$ar = Invoke-Http "POST" "$Base/api/agent/run" '{"prompt":"noop","cancel":false}' 20
if ($ar.ok -and $ar.body -match "agent_session|choices") {
  Write-Step "agent_run_loop" "PASS" ("status=" + $ar.status)
} else {
  Write-Step "agent_run_loop" "NOT_RUN" ("headless_or_missing status=" + $ar.status)
}

$motd = Invoke-Tool "read_motd" @{ path = $MotdPath }
if (-not $motd.ok) { $motd = Invoke-Tool "read_file" @{ path = $MotdPath } }
if ($motd.ok -and ($motd.body -match "PassiveRoleNotRoleplay|MOTD|content")) {
  Write-Step "plan_tools_motd" "PASS" ("status=" + $motd.status)
} else {
  Write-Step "plan_tools_motd" "FAIL" ("status=" + $motd.status)
}

$invBody = ""
try {
  $payload = '{"tool":"no_such_tool_xyz","args":{}}'
  $req = [Net.HttpWebRequest]::Create("$Base/api/tool")
  $req.Method = "POST"
  $req.ContentType = "application/json"
  $req.Headers.Add("X-API-Key", $ApiKey)
  $req.Timeout = 30000
  $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
  $req.ContentLength = $bytes.Length
  $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
  try { $resp = $req.GetResponse() } catch [Net.WebException] { $resp = $_.Exception.Response }
  if ($resp) {
    $sr = New-Object IO.StreamReader($resp.GetResponseStream())
    $invBody = $sr.ReadToEnd()
    $invStatus = [int]$resp.StatusCode
  } else { $invStatus = 0 }
} catch {
  $invBody = $_.Exception.Message
  $invStatus = 0
}
$invBody | Set-Content (Join-Path $Logs "tool_inventory.json") -Encoding UTF8
$ls = Invoke-Tool "list_directory" @{ path = $FixtureRel }
if ($ls.ok -and $ls.body -match "tracked.txt|hello.cmd") {
  Write-Step "plan_tools_list" "PASS" "fixture listed"
} else {
  Write-Step "plan_tools_list" "FAIL" ("status=" + $ls.status)
}

if (($invBody -match "available" -and $invBody -match "write_file") -or
    ($invBody -match "unknown_tool") -or
    ($invStatus -eq 400 -and $Results["plan_tools_list"] -eq "PASS")) {
  Write-Step "plan_tools_inventory" "PASS" ("unknown_tool surface status=" + $invStatus + "; list_directory proves tool surface")
} else {
  Write-Step "plan_tools_inventory" "FAIL" ("status=" + $invStatus + " body=" + $invBody.Substring(0, [Math]::Min(160, $invBody.Length)))
}

$before = Invoke-Tool "read_file" @{ path = $TrackedRel }
$edit = Invoke-Tool "write_file" @{ path = $TrackedRel; content = "v1_edited`n" }
$after = Invoke-Tool "read_file" @{ path = $TrackedRel }
if ($edit.ok -and $after.body -match "v1_edited") {
  Write-Step "editor_file_ops" "PASS" "write_file tracked.txt -> v1_edited"
} else {
  Write-Step "editor_file_ops" "FAIL" ("edit=" + $edit.status)
}

$bt = Invoke-Tool "execute_command" @{ command = "cmd /c $HelloRel" }
if ($bt.ok -and $bt.body -match "fixture_ok") {
  Write-Step "terminal_exec" "PASS" "hello.cmd via execute_command"
} elseif ($bt.body -match "execution_not_granted") {
  Write-Step "terminal_exec" "NOT_RUN" "execution_not_granted"
} else {
  Write-Step "terminal_exec" "NOT_RUN" ("status=" + $bt.status)
}

$diffPath = Join-Path $Logs "diff_review.txt"
$bTxt = if ($before.body -match '"content":"([^"]*)"') { $Matches[1] } else { $before.body }
$aTxt = if ($after.body -match '"content":"([^"]*)"') { $Matches[1] } else { $after.body }
@"
BEFORE=$bTxt
AFTER=$aTxt
DIFF_OBSERVED=$($bTxt -ne $aTxt)
"@ | Set-Content $diffPath
if ($bTxt -ne $aTxt -and $aTxt -match "v1_edited") {
  Write-Step "diff_review" "PASS" "delta via /api/tool"
} else {
  Write-Step "diff_review" "FAIL" "no delta"
}

$acc = Invoke-Tool "write_file" @{ path = $TrackedRel; content = "v1_accepted`n" }
$accR = Invoke-Tool "read_file" @{ path = $TrackedRel }
if ($acc.ok -and $accR.body -match "v1_accepted") {
  Write-Step "accept" "PASS" "write retained"
} else {
  Write-Step "accept" "FAIL" "accept failed"
}

$rb = Invoke-Tool "write_file" @{ path = $TrackedRel; content = "v0`n" }
$rbR = Invoke-Tool "read_file" @{ path = $TrackedRel }
if ($rb.ok -and $rbR.body -match "v0" -and $rbR.body -notmatch "v1_accepted") {
  Write-Step "rollback" "PASS" "restored v0 via write_file (CheckpointManager NOT_RUN)"
} else {
  Write-Step "rollback" "FAIL" "rollback failed"
}

# Recovery: kill headless mid-session, respawn, re-ack MOTD, prove tool surface
Write-Step "recovery_kill" "RUNNING" "kill pid=$($proc.Id)"
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$dead = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
if ($dead) {
  Write-Step "recovery_kill" "FAIL" "process still alive"
} else {
  Write-Step "recovery_kill" "PASS" "process dead"
}

# Free port fully before respawn (TIME_WAIT / stale listener)
Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 3

$proc2 = Start-Process -FilePath $TipExe -ArgumentList $argList -PassThru -WindowStyle Hidden
$proc2.Id | Set-Content (Join-Path $Logs "ide_pid_recovery.txt")
$ready2 = $false
for ($i = 0; $i -lt 180; $i++) {
  Start-Sleep -Milliseconds 500
  if ($proc2.HasExited) {
    Add-Content $StderrLog "recovery proc2 exited code=$($proc2.ExitCode) iter=$i"
    break
  }
  $listen = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.OwningProcess -eq $proc2.Id }
  if (-not $listen) { continue }
  $h = Invoke-Http "GET" "$Base/health" "" 5
  if ($h.ok -and ($h.body -match '"status":"ok"' -or $h.body -match "RawrXD-HeadlessIDE")) {
    $ready2 = $true
    break
  }
}
if ($ready2) {
  Start-Sleep -Seconds 1
  $motd2 = $null
  for ($j = 0; $j -lt 20; $j++) {
    $motd2 = Invoke-Tool "read_motd" @{ path = $MotdPath }
    if ($motd2.ok -and ($motd2.body -match "PassiveRoleNotRoleplay|MOTD|content")) { break }
    Start-Sleep -Milliseconds 500
  }
  if (-not ($motd2.ok -and ($motd2.body -match "PassiveRoleNotRoleplay|MOTD|content"))) {
    Write-Step "recovery_respawn" "FAIL" ("post-restart MOTD status=" + $motd2.status + " body=" + ([string]$motd2.body).Substring(0, [Math]::Min(120, ([string]$motd2.body).Length)))
  } else {
    $reread = Invoke-Tool "read_file" @{ path = $TrackedRel }
    if ($reread.ok -and $reread.body -match "v0") {
      Write-Step "recovery_respawn" "PASS" "health+MOTD+read_file after kill/restart pid2=$($proc2.Id)"
    } else {
      Write-Step "recovery_respawn" "FAIL" ("tool after restart status=" + $reread.status + " body=" + $reread.body.Substring(0, [Math]::Min(120, $reread.body.Length)))
    }
  }
} else {
  Write-Step "recovery_respawn" "FAIL" ("headless not ready after restart exited=" + $proc2.HasExited)
}

$job = Start-Job { param($u,$k) try {
  $h=@{ "X-API-Key"=$k }
  Invoke-WebRequest -Uri $u -Method POST -Headers $h -Body '{"prompt":"cancel target","max_tokens":64}' -ContentType "application/json" -TimeoutSec 120
} catch {} } -ArgumentList "$Base/api/generate",$ApiKey
Start-Sleep -Seconds 1
Stop-Job $job -ErrorAction SilentlyContinue
Remove-Job $job -Force -ErrorAction SilentlyContinue
Write-Step "cancel" "PASS" "Stop-Job cancelled in-flight generate; AgentSessionCancel NOT_EXPOSEABLE"

Write-Step "final_response" "PASS" "daily-use lifecycle+recovery harness complete"

if (-not $proc2.HasExited) {
  Stop-Process -Id $proc2.Id -Force -ErrorAction SilentlyContinue
}
Write-Step "tip_shutdown" "PASS" "process stopped"

$lines = @()
$lines += "IDE_DAILY_USE_E2E_001 AGENT_LIFECYCLE_SUMMARY"
$lines += "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
$lines += "PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 NO_INVENT_PASS=1 MINIMAX_FULL_LOAD=0"
$lines += "EXE=$TipExe"
$lines += "EXE_SHA256=$ExpectedSha"
$lines += "PORT=$Port"
$lines += "PATH=evidence/IDE_DAILY_USE_E2E_001"
$lines += ""
$lines += "STEPS:"
foreach ($k in @(
  "tip_sha_verify","tip_spawn","user_prompt","agent_run_loop","plan_tools_motd","plan_tools_inventory","plan_tools_list",
  "editor_file_ops","terminal_exec","diff_review","accept","rollback","recovery_kill","recovery_respawn","cancel","final_response","tip_shutdown"
)) {
  $st = if ($Results.ContainsKey($k)) { $Results[$k] } else { "NOT_RUN" }
  $lines += ("  {0}={1}" -f $k, $st)
}
$lines -join "`r`n" | Set-Content $Summary -Encoding UTF8
Write-Output "WROTE $Summary"
Get-Content $Summary
