# HEADLESS_API_TOOL_TIP_748B_001 — critical /api/tool routes E2E on FROZEN tip 748B
# Client: curl.exe (Invoke-WebRequest unstable after large MOTD on this host)
# Schema: {"tool":"...","args":{...}}
# PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1 REBUILD=0 GhostText ABSORB=NOT_AUTHORIZED
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\HEADLESS_API_TOOL_TIP_748B_001"
$Logs = Join-Path $OutDir "logs"
$Sandbox = Join-Path $OutDir "sandbox"
New-Item -ItemType Directory -Force -Path $Logs, $Sandbox | Out-Null
"seed748b" | Set-Content (Join-Path $Sandbox "seed.txt") -Encoding ascii
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$Expect = "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145"
$Port = 18991
$Sha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$Sha | Set-Content (Join-Path $Logs "exe_sha.txt")
$ShaMatch = [int]($Sha -eq $Expect)
"SHA_MATCH=$ShaMatch SHA=$Sha EXPECT=$Expect" | Set-Content (Join-Path $Logs "sha_match.txt")

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2

function Start-TipServer {
  param([string]$Phase, [string]$Dir)
  $out = Join-Path $Logs ("srv_" + $Phase + "_out.txt")
  $err = Join-Path $Logs ("srv_" + $Phase + "_err.txt")
  $proc = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
    -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir",$Dir) `
    -RedirectStandardOutput $out -RedirectStandardError $err `
    -PassThru -WindowStyle Hidden
  $ready = $false
  for ($i = 0; $i -lt 120; $i++) {
    if ($proc.HasExited) { break }
    try {
      $c = New-Object System.Net.Sockets.TcpClient
      $c.Connect("127.0.0.1", $Port)
      $c.Close()
      $ready = $true
      break
    } catch {}
    Start-Sleep -Milliseconds 250
  }
  "PHASE=$Phase PID=$($proc.Id) READY=$ready EXITED=$($proc.HasExited)" |
    Set-Content (Join-Path $Logs ("srv_" + $Phase + "_meta.txt"))
  return @{ Proc = $proc; Ready = $ready }
}

function Stop-TipServer {
  param($Handle)
  if ($null -ne $Handle -and $null -ne $Handle.Proc -and -not $Handle.Proc.HasExited) {
    Stop-Process -Id $Handle.Proc.Id -Force -ErrorAction SilentlyContinue
  }
  Start-Sleep 2
}

function Curl-Tool {
  param([string]$Tag, [string]$JsonBody, [hashtable]$ExtraHeaders)
  $req = Join-Path $Logs ("req_" + $Tag + ".json")
  $JsonBody | Set-Content -Path $req -Encoding ascii -NoNewline
  $hdr = Join-Path $Logs ("R_" + $Tag + ".hdr.txt")
  $bod = Join-Path $Logs ("R_" + $Tag + ".body.txt")
  $codePath = Join-Path $Logs ("R_" + $Tag + ".code.txt")
  $args = @(
    "-sS","-o",$bod,"-D",$hdr,"-w","%{http_code}",
    "-X","POST","http://127.0.0.1:$Port/api/tool",
    "-H","Content-Type: application/json",
    "--data-binary","@$req"
  )
  if ($ExtraHeaders) {
    foreach ($k in $ExtraHeaders.Keys) {
      $args += @("-H", ($k + ": " + $ExtraHeaders[$k]))
    }
  }
  $code = & curl.exe @args
  if (-not $code) { $code = "-1" }
  "$code".Trim() | Set-Content $codePath
  $bodyTxt = ""
  if (Test-Path $bod) { $bodyTxt = Get-Content $bod -Raw }
  "$Tag|$code|$bodyTxt" | Set-Content (Join-Path $Logs ("R_" + $Tag + ".txt"))
  return @{ code = "$code".Trim(); body = $bodyTxt }
}

function CodeOf([string]$tag) {
  $p = Join-Path $Logs ("R_" + $tag + ".code.txt")
  if (Test-Path $p) { return (Get-Content $p -Raw).Trim() }
  return "-1"
}
function BodyOf([string]$tag) {
  $p = Join-Path $Logs ("R_" + $tag + ".body.txt")
  if (Test-Path $p) { return (Get-Content $p -Raw) }
  return ""
}

# ---------- Phase A: bare no-key ----------
Remove-Item Env:RAWRXD_HOSTED_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_HOSTED_API_SCOPES -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_IDE_EXEC_GRANT -ErrorAction SilentlyContinue
$env:RAWRXD_HEADLESS = "1"
$env:LOCAL_ONLY = "1"
$hA = Start-TipServer -Phase "bare" -Dir $Sandbox
$bare = Curl-Tool -Tag "bare_nokey" -JsonBody '{"tool":"read_motd","args":{}}' -ExtraHeaders @{}
Stop-TipServer $hA

# ---------- Phase B: auth surface (no exec grant) ----------
$key = "tip748b-routes-" + [guid]::NewGuid().ToString("N").Substring(0,12)
$env:RAWRXD_HOSTED_API_KEY = $key
$env:RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin"
Remove-Item Env:RAWRXD_IDE_EXEC_GRANT -ErrorAction SilentlyContinue
$hB = Start-TipServer -Phase "auth" -Dir $Sandbox

$auth = @{ "X-API-Key" = $key; "Origin" = "http://127.0.0.1:$Port" }
$evil = @{ "X-API-Key" = $key; "Origin" = "https://evil.example" }
$nokey = @{ "Origin" = "http://127.0.0.1:$Port" }

Curl-Tool -Tag "evil" -JsonBody '{"tool":"read_motd","args":{}}' -ExtraHeaders $evil | Out-Null
Curl-Tool -Tag "nokey_auth" -JsonBody '{"tool":"read_motd","args":{}}' -ExtraHeaders $nokey | Out-Null
Curl-Tool -Tag "read_motd" -JsonBody '{"tool":"read_motd","args":{}}' -ExtraHeaders $auth | Out-Null
Curl-Tool -Tag "read_file" -JsonBody '{"tool":"read_file","args":{"path":"seed.txt"}}' -ExtraHeaders $auth | Out-Null
Curl-Tool -Tag "list_directory" -JsonBody '{"tool":"list_directory","args":{"path":"."}}' -ExtraHeaders $auth | Out-Null
Curl-Tool -Tag "list_dir" -JsonBody '{"tool":"list_dir","args":{"path":"."}}' -ExtraHeaders $auth | Out-Null

$inside = "inside_ok_748b_routes.txt"
Curl-Tool -Tag "write_file" -JsonBody ("{`"tool`":`"write_file`",`"args`":{`"path`":`"$inside`",`"content`":`"ok748b_routes`"}}") -ExtraHeaders $auth | Out-Null
Curl-Tool -Tag "safe_write_preview" -JsonBody '{"tool":"safe_write_preview","args":{}}' -ExtraHeaders $auth | Out-Null
Curl-Tool -Tag "safe_write_status" -JsonBody '{"tool":"safe_write_status","args":{}}' -ExtraHeaders $auth | Out-Null
# rewrite then rollback
Curl-Tool -Tag "write_file2" -JsonBody ("{`"tool`":`"write_file`",`"args`":{`"path`":`"$inside`",`"content`":`"ok748b_routes_v2`"}}") -ExtraHeaders $auth | Out-Null
Curl-Tool -Tag "safe_write_rollback" -JsonBody '{"tool":"safe_write_rollback","args":{}}' -ExtraHeaders $auth | Out-Null

Curl-Tool -Tag "deny_abs" -JsonBody '{"tool":"write_file","args":{"path":"C:\\Windows\\Temp\\rawrxd_deny_748b_routes.txt","content":"deny"}}' -ExtraHeaders $auth | Out-Null
Curl-Tool -Tag "deny_dotdot" -JsonBody '{"tool":"write_file","args":{"path":"..\\..\\..\\Windows\\Temp\\rawrxd_trav_748b_routes.txt","content":"deny"}}' -ExtraHeaders $auth | Out-Null

Curl-Tool -Tag "search_files" -JsonBody '{"tool":"search_files","args":{"path":".","pattern":"seed"}}' -ExtraHeaders $auth | Out-Null
Curl-Tool -Tag "grep_files" -JsonBody '{"tool":"grep_files","args":{"path":".","pattern":"seed"}}' -ExtraHeaders $auth | Out-Null
Curl-Tool -Tag "exec_nogrant" -JsonBody '{"tool":"execute_command","args":{"command":"cmd /c echo exec_nogrant"}}' -ExtraHeaders $auth | Out-Null

$insideFs = Test-Path (Join-Path $Sandbox $inside)
$absFs = Test-Path "C:\Windows\Temp\rawrxd_deny_748b_routes.txt"
$travFs = Test-Path "C:\Windows\Temp\rawrxd_trav_748b_routes.txt"
Stop-TipServer $hB

# ---------- Phase C: exec grant ----------
$env:RAWRXD_IDE_EXEC_GRANT = "1"
$hC = Start-TipServer -Phase "grant" -Dir $Sandbox
Curl-Tool -Tag "grant_motd" -JsonBody '{"tool":"read_motd","args":{}}' -ExtraHeaders $auth | Out-Null
Curl-Tool -Tag "exec_grant" -JsonBody '{"tool":"execute_command","args":{"command":"cmd /c echo exec_ok_748b_routes"}}' -ExtraHeaders $auth | Out-Null
Stop-TipServer $hC

# ---------- Disposition ----------
$cMotd = CodeOf "read_motd"
$cRead = CodeOf "read_file"
$cList = CodeOf "list_directory"
$cListA = CodeOf "list_dir"
$cWrite = CodeOf "write_file"
$cPrev = CodeOf "safe_write_preview"
$cStat = CodeOf "safe_write_status"
$cRoll = CodeOf "safe_write_rollback"
$cSearch = CodeOf "search_files"
$cGrep = CodeOf "grep_files"
$cExecNo = CodeOf "exec_nogrant"
$cExecYes = CodeOf "exec_grant"
$cEvil = CodeOf "evil"
$cNokey = CodeOf "nokey_auth"
$cBare = CodeOf "bare_nokey"
$cDenyAbs = CodeOf "deny_abs"
$cDenyDot = CodeOf "deny_dotdot"

$dispMotd = if ($cMotd -eq "200") { "RUNTIME" } else { "OPEN" }
$dispRead = if ($cRead -eq "200") { "RUNTIME" } else { "OPEN" }
$dispList = if ($cList -eq "200") { "RUNTIME" } else { "OPEN" }
$dispListA = if ($cListA -eq "200") { "RUNTIME" } else { "OPEN" }
$dispWrite = if ($cWrite -eq "200") { "RUNTIME" } else { "OPEN" }
$dispPrev = if ($cPrev -eq "200") { "RUNTIME" } else { "OPEN" }
$dispStat = if ($cStat -eq "200") { "RUNTIME" } else { "OPEN" }
$dispRoll = if ($cRoll -eq "200") { "RUNTIME" } else { "OPEN" }
$dispSearch = if ($cSearch -eq "200") { "RUNTIME" } else { "OPEN" }
$dispGrep = if ($cGrep -eq "400" -and ((BodyOf "grep_files") -match "unknown_tool")) { "FAIL_CLOSED" } `
  elseif ($cGrep -eq "200") { "RUNTIME" } else { "OPEN" }
$dispExecNo = if ($cExecNo -eq "403" -or ((BodyOf "exec_nogrant") -match "execution_not_granted")) { "FAIL_CLOSED" } else { "OPEN" }
$dispExecYes = if ($cExecYes -eq "200" -and ((BodyOf "exec_grant") -match "exec_ok_748b_routes")) { "RUNTIME" } else { "OPEN" }
$dispEvil = if ($cEvil -eq "403") { "FAIL_CLOSED" } else { "OPEN" }
$dispNokey = if ($cNokey -in @("401","403","503")) { "FAIL_CLOSED" } else { "OPEN" }
# Bare with no key configured: tip may allow local tools (200) or deny (401/403/503).
# Seal observed code honestly — do not invent PASS for auth policy.
$dispBare = if ($cBare -in @("401","403","503")) { "FAIL_CLOSED" } `
  elseif ($cBare -eq "200") { "RUNTIME_UNAUTH_LOCAL" } else { "OPEN" }
$dispDenyAbs = if ($cDenyAbs -eq "403") { "FAIL_CLOSED" } else { "OPEN" }
$dispDenyDot = if ($cDenyDot -eq "403") { "FAIL_CLOSED" } else { "OPEN" }

$G16 = [int]($ShaMatch -eq 1 -and $dispMotd -eq "RUNTIME" -and $dispList -eq "RUNTIME" -and $dispEvil -eq "FAIL_CLOSED")

$routeTable = @"
ROUTE|TOOL|HTTP|DISPOSITION|SHA|NOTE
POST /api/tool|read_motd|$cMotd|$dispMotd|$Sha|MOTD gate ack
POST /api/tool|read_file|$cRead|$dispRead|$Sha|workspace seed.txt
POST /api/tool|list_directory|$cList|$dispList|$Sha|critical
POST /api/tool|list_dir|$cListA|$dispListA|$Sha|alias->list_directory
POST /api/tool|write_file|$cWrite|$dispWrite|$Sha|SafeWriteAtomic
POST /api/tool|safe_write_preview|$cPrev|$dispPrev|$Sha|A06 preview
POST /api/tool|safe_write_status|$cStat|$dispStat|$Sha|A06 status
POST /api/tool|safe_write_rollback|$cRoll|$dispRoll|$Sha|A06 rollback
POST /api/tool|search_files|$cSearch|$dispSearch|$Sha|search present
POST /api/tool|grep_files|$cGrep|$dispGrep|$Sha|not in available[] unknown_tool
POST /api/tool|execute_command(no_grant)|$cExecNo|$dispExecNo|$Sha|execution_not_granted
POST /api/tool|execute_command(grant)|$cExecYes|$dispExecYes|$Sha|RAWRXD_IDE_EXEC_GRANT=1
NEG Origin evil|read_motd|$cEvil|$dispEvil|$Sha|origin_denied
NEG no key (auth cfg)|read_motd|$cNokey|$dispNokey|$Sha|unauthorized
NEG bare no-key cfg|read_motd|$cBare|$dispBare|$Sha|observed auth policy
NEG write abs|write_file|$cDenyAbs|$dispDenyAbs|$Sha|workspace fence
NEG write ..|write_file|$cDenyDot|$dispDenyDot|$Sha|traversal fence
"@
$routeTable | Set-Content (Join-Path $OutDir "ROUTE_TABLE.txt")
$routeTable | Set-Content (Join-Path $Logs "route_table.txt")

$summary = @"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
EVIDENCE=HEADLESS_API_TOOL_TIP_748B_001
TIP_EXE=G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe
TIP_SHA=$Sha
SHA_MATCH=$ShaMatch
PORT=$Port
G16_MET=$G16
FS_INSIDE_WRITE=$insideFs
FS_ABS_LEAK=$absFs
FS_TRAV_LEAK=$travFs
BARE_NOKEY_HTTP=$cBare
EVIL_HTTP=$cEvil
MOTD_HTTP=$cMotd
READ_FILE_HTTP=$cRead
LIST_HTTP=$cList
WRITE_HTTP=$cWrite
SAFE_PREVIEW_HTTP=$cPrev
SAFE_STATUS_HTTP=$cStat
SAFE_ROLLBACK_HTTP=$cRoll
SEARCH_HTTP=$cSearch
GREP_HTTP=$cGrep
EXEC_NOGRANT_HTTP=$cExecNo
EXEC_GRANT_HTTP=$cExecYes
DENY_ABS_HTTP=$cDenyAbs
DENY_DOT_HTTP=$cDenyDot
CLIENT=curl.exe
REBUILD=0
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
NO_INVENT_PASS=1
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
"@
$summary | Set-Content (Join-Path $OutDir "SUMMARY.txt")
$summary | Set-Content (Join-Path $Logs "scoreboard.txt")
Write-Output $summary
Write-Output "---- ROUTE_TABLE ----"
Write-Output $routeTable
