# TIP_FREEZE_748B_HEADLESS_SURFACE_002 — G16 tip /api/tool (curl only)
# AUTHORITY: TIP_FREEZE_001\bin SHA 748B… · REBUILD=0 · ABSORB NOT_AUTHORIZED · PROMOTE=0
# G16 = SHA_MATCH && MOTD_200 && LIST_200 && EVIL_403
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\TIP_FREEZE_748B_HEADLESS_SURFACE_002"
$Logs = Join-Path $OutDir "logs"
$Sandbox = Join-Path $OutDir "sandbox"
New-Item -ItemType Directory -Force -Path $Logs, $Sandbox | Out-Null
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$ExpectSha = "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145"
$Port = 18981
$MotdPath = "G:/~dev/rawrxd/.cursor/rules/PassiveRoleNotRoleplay.mdc"
$Curl = "C:\Windows\System32\curl.exe"

$Sha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$Sha | Set-Content (Join-Path $Logs "exe_sha.txt")
$ShaMatch = [int]($Sha -eq $ExpectSha)
"SHA_MATCH=$ShaMatch SHA=$Sha" | Set-Content (Join-Path $Logs "sha_match.txt")
if ($ShaMatch -ne 1) { throw "TIP SHA mismatch; abort" }

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2

function Invoke-CurlTool {
  param(
    [string]$Tag,
    [string]$JsonBody,
    [string[]]$ExtraHeaders
  )
  $hdr = Join-Path $Logs ("R_" + $Tag + ".hdr.txt")
  $body = Join-Path $Logs ("R_" + $Tag + ".body.txt")
  $codef = Join-Path $Logs ("R_" + $Tag + ".code.txt")
  $reqf = Join-Path $Logs ("R_" + $Tag + ".req.json")
  $JsonBody | Set-Content $reqf -Encoding ascii
  $args = @(
    "-sS", "-D", $hdr, "-o", $body, "-w", "%{http_code}",
    "--max-time", "45",
    "-H", "Content-Type: application/json; charset=utf-8"
  )
  foreach ($h in $ExtraHeaders) { $args += @("-H", $h) }
  $args += @("-d", $JsonBody, "http://127.0.0.1:$Port/api/tool")
  $code = & $Curl @args 2> (Join-Path $Logs ("R_" + $Tag + ".curlerr.txt"))
  if (-not $code) { $code = "-1" }
  "$code".Trim() | Set-Content $codef -Encoding ascii
  return "$code".Trim()
}

function Wait-Port([int]$Seconds = 90) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    if (netstat -ano | Select-String ":$Port\s+.*LISTENING") { return $true }
    Start-Sleep -Milliseconds 400
  }
  return $false
}

# --- Phase A: bare no-key (auth not configured) ---
Remove-Item Env:RAWRXD_HOSTED_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_HOSTED_API_SCOPES -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_IDE_EXEC_GRANT -ErrorAction SilentlyContinue
$env:RAWRXD_HEADLESS = "1"
$env:LOCAL_ONLY = "1"

$pA = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir",$Sandbox) `
  -RedirectStandardOutput (Join-Path $Logs "srv_bare_out.txt") `
  -RedirectStandardError (Join-Path $Logs "srv_bare_err.txt") `
  -PassThru -WindowStyle Hidden
$readyA = Wait-Port
"PHASE=bare PID=$($pA.Id) READY=$readyA EXITED=$($pA.HasExited)" | Set-Content (Join-Path $Logs "srv_bare_meta.txt")
$bareJson = "{`"tool`":`"read_motd`",`"args`":{`"path`":`"$MotdPath`"}}"
$bareCode = Invoke-CurlTool -Tag "bare_motd" -JsonBody $bareJson -ExtraHeaders @()
if (-not $pA.HasExited) { Stop-Process -Id $pA.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 2

# --- Phase B: auth surface (G16 core) ---
$key = "tip748b-g16-" + [guid]::NewGuid().ToString("N").Substring(0, 12)
$env:RAWRXD_HOSTED_API_KEY = $key
$env:RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin,*"
Remove-Item Env:RAWRXD_IDE_EXEC_GRANT -ErrorAction SilentlyContinue
$key | Set-Content (Join-Path $Logs "api_key_len.txt")
$key.Length | Add-Content (Join-Path $Logs "api_key_len.txt")

$pB = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir",$Sandbox) `
  -RedirectStandardOutput (Join-Path $Logs "srv_auth_out.txt") `
  -RedirectStandardError (Join-Path $Logs "srv_auth_err.txt") `
  -PassThru -WindowStyle Hidden
$readyB = Wait-Port
"PHASE=auth PID=$($pB.Id) READY=$readyB EXITED=$($pB.HasExited) KEY_LEN=$($key.Length)" | Set-Content (Join-Path $Logs "srv_auth_meta.txt")

$authH = @(
  "X-Api-Key: $key",
  "Origin: http://127.0.0.1:$Port"
)
$evilH = @(
  "X-Api-Key: $key",
  "Origin: https://evil.example"
)
$nokeyH = @(
  "Origin: http://127.0.0.1:$Port"
)
$nullH = @(
  "X-Api-Key: $key",
  "Origin: null"
)

$motdJson = "{`"tool`":`"read_motd`",`"args`":{`"path`":`"$MotdPath`"}}"
$listJson = "{`"tool`":`"list_directory`",`"args`":{`"path`":`".`"}}"

$evilCode = Invoke-CurlTool -Tag "evil" -JsonBody $motdJson -ExtraHeaders $evilH
$nokeyCode = Invoke-CurlTool -Tag "nokey_auth" -JsonBody $motdJson -ExtraHeaders $nokeyH
$nullCode = Invoke-CurlTool -Tag "nullorig" -JsonBody $motdJson -ExtraHeaders $nullH
$motdCode = Invoke-CurlTool -Tag "motd" -JsonBody $motdJson -ExtraHeaders $authH
$listCode = Invoke-CurlTool -Tag "list" -JsonBody $listJson -ExtraHeaders $authH

# secondary authorized POS for surface completeness (not G16 conjunction)
$readJson = "{`"tool`":`"read_file`",`"args`":{`"path`":`"seed.txt`"}}"
$writeJson = "{`"tool`":`"write_file`",`"args`":{`"path`":`"inside_ok.txt`",`"content`":`"ok748b`"}}"
$denyAbsJson = "{`"tool`":`"write_file`",`"args`":{`"path`":`"C:/Windows/Temp/rawrxd_deny_748b_g16.txt`",`"content`":`"deny`"}}"
$denyDotJson = "{`"tool`":`"write_file`",`"args`":{`"path`":`"../../../Windows/Temp/rawrxd_trav_748b_g16.txt`",`"content`":`"deny`"}}"
$execNoJson = "{`"tool`":`"execute_command`",`"args`":{`"command`":`"cmd /c echo exec_nogrant`"}}"

$readCode = Invoke-CurlTool -Tag "read_file" -JsonBody $readJson -ExtraHeaders $authH
$writeCode = Invoke-CurlTool -Tag "write_inside" -JsonBody $writeJson -ExtraHeaders $authH
$denyAbsCode = Invoke-CurlTool -Tag "deny_abs" -JsonBody $denyAbsJson -ExtraHeaders $authH
$denyDotCode = Invoke-CurlTool -Tag "deny_dotdot" -JsonBody $denyDotJson -ExtraHeaders $authH
$execNoCode = Invoke-CurlTool -Tag "exec_nogrant" -JsonBody $execNoJson -ExtraHeaders $authH

$insideFs = Test-Path (Join-Path $Sandbox "inside_ok.txt")
$absFs = Test-Path "C:\Windows\Temp\rawrxd_deny_748b_g16.txt"
$travFs = Test-Path "C:\Windows\Temp\rawrxd_trav_748b_g16.txt"

if (-not $pB.HasExited) { Stop-Process -Id $pB.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 2

# --- Phase C: exec grant (cite only; != invent G16 from HEADLESS_EXECUTE_COMMAND_003) ---
$env:RAWRXD_IDE_EXEC_GRANT = "1"
$pC = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir",$Sandbox) `
  -RedirectStandardOutput (Join-Path $Logs "srv_grant_out.txt") `
  -RedirectStandardError (Join-Path $Logs "srv_grant_err.txt") `
  -PassThru -WindowStyle Hidden
$readyC = Wait-Port
"PHASE=grant PID=$($pC.Id) READY=$readyC EXITED=$($pC.HasExited)" | Set-Content (Join-Path $Logs "srv_grant_meta.txt")
[void](Invoke-CurlTool -Tag "grant_motd" -JsonBody $motdJson -ExtraHeaders $authH)
$execYesCode = Invoke-CurlTool -Tag "exec_grant" -JsonBody "{`"tool`":`"execute_command`",`"args`":{`"command`":`"cmd /c echo exec_ok_748b`"}}" -ExtraHeaders $authH
$execYesBody = Get-Content (Join-Path $Logs "R_exec_grant.body.txt") -Raw -ErrorAction SilentlyContinue
if (-not $pC.HasExited) { Stop-Process -Id $pC.Id -Force -ErrorAction SilentlyContinue }

$g16_motd = [int]($motdCode -eq "200")
$g16_list = [int]($listCode -eq "200")
$g16_evil = [int]($evilCode -eq "403")
$G16 = [int]($ShaMatch -eq 1 -and $g16_motd -eq 1 -and $g16_list -eq 1 -and $g16_evil -eq 1)
$execGrantPass = [int](($execYesCode -eq "200") -and ($execYesBody -match "exec_ok_748b|`"exitCode`":0"))

$tsv = @(
  "tag|http",
  "bare_motd|$bareCode",
  "evil|$evilCode",
  "nokey_auth|$nokeyCode",
  "nullorig|$nullCode",
  "motd|$motdCode",
  "list|$listCode",
  "read_file|$readCode",
  "write_inside|$writeCode",
  "deny_abs|$denyAbsCode",
  "deny_dotdot|$denyDotCode",
  "exec_nogrant|$execNoCode",
  "exec_grant|$execYesCode"
) -join "`n"
$tsv | Set-Content (Join-Path $Logs "score.tsv") -Encoding ascii

$summary = @"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
EVIDENCE=TIP_FREEZE_748B_HEADLESS_SURFACE_002
WORKSTREAM=TOP10_4_G16_HEADLESS_TOOL_SURFACE_TIP_748B
TIP_EXE=$TipExe
TIP_SHA=$Sha
SHA_MATCH=$ShaMatch
PORT=$Port
MOTD_PATH=$MotdPath
BIND=127.0.0.1
LOCAL_ONLY=1
G16_MOTD_200=$g16_motd
G16_LIST_200=$g16_list
G16_EVIL_403=$g16_evil
G16_MET=$G16
BARE_MOTD_HTTP=$bareCode
NOKEY_AUTH_HTTP=$nokeyCode
NULL_ORIG_HTTP=$nullCode
READ_FILE_HTTP=$readCode
WRITE_INSIDE_HTTP=$writeCode
DENY_ABS_HTTP=$denyAbsCode
DENY_DOTDOT_HTTP=$denyDotCode
EXEC_NOGRANT_HTTP=$execNoCode
EXEC_GRANT_HTTP=$execYesCode
EXEC_GRANT_PASS=$execGrantPass
FS_INSIDE=$insideFs
FS_ABS_LEAK=$absFs
FS_TRAV_LEAK=$travFs
HEADLESS_EXECUTE_COMMAND_003=CITE_ONLY_NOT_TRANSFER
PRIOR_SURFACE_001_G16_MET=0
REBUILD_THIS_DISPATCH=0
ABSORB=NOT_AUTHORIZED
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
NO_INVENT_PASS=1
NO_BUILD_TREE_SUBSTITUTION=1
"@
$summary | Set-Content (Join-Path $OutDir "SUMMARY.txt") -Encoding ascii
$summary | Set-Content (Join-Path $Logs "scoreboard.txt") -Encoding ascii
Write-Output $summary
