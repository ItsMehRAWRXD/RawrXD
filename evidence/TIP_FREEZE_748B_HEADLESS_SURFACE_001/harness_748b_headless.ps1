# TIP_FREEZE_748B_HEADLESS_SURFACE_001
# G16 + A06 deny + A07 isolation + execute_command on FROZEN 748B
# Schema: {"tool":"...","args":{...}}  Header: X-Api-Key
# PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1 REBUILD=0
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\TIP_FREEZE_748B_HEADLESS_SURFACE_001"
$Logs = Join-Path $OutDir "logs"
$Sandbox = Join-Path $OutDir "sandbox"
New-Item -ItemType Directory -Force -Path $Logs, $Sandbox | Out-Null
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$Port = 18951
$MotdPath = "G:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc"
$Sha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$Sha | Set-Content (Join-Path $Logs "exe_sha.txt")
$ShaMatch = [int]($Sha -eq "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145")
"SHA_MATCH=$ShaMatch SHA=$Sha" | Set-Content (Join-Path $Logs "sha_match.txt")

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2

function Invoke-ApiTool {
  param([string]$Name, [hashtable]$ArgsObj, [hashtable]$Headers, [string]$Tag, [int]$TimeoutSec = 30)
  $bodyObj = @{ tool = $Name; args = $ArgsObj }
  $json = ($bodyObj | ConvertTo-Json -Compress -Depth 6)
  $uri = "http://127.0.0.1:$Port/api/tool"
  $code = -1
  $body = ""
  try {
    $resp = Invoke-WebRequest -Uri $uri -Method POST -Body ([System.Text.Encoding]::UTF8.GetBytes($json)) `
      -ContentType "application/json; charset=utf-8" `
      -Headers $Headers -TimeoutSec $TimeoutSec -UseBasicParsing
    $code = [int]$resp.StatusCode
    $body = [string]$resp.Content
  } catch {
    if ($_.Exception.Response) {
      $code = [int]$_.Exception.Response.StatusCode.value__
      if (-not $code) { $code = [int]$_.Exception.Response.StatusCode }
      try {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $body = $reader.ReadToEnd()
      } catch { $body = "" }
    } else {
      $code = -1
      $body = $_.Exception.Message
    }
  }
  "$Tag|$code|$body" | Set-Content (Join-Path $Logs ("R_" + $Tag + ".txt"))
  $code | Set-Content (Join-Path $Logs ("R_" + $Tag + ".code.txt"))
  $body | Set-Content (Join-Path $Logs ("R_" + $Tag + ".body.txt"))
  $json | Set-Content (Join-Path $Logs ("R_" + $Tag + ".req.json"))
  return @{ code = $code; body = $body }
}

function Wait-PortReady {
  param($Proc, [int]$Seconds = 90)
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    if ($Proc.HasExited) { return $false }
    if (netstat -ano | Select-String ":$Port\s+.*LISTENING") { return $true }
    Start-Sleep -Milliseconds 400
  }
  return $false
}

# --- Phase A: bare no-key ---
Remove-Item Env:RAWRXD_HOSTED_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_HOSTED_API_SCOPES -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_IDE_EXEC_GRANT -ErrorAction SilentlyContinue
$env:RAWRXD_HEADLESS = "1"
$env:LOCAL_ONLY = "1"

$pA = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir","G:\~dev\rawrxd") `
  -RedirectStandardOutput (Join-Path $Logs "srv_bare_out.txt") `
  -RedirectStandardError (Join-Path $Logs "srv_bare_err.txt") `
  -PassThru -WindowStyle Hidden
$ready = Wait-PortReady $pA
"PHASE=bare PID=$($pA.Id) READY=$ready EXITED=$($pA.HasExited)" | Set-Content (Join-Path $Logs "srv_bare_meta.txt")
$bare = Invoke-ApiTool -Name "read_motd" -ArgsObj @{ path = $MotdPath } -Headers @{} -Tag "bare_nokey"
"BARE_NOKEY_HTTP=$($bare.code)" | Set-Content (Join-Path $Logs "bare_nokey_summary.txt")
if (-not $pA.HasExited) { Stop-Process -Id $pA.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 2

# --- Phase B: auth + surface probes ---
$key = "tip748b-surface-" + [guid]::NewGuid().ToString("N").Substring(0,12)
$env:RAWRXD_HOSTED_API_KEY = $key
$env:RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin,*"
Remove-Item Env:RAWRXD_IDE_EXEC_GRANT -ErrorAction SilentlyContinue

$pB = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir",$Sandbox) `
  -RedirectStandardOutput (Join-Path $Logs "srv_auth_out.txt") `
  -RedirectStandardError (Join-Path $Logs "srv_auth_err.txt") `
  -PassThru -WindowStyle Hidden
$ready = Wait-PortReady $pB
"PHASE=auth PID=$($pB.Id) READY=$ready EXITED=$($pB.HasExited) KEY_LEN=$($key.Length)" | Set-Content (Join-Path $Logs "srv_auth_meta.txt")

$auth = @{ "X-Api-Key" = $key; "Origin" = "http://127.0.0.1:$Port" }
$evil = @{ "X-Api-Key" = $key; "Origin" = "https://evil.example" }
$nokey = @{ "Origin" = "http://127.0.0.1:$Port" }

[void](Invoke-ApiTool -Name "read_motd" -ArgsObj @{ path = $MotdPath } -Headers $evil -Tag "evil")
[void](Invoke-ApiTool -Name "read_motd" -ArgsObj @{ path = $MotdPath } -Headers $nokey -Tag "nokey_auth")
[void](Invoke-ApiTool -Name "read_motd" -ArgsObj @{ path = $MotdPath } -Headers $auth -Tag "motd")
[void](Invoke-ApiTool -Name "list_directory" -ArgsObj @{ path = "." } -Headers $auth -Tag "list")
$insidePath = "inside_ok_748b.txt"
[void](Invoke-ApiTool -Name "write_file" -ArgsObj @{ path = $insidePath; content = "ok748b" } -Headers $auth -Tag "write_inside")
[void](Invoke-ApiTool -Name "write_file" -ArgsObj @{ path = "C:\Windows\Temp\rawrxd_deny_748b.txt"; content = "deny" } -Headers $auth -Tag "deny_abs")
[void](Invoke-ApiTool -Name "write_file" -ArgsObj @{ path = "..\..\..\Windows\Temp\rawrxd_trav_748b.txt"; content = "deny" } -Headers $auth -Tag "deny_dotdot")
[void](Invoke-ApiTool -Name "write_file" -ArgsObj @{ path = "\\127.0.0.1\c$\Windows\Temp\rawrxd_unc_748b.txt"; content = "deny" } -Headers $auth -Tag "deny_unc")
[void](Invoke-ApiTool -Name "execute_command" -ArgsObj @{ command = "cmd /c echo exec_nogrant" } -Headers $auth -Tag "exec_nogrant")

$insideFs = Test-Path (Join-Path $Sandbox $insidePath)
$absFs = Test-Path "C:\Windows\Temp\rawrxd_deny_748b.txt"
$travFs = Test-Path "C:\Windows\Temp\rawrxd_trav_748b.txt"

if (-not $pB.HasExited) { Stop-Process -Id $pB.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 2

# --- Phase C: exec grant ---
$env:RAWRXD_IDE_EXEC_GRANT = "1"
$pC = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir",$Sandbox) `
  -RedirectStandardOutput (Join-Path $Logs "srv_grant_out.txt") `
  -RedirectStandardError (Join-Path $Logs "srv_grant_err.txt") `
  -PassThru -WindowStyle Hidden
$ready = Wait-PortReady $pC
"PHASE=grant PID=$($pC.Id) READY=$ready EXITED=$($pC.HasExited)" | Set-Content (Join-Path $Logs "srv_grant_meta.txt")
[void](Invoke-ApiTool -Name "execute_command" -ArgsObj @{ command = "cmd /c echo exec_ok_748b" } -Headers $auth -Tag "exec_grant")
if (-not $pC.HasExited) { Stop-Process -Id $pC.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 1

function CodeOf([string]$tag) { return (Get-Content (Join-Path $Logs ("R_" + $tag + ".code.txt")) -Raw).Trim() }
function BodyOf([string]$tag) { return (Get-Content (Join-Path $Logs ("R_" + $tag + ".body.txt")) -Raw) }

$g16_motd = [int]((CodeOf "motd") -eq "200")
$g16_list = [int]((CodeOf "list") -eq "200")
$g16_evil = [int]((CodeOf "evil") -eq "403")
$a07_nokey = [int]((CodeOf "nokey_auth") -in @("401","403","503"))
$a06_in = [int]((CodeOf "write_inside") -eq "200")
$a06_abs = [int]((CodeOf "deny_abs") -eq "403")
$a06_dot = [int]((CodeOf "deny_dotdot") -eq "403")
$a06_unc = [int]((CodeOf "deny_unc") -eq "403")
$execNoBody = BodyOf "exec_nogrant"
$a07_exec = [int](($execNoBody -match "execution_not_granted") -or ((CodeOf "exec_nogrant") -eq "403"))
$execYesCode = CodeOf "exec_grant"
$execYesBody = BodyOf "exec_grant"
$exec_grant = [int](($execYesCode -eq "200") -and ($execYesBody -match "exec_ok_748b|`"exitCode`":0"))

$G16 = [int]($ShaMatch -eq 1 -and $g16_motd -eq 1 -and $g16_list -eq 1 -and $g16_evil -eq 1)
$A06_DENY = [int]($ShaMatch -eq 1 -and $a06_in -eq 1 -and $a06_abs -eq 1 -and $a06_dot -eq 1 -and $a06_unc -eq 1 -and (-not $absFs) -and (-not $travFs))
$A07 = [int]($ShaMatch -eq 1 -and $a07_nokey -eq 1 -and $g16_evil -eq 1 -and $a07_exec -eq 1)

$summary = @"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
TIP_SHA=$Sha
SHA_MATCH=$ShaMatch
PORT=$Port
G16_MOTD_200=$g16_motd
G16_LIST_200=$g16_list
G16_EVIL_403=$g16_evil
G16_MET=$G16
A07_NOKEY_FAILCLOSED=$a07_nokey
A06_WRITE_INSIDE_200=$a06_in
A06_DENY_ABS_403=$a06_abs
A06_DENY_DOTDOT_403=$a06_dot
A06_DENY_UNC_403=$a06_unc
A06_FS_INSIDE=$insideFs
A06_FS_ABS=$absFs
A06_FS_TRAV=$travFs
A06_DENY_RUNTIME=$A06_DENY
A07_EXEC_NOGRANT=$a07_exec
EXEC_GRANT_PASS=$exec_grant
EXEC_GRANT_HTTP=$execYesCode
A07_RUNTIME=$A07
BARE_NOKEY_HTTP=$($bare.code)
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
REBUILD=0
NO_INVENT_PASS=1
"@
$summary | Set-Content (Join-Path $OutDir "SUMMARY.txt")
$summary | Set-Content (Join-Path $Logs "scoreboard.txt")
Write-Output $summary
