# Final seal — tip 748B headless surface (curl only)
# PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1 REBUILD=0
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\TIP_FREEZE_748B_HEADLESS_SURFACE_001"
$Logs = Join-Path $OutDir "logs"
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$Expect = "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145"
$Port = 18981
$Motd = "G:/~/dev/rawrxd/.cursor/rules/PassiveRoleNotRoleplay.mdc"
# forward-slash path still resolves on Win32; prefer exact workspace path:
$Motd = "G:\\~dev\\rawrxd\\.cursor\\rules\\PassiveRoleNotRoleplay.mdc"
$SandboxRel = "evidence/TIP_FREEZE_748B_HEADLESS_SURFACE_001/sandbox/inside_ok_748b.txt"
$Key = "tip748b_seal_key_01"

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
$Sha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$Sha | Set-Content (Join-Path $Logs "exe_sha.txt")

function Write-Json([string]$path, [string]$json) {
  [System.IO.File]::WriteAllText($path, $json, [System.Text.UTF8Encoding]::new($false))
}

function Hit([string]$tag, [string]$json, [string[]]$hdrs) {
  $req = Join-Path $Logs ("SEAL_" + $tag + ".req.json")
  $hdr = Join-Path $Logs ("SEAL_" + $tag + ".hdr.txt")
  $body = Join-Path $Logs ("SEAL_" + $tag + ".body.txt")
  Write-Json $req $json
  $arg = @("-sS","--max-time","30","-D",$hdr,"-o",$body,"-X","POST",
    "http://127.0.0.1:$Port/api/tool","-H","Content-Type: application/json")
  foreach ($h in $hdrs) { $arg += @("-H", $h) }
  $arg += @("--data-binary", "@$req")
  & curl.exe @arg
  $code = ""
  if (Test-Path $hdr) {
    $m = Select-String -Path $hdr -Pattern 'HTTP/1\.\d\s+(\d+)' | Select-Object -First 1
    if ($m) { $code = $m.Matches.Groups[1].Value }
  }
  "$tag|$code" | Add-Content (Join-Path $Logs "SEAL_score.tsv")
  return $code
}

function Spawn([string]$phase, [hashtable]$extraEnv) {
  Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep 2
  # Clear then set env for child inheritance
  Remove-Item Env:RAWRXD_HOSTED_API_KEY -ErrorAction SilentlyContinue
  Remove-Item Env:RAWRXD_HOSTED_API_SCOPES -ErrorAction SilentlyContinue
  Remove-Item Env:RAWRXD_IDE_EXEC_GRANT -ErrorAction SilentlyContinue
  foreach ($k in $extraEnv.Keys) { Set-Item -Path ("Env:" + $k) -Value $extraEnv[$k] }
  $env:RAWRXD_HEADLESS = "1"
  $env:LOCAL_ONLY = "1"
  $out = Join-Path $Logs ("SEAL_" + $phase + "_out.txt")
  $err = Join-Path $Logs ("SEAL_" + $phase + "_err.txt")
  $p = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
    -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir","G:\~dev\rawrxd") `
    -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -WindowStyle Hidden
  $ready = $false
  for ($i = 0; $i -lt 150; $i++) {
    if ($p.HasExited) { break }
    if (netstat -ano | Select-String ":$Port\s+.*LISTENING") { $ready = $true; break }
    Start-Sleep -Milliseconds 400
  }
  "PHASE=$phase PID=$($p.Id) READY=$ready EXITED=$($p.HasExited)" | Set-Content (Join-Path $Logs ("SEAL_" + $phase + "_meta.txt"))
  return $p
}

Remove-Item (Join-Path $Logs "SEAL_score.tsv") -ErrorAction SilentlyContinue
$auth = @(
  "Origin: http://127.0.0.1:$Port",
  "X-Api-Key: $Key"
)
$evil = @(
  "Origin: https://evil.example",
  "X-Api-Key: $Key"
)
$nokey = @(
  "Origin: http://127.0.0.1:$Port"
)

# Phase A: keyed surface
$p = Spawn "auth" @{
  RAWRXD_HOSTED_API_KEY = $Key
  RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin,*"
}

$cNokey = Hit "nokey" "{`"tool`":`"read_motd`",`"args`":{`"path`":`"G:\\~dev\\rawrxd\\.cursor\\rules\\PassiveRoleNotRoleplay.mdc`"}}" $nokey
$cEvil = Hit "evil" "{`"tool`":`"read_motd`",`"args`":{`"path`":`"G:\\~dev\\rawrxd\\.cursor\\rules\\PassiveRoleNotRoleplay.mdc`"}}" $evil
$cMotd = Hit "motd" "{`"tool`":`"read_motd`",`"args`":{`"path`":`"G:\\~dev\\rawrxd\\.cursor\\rules\\PassiveRoleNotRoleplay.mdc`"}}" $auth
$cList = Hit "list" "{`"tool`":`"list_directory`",`"args`":{`"path`":`".`"}}" $auth
$cWrite = Hit "write_inside" "{`"tool`":`"write_file`",`"args`":{`"path`":`"$SandboxRel`",`"content`":`"ok748b`"}}" $auth
$cAbs = Hit "deny_abs" "{`"tool`":`"write_file`",`"args`":{`"path`":`"C:\\Windows\\Temp\\rawrxd_deny_748b.txt`",`"content`":`"deny`"}}" $auth
$cDot = Hit "deny_dotdot" "{`"tool`":`"write_file`",`"args`":{`"path`":`"..\\..\\Windows\\Temp\\rawrxd_trav_748b.txt`",`"content`":`"deny`"}}" $auth
$cUnc = Hit "deny_unc" "{`"tool`":`"write_file`",`"args`":{`"path`":`"\\\\127.0.0.1\\c$\\Windows\\Temp\\rawrxd_unc_748b.txt`",`"content`":`"deny`"}}" $auth
$cExecNo = Hit "exec_nogrant" "{`"tool`":`"execute_command`",`"args`":{`"command`":`"cmd /c echo exec_nogrant`"}}" $auth

$insideFs = Test-Path "G:\~dev\rawrxd\$SandboxRel"
$absFs = Test-Path "C:\Windows\Temp\rawrxd_deny_748b.txt"
$travFs = Test-Path "C:\Windows\Temp\rawrxd_trav_748b.txt"

if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 2

# Phase B: exec grant
$p2 = Spawn "grant" @{
  RAWRXD_HOSTED_API_KEY = $Key
  RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin,*"
  RAWRXD_IDE_EXEC_GRANT = "1"
}
[void](Hit "grant_motd" "{`"tool`":`"read_motd`",`"args`":{`"path`":`"G:\\~dev\\rawrxd\\.cursor\\rules\\PassiveRoleNotRoleplay.mdc`"}}" $auth)
$cExecYes = Hit "exec_grant" "{`"tool`":`"execute_command`",`"args`":{`"command`":`"cmd /c echo exec_ok_748b`"}}" $auth
if ($p2 -and -not $p2.HasExited) { Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue }

function Body([string]$tag) {
  $p = Join-Path $Logs ("SEAL_" + $tag + ".body.txt")
  if (Test-Path $p) { return Get-Content $p -Raw }
  return ""
}

$motdOk = [int]($cMotd -eq "200" -and ((Body "motd") -match "PassiveRoleNotRoleplay|MOTD_ACK|Message of the Day"))
$listOk = [int]($cList -eq "200" -and ((Body "list") -match "entries|path"))
$evilOk = [int]($cEvil -eq "403" -and ((Body "evil") -match "origin_denied"))
$nokeyOk = [int]($cNokey -in @("401","403"))
$writeOk = [int]($cWrite -eq "200" -and $insideFs)
$absOk = [int]($cAbs -eq "403" -and -not $absFs)
$dotOk = [int]($cDot -eq "403" -and -not $travFs)
$uncOk = [int]($cUnc -eq "403")
$execNoOk = [int](((Body "exec_nogrant") -match "execution_not_granted") -or $cExecNo -eq "403")
$execYesOk = [int]($cExecYes -eq "200" -and ((Body "exec_grant") -match "exec_ok_748b"))
$shaOk = [int]($Sha -eq $Expect)

$G16 = [int]($shaOk -and $motdOk -and $listOk -and $evilOk)
$A06 = [int]($shaOk -and $writeOk -and $absOk -and $dotOk -and $uncOk)
$A07 = [int]($shaOk -and $nokeyOk -and $evilOk -and $execNoOk)

$summary = @"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
TIP_SHA=$Sha
SHA_MATCH=$shaOk
PORT=$Port
G16_MOTD=$motdOk
G16_LIST=$listOk
G16_EVIL=$evilOk
G16_MET=$G16
A06_WRITE_INSIDE=$writeOk
A06_DENY_ABS=$absOk
A06_DENY_DOTDOT=$dotOk
A06_DENY_UNC=$uncOk
A06_DENY_RUNTIME=$A06
A07_NOKEY=$nokeyOk
A07_EXEC_NOGRANT=$execNoOk
A07_RUNTIME=$A07
EXEC_GRANT_PASS=$execYesOk
EXEC_GRANT_HTTP=$cExecYes
HTTP_CODES=nokey:$cNokey,evil:$cEvil,motd:$cMotd,list:$cList,write:$cWrite,abs:$cAbs,dot:$cDot,unc:$cUnc,execNo:$cExecNo,execYes:$cExecYes
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
REBUILD=0
NO_INVENT_PASS=1
GHOSTTEXT_B421_ABSORB=NOT_AUTHORIZED
CITE=TIP_FREEZE_748B_HEADLESS_SURFACE_001
"@
$summary | Set-Content (Join-Path $OutDir "SUMMARY.txt")
$summary | Set-Content (Join-Path $Logs "scoreboard.txt")
Write-Output $summary
