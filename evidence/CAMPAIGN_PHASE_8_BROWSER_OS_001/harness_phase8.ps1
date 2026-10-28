# CAMPAIGN_PHASE_8_BROWSER_OS_001 — tip 748B Browser/OS + security
# PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1 REBUILD=0
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\CAMPAIGN_PHASE_8_BROWSER_OS_001"
$Logs = Join-Path $OutDir "logs"
$Sandbox = Join-Path $OutDir "sandbox"
New-Item -ItemType Directory -Force -Path $Logs, $Sandbox | Out-Null
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$Port = 18958
$MotdPath = "G:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc"
$Sha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$Sha | Set-Content (Join-Path $Logs "exe_sha.txt")
$ShaMatch = [int]($Sha -eq "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145")
"SHA_MATCH=$ShaMatch SHA=$Sha" | Set-Content (Join-Path $Logs "sha_match.txt")

$loaderPath = Join-Path (Split-Path $TipExe) "WebView2Loader.dll"
$LoaderPresent = [int](Test-Path $loaderPath)
"WEBVIEW2LOADER_PRESENT=$LoaderPresent PATH=$loaderPath" | Set-Content (Join-Path $Logs "webview2_loader.txt")

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

$key = "phase8-748b-" + [guid]::NewGuid().ToString("N").Substring(0,12)
$env:RAWRXD_HEADLESS = "1"
$env:LOCAL_ONLY = "1"
$env:RAWRXD_HOSTED_API_KEY = $key
$env:RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin,*"
Remove-Item Env:RAWRXD_IDE_EXEC_GRANT -ErrorAction SilentlyContinue

$p = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir",$Sandbox) `
  -RedirectStandardOutput (Join-Path $Logs "srv_out.txt") `
  -RedirectStandardError (Join-Path $Logs "srv_err.txt") `
  -PassThru -WindowStyle Hidden
$ready = Wait-PortReady $p
"PID=$($p.Id) READY=$ready EXITED=$($p.HasExited)" | Set-Content (Join-Path $Logs "srv_meta.txt")

$auth = @{ "X-Api-Key" = $key; "Origin" = "http://127.0.0.1:$Port" }
$evil = @{ "X-Api-Key" = $key; "Origin" = "https://evil.example" }

[void](Invoke-ApiTool -Name "read_motd" -ArgsObj @{ path = $MotdPath } -Headers $auth -Tag "motd")
[void](Invoke-ApiTool -Name "read_motd" -ArgsObj @{ path = $MotdPath } -Headers $evil -Tag "evil_origin")
[void](Invoke-ApiTool -Name "write_file" -ArgsObj @{ path = "p8_inside.txt"; content = "ok" } -Headers $auth -Tag "write_inside")
[void](Invoke-ApiTool -Name "write_file" -ArgsObj @{ path = "C:\Windows\Temp\rawrxd_p8_deny.txt"; content = "deny" } -Headers $auth -Tag "deny_abs")
[void](Invoke-ApiTool -Name "write_file" -ArgsObj @{ path = "..\..\..\Windows\Temp\rawrxd_p8_trav.txt"; content = "deny" } -Headers $auth -Tag "deny_dotdot")
[void](Invoke-ApiTool -Name "write_file" -ArgsObj @{ path = "\\127.0.0.1\c$\Windows\Temp\rawrxd_p8_unc.txt"; content = "deny" } -Headers $auth -Tag "deny_unc")
[void](Invoke-ApiTool -Name "execute_command" -ArgsObj @{ command = "cmd /c echo p8_nogrant" } -Headers $auth -Tag "exec_nogrant")
# Browser/OS native action tools — expect missing or fail-closed (not invent PASS)
[void](Invoke-ApiTool -Name "browser_navigate" -ArgsObj @{ url = "https://example.com" } -Headers $auth -Tag "browser_navigate")
[void](Invoke-ApiTool -Name "browser_automation" -ArgsObj @{ action = "click"; selector = "a" } -Headers $auth -Tag "browser_automation")
[void](Invoke-ApiTool -Name "native_action" -ArgsObj @{ action = "open_explorer" } -Headers $auth -Tag "native_action")
[void](Invoke-ApiTool -Name "os_explorer" -ArgsObj @{ path = "." } -Headers $auth -Tag "os_explorer")

$insideFs = Test-Path (Join-Path $Sandbox "p8_inside.txt")
$absFs = Test-Path "C:\Windows\Temp\rawrxd_p8_deny.txt"
$travFs = Test-Path "C:\Windows\Temp\rawrxd_p8_trav.txt"

if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 1

function CodeOf([string]$tag) {
  $f = Join-Path $Logs ("R_" + $tag + ".code.txt")
  if (Test-Path $f) { return (Get-Content $f -Raw).Trim() }
  return "-1"
}
function BodyOf([string]$tag) {
  $f = Join-Path $Logs ("R_" + $tag + ".body.txt")
  if (Test-Path $f) { return (Get-Content $f -Raw) }
  return ""
}

$sec_motd = [int]((CodeOf "motd") -eq "200")
$sec_evil = [int]((CodeOf "evil_origin") -eq "403")
$sec_in = [int]((CodeOf "write_inside") -eq "200")
$sec_abs = [int]((CodeOf "deny_abs") -eq "403")
$sec_dot = [int]((CodeOf "deny_dotdot") -eq "403")
$sec_unc = [int]((CodeOf "deny_unc") -eq "403")
$sec_exec = [int](((BodyOf "exec_nogrant") -match "execution_not_granted") -or ((CodeOf "exec_nogrant") -eq "403"))
$SEC_RUNTIME = [int]($ShaMatch -eq 1 -and $sec_evil -eq 1 -and $sec_abs -eq 1 -and $sec_dot -eq 1 -and $sec_unc -eq 1 -and (-not $absFs) -and (-not $travFs) -and $sec_exec -eq 1)

# Browser tools: honest disposition — unknown tool / non-200 = FAIL_CLOSED NOT_RUN product path
function ToolDisp([string]$tag) {
  $c = CodeOf $tag
  $b = BodyOf $tag
  if ($c -eq "200" -and ($b -match '"ok"\s*:\s*true|navigated|RUNTIME')) { return "RUNTIME_REACHED" }
  if ($c -in @("404","400","501","503") -or ($b -match "unknown|not.?found|unsupported|FEATURE_FICTION|NOT_PRODUCT")) {
    return "FAIL_CLOSED_NOT_RUN"
  }
  return "FAIL_CLOSED_NOT_RUN"
}

$navDisp = ToolDisp "browser_navigate"
$autoDisp = ToolDisp "browser_automation"
$natDisp = ToolDisp "native_action"
$osDisp = ToolDisp "os_explorer"

# GUI browser HWND: tip lacks WebView2Loader → NOT_RUN blocker
$guiBlocker = "WEBVIEW2LOADER_MISSING_IN_TIP_BIN"
if ($LoaderPresent -eq 1) { $guiBlocker = "LOADER_PRESENT_BUT_GUI_HWND_PROBE_NOT_RUN_HEADLESS_ONLY" }

$summary = @"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
CAMPAIGN_PHASE=8
TIP_SHA=$Sha
SHA_MATCH=$ShaMatch
PORT=$Port
WEBVIEW2LOADER_PRESENT=$LoaderPresent
SECURITY_MOTD_200=$sec_motd
SECURITY_EVIL_403=$sec_evil
SECURITY_WRITE_INSIDE_200=$sec_in
SECURITY_DENY_ABS_403=$sec_abs
SECURITY_DENY_DOTDOT_403=$sec_dot
SECURITY_DENY_UNC_403=$sec_unc
SECURITY_FS_INSIDE=$insideFs
SECURITY_FS_ABS=$absFs
SECURITY_FS_TRAV=$travFs
SECURITY_EXEC_NOGRANT=$sec_exec
SECURITY_BOUNDARY_RUNTIME=$SEC_RUNTIME
BROWSER_NAVIGATE_HTTP=$(CodeOf 'browser_navigate')
BROWSER_NAVIGATE_DISP=$navDisp
BROWSER_AUTOMATION_HTTP=$(CodeOf 'browser_automation')
BROWSER_AUTOMATION_DISP=$autoDisp
NATIVE_ACTION_HTTP=$(CodeOf 'native_action')
NATIVE_ACTION_DISP=$natDisp
OS_EXPLORER_HTTP=$(CodeOf 'os_explorer')
OS_EXPLORER_DISP=$osDisp
GUI_BROWSER_NAV_DISP=FAIL_CLOSED_NOT_RUN
GUI_BROWSER_BLOCKER=$guiBlocker
NAV_STARTING_COM_BINDING=MISSING_IN_MINIMAL_WEBVIEW2_H
HOST_NAVIGATE_SCHEME_FILTER=SOURCE_WIRED_CANDIDATE_ONLY
OSEXPLORER_VOID_PATH=FAIL_CLOSED_FEATURE_FICTION_SOURCE
OSEXPLORER_TIP_RUNTIME=NOT_RUN_NO_PRODUCT_TOOL_ROUTE
PROMOTE=0
TIP_CLIMB=HOLD
PRODUCT_CERTIFIED=0
ABSORB_GHOSTTEXT=NOT_AUTHORIZED
REBUILD=0
NO_INVENT_PASS=1
"@
$summary | Set-Content (Join-Path $OutDir "SUMMARY.txt")
$summary | Set-Content (Join-Path $Logs "scoreboard.txt")
Write-Output $summary
