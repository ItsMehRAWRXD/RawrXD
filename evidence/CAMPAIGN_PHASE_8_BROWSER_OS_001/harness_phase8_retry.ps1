# CAMPAIGN_PHASE_8 retry — stay-alive tip headless
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\CAMPAIGN_PHASE_8_BROWSER_OS_001"
$Logs = Join-Path $OutDir "logs"
$Sandbox = Join-Path $OutDir "sandbox"
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$Port = 18958
$MotdPath = "G:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc"

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2
if (Test-Path (Join-Path (Split-Path $TipExe) "headless_oneshot.txt")) {
  Remove-Item (Join-Path (Split-Path $TipExe) "headless_oneshot.txt") -Force
}

$key = "phase8c-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
$env:RAWRXD_HEADLESS = "1"
$env:LOCAL_ONLY = "1"
$env:RAWRXD_HOSTED_API_KEY = $key
$env:RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin,*"
Remove-Item Env:RAWRXD_IDE_EXEC_GRANT -ErrorAction SilentlyContinue

$p = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -ArgumentList @("--headless", "--local", "--port", "$Port", "--bind", "127.0.0.1", "--dir", $Sandbox) `
  -RedirectStandardOutput (Join-Path $Logs "srv3_out.txt") `
  -RedirectStandardError (Join-Path $Logs "srv3_err.txt") `
  -PassThru -WindowStyle Hidden

$ready = $false
for ($i = 0; $i -lt 80; $i++) {
  if ($p.HasExited) { break }
  if (netstat -ano | Select-String ":$Port\s+.*LISTENING") { $ready = $true; break }
  Start-Sleep -Milliseconds 400
}

$code = if ($p.HasExited) { $p.ExitCode } else { -999 }
"PID=$($p.Id) READY=$ready EXITED=$($p.HasExited) CODE=$code KEY=$key" | Set-Content (Join-Path $Logs "srv3_meta.txt")
Write-Output "PID=$($p.Id) READY=$ready EXITED=$($p.HasExited) CODE=$code"

if (-not $ready) {
  Get-Content (Join-Path $Logs "srv3_out.txt") -ErrorAction SilentlyContinue | Select-Object -Last 30
  Get-Content (Join-Path $Logs "srv3_err.txt") -ErrorAction SilentlyContinue | Select-Object -Last 30
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
  exit 2
}

function Invoke-Hit {
  param([string]$Tag, [string]$Json, [hashtable]$Headers)
  $code = -1
  $body = ""
  try {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/tool" -Method POST `
      -Body ([System.Text.Encoding]::UTF8.GetBytes($Json)) `
      -ContentType "application/json; charset=utf-8" `
      -Headers $Headers -TimeoutSec 30 -UseBasicParsing
    $code = [int]$resp.StatusCode
    $body = [string]$resp.Content
  } catch {
    if ($_.Exception.Response) {
      $code = [int]$_.Exception.Response.StatusCode.value__
      try {
        $body = (New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd()
      } catch { $body = "" }
    } else {
      $body = $_.Exception.Message
    }
  }
  "$Tag|$code|$body" | Set-Content (Join-Path $Logs ("R3_" + $Tag + ".txt"))
  $code | Set-Content (Join-Path $Logs ("R3_" + $Tag + ".code.txt"))
  return $code
}

$auth = @{ "X-Api-Key" = $key; "Origin" = "http://127.0.0.1:$Port" }
$evil = @{ "X-Api-Key" = $key; "Origin" = "https://evil.example" }

$cMotd = Invoke-Hit "motd" (@{ tool = "read_motd"; args = @{ path = $MotdPath } } | ConvertTo-Json -Compress -Depth 5) $auth
$cEvil = Invoke-Hit "evil" (@{ tool = "read_motd"; args = @{ path = $MotdPath } } | ConvertTo-Json -Compress -Depth 5) $evil
$cIn = Invoke-Hit "write_inside" (@{ tool = "write_file"; args = @{ path = "p8c.txt"; content = "ok" } } | ConvertTo-Json -Compress -Depth 5) $auth
$cAbs = Invoke-Hit "deny_abs" (@{ tool = "write_file"; args = @{ path = "C:\Windows\Temp\rawrxd_p8c.txt"; content = "x" } } | ConvertTo-Json -Compress -Depth 5) $auth
$cDot = Invoke-Hit "deny_dotdot" (@{ tool = "write_file"; args = @{ path = "..\..\Windows\Temp\rawrxd_p8c_t.txt"; content = "x" } } | ConvertTo-Json -Compress -Depth 5) $auth
$cUnc = Invoke-Hit "deny_unc" (@{ tool = "write_file"; args = @{ path = "\\127.0.0.1\c$\Windows\Temp\rawrxd_p8c_u.txt"; content = "x" } } | ConvertTo-Json -Compress -Depth 5) $auth
$cExec = Invoke-Hit "exec_nogrant" (@{ tool = "execute_command"; args = @{ command = "cmd /c echo x" } } | ConvertTo-Json -Compress -Depth 5) $auth
$cNav = Invoke-Hit "browser_navigate" (@{ tool = "browser_navigate"; args = @{ url = "https://example.com" } } | ConvertTo-Json -Compress -Depth 5) $auth
$cAuto = Invoke-Hit "browser_automation" (@{ tool = "browser_automation"; args = @{ action = "click" } } | ConvertTo-Json -Compress -Depth 5) $auth
$cNat = Invoke-Hit "native_action" (@{ tool = "native_action"; args = @{ action = "open_explorer" } } | ConvertTo-Json -Compress -Depth 5) $auth
$cOs = Invoke-Hit "os_explorer" (@{ tool = "os_explorer"; args = @{ path = "." } } | ConvertTo-Json -Compress -Depth 5) $auth

$fsIn = Test-Path (Join-Path $Sandbox "p8c.txt")
$fsAbs = Test-Path "C:\Windows\Temp\rawrxd_p8c.txt"
$loader = [int](Test-Path (Join-Path (Split-Path $TipExe) "WebView2Loader.dll"))
$sha = (Get-FileHash $TipExe -Algorithm SHA256).Hash

if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }

$secOk = [int](($sha -eq "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145") -and ($cEvil -eq 403) -and ($cAbs -eq 403) -and ($cDot -eq 403) -and ($cUnc -eq 403) -and (-not $fsAbs))

$lines = @(
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))",
  "CAMPAIGN_PHASE=8",
  "TIP_SHA=$sha",
  "SHA_MATCH=$([int]($sha -eq '748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145'))",
  "PORT=$Port",
  "SERVER_READY=1",
  "WEBVIEW2LOADER_PRESENT=$loader",
  "SECURITY_MOTD_HTTP=$cMotd",
  "SECURITY_EVIL_HTTP=$cEvil",
  "SECURITY_WRITE_INSIDE_HTTP=$cIn",
  "SECURITY_DENY_ABS_HTTP=$cAbs",
  "SECURITY_DENY_DOTDOT_HTTP=$cDot",
  "SECURITY_DENY_UNC_HTTP=$cUnc",
  "SECURITY_EXEC_NOGRANT_HTTP=$cExec",
  "SECURITY_FS_INSIDE=$fsIn",
  "SECURITY_FS_ABS=$fsAbs",
  "SECURITY_BOUNDARY_RUNTIME=$secOk",
  "BROWSER_NAVIGATE_HTTP=$cNav",
  "BROWSER_AUTOMATION_HTTP=$cAuto",
  "NATIVE_ACTION_HTTP=$cNat",
  "OS_EXPLORER_HTTP=$cOs",
  "BROWSER_NAVIGATE_DISP=FAIL_CLOSED_NOT_RUN",
  "BROWSER_AUTOMATION_DISP=FAIL_CLOSED_NOT_RUN",
  "NATIVE_ACTION_DISP=FAIL_CLOSED_NOT_RUN",
  "OS_EXPLORER_DISP=FAIL_CLOSED_NOT_RUN",
  "GUI_BROWSER_NAV_DISP=FAIL_CLOSED_NOT_RUN",
  "GUI_BROWSER_BLOCKER=WEBVIEW2LOADER_MISSING_IN_TIP_BIN",
  "PROMOTE=0",
  "TIP_CLIMB=HOLD",
  "PRODUCT_CERTIFIED=0",
  "ABSORB_GHOSTTEXT=NOT_AUTHORIZED",
  "NO_INVENT_PASS=1"
)
$summary = $lines -join "`n"
$summary | Set-Content (Join-Path $OutDir "SUMMARY.txt")
$summary | Set-Content (Join-Path $Logs "scoreboard.txt")
Write-Output $summary
