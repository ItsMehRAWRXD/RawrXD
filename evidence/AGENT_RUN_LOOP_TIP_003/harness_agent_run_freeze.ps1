# AGENT_RUN_LOOP_TIP_003 + PATH_B on TIP_FREEZE_001
# PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 FAIL_CLOSED
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\AGENT_RUN_LOOP_TIP_003"
$Logs = Join-Path $OutDir "logs"
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$PathBDir = "G:\~dev\rawrxd\evidence\SWARM_16_RUNTIME_002_PATH_B"
$Port = 18941
$Sha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$Sha | Set-Content (Join-Path $Logs "exe_sha.txt")
"NEW_SHA=$Sha" | Set-Content (Join-Path $Logs "exe_sha_full.txt")

Get-CimInstance Win32_Process | Where-Object {
  $_.Name -match "^(ninja|cmake|link|cl)\.exe$" -and $_.CommandLine -match "build_win32ide_link001|RawrXD-Win32IDE"
} | ForEach-Object {
  Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2

$cs = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class TipFreezeHwnd003 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static IntPtr FindMainByPid(uint pid, string className) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint pp; GetWindowThreadProcessId(h, out pp);
      if (pp != pid) return true;
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      if (cls.ToString() == className) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

$env:RAWRXD_GUI = "1"
$env:RAWRXD_HTTP_PORT = "$Port"
Remove-Item Env:RAWRXD_HEADLESS -ErrorAction SilentlyContinue
Remove-Item Env:LOCAL_ONLY -ErrorAction SilentlyContinue

$stdout = Join-Path $Logs "srv_out.txt"
$stderr = Join-Path $Logs "srv_err.txt"
$p = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -ArgumentList @("--port", "$Port") `
  -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
  -PassThru -WindowStyle Normal

$ready = $false
$hwndReady = $false
$hwnd = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) { break }
  $listen = netstat -ano | Select-String ":$Port\s+.*LISTENING"
  if ($listen) { $ready = $true; break }
  $hwnd = [TipFreezeHwnd003]::FindMainByPid([uint32]$p.Id, "RawrXD_IDE_MainWindow")
  if ($hwnd -ne [IntPtr]::Zero) { $hwndReady = $true; $ready = $true; break }
  Start-Sleep -Milliseconds 500
}
$hwnd = [TipFreezeHwnd003]::FindMainByPid([uint32]$p.Id, "RawrXD_IDE_MainWindow")
if ($hwnd -ne [IntPtr]::Zero) { $hwndReady = $true }

"PID=$($p.Id) READY=$ready EXITED=$($p.HasExited) HWND=$hwnd" | Set-Content (Join-Path $Logs "srv_meta.txt")

$http = 0
$body = ""
$entered = 0
$reqBody = '{"prompt":"noop freeze agent run probe","cancel":false}'
$reqBody | Set-Content (Join-Path $Logs "req_agent_run.json")
try {
  $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/agent/run" -Method POST -Body $reqBody -ContentType "application/json" -TimeoutSec 30 -UseBasicParsing
  $http = [int]$resp.StatusCode
  $body = [string]$resp.Content
} catch {
  if ($_.Exception.Response) {
    $http = [int]$_.Exception.Response.StatusCode.value__
    if (-not $http) { $http = [int]$_.Exception.Response.StatusCode }
    try {
      $stream = $_.Exception.Response.GetResponseStream()
      $reader = New-Object System.IO.StreamReader($stream)
      $body = $reader.ReadToEnd()
    } catch { $body = "" }
  } else {
    $http = -1
    $body = $_.Exception.Message
  }
}
"HTTP=$http" | Set-Content (Join-Path $Logs "R_agent_run.code.txt")
$body | Set-Content (Join-Path $Logs "R_agent_run.body.txt")
if (($body -match "agent_session|iterations|AgentRunLoop") -and ($http -eq 200)) { $entered = 1 }

$pathBInvoked = 0
if ($hwndReady -and $hwnd -ne [IntPtr]::Zero) {
  $ok = [TipFreezeHwnd003]::PostMessageW($hwnd, 0x0111, [IntPtr]4111, [IntPtr]::Zero)
  $pathBInvoked = [int]$ok
  Start-Sleep 5
  "PATH_B_INVOKED=$pathBInvoked HWND=$hwnd SHA=$Sha ASOF=$((Get-Date).ToUniversalTime().ToString('o')) PROMOTE=0" |
    Set-Content (Join-Path $PathBDir "PATH_B_FREEZE_748B.txt")
} else {
  "PATH_B_INVOKED=0 HWND=0 REASON=NO_HWND SHA=$Sha PROMOTE=0" |
    Set-Content (Join-Path $PathBDir "PATH_B_FREEZE_748B.txt")
}

Start-Sleep 2
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 1
Get-Content $stdout -Tail 40 -ErrorAction SilentlyContinue | Set-Content (Join-Path $Logs "srv_out_tail.txt")
Get-Content $stderr -Tail 60 -ErrorAction SilentlyContinue | Set-Content (Join-Path $Logs "srv_err_tail.txt")

$disp = if ($entered -eq 1) { "ENTERED" }
  elseif ($http -eq 503) { "FAIL_CLOSED_NOT_ENTERED_HTTP_503" }
  elseif ($http -lt 0) { "FAIL_CLOSED_NO_HTTP" }
  else { "FAIL_CLOSED_HTTP_$http" }

@"
AGENT_RUN_LOOP_TIP_003 / RECEIPT
================================
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
NO_INVENT_PASS=1
EXE=$TipExe
EXE_SHA=$Sha
PORT=$Port
READY=$ready
HWND=$hwnd
HWND_NE_0=$([int]$hwndReady)
HTTP=$http
BODY_LEN=$($body.Length)
BODY_EMPTY=$([int]([string]::IsNullOrEmpty($body)))
ENTERED_AGENT_RUN_LOOP=$entered
PATH_B_WM4111_POST=$pathBInvoked
SOURCE_MAP_AgentRunLoop=1
REBUILD_THIS_DISPATCH=0
DISPOSITION=$disp
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
"@ | Set-Content (Join-Path $OutDir "RECEIPT.txt")

Write-Output "HTTP=$http ENTERED=$entered HWND=$hwnd PATH_B=$pathBInvoked DISP=$disp"
Get-Content (Join-Path $OutDir "RECEIPT.txt")
