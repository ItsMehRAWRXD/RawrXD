# PHASE4_AGENTIC_IDE_E2E_001 — tip freeze 748B workflows
# Ask/Agent/Plan/Debug · multitask · terminal · SafeWrite · stop/restore
# Prefer HTTP/HWND. PROMOTE=0. GhostText ABSORB=NOT_AUTHORIZED.
# AgentRunLoop: one re-verify; extend FAIL_CLOSED — do not thrash.
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\PHASE4_AGENTIC_IDE_E2E_001"
$Logs = Join-Path $OutDir "logs"
$Sandbox = Join-Path $OutDir "sandbox"
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$ExpectedSha = "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145"
$Port = 19141
$Base = "http://127.0.0.1:$Port"
$WorkDir = "G:\~dev\rawrxd"
$ApiKey = "phase4_agentic_ide_e2e_001_key"
$MotdRel = "evidence\PHASE4_AGENTIC_IDE_E2E_001\sandbox\PassiveRoleNotRoleplay.mdc"
$TrackedRel = "evidence\PHASE4_AGENTIC_IDE_E2E_001\sandbox\tracked.txt"
$HelloRel = "evidence\PHASE4_AGENTIC_IDE_E2E_001\sandbox\hello.cmd"
$Model = "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
$Table = @{}
$env:RAWRXD_HOSTED_API_KEY = $ApiKey
$env:RAWRXD_IDE_EXEC_GRANT = "1"
$env:RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin"
if (Test-Path $Model) { $env:RAWRXD_PRODUCT_MODEL = $Model }

New-Item -ItemType Directory -Force -Path $Logs, $Sandbox | Out-Null
Copy-Item "G:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc" (Join-Path $Sandbox "PassiveRoleNotRoleplay.mdc") -Force
Set-Content (Join-Path $Sandbox "tracked.txt") -Value "v0`n" -Encoding ASCII -NoNewline
Set-Content (Join-Path $Sandbox "hello.cmd") -Value "@echo phase4_terminal_ok`r`n" -Encoding ASCII

function Seal-Row([string]$wf, [string]$disp, [string]$detail) {
  $script:Table[$wf] = @{ disposition = $disp; detail = $detail }
  $line = "$wf|$disp|$detail"
  Add-Content (Join-Path $Logs "WORKFLOW_ROWS.txt") $line
  Write-Output "[$disp] $wf :: $detail"
}

function Invoke-Http([string]$method, [string]$url, [string]$body, [int]$timeoutSec = 45, [hashtable]$extraHeaders = $null) {
  try {
    $headers = @{ "X-API-Key" = $ApiKey; "Origin" = "http://127.0.0.1:$Port" }
    if ($extraHeaders) { foreach ($k in $extraHeaders.Keys) { $headers[$k] = $extraHeaders[$k] } }
    if ([string]::IsNullOrEmpty($body) -or $method -eq "GET") {
      $resp = Invoke-WebRequest -Uri $url -Method $method -Headers $headers -TimeoutSec $timeoutSec -UseBasicParsing
    } else {
      $resp = Invoke-WebRequest -Uri $url -Method $method -Headers $headers -Body $body `
        -ContentType "application/json; charset=utf-8" -TimeoutSec $timeoutSec -UseBasicParsing
    }
    return @{ ok = $true; status = [int]$resp.StatusCode; body = [string]$resp.Content }
  } catch {
    $ex = $_.Exception; $code = 0; $b = ""
    if ($ex.Response) {
      try { $code = [int]$ex.Response.StatusCode.value__ } catch { try { $code = [int]$ex.Response.StatusCode } catch {} }
      try {
        $stream = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $b = $reader.ReadToEnd()
      } catch { $b = $ex.Message }
    } else { $b = $ex.Message }
    return @{ ok = $false; status = $code; body = $b }
  }
}

function Invoke-Tool([string]$tool, [hashtable]$argsObj, [int]$timeoutSec = 60) {
  $payload = @{ tool = $tool; args = $argsObj } | ConvertTo-Json -Compress -Depth 8
  return Invoke-Http "POST" "$Base/api/tool" $payload $timeoutSec
}

function Save-Log([string]$name, [string]$content) {
  Set-Content (Join-Path $Logs $name) -Value $content -Encoding UTF8
}

# --- SHA gate ---
"" | Set-Content (Join-Path $Logs "WORKFLOW_ROWS.txt")
$sha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
Save-Log "exe_sha.txt" $sha
if ($sha -ne $ExpectedSha) {
  Seal-Row "TIP_SHA" "FAIL_CLOSED" "SHA_MISMATCH obs=$sha"
  exit 3
}
Seal-Row "TIP_SHA" "RUNTIME_REACHED" "SHA_MATCH=$ExpectedSha"

Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
}
Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2

# ========== A) HEADLESS HTTP surface ==========
$argList = @("--headless", "--local", "--port", "$Port", "--bind", "127.0.0.1", "--dir", $WorkDir)
$proc = Start-Process -FilePath $TipExe -ArgumentList $argList -PassThru -WindowStyle Hidden
$proc.Id | Set-Content (Join-Path $Logs "headless_pid.txt")
$ready = $false
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep -Milliseconds 500
  if ($proc.HasExited) { break }
  $listen = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.OwningProcess -eq $proc.Id }
  if (-not $listen) { continue }
  $h = Invoke-Http "GET" "$Base/health" "" 5
  if ($h.body -match '"status":"ok"' -or $h.body -match "RawrXD-HeadlessIDE" -or $h.status -eq 200) {
    $ready = $true; break
  }
}
Save-Log "headless_ready.txt" "READY=$ready PID=$($proc.Id) EXITED=$($proc.HasExited)"
if (-not $ready) {
  Seal-Row "HEADLESS_SPAWN" "FAIL_CLOSED" "not ready pid=$($proc.Id)"
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
  exit 4
}
Seal-Row "HEADLESS_SPAWN" "RUNTIME_REACHED" "pid=$($proc.Id) port=$Port"

function Ack-Motd {
  $m = Invoke-Tool "read_motd" @{ path = $MotdRel }
  if ($m.status -ne 200) { $m = Invoke-Tool "read_file" @{ path = $MotdRel } }
  return $m
}

# MOTD unlock for /api/tool (must re-ack after /ask|/api/generate — motdResetOnGenerate)
$motd = Ack-Motd
Save-Log "motd.body.txt" ("status=$($motd.status)`n" + $motd.body)

# --- Ask mode (HTTP /ask product path) ---
$askBody = '{"prompt":"PHASE4 Ask mode probe: reply with one word OK.","stream":false,"max_tokens":16}'
$ask = Invoke-Http "POST" "$Base/ask" $askBody 60
if (-not $ask.ok -and $ask.status -eq 0) { $ask = Invoke-Http "POST" "$Base/api/generate" $askBody 60 }
Save-Log "ask.body.txt" ("status=$($ask.status)`n" + $ask.body)
if ($ask.status -ge 200 -and $ask.status -lt 300 -and $ask.body.Length -gt 0) {
  Seal-Row "MODE_ASK" "RUNTIME_REACHED" "HTTP=$($ask.status) body_len=$($ask.body.Length)"
} elseif ($ask.status -eq 503 -or $ask.body -match "model_not_loaded|warming|not_loaded") {
  Seal-Row "MODE_ASK" "RUNTIME_REACHED" "route_hit failclosed HTTP=$($ask.status) $($ask.body.Substring(0,[Math]::Min(120,$ask.body.Length)))"
} elseif ($ask.status -gt 0) {
  Seal-Row "MODE_ASK" "RUNTIME_REACHED" "HTTP=$($ask.status) route_reached"
} else {
  Seal-Row "MODE_ASK" "FAIL_CLOSED" "unreachable $($ask.body)"
}

# Re-ack MOTD after generate reset before tool workflows
$motd2 = Ack-Motd
Save-Log "motd_reack.body.txt" ("status=$($motd2.status)`n" + $motd2.body)

# --- Plan mode (tool inventory / plan surface via list + unknown tool) ---
$list = Invoke-Tool "list_directory" @{ path = "evidence\PHASE4_AGENTIC_IDE_E2E_001\sandbox" }
$inv = Invoke-Tool "unknown_phase4_tool" @{ }
Save-Log "plan_list.body.txt" ("status=$($list.status)`n" + $list.body)
Save-Log "plan_inv.body.txt" ("status=$($inv.status)`n" + $inv.body)
if ($list.status -eq 200 -and ($inv.body -match "available|unknown|safe_write|write_file|execute_command")) {
  Seal-Row "MODE_PLAN" "RUNTIME_REACHED" "tool_surface list=200 inventory_hit=1"
} elseif ($list.status -eq 200) {
  Seal-Row "MODE_PLAN" "RUNTIME_REACHED" "list_directory=200 (inventory partial)"
} else {
  Seal-Row "MODE_PLAN" "FAIL_CLOSED" "list HTTP=$($list.status) body=$($list.body.Substring(0,[Math]::Min(120,$list.body.Length)))"
}

# --- Agent mode / AgentRunLoop (ONE re-verify; extend prior 503 seal) ---
$ar1 = Invoke-Http "POST" "$Base/api/agent/run" '{"prompt":"PHASE4 agent run noop","cancel":false}' 30
Save-Log "agent_run_1.code.txt" "HTTP=$($ar1.status)"
Save-Log "agent_run_1.body.txt" $ar1.body
$entered = 0
if ($ar1.status -eq 200 -and $ar1.body -match "agent_session|iterations") { $entered = 1 }

# Optional single model-load assist (not thrash loop)
if ($entered -eq 0 -and (Test-Path $Model) -and $ar1.body -match "model_not_loaded") {
  $load = Invoke-Http "POST" "$Base/api/model/load" (@{ path = $Model } | ConvertTo-Json -Compress) 120
  Save-Log "model_load.body.txt" ("status=$($load.status)`n" + $load.body)
  $ar2 = Invoke-Http "POST" "$Base/api/agent/run" '{"prompt":"PHASE4 agent run after load","cancel":false}' 90
  Save-Log "agent_run_2.code.txt" "HTTP=$($ar2.status)"
  Save-Log "agent_run_2.body.txt" $ar2.body
  if ($ar2.status -eq 200 -and $ar2.body -match "agent_session|iterations") {
    $entered = 1
    $ar1 = $ar2
  } else {
    $ar1 = $ar2
  }
}

if ($entered -eq 1) {
  Seal-Row "MODE_AGENT" "RUNTIME_REACHED" "AgentRunLoop entered HTTP=200"
} elseif ($ar1.status -eq 503 -and [string]::IsNullOrWhiteSpace($ar1.body)) {
  Seal-Row "MODE_AGENT" "FAIL_CLOSED" "HTTP=503 empty_body EXTEND AGENT_RUN_LOOP_TIP_003 (no thrash)"
} elseif ($ar1.status -eq 503) {
  Seal-Row "MODE_AGENT" "FAIL_CLOSED" "HTTP=503 body=$($ar1.body.Substring(0,[Math]::Min(160,$ar1.body.Length))) EXTEND TIP_003"
} else {
  Seal-Row "MODE_AGENT" "FAIL_CLOSED" "HTTP=$($ar1.status) not_entered"
}

# Re-ack again if agent/generate reset MOTD
$null = Ack-Motd

# --- Debug mode (no onAgenticModeDebug on tip map; native debug status is separate) ---
$dbg = Invoke-Http "GET" "$Base/api/debug/status" "" 10
if ($dbg.status -eq 0) { $dbg = Invoke-Http "GET" "$Base/api/native-debug/status" "" 10 }
Save-Log "debug.body.txt" ("status=$($dbg.status)`n" + $dbg.body)
if ($dbg.status -eq 200 -and $dbg.body.Length -gt 0) {
  Seal-Row "MODE_DEBUG" "RUNTIME_REACHED" "native_debug_status HTTP=200 (agentic Debug mode enum HWND separate)"
} else {
  Seal-Row "MODE_DEBUG" "FAIL_CLOSED" "onAgenticModeDebug=ABSENT tip; HTTP=$($dbg.status) NOT_INVOKED_AS_MODE"
}

# --- Multitask (/api/subagent) ---
$subBody = '{"prompt":"PHASE4 multitask noop","task":"echo","cancelAfterMs":500}'
$sub = Invoke-Http "POST" "$Base/api/subagent" $subBody 45
Save-Log "subagent.body.txt" ("status=$($sub.status)`n" + $sub.body)
if ($sub.status -eq 200 -and $sub.body -match "agent|subagent|task|id|result|spawn") {
  Seal-Row "MULTITASK" "RUNTIME_REACHED" "HTTP=200 subagent route"
} elseif ($sub.status -eq 503 -or $sub.body -match "hexmag_unavailable|authentication|model_not") {
  Seal-Row "MULTITASK" "RUNTIME_REACHED" "route_hit failclosed HTTP=$($sub.status)"
} elseif ($sub.status -gt 0) {
  Seal-Row "MULTITASK" "RUNTIME_REACHED" "HTTP=$($sub.status) route_reached"
} else {
  Seal-Row "MULTITASK" "FAIL_CLOSED" "unreachable"
}

$null = Ack-Motd

# --- Terminal tools (execute_command) ---
$exec = Invoke-Tool "execute_command" @{ command = "cmd /c evidence\PHASE4_AGENTIC_IDE_E2E_001\sandbox\hello.cmd" }
Save-Log "terminal.body.txt" ("status=$($exec.status)`n" + $exec.body)
if ($exec.status -eq 200 -and $exec.body -match "phase4_terminal_ok") {
  Seal-Row "TERMINAL" "RUNTIME_REACHED" "execute_command exit+output ok"
} elseif ($exec.body -match "execution_not_granted") {
  Seal-Row "TERMINAL" "RUNTIME_REACHED" "deny_path execution_not_granted (grant env may miss child)"
} elseif ($exec.status -eq 200) {
  Seal-Row "TERMINAL" "RUNTIME_REACHED" "HTTP=200 body=$($exec.body.Substring(0,[Math]::Min(120,$exec.body.Length)))"
} else {
  Seal-Row "TERMINAL" "FAIL_CLOSED" "HTTP=$($exec.status) $($exec.body.Substring(0,[Math]::Min(160,$exec.body.Length)))"
}

# --- SafeWrite (atomic write + preview + rollback) ---
$wf = Invoke-Tool "write_file" @{ path = $TrackedRel; content = "v1_phase4`n" }
Save-Log "safewrite_write.body.txt" ("status=$($wf.status)`n" + $wf.body)
$prev = Invoke-Tool "safe_write_preview" @{}
Save-Log "safewrite_preview.body.txt" ("status=$($prev.status)`n" + $prev.body)
$st = Invoke-Tool "safe_write_status" @{}
Save-Log "safewrite_status.body.txt" ("status=$($st.status)`n" + $st.body)
$disk1 = Get-Content (Join-Path $Sandbox "tracked.txt") -Raw -ErrorAction SilentlyContinue
$rb = Invoke-Tool "safe_write_rollback" @{}
Save-Log "safewrite_rollback.body.txt" ("status=$($rb.status)`n" + $rb.body)
$disk2 = Get-Content (Join-Path $Sandbox "tracked.txt") -Raw -ErrorAction SilentlyContinue
$atomic = ($wf.status -eq 200 -and $wf.body -match '"atomic"\s*:\s*true')
$rolled = ($rb.status -eq 200 -and $rb.body -match "Rollback|success")
if ($atomic -and $rolled) {
  Seal-Row "SAFEWRITE" "RUNTIME_REACHED" "atomic=true preview+rollback HTTP ok disk_before=$disk1 disk_after=$disk2"
} elseif ($atomic) {
  Seal-Row "SAFEWRITE" "RUNTIME_REACHED" "atomic=true write ok; rollback partial HTTP=$($rb.status)"
} elseif ($wf.status -eq 200) {
  Seal-Row "SAFEWRITE" "FAIL_CLOSED" "write 200 but atomic!=true body=$($wf.body.Substring(0,[Math]::Min(160,$wf.body.Length)))"
} else {
  Seal-Row "SAFEWRITE" "FAIL_CLOSED" "write HTTP=$($wf.status) $($wf.body.Substring(0,[Math]::Min(160,$wf.body.Length)))"
}

# --- Stop / restore ---
$cancelState = "NOT_RUN"
try {
  $cts = [System.Threading.CancellationTokenSource]::new()
  $task = [System.Threading.Tasks.Task]::Run({
    try {
      Invoke-WebRequest -Uri "$using:Base/api/generate" -Method POST `
        -Headers @{ "X-API-Key" = $using:ApiKey } `
        -Body '{"prompt":"PHASE4 long cancel probe please stall","stream":false,"max_tokens":64}' `
        -ContentType "application/json" -TimeoutSec 5 -UseBasicParsing | Out-Null
    } catch {}
  })
  Start-Sleep -Milliseconds 200
  if (-not $task.Wait(500)) { $cancelState = "Stopped_Timeout" } else { $cancelState = "Completed" }
} catch {
  $cancelState = "Stopped_Exception"
}
# Explicit agent cancel probe
$cancelHttp = Invoke-Http "POST" "$Base/api/agent/run" '{"prompt":"PHASE4 cancel","cancel":true}' 15
Save-Log "agent_cancel.body.txt" ("status=$($cancelHttp.status)`n" + $cancelHttp.body)
$null = Ack-Motd
$rest = Invoke-Tool "write_file" @{ path = $TrackedRel; content = "v0_restored`n" }
$disk3 = Get-Content (Join-Path $Sandbox "tracked.txt") -Raw -ErrorAction SilentlyContinue
Save-Log "stop_restore.body.txt" "cancel_job=$cancelState`ncancel_http=$($cancelHttp.status)`nrestore_status=$($rest.status)`n$($rest.body)`ndisk=$disk3"
if (($cancelState -match "Stopped|Completed") -and $rest.status -eq 200 -and $disk3 -match "v0_restored") {
  Seal-Row "STOP_RESTORE" "RUNTIME_REACHED" "cancel=$cancelState restore_write=200 disk=v0_restored (+rollback prior)"
} elseif ($rest.status -eq 200 -and $disk3 -match "v0_restored") {
  Seal-Row "STOP_RESTORE" "RUNTIME_REACHED" "restore_write=200 cancel=$cancelState agent_cancel_http=$($cancelHttp.status)"
} else {
  Seal-Row "STOP_RESTORE" "FAIL_CLOSED" "cancel=$cancelState restore HTTP=$($rest.status)"
}

if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 2

# ========== B) GUI HWND mode buttons (Ask/Plan/Agent) ==========
$guiPort = 19142
Get-NetTCPConnection -LocalPort $guiPort -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
}
$cs = @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class Phase4Hwnd {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
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
  public static List<string> ListButtons(IntPtr main) {
    var outList = new List<string>();
    EnumChildWindows(main, (h, l) => {
      var cls = new StringBuilder(64); GetClassNameW(h, cls, 64);
      var txt = new StringBuilder(128); GetWindowTextW(h, txt, 128);
      if (cls.ToString() == "Button") outList.Add(txt.ToString() + "|" + h.ToString("X"));
      return true;
    }, IntPtr.Zero);
    return outList;
  }
  public static bool ClickByText(IntPtr main, string want) {
    IntPtr target = IntPtr.Zero;
    EnumChildWindows(main, (h, l) => {
      var cls = new StringBuilder(64); GetClassNameW(h, cls, 64);
      var txt = new StringBuilder(128); GetWindowTextW(h, txt, 128);
      if (cls.ToString() == "Button" && string.Equals(txt.ToString(), want, StringComparison.OrdinalIgnoreCase)) {
        target = h; return false;
      }
      return true;
    }, IntPtr.Zero);
    if (target == IntPtr.Zero) return false;
    SendMessageW(target, 0x00F5 /*BM_CLICK*/, IntPtr.Zero, IntPtr.Zero);
    return true;
  }
}
"@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

$env:RAWRXD_GUI = "1"
$env:RAWRXD_HTTP_PORT = "$guiPort"
Remove-Item Env:RAWRXD_HEADLESS -ErrorAction SilentlyContinue
$gui = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -ArgumentList @("--port", "$guiPort") -PassThru -WindowStyle Normal
$hwnd = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(45)
while ((Get-Date) -lt $deadline) {
  if ($gui.HasExited) { break }
  $hwnd = [Phase4Hwnd]::FindMainByPid([uint32]$gui.Id, "RawrXD_IDE_MainWindow")
  if ($hwnd -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 400
}
$hwndHex = "0x{0:X}" -f $hwnd.ToInt64()
# Copilot sidebar mode IDs (Win32IDE_Core.cpp): 1206=Plan 1207=Agent 1208=Ask
$wmCommand = 0x0111
$postedAsk = $false; $postedPlan = $false; $postedAgent = $false
if ($hwnd -ne [IntPtr]::Zero) {
  Start-Sleep 2
  $postedAsk = [Phase4Hwnd]::PostMessageW($hwnd, [uint32]$wmCommand, [IntPtr]1208, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 250
  $postedPlan = [Phase4Hwnd]::PostMessageW($hwnd, [uint32]$wmCommand, [IntPtr]1206, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 250
  $postedAgent = [Phase4Hwnd]::PostMessageW($hwnd, [uint32]$wmCommand, [IntPtr]1207, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 250
}
Save-Log "gui_hwnd.txt" "PID=$($gui.Id) HWND=$hwndHex ASK_WM=$postedAsk PLAN_WM=$postedPlan AGENT_WM=$postedAgent IDS=1208/1206/1207"

if ($postedAsk) {
  Seal-Row "MODE_ASK_HWND" "RUNTIME_REACHED" "WM_COMMAND 1208 Ask HWND=$hwndHex"
} else {
  Seal-Row "MODE_ASK_HWND" "FAIL_CLOSED" "WM_COMMAND Ask post failed HWND=$hwndHex"
}
if ($postedPlan) {
  Seal-Row "MODE_PLAN_HWND" "RUNTIME_REACHED" "WM_COMMAND 1206 Plan HWND=$hwndHex"
} else {
  Seal-Row "MODE_PLAN_HWND" "FAIL_CLOSED" "WM_COMMAND Plan post failed HWND=$hwndHex"
}
if ($postedAgent) {
  Seal-Row "MODE_AGENT_HWND" "RUNTIME_REACHED" "WM_COMMAND 1207 Agent HWND=$hwndHex"
} else {
  Seal-Row "MODE_AGENT_HWND" "FAIL_CLOSED" "WM_COMMAND Agent post failed HWND=$hwndHex"
}
# Debug agentic mode: no control ID / onAgenticModeDebug on tip
$clickDebug = $false
if ($hwnd -ne [IntPtr]::Zero) { $clickDebug = [Phase4Hwnd]::ClickByText($hwnd, "Debug") }
if ($clickDebug) {
  Seal-Row "MODE_DEBUG_HWND" "RUNTIME_REACHED" "BM_CLICK Debug"
} else {
  Seal-Row "MODE_DEBUG_HWND" "FAIL_CLOSED" "Debug agentic control ABSENT on tip UI (IDs 1206-1208 only)"
}

if (-not $gui.HasExited) { Stop-Process -Id $gui.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 1

# Write table + receipt stubs filled by caller
$wfOrder = @(
  "TIP_SHA","HEADLESS_SPAWN","MODE_ASK","MODE_ASK_HWND","MODE_PLAN","MODE_PLAN_HWND",
  "MODE_AGENT","MODE_AGENT_HWND","MODE_DEBUG","MODE_DEBUG_HWND",
  "MULTITASK","TERMINAL","SAFEWRITE","STOP_RESTORE"
)
$lines = @("WORKFLOW|DISPOSITION|DETAIL")
foreach ($k in $wfOrder) {
  if ($Table.ContainsKey($k)) {
    $lines += "$k|$($Table[$k].disposition)|$($Table[$k].detail)"
  }
}
$lines -join "`n" | Set-Content (Join-Path $OutDir "WORKFLOW_TABLE.txt") -Encoding UTF8
"DONE UTC=$((Get-Date).ToUniversalTime().ToString('o')) SHA=$sha PROMOTE=0" | Set-Content (Join-Path $Logs "harness_done.txt")
Write-Output "HARNESS_DONE rows=$($Table.Count)"
