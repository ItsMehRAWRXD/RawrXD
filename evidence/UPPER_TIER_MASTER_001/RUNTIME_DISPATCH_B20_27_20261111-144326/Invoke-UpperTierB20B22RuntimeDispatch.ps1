# UPPER_TIER B20/B21/B22 tip-exe runtime dispatch.
# CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD. NOT_RUN != PASS. No invent PASS.
param(
  [string]$ExePath = 'F:\rawrxd\build_win32ide\bin\Release\RawrXD-Win32IDE-Native.exe',
  [string]$PreRewireSha = '16D85B1CF7651CA6F43FBC60B99F352A96BBB6C7C00C85ED777F941C8911CE4B',
  [string]$OutDir = '.',
  [int]$WaitMs = 7000,
  [switch]$AllowLaunch
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runLog = Join-Path $OutDir "runtime_dispatch_run_$stamp.txt"
$master = Join-Path $OutDir 'RUNTIME_DISPATCH_RECEIPT.txt'
$b20Dir = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_20_AUDIT\RUNTIME_DISPATCH'
$b21Dir = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_21_AUDIT\RUNTIME_DISPATCH'
$b22Dir = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_22_AUDIT\RUNTIME_DISPATCH'
foreach ($d in @($b20Dir,$b21Dir,$b22Dir)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runLog -Value $line -Encoding UTF8
  Write-Output $line
}

if (-not (Test-Path -LiteralPath $ExePath)) {
  Log "EXE_ABSENT=$ExePath"
  exit 2
}

$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExePath).Hash.ToUpperInvariant()
$bytes = (Get-Item -LiteralPath $ExePath).Length
$mtime = (Get-Item -LiteralPath $ExePath).LastWriteTime.ToString('o')
$shaChanged = if ($sha -ne $PreRewireSha.ToUpperInvariant()) { 1 } else { 0 }
Log "EXE_PATH=$ExePath"
Log "PRE_REWIRE_SHA=$PreRewireSha"
Log "TIP_SHA=$sha"
Log "SHA_CHANGED=$shaChanged BYTES=$bytes MTIME=$mtime"
Log "EXT_HOST_BIN=$(Test-Path 'F:\rawrxd\build_win32ide\bin\Release\RawrXD-ExtensionHost.exe')"

if (-not $AllowLaunch) {
  Log 'LAUNCH=HELD_NO_ALLOWLAUNCH'
  exit 0
}

Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class UTB2022 {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_CLOSE = 0x0010;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint BM_CLICK = 0x00F5;
  public const int IDOK = 1;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("RawrXD", StringComparison.OrdinalIgnoreCase) >= 0) { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindById(IntPtr root, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) == id) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static string GetText(IntPtr h) {
    if (h == IntPtr.Zero) return "";
    int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (len <= 0) return "";
    if (len > 262144) len = 262144;
    var sb = new StringBuilder(len + 2);
    SendMessageW(h, WM_GETTEXT, (IntPtr)(len + 1), sb);
    return sb.ToString();
  }
  public static int DismissDialogs(uint pid) {
    int n = 0;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var cls = new StringBuilder(64);
      GetClassNameW(h, cls, cls.Capacity);
      if (cls.ToString() != "#32770") return true;
      IntPtr ok = FindById(h, IDOK);
      if (ok != IntPtr.Zero) { PostMessageW(ok, BM_CLICK, IntPtr.Zero, IntPtr.Zero); n++; }
      else { PostMessageW(h, WM_CLOSE, IntPtr.Zero, IntPtr.Zero); n++; }
      return true;
    }, IntPtr.Zero);
    return n;
  }
  public static string Vis(IntPtr h) {
    if (h == IntPtr.Zero) return "ABSENT";
    return IsWindowVisible(h) ? "VISIBLE" : "HIDDEN";
  }
}
"@

Get-Process -Name 'RawrXD-Win32IDE-Native*' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$workDir = Split-Path -Parent $ExePath
$env:RAWRXD_LOG_DIR = $OutDir
$sw = [Diagnostics.Stopwatch]::StartNew()
$proc = Start-Process -FilePath $ExePath -WorkingDirectory $workDir -PassThru -WindowStyle Normal
Log "PID=$($proc.Id)"

$main = [IntPtr]::Zero
$earlyExit = $false
$exitCode = ''
for ($i = 0; $i -lt 100; $i++) {
  Start-Sleep -Milliseconds 250
  try { $proc.Refresh() } catch {}
  if ($proc.HasExited) {
    $earlyExit = $true
    $exitCode = "$($proc.ExitCode)"
    Log "EARLY_EXIT code=$exitCode after_ms=$($sw.ElapsedMilliseconds)"
    break
  }
  if ($proc.MainWindowHandle -ne 0) { $main = [IntPtr]$proc.MainWindowHandle; break }
  $main = [UTB2022]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log ("MAIN_HWND=0x{0:X} startup_ms={1}" -f $main.ToInt64(), $sw.ElapsedMilliseconds)

$cold = 'NOT_RUN'
if ($earlyExit) { $cold = 'FAIL_EARLY_EXIT' }
elseif ($main -eq [IntPtr]::Zero) { $cold = 'HELD_NO_MAIN_HWND' }
else { $cold = 'RUNTIME_REACHED_COLD_START_HWND' }

function Alive() {
  try { $proc.Refresh() } catch {}
  return -not $proc.HasExited
}
function PostCmd([int]$id, [string]$name) {
  if ($main -eq [IntPtr]::Zero -or -not (Alive)) { Log "SKIP_POST $name"; return $false }
  [void][UTB2022]::SetForegroundWindow($main)
  [void][UTB2022]::PostMessageW($main, [UTB2022]::WM_COMMAND, [IntPtr]$id, [IntPtr]::Zero)
  Log "POST WM_COMMAND id=$id name=$name"
  Start-Sleep -Milliseconds 600
  $dismissed = [UTB2022]::DismissDialogs([uint32]$proc.Id)
  if ($dismissed -gt 0) { Log "DISMISS_DIALOGS=$dismissed after=$name"; Start-Sleep -Milliseconds 400 }
  # second pass for chained dialogs
  $dismissed2 = [UTB2022]::DismissDialogs([uint32]$proc.Id)
  if ($dismissed2 -gt 0) { Log "DISMISS_DIALOGS2=$dismissed2 after=$name"; Start-Sleep -Milliseconds 300 }
  if (-not (Alive)) {
    $script:earlyExit = $true
    $script:exitCode = "$($proc.ExitCode)"
    Log "EXIT_AFTER_CMD name=$name code=$($script:exitCode)"
    return $false
  }
  return $true
}
function ReadOutput() {
  $parts = @()
  foreach ($id in @(1011,1012,1013,1014,1303)) {
    $h = [UTB2022]::FindById($main, $id)
    $t = [UTB2022]::GetText($h)
    if ($t -and $t.Trim().Length -gt 0) {
      $parts += "CTRL_$id`n$t"
      Log ("OUTPUT_CTRL id=$id len={0} vis={1}" -f $t.Length, [UTB2022]::Vis($h))
    }
  }
  return ($parts -join "`n====`n")
}

# ---- B20 probes (agent reliability) ----
$b20 = [ordered]@{
  cold_start = $cold
  view_tools = 'NOT_RUN'
  view_status = 'NOT_RUN'
  loop_cancel = 'NOT_RUN'
  loop_status = 'NOT_RUN'
  tool_dispatch_fallthrough = 'NOT_RUN'
  product_pass = 0
}
if ($main -ne [IntPtr]::Zero -and -not $earlyExit) {
  if (PostCmd 4103 'IDM_AGENT_VIEW_TOOLS') {
    Start-Sleep -Milliseconds 500
    [void][UTB2022]::DismissDialogs([uint32]$proc.Id)
    $out = ReadOutput
    if ($out -match 'Available Agent Tools|Agent Tools|session registry') {
      $b20.view_tools = 'RUNTIME_REACHED_TOOLS_LISTED'
    } elseif (Alive) {
      $b20.view_tools = 'RUNTIME_REACHED_CMD_POSTED_OUTPUT_UNCONFIRMED'
    }
  }
  if (PostCmd 4104 'IDM_AGENT_VIEW_STATUS') {
    Start-Sleep -Milliseconds 500
    [void][UTB2022]::DismissDialogs([uint32]$proc.Id)
    $out = ReadOutput
    if ($out -match 'Agent Status|Agentic|not initialized') {
      $b20.view_status = 'RUNTIME_REACHED_STATUS_OBSERVED'
    } elseif (Alive) {
      $b20.view_status = 'RUNTIME_REACHED_CMD_POSTED_OUTPUT_UNCONFIRMED'
    }
  }
  if (PostCmd 4107 'IDM_AGENTIC_LOOP_CANCEL') {
    $out = ReadOutput
    if ($out -match 'cancelled|Cancel') { $b20.loop_cancel = 'RUNTIME_REACHED_CANCEL_OBSERVED' }
    elseif (Alive) { $b20.loop_cancel = 'RUNTIME_REACHED_CANCEL_POSTED' }
  }
  if (PostCmd 4108 'IDM_AGENTIC_LOOP_STATUS') {
    Start-Sleep -Milliseconds 500
    [void][UTB2022]::DismissDialogs([uint32]$proc.Id)
    $out = ReadOutput
    if ($out -match 'Agentic Loop Status|Loop Bridge|not initialized') {
      $b20.loop_status = 'RUNTIME_REACHED_STATUS_OBSERVED'
    } elseif (Alive) {
      $b20.loop_status = 'RUNTIME_REACHED_CMD_POSTED_OUTPUT_UNCONFIRMED'
    }
  }
  # Fallthrough: without modal Execute Command input injection, record exercised registry surface only.
  if ($b20.view_tools -like 'RUNTIME_REACHED*') {
    $b20.tool_dispatch_fallthrough = 'RUNTIME_REACHED_REGISTRY_SURFACE_ONLY_FALLTHROUGH_NOT_PROVEN'
  }
}

# ---- B21 probes (LSP/DAP) ----
$b21 = [ordered]@{
  cold_start = $cold
  lsp_start = 'NOT_RUN'
  lsp_status = 'NOT_RUN'
  lsp_publish_diag = 'NOT_RUN'
  dap_show_variables = 'NOT_RUN'
  dap_show_callstack = 'NOT_RUN'
  dap_attach = 'NOT_RUN'
  peek_overlay = 'NOT_RUN'
  product_pass = 0
}
if ($main -ne [IntPtr]::Zero -and -not $earlyExit) {
  # Switch bottom panel toward Output if present
  $tabs = [UTB2022]::FindById($main, 1301)
  if ($tabs -ne [IntPtr]::Zero) {
    [void][UTB2022]::SendMessageW($tabs, 0x130C, [IntPtr]1, [IntPtr]::Zero) # TCM_SETCURSEL approx idx1 Output
    Log "BOTTOM_TABS present; attempted sel=1"
  }
  if (PostCmd 9200 'IDM_LSP_SERVER_START') {
    Start-Sleep -Milliseconds 800
    $out = ReadOutput
    if ($out -match 'LSP Server started|already running|LSP Server failed|LSP Server') {
      $b21.lsp_start = 'RUNTIME_REACHED_LSP_START_OUTPUT'
    } elseif (Alive) {
      $b21.lsp_start = 'RUNTIME_REACHED_CMD_POSTED_OUTPUT_UNCONFIRMED'
    }
  }
  if (PostCmd 9202 'IDM_LSP_SERVER_STATUS') {
    Start-Sleep -Milliseconds 500
    $out = ReadOutput
    if ($out -match 'LSP Server') { $b21.lsp_status = 'RUNTIME_REACHED_LSP_STATUS_OUTPUT' }
    elseif (Alive) { $b21.lsp_status = 'RUNTIME_REACHED_CMD_POSTED_OUTPUT_UNCONFIRMED' }
  }
  if (PostCmd 9205 'IDM_LSP_SERVER_PUBLISH_DIAG') {
    Start-Sleep -Milliseconds 500
    $out = ReadOutput
    if ($out -match 'Published|cannot publish|not running|diagnostic') {
      $b21.lsp_publish_diag = 'RUNTIME_REACHED_PUBLISH_DIAG_OUTPUT'
    } elseif (Alive) {
      $b21.lsp_publish_diag = 'RUNTIME_REACHED_CMD_POSTED_OUTPUT_UNCONFIRMED'
    }
  }
  if (PostCmd 10508 'IDM_DEBUG_SHOW_VARIABLES') {
    $out = ReadOutput
    if ($out -match '\[Debug\]|variable|Variables') { $b21.dap_show_variables = 'RUNTIME_REACHED_DEBUG_OUTPUT' }
    elseif (Alive) { $b21.dap_show_variables = 'RUNTIME_REACHED_CMD_POSTED_NO_CRASH' }
  }
  if (PostCmd 10507 'IDM_DEBUG_SHOW_CALLSTACK') {
    if (Alive) { $b21.dap_show_callstack = 'RUNTIME_REACHED_CMD_POSTED_NO_CRASH' }
  }
  if (PostCmd 10510 'IDM_DEBUG_ATTACH') {
    Start-Sleep -Milliseconds 700
    [void][UTB2022]::DismissDialogs([uint32]$proc.Id)
    $out = ReadOutput
    if ($out -match 'attach|Attach|DebugActiveProcess|startDebugging') {
      $b21.dap_attach = 'RUNTIME_REACHED_ATTACH_PATH_OBSERVED_TRUE_ATTACH_UNPROVEN'
    } elseif (Alive) {
      $b21.dap_attach = 'RUNTIME_REACHED_CMD_POSTED_TRUE_ATTACH_UNPROVEN'
    }
  }
  # PeekOverlay: string probe already 0; mark FAIL_CLOSED absent unless Output proves otherwise
  $b21.peek_overlay = 'NOT_REACHED_PEEK_STRING_ABSENT_IN_EXE'
}

# ---- B22 probes (extension host) ----
$extHost = Test-Path 'F:\rawrxd\build_win32ide\bin\Release\RawrXD-ExtensionHost.exe'
$b22 = [ordered]@{
  cold_start = $cold
  extension_host_binary = $(if ($extHost) { 'PRESENT' } else { 'ABSENT' })
  activation_lifecycle = 'NOT_REACHED_NO_EXTENSIONHOST_EXE'
  product_extension_runtime = 'NOT_REACHED_PRODUCT_STRING_ABSENT'
  vscode_activate = 'NOT_REACHED_NO_JS_ACTIVATE_HOST'
  process_isolation = 'NOT_RUN'
  product_pass = 0
}
# Binary string evidence captured at bind time
$raw = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($ExePath))
$b22.str_ExtensionHost = $(if ($raw.Contains('ExtensionHost')) { 1 } else { 0 })
$b22.str_ProductExtensionRuntime = $(if ($raw.Contains('ProductExtensionRuntime')) { 1 } else { 0 })
$b22.str_ActivateExtension = $(if ($raw.Contains('ActivateExtension')) { 1 } else { 0 })
$b22.str_RawrXD_ExtensionHost = $(if ($raw.Contains('RawrXD-ExtensionHost')) { 1 } else { 0 })
if ($b22.str_ExtensionHost -eq 1 -and -not $extHost) {
  $b22.activation_lifecycle = 'SOURCE_HINT_ExtensionHost_IN_EXE_BUT_SIBLING_EXE_ABSENT'
}
if (Alive -and $main -ne [IntPtr]::Zero) {
  $b22.process_isolation = 'NOT_REACHED_PRODUCT_SPAWN_UNEXERCISED_NO_WORKER_EXE'
}

# Final survival
$survived = if (Alive) { 1 } else { 0 }
Log "PROCESS_SURVIVED=$survived EARLY_EXIT=$earlyExit EXIT_CODE=$exitCode"
$finalOut = ''
if ($main -ne [IntPtr]::Zero -and (Alive)) { $finalOut = ReadOutput }
Set-Content -Path (Join-Path $OutDir 'output_panel_capture.txt') -Value $finalOut -Encoding UTF8

try { if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force } } catch {}
Start-Sleep -Milliseconds 500

function CountReached($map) {
  $n = 0; $t = 0
  foreach ($k in $map.Keys) {
    if ($k -in @('product_pass','str_ExtensionHost','str_ProductExtensionRuntime','str_ActivateExtension','str_RawrXD_ExtensionHost','extension_host_binary')) { continue }
    $t++
    if ("$($map[$k])" -like 'RUNTIME_REACHED*') { $n++ }
  }
  return @{ reached = $n; total = $t }
}

$c20 = CountReached $b20
$c21 = CountReached $b21
# B22: cold_start may REACH; others intentionally NOT_REACHED
$c22Reached = 0
if ($b22.cold_start -like 'RUNTIME_REACHED*') { $c22Reached = 1 }

# Dimension rollup vs audit matrices
# B20 matrix 6 dims — map probes honestly
$b20Dim = [ordered]@{
  tool_dispatch_fallthrough = $b20.tool_dispatch_fallthrough
  cancel_stale_callback = $b20.loop_cancel
  atomic_edit_rollback = 'NOT_RUN'
  duplicate_tool_exec = 'NOT_RUN'
  infinite_loop_bounds = 'NOT_RUN'
  task_success_rates = 'NOT_RUN'
}
$b20ReachedDims = @($b20Dim.Values | Where-Object { $_ -like 'RUNTIME_REACHED*' }).Count

# B21 selected of 13
$b21Dim = [ordered]@{
  lsp_completion = 'NOT_RUN'
  lsp_hover = 'NOT_RUN'
  lsp_goto_definition = 'NOT_RUN'
  lsp_find_references = 'NOT_RUN'
  lsp_rename = 'NOT_RUN'
  lsp_semantic_tokens = 'NOT_RUN'
  lsp_diagnostics = $b21.lsp_publish_diag
  lsp_peek = $b21.peek_overlay
  dap_launch = 'NOT_RUN'
  dap_attach = $b21.dap_attach
  dap_breakpoints = 'NOT_RUN'
  dap_step_continue = 'NOT_RUN'
  dap_variables_scopes_stack = $b21.dap_show_variables
}
# also count lsp_start/status as diagnostics-adjacent runtime for server path
$b21ExtraServer = @($b21.lsp_start, $b21.lsp_status) | Where-Object { $_ -like 'RUNTIME_REACHED*' }
$b21ReachedCaps = @($b21Dim.Values | Where-Object { $_ -like 'RUNTIME_REACHED*' }).Count

$b22Dim = [ordered]@{
  api_surface_vscode_compat_header = 'NOT_RUN'
  manifest_package_json_parse = 'NOT_RUN'
  activation_lifecycle = $b22.activation_lifecycle
  process_isolation = $b22.process_isolation
  sandbox_permissions = 'NOT_RUN'
  sample_extensions_inventory = 'NOT_RUN'
  vscode_compatibility_claims_vs_reality = $b22.vscode_activate
  product_http_api_extensions_routes = 'NOT_RUN'
  extension_host_worker_binary = $(if ($extHost) { 'RUNTIME_REACHED_BINARY_PRESENT_UNEXERCISED' } else { 'NOT_REACHED_BINARY_ABSENT' })
  ipc_bridge_and_command_dispatch = 'NOT_RUN'
}
$b22ReachedCaps = @($b22Dim.Values | Where-Object { $_ -like 'RUNTIME_REACHED*' }).Count

$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

# Write batch receipts
$b20Body = @"
BATCH_20_RUNTIME_DISPATCH=EXERCISED_UNPROMOTED
ASOF_UTC=$asof
EXE_PATH=$ExePath
PRE_REWIRE_SHA=$PreRewireSha
TIP_SHA=$sha
SHA_CHANGED=$shaChanged
BYTES=$bytes
COLD_START=$($b20.cold_start)
VIEW_TOOLS=$($b20.view_tools)
VIEW_STATUS=$($b20.view_status)
LOOP_CANCEL=$($b20.loop_cancel)
LOOP_STATUS=$($b20.loop_status)
TOOL_DISPATCH_FALLTHROUGH=$($b20.tool_dispatch_fallthrough)
DIM_tool_dispatch_fallthrough=$($b20Dim.tool_dispatch_fallthrough)
DIM_cancel_stale_callback=$($b20Dim.cancel_stale_callback)
DIM_atomic_edit_rollback=$($b20Dim.atomic_edit_rollback)
DIM_duplicate_tool_exec=$($b20Dim.duplicate_tool_exec)
DIM_infinite_loop_bounds=$($b20Dim.infinite_loop_bounds)
DIM_task_success_rates=$($b20Dim.task_success_rates)
RUNTIME_REACHED_DIMS=$b20ReachedDims/6
PRODUCT_RUNTIME_PASS=0/6
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
UPPER_TIER=0
NO_INVENT_PASS=1
NOT_RUN_NEQ_PASS=1
NOTE=Fallthrough not proven (no Execute-Command input injection); registry/cancel/status surfaces exercised only.
RUNLOG=$runLog
"@
Set-Content -Path (Join-Path $b20Dir 'RUNTIME_DISPATCH_RECEIPT.txt') -Value $b20Body -Encoding UTF8
Set-Content -Path (Join-Path $b20Dir 'DISPOSITION_RUNTIME.txt') -Value @"
DISPOSITION=BATCH_20_PARTIAL_RUNTIME_REACHED_UNPROMOTED
ASOF_UTC=$asof
TIP_SHA=$sha
PRE_REWIRE_SHA=$PreRewireSha
SHA_CHANGED=$shaChanged
RUNTIME_REACHED=$b20ReachedDims/6
PRODUCT_RUNTIME_PASS=0/6
AGENT_LOOP_MILESTONE=NOT_ACCEPTED
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
NEXT_GATE=IdeSsot unknown-tool+alias fallthrough E2E; cancel/stale suite; atomic edit fault inject; exactly-once stress; bounded loop SSOT; reliability rates measured only
"@ -Encoding UTF8

$b21Body = @"
BATCH_21_RUNTIME_DISPATCH=EXERCISED_UNPROMOTED
ASOF_UTC=$asof
EXE_PATH=$ExePath
PRE_REWIRE_SHA=$PreRewireSha
TIP_SHA=$sha
SHA_CHANGED=$shaChanged
COLD_START=$($b21.cold_start)
LSP_START=$($b21.lsp_start)
LSP_STATUS=$($b21.lsp_status)
LSP_PUBLISH_DIAG=$($b21.lsp_publish_diag)
DAP_SHOW_VARIABLES=$($b21.dap_show_variables)
DAP_SHOW_CALLSTACK=$($b21.dap_show_callstack)
DAP_ATTACH=$($b21.dap_attach)
PEEK_OVERLAY=$($b21.peek_overlay)
RUNTIME_REACHED_CAPS=$b21ReachedCaps/13
LSP_SERVER_PATH_EXTRA_REACHED=$($b21ExtraServer.Count)
PRODUCT_RUNTIME_PASS=0/13
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
UPPER_TIER=0
NO_INVENT_PASS=1
NOT_RUN_NEQ_PASS=1
NOTE=LSP completion/hover/goto/refs/rename/semantic NOT_RUN (no live LS client E2E). Peek NOT_REACHED (string absent). DAP attach true DebugActiveProcess unproven. Variables empty/unproven PASS.
RUNLOG=$runLog
"@
Set-Content -Path (Join-Path $b21Dir 'RUNTIME_DISPATCH_RECEIPT.txt') -Value $b21Body -Encoding UTF8
Set-Content -Path (Join-Path $b21Dir 'DISPOSITION_RUNTIME.txt') -Value @"
DISPOSITION=BATCH_21_PARTIAL_RUNTIME_REACHED_UNPROMOTED
ASOF_UTC=$asof
TIP_SHA=$sha
PRE_REWIRE_SHA=$PreRewireSha
SHA_CHANGED=$shaChanged
RUNTIME_REACHED=$b21ReachedCaps/13
PRODUCT_RUNTIME_PASS=0/13
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
NEXT_GATE=PeekOverlay CMake absorb on F; live LSP JSON-RPC E2E; DAP BP-hit+real variables; true DebugActiveProcess or hold OPEN
"@ -Encoding UTF8

$b22Body = @"
BATCH_22_RUNTIME_DISPATCH=EXERCISED_FAILCLOSED_UNPROMOTED
ASOF_UTC=$asof
EXE_PATH=$ExePath
PRE_REWIRE_SHA=$PreRewireSha
TIP_SHA=$sha
SHA_CHANGED=$shaChanged
COLD_START=$($b22.cold_start)
EXTENSION_HOST_BINARY=$($b22.extension_host_binary)
ACTIVATION_LIFECYCLE=$($b22.activation_lifecycle)
PRODUCT_EXTENSION_RUNTIME=$($b22.product_extension_runtime)
VSCODE_ACTIVATE=$($b22.vscode_activate)
PROCESS_ISOLATION=$($b22.process_isolation)
STR_ExtensionHost=$($b22.str_ExtensionHost)
STR_ProductExtensionRuntime=$($b22.str_ProductExtensionRuntime)
STR_ActivateExtension=$($b22.str_ActivateExtension)
STR_RawrXD_ExtensionHost=$($b22.str_RawrXD_ExtensionHost)
RUNTIME_REACHED_CAPS=$b22ReachedCaps/10
PRODUCT_RUNTIME_PASS=0/10
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
UPPER_TIER=0
NO_INVENT_PASS=1
NOT_RUN_NEQ_PASS=1
NOTE=Sibling RawrXD-ExtensionHost.exe ABSENT beside tip Native; ProductExtensionRuntime string absent; no JS activate path. MATRIX_002 candidate PASS not absorbed.
RUNLOG=$runLog
"@
Set-Content -Path (Join-Path $b22Dir 'RUNTIME_DISPATCH_RECEIPT.txt') -Value $b22Body -Encoding UTF8
Set-Content -Path (Join-Path $b22Dir 'DISPOSITION_RUNTIME.txt') -Value @"
DISPOSITION=BATCH_22_RUNTIME_FAILCLOSED_NO_EXTENSIONHOST_EXE
ASOF_UTC=$asof
TIP_SHA=$sha
PRE_REWIRE_SHA=$PreRewireSha
SHA_CHANGED=$shaChanged
RUNTIME_REACHED=$b22ReachedCaps/10
PRODUCT_RUNTIME_PASS=0/10
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
NEXT_GATE=Tip-coherent RawrXD-ExtensionHost.exe side-by-side; decide F absorb of G ProductExtensionRuntime; re-run EXT matrix PROMOTE=0; hold VS Code JS activate OPEN unless real script host
"@ -Encoding UTF8

$masterBody = @"
UPPER_TIER_B20_22_RUNTIME_DISPATCH=COMPLETE_UNPROMOTED
ASOF_UTC=$asof
EXE_PATH=$ExePath
PRE_REWIRE_SHA=$PreRewireSha
TIP_SHA=$sha
SHA_CHANGED=$shaChanged
BYTES=$bytes
MTIME=$mtime
PROCESS_SURVIVED=$survived
EARLY_EXIT=$earlyExit
EXIT_CODE=$exitCode
COLD_START=$cold
B20_RUNTIME_REACHED=$b20ReachedDims/6
B20_PRODUCT_PASS=0/6
B21_RUNTIME_REACHED=$b21ReachedCaps/13
B21_PRODUCT_PASS=0/13
B22_RUNTIME_REACHED=$b22ReachedCaps/10
B22_PRODUCT_PASS=0/10
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
UPPER_TIER=0
NO_INVENT_PASS=1
NOT_RUN_NEQ_PASS=1
B20_RECEIPT=$b20Dir\RUNTIME_DISPATCH_RECEIPT.txt
B21_RECEIPT=$b21Dir\RUNTIME_DISPATCH_RECEIPT.txt
B22_RECEIPT=$b22Dir\RUNTIME_DISPATCH_RECEIPT.txt
RUNLOG=$runLog
OUTPUT_CAPTURE=$OutDir\output_panel_capture.txt
"@
Set-Content -Path $master -Value $masterBody -Encoding UTF8
Get-Content $master
Write-Output '---B20---'
Get-Content (Join-Path $b20Dir 'RUNTIME_DISPATCH_RECEIPT.txt')
Write-Output '---B21---'
Get-Content (Join-Path $b21Dir 'RUNTIME_DISPATCH_RECEIPT.txt')
Write-Output '---B22---'
Get-Content (Join-Path $b22Dir 'RUNTIME_DISPATCH_RECEIPT.txt')
exit 0
