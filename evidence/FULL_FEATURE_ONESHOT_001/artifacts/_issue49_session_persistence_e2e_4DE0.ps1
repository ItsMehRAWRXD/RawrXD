#Requires -Version 5.1
# Issue #49 map #7 — session persistence across restart on tip_integ_candidate_001 (4DE0).
# Product surface: %LOCALAPPDATA%\RawrXD\ide_session.json (saveIdeSession/loadIdeSession).
# Laws: PROMOTE=0 MATURITY=82 E6CF HELD; NOT_RUN!=PASS; NO_CROSS_SHA_PASS; FORCE_KILL=0 preferred.
$ErrorActionPreference = 'Continue'
$ExpectSha = '4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6'
$TipExe = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$CandDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001'
$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
$SessionPath = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
if ($Sha -ne $ExpectSha) { Write-Host "SHA_DRIFT=$Sha expected=$ExpectSha"; exit 9 }

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','rawr' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2

Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class Map7SP {
  public const uint WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_COMMAND=0x0111, WM_CLOSE=0x0010;
  public const uint CB_SETCURSEL=0x014E; public const int CBN_SELCHANGE=1;
  public const int ID_EDITOR=1001, ID_CHAT=1202, ID_OUT=1203, ID_SEND=1204, ID_MODEL=1206, ID_CTX=1220, ID_TOK=1219;
  public const int IDM_FILE_SAVE=2003;
  public const uint CB_GETCOUNT=0x0146, CB_GETLBTEXT=0x0148, CB_GETLBTEXTLEN=0x0149;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr FindWindowExW(IntPtr parent, IntPtr child, string cls, string win);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h,l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(128); GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_MainWindow" || c == "RawrXD_IDE_Window" || c.IndexOf("RawrXD") >= 0) { found = h; return false; }
      return true;
    }, IntPtr.Zero); return found;
  }
  public static IntPtr FindCtrl(IntPtr root, int id) {
    var stack = new Stack<IntPtr>(); stack.Push(root);
    while (stack.Count > 0) {
      IntPtr cur = stack.Pop(); var kids = new List<IntPtr>();
      EnumChildWindows(cur, (h,lp) => { kids.Add(h); return true; }, IntPtr.Zero);
      foreach (var k in kids) { if (GetDlgCtrlID(k) == id) return k; stack.Push(k); }
    } return IntPtr.Zero;
  }
  public static IntPtr FindEditor(IntPtr root) {
    IntPtr byId = FindCtrl(root, ID_EDITOR);
    if (byId != IntPtr.Zero) return byId;
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(root, (h,lp) => {
      var sb = new StringBuilder(64); GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0 ||
          c.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) >= 0) {
        if (GetDlgCtrlID(h) == ID_EDITOR || found == IntPtr.Zero) found = h;
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static string GetText(IntPtr h) {
    if (h == IntPtr.Zero || !IsWindow(h)) return "";
    int n = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (n <= 0) return "";
    var sb = new StringBuilder(n + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb); return sb.ToString();
  }
  public static void SetText(IntPtr h, string t) { SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? ""); }
  public static void SelectCombo(IntPtr main, IntPtr combo, int id, int index) {
    if (combo == IntPtr.Zero) return;
    SendMessageW(combo, CB_SETCURSEL, (IntPtr)index, IntPtr.Zero);
    SendMessageW(main, WM_COMMAND, (IntPtr)((CBN_SELCHANGE << 16) | (id & 0xFFFF)), combo);
  }
  public static string ComboText(IntPtr combo, int index) {
    int len = (int)SendMessageW(combo, CB_GETLBTEXTLEN, (IntPtr)index, IntPtr.Zero);
    if (len <= 0) return "";
    var sb = new StringBuilder(len + 8);
    SendMessageW(combo, CB_GETLBTEXT, (IntPtr)index, sb); return sb.ToString();
  }
  public static int SelectModelContaining(IntPtr main, IntPtr combo, string needle) {
    if (combo == IntPtr.Zero) return -1;
    int count = (int)SendMessageW(combo, CB_GETCOUNT, IntPtr.Zero, IntPtr.Zero);
    for (int i = 0; i < count; i++) {
      string t = ComboText(combo, i);
      if (t.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) {
        SendMessageW(combo, CB_SETCURSEL, (IntPtr)i, IntPtr.Zero);
        SendMessageW(main, WM_COMMAND, (IntPtr)((CBN_SELCHANGE << 16) | (ID_MODEL & 0xFFFF)), combo);
        return i;
      }
    }
    return -1;
  }
  public static bool CloseClean(IntPtr main, int waitMs) {
    if (main == IntPtr.Zero || !IsWindow(main)) return true;
    PostMessageW(main, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
    int slept = 0;
    while (slept < waitMs) {
      if (!IsWindow(main)) return true;
      System.Threading.Thread.Sleep(250);
      slept += 250;
    }
    return !IsWindow(main);
  }
}
"@

function Wait-Main([Diagnostics.Process]$proc, [int]$sec = 55) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    try { $proc.Refresh() } catch {}
    if ($proc.HasExited) { return [IntPtr]::Zero }
    $m = [Map7SP]::FindMain([uint32]$proc.Id)
    if ($m -ne [IntPtr]::Zero) { return $m }
    Start-Sleep -Milliseconds 250
  }
  return [IntPtr]::Zero
}

function Wait-ProcessExit([Diagnostics.Process]$proc, [int]$sec = 25) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    try { $proc.Refresh() } catch { return $true }
    if ($proc.HasExited) { return $true }
    Start-Sleep -Milliseconds 250
  }
  try { return $proc.HasExited } catch { return $true }
}

function Get-SessionRaw {
  if (-not (Test-Path -LiteralPath $SessionPath)) { return '' }
  try { return (Get-Content -LiteralPath $SessionPath -Raw -ErrorAction Stop) } catch { return '' }
}

$runDir = Join-Path $CandDir ("map7_persist_$Stamp")
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$ws = Join-Path $runDir 'workspace'
New-Item -ItemType Directory -Force -Path $ws | Out-Null
$session = "integ_map7_$Stamp"
$runId = "integ_map7_run_$Stamp"
$markerDoc = "MAP7_DOC_MARKER_$Stamp"
$markerChat = "MAP7_CHAT_MARKER_$Stamp"
$seed = Join-Path $ws ("map7_seed_$Stamp.txt")
Set-Content -LiteralPath $seed -Value "$markerDoc`r`nseed for session persistence across restart`r`n" -Encoding ascii
$seedNorm = $seed.Replace('\','/')

# Quarantine prior session so argv-open + our markers are authoritative.
$sessionBackup = Join-Path $runDir 'ide_session_BEFORE_quarantine.json'
if (Test-Path -LiteralPath $SessionPath) {
  Copy-Item -LiteralPath $SessionPath -Destination $sessionBackup -Force
}
$sessionDir = Split-Path -Parent $SessionPath
New-Item -ItemType Directory -Force -Path $sessionDir | Out-Null
$cleanSession = '{"active":0,"chat_mode":0,"documents":[{"path":"","text":"","modified":false}],"chat":{"active":0,"next_id":2,"sessions":[{"id":1,"title":"Chat 1","history":[],"response_buffer":"","checkpoints":[],"step_rows":[]}]}}'
Set-Content -LiteralPath $SessionPath -Value $cleanSession -Encoding utf8

$env:RAWRXD_LOG_DIR = $runDir
$env:RAWRXD_CHAT_SESSION_ID = $session
$env:RAWRXD_CHAT_RUN_ID = $runId
$rt = Join-Path $runDir 'chat_runtime.log'
if (Test-Path $rt) { Remove-Item $rt -Force }

$p1 = 'FAIL'; $establish = 'FAIL'; $persistFs = 'FAIL'; $cleanExit = 'FAIL'
$relaunch = 'FAIL'; $restoreFs = 'FAIL'; $restoreHwnd = 'FAIL'
$forceKill = 0; $mainHexA = '0x0'; $mainHexB = '0x0'
$pidA = 0; $pidB = 0; $editorBefore = ''; $editorAfter = ''
$chatOutAfter = ''; $sessionBeforeClose = ''; $sessionAfterRestart = ''
$modelSel = 'SKIP'; $chatArmed = 'SKIP'
$persistFsPreClose = 'MISS'; $persistFsOk = $false

# --- Phase A: launch + establish durable state ---
$p = Start-Process -FilePath $TipExe -ArgumentList @($seed) -WorkingDirectory $ws -PassThru -WindowStyle Normal
$pidA = $p.Id
$main = Wait-Main $p 55
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  $p1 = 'PASS'
  $mainHexA = ('0x{0:X}' -f $main.ToInt64())
  Start-Sleep 6
  [void][Map7SP]::SetForegroundWindow($main)
  $editor = [Map7SP]::FindEditor($main)
  $chat = [Map7SP]::FindCtrl($main, [Map7SP]::ID_CHAT)
  $send = [Map7SP]::FindCtrl($main, [Map7SP]::ID_SEND)
  $out = [Map7SP]::FindCtrl($main, [Map7SP]::ID_OUT)
  $model = [Map7SP]::FindCtrl($main, [Map7SP]::ID_MODEL)
  $ctx = [Map7SP]::FindCtrl($main, [Map7SP]::ID_CTX)
  $tok = [Map7SP]::FindCtrl($main, [Map7SP]::ID_TOK)

  # Confirm seed text present in editor (product opened argv file).
  $deadlineEd = (Get-Date).AddSeconds(20)
  while ((Get-Date) -lt $deadlineEd) {
    $editorBefore = [Map7SP]::GetText($editor)
    if ($editorBefore -like "*$markerDoc*") { break }
    Start-Sleep -Milliseconds 400
    $editor = [Map7SP]::FindEditor($main)
  }

  # Chat marker: short dispatch so history is durable; no need for full completion.
  if ($ctx -ne [IntPtr]::Zero) { [Map7SP]::SelectCombo($main, $ctx, 1220, 0) }
  if ($tok -ne [IntPtr]::Zero) { [Map7SP]::SelectCombo($main, $tok, 1219, 0) }
  $mi = [Map7SP]::SelectModelContaining($main, $model, 'llama3.2')
  if ($mi -lt 0) { $mi = [Map7SP]::SelectModelContaining($main, $model, 'llama3.1:8b') }
  if ($mi -lt 0) { $mi = [Map7SP]::SelectModelContaining($main, $model, 'gemma3:4b') }
  if ($mi -lt 0) { $mi = [Map7SP]::SelectModelContaining($main, $model, 'qwen2.5-coder:1.5b') }
  $modelSel = if ($mi -ge 0) { "PASS index=$mi" } else { 'FAIL_DEFAULT' }
  if ($chat -ne [IntPtr]::Zero -and $send -ne [IntPtr]::Zero) {
    [Map7SP]::SetText($chat, "$markerChat Reply with exactly one word: ok")
    Start-Sleep -Milliseconds 200
    [void][Map7SP]::SendMessageW($main, [Map7SP]::WM_COMMAND, [IntPtr]1204, $send)
    $chatArmed = 'SENT'
    # Allow history attach + debounced session autosave / journal.
    Start-Sleep 8
  }

  if ($editorBefore -like "*$markerDoc*") { $establish = 'PASS_DOC' }
  elseif ($chatArmed -eq 'SENT') { $establish = 'PASS_CHAT_ONLY' }
  else { $establish = 'FAIL_NO_MARKER' }

  # Pre-close snapshot is advisory (autosave debounce race). Authoritative persist
  # is saveIdeSession on WM_CLOSE — measured after clean exit below.
  $sessionBeforeClose = Get-SessionRaw
  $persistFsPreClose = 'MISS'
  if (($sessionBeforeClose -like "*$markerDoc*") -or ($sessionBeforeClose -like "*map7_seed_$Stamp*") -or ($sessionBeforeClose -like "*$markerChat*")) {
    $persistFsPreClose = 'HIT'
    $persistFs = 'PASS_PRE_CLOSE'
  }

  # Prefer clean close (FORCE_KILL=0). Seed file is unmodified on disk => no save prompt.
  $closed = [Map7SP]::CloseClean($main, 20000)
  $exited = Wait-ProcessExit $p 15
  if ($closed -and $exited) {
    $cleanExit = 'PASS'
  } else {
    # Fail-closed measurement: escalate only after clean close timed out.
    $forceKill = 1
    try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } } catch {}
    Wait-ProcessExit $p 8 | Out-Null
    $cleanExit = 'FAIL_ESCALATED_FORCE_KILL'
  }
} else {
  try { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
}

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2

# Capture mid-gap session (post-close / pre-relaunch) — product saveIdeSession evidence.
$sessionMid = Get-SessionRaw
Copy-Item -LiteralPath $SessionPath -Destination (Join-Path $runDir 'ide_session_AFTER_CLOSE.json') -Force -ErrorAction SilentlyContinue
if ($persistFs -ne 'PASS_PRE_CLOSE') {
  $docMid = ($sessionMid -like "*$markerDoc*") -or ($sessionMid -like "*map7_seed_$Stamp*")
  $chatMid = ($sessionMid -like "*$markerChat*")
  if ($docMid -or $chatMid) { $persistFs = 'PASS_POST_CLOSE' }
  elseif (Test-Path $SessionPath) { $persistFs = 'FAIL_SESSION_NO_MARKER' }
  else { $persistFs = 'FAIL_NO_SESSION_FILE' }
}
$persistFsOk = ($persistFs -eq 'PASS_PRE_CLOSE' -or $persistFs -eq 'PASS_POST_CLOSE')

# --- Phase B: relaunch WITHOUT argv seed — restore must come from ide_session.json ---
$p2 = $null
if ($p1 -eq 'PASS' -and ($persistFsOk -or $establish -match '^PASS')) {
  $p2 = Start-Process -FilePath $TipExe -WorkingDirectory $ws -PassThru -WindowStyle Normal
  $pidB = $p2.Id
  $main2 = Wait-Main $p2 55
  if ($main2 -ne [IntPtr]::Zero -and -not $p2.HasExited) {
    $relaunch = 'PASS'
    $mainHexB = ('0x{0:X}' -f $main2.ToInt64())
    Start-Sleep 8
    [void][Map7SP]::SetForegroundWindow($main2)
    $editor2 = [Map7SP]::FindEditor($main2)
    $out2 = [Map7SP]::FindCtrl($main2, [Map7SP]::ID_OUT)
    $deadlineR = (Get-Date).AddSeconds(25)
    while ((Get-Date) -lt $deadlineR) {
      $editorAfter = [Map7SP]::GetText($editor2)
      $chatOutAfter = [Map7SP]::GetText($out2)
      if (($editorAfter -like "*$markerDoc*") -or ($chatOutAfter -like "*$markerChat*")) { break }
      Start-Sleep -Milliseconds 500
      $editor2 = [Map7SP]::FindEditor($main2)
      $out2 = [Map7SP]::FindCtrl($main2, [Map7SP]::ID_OUT)
    }
    $sessionAfterRestart = Get-SessionRaw
    $fsDoc = ($sessionAfterRestart -like "*$markerDoc*") -or ($sessionAfterRestart -like "*map7_seed_$Stamp*")
    $fsChat = ($sessionAfterRestart -like "*$markerChat*")
    if ($fsDoc -or $fsChat) { $restoreFs = 'PASS' } else { $restoreFs = 'FAIL_FS' }
    if ($editorAfter -like "*$markerDoc*") { $restoreHwnd = 'PASS_EDITOR' }
    elseif ($chatOutAfter -like "*$markerChat*") { $restoreHwnd = 'PASS_CHAT' }
    else { $restoreHwnd = 'FAIL_HWND' }

    [void][Map7SP]::CloseClean($main2, 15000)
    if (-not (Wait-ProcessExit $p2 10)) {
      try { Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
  } else {
    $relaunch = 'FAIL'
    try { if ($p2 -and -not $p2.HasExited) { Stop-Process -Id $p2.Id -Force } } catch {}
  }
}

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue

# Final session snapshot
if (-not $sessionAfterRestart) { $sessionAfterRestart = Get-SessionRaw }
Copy-Item -LiteralPath $SessionPath -Destination (Join-Path $runDir 'ide_session_AFTER_RESTART.json') -Force -ErrorAction SilentlyContinue
Set-Content -LiteralPath (Join-Path $runDir 'editor_before.txt') -Value $editorBefore -Encoding utf8
Set-Content -LiteralPath (Join-Path $runDir 'editor_after.txt') -Value $editorAfter -Encoding utf8
Set-Content -LiteralPath (Join-Path $runDir 'chat_out_after.txt') -Value $chatOutAfter -Encoding utf8
if (Test-Path $rt) {
  Copy-Item -LiteralPath $rt -Destination (Join-Path $OutDir 'ISSUE49_SESSION_PERSISTENCE_JOURNAL.txt') -Force
}

$map7 = 'FAIL'
if ($p1 -eq 'PASS' -and $Sha -eq $ExpectSha -and $establish -match '^PASS' -and $persistFsOk `
    -and $cleanExit -eq 'PASS' -and $forceKill -eq 0 -and $relaunch -eq 'PASS' `
    -and $restoreFs -eq 'PASS' -and ($restoreHwnd -match '^PASS')) {
  $map7 = 'PASS'
} elseif ($p1 -ne 'PASS') {
  $map7 = 'NOT_DEMONSTRATED'
} elseif ($p1 -eq 'PASS' -and $establish -match '^PASS' -and $restoreFs -eq 'PASS' -and ($restoreHwnd -match '^PASS') -and $forceKill -eq 1) {
  # Restored, but preferred clean-close path failed — still measured restore; call PARTIAL not invent PASS.
  $map7 = 'PARTIAL_FORCE_KILL'
} elseif ($p1 -eq 'PASS' -and $establish -match '^PASS' -and $restoreFs -eq 'PASS' -and $restoreHwnd -eq 'FAIL_HWND') {
  $map7 = 'PARTIAL_FS_ONLY'
} else {
  $map7 = 'FAIL'
}

$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$advance = if ($map7 -eq 'PASS') { '6/11->7/11' } else { 'HOLD_6/11' }
$receipt = @"
ISSUE49_SESSION_PERSISTENCE_RECEIPT
ASOF_UTC=$asof
ACTIVE_TRACK=ISSUE_49
MAP=7
CANDIDATE=tip_integ_candidate_001
TIP_SHA256=$Sha
PRIOR_SHA256=1046C2B8394267D87CAD3970A16C34EFF231A5B84FEA6FF6D5A6BBD2622192CE
TIP_EXE=$TipExe
SUITE_STAMP=$Stamp
SESSION_ID=$session
RUN_ID=$runId
MAIN_HWND_A=$mainHexA
MAIN_HWND_B=$mainHexB
PID_A=$pidA
PID_B=$pidB
PRODUCT_SURFACE=%LOCALAPPDATA%\RawrXD\ide_session.json
SESSION_PATH=$SessionPath
SEED_FILE=$seed
MARKER_DOC=$markerDoc
MARKER_CHAT=$markerChat
RUNTIME_LOG=$rt
HARNESS=artifacts\_issue49_session_persistence_e2e.ps1
FORCE_KILL=$forceKill
NO_CROSS_SHA_PASS=1
T074_NE_MAP7=1

## Establish (launch #1 + argv seed open)
P1_HWND=$p1
ESTABLISH=$establish
EDITOR_BEFORE_HAS_MARKER=$(if($editorBefore -like "*$markerDoc*"){'YES'}else{'NO'})
EDITOR_BEFORE_LEN=$($editorBefore.Length)
CHAT_ARMED=$chatArmed
MODEL_SELECT=$modelSel
PERSIST_FS=$persistFs
PERSIST_FS_PRE_CLOSE=$persistFsPreClose

## Clean restart
CLEAN_EXIT=$cleanExit
RELAUNCH=$relaunch

## Restore (launch #2, no argv — rehydrate from ide_session.json)
RESTORE_FS=$restoreFs
RESTORE_HWND=$restoreHwnd
EDITOR_AFTER_HAS_MARKER=$(if($editorAfter -like "*$markerDoc*"){'YES'}else{'NO'})
EDITOR_AFTER_LEN=$($editorAfter.Length)
CHAT_OUT_AFTER_HAS_MARKER=$(if($chatOutAfter -like "*$markerChat*"){'YES'}else{'NO'})
CHAT_OUT_AFTER_LEN=$($chatOutAfter.Length)
SESSION_AFTER_HAS_DOC=$(if(($sessionAfterRestart -like "*$markerDoc*") -or ($sessionAfterRestart -like "*map7_seed_$Stamp*")){'YES'}else{'NO'})
SESSION_AFTER_HAS_CHAT=$(if($sessionAfterRestart -like "*$markerChat*"){'YES'}else{'NO'})

## Gate
MAP7=$map7
ISSUE49_ADVANCE=$advance
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY=82_UNCHANGED
E6CF_RESTORE=HELD
CC79_UNREPLACED=1
A4F_IMMUTABLE=1
TIP_MOVE_AUTHORIZED=0
INVENT_PASS=0
"@

$receiptPath = Join-Path $OutDir 'ISSUE49_SESSION_PERSISTENCE_RECEIPT.txt'
Set-Content -LiteralPath $receiptPath -Value $receipt -Encoding ascii
Set-Content -LiteralPath (Join-Path $runDir 'SESSION_PERSISTENCE_RECEIPT.txt') -Value $receipt -Encoding ascii
Write-Host $receipt
Write-Host "RECEIPT=$receiptPath"
Write-Host "MAP7=$map7"
if ($map7 -eq 'PASS') { exit 0 }
elseif ($map7 -match '^PARTIAL') { exit 3 }
else { exit 1 }
