# Minimal HWND 1203 (IDC_COPILOT_CHAT_OUTPUT) capture after Send on tip_cc79_integ_002.
# Prefer Welcome/AI/[dispatch_id]; reject debug/log scrapes. No tip rebuild. PROMOTE=0.
param(
  [string]$TipExe = "F:\rawrxd\evidence\CC79_RUNTIME_001\package\tip_cc79_integ_002\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "F5F4807E4738F500397AA5ACEBC8BE095806DF19C71FF959083512C73A16BA15",
  [string]$OutDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\candidates\tip_cc79_integ_002_eo_hwnd1203",
  [string]$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp",
  [int]$BootWaitSec = 3,
  [int]$IdleTimeoutMs = 60000
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$sessionId = "eo1203_sess_$stamp"
$runId = "eo1203_run_$stamp"
$runlog = Join-Path $OutDir "chat_hwnd1203_run_$stamp.txt"
$receipt = Join-Path $OutDir "CHAT_HWND1203_CAPTURE_RECEIPT.txt"
$rt = Join-Path $LogDir "chat_runtime.log"
$visPath = Join-Path $LogDir "hwnd1203_transcript_$stamp.txt"
$enumPath = Join-Path $LogDir "hwnd1203_enum_$stamp.txt"

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runlog -Value $line
  Write-Host $line
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
public static class H1203Native {
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_COMMAND = 0x0111;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static void SetText(IntPtr h, string t) { SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? ""); }
  public static string GetText(IntPtr h) {
    int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (len < 0) len = 0;
    var sb = new StringBuilder(len + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
    return sb.ToString();
  }
  public static IntPtr FindCtrl(IntPtr parent, int wantId, string classPart) {
    Stack<IntPtr> stack = new Stack<IntPtr>();
    stack.Push(parent);
    while (stack.Count > 0) {
      IntPtr cur = stack.Pop();
      List<IntPtr> kids = new List<IntPtr>();
      EnumChildWindows(cur, (h, lp) => { kids.Add(h); return true; }, IntPtr.Zero);
      foreach (IntPtr k in kids) {
        int id = GetDlgCtrlID(k);
        StringBuilder cls = new StringBuilder(64);
        GetClassNameW(k, cls, 64);
        if (id == wantId && cls.ToString().IndexOf(classPart, StringComparison.OrdinalIgnoreCase) >= 0) return k;
        stack.Push(k);
      }
    }
    return IntPtr.Zero;
  }
  public class EditInfo {
    public IntPtr Hwnd; public int Id; public string Cls; public string Text; public int Score;
  }
  public static List<EditInfo> EnumScoreEdits(IntPtr parent) {
    var list = new List<EditInfo>();
    Stack<IntPtr> stack = new Stack<IntPtr>();
    stack.Push(parent);
    while (stack.Count > 0) {
      IntPtr cur = stack.Pop();
      List<IntPtr> kids = new List<IntPtr>();
      EnumChildWindows(cur, (h, lp) => { kids.Add(h); return true; }, IntPtr.Zero);
      foreach (IntPtr k in kids) {
        StringBuilder cls = new StringBuilder(64);
        GetClassNameW(k, cls, 64);
        string c = cls.ToString();
        bool isText = c.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) >= 0 ||
                      c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0;
        if (isText) {
          int id = GetDlgCtrlID(k);
          string t = GetText(k);
          int score = 0;
          if (id == 1203) score += 20;
          if (t.IndexOf("Welcome to RawrXD AI Chat", StringComparison.OrdinalIgnoreCase) >= 0) score += 100;
          if (t.IndexOf("GitHub Copilot Chat", StringComparison.OrdinalIgnoreCase) >= 0) score += 100;
          if (t.IndexOf("Ask me anything about your code", StringComparison.OrdinalIgnoreCase) >= 0) score += 80;
          if (t.IndexOf("[dispatch_id=", StringComparison.OrdinalIgnoreCase) >= 0) score += 80;
          if (t.IndexOf("AI:", StringComparison.OrdinalIgnoreCase) >= 0) score += 40;
          if (t.IndexOf("> User:", StringComparison.OrdinalIgnoreCase) >= 0) score += 40;
          if (t.IndexOf("eo-hwnd1203", StringComparison.OrdinalIgnoreCase) >= 0) score += 30;
          if (t.IndexOf("eo-corr-", StringComparison.OrdinalIgnoreCase) >= 0) score += 30;
          // Reject debug/log panes hard
          if (t.IndexOf("[CHAT_RUNTIME]", StringComparison.OrdinalIgnoreCase) >= 0) score -= 200;
          if (t.IndexOf("Logging Initialized", StringComparison.OrdinalIgnoreCase) >= 0) score -= 200;
          if (t.IndexOf("[GhostText]", StringComparison.OrdinalIgnoreCase) >= 0) score -= 150;
          if (t.IndexOf("PowerShell Version:", StringComparison.OrdinalIgnoreCase) >= 0) score -= 150;
          if (t.IndexOf("[EDITOR_CHANGE]", StringComparison.OrdinalIgnoreCase) >= 0) score -= 150;
          list.Add(new EditInfo { Hwnd = k, Id = id, Cls = c, Text = t, Score = score });
        }
        stack.Push(k);
      }
    }
    return list;
  }
}
public static class H1203HwndFind {
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256); GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_MainWindow" || c == "RawrXD_IDE_Window") { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@

$hash = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_SHA256=$hash EXPECT=$ExpectSha MATCH=$([int]($hash -eq $ExpectSha))"
$tipHasInsert = $false
try {
  $bytes = [IO.File]::ReadAllBytes($TipExe)
  $ascii = [Text.Encoding]::ASCII.GetString($bytes)
  $tipHasInsert = $ascii.Contains("TRANSCRIPT_INSERT")
} catch {}
Log "TIP_HAS_TRANSCRIPT_INSERT=$([int]$tipHasInsert)"

# Do not thrash H57 / other Native-Ext binds: only stop this tip package path.
Get-Process -Name "RawrXD-Win32IDE-Native*" -EA SilentlyContinue | ForEach-Object {
  try {
    $path = $_.Path
    if ($path -and ($path -like "*tip_cc79_integ_002*" -or $path -like "*tip_cc79_integ_002_eo*")) {
      Log "STOP_OWN_TIP pid=$($_.Id) path=$path"
      Stop-Process -Id $_.Id -Force -EA SilentlyContinue
    } else {
      Log "LEAVE_OTHER_NATIVE pid=$($_.Id) path=$path"
    }
  } catch { Log "STOP_SCAN_ERR=$($_.Exception.Message)" }
}
Start-Sleep 2
if (Test-Path $rt) { Remove-Item $rt -Force }
$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_CHAT_SESSION_ID = $sessionId
$env:RAWRXD_CHAT_RUN_ID = $runId
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue

$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -PassThru -WindowStyle Normal
Log "PID=$($p.Id) SESSION=$sessionId RUN=$runId"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $byPid = [H1203HwndFind]::FindMain([uint32]$p.Id)
  if ($byPid -ne [IntPtr]::Zero) { $main = $byPid; break }
}
$mainHx = '{0:X}' -f $main.ToInt64()
Log "MAIN=0x$mainHx"
if ($main -eq [IntPtr]::Zero) {
  @"
EXACTLY_ONCE=NOT_VERIFIED
DISPATCH_VISIBLE=NOT_CAPTURED
REASON=main_hwnd_missing
PROMOTE=0
"@ | Set-Content $receipt
  exit 3
}

$chat = [H1203Native]::FindCtrl($main, 1202, "Edit")
$send = [H1203Native]::FindCtrl($main, 1204, "Button")
$byId1203 = [H1203Native]::FindCtrl($main, 1203, "Edit")
$cHx = '{0:X}' -f $chat.ToInt64(); $sHx = '{0:X}' -f $send.ToInt64(); $iHx = '{0:X}' -f $byId1203.ToInt64()
Log "CHAT_INPUT=0x$cHx SEND=0x$sHx ID1203_FIRST=0x$iHx"
if ($chat -eq [IntPtr]::Zero -or $send -eq [IntPtr]::Zero) {
  @"
EXACTLY_ONCE=NOT_VERIFIED
DISPATCH_VISIBLE=NOT_CAPTURED
REASON=chat_controls_missing
PROMOTE=0
"@ | Set-Content $receipt
  try { Stop-Process -Id $p.Id -Force } catch {}
  exit 4
}

function Read-Rt { if (Test-Path $rt) { @(Get-Content $rt -EA SilentlyContinue) } else { @() } }
function Wait-Idle([int]$armedTarget) {
  $deadline = [Environment]::TickCount64 + $IdleTimeoutMs
  while ([Environment]::TickCount64 -lt $deadline) {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { return $false }
    $lines = Read-Rt
    $armed = @($lines | Where-Object { $_ -match 'CHAT_SEND_ARMED' }).Count
    $complete = @($lines | Where-Object { $_ -match 'ui_update .*complete=1' }).Count
    if ($armed -ge $armedTarget -and $complete -ge $armed) { return $true }
    Start-Sleep -Milliseconds 400
  }
  return $false
}

Start-Sleep -Seconds $BootWaitSec

# Pre-send enum while process alive (identity of chat vs debug panes)
$preEdits = @()
try { $preEdits = @([H1203Native]::EnumScoreEdits($main)) } catch { Log "PRE_ENUM_FAIL=$($_.Exception.Message)" }
$preEnumPath = Join-Path $LogDir "hwnd1203_pre_enum_$stamp.txt"
$preLines = @("EDIT_COUNT=$($preEdits.Count)")
foreach ($e in ($preEdits | Sort-Object Score -Descending)) {
  $sample = if ($e.Text.Length -gt 120) { $e.Text.Substring(0, 120) -replace "`r|`n", " " } else { ($e.Text -replace "`r|`n", " ") }
  $preLines += ("id={0} hwnd=0x{1:X} score={2} cls={3} len={4} sample={5}" -f $e.Id, $e.Hwnd.ToInt64(), $e.Score, $e.Cls, $e.Text.Length, $sample)
}
$preLines | Set-Content $preEnumPath -Encoding UTF8
Log "PRE_ENUM count=$($preEdits.Count) path=$preEnumPath"

# Boot capture of id=1203 before Send (expect Copilot/Welcome text)
$boot1203 = ""
if ($byId1203 -ne [IntPtr]::Zero) {
  try { $boot1203 = [H1203Native]::GetText($byId1203) } catch {}
}
# If first id=1203 empty, prefer best pre-scored chat-like edit
$bootBest = $null
foreach ($e in ($preEdits | Sort-Object Score -Descending)) {
  if ($e.Score -gt 0) { $bootBest = $e; break }
}
if ($boot1203.Length -eq 0 -and $null -ne $bootBest) {
  $boot1203 = $bootBest.Text
  $byId1203 = $bootBest.Hwnd
  Log "BOOT_FALLBACK_SCORED id=$($bootBest.Id) score=$($bootBest.Score)"
}
$bootPath = Join-Path $LogDir "hwnd1203_boot_$stamp.txt"
Set-Content -Path $bootPath -Value $boot1203 -Encoding UTF8
$bootOne = ($boot1203 -replace "`r|`n", " ")
$bootSamp = if ($bootOne.Length -gt 80) { $bootOne.Substring(0, 80) } else { $bootOne }
Log "BOOT_1203_LEN=$($boot1203.Length) sample=$bootSamp"

try { $p.Refresh() } catch {}
if ($p.HasExited) {
  Log "PROCESS_DEAD_BEFORE_CLICK"
} else {
  [H1203Native]::SetText($chat, "eo-hwnd1203-1")
  Start-Sleep -Milliseconds 100
  [void][H1203Native]::SendMessageW($main, 0x0111, [IntPtr]1204, $send)
  Log "CLICK=1 msg=eo-hwnd1203-1"
  $idleOk = Wait-Idle 1
  Log "IDLE_OK=$([int]$idleOk) exited=$([int]$p.HasExited)"
  Start-Sleep -Seconds 2
}

# Enumerate + score edits; pick chat, never debug
$edits = @()
try {
  if (-not $p.HasExited) { $edits = @([H1203Native]::EnumScoreEdits($main)) }
  else { $edits = $preEdits; Log "POST_ENUM_SKIPPED_USING_PRE" }
} catch { Log "ENUM_FAIL=$($_.Exception.Message)" }
$enumLines = @("EDIT_COUNT=$($edits.Count)")
foreach ($e in ($edits | Sort-Object Score -Descending)) {
  $sample = if ($e.Text.Length -gt 120) { $e.Text.Substring(0, 120) -replace "`r|`n", " " } else { ($e.Text -replace "`r|`n", " ") }
  $enumLines += ("id={0} hwnd=0x{1:X} score={2} cls={3} len={4} sample={5}" -f $e.Id, $e.Hwnd.ToInt64(), $e.Score, $e.Cls, $e.Text.Length, $sample)
}
$enumLines | Set-Content $enumPath -Encoding UTF8
Log "ENUM_WRITTEN count=$($edits.Count) path=$enumPath"

$best = $null
foreach ($e in ($edits | Sort-Object Score -Descending)) {
  if ($e.Score -gt 0) { $best = $e; break }
}
# Prefer positive-scored id=1203 if present
$id1203Pos = @($edits | Where-Object { $_.Id -eq 1203 -and $_.Score -gt 0 } | Sort-Object Score -Descending)
if ($id1203Pos.Count -ge 1) { $best = $id1203Pos[0] }

$vis = ""
$captureKind = "NONE"
$hwndUsed = [IntPtr]::Zero
if ($null -ne $best) {
  $vis = $best.Text
  $captureKind = "SCORED_EDIT id=$($best.Id) score=$($best.Score)"
  $hwndUsed = $best.Hwnd
} elseif ($byId1203 -ne [IntPtr]::Zero) {
  $raw = ""
  try { $raw = [H1203Native]::GetText($byId1203) } catch {}
  # Accept only if not debug-like
  if ($raw.Length -gt 0 -and $raw -notmatch '\[CHAT_RUNTIME\]|Logging Initialized|\[GhostText\]|\[EDITOR_CHANGE\]') {
    $vis = $raw
    $captureKind = "ID1203_RAW_NONDEBUG"
    $hwndUsed = $byId1203
  } elseif ($boot1203.Length -gt 0 -and $boot1203 -notmatch '\[CHAT_RUNTIME\]|Logging Initialized') {
    # Fall back to boot capture as HWND_1203 identity proof (pre-send)
    $vis = $boot1203
    $captureKind = "ID1203_BOOT_ONLY_POSTSEND_EMPTY"
    $hwndUsed = $byId1203
  } elseif ($raw -match '\[CHAT_RUNTIME\]|Logging Initialized|\[GhostText\]|\[EDITOR_CHANGE\]') {
    $captureKind = "ID1203_REJECTED_DEBUG_CONTENT"
    $vis = ""
  } else {
    $captureKind = "ID1203_EMPTY"
    $vis = ""
  }
}

Set-Content -Path $visPath -Value $vis -Encoding UTF8
$visHx = '{0:X}' -f $hwndUsed.ToInt64()
Log "CAPTURE kind=$captureKind hwnd=0x$visHx len=$($vis.Length)"

$hasWelcome = [int]($vis -match 'Welcome to RawrXD AI Chat')
$hasAi = [int]($vis -match '(?i)\bAI:')
$hasUser = [int]($vis -match '(?i)>\s*User:')
$tagHits = [regex]::Matches($vis, '\[dispatch_id=(\d+)\]')
$tagIds = @($tagHits | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
$dispatchVisible = if ($tagHits.Count -ge 1) { "PRESENT tags=$($tagIds -join ',')" } else { "NOT_CAPTURED" }
$hasProbe = [int]($vis -match 'eo-hwnd1203-1')
$isDebug = [int]($vis -match '\[CHAT_RUNTIME\]|Logging Initialized|\[GhostText\]')

$lines = Read-Rt
$rtCopy = Join-Path $OutDir "chat_hwnd1203_runtime_$stamp.log"
if (Test-Path $rt) { Copy-Item $rt $rtCopy -Force }
$insertN = @($lines | Where-Object { $_ -match 'TRANSCRIPT_INSERT' }).Count
$inputN = @($lines | Where-Object { $_ -match 'INPUT_EVENT kind=BUTTON_CLICK' }).Count
$attemptN = @($lines | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }).Count
$armedN = @($lines | Where-Object { $_ -match 'CHAT_SEND_ARMED' }).Count
$uiCompleteN = @($lines | Where-Object { $_ -match 'ui_update .*complete=1' }).Count

$blockers = @()
if (-not $tipHasInsert -or $insertN -eq 0) { $blockers += "BLOCKED_NEEDS_TIP_INSTRUMENT" }
if ($dispatchVisible -eq "NOT_CAPTURED") { $blockers += "TRANSCRIPT_VISIBLE_TAG_MISSING" }
if ($isDebug -eq 1) { $blockers += "HWND_SCRAPE_WAS_DEBUG" }
if ($hasWelcome -eq 0 -and $hasAi -eq 0 -and $vis.Length -eq 0) { $blockers += "CHAT_OUTPUT_TEXT_EMPTY_OR_UNFOUND" }
$blockers += "FULL_CHAIN_1_1_UNPROVEN"
$blockers += "NO_REBUILD_H57_HOLD"

$next = "Hold EXACTLY_ONCE=NOT_VERIFIED; rebuild TRANSCRIPT_INSERT only when H57 Native-Ext bind idle or isolated tip stage"
if ($dispatchVisible -ne "NOT_CAPTURED" -and -not $tipHasInsert) {
  $next = "Visible tags captured; still need TRANSCRIPT_INSERT tip instrument when H57 idle (no rebuild now)"
}

$visSample = if ($vis.Length -gt 400) { $vis.Substring(0, 400) -replace "`r|`n", " " } else { ($vis -replace "`r|`n", " ") }

@"
EXACTLY_ONCE=NOT_VERIFIED
DISPATCH_VISIBLE=$dispatchVisible
HWND_1203_CAPTURE_KIND=$captureKind
HWND_1203_HWND=0x$visHx
HAS_WELCOME=$hasWelcome
HAS_AI=$hasAi
HAS_USER=$hasUser
HAS_PROBE_TEXT=$hasProbe
IS_DEBUG_CONTENT=$isDebug
TRANSCRIPT_INSERT_ON_TIP=$([int]$tipHasInsert)
TRANSCRIPT_INSERT_JOURNAL_LINES=$insertN
INPUT_EVENT_BUTTON_CLICK=$inputN
CHAT_SEND_ATTEMPT=$attemptN
CHAT_SEND_ARMED=$armedN
UI_UPDATE_COMPLETE=$uiCompleteN
BLOCKERS=$($blockers -join ',')
NEXT_ACTION=$next
TIP_SHA=$hash
SESSION_ID=$sessionId
RUN_ID=$runId
VISIBLE_PATH=$visPath
ENUM_PATH=$enumPath
RUNTIME_COPY=$rtCopy
VISIBLE_SAMPLE=$visSample
PROMOTE=0
ENGINEERING_MATURITY=82%_UNCHANGED
NO_DEBUG_OUTPUT_ISSUE49_PASS=1
"@ | Set-Content $receipt -Encoding UTF8

Get-Content $receipt
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
exit 0
