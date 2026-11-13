# GUI_TOP25_VALUATION_001 — ConPTY product E2E + editor save smoke on tip 6754616E
# PROMOTE=0 · TIP_CLIMB=HOLD · NOT_RUN!=PASS · no invent PASS
$ErrorActionPreference = 'Continue'
$Root = 'G:\~dev\rawrxd'
$Base = Join-Path $Root 'evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001'
$OutDir = Join-Path $Base 'runtime_6754'
$ExpectSha = '6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431'
$Exe = Join-Path $Root 'build_win32ide_link001\bin\RawrXD-Win32IDE_tip_land_6754616E.exe'
$Alt = Join-Path $Root 'build_win32ide_link001\bin\RawrXD-Win32IDE.exe'
$IDM_PS = 4001
$IDM_FILE_OPEN = 1002
$IDM_FILE_SAVE = 1003
$WM_COMMAND = 0x0111
$WM_SETTEXT = 0x000C
$WM_GETTEXT = 0x000D
$WM_GETTEXTLENGTH = 0x000E

New-Item -ItemType Directory -Force -Path $OutDir,(Join-Path $OutDir 'logs') | Out-Null
$Log = Join-Path $OutDir 'RUNLOG.txt'
$Summary = Join-Path $OutDir 'SUMMARY.txt'
Set-Content $Log ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content $Log $line
  Write-Output $line
}

$cs = @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public class Gui6754 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetPropW(IntPtr h, string name);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint Msg, IntPtr wParam, IntPtr lParam, uint flags, uint timeout, out IntPtr result);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, 256);
      if (sb.ToString() == "RawrXD_IDE_MainWindow") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static bool MenuReady(IntPtr main) { return GetPropW(main, "RawrXD.MainMenuReady") != IntPtr.Zero; }
  public static int PostId(IntPtr h, int id) { return PostMessageW(h, 0x0111, (IntPtr)id, IntPtr.Zero) ? 1 : 0; }
  public static IntPtr FindBestEdit(IntPtr main) {
    IntPtr best = IntPtr.Zero; int bestArea = -1;
    if (main == IntPtr.Zero) return best;
    EnumChildWindows(main, (h, l) => {
      if (!IsWindowVisible(h)) return true;
      var cls = new StringBuilder(64); GetClassNameW(h, cls, 64);
      string c = cls.ToString();
      if (c != "Edit" && c != "RichEdit50W" && c != "RichEdit20W" && c != "Scintilla") return true;
      var r = new RECT(); GetWindowRect(h, out r);
      int area = Math.Max(0, r.Right - r.Left) * Math.Max(0, r.Bottom - r.Top);
      if (area > bestArea) { bestArea = area; best = h; }
      return true;
    }, IntPtr.Zero);
    return best;
  }
  [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
  public struct RECT { public int Left, Top, Right, Bottom; }
  public static string GetText(IntPtr h) {
    IntPtr lenPtr = SendMessageW(h, 0x000E, IntPtr.Zero, IntPtr.Zero);
    int len = lenPtr.ToInt32();
    if (len <= 0) return "";
    var sb = new StringBuilder(len + 8);
    SendMessageW(h, 0x000D, (IntPtr)(len + 1), sb);
    return sb.ToString();
  }
  public static int SetText(IntPtr h, string t) {
    SendMessageW(h, 0x000C, IntPtr.Zero, t);
    return 1;
  }
  public static int Ping(IntPtr h, uint ms, out int timedOut) {
    IntPtr r; IntPtr ok = SendMessageTimeoutW(h, 0, IntPtr.Zero, IntPtr.Zero, 0x0002, ms, out r);
    timedOut = (ok == IntPtr.Zero) ? 1 : 0; return (ok != IntPtr.Zero) ? 1 : 0;
  }
  public static int CountNeedle(IntPtr main, string needle) {
    int n = 0; if (main == IntPtr.Zero) return 0;
    EnumChildWindows(main, (h, l) => {
      var t = new StringBuilder(256); GetWindowTextW(h, t, 256);
      var c = new StringBuilder(64); GetClassNameW(h, c, 64);
      string blob = (t.ToString() + " " + c.ToString()).ToLowerInvariant();
      if (blob.Contains(needle.ToLowerInvariant())) n++;
      return true;
    }, IntPtr.Zero);
    return n;
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

WLog 'START harness_conpty_editor_6754 PROMOTE=0'
if (-not (Test-Path -LiteralPath $Exe)) {
  if (Test-Path -LiteralPath $Alt) { $Exe = $Alt; WLog "FALLBACK_ALT_EXE=$Exe" }
}
if (-not (Test-Path -LiteralPath $Exe)) {
  WLog 'EXE_MISSING FAIL_CLOSED'
  "CONPTY_PRODUCT_E2E=FAIL_CLOSED`nEDITOR_SAVE_E2E=FAIL_CLOSED`nEXE_MISSING=1`nPROMOTE=0" | Set-Content $Summary
  exit 2
}
$sha = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash
$len = (Get-Item -LiteralPath $Exe).Length
WLog "EXE=$Exe SHA=$sha LEN=$len"
if ($sha -ne $ExpectSha) {
  WLog "SHA_MISMATCH expect=$ExpectSha FAIL_CLOSED"
  @"
CONPTY_PRODUCT_E2E=FAIL_CLOSED_SHA_DRIFT
EDITOR_SAVE_E2E=FAIL_CLOSED_SHA_DRIFT
EXE_SHA256=$sha
PROMOTE=0
"@ | Set-Content $Summary
  exit 3
}
$sha | Set-Content (Join-Path $OutDir 'EXE_SHA256.txt')

# --- A) terminal_gate v5 (ConPTY compile+run logic harness; product-adjacent) ---
$tg = Join-Path $Root 'evidence\FOUR_PANEL_COMPLETION_001\bin\terminal_gate.exe'
$tgOut = Join-Path $OutDir 'logs\terminal_gate_v5.out.txt'
$tgErr = Join-Path $OutDir 'logs\terminal_gate_v5.err.txt'
$tgPass = 0
if (Test-Path $tg) {
  $tgSha = (Get-FileHash $tg -Algorithm SHA256).Hash
  WLog "TERMINAL_GATE sha=$tgSha"
  $pTg = Start-Process -FilePath $tg -WorkingDirectory (Split-Path $tg) -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $tgOut -RedirectStandardError $tgErr
  $tgText = Get-Content $tgOut -Raw -ErrorAction SilentlyContinue
  if ($tgText -match 'TERMINAL=PASS' -or ($tgText -match 'fail_count=0' -and $tgText -match 'compile\+run via ConPTY')) {
    $tgPass = 1
  }
  WLog "TERMINAL_GATE_PASS=$tgPass EXIT=$($pTg.ExitCode)"
} else {
  WLog 'TERMINAL_GATE_MISSING'
}

# --- B) IDE product ConPTY + editor save ---
Get-Process -Name 'RawrXD-Win32IDE' -ErrorAction SilentlyContinue | ForEach-Object {
  WLog "KILL_PRIOR pid=$($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 1

$fixtureDir = Join-Path $OutDir 'fixture'
New-Item -ItemType Directory -Force -Path $fixtureDir | Out-Null
$tracked = Join-Path $fixtureDir 'tracked_save.txt'
$marker = 'GUI_TOP25_EDITOR_SAVE_' + (Get-Date -Format 'yyyyMMddHHmmss')
Set-Content -Path $tracked -Value ("v0`r`n") -Encoding ASCII -NoNewline

$gateStream = Join-Path $Root 'evidence\CONPTY_STREAM_OWNER_001\GATE_STREAM.txt'
$gateTerm = Join-Path $Root 'evidence\SHELLLAYOUT_PHASE5_001\GATE_TERMINAL.txt'
foreach ($g in @($gateStream, $gateTerm)) {
  if (Test-Path $g) { Remove-Item $g -Force -ErrorAction SilentlyContinue }
}

$env:RAWRXD_GUI = '1'
$env:RAWRXD_SHELL_LAYOUT_PHASE = '5'
$env:LOCAL_ONLY = '1'
$env:RAWRXD_P1_CMD_DIAG = '1'
$env:RAWRXD_SKIP_DEFERRED_MODEL_LOAD = '1'
Remove-Item Env:RAWRXD_HEADLESS -ErrorAction SilentlyContinue

$wd = Split-Path $Exe
$stdout = Join-Path $OutDir 'logs\ide_gui.out.txt'
$stderr = Join-Path $OutDir 'logs\ide_gui.err.txt'
WLog 'LAUNCH_IDE GUI ConPTY+editor'
# No redirect: Win32 GUI often hangs/dies with redirected std handles under ConPTY exercise.
$p = Start-Process -FilePath $Exe -WorkingDirectory $Root -PassThru -WindowStyle Normal
WLog "PID=$($p.Id)"

$hwnd = [IntPtr]::Zero
$menuReady = $false
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { WLog ("EARLY_EXIT code={0}" -f $p.ExitCode); break }
  $hwnd = [Gui6754]::FindMain([uint32]$p.Id)
  if ($hwnd -ne [IntPtr]::Zero) {
    $menuReady = [Gui6754]::MenuReady($hwnd)
    if ($menuReady) { break }
  }
  Start-Sleep -Milliseconds 250
}
$hwndHex = if ($hwnd -ne [IntPtr]::Zero) { ('0x{0:X}' -f $hwnd.ToInt64()) } else { '0' }
WLog "MAIN_HWND=$hwndHex MENU_READY=$menuReady"

$conptyProduct = 'NOT_RUN'
$editorSave = 'NOT_RUN'
$editorSetText = 0
$post4001 = 0
$gateStreamHit = 0
$psChild = 0
$ptyChild = 0
$termHits = 0

if ($hwnd -ne [IntPtr]::Zero -and $menuReady -and -not $p.HasExited) {
  # Editor SETTEXT smoke first (largest Edit)
  $edit = [Gui6754]::FindBestEdit($hwnd)
  WLog ("EDIT_HWND=0x{0:X}" -f $edit.ToInt64())
  if ($edit -ne [IntPtr]::Zero) {
    [void][Gui6754]::SetText($edit, $marker)
    Start-Sleep -Milliseconds 200
    $got = [Gui6754]::GetText($edit)
    if ($got -like ("*{0}*" -f $marker)) { $editorSetText = 1 }
    WLog "EDITOR_SETTEXT=$editorSetText LEN=$($got.Length)"
    # Save: post Ctrl+S command; requires currentFile — try Open dialog then Save
    [void][Gui6754]::SetForegroundWindow($hwnd)
    $postOpen = [Gui6754]::PostId($hwnd, $IDM_FILE_OPEN)
    WLog "POST_OPEN=$postOpen"
    Start-Sleep 1
    # Best-effort common-dialog: type path + Enter via SendKeys
    try {
      Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
      [System.Windows.Forms.SendKeys]::SendWait($tracked)
      Start-Sleep -Milliseconds 400
      [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
      Start-Sleep 1
      [void][Gui6754]::SetText($edit, ($marker + "`r`nv1_edited`r`n"))
      Start-Sleep -Milliseconds 300
      $postSave = [Gui6754]::PostId($hwnd, $IDM_FILE_SAVE)
      WLog "POST_SAVE=$postSave"
      Start-Sleep 2
      # SaveAs dialog may appear if no current file — send path+enter again
      if ((Get-Content $tracked -Raw -ErrorAction SilentlyContinue) -notmatch 'v1_edited') {
        [System.Windows.Forms.SendKeys]::SendWait($tracked)
        Start-Sleep -Milliseconds 300
        [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
        Start-Sleep 2
      }
    } catch {
      WLog ("SENDKEYS_ERR={0}" -f $_.Exception.Message)
    }
    $disk = Get-Content $tracked -Raw -ErrorAction SilentlyContinue
    if ($disk -match [regex]::Escape($marker) -or $disk -match 'v1_edited') {
      $editorSave = 'PASS'
    } else {
      $editorSave = 'FAIL_CLOSED'
    }
    WLog "EDITOR_SAVE_DISK=$editorSave"
    Copy-Item $tracked (Join-Path $OutDir 'logs\tracked_after.txt') -Force -ErrorAction SilentlyContinue
  } else {
    $editorSave = 'FAIL_CLOSED_NO_EDIT'
  }

  # ConPTY product: IDM 4001
  $kidsBefore = [Gui6754]::CountNeedle($hwnd, 'terminal') + [Gui6754]::CountNeedle($hwnd, 'conpty')
  $post4001 = [Gui6754]::PostId($hwnd, $IDM_PS)
  WLog "POST_4001=$post4001"
  $waitEnd = (Get-Date).AddSeconds(12)
  while ((Get-Date) -lt $waitEnd) {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { WLog ("EXIT_AFTER_4001 code={0}" -f $p.ExitCode); break }
    if (Test-Path $gateStream) { $gateStreamHit = 1; break }
    Start-Sleep -Milliseconds 400
  }
  $termHits = [Gui6754]::CountNeedle($hwnd, 'terminal') + [Gui6754]::CountNeedle($hwnd, 'conpty') + [Gui6754]::CountNeedle($hwnd, 'powershell')
  $psChild = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ParentProcessId -eq $p.Id -and $_.Name -match '^(pwsh|powershell)\.exe$' }).Count
  $ptyChild = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ParentProcessId -eq $p.Id -and $_.Name -match '^(OpenConsole|conhost|WindowsTerminal)\.exe$' }).Count
  if (Test-Path $gateStream) {
    $gateStreamHit = 1
    Copy-Item $gateStream (Join-Path $OutDir 'logs\GATE_STREAM.txt') -Force
  }
  if (Test-Path $gateTerm) {
    Copy-Item $gateTerm (Join-Path $OutDir 'logs\GATE_TERMINAL.txt') -Force
  }
  $to = 0; $ping = 0
  if (-not $p.HasExited) { $ping = [Gui6754]::Ping($hwnd, 2000, [ref]$to) }
  WLog "GATE_STREAM=$gateStreamHit PS_CHILD=$psChild PTY_CHILD=$ptyChild TERM_HITS=$termHits PING=$ping"

  # Product ConPTY PASS requires: post4001 + (GATE_STREAM write OR pty/ps child OR termHits growth) + process alive
  if ($post4001 -eq 1 -and -not $p.HasExited -and ($gateStreamHit -eq 1 -or $psChild -gt 0 -or $ptyChild -gt 0 -or $termHits -gt $kidsBefore)) {
    $conptyProduct = 'PASS'
  } elseif ($post4001 -eq 1 -and -not $p.HasExited -and $termHits -gt 0 -and $ping -eq 1) {
    # HWND terminal surface exercised; stream gate absent → PARTIAL (not invent full PASS)
    $conptyProduct = 'PARTIAL_HWND_NO_STREAM_GATE'
  } elseif ($p.HasExited) {
    $conptyProduct = 'FAIL_CLOSED_EXIT'
  } else {
    $conptyProduct = 'FAIL_CLOSED'
  }
} else {
  $conptyProduct = 'FAIL_CLOSED_NO_HWND'
  if ($editorSave -eq 'NOT_RUN') { $editorSave = 'FAIL_CLOSED_NO_HWND' }
}

# Cleanup IDE
if (-not $p.HasExited) {
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep 1
}

@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
EXE=$Exe
EXE_SHA256=$sha
EXE_LEN=$len
PID=$($p.Id)
MAIN_HWND=$hwndHex
MENU_READY=$([int]$menuReady)
TERMINAL_GATE_V5_PASS=$tgPass
CONPTY_PRODUCT_E2E=$conptyProduct
POST_4001=$post4001
GATE_STREAM_HIT=$gateStreamHit
PS_CHILD=$psChild
PTY_CHILD=$ptyChild
TERM_HITS=$termHits
EDITOR_SETTEXT=$editorSetText
EDITOR_SAVE_E2E=$editorSave
EDITOR_MARKER=$marker
BP_STEP_VARS=NOT_RUN
PROMOTE=0
TIP_CLIMB=HOLD
NOT_RUN_NE_PASS=1
"@ | Set-Content $Summary
WLog "SUMMARY written CONPTY=$conptyProduct EDITOR_SAVE=$editorSave"
Get-Content $Summary
exit 0
