# GUI_TOP25_VALUATION_001 — FOUR_PANEL HWND probe
# PROMOTE=0 · NOT_RUN!=PASS · fail-closed on stale/missing EXE
$ErrorActionPreference = 'Continue'
$base = 'G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001'
$hwndDir = Join-Path $base 'hwnd'
New-Item -ItemType Directory -Force -Path $hwndDir | Out-Null
$exe = 'G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe'
$candDir = Split-Path $exe
$expectPath = Join-Path $base 'EXE_SHA256_EXPECT.txt'
$log = Join-Path $hwndDir 'RUNLOG.txt'
Set-Content $log ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content $log $line
  Write-Output $line
}
if (-not (Test-Path -LiteralPath $exe)) {
  WLog 'EXE_MISSING FAIL_CLOSED'
  "MAIN_HWND_PASS=0`nDISPOSITION=FAIL_CLOSED_EXE_MISSING`nPROMOTE=0" | Set-Content (Join-Path $hwndDir 'SUMMARY.txt')
  exit 2
}
$sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$mtime = (Get-Item -LiteralPath $exe).LastWriteTime
WLog "PRE_HASH=$sha"
WLog "EXE_MTIME=$mtime"
if ($mtime -le [datetime]'2026-10-31 23:59:59') {
  WLog 'EXE_STALE_OCT31 FAIL_CLOSED'
  @"
MAIN_HWND_PASS=0
EDITOR_HWND_PASS=0
TERMINAL_HWND_PASS=0
DEBUGGER_HWND_PASS=0
AGENT_CHAT_HWND_PASS=0
DISPOSITION=FAIL_CLOSED_EXE_STALE
EXE_SHA256=$sha
PROMOTE=0
"@ | Set-Content (Join-Path $hwndDir 'SUMMARY.txt')
  exit 3
}
if (Test-Path $expectPath) {
  $expect = (Get-Content $expectPath -Raw).Trim()
  if ($expect -and ($sha -ne $expect)) {
    WLog "SHA_MISMATCH expect=$expect FAIL_CLOSED"
    @"
MAIN_HWND_PASS=0
DISPOSITION=FAIL_CLOSED_SHA_DRIFT
EXE_SHA256=$sha
PROMOTE=0
"@ | Set-Content (Join-Path $hwndDir 'SUMMARY.txt')
    exit 2
  }
}
Get-Process -Name 'RawrXD-Win32IDE' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1
$cs = @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public class GuiFpHwnd {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetPropW(IntPtr h, string name);
  public static IntPtr FindByClass(uint pid, string clsWant) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, 256);
      if (sb.ToString() == clsWant) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static List<string> DumpTop(uint pid) {
    var rows = new List<string>();
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var c = new StringBuilder(256); var t = new StringBuilder(256);
      GetClassNameW(h, c, 256); GetWindowTextW(h, t, 256);
      rows.Add(string.Format("TOP hwnd=0x{0:X} vis={1} class={2} title={3}", h.ToInt64(), IsWindowVisible(h), c, t));
      return true;
    }, IntPtr.Zero);
    return rows;
  }
  public static List<string> DumpChildren(IntPtr parent) {
    var rows = new List<string>();
    if (parent == IntPtr.Zero) return rows;
    EnumChildWindows(parent, (h, l) => {
      var c = new StringBuilder(256); var t = new StringBuilder(128);
      GetClassNameW(h, c, 256); GetWindowTextW(h, t, 128);
      rows.Add(string.Format("CHILD hwnd=0x{0:X} vis={1} class={2} title={3}", h.ToInt64(), IsWindowVisible(h), c, t));
      return true;
    }, IntPtr.Zero);
    return rows;
  }
  public static bool MenuReady(IntPtr main) { return GetPropW(main, "RawrXD.MainMenuReady") != IntPtr.Zero; }
  public static int CountNeedle(IntPtr parent, string needle) {
    int n = 0;
    if (parent == IntPtr.Zero) return 0;
    EnumChildWindows(parent, (h, l) => {
      var c = new StringBuilder(256); var t = new StringBuilder(128);
      GetClassNameW(h, c, 256); GetWindowTextW(h, t, 128);
      var s = (c.ToString() + " " + t.ToString()).ToLowerInvariant();
      if (s.Contains(needle.ToLowerInvariant())) n++;
      return true;
    }, IntPtr.Zero);
    return n;
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.WorkingDirectory = $candDir
$psi.UseShellExecute = $false
foreach ($kv in @{
  RAWRXD_ALLOW_GPU = '1'
  RAWRXD_GUI = '1'
  RAWRXD_DISABLE_OLLAMA_FETCH = '1'
  LOCAL_ONLY = '1'
  LOCAL_ONLY_NO_OLLAMA = '1'
  RAWRXD_MODELS = 'G:\~dev\rawrxd\models'
  RAWRXD_SKIP_GPU_POWER_PROBE = '1'
  RAWRXD_FORCE_CPU_INFERENCE = '0'
}.GetEnumerator()) { $psi.EnvironmentVariables[$kv.Key] = $kv.Value }
$p = [System.Diagnostics.Process]::Start($psi)
WLog "SPAWN_PID=$($p.Id)"
$main = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) { WLog "EXITED_EARLY code=$($p.ExitCode)"; break }
  $main = [GuiFpHwnd]::FindByClass([uint32]$p.Id, 'RawrXD_IDE_MainWindow')
  if ($main -ne [IntPtr]::Zero -and [GuiFpHwnd]::MenuReady($main)) { break }
  Start-Sleep -Milliseconds 400
}
$menuReady = ($main -ne [IntPtr]::Zero) -and [GuiFpHwnd]::MenuReady($main)
WLog ("MAIN=0x{0:X} MENU_READY={1} ALIVE={2}" -f $main.ToInt64(), $menuReady, (-not $p.HasExited))
$tops = [GuiFpHwnd]::DumpTop([uint32]$p.Id)
$tops | Set-Content (Join-Path $hwndDir 'TOP_WINDOWS.txt')
$children = @()
if ($main -ne [IntPtr]::Zero) {
  $children = [GuiFpHwnd]::DumpChildren($main)
  $children | Set-Content (Join-Path $hwndDir 'CHILD_WINDOWS.txt')
}
$allText = ($tops + $children) -join "`n"
$editorHits = [GuiFpHwnd]::CountNeedle($main,'edit') + [GuiFpHwnd]::CountNeedle($main,'scintilla') + [GuiFpHwnd]::CountNeedle($main,'richedit')
$termHits = [GuiFpHwnd]::CountNeedle($main,'conpty') + [GuiFpHwnd]::CountNeedle($main,'terminal') + ([regex]::Matches($allText,'(?i)terminal|conpty|console')).Count
$debugHits = [GuiFpHwnd]::CountNeedle($main,'debug') + ([regex]::Matches($allText,'(?i)debug|breakpoint|watch')).Count
$agentHits = [GuiFpHwnd]::CountNeedle($main,'chat') + ([regex]::Matches($allText,'(?i)chat|agent|aiedit')).Count
$editorPass = [int]($menuReady -and ($editorHits -gt 0 -or $allText -match '(?i)Scintilla|RichEdit|RawrXD.*Edit|Editor'))
$termPass = [int]($menuReady -and ($termHits -gt 0 -or $allText -match '(?i)Terminal|ConPTY|Console'))
$debugPass = [int]($menuReady -and ($debugHits -gt 0 -or $allText -match '(?i)Debug|Breakpoint|Watch'))
$agentPass = [int]($menuReady -and ($agentHits -gt 0 -or $allText -match '(?i)Chat|Agent|AI '))
$mainPass = [int]$menuReady
Start-Sleep 2
if (-not $p.HasExited -and $main -ne [IntPtr]::Zero) {
  [GuiFpHwnd]::DumpTop([uint32]$p.Id) | Set-Content (Join-Path $hwndDir 'TOP_WINDOWS_AFTER.txt')
  [GuiFpHwnd]::DumpChildren($main) | Set-Content (Join-Path $hwndDir 'CHILD_WINDOWS_AFTER.txt')
}
if (-not $p.HasExited) { try { $p.Kill() } catch {}; Start-Sleep 1 }
$disposition = if ($mainPass -and $editorPass -and $termPass -and $debugPass -and $agentPass) { 'PASS_HWND_SURFACES' } else { 'FAIL_CLOSED_OR_PARTIAL' }
@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
EXE_SHA256=$sha
PID=$($p.Id)
MAIN_HWND_PASS=$mainPass
EDITOR_HWND_PASS=$editorPass
TERMINAL_HWND_PASS=$termPass
DEBUGGER_HWND_PASS=$debugPass
AGENT_CHAT_HWND_PASS=$agentPass
MENU_READY=$([int]$menuReady)
EDITOR_HITS=$editorHits
TERM_HITS=$termHits
DEBUG_HITS=$debugHits
AGENT_HITS=$agentHits
BP_STEP_VARS=NOT_RUN
AGENT_LOCAL_GPU_INFER=NOT_RUN
DISPOSITION=$disposition
PROMOTE=0
NOT_RUN_NE_PASS=1
"@ | Set-Content (Join-Path $hwndDir 'SUMMARY.txt')
WLog "DISPOSITION=$disposition main=$mainPass ed=$editorPass term=$termPass dbg=$debugPass agent=$agentPass"
if ($disposition -eq 'PASS_HWND_SURFACES') { exit 0 } else { exit 1 }
