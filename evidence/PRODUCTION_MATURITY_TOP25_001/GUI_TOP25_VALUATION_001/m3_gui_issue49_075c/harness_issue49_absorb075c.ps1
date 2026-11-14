# M3 follow-on: Issue #49 AGENT_RESULT=5 on absorb075c E7189EA8
# Stage tip CLI SHA 15A119 only (reject 30DCB4). PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0
$ErrorActionPreference = 'Continue'
$outDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$base = 'G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001'
$log = Join-Path $outDir 'RUNLOG.txt'
Set-Content $log ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content $log $line
  Write-Output $line
}

$expect = 'E7189EA8D67C8DACD54F7DB3FAA267A2311DD09688AFD3F8E42D600F99A082A7'
$tipCli = '15A119D148572A4B3011AA9A8AFFE605F8FF40D64B7BF83673ECC10A9393C967'
$rejectAssist = '30DCB4B12DCA0F13542C14CCC6C4038E70DBFE2555DE65AB005093A1FF60F24D'
$exe = Join-Path $base 'clean_link\RawrXD-Win32IDE_absorb075c.exe'
$stagedRawr = Join-Path $base 'clean_link\rawr.exe'
$ws = Join-Path $outDir 'ws'
New-Item -ItemType Directory -Force -Path $ws | Out-Null
Set-Content (Join-Path $ws 'note.txt') "note_pre`n"
Set-Content (Join-Path $ws 'bug.cpp') "#include <cstdio>`nint main(){ std::puts(`"BUG`"); return 0; }`n"

$sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
if ($sha -ne $expect) { throw "GUI_SHA_DRIFT $sha" }
$stagedSha = (Get-FileHash -LiteralPath $stagedRawr -Algorithm SHA256).Hash
if ($stagedSha -eq $rejectAssist) { throw "REJECT_STAGED_30DCB4" }
if ($stagedSha -ne $tipCli) { throw "STAGED_NOT_TIP_15A119 $stagedSha" }
WLog "GUI_PIN_OK SHA=$sha STAGED_RAWR=$stagedSha"

$cs = @'
using System; using System.Text; using System.Runtime.InteropServices;
public class M3Issue49 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetPropW(IntPtr h, string name);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_SETTEXT = 0x000C;
  public const uint BM_CLICK = 0x00F5;
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      string c = cls.ToString();
      if (c == "RawrXD_IDE_MainWindow" || c == "RawrXD_IDE_Window") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static bool MenuReady(IntPtr main) { return GetPropW(main, "RawrXD.MainMenuReady") != IntPtr.Zero; }
  public static int PostId(IntPtr h, int id) {
    if (h == IntPtr.Zero || !IsWindow(h)) return 0;
    return PostMessageW(h, WM_COMMAND, (IntPtr)id, IntPtr.Zero) ? 1 : 0;
  }
  public static IntPtr FindTitlePid(uint pid, string titleNeedle) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var t = new StringBuilder(256);
      GetWindowTextW(h, t, 256);
      if (t.ToString().IndexOf(titleNeedle, StringComparison.OrdinalIgnoreCase) >= 0) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindChildClass(IntPtr parent, string clsWant) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, (h, l) => {
      var c = new StringBuilder(64);
      GetClassNameW(h, c, 64);
      if (string.Equals(c.ToString(), clsWant, StringComparison.OrdinalIgnoreCase)) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindChildTitle(IntPtr parent, string titleNeedle) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, (h, l) => {
      var t = new StringBuilder(128);
      GetWindowTextW(h, t, 128);
      if (t.ToString().IndexOf(titleNeedle, StringComparison.OrdinalIgnoreCase) >= 0) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static int FillBoundedDialog(uint pid, string prompt) {
    IntPtr dlg = FindTitlePid(pid, "Bounded Agent Loop");
    if (dlg == IntPtr.Zero) return 0;
    IntPtr edit = FindChildClass(dlg, "Edit");
    if (edit == IntPtr.Zero) return 0;
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, prompt);
    IntPtr ok = FindChildTitle(dlg, "Run Agent");
    if (ok == IntPtr.Zero) ok = FindChildTitle(dlg, "OK");
    if (ok == IntPtr.Zero) return 0;
    SetForegroundWindow(dlg);
    SendMessageW(ok, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    return 1;
  }
  public static int DismissMessageBox(uint pid) {
    IntPtr mb = FindTitlePid(pid, "Agent Error");
    if (mb == IntPtr.Zero) mb = FindTitlePid(pid, "Error");
    if (mb == IntPtr.Zero) return 0;
    IntPtr ok = FindChildTitle(mb, "OK");
    if (ok != IntPtr.Zero) SendMessageW(ok, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    return 1;
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

foreach ($p in @(
  'F:\rawrxd\evidence\TOP25_C14_DIFF.log',
  'F:\rawrxd\evidence\TOP25_C11_TOOLS.log',
  (Join-Path $base 'logs\TOP25_C14_DIFF.log')
)) { if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue } }

Get-Process -Name 'RawrXD-Win32IDE*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.WorkingDirectory = (Split-Path $exe)
$psi.UseShellExecute = $false
$psi.Arguments = "--no-server `"$ws`""
foreach ($kv in @{
  SKIP_DEFERRED_MODEL_LOAD = '1'
  RAWRXD_ALLOW_GPU = '0'
  RAWRXD_GUI = '1'
  RAWRXD_DISABLE_OLLAMA_FETCH = '1'
  LOCAL_ONLY = '1'
  LOCAL_ONLY_NO_OLLAMA = '1'
  RAWRXD_SKIP_GPU_POWER_PROBE = '1'
  RAWRXD_CLI_PATH = $stagedRawr
}.GetEnumerator()) { $psi.EnvironmentVariables[$kv.Key] = $kv.Value }

$sw = [Diagnostics.Stopwatch]::StartNew()
$proc = [Diagnostics.Process]::Start($psi)
WLog "SPAWN_PID=$($proc.Id) EXE=$exe"
$main = [IntPtr]::Zero
$ready = $false
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog "EXITED_EARLY code=$($proc.ExitCode)"; break }
  $main = [M3Issue49]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [M3Issue49]::MenuReady($main)) { $ready = $true; break }
  Start-Sleep -Milliseconds 400
}
WLog ("MAIN=0x{0:X} MENU_READY={1} WALL_MS={2}" -f $main.ToInt64(), [int]$ready, $sw.ElapsedMilliseconds)

$result = [ordered]@{
  EXE = $exe
  EXE_SHA256 = $sha
  STAGED_RAWR_SHA256 = $stagedSha
  MENU_READY = [int]$ready
  DEEP2_AGENTIC_LOOP = 'ABSENT'
  POST_4120 = 0
  POST_4100 = 0
  POST_14003 = 0
  POST_9618 = 0
  BOUNDED_DIALOG_FILLED = 0
  APPLY = 0
  AGENTIC_RR = 0
  AGENT_RESULT5 = 0
  BUILD_TEST_CRUMB = 0
  GUI_EBT_FULL = 0
}

if ($ready) {
  $main = [M3Issue49]::FindMain([uint32]$proc.Id)
  $result.POST_4120 = [M3Issue49]::PostId($main, 4120)
  WLog "POST_4120=$($result.POST_4120)"
  Start-Sleep 1
  $prompt = 'Read note.txt and bug.cpp; patch bug.cpp to print AGENT_RESULT=5; build and run.'
  $fillEnd = (Get-Date).AddSeconds(12)
  while ((Get-Date) -lt $fillEnd) {
    if ([M3Issue49]::FillBoundedDialog([uint32]$proc.Id, $prompt) -eq 1) {
      $result.BOUNDED_DIALOG_FILLED = 1
      break
    }
    Start-Sleep -Milliseconds 250
  }
  WLog "BOUNDED_DIALOG_FILLED=$($result.BOUNDED_DIALOG_FILLED)"
  Start-Sleep 20
  [void][M3Issue49]::DismissMessageBox([uint32]$proc.Id)

  $main = [M3Issue49]::FindMain([uint32]$proc.Id)
  $result.POST_4100 = [M3Issue49]::PostId($main, 4100)
  WLog "POST_4100=$($result.POST_4100)"
  Start-Sleep 3
  [void][M3Issue49]::DismissMessageBox([uint32]$proc.Id)

  $main = [M3Issue49]::FindMain([uint32]$proc.Id)
  $result.POST_14003 = [M3Issue49]::PostId($main, 14003)
  WLog "POST_14003=$($result.POST_14003)"
  Start-Sleep 3

  $main = [M3Issue49]::FindMain([uint32]$proc.Id)
  $result.POST_9618 = [M3Issue49]::PostId($main, 9618)
  WLog "POST_9618=$($result.POST_9618)"
  Start-Sleep 8

  foreach ($lp in @(
    (Join-Path $base 'logs\TOP25_C14_DIFF.log'),
    'F:\rawrxd\evidence\TOP25_C14_DIFF.log'
  )) {
    if (Test-Path $lp) {
      Copy-Item $lp (Join-Path $outDir 'TOP25_C14_DIFF.log') -Force
      $body = Get-Content $lp -Raw -ErrorAction SilentlyContinue
      if ($body -match 'action=APPLY') { $result.APPLY = 1 }
      if ($body -match 'RUNTIME_REACHED=1') { $result.AGENTIC_RR = 1 }
    }
  }

  $scan = @()
  Get-ChildItem $ws -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $scan += $_.FullName }
  $scan += @('F:\rawrxd\evidence\TOP25_C11_TOOLS.log', (Join-Path $base 'logs\TOP25_C11_TOOLS.log'))
  foreach ($f in $scan) {
    if (-not (Test-Path $f)) { continue }
    try {
      $t = Get-Content $f -Raw -ErrorAction SilentlyContinue
      if ($t -match 'AGENT_RESULT=5') { $result.AGENT_RESULT5 = 1 }
      if ($t -match 'BUILD_COMPLETED=1|RAWR_AGENT_BUILD_OK|OLLAMA_AGENT_BUILD_TEST PASS') { $result.BUILD_TEST_CRUMB = 1 }
    } catch {}
  }
  if (Test-Path (Join-Path $ws 'bug.exe')) { $result.BUILD_TEST_CRUMB = 1 }
}

$result.GUI_EBT_FULL = [int](($result.AGENT_RESULT5 -eq 1) -and ($result.BUILD_TEST_CRUMB -eq 1))
WLog ("AGENT_RESULT5={0} BUILD_TEST_CRUMB={1} GUI_EBT_FULL={2}" -f $result.AGENT_RESULT5, $result.BUILD_TEST_CRUMB, $result.GUI_EBT_FULL)

try { if (-not $proc.HasExited) { $proc.Kill() } } catch {}
Start-Sleep 1

$meta = @"
ID=m3_gui_issue49_075c
EXE=$exe
EXE_SHA256=$sha
STAGED_RAWR_SHA256=$stagedSha
MENU_READY=$($result.MENU_READY)
POST_4120=$($result.POST_4120)
BOUNDED_DIALOG_FILLED=$($result.BOUNDED_DIALOG_FILLED)
POST_4100=$($result.POST_4100)
POST_14003=$($result.POST_14003)
POST_9618=$($result.POST_9618)
APPLY=$($result.APPLY)
AGENTIC_RR=$($result.AGENTIC_RR)
AGENT_RESULT5=$($result.AGENT_RESULT5)
BUILD_TEST_CRUMB=$($result.BUILD_TEST_CRUMB)
GUI_EBT_FULL=$($result.GUI_EBT_FULL)
DEEP2_AGENTIC_LOOP=ABSENT
TIP_6754616E_THRASHED=0
PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0 NOT_RUN!=PASS
ASOF=$((Get-Date).ToString('o'))
"@
Set-Content (Join-Path $outDir 'run.meta.txt') $meta
Set-Content (Join-Path $outDir 'RESULT.txt') @"
AGENT_RESULT5=$($result.AGENT_RESULT5)
BUILD_TEST_CRUMB=$($result.BUILD_TEST_CRUMB)
GUI_EBT_FULL=$($result.GUI_EBT_FULL)
STAGED_RAWR_SHA256=$stagedSha
"@
WLog "WROTE run.meta.txt"
$result.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
