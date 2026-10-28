# CONPTY_STREAM_OWNER_RUNTIME_748B_001
# Tip 748B GUI: ShellLayout PHASE=5 chrome + IDM 4001 ConPTY start.
# PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 FAIL_CLOSED
# ABSORB GhostText = NOT_AUTHORIZED (no tip rebuild).
$ErrorActionPreference = "Continue"
$Root = "G:\~dev\rawrxd"
$OutDir = Join-Path $Root "evidence\CONPTY_STREAM_OWNER_RUNTIME_748B_001"
$TipExe = Join-Path $Root "evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$ExpectSha = "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145"
$IDM_TERMINAL_POWERSHELL = 4001
$WM_COMMAND = 0x0111
$WM_SIZE = 0x0005
$ClassName = "RawrXD_IDE_MainWindow"

New-Item -ItemType Directory -Force -Path (Join-Path $OutDir "logs") | Out-Null
$Log = Join-Path $OutDir "RUNLOG.txt"
$Stdout = Join-Path $OutDir "logs\tip_stdout.log"
$Stderr = Join-Path $OutDir "logs\tip_stderr.log"
$Summary = Join-Path $OutDir "SUMMARY.txt"
Set-Content -Path $Log -Value ""

function WLog([string]$m) {
  $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"), $m
  Add-Content -Path $Log -Value $line
  Write-Output $line
}

$cs = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class TipConPtyPhase5 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  public struct RECT { public int Left, Top, Right, Bottom; }
  public static IntPtr FindMainByPid(uint pid, string className) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      if (cls.ToString() == className) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static int CountChildren(IntPtr main) {
    int n = 0;
    if (main == IntPtr.Zero) return 0;
    EnumChildWindows(main, (h, l) => { n++; return true; }, IntPtr.Zero);
    return n;
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

WLog "START CONPTY_STREAM_OWNER_RUNTIME_748B_001"
WLog "PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 ABSORB_GHOSTTEXT=NOT_AUTHORIZED"

# Clear prior fail-closed gates from previous runs (cwd-relative writes).
$gateTerm = Join-Path $Root "evidence\SHELLLAYOUT_PHASE5_001\GATE_TERMINAL.txt"
$gateStream = Join-Path $Root "evidence\CONPTY_STREAM_OWNER_001\GATE_STREAM.txt"
$chromeVis = Join-Path $Root "evidence\P1_UI_SHELL_LAYOUT_001\CHROME_VIS_TRANSITION.txt"
foreach ($g in @($gateTerm, $gateStream)) {
  if (Test-Path $g) {
    WLog "CLEAR_PRIOR_GATE $g"
    Remove-Item $g -Force -ErrorAction SilentlyContinue
  }
}
$chromeBefore = $false
if (Test-Path $chromeVis) {
  $chromeBefore = $true
  Copy-Item $chromeVis (Join-Path $OutDir "logs\CHROME_VIS_BEFORE.txt") -Force
}

if (-not (Test-Path $TipExe)) {
  WLog "FAIL_CLOSED: tip exe missing"
  @"
TIP_EXE_MISSING=1
RUNTIME_PASS=0
RELINK_CLOSED=0
PROMOTE=0
"@ | Set-Content $Summary
  exit 2
}

$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Set-Content (Join-Path $OutDir "sha.txt") "TIP_SHA=$sha"
WLog "TIP_SHA=$sha"
$shaMatch = ($sha -eq $ExpectSha)
WLog "SHA_MATCH_748B=$shaMatch"
if (-not $shaMatch) {
  WLog 'FAIL_CLOSED: tip SHA != freeze 748B - refuse invent RELINK close'
}

# Binary presence (SOURCE_WIRED absorb into tip) - not RUNTIME.
$bytes = [IO.File]::ReadAllBytes($TipExe)
$text = [Text.Encoding]::ASCII.GetString($bytes)
$bin = @{
  CreatePseudoConsole_absent = $text.Contains("CreatePseudoConsole_absent")
  CreatePseudoConsole_failed = $text.Contains("CreatePseudoConsole_failed")
  CONPTY_STREAM_OWNER_001 = $text.Contains("CONPTY_STREAM_OWNER_001")
  SHELLLAYOUT_PHASE5_001 = $text.Contains("SHELLLAYOUT_PHASE5_001")
  null_hwnd = $text.Contains("null_hwnd")
  dead_hwnd = $text.Contains("dead_hwnd")
  getPowerShellPanel = $text.Contains("getPowerShellPanel")
}
WLog ("BIN_WIRE conpty={0} phase5={1} panel={2}" -f `
  ($bin.CreatePseudoConsole_absent -and $bin.CONPTY_STREAM_OWNER_001), `
  ($bin.SHELLLAYOUT_PHASE5_001 -and $bin.null_hwnd), `
  $bin.getPowerShellPanel)
$relinkClosed = ($shaMatch -and $bin.CreatePseudoConsole_absent -and $bin.CONPTY_STREAM_OWNER_001 `
  -and $bin.SHELLLAYOUT_PHASE5_001 -and $bin.null_hwnd -and $bin.getPowerShellPanel)
WLog "RELINK_CLOSED_VS_748B=$relinkClosed"

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  WLog "KILL_PRIOR pid=$($_.Id)"
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

$env:RAWRXD_SHELL_LAYOUT_REBUILD = "1"
$env:RAWRXD_SHELL_LAYOUT_PHASE = "5"
$env:RAWRXD_GUI = "1"
Remove-Item Env:RAWRXD_HEADLESS -ErrorAction SilentlyContinue

# Avoid stdout/stderr redirect — can race with locked log files and GUI startup.
WLog "LAUNCH tip GUI cwd=$Root PHASE=5 REBUILD=1 (no std redirect)"
$p = Start-Process -FilePath $TipExe -WorkingDirectory $Root `
  -PassThru -WindowStyle Normal
WLog "PID=$($p.Id)"
# Best-effort capture via DebugView-less fallback: tip may still write gates to cwd.

$hwnd = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) {
    WLog ("FAIL_CLOSED: early exit code={0}" -f $p.ExitCode)
    break
  }
  $hwnd = [TipConPtyPhase5]::FindMainByPid([uint32]$p.Id, $ClassName)
  if ($hwnd -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 250
}

WLog ("MAIN_HWND=0x{0:X}" -f $hwnd.ToInt64())
$childBefore = [TipConPtyPhase5]::CountChildren($hwnd)
WLog "CHILD_COUNT_BEFORE=$childBefore"

$postOk = $false
$psChild = 0
$cmdChildBefore = 0
$cmdChildAfter = 0
$psChildBefore = 0
$ptyBefore = 0
$ptyAfter = 0
$newPty = 0
$gateTermHit = 0
$gateStreamHit = 0
$chromeHit = 0
$streamIo = 0
$conptyStartWitness = 0
$newPsChild = 0

function Count-TipShells([int]$tipPid) {
  $ps = 0; $cmd = 0; $pty = 0
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.ParentProcessId -ne $tipPid) { return }
    $n = $_.Name
    if ($n -match '^(pwsh|powershell)\.exe$') { $ps++ }
    elseif ($n -eq 'cmd.exe') { $cmd++ }
    elseif ($n -match '^(OpenConsole|conhost|WindowsTerminal)\.exe$') { $pty++ }
  }
  return @{ Ps = $ps; Cmd = $cmd; Pty = $pty }
}

if ($hwnd -eq [IntPtr]::Zero) {
  WLog "WINDOW_NOT_FOUND RUNTIME=NOT_RUN"
} else {
  $before = Count-TipShells $p.Id
  $psChildBefore = [int]$before.Ps
  $cmdChildBefore = [int]$before.Cmd
  $ptyBefore = [int]$before.Pty
  WLog ("SHELL_BEFORE ps={0} cmd={1} ptyHost={2}" -f $psChildBefore, $cmdChildBefore, $ptyBefore)

  # Force layout pass (WM_SIZE) so PHASE=5 LayoutIDE can MoveHwnd terminal.
  $r = New-Object TipConPtyPhase5+RECT
  [void][TipConPtyPhase5]::GetClientRect($hwnd, [ref]$r)
  $w = [Math]::Max(1, $r.Right - $r.Left)
  $h = [Math]::Max(1, $r.Bottom - $r.Top)
  $lp = [IntPtr](($h -shl 16) -bor ($w -band 0xFFFF))
  $szOk = [TipConPtyPhase5]::PostMessageW($hwnd, [uint32]$WM_SIZE, [IntPtr]::Zero, $lp)
  WLog ("PostMessageW WM_SIZE ok={0} client={1}x{2}" -f $szOk, $w, $h)
  Start-Sleep -Seconds 2

  # Ensure terminal view then start PowerShell (4001).
  $viewTerm = [TipConPtyPhase5]::PostMessageW($hwnd, [uint32]$WM_COMMAND, [IntPtr]2029, [IntPtr]::Zero)
  WLog ("PostMessageW WM_COMMAND 2029 VIEW_TERMINAL ok={0}" -f $viewTerm)
  Start-Sleep -Seconds 1

  $postOk = [TipConPtyPhase5]::PostMessageW($hwnd, [uint32]$WM_COMMAND, `
    [IntPtr]$IDM_TERMINAL_POWERSHELL, [IntPtr]::Zero)
  WLog ("PostMessageW WM_COMMAND 4001 ok={0}" -f $postOk)
  Start-Sleep -Seconds 12

  $after = Count-TipShells $p.Id
  $psChild = [int]$after.Ps
  $cmdChildAfter = [int]$after.Cmd
  $ptyAfter = [int]$after.Pty
  $newPsChild = [Math]::Max(0, $psChild - $psChildBefore)
  $newPty = [Math]::Max(0, $ptyAfter - $ptyBefore)
  WLog ("SHELL_AFTER ps={0} cmd={1} ptyHost={2} NEW_PS={3} NEW_PTY={4}" -f `
    $psChild, $cmdChildAfter, $ptyAfter, $newPsChild, $newPty)
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.ParentProcessId -eq $p.Id -and $_.Name -match '^(pwsh|powershell|cmd|OpenConsole|conhost)\.exe$'
  } | ForEach-Object {
    WLog ("CHILD name={0} pid={1}" -f $_.Name, $_.ProcessId)
  }
  # Descendants: powershell may parent under conhost/OpenConsole under tip.
  $descPs = 0
  Get-CimInstance Win32_Process -Filter "Name='pwsh.exe' OR Name='powershell.exe'" `
    -ErrorAction SilentlyContinue | ForEach-Object {
    $walk = $_
    $guard = 0
    while ($walk -and $guard -lt 8) {
      if ($walk.ParentProcessId -eq $p.Id) { $descPs++; break }
      $walk = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $walk.ParentProcessId) `
        -ErrorAction SilentlyContinue
      $guard++
    }
  }
  if ($descPs -gt 0) {
    WLog ("DESCENDANT_PS count={0}" -f $descPs)
    if ($newPsChild -eq 0) { $newPsChild = $descPs }
  }

  if (Test-Path $gateTerm) {
    $gateTermHit = 1
    Copy-Item $gateTerm (Join-Path $OutDir "logs\GATE_TERMINAL.txt") -Force
    WLog "GATE_TERMINAL FIRED (phase5 fail-closed)"
  }
  if (Test-Path $gateStream) {
    $gateStreamHit = 1
    Copy-Item $gateStream (Join-Path $OutDir "logs\GATE_STREAM.txt") -Force
    WLog "GATE_STREAM FIRED (conpty fail-closed)"
  }
  if (Test-Path $chromeVis) {
    $chromeHit = 1
    Copy-Item $chromeVis (Join-Path $OutDir "logs\CHROME_VIS_AFTER.txt") -Force
    $cv = Get-Content $chromeVis -Raw -ErrorAction SilentlyContinue
    if ($cv -match "PHASE=5") { WLog "CHROME_VIS PHASE=5 HIT" }
    else { WLog "CHROME_VIS present but PHASE!=5" }
  }

  $errText = ""; $outText = ""
  if (Test-Path $Stderr) { $errText = Get-Content $Stderr -Raw -ErrorAction SilentlyContinue }
  if (Test-Path $Stdout) { $outText = Get-Content $Stdout -Raw -ErrorAction SilentlyContinue }
  $blob = "$errText`n$outText"
  if ($blob -match "PowerShell started|RAWRXD_PS_META|\[CONPTY_STREAM_OWNER\]") {
    $conptyStartWitness = 1
    WLog "STDOUT/ERR conpty/ps witness HIT"
  }
  if ($blob -match "RAWRXD_PS_META") { $streamIo = 1 }

  # Fail-closed: PostMessage alone != RUNTIME; pre-existing cmd != PowerShell ConPTY
  if ($postOk -and $conptyStartWitness -eq 0 -and $newPsChild -eq 0) {
    WLog 'FAIL_CLOSED: no NEW pwsh/powershell child and no PowerShell started witness'
  }
}

# Stop tip
if (-not $p.HasExited) {
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2
}

# RUNTIME_REACHED: tip SHA + RELINK closed + HWND + Post 4001 +
# (NEW pwsh/powershell child OR "PowerShell started" witness) + no GATE_STREAM.
# Pre-existing cmd.exe (agent pane) does NOT count.
$runtimeReached = 0
$runtimePass = 0
if ($shaMatch -and $relinkClosed -and ($hwnd -ne [IntPtr]::Zero) -and $postOk) {
  if (($newPsChild -gt 0 -or $conptyStartWitness -eq 1) -and $gateStreamHit -eq 0) {
    $runtimeReached = 1
  }
}
# phase5 chrome: HWND live + no GateTerminal. CHROME_VIS PHASE=5 preferred but
# absence alone does not invent PASS for stream; PHASE5_RUNTIME is soft.
$phase5Runtime = 0
if ($shaMatch -and $relinkClosed -and ($hwnd -ne [IntPtr]::Zero) -and $gateTermHit -eq 0 -and $chromeHit -eq 1) {
  $phase5Runtime = 1
} elseif ($shaMatch -and $relinkClosed -and ($hwnd -ne [IntPtr]::Zero) -and $gateTermHit -eq 0) {
  WLog 'PHASE5_RUNTIME soft: HWND ok GATE_TERMINAL=0 but CHROME_VIS absent - not invent PASS'
}
# Full MET only if stream RUNTIME_REACHED + phase5 chrome witness; still != PROMOTE.
if ($runtimeReached -eq 1 -and $phase5Runtime -eq 1) {
  $runtimePass = 1
} else {
  WLog 'RUNTIME_PASS=0 fail-closed (insufficient ConPTY/phase5 witnesses)'
}

$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$hwndHex = '{0:X}' -f $hwnd.ToInt64()
$sm = if ($shaMatch) { '1' } else { '0' }
$bc = if ($bin.CONPTY_STREAM_OWNER_001) { '1' } else { '0' }
$bp = if ($bin.SHELLLAYOUT_PHASE5_001) { '1' } else { '0' }
$rc = if ($relinkClosed) { '1' } else { '0' }
$p4 = if ($postOk) { '1' } else { '0' }
$sumLines = @(
  "ASOF_UTC=$asof"
  "TIP_SHA=$sha"
  "SHA_MATCH_748B=$sm"
  "BIN_CONPTY=$bc"
  "BIN_PHASE5=$bp"
  "RELINK_CLOSED=$rc"
  "MAIN_HWND=0x$hwndHex"
  "POST_4001=$p4"
  "PS_CHILD=$psChild"
  "PS_CHILD_BEFORE=$psChildBefore"
  "NEW_PS_CHILD=$newPsChild"
  "CMD_BEFORE=$cmdChildBefore"
  "CMD_AFTER=$cmdChildAfter"
  "CONPTY_WITNESS=$conptyStartWitness"
  "STREAM_IO=$streamIo"
  "GATE_TERMINAL=$gateTermHit"
  "GATE_STREAM=$gateStreamHit"
  "CHROME_VIS=$chromeHit"
  "PHASE5_RUNTIME=$phase5Runtime"
  "RUNTIME_REACHED=$runtimeReached"
  "RUNTIME_PASS=$runtimePass"
  "ABSORB_GHOSTTEXT=NOT_AUTHORIZED"
  "NO_TIP_REBUILD=1"
  "PROMOTE=0"
  "TIP_CLIMB=HOLD"
  "CERTIFIED=0"
  "NO_INVENT_PASS=1"
  "NOTE=PostMessage_ne_PASS; GATE_fire_FAIL_CLOSED; GhostText_absorb_forbidden"
)
Set-Content -Path $Summary -Value ($sumLines -join "`n")

WLog ("SUMMARY RUNTIME_REACHED={0} RUNTIME_PASS={1} RELINK_CLOSED={2}" -f $runtimeReached,$runtimePass,$rc)
WLog 'END'
exit 0
