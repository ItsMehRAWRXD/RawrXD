#Requires -Version 5.1
# DAILY_DRIVER_CLOSE_001 T18/T19 bounded endurance+memory on tip A4F083DF
# Adapted from PHASE4_5 soak intent; does NOT transfer 3B72 seals.
# PROMOTE=0 CERTIFIED=0 NOT_RUN!=PASS
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001'
$LogDir = Join-Path $OutDir 'logs'
$WorkDir = Join-Path $OutDir 'ENDURANCE_workdir'
New-Item -ItemType Directory -Force -Path $LogDir, $WorkDir | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$TipExe = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_t05_fix\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E'
$Cycles = 12
$Log = Join-Path $LogDir ("t18_t19_runlog_$Stamp.txt")
$MemCsv = Join-Path $LogDir ("t18_t19_memory_$Stamp.csv")
$ResultJson = Join-Path $LogDir ("t18_t19_result_$Stamp.json")
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Write-Host $line
}
function Get-Sha([string]$p) { (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash }

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class T18Tip {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);
  public const uint WM_COMMAND=0x0111, WM_CLOSE=0x0010, BM_CLICK=0x00F5;
  public const int SW_RESTORE=9;
  public const int IDM_FILE_NEW=2001, IDM_FILE_OPEN=2002;
  public static string ClassName(IntPtr h){ var s=new StringBuilder(256); GetClassNameW(h,s,s.Capacity); return s.ToString(); }
  public static string TitleOf(IntPtr h){ var s=new StringBuilder(1024); GetWindowTextW(h,s,s.Capacity); return s.ToString(); }
  public static IntPtr FindMain(uint p){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p) return true;
      if(ClassName(h)=="RawrXD_IDE_Window" && IsWindowVisible(h)){ f=h; return false;} return true; }, IntPtr.Zero); return f;
  }
  public static IntPtr FindDialog(uint p){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p) return true;
      string c=ClassName(h);
      if((c=="#32770" || c.IndexOf("Dialog",StringComparison.OrdinalIgnoreCase)>=0) && IsWindowVisible(h)){ f=h; return false;}
      return true; }, IntPtr.Zero); return f;
  }
  public static IntPtr FindChildById(IntPtr root, int id){
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,l)=>{ if(GetDlgCtrlID(h)==id){ f=h; return false;} return true;}, IntPtr.Zero); return f;
  }
  public static void ClickChild(IntPtr parent, IntPtr child, int id){
    if(child==IntPtr.Zero) return;
    PostMessageW(parent, WM_COMMAND, (IntPtr)id, child);
    SendMessageW(child, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
  }
}
'@

$results = [ordered]@{
  TIP_SHA_PRE = ''
  TIP_SHA_POST = ''
  SHA_MATCH = 0
  CYCLES_PLANNED = $Cycles
  CYCLES_COMPLETED = 0
  T18 = 'NOT_RUN'
  T19 = 'NOT_RUN'
  PID = 0
  PRIVATE_BYTES_START = 0
  PRIVATE_BYTES_END = 0
  PRIVATE_BYTES_DELTA = 0
  GDI_START = 0
  GDI_END = 0
  USER_START = 0
  USER_END = 0
  THREADS_START = 0
  THREADS_END = 0
  SURVIVED = 0
  FORCE_KILL = 0
  BLOCKERS = @()
  NOTE = 'BOUNDED_N12_CANCEL_OPEN; not 100-cycle PHASE4_5; 3B72 seals not transferred'
}

"PrivateBytes,Gdi,User,Threads,Label,Utc" | Set-Content $MemCsv -Encoding UTF8
function Sample-Mem([System.Diagnostics.Process]$proc, [string]$label) {
  $proc.Refresh()
  if ($proc.HasExited) { return $null }
  $h = $proc.Handle
  $gdi = [int][T18Tip]::GetGuiResources($h, 0)
  $user = [int][T18Tip]::GetGuiResources($h, 1)
  $row = [ordered]@{
    PrivateMemory = [int64]$proc.PrivateMemorySize64
    Gdi = $gdi
    User = $user
    Threads = $proc.Threads.Count
  }
  '{0},{1},{2},{3},{4},{5}' -f $row.PrivateMemory,$row.Gdi,$row.User,$row.Threads,$label,(Get-Date).ToUniversalTime().ToString('o') |
    Add-Content $MemCsv
  return $row
}

WLog '=== T18/T19 BOUNDED TIP SOAK ==='
$shaPre = Get-Sha $TipExe
$results.TIP_SHA_PRE = $shaPre
WLog "SHA_PRE=$shaPre"
if ($shaPre -ne $ExpectedSha) {
  $results.T18 = 'FAIL_SHA_MISMATCH'
  $results.T19 = 'FAIL_SHA_MISMATCH'
  $results.BLOCKERS += 'SHA_MISMATCH'
  $results | ConvertTo-Json -Depth 5 | Set-Content $ResultJson -Encoding UTF8
  WLog "ABORT SHA mismatch"
  exit 2
}

Get-Process RawrXD-Win32IDE-Native -ErrorAction SilentlyContinue | ForEach-Object {
  try {
    $path = $_.Path
    if ($path -and ($path -like '*tip_t05_fix*' -or $path -like '*build_repair_*')) {
      WLog "KILL_STALE pid=$($_.Id)"
      Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
  } catch {}
}
Start-Sleep -Milliseconds 400

$wd = Split-Path $TipExe -Parent
$proc = Start-Process -FilePath $TipExe -WorkingDirectory $wd -PassThru
$results.PID = $proc.Id
WLog "LAUNCH pid=$($proc.Id)"
$main = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { break }
  $main = [T18Tip]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 250
}
if ($proc.HasExited -or $main -eq [IntPtr]::Zero) {
  $results.T18 = 'FAIL_LAUNCH'
  $results.T19 = 'FAIL_LAUNCH'
  $results.BLOCKERS += 'LAUNCH'
  WLog "LAUNCH_FAIL exited=$($proc.HasExited) hwnd=$main"
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
  $results | ConvertTo-Json -Depth 5 | Set-Content $ResultJson -Encoding UTF8
  exit 3
}
[void][T18Tip]::ShowWindow($main, [T18Tip]::SW_RESTORE)
[void][T18Tip]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 500

$s0 = Sample-Mem $proc 'START'
if ($s0) {
  $results.PRIVATE_BYTES_START = $s0.PrivateMemory
  $results.GDI_START = $s0.Gdi
  $results.USER_START = $s0.User
  $results.THREADS_START = $s0.Threads
}

$btnStop = [T18Tip]::FindChildById($main, 1210)
$sidebar = [T18Tip]::FindChildById($main, 1200)
$openFixture = Join-Path $WorkDir 't18_open_fixture.txt'
[IO.File]::WriteAllText($openFixture, "T18_BOUNDED_FIXTURE`r`n", [Text.UTF8Encoding]::new($false))

$completed = 0
$diedAt = -1
for ($i = 1; $i -le $Cycles; $i++) {
  WLog "CYCLE=$i/$Cycles"
  $proc.Refresh()
  if ($proc.HasExited) { $diedAt = $i; WLog "DIED_BEFORE_CYCLE exit=$($proc.ExitCode)"; break }
  $main = [T18Tip]::FindMain([uint32]$proc.Id)
  if ($main -eq [IntPtr]::Zero) { $diedAt = $i; WLog 'MAIN_LOST'; break }

  # Open dialog then cancel (bounded open/cancel surface)
  [void][T18Tip]::PostMessageW($main, [T18Tip]::WM_COMMAND, [IntPtr][T18Tip]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 500
  $dlg = [T18Tip]::FindDialog([uint32]$proc.Id)
  if ($dlg -ne [IntPtr]::Zero) {
    [void][T18Tip]::PostMessageW($dlg, [T18Tip]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 250
    WLog "OPEN_DIALOG_CANCEL hwnd=$dlg"
  } else {
    WLog 'OPEN_DIALOG_NOT_SEEN'
  }

  # Idle Stop click (cancel surface without requiring live inference)
  $btnStop = [T18Tip]::FindChildById($main, 1210)
  $sidebar = [T18Tip]::FindChildById($main, 1200)
  if ($btnStop -ne [IntPtr]::Zero -and $sidebar -ne [IntPtr]::Zero) {
    [T18Tip]::ClickChild($sidebar, $btnStop, 1210)
  }

  [void][T18Tip]::PostMessageW($main, [T18Tip]::WM_COMMAND, [IntPtr][T18Tip]::IDM_FILE_NEW, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 200

  $proc.Refresh()
  if ($proc.HasExited) { $diedAt = $i; WLog "DIED_AFTER_CYCLE exit=$($proc.ExitCode)"; break }
  Sample-Mem $proc ("C$i") | Out-Null
  $completed++
}

$results.CYCLES_COMPLETED = $completed
$proc.Refresh()
$alive = -not $proc.HasExited
$results.SURVIVED = if ($alive) { 1 } else { 0 }
$s1 = if ($alive) { Sample-Mem $proc 'END' } else { $null }
if ($s1) {
  $results.PRIVATE_BYTES_END = $s1.PrivateMemory
  $results.GDI_END = $s1.Gdi
  $results.USER_END = $s1.User
  $results.THREADS_END = $s1.Threads
  $results.PRIVATE_BYTES_DELTA = [int64]$s1.PrivateMemory - [int64]$results.PRIVATE_BYTES_START
}

# Close
if ($alive) {
  $main = [T18Tip]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) {
    [void][T18Tip]::PostMessageW($main, [T18Tip]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  }
  $closeDeadline = (Get-Date).AddSeconds(8)
  while ((Get-Date) -lt $closeDeadline -and -not $proc.HasExited) { Start-Sleep -Milliseconds 200 }
  if (-not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    $results.FORCE_KILL = 1
  }
  $proc.WaitForExit(5000) | Out-Null
}

$shaPost = Get-Sha $TipExe
$results.TIP_SHA_POST = $shaPost
$results.SHA_MATCH = if ($shaPre -eq $ExpectedSha -and $shaPost -eq $ExpectedSha) { 1 } else { 0 }

# T18 PASS: completed all cycles + survived
if ($completed -eq $Cycles -and $results.SURVIVED -eq 1 -and $results.SHA_MATCH -eq 1) {
  $results.T18 = 'PASS'
} elseif ($diedAt -gt 0) {
  $results.T18 = "FAIL_DIED_CYCLE_$diedAt"
  $results.BLOCKERS += 'PROCESS_DIED'
} else {
  $results.T18 = 'FAIL_INCOMPLETE'
  $results.BLOCKERS += 'INCOMPLETE_CYCLES'
}

# T19 PASS: start+end samples, survived, no catastrophic private growth (>256MB delta) / GDI runaway (>200)
$deltaPriv = [int64]$results.PRIVATE_BYTES_DELTA
$deltaGdi = [int]$results.GDI_END - [int]$results.GDI_START
if ($results.T18 -ne 'PASS') {
  $results.T19 = 'FAIL_DEPENDENT_T18'
  $results.BLOCKERS += 'T19_DEPENDENT'
} elseif ($results.PRIVATE_BYTES_START -le 0 -or $results.PRIVATE_BYTES_END -le 0) {
  $results.T19 = 'FAIL_NO_SAMPLE'
  $results.BLOCKERS += 'T19_SAMPLE'
} elseif ($deltaPriv -gt 268435456 -or $deltaGdi -gt 200) {
  $results.T19 = "FAIL_GROWTH privDelta=$deltaPriv gdiDelta=$deltaGdi"
  $results.BLOCKERS += 'T19_GROWTH'
} else {
  $results.T19 = 'PASS'
}

WLog "T18=$($results.T18) T19=$($results.T19) cycles=$completed/$Cycles survived=$($results.SURVIVED) deltaPriv=$deltaPriv deltaGdi=$deltaGdi"
WLog "SHA_POST=$shaPost MATCH=$($results.SHA_MATCH) FORCE_KILL=$($results.FORCE_KILL)"
$results | ConvertTo-Json -Depth 5 | Set-Content $ResultJson -Encoding UTF8
WLog "RESULT_JSON=$ResultJson"
Write-Output "T18=$($results.T18)"
Write-Output "T19=$($results.T19)"
Write-Output "RESULT=$ResultJson"
