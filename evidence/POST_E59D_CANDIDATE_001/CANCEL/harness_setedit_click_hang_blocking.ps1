#Requires -Version 5.1
# Blocking-API hang isolation (mirrors Cancel SetEdit + ClickChild).
# Each SendMessage runs in a runspace with hard timeout — no 4min unbounded hang.
# PROMOTE=0 REBUILD=HELD. Original Cancel crash artifacts untouched.
param(
  [ValidateSet('TRIPLE','SINGLE','SETEDIT_ONLY')]
  [string]$Mode = 'TRIPLE',
  [int]$StepTimeoutMs = 10000,
  [int]$WatchdogSec = 20
)
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\CANCEL'
$HangDir = Join-Path $OutDir 'hang_isolation'
New-Item -ItemType Directory -Force -Path $HangDir | Out-Null
$CandExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Log = Join-Path $HangDir ("BLOCK_${Mode}_$stamp`_RUNLOG.txt")
$StatePath = Join-Path $HangDir 'LAST_STEP_BLOCK.txt'
$ResultPath = Join-Path $HangDir ("BLOCK_${Mode}_$stamp`_RESULT.txt")
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Write-Output $line
}
function MarkStep([string]$s) {
  $s | Set-Content -LiteralPath $StatePath
  WLog "STEP=$s"
}

# Shared UI helpers (main session — discovery only; no blocking Send on submit path here)
$cs = @'
using System; using System.Text; using System.Runtime.InteropServices; using System.Diagnostics; using System.IO;
public class HangBlock {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsHungAppWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile, int DumpType, IntPtr a, IntPtr b, IntPtr c);
  [DllImport("kernel32.dll")] public static extern uint GetLastError();
  public const uint WM_SETTEXT=0x000C, WM_COMMAND=0x0111, BM_CLICK=0x00F5, WM_CLOSE=0x0010;
  public static IntPtr FindMain(uint pid) {
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true;
      var c=new StringBuilder(256); GetClassNameW(h,c,256);
      if(c.ToString()=="RawrXD_IDE_Window"){ found=h; return false;} return true;}, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindId(IntPtr parent, int id) {
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(parent,(h,l)=>{ if(GetWindowLongW(h,-12)==id){found=h;return false;} return true;}, IntPtr.Zero);
    return found;
  }
  public static string WriteMiniDump(int pid, string path) {
    try {
      var proc = Process.GetProcessById(pid);
      using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite)) {
        bool ok = MiniDumpWriteDump(proc.Handle, (uint)pid, fs.SafeFileHandle.DangerousGetHandle(), 0x216, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (!ok) return "MINIDUMP_FAIL err="+GetLastError();
        return "MINIDUMP_OK bytes="+fs.Length;
      }
    } catch (Exception ex) { return "MINIDUMP_EX="+ex.Message; }
  }
  public static string ThreadSummary(int pid) {
    try {
      var p = Process.GetProcessById(pid);
      var sb = new StringBuilder();
      sb.AppendLine("THREADS="+p.Threads.Count+" Responding="+p.Responding);
      foreach (ProcessThread t in p.Threads)
        sb.AppendLine(" tid="+t.Id+" state="+t.ThreadState+" wait="+t.WaitReason);
      return sb.ToString();
    } catch (Exception ex) { return "THREAD_SUM_EX="+ex.Message; }
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

# Runspace script: blocking Cancel-faithful SetEdit / Click ops
$blockOpsCs = @'
using System; using System.Runtime.InteropServices; using System.Diagnostics;
public static class BlockOps {
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public const uint WM_SETTEXT=0x000C, WM_COMMAND=0x0111, BM_CLICK=0x00F5;
  public static string SetEditDual(long editHwnd, string text) {
    IntPtr edit = new IntPtr(editHwnd);
    long t0 = Stopwatch.GetTimestamp();
    IntPtr p = Marshal.StringToHGlobalUni(text);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, p);
    long tMid = Stopwatch.GetTimestamp();
    Marshal.FreeHGlobal(p);
    SetWindowTextW(edit, text);
    long t1 = Stopwatch.GetTimestamp();
    double ms1 = (tMid-t0)*1000.0/Stopwatch.Frequency;
    double ms2 = (t1-tMid)*1000.0/Stopwatch.Frequency;
    return "OK_SETEDIT_DUAL wm_settext_ms="+ms1.ToString("F1")+" setwindowtext_ms="+ms2.ToString("F1");
  }
  public static string SetEditWmOnly(long editHwnd, string text) {
    IntPtr edit = new IntPtr(editHwnd);
    long t0 = Stopwatch.GetTimestamp();
    IntPtr p = Marshal.StringToHGlobalUni(text);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, p);
    Marshal.FreeHGlobal(p);
    long t1 = Stopwatch.GetTimestamp();
    return "OK_SETEDIT_WM_ONLY ms="+((t1-t0)*1000.0/Stopwatch.Frequency).ToString("F1");
  }
  public static string BmClick(long btnHwnd) {
    IntPtr btn = new IntPtr(btnHwnd);
    long t0 = Stopwatch.GetTimestamp();
    IntPtr r = SendMessageW(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    long t1 = Stopwatch.GetTimestamp();
    return "OK_BM_CLICK ms="+((t1-t0)*1000.0/Stopwatch.Frequency).ToString("F1")+" r="+r.ToInt64();
  }
  public static string WmCommandSync(long parentHwnd, long btnHwnd, int id) {
    IntPtr parent = new IntPtr(parentHwnd); IntPtr btn = new IntPtr(btnHwnd);
    IntPtr wp = (IntPtr)((0 << 16) | (id & 0xFFFF));
    long t0 = Stopwatch.GetTimestamp();
    IntPtr r = SendMessageW(parent, WM_COMMAND, wp, btn);
    long t1 = Stopwatch.GetTimestamp();
    return "OK_WM_COMMAND ms="+((t1-t0)*1000.0/Stopwatch.Frequency).ToString("F1")+" r="+r.ToInt64();
  }
  public static string PostCmd(long parentHwnd, long btnHwnd, int id) {
    IntPtr parent = new IntPtr(parentHwnd); IntPtr btn = new IntPtr(btnHwnd);
    IntPtr wp = (IntPtr)((0 << 16) | (id & 0xFFFF));
    bool ok = PostMessageW(parent, WM_COMMAND, wp, btn);
    return "OK_POST="+ok;
  }
}
'@

function Invoke-BlockedOp {
  param(
    [string]$OpName,
    [scriptblock]$Action,
    [int]$TimeoutMs
  )
  MarkStep "BEFORE_$OpName"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $rs = [runspacefactory]::CreateRunspace()
  $rs.Open()
  $ps = [powershell]::Create()
  $ps.Runspace = $rs
  [void]$ps.AddScript($blockOpsCs)
  [void]$ps.AddScript('Add-Type -TypeDefinition $opsCs -ErrorAction SilentlyContinue | Out-Null')
  # inject type via separate add
  $null = $ps.AddScript(@'
param($opsCs)
Add-Type -TypeDefinition $opsCs -ErrorAction SilentlyContinue | Out-Null
'@).AddArgument($blockOpsCs)
  # clearer: one pipeline
  $ps.Commands.Clear()
  [void]$ps.AddScript(@"
Add-Type -TypeDefinition @'
$blockOpsCs
'@ -ErrorAction SilentlyContinue | Out-Null
"@)
  # Actually nested here-string in ExpandString is messy — use file-based approach below
  $ps.Dispose(); $rs.Dispose()

  # Prefer Start-Job with Add-Type inside (isolated process = true timeout kill)
  $jobScript = {
    param($Op, $Edit, $Send, $Parent, $Text, $OpsCs)
    Add-Type -TypeDefinition $OpsCs -ErrorAction SilentlyContinue | Out-Null
    switch ($Op) {
      'SETEDIT_DUAL' { return [BlockOps]::SetEditDual($Edit, $Text) }
      'SETEDIT_WM'   { return [BlockOps]::SetEditWmOnly($Edit, $Text) }
      'BM_CLICK'     { return [BlockOps]::BmClick($Send) }
      'WM_COMMAND'   { return [BlockOps]::WmCommandSync($Parent, $Send, 1204) }
      'POST'         { return [BlockOps]::PostCmd($Parent, $Send, 1204) }
      default { return "UNKNOWN_OP=$Op" }
    }
  }
  $job = Start-Job -ScriptBlock $jobScript -ArgumentList $OpName, $Action.Edit, $Action.Send, $Action.Parent, $Action.Text, $blockOpsCs
  $ok = Wait-Job $job -Timeout ([math]::Ceiling($TimeoutMs / 1000.0))
  $sw.Stop()
  if (-not $ok) {
    WLog "TIMEOUT_$OpName elapsed_ms=$($sw.ElapsedMilliseconds)"
    MarkStep "TIMEOUT_$OpName"
    try { Stop-Job $job -Force -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue } catch {}
    return @{ Hung = 1; Result = "TIMEOUT_$OpName"; Ms = $sw.ElapsedMilliseconds }
  }
  $out = Receive-Job $job -ErrorAction SilentlyContinue
  Remove-Job $job -Force -ErrorAction SilentlyContinue
  $msg = if ($out) { ($out | Out-String).Trim() } else { 'EMPTY' }
  WLog "RESULT_$OpName=$msg elapsed_ms=$($sw.ElapsedMilliseconds)"
  MarkStep "AFTER_$OpName"
  return @{ Hung = 0; Result = $msg; Ms = $sw.ElapsedMilliseconds }
}

# Simpler Invoke without broken runspace preamble
function Invoke-HangJob {
  param([string]$OpName, [hashtable]$ArgsMap, [int]$TimeoutMs)
  MarkStep "BEFORE_$OpName"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $job = Start-Job -ScriptBlock {
    param($Op, $Edit, $Send, $Parent, $Text, $OpsCs)
    Add-Type -TypeDefinition $OpsCs -ErrorAction SilentlyContinue | Out-Null
    switch ($Op) {
      'SETEDIT_DUAL' { [BlockOps]::SetEditDual([int64]$Edit, [string]$Text) }
      'SETEDIT_WM'   { [BlockOps]::SetEditWmOnly([int64]$Edit, [string]$Text) }
      'BM_CLICK'     { [BlockOps]::BmClick([int64]$Send) }
      'WM_COMMAND'   { [BlockOps]::WmCommandSync([int64]$Parent, [int64]$Send, 1204) }
      'POST'         { [BlockOps]::PostCmd([int64]$Parent, [int64]$Send, 1204) }
      default { "UNKNOWN_OP=$Op" }
    }
  } -ArgumentList $OpName, $ArgsMap.Edit, $ArgsMap.Send, $ArgsMap.Parent, $ArgsMap.Text, $blockOpsCs
  $waitSec = [Math]::Max(1, [int][Math]::Ceiling($TimeoutMs / 1000.0))
  $finished = Wait-Job $job -Timeout $waitSec
  $sw.Stop()
  if (-not $finished) {
    WLog "TIMEOUT_$OpName elapsed_ms=$($sw.ElapsedMilliseconds) job_state=$($job.State)"
    MarkStep "TIMEOUT_$OpName"
    Stop-Job $job -Force -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    return @{ Hung = 1; Result = "TIMEOUT_$OpName"; Ms = $sw.ElapsedMilliseconds }
  }
  $err = $job.ChildJobs[0].Error | ForEach-Object { "$_" }
  $out = Receive-Job $job -ErrorAction SilentlyContinue
  Remove-Job $job -Force -ErrorAction SilentlyContinue
  $msg = if ($null -ne $out) { ($out | Out-String).Trim() } else { "EMPTY err=$err" }
  WLog "RESULT_$OpName=$msg elapsed_ms=$($sw.ElapsedMilliseconds)"
  if ($err) { WLog "ERR_$OpName=$err" }
  MarkStep "AFTER_$OpName"
  return @{ Hung = 0; Result = $msg; Ms = $sw.ElapsedMilliseconds }
}

$sha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
WLog "MODE=$Mode StepTimeoutMs=$StepTimeoutMs"
WLog "SHA_PRE=$sha"
if ($sha -ne $ExpectSha) { "HANG_BOUNDARY=SHA_DRIFT`nREQUEST_A_SUBMITTED=0" | Set-Content $ResultPath; exit 3 }

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } |
  ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 2

$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName = $CandExe; $psi.WorkingDirectory = (Split-Path $CandExe); $psi.UseShellExecute = $false
$proc = [Diagnostics.Process]::Start($psi)
WLog "PID=$($proc.Id)"
$proc.Id | Set-Content (Join-Path $HangDir 'pid_block.txt')

MarkStep 'WAIT_MAIN'
$main = [IntPtr]::Zero
$dl = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $dl) {
  if ($proc.HasExited) { break }
  $main = [HangBlock]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [HangBlock]::IsWindowVisible($main) -and [HangBlock]::FindId($main,1204) -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 250
}
if ($main -eq [IntPtr]::Zero -or $proc.HasExited) {
  "HANG_BOUNDARY=FAIL_MAIN`nREQUEST_A_SUBMITTED=0`nHANG_EQUIV_CRASH=NOT_EQUATED" | Set-Content $ResultPath
  exit 4
}
[void][HangBlock]::ShowWindow($main, 9)
WLog ("HWND=0x{0:X}" -f $main.ToInt64())

$inputHwnd = [HangBlock]::FindId($main, 1202)
$send = [HangBlock]::FindId($main, 1204)
$combo = [HangBlock]::FindId($main, 1206)
$sidebar = [HangBlock]::FindId($main, 1200)
if ($sidebar -eq [IntPtr]::Zero) { $sidebar = $main }

MarkStep 'MODEL_SELECT_BEGIN'
$cnt = [HangBlock]::SendMessageW($combo, 0x0146, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
$model = ''
for ($i = 0; $i -lt $cnt; $i++) {
  $tlen = [HangBlock]::SendMessageW($combo, 0x0149, [IntPtr]$i, [IntPtr]::Zero).ToInt32()
  if ($tlen -le 0) { continue }
  $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal(($tlen + 2) * 2)
  try {
    [void][HangBlock]::SendMessageW($combo, 0x0148, [IntPtr]$i, $buf)
    $item = [Runtime.InteropServices.Marshal]::PtrToStringUni($buf)
  } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
  if ($item -like '*gemma3:4b*') {
    [void][HangBlock]::SendMessageW($combo, 0x014E, [IntPtr]$i, [IntPtr]::Zero)
    $wp = [IntPtr]((1 -shl 16) -bor 1206)
    [void][HangBlock]::PostMessageW($main, 0x0111, $wp, $combo)
    $model = $item; break
  }
}
WLog "MODEL=$model"
MarkStep 'MODEL_SELECT_DONE'
Start-Sleep -Milliseconds 600

$prompt = 'Write a very long detailed essay of at least 2000 words about Windows kernel scheduling. Include marker HANGISO_MARKER_A.'
$argsMap = @{
  Edit = $inputHwnd.ToInt64()
  Send = $send.ToInt64()
  Parent = $sidebar.ToInt64()
  Text = $prompt
}

$hangBoundary = 'NONE'
$submitted = 0
$hungFlag = 0
$dumpNote = ''

function Capture-Hang([string]$boundary) {
  $script:hangBoundary = $boundary
  $script:hungFlag = 1
  WLog "HANG_CAPTURE boundary=$boundary"
  $ts = [HangBlock]::ThreadSummary([int]$proc.Id)
  $ts | Set-Content (Join-Path $HangDir ("threads_block_${Mode}_$stamp.txt"))
  WLog $ts
  $dumpPath = Join-Path $HangDir ("hang_block_${Mode}_$stamp.dmp")
  $script:dumpNote = [HangBlock]::WriteMiniDump([int]$proc.Id, $dumpPath)
  WLog "DUMP=$dumpNote"
  WLog ("IsHungAppWindow={0} Responding={1}" -f [int][HangBlock]::IsHungAppWindow($main), $(try{$proc.Responding}catch{'?'}))
}

# SETEDIT dual (Cancel-faithful)
$r = Invoke-HangJob -OpName 'SETEDIT_DUAL' -ArgsMap $argsMap -TimeoutMs $StepTimeoutMs
if ($r.Hung -eq 1) { Capture-Hang 'SETEDIT_DUAL' }

if ($hungFlag -eq 0 -and $Mode -ne 'SETEDIT_ONLY') {
  if ($Mode -eq 'SINGLE') {
    $r = Invoke-HangJob -OpName 'BM_CLICK' -ArgsMap $argsMap -TimeoutMs $StepTimeoutMs
    if ($r.Hung -eq 1) { Capture-Hang 'BM_CLICK' }
    else { $submitted = 1; WLog 'REQUEST_A_SUBMITTED=1'; MarkStep 'REQUEST_A_SUBMITTED' }
  } else {
    $r = Invoke-HangJob -OpName 'BM_CLICK' -ArgsMap $argsMap -TimeoutMs $StepTimeoutMs
    if ($r.Hung -eq 1) { Capture-Hang 'BM_CLICK' }
    else {
      $r = Invoke-HangJob -OpName 'WM_COMMAND' -ArgsMap $argsMap -TimeoutMs $StepTimeoutMs
      if ($r.Hung -eq 1) { Capture-Hang 'WM_COMMAND_SYNC' }
      else {
        $r = Invoke-HangJob -OpName 'POST' -ArgsMap $argsMap -TimeoutMs $StepTimeoutMs
        $submitted = 1
        WLog 'REQUEST_A_SUBMITTED=1 MODE=TRIPLE_BLOCKING'
        MarkStep 'REQUEST_A_SUBMITTED'
      }
    }
  }
}

if ($submitted -eq 1 -and $hungFlag -eq 0) {
  MarkStep 'POST_SUBMIT_WATCH'
  $watchDl = (Get-Date).AddSeconds($WatchdogSec)
  while ((Get-Date) -lt $watchDl) {
    if ($proc.HasExited) {
      WLog ("CRASH_POST_SUBMIT exit={0} hex=0x{1:X8}" -f $proc.ExitCode, [uint32]$proc.ExitCode)
      $hangBoundary = 'POST_SUBMIT_CRASH'
      break
    }
    Start-Sleep -Milliseconds 200
  }
  if ($hangBoundary -eq 'NONE' -and -not $proc.HasExited) {
    WLog "NO_CRASH_IN_${WatchdogSec}S"
    $hangBoundary = 'NO_HANG_NO_CRASH'
  }
}

if (-not $proc.HasExited) {
  [void][HangBlock]::PostMessageW($main, [HangBlock]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}
Start-Sleep 1
$shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
WLog "SHA_POST=$shaPost"
$lastStep = if (Test-Path $StatePath) { (Get-Content $StatePath -Raw).Trim() } else { '?' }

@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
MODE=$Mode
PATH=BLOCKING_CANCEL_FAITHFUL
CERT_EXE_SHA=$sha
SHA_POST=$shaPost
HANG_BOUNDARY=$hangBoundary
REQUEST_A_SUBMITTED=$submitted
HUNG_FLAG=$hungFlag
LAST_STEP=$lastStep
HANG_EQUIV_CRASH=NOT_EQUATED
ORIGINAL_CRASH=0xC000041D
DUMP_NOTE=$dumpNote
PROMOTE=0
REBUILD=HELD
PRODUCT_DEFECT=NOT_PROVEN
RUNLOG=$Log
"@ | Set-Content -LiteralPath $ResultPath
WLog "RESULT HANG_BOUNDARY=$hangBoundary REQUEST_A_SUBMITTED=$submitted HUNG_FLAG=$hungFlag"
if ($hungFlag -eq 1) { exit 10 }
if ($hangBoundary -eq 'POST_SUBMIT_CRASH') { exit 11 }
exit 0
