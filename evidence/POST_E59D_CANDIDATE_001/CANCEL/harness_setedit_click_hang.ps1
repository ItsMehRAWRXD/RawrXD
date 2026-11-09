#Requires -Version 5.1
# SETEDIT_CLICK_HANG isolation — CERT 3B720981 only.
# Bounded waits. PROMOTE=0 REBUILD=HELD. Does NOT touch original Cancel crash artifacts.
param(
  [ValidateSet('TRIPLE','SINGLE')]
  [string]$Mode = 'TRIPLE',
  [int]$StepTimeoutMs = 8000,
  [int]$WatchdogSec = 45
)
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\CANCEL'
$HangDir = Join-Path $OutDir 'hang_isolation'
New-Item -ItemType Directory -Force -Path $HangDir | Out-Null
$CandExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Log = Join-Path $HangDir ("HANG_${Mode}_$stamp`_RUNLOG.txt")
$StatePath = Join-Path $HangDir 'LAST_STEP.txt'
$ResultPath = Join-Path $HangDir ("HANG_${Mode}_$stamp`_RESULT.txt")
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

$cs = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
public class HangIso {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsHungAppWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)]
  public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint Msg, IntPtr wParam, IntPtr lParam,
    uint fuFlags, uint uTimeout, out IntPtr lpdwResult);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile,
    int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
  [DllImport("kernel32.dll")] public static extern uint GetLastError();
  public const uint WM_SETTEXT=0x000C, WM_COMMAND=0x0111, BM_CLICK=0x00F5, WM_CLOSE=0x0010;
  public const uint SMTO_ABORTIFHUNG=0x0002, SMTO_NORMAL=0x0000, SMTO_BLOCK=0x0001;
  public const int GWL_ID=-12;
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
  // Timed SetEdit: SendMessageTimeout WM_SETTEXT only (no second SetWindowText sync path).
  public static string SetEditTimed(IntPtr edit, string text, uint timeoutMs, out int hung) {
    hung=0;
    IntPtr p = Marshal.StringToHGlobalUni(text);
    IntPtr result;
    long t0 = Stopwatch.GetTimestamp();
    IntPtr ok = SendMessageTimeoutW(edit, WM_SETTEXT, IntPtr.Zero, p, SMTO_ABORTIFHUNG|SMTO_NORMAL, timeoutMs, out result);
    long t1 = Stopwatch.GetTimestamp();
    Marshal.FreeHGlobal(p);
    double ms = (t1-t0)*1000.0/Stopwatch.Frequency;
    if (ok==IntPtr.Zero) { hung=1; return "TIMEOUT_SETEDIT_MS="+ms.ToString("F1")+" lasterr="+GetLastError(); }
    return "OK_SETEDIT_MS="+ms.ToString("F1")+" result="+result.ToInt64();
  }
  // Single BM_CLICK with timeout.
  public static string BmClickTimed(IntPtr btn, uint timeoutMs, out int hung) {
    hung=0;
    IntPtr result;
    long t0 = Stopwatch.GetTimestamp();
    IntPtr ok = SendMessageTimeoutW(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero, SMTO_ABORTIFHUNG|SMTO_NORMAL, timeoutMs, out result);
    long t1 = Stopwatch.GetTimestamp();
    double ms = (t1-t0)*1000.0/Stopwatch.Frequency;
    if (ok==IntPtr.Zero) { hung=1; return "TIMEOUT_BM_CLICK_MS="+ms.ToString("F1")+" lasterr="+GetLastError(); }
    return "OK_BM_CLICK_MS="+ms.ToString("F1")+" result="+result.ToInt64();
  }
  // Sync WM_COMMAND with timeout (the extra notify suspected in triple path).
  public static string WmCommandTimed(IntPtr parent, IntPtr btn, int id, uint timeoutMs, out int hung) {
    hung=0;
    IntPtr wp = (IntPtr)((0 << 16) | (id & 0xFFFF));
    IntPtr result;
    long t0 = Stopwatch.GetTimestamp();
    IntPtr ok = SendMessageTimeoutW(parent, WM_COMMAND, wp, btn, SMTO_ABORTIFHUNG|SMTO_NORMAL, timeoutMs, out result);
    long t1 = Stopwatch.GetTimestamp();
    double ms = (t1-t0)*1000.0/Stopwatch.Frequency;
    if (ok==IntPtr.Zero) { hung=1; return "TIMEOUT_WM_COMMAND_MS="+ms.ToString("F1")+" lasterr="+GetLastError(); }
    return "OK_WM_COMMAND_MS="+ms.ToString("F1")+" result="+result.ToInt64();
  }
  // Blocking SendMessage BM_CLICK in a way we can observe hang (caller uses job timeout).
  public static string BmClickBlocking(IntPtr btn) {
    long t0 = Stopwatch.GetTimestamp();
    IntPtr r = SendMessageW(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    long t1 = Stopwatch.GetTimestamp();
    return "OK_BM_CLICK_BLOCK_MS="+((t1-t0)*1000.0/Stopwatch.Frequency).ToString("F1")+" r="+r.ToInt64();
  }
  public static string WriteMiniDump(int pid, string path) {
    try {
      var proc = Process.GetProcessById(pid);
      using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite)) {
        // MiniDumpWithFullMemory=2 is heavy; use MiniDumpWithThreadInfo|MiniDumpWithHandleData|MiniDumpNormal variants
        // 0x0010 = MiniDumpWithThreadInfo, 0x0002 = MiniDumpWithFullMemory — use 0x1826 (useful + thread info)
        int dtype = 0x00000216; // Normal|WithHandleData|WithThreadInfo|WithUnloadedModules-ish
        bool ok = MiniDumpWriteDump(proc.Handle, (uint)pid, fs.SafeFileHandle.DangerousGetHandle(), dtype, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (!ok) return "MINIDUMP_FAIL err="+GetLastError();
        return "MINIDUMP_OK bytes="+fs.Length;
      }
    } catch (Exception ex) { return "MINIDUMP_EX="+ex.Message; }
  }
  public static string ThreadSummary(int pid) {
    try {
      var p = Process.GetProcessById(pid);
      var sb = new StringBuilder();
      sb.Append("THREADS="+p.Threads.Count+" Responding=");
      try { sb.Append(p.Responding); } catch { sb.Append("?"); }
      sb.AppendLine();
      foreach (ProcessThread t in p.Threads) {
        sb.AppendFormat(" tid={0} state={1} wait={2} start={3:o}", t.Id, t.ThreadState, t.WaitReason, t.StartTime);
        sb.AppendLine();
      }
      return sb.ToString();
    } catch (Exception ex) { return "THREAD_SUM_EX="+ex.Message; }
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

$sha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
WLog "MODE=$Mode StepTimeoutMs=$StepTimeoutMs WatchdogSec=$WatchdogSec"
WLog "SHA_PRE=$sha"
if ($sha -ne $ExpectSha) { WLog 'SHA_DRIFT'; "HANG_BOUNDARY=SHA_DRIFT`nREQUEST_A_SUBMITTED=0" | Set-Content $ResultPath; exit 3 }

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } |
  ForEach-Object { WLog "KILL_PRE pid=$($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $CandExe
$psi.WorkingDirectory = (Split-Path $CandExe)
$psi.UseShellExecute = $false
$proc = [Diagnostics.Process]::Start($psi)
WLog "PID=$($proc.Id)"
$proc.Id | Set-Content (Join-Path $HangDir 'pid.txt')

MarkStep 'WAIT_MAIN'
$main = [IntPtr]::Zero
$dl = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $dl) {
  if ($proc.HasExited) { WLog "EXIT_EARLY $($proc.ExitCode)"; break }
  $main = [HangIso]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [HangIso]::IsWindowVisible($main) -and [HangIso]::FindId($main,1204) -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 250
}
if ($main -eq [IntPtr]::Zero -or $proc.HasExited) {
  WLog 'FAIL_MAIN'
  "HANG_BOUNDARY=FAIL_MAIN`nREQUEST_A_SUBMITTED=0`nHANG_EQUIV_CRASH=NOT_EQUATED" | Set-Content $ResultPath
  exit 4
}
[void][HangIso]::ShowWindow($main, 9)
WLog ("HWND=0x{0:X} hungApp={1}" -f $main.ToInt64(), [int][HangIso]::IsHungAppWindow($main))

$input = [HangIso]::FindId($main, 1202)
$send = [HangIso]::FindId($main, 1204)
$combo = [HangIso]::FindId($main, 1206)
$sidebar = [HangIso]::FindId($main, 1200)
if ($sidebar -eq [IntPtr]::Zero) { $sidebar = $main }

MarkStep 'MODEL_SELECT_BEGIN'
$cnt = [HangIso]::SendMessageW($combo, 0x0146, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
$model = ''
for ($i = 0; $i -lt $cnt; $i++) {
  $tlen = [HangIso]::SendMessageW($combo, 0x0149, [IntPtr]$i, [IntPtr]::Zero).ToInt32()
  if ($tlen -le 0) { continue }
  $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal(($tlen + 2) * 2)
  try {
    [void][HangIso]::SendMessageW($combo, 0x0148, [IntPtr]$i, $buf)
    $item = [Runtime.InteropServices.Marshal]::PtrToStringUni($buf)
  } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
  if ($item -like '*gemma3:4b*') {
    [void][HangIso]::SendMessageW($combo, 0x014E, [IntPtr]$i, [IntPtr]::Zero)
    $wp = [IntPtr]((1 -shl 16) -bor 1206)
    [void][HangIso]::PostMessageW($main, [HangIso]::WM_COMMAND, $wp, $combo)
    $model = $item
    break
  }
}
WLog "MODEL=$model"
MarkStep 'MODEL_SELECT_DONE'
Start-Sleep -Milliseconds 500

$prompt = 'Write a very long detailed essay of at least 2000 words about Windows kernel scheduling. Include marker HANGISO_MARKER_A.'
$hangBoundary = 'NONE'
$submitted = 0
$hungFlag = 0
$dumpNote = ''

function Capture-HangEvidence([string]$boundary) {
  $script:hangBoundary = $boundary
  $script:hungFlag = 1
  WLog "HANG_CAPTURE boundary=$boundary"
  $ts = [HangIso]::ThreadSummary([int]$proc.Id)
  $ts | Set-Content (Join-Path $HangDir ("threads_${Mode}_$stamp.txt"))
  WLog "THREAD_SUMMARY_LEN=$($ts.Length)"
  WLog $ts
  $dumpPath = Join-Path $HangDir ("hang_${Mode}_$stamp.dmp")
  $script:dumpNote = [HangIso]::WriteMiniDump([int]$proc.Id, $dumpPath)
  WLog "DUMP=$dumpNote path=$dumpPath"
  WLog ("IsHungAppWindow={0}" -f [int][HangIso]::IsHungAppWindow($main))
  if (-not $proc.HasExited) {
    try { WLog "Responding=$($proc.Responding) HasExited=0" } catch { WLog 'Responding=?' }
  } else {
    WLog "HasExited=1 ExitCode=$($proc.ExitCode)"
  }
}

# --- SetEdit (timed) ---
MarkStep 'BEFORE_SETEDIT'
$h = 0
$setRes = [HangIso]::SetEditTimed($input, $prompt, [uint32]$StepTimeoutMs, [ref]$h)
WLog "SETEDIT_RESULT=$setRes hung=$h"
if ($h -eq 1) {
  MarkStep 'AFTER_SETEDIT_TIMEOUT'
  Capture-HangEvidence 'SETEDIT'
} else {
  MarkStep 'AFTER_SETEDIT_OK'
}

if ($hungFlag -eq 0) {
  if ($Mode -eq 'SINGLE') {
    MarkStep 'BEFORE_BM_CLICK'
    $h = 0
    $clk = [HangIso]::BmClickTimed($send, [uint32]$StepTimeoutMs, [ref]$h)
    WLog "CLICK_RESULT=$clk hung=$h"
    if ($h -eq 1) {
      MarkStep 'AFTER_BM_CLICK_TIMEOUT'
      Capture-HangEvidence 'BM_CLICK'
    } else {
      MarkStep 'AFTER_BM_CLICK_OK'
      $submitted = 1
      WLog 'REQUEST_A_SUBMITTED=1 MODE=SINGLE'
      MarkStep 'REQUEST_A_SUBMITTED'
    }
  } else {
    # TRIPLE path mirrors Cancel ClickChild: BM_CLICK + sync WM_COMMAND + PostMessage
    MarkStep 'BEFORE_BM_CLICK'
    $h = 0
    $clk = [HangIso]::BmClickTimed($send, [uint32]$StepTimeoutMs, [ref]$h)
    WLog "CLICK_BM_RESULT=$clk hung=$h"
    if ($h -eq 1) {
      MarkStep 'AFTER_BM_CLICK_TIMEOUT'
      Capture-HangEvidence 'BM_CLICK'
    } else {
      MarkStep 'AFTER_BM_CLICK_OK'
      MarkStep 'BEFORE_WM_COMMAND_SYNC'
      $h2 = 0
      $cmd = [HangIso]::WmCommandTimed($sidebar, $send, 1204, [uint32]$StepTimeoutMs, [ref]$h2)
      WLog "CLICK_WM_COMMAND_RESULT=$cmd hung=$h2"
      if ($h2 -eq 1) {
        MarkStep 'AFTER_WM_COMMAND_TIMEOUT'
        Capture-HangEvidence 'WM_COMMAND_SYNC'
      } else {
        MarkStep 'AFTER_WM_COMMAND_OK'
        MarkStep 'BEFORE_POSTMESSAGE'
        $wp = [IntPtr]((0 -shl 16) -bor 1204)
        $okPost = [HangIso]::PostMessageW($sidebar, [HangIso]::WM_COMMAND, $wp, $send)
        WLog "POSTMESSAGE_OK=$okPost"
        MarkStep 'AFTER_POSTMESSAGE'
        $submitted = 1
        WLog 'REQUEST_A_SUBMITTED=1 MODE=TRIPLE'
        MarkStep 'REQUEST_A_SUBMITTED'
      }
    }
  }
}

# Post-submit observation (bounded) — crash vs alive; not equated to hang
if ($submitted -eq 1 -and $hungFlag -eq 0) {
  MarkStep 'POST_SUBMIT_WATCH'
  $watchDl = (Get-Date).AddSeconds($WatchdogSec)
  while ((Get-Date) -lt $watchDl) {
    if ($proc.HasExited) {
      $code = $proc.ExitCode
      WLog ("CRASH_POST_SUBMIT exit=$code hex=0x{0:X8}" -f [uint32]$code)
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

# Cleanup
if (-not $proc.HasExited) {
  try { [void][HangIso]::PostMessageW($main, [HangIso]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) } catch {}
  Start-Sleep -Milliseconds 500
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}
Start-Sleep -Seconds 1
$shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
WLog "SHA_POST=$shaPost"
$lastStep = if (Test-Path $StatePath) { Get-Content $StatePath -Raw } else { '?' }
$equiv = 'NOT_EQUATED'
if ($hangBoundary -eq 'POST_SUBMIT_CRASH' -and $proc.ExitCode -eq -1073740771) {
  # Still NOT equated to SetEdit hang — separate outcome after submit
  $equiv = 'NOT_EQUATED_POST_SUBMIT_IS_CRASH_CLASS'
}

@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
MODE=$Mode
CERT_EXE_SHA=$sha
SHA_POST=$shaPost
HANG_BOUNDARY=$hangBoundary
REQUEST_A_SUBMITTED=$submitted
HUNG_FLAG=$hungFlag
LAST_STEP=$($lastStep.Trim())
HANG_EQUIV_CRASH=$equiv
ORIGINAL_CRASH=0xC000041D
DUMP_NOTE=$dumpNote
PROMOTE=0
REBUILD=HELD
PRODUCT_DEFECT=NOT_PROVEN
RUNLOG=$Log
"@ | Set-Content -LiteralPath $ResultPath
WLog "RESULT written HANG_BOUNDARY=$hangBoundary REQUEST_A_SUBMITTED=$submitted"
if ($hungFlag -eq 1) { exit 10 }
if ($hangBoundary -eq 'POST_SUBMIT_CRASH') { exit 11 }
exit 0
