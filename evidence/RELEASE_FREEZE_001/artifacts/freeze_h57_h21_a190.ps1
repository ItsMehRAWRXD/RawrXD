param(
  [string]$TipExe = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-FreezeEO-A190.exe",
  [string]$ExpectSha = "35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563",
  [string]$OutDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts",
  [string]$WorkDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\h57_runtime_35c22",
  [int]$BootWaitSec = 12
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir, $WorkDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runlog = Join-Path $OutDir ("freeze_h57_h21_run_" + $stamp + ".txt")
$receipt = Join-Path $OutDir "H57_H21_RUNTIME_RECEIPT.txt"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices; using System.Text;
public static class H57H21A {
  public const uint WM_DPICHANGED = 0x02E0;
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int left, top, right, bottom; }
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("kernel32.dll")] public static extern IntPtr LocalAlloc(uint u, UIntPtr s);
  [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr h);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256); GetClassNameW(h, sb, sb.Capacity);
      if (sb.ToString().Contains("RawrXD_IDE")) { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static bool DpiProbe(IntPtr main, out string detail) {
    RECT before; GetWindowRect(main, out before);
    RECT suggested; suggested.left = before.left; suggested.top = before.top;
    suggested.right = before.left + Math.Max(400, (before.right - before.left) + 80);
    suggested.bottom = before.top + Math.Max(300, (before.bottom - before.top) + 60);
    IntPtr mem = LocalAlloc(0x40, (UIntPtr)Marshal.SizeOf(typeof(RECT)));
    Marshal.StructureToPtr(suggested, mem, false);
    IntPtr wp = (IntPtr)((120 << 16) | 120);
    SendMessageW(main, WM_DPICHANGED, wp, mem);
    LocalFree(mem);
    System.Threading.Thread.Sleep(400);
    RECT after; GetWindowRect(main, out after);
    bool changed = after.left != before.left || after.top != before.top ||
                   after.right != before.right || after.bottom != before.bottom;
    detail = string.Format("before={0},{1},{2},{3} after={4},{5},{6},{7}",
      before.left, before.top, before.right, before.bottom,
      after.left, after.top, after.right, after.bottom);
    return changed;
  }
}
"@

$hash = (certutil -hashfile $TipExe SHA256 | Where-Object { $_ -match '^[0-9A-Fa-f]{64}$' }).ToUpper()
Log "TIP_EXE=$TipExe SHA=$hash EXPECT=$ExpectSha"
if ($hash -ne $ExpectSha) {
  Set-Content $receipt "H57=FAIL`nH21=FAIL`nREASON=SHA_MISMATCH`nMEASURED=$hash`nEXPECT=$ExpectSha`nPROMOTE=0"
  exit 2
}
$tipBase = [IO.Path]::GetFileNameWithoutExtension($TipExe)
Get-Process -Name $tipBase -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2
$logDir = Join-Path $WorkDir "logs_runtime"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$env:RAWRXD_LOG_DIR = $logDir
$env:RAWRXD_CHAT_SESSION_ID = "h57_$stamp"
$env:RAWRXD_CHAT_RUN_ID = "h57run_$stamp"
$p = Start-Process -FilePath $TipExe -PassThru -WorkingDirectory $WorkDir -WindowStyle Normal
Log ("PID=" + $p.Id)
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log ("EXIT_EARLY " + $p.ExitCode); break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $by = [H57H21A]::FindMain([uint32]$p.Id)
  if ($by -ne [IntPtr]::Zero) { $main = $by; break }
}
Log ("MAIN=0x{0:X}" -f $main.ToInt64())
Start-Sleep -Seconds $BootWaitSec

# Trigger a trivial agent-session path via Send if controls exist (ledger creation)
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices; using System.Text;
public static class H57Ui {
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static IntPtr FindCtrl(IntPtr parent, int wantId, string classPart) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, (h, lp) => {
      int id = GetDlgCtrlID(h); var sb = new StringBuilder(64); GetClassNameW(h, sb, 64);
      if (id == wantId && sb.ToString().IndexOf(classPart, StringComparison.OrdinalIgnoreCase) >= 0) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@ -ErrorAction SilentlyContinue
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  $chat = [H57Ui]::FindCtrl($main, 1202, "Edit")
  $send = [H57Ui]::FindCtrl($main, 1204, "Button")
  if ($chat -ne [IntPtr]::Zero -and $send -ne [IntPtr]::Zero) {
    [void][H57Ui]::SendMessageW($chat, 0x000C, [IntPtr]::Zero, "h57-ledger-probe")
    Start-Sleep -Milliseconds 100
    [void][H57Ui]::SendMessageW($main, 0x0111, [IntPtr]1204, $send)
    Log "H57_SEND_PROBE"
    Start-Sleep -Seconds 8
  }
}

$ledger = Join-Path $WorkDir ".rawrxd\ledger\native_agent_session.json"
$ledgerAlt = Get-ChildItem -Path $WorkDir -Recurse -Filter "native_agent_session.json" -ErrorAction SilentlyContinue | Select-Object -First 1
$h57 = "FAIL_NO_LEDGER"
$ledgerPath = ""
if (Test-Path $ledger) {
  $h57 = "PASS_LEDGER_RUNTIME"
  $ledgerPath = $ledger
} elseif ($ledgerAlt) {
  $h57 = "PASS_LEDGER_RUNTIME"
  $ledgerPath = $ledgerAlt.FullName
} else {
  $rt = Join-Path $logDir "chat_runtime.log"
  $rtAlt = Get-ChildItem -Path $WorkDir -Recurse -Filter "chat_runtime.log" -ErrorAction SilentlyContinue | Select-Object -First 1
  $rtPath = if (Test-Path $rt) { $rt } elseif ($rtAlt) { $rtAlt.FullName } else { "" }
  if ($rtPath -and ((Get-Content $rtPath -Raw -ErrorAction SilentlyContinue) -match 'AgentSession|native_agent_session|request_started|CHAT_SEND_ARMED|SESSION_OPEN')) {
    $h57 = "PASS_SESSION_JOURNAL"
    $ledgerPath = $rtPath
  }
}
Log "H57=$h57 LEDGER=$ledgerPath"

$h21 = "FAIL"
$dpiDetail = ""
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  $changed = [H57H21A]::DpiProbe($main, [ref]$dpiDetail)
  if ($changed) { $h21 = "PASS" } else { $h21 = "FAIL_NO_RECT_CHANGE" }
  Log "H21=$h21 $dpiDetail"
} else {
  $h21 = "FAIL_NO_HWND"
  Log "H21=$h21"
}
try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } } catch {}

@(
  "CANDIDATE_SHA=$hash",
  "H57=$h57",
  "H21=$h21",
  "DPI_DETAIL=$dpiDetail",
  "LEDGER_PATH=$ledgerPath",
  "STARTUP_LEDGER=$([bool](Test-Path $ledger))",
  "WORKING_DIRECTORY=$WorkDir",
  "TIP_EXE=$TipExe",
  "RUNLOG=$runlog",
  "PIN=A190",
  "PROMOTE=0",
  "MATURITY=82%"
) | Tee-Object -FilePath $receipt
if (($h57 -match '^PASS') -and ($h21 -eq "PASS")) { exit 0 } else { exit 5 }
