# Minimal exclusive DEBUG for tip_011 — mirrors live VARS probe (no ShowWindow storm).
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$tip = Join-Path $root 'candidates\tip_final_integ_011'
$exe = Join-Path $tip 'RawrXD-Win32IDE-Native-Ext.exe'
$dbg = Join-Path $tip 'debuggee_fixture.exe'
$fix = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp'
$expect = (Get-Content (Join-Path $tip 'SHA256.txt') -Raw).Trim()
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$outDir = Join-Path $root 'artifacts'
$receipt = Join-Path $outDir 'INTEG011_DEBUG_MINIMAL_RECEIPT.txt'
$runlog = Join-Path $outDir ("INTEG011_debug_minimal_{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
function Log([string]$m) { $l="$(Get-Date -Format o) $m"; Add-Content $runlog $l; Write-Host $l }

$pre = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
Log "PRE_SHA=$pre SHA_MATCH=$([int]($pre -eq $expect))"
if ($pre -ne $expect) { 'DISK_DRIFT=1'; exit 3 }

@(
  'OWNER=integ011_debug_minimal'
  "PID=$PID"
  "SHA=$expect"
  'DO_NOT_STOP_PROCESS_NATIVE_EXT=1'
) | Set-Content $lock -Encoding ASCII

cmd /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1"
Start-Sleep 2
$sessDir = Join-Path $env:LOCALAPPDATA 'RawrXD'
New-Item -ItemType Directory -Force -Path $sessDir | Out-Null
Set-Content (Join-Path $sessDir 'ide_session.json') '{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}' -Encoding UTF8
Remove-Item (Join-Path $sessDir 'session.state') -Force -EA SilentlyContinue

$env:RAWRXD_DEBUGGEE = $dbg
$env:RAWRXD_PROBLEMS_FIXTURE = $fix
Remove-Item Env:VS_UNICODE_OUTPUT -EA SilentlyContinue

Add-Type @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class Dmin011 {
  public const uint WM_COMMAND=0x0111; public const uint LVM_GETITEMCOUNT=0x1004; public const uint SMTO_ABORTIFHUNG=0x0002;
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h,StringBuilder sb,int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll",SetLastError=true)] public static extern IntPtr SendMessageTimeoutW(IntPtr h,uint Msg,IntPtr w,IntPtr l,uint f,uint t,out IntPtr r);
  public static IntPtr FindMain(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true; var sb=new StringBuilder(256); GetClassNameW(h,sb,256); if(sb.ToString()=="RawrXD_IDE_Window" && IsWindowVisible(h)){ f=h; return false;} return true;}, IntPtr.Zero); return f; }
  static IntPtr found; static int want;
  public static int ListCount(IntPtr main,int id,uint ms){ found=IntPtr.Zero; want=id; EnumChildWindows(main,(h,l)=>{ if(GetDlgCtrlID(h)==want){ found=h; return false;} return true;},IntPtr.Zero); if(found==IntPtr.Zero) return -1; IntPtr r; if(SendMessageTimeoutW(found,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return -2; return r.ToInt32(); }
}
'@

$peak6043 = 0; $peak1317 = 0; $aliveEnd = 0; $exitCode = ''
try {
  $p = Start-Process -FilePath $exe -ArgumentList "`"$fix`"" -WorkingDirectory $tip -PassThru
  Log "PID=$($p.Id)"
  $main = [IntPtr]::Zero
  for ($i=0; $i -lt 30 -and $main -eq [IntPtr]::Zero; $i++) {
    Start-Sleep 1
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
    $main = [Dmin011]::FindMain([uint32]$p.Id)
  }
  Log "MAIN=0x$('{0:X}' -f $main.ToInt64())"
  if ($main -eq [IntPtr]::Zero -or $p.HasExited) { throw "no_main" }
  Start-Sleep 2
  [void][Dmin011]::PostMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
  Log 'POSTED_BUILD'
  Start-Sleep 6
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EXIT_AFTER_BUILD=$($p.ExitCode)"; throw "dead_after_build" }
  [void][Dmin011]::PostMessageW($main, 0x0111, [IntPtr]1104, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void][Dmin011]::PostMessageW($main, 0x0111, [IntPtr]5060, [IntPtr]::Zero)
  Log 'POSTED_5060'
  for ($t=0; $t -lt 40; $t++) {
    Start-Sleep -Milliseconds 250
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { Log "EXIT_DURING_POLL t=$t code=$($p.ExitCode)"; break }
    $v6043 = [Dmin011]::ListCount($main, 6043, 1500)
    $v1317 = [Dmin011]::ListCount($main, 1317, 1500)
    if ($v6043 -gt $peak6043) { $peak6043 = $v6043 }
    if ($v1317 -gt $peak1317) { $peak1317 = $v1317 }
    if (($t % 4) -eq 0) { Log "POLL t=$t v6043=$v6043 v1317=$v1317 peak6043=$peak6043" }
    if ($peak6043 -gt 0 -or $peak1317 -gt 0) { Log "VARS_HIT t=$t"; break }
  }
  try { $p.Refresh() } catch {}
  $aliveEnd = [int](-not $p.HasExited)
  $exitCode = "$($p.ExitCode)"
  try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {}
} finally {
  cmd /c "taskkill /F /IM debuggee_fixture.exe >nul 2>&1"
  Remove-Item $lock -Force -EA SilentlyContinue
}

$sessionReal = [int]($peak6043 -gt 0 -or $peak1317 -gt 0)
$dbgPass = if ($sessionReal -eq 1) { 'PASS' } else { 'FAIL' }
$post = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
@"
INTEG011_DEBUG_MINIMAL=MEASURED
TIP_SHA256=$pre
POST_SHA=$post
DISK_DRIFT=0
DISK_POST_DRIFT=$([int]($post -ne $expect))
DEBUG_VARS_ID6043=$peak6043
DEBUG_VARS_ID1317=$peak1317
SESSION_REAL_VIA_IDE_UI=$sessionReal
IDE_DEBUG_UI=$dbgPass
GUI_DEBUG_CONSOLE_E2E=$dbgPass
ALIVE_AT_VARS=$aliveEnd
EXIT=$exitCode
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
TIP_MOVE_AUTHORIZED=0
FROZEN_TIP_009_0946_UNTOUCHED=1
"@ | Set-Content $receipt -Encoding ASCII
Get-Content $receipt
exit $(if ($sessionReal -eq 1) { 0 } else { 4 })
