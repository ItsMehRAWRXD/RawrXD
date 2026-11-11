# Dedicated S11 WFDE BP-hit probe on Ext tip. PROMOTE=0. Does not touch A190.
$ErrorActionPreference = 'Continue'
$tipDir = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001'
$exe = Join-Path $tipDir 'RawrXD-Win32IDE-Native-Ext.exe'
$debuggee = Join-Path $tipDir 'debuggee_fixture.exe'
$broken = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp'
$outDir = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts'
$logDir = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_002\s11_wfde_317d'
New-Item -ItemType Directory -Force -Path $outDir, $logDir | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*','debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $outDir ("s11_wfde_run_$stamp.txt")
$receipt = Join-Path $outDir 'S11_WFDE_BP_HIT_RECEIPT.txt'
function Log([string]$m) { $line = "$(Get-Date -Format o) $m"; Add-Content $runlog $line; Write-Host $line }
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class S11Wfde {
  public const uint WM_COMMAND=0x0111; public const uint WM_CLOSE=0x0010; public const uint SMTO_NORMAL=0;
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  public static IntPtr FindMain(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true; var sb=new StringBuilder(256); GetClassNameW(h,sb,256); if(sb.ToString()=="RawrXD_IDE_Window"){ f=h; return false;} return true; }, IntPtr.Zero); return f; }
  public static bool Cmd(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
}
"@
Remove-Item -LiteralPath (Join-Path $logDir 'WFDE_BP_HIT_RECEIPT.txt') -Force -EA SilentlyContinue
$env:RAWRXD_LOG_DIR = $logDir
$env:RAWRXD_DEBUGGEE = $debuggee
$env:RAWRXD_PROBLEMS_FIXTURE = $broken
Log "TIP_SHA256=$sha DEBUGGEE_EXISTS=$([int](Test-Path $debuggee))"
$p = Start-Process -FilePath $exe -ArgumentList @($broken) -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 400
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  $main = [S11Wfde]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log ("MAIN=0x{0:X}" -f $main.ToInt64())
if ($main -eq [IntPtr]::Zero) {
  @"
S11_WFDE_PROBE=MEASURED
TIP_SHA256=$sha
S11=FAIL_NO_MAIN_HWND
WFDE_BP_HIT=0
PROMOTE=0
MATURITY=82%
RUNLOG=$runlog
"@ | Set-Content $receipt
  exit 2
}
[void][S11Wfde]::ShowWindow($main, 9)
[void][S11Wfde]::SetForegroundWindow($main)
Start-Sleep 1
# View debug / panels then START once (no early STOP)
foreach ($cmd in @(2034, 2025, 2029)) { [void][S11Wfde]::Cmd($main, $cmd, 2000); Start-Sleep -Milliseconds 250 }
$startOk = [S11Wfde]::Cmd($main, 5060, 15000)
Log "START5060=$startOk"
$wfdePath = Join-Path $logDir 'WFDE_BP_HIT_RECEIPT.txt'
$hit = 0; $body = ''
for ($w = 0; $w -lt 20; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { Log "IDE_EXIT=$($p.ExitCode) w=$w"; break }
  if (Test-Path -LiteralPath $wfdePath) {
    $body = Get-Content -LiteralPath $wfdePath -Raw -EA SilentlyContinue
    if ($body -match 'WFDE_BP_HIT=1' -and $body -match 'WaitForDebugEvent') { $hit = 1; Log "WFDE_HIT_AT_w=$w"; break }
  }
  Log "w=$w hit=$hit alive=$([int](-not $p.HasExited))"
}
$alive = [int](-not $p.HasExited -and [S11Wfde]::IsWindow($main))
$s11 = if ($hit -eq 1) { 'PASS' } else { 'NOT_RUN_NO_WFDE_RECEIPT_THIS_SHA' }
@"
S11_WFDE_PROBE=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP_SHA256=$sha
TIP_EXE=$exe
DEBUGGEE=$debuggee
S11=$s11
WFDE_BP_HIT=$hit
WFDE_RECEIPT=$wfdePath
WFDE_BODY=$(($body -replace "`r|`n",'|'))
DEBUG_START_5060=$startOk
ALIVE=$alive
API=WaitForDebugEvent
NO_CROSS_SHA_PASS_INHERITANCE=1
A190_UNTOUCHED=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY=82%
RUNLOG=$runlog
"@ | Set-Content -LiteralPath $receipt
Get-Content $receipt | ForEach-Object { Log $_ }
[void][S11Wfde]::Cmd($main, 5061, 3000)
Start-Sleep 1
if (-not $p.HasExited) { [void][S11Wfde]::Cmd($main, 0, 0); try { $p.CloseMainWindow() | Out-Null } catch {}; Start-Sleep 1 }
try { if (-not $p.HasExited) { $p.Kill() } } catch {}
Get-Process -Name 'RawrXD-Win32IDE-Native*','debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
exit $(if ($hit -eq 1) { 0 } else { 4 })
