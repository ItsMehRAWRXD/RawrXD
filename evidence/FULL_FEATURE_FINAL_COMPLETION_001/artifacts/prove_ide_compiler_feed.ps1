# IDE-only compiler feed proof. Does NOT claim tip promote. CONTROLLING=CC79. PROMOTE=0.
$ErrorActionPreference = 'Continue'
$tipDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_005'
$TipExe = Join-Path $tipDir 'RawrXD-Win32IDE-Native-Ext.exe'
$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts'
$BrokenCpp = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp'
$Receipt = Join-Path $OutDir 'COMPILER_CAPTURE_RECEIPT.txt'
$IdeReceipt = Join-Path $OutDir 'IDE_COMPILER_FEED_RECEIPT.txt'
$LogDir = Join-Path $tipDir 'gui_probe_logs'
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class IdeCap2 {
  public const uint WM_COMMAND=0x0111; public const uint LVM_GETITEMCOUNT=0x1004;
  public const uint SMTO_ABORTIFHUNG=0x0002; public const uint SMTO_NORMAL=0x0000;
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public static IntPtr FindMain(uint pid) {
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,256);
      if(sb.ToString()=="RawrXD_IDE_Window"){ found=h; return false;} return true; }, IntPtr.Zero);
    return found;
  }
  public static string Title(IntPtr h){ var sb=new StringBuilder(512); GetWindowTextW(h,sb,512); return sb.ToString(); }
  public static IntPtr FindById(IntPtr root, int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static bool CmdSend(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static bool CmdPost(IntPtr main,int id){ return PostMessageW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero); }
  public static int ListCount(IntPtr root,int id,uint ms){ IntPtr h=FindById(root,id); if(h==IntPtr.Zero) return -1; IntPtr r; if(SendMessageTimeoutW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,ms,out r)==IntPtr.Zero) return -3; return r.ToInt32(); }
}
"@

Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'RawrXD*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
Start-Sleep 2
Remove-Item $Receipt,'F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log' -Force -EA SilentlyContinue
$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
for ($i=0; $i -lt 90; $i++) {
  Start-Sleep -Milliseconds 500
  if ($p.HasExited) { break }
  $main = [IdeCap2]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero -and [IdeCap2]::IsWindowVisible($main)) { break }
}
# Settle UI thread before Tools→Build (3014) so SendMessageTimeout is not aborted.
Start-Sleep 3
$title = if ($main -ne [IntPtr]::Zero) { [IdeCap2]::Title($main) } else { '' }
$buildOk = $false
$buildMode = 'none'
if ($main -ne [IntPtr]::Zero) {
  for ($t=0; $t -lt 5 -and -not $buildOk; $t++) {
    $buildOk = [IdeCap2]::CmdSend($main, 3014, 15000)
    if ($buildOk) { $buildMode = 'SendMessageTimeout'; break }
    Start-Sleep 1
  }
  if (-not $buildOk) {
    $buildOk = [IdeCap2]::CmdPost($main, 3014)
    if ($buildOk) { $buildMode = 'PostMessage' }
  }
}
$deadline = (Get-Date).AddSeconds(130)
$items = 0
$diag = 0
$exitDisp = 'running'
$hwndUpdated = $false
while ((Get-Date) -lt $deadline) {
  Start-Sleep 2
  if (Test-Path $Receipt) {
    $txt = Get-Content $Receipt -Raw
    $diag = ([regex]::Matches($txt, 'DIAGNOSTIC_PARSED')).Count
    if ($txt -match 'BUILD_RESULT=(\w+)') { $exitDisp = $Matches[1] }
    if ($txt -match 'PROBLEMS_HWND_UPDATED') { $hwndUpdated = $true }
  }
  if (-not $p.HasExited -and $main -ne [IntPtr]::Zero -and [IdeCap2]::IsWindow($main)) {
    $items = [IdeCap2]::ListCount($main, 1312, 2000)
    if ($items -gt 0) { $hwndUpdated = $true }
  }
  if ($diag -gt 0 -and $items -gt 0 -and ($exitDisp -ne 'running')) { break }
  if ($diag -gt 0 -and $items -gt 0) { break }
  if ($p.HasExited -and (Test-Path $Receipt) -and ((Get-Content $Receipt -Raw) -match 'PROCESS_EXIT')) { break }
}
if (-not $p.HasExited) { try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {} }
$titleEnd = if ($main -ne [IntPtr]::Zero -and [IdeCap2]::IsWindow($main)) { [IdeCap2]::Title($main) } else { $title }
$recTxt = if (Test-Path $Receipt) { Get-Content $Receipt -Raw } else { '' }
$stdoutLines = ([regex]::Matches($recTxt, 'STDOUT_LINE')).Count
$problemAdded = ([regex]::Matches($recTxt, 'PROBLEM_ADDED')).Count
@"
IDE_COMPILER_FEED=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
CONTROLLING_TIP=CC79
CANDIDATE_SHA256=$sha
CANDIDATE_NOT_PROMOTED=1
TIP_EXE=$TipExe
TITLE=$titleEnd
BUILD_CMD_3014=$buildOk
BUILD_CMD_MODE=$buildMode
COMPILER_EXECUTION=$(if($recTxt -match 'PROCESS_STARTED'){'VERIFIED'}else{'NOT_VERIFIED'})
COMPILER_OUTPUT_CAPTURE=$(if($stdoutLines -gt 1){'VERIFIED'}else{'NOT_VERIFIED'})
DIAGNOSTIC_FEED=$(if($diag -gt 0){'VERIFIED'}else{'NOT_VERIFIED'})
DIAGNOSTIC_PARSED_COUNT=$diag
PROBLEM_ADDED_COUNT=$problemAdded
STDOUT_LINE_COUNT=$stdoutLines
PROBLEMS_ID1312_ITEMS=$items
PROBLEMS_HWND_UPDATED=$hwndUpdated
BUILD_RESULT_DISPOSITION=$exitDisp
PROCESS_EXIT_SEEN=$($recTxt -match 'PROCESS_EXIT')
BOUNDARY_BUILD_REQUEST=$($recTxt -match 'BUILD_REQUEST')
BOUNDARY_PROCESS_CREATE=$($recTxt -match 'PROCESS_CREATE')
BOUNDARY_PROCESS_STARTED=$($recTxt -match 'PROCESS_STARTED')
BOUNDARY_STDOUT_LINE=$($recTxt -match 'STDOUT_LINE')
BOUNDARY_STDERR_LINE=$($recTxt -match 'STDERR_LINE')
BOUNDARY_PROCESS_EXIT=$($recTxt -match 'PROCESS_EXIT')
BOUNDARY_DIAGNOSTIC_PARSED=$($recTxt -match 'DIAGNOSTIC_PARSED')
BOUNDARY_PROBLEM_ADDED=$($recTxt -match 'PROBLEM_ADDED')
BOUNDARY_BUILD_RESULT=$($recTxt -match 'BUILD_RESULT')
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
RECEIPT=$Receipt
"@ | Set-Content -LiteralPath $IdeReceipt -Encoding UTF8
Write-Host (Get-Content $IdeReceipt -Raw)
if ($diag -le 0) { exit 2 }
exit 0

