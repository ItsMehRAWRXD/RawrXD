$ErrorActionPreference = "Continue"
$exe = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe"
$expect = "27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC"
$broken = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp"
$outDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts"
$logDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\output_probe_27e2"
$receipt = Join-Path $outDir "OUTPUT_HWND_LIVE_27E2_RECEIPT.txt"
New-Item -ItemType Directory -Force -Path $outDir, $logDir | Out-Null
Get-Process -Name "RawrXD-Win32IDE-Native*" -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
if ($sha -ne $expect) {
  "OUTPUT_HWND_LIVE=NOT_RUN`nREASON=SHA_DRIFT`nTIP_SHA256=$sha`nEXPECT=$expect`nPROMOTE=0" | Set-Content $receipt
  exit 3
}
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class Out27b {
  public const uint WM_COMMAND=0x0111; public const uint WM_GETTEXTLENGTH=0x000E; public const uint LVM_GETITEMCOUNT=0x1004;
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,256);
      if(sb.ToString()=="RawrXD_IDE_Window"){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static IntPtr FindId(IntPtr root,int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static int IdLen(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); }
  public static int IdList(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero); }
}
"@
$env:RAWRXD_LOG_DIR = $logDir
$env:RAWRXD_PROBLEMS_FIXTURE = $broken
$p = Start-Process -FilePath $exe -ArgumentList @($broken) -WorkingDirectory "F:\rawrxd" -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
for ($i=0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 400
  if ($p.HasExited) { break }
  $main = [Out27b]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
$id1604 = -1; $id1312 = -1; $id1012 = -1
if ($main -ne [IntPtr]::Zero) {
  [void][Out27b]::SendMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
  for ($w=0; $w -lt 30; $w++) {
    Start-Sleep 1
    if ($p.HasExited) { break }
    $id1312 = [Out27b]::IdList($main, 1312)
    $id1604 = [Out27b]::IdLen($main, 1604)
    $id1012 = [Out27b]::IdLen($main, 1012)
    if ($id1312 -gt 0) { break }
  }
}
$verdict = if ($id1604 -gt 0) { "PASS" } elseif ($id1604 -eq 0) { "FAIL_ZERO" } elseif ($id1604 -eq -1) { "FAIL_HWND_ABSENT" } else { "NOT_RUN" }
$a4f = (Get-FileHash "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe" -Algorithm SHA256).Hash
@(
"OUTPUT_HWND_LIVE=MEASURED",
"TIP_SHA256=$sha",
"PROBLEMS_ID1312_ITEMS=$id1312",
"OUTPUT_ID1604_LEN=$id1604",
"OUTPUT_ID1012_LEN=$id1012",
"OUTPUT_HWND=$verdict",
"MAIN_FOUND=$([int]($main -ne [IntPtr]::Zero))",
"A4F_UNTOUCHED=$([int]($a4f -eq 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E'))",
"FOUR_PANEL=NOT_RUN",
"DEBUG_UI=NOT_RUN",
"PROMOTE=0",
"CERTIFIED=0",
"PRODUCT_PASS=0"
) | Set-Content $receipt
Get-Content $receipt
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
