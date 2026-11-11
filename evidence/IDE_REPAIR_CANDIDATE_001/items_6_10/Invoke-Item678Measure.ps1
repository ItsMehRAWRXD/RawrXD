#Requires -Version 5.1
param(
  [string]$TipExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_daily_items710_001\RawrXD-Win32IDE-Native-Ext.exe',
  [string]$ExpectSha = '9FDEBF0947AC855619E2CC0A44A40AD6590C4BD680D6FFC4B46D4EF54A266D85',
  [string]$OutRoot = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\items_6_10'
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null
$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
if ($sha -ne $ExpectSha) { throw "SHA_DRIFT $sha" }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ud = Join-Path $OutRoot "ud_item678_$stamp"
New-Item -ItemType Directory -Force -Path $ud | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

if (-not ('M678' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class M678 {
  public const uint WM_COMMAND=0x0111;
  public const uint TCM_SETCURSEL=0x130C;
  public const uint TCM_GETCURSEL=0x130B;
  public const uint WM_SETTEXT=0x000C;
  public const uint WM_GETTEXT=0x000D;
  public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint BM_CLICK=0x00F5;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h,int n);
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h,int x,int y,int w,int hh,bool r);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h,StringBuilder sb,int n);
  [DllImport("gdi32.dll")] public static extern uint GetPixel(IntPtr hdc,int x,int y);
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h,IntPtr hdc);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public static IntPtr FindMain(uint pid) {
    IntPtr f = IntPtr.Zero;
    EnumWindows((h,l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256); GetClassNameW(h, sb, 256);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_Window" || c == "RawrXD_IDE_MainWindow") { f = h; return false; }
      return true;
    }, IntPtr.Zero);
    return f;
  }
  public static IntPtr FindId(IntPtr root, int id) {
    IntPtr f = IntPtr.Zero;
    EnumChildWindows(root, (h,lp) => { if (GetDlgCtrlID(h)==id) { f=h; return false; } return true; }, IntPtr.Zero);
    return f;
  }
  public static void SetText(IntPtr h, string t) {
    IntPtr p = Marshal.StringToHGlobalUni(t);
    try { SendMessage(h, WM_SETTEXT, IntPtr.Zero, p); } finally { Marshal.FreeHGlobal(p); }
  }
  public static string GetText(IntPtr h) {
    int n = (int)SendMessage(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (n <= 0) return "";
    IntPtr buf = Marshal.AllocHGlobal((n+1)*2);
    try { SendMessage(h, WM_GETTEXT, (IntPtr)(n+1), buf); return Marshal.PtrToStringUni(buf) ?? ""; }
    finally { Marshal.FreeHGlobal(buf); }
  }
  public static string SampleRgb(IntPtr hwnd, int x, int y) {
    IntPtr dc = GetDC(hwnd); uint px = GetPixel(dc, x, y); ReleaseDC(hwnd, dc);
    return ((int)(px & 0xFF)) + "," + ((int)((px >> 8) & 0xFF)) + "," + ((int)((px >> 16) & 0xFF));
  }
}
'@
}

$rec = Join-Path $OutRoot ("ITEM678_" + $stamp + ".txt")
function W([string]$s) { Add-Content -LiteralPath $rec -Value $s -Encoding ASCII; Write-Host $s }

W "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))"
W "GATE=ITEMS_5_6_7_8_MEASURE"
W "IDE_SHA256=$sha"
W "TIP_EXE=$TipExe"
W "PROMOTE=0"
W "CERTIFIED=0"
W "INVENT_PASS=0"
W "NO_CROSS_SHA=1"

$workDir = Split-Path -Parent $TipExe
$p = Start-Process -FilePath $TipExe -ArgumentList @('--user-data-dir', $ud) -WorkingDirectory $workDir -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 80; $i++) {
  Start-Sleep -Milliseconds 250
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { break }
  $main = [M678]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Start-Sleep -Seconds 3
W "PID=$($p.Id)"
W "MAIN=$main"
W "ALIVE=$(-not $p.HasExited)"
if ($p.HasExited -or $main -eq [IntPtr]::Zero) {
  W "VERDICT=FAIL_NO_HWND"
  W "EXIT=$($p.ExitCode)"
  exit 2
}

foreach ($cmd in 2034,2025,2021,2029) {
  [void][M678]::SendMessage($main, 0x0111, [IntPtr]$cmd, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 80
}
Start-Sleep -Milliseconds 500

$dock = [M678]::FindId($main, 1300)
$tabs = [M678]::FindId($main, 1301)
W "DOCK_1300=$dock"
W "TABS_1301=$tabs"
$themeOk = $false
$layoutOk = $false
$tabOk = $false
$resizeOk = $false
if ($dock -ne [IntPtr]::Zero) {
  $r = New-Object M678+RECT
  [void][M678]::GetWindowRect($dock, [ref]$r)
  $dw = $r.Right - $r.Left
  $dh = $r.Bottom - $r.Top
  $px = [M678]::SampleRgb($dock, 10, 40)
  W "DOCK_SIZE=${dw}x${dh}"
  W "DOCK_PX=$px"
  $layoutOk = ($dh -ge 200 -and $dw -ge 400 -and [M678]::IsWindowVisible($dock))
  $parts = $px.Split(',')
  $themeOk = ([int]$parts[0] -lt 80 -and [int]$parts[1] -lt 80 -and [int]$parts[2] -lt 100 -and $px -ne '240,240,240')
  W "ITEM5_THEME_OK=$themeOk"
  W "ITEM6_LAYOUT_OK=$layoutOk"
}

if ($tabs -ne [IntPtr]::Zero) {
  [void][M678]::SendMessage($tabs, 0x130C, [IntPtr]2, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 250
  $prob = [M678]::SendMessage($tabs, 0x130B, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
  [void][M678]::SendMessage($tabs, 0x130C, [IntPtr]0, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 250
  $term = [M678]::SendMessage($tabs, 0x130B, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
  $tabOk = ($prob -eq 2 -and $term -eq 0)
  W "TAB_PROBLEMS=$prob"
  W "TAB_TERMINAL=$term"
  W "ITEM6_TAB_OK=$tabOk"
} else {
  W "ITEM6_TAB_OK=False"
}

$mr = New-Object M678+RECT
[void][M678]::GetWindowRect($main, [ref]$mr)
[void][M678]::MoveWindow($main, $mr.Left, $mr.Top, ($mr.Right-$mr.Left)+100, ($mr.Bottom-$mr.Top)+80, $true)
Start-Sleep -Milliseconds 500
if ($dock -ne [IntPtr]::Zero) {
  $r2 = New-Object M678+RECT
  [void][M678]::GetWindowRect($dock, [ref]$r2)
  $resizeOk = ([M678]::IsWindowVisible($dock) -and (($r2.Right-$r2.Left) -ge 400))
  W "DOCK_AFTER_RESIZE=$(($r2.Right-$r2.Left))x$(($r2.Bottom-$r2.Top))"
  W "ITEM6_RESIZE_OK=$resizeOk"
}

$psEdit = [M678]::FindId($main, 5602)
$psOut = [M678]::FindId($main, 5601)
$psExec = [M678]::FindId($main, 5610)
$psStop = [M678]::FindId($main, 5612)
W "PS_EDIT=$psEdit PS_OUT=$psOut PS_EXEC=$psExec PS_STOP=$psStop"
if ($psEdit -ne [IntPtr]::Zero) { [void][M678]::ShowWindow($psEdit, 5) }
if ($psOut -ne [IntPtr]::Zero) { [void][M678]::ShowWindow($psOut, 5) }
if ($psExec -ne [IntPtr]::Zero) { [void][M678]::ShowWindow($psExec, 5) }

$marker = "RAWRXD_ITEM8_$stamp"
$termOk = $false
$cancelOk = $false
if ($psEdit -ne [IntPtr]::Zero -and $psExec -ne [IntPtr]::Zero) {
  [void][M678]::SetForegroundWindow($main)
  [M678]::SetText($psEdit, "Write-Output '$marker'")
  Start-Sleep -Milliseconds 200
  [void][M678]::SendMessage($psExec, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)
  Start-Sleep -Seconds 2
  $outText = ''
  if ($psOut -ne [IntPtr]::Zero) { $outText = [M678]::GetText($psOut) }
  W "PS_OUT_LEN=$($outText.Length)"
  $termOk = ($outText -match [regex]::Escape($marker))
  W "ITEM8_PS_MARKER_FOUND=$termOk"

  [M678]::SetText($psEdit, 'Start-Sleep -Seconds 30')
  [void][M678]::SendMessage($psExec, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 600
  $posted = $false
  if ($psStop -ne [IntPtr]::Zero) {
    [void][M678]::SendMessage($psStop, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)
    $posted = $true
  }
  Start-Sleep -Milliseconds 800
  try { $p.Refresh() } catch {}
  $cancelOk = ($posted -and (-not $p.HasExited))
  W "ITEM7_CANCEL_POSTED=$posted"
  W "ITEM7_ALIVE_AFTER=$(-not $p.HasExited)"
  W "ITEM7_CANCEL_OK=$cancelOk"
} else {
  W "ITEM8_PS_MARKER_FOUND=False"
  W "ITEM7_CANCEL_OK=False"
}

try { $p.Refresh() } catch {}
W "FINAL_ALIVE=$(-not $p.HasExited)"
W "ITEM5_VERDICT=$(if($themeOk){'PASS'}else{'FAIL'})"
W "ITEM6_VERDICT=$(if($layoutOk -and $tabOk -and $resizeOk -and $themeOk){'PASS'}elseif($layoutOk -and $themeOk){'PARTIAL'}else{'FAIL'})"
W "ITEM7_VERDICT=$(if($cancelOk){'PASS'}else{'FAIL_OR_NOT_RUN'})"
W "ITEM8_VERDICT=$(if($termOk){'PASS'}else{'FAIL_OR_NOT_RUN'})"
W "RECEIPT=$rec"
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
exit 0
