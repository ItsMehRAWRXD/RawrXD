#Requires -Version 5.1
# Dock theme/layout probe for Native-Ext tip. PROMOTE=0 INVENT_PASS=0 NO_CROSS_SHA.
param(
  [Parameter(Mandatory = $true)][string]$TipExe,
  [Parameter(Mandatory = $true)][string]$ExpectSha,
  [string]$OutRoot = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\p0_createwindow_fix'
)
$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
if ($sha -ne $ExpectSha) {
  Write-Host "SHA_DRIFT measured=$sha expected=$ExpectSha"
  exit 9
}
$ud = Join-Path $OutRoot "ud_dock_$stamp"
$receipt = Join-Path $OutRoot "DOCK_THEME_LAYOUT_$stamp.txt"
New-Item -ItemType Directory -Force -Path $ud, (Join-Path $ud 'logs') | Out-Null

Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices; using System.Collections.Generic;
public class DockThemeProbe {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr hdc);
  [DllImport("gdi32.dll")] public static extern uint GetPixel(IntPtr hdc, int x, int y);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int cx, int cy, bool r);
  [DllImport("user32.dll")] public static extern uint GetSysColor(int i);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
  public const int GWL_ID = -12;
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p); if (p != pid) return true;
      var cls = new StringBuilder(256); GetClassNameW(h, cls, 256);
      if (cls.ToString() == "RawrXD_IDE_Window") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindChildById(IntPtr parent, int id) {
    IntPtr via = GetDlgItem(parent, id);
    if (via != IntPtr.Zero) return via;
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, (h, l) => {
      if (GetWindowLongW(h, GWL_ID) == id) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static string SizeOf(IntPtr h) {
    RECT r; GetClientRect(h, out r); return (r.R - r.L) + "x" + (r.B - r.T);
  }
  public static uint SamplePoint(IntPtr h, int x, int y) {
    IntPtr hdc = GetDC(h); uint pix = GetPixel(hdc, x, y); ReleaseDC(h, hdc); return pix;
  }
}
'@ -Language CSharp -ErrorAction Stop

$env:RAWRXD_USER_DATA_DIR = $ud
$env:RAWRXD_LOG_DIR = Join-Path $ud 'logs'
$proc = Start-Process -FilePath $TipExe -ArgumentList @("--user-data-dir=$ud") -PassThru -WindowStyle Normal
$hwnd = [IntPtr]::Zero
for ($i = 0; $i -lt 100; $i++) {
  Start-Sleep -Milliseconds 250
  try { $proc.Refresh() } catch {}
  if ($proc.HasExited) { break }
  $hwnd = [DockThemeProbe]::FindMain([uint32]$proc.Id)
  if ($hwnd -ne [IntPtr]::Zero -and $i -gt 24) { break }
}
Start-Sleep 3

$L = New-Object System.Collections.Generic.List[string]
$L.Add("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))")
$L.Add('GATE=DOCK_THEME_LAYOUT')
$L.Add("IDE_SHA256=$sha")
$L.Add("TIP_EXE=$TipExe")
$L.Add("USER_DATA_DIR=$ud")
$L.Add("PID=$($proc.Id)")
$L.Add("MAIN_HWND=$hwnd")
$L.Add('PROMOTE=0')
$L.Add('CERTIFIED=0')
$L.Add('INVENT_PASS=0')
$L.Add('NO_CROSS_SHA=1')
$L.Add('PRESENT=1')
$L.Add('ACCEPTED=0')

if ($hwnd -eq [IntPtr]::Zero -or $proc.HasExited) {
  $L.Add('LAUNCH=FAIL')
  $L.Add('VERDICT=DOCK_PROBE_FAIL')
} else {
  [void][DockThemeProbe]::ShowWindow($hwnd, 9)
  [void][DockThemeProbe]::SetForegroundWindow($hwnd)
  [void][DockThemeProbe]::MoveWindow($hwnd, 50, 50, 1500, 950, $true)
  Start-Sleep 1
  # IDM_VIEW_PANEL = 2034 (show-only)
  [void][DockThemeProbe]::PostMessageW($hwnd, 0x0111, [IntPtr]2034, [IntPtr]::Zero)
  Start-Sleep 1
  [void][DockThemeProbe]::PostMessageW($hwnd, 0x0005, [IntPtr]0, [IntPtr]((900 -shl 16) -bor 1480))
  Start-Sleep 1

  $colorWindow = [DockThemeProbe]::GetSysColor(5)
  $dock = [DockThemeProbe]::FindChildById($hwnd, 1300)
  $tabs = [DockThemeProbe]::FindChildById($hwnd, 1301)
  $plist = [DockThemeProbe]::FindChildById($hwnd, 1312)
  $ps = [DockThemeProbe]::FindChildById($hwnd, 5600)
  $psi = [DockThemeProbe]::FindChildById($hwnd, 5602)

  $dockSz = if ($dock -ne [IntPtr]::Zero) { [DockThemeProbe]::SizeOf($dock) } else { '0x0' }
  $dockVis = ($dock -ne [IntPtr]::Zero) -and [DockThemeProbe]::IsWindowVisible($dock)
  $L.Add(('COLOR_WINDOW_SYS=0x{0:X6}' -f $colorWindow))
  $L.Add("DOCK_PRESENT=$($dock -ne [IntPtr]::Zero)")
  $L.Add("DOCK_VISIBLE=$dockVis")
  $L.Add("DOCK_SIZE=$dockSz")

  $themePass = $false
  $themeNote = 'NO_DOCK'
  if ($dock -ne [IntPtr]::Zero) {
    $pix = [DockThemeProbe]::SamplePoint($dock, 10, 12)
    $r = $pix -band 0xFF; $g = ($pix -shr 8) -band 0xFF; $b = ($pix -shr 16) -band 0xFF
    $sysR = $colorWindow -band 0xFF; $sysG = ($colorWindow -shr 8) -band 0xFF; $sysB = ($colorWindow -shr 16) -band 0xFF
    $isSys = ($r -eq $sysR -and $g -eq $sysG -and $b -eq $sysB)
    $luma = 0.299 * $r + 0.587 * $g + 0.114 * $b
    $themePass = (-not $isSys) -and ($luma -lt 80)
    $themeNote = ('pix=0x{0:X6} rgb={1},{2},{3} luma={4:N1} isSysGray={5}' -f $pix, $r, $g, $b, $luma, $isSys)
  }
  $L.Add("DOCK_PIXEL=$themeNote")
  $L.Add("DOCK_THEME_NOT_SYS_GRAY=$themePass")

  $dockH = 0
  if ($dockSz -match 'x(\d+)$') { $dockH = [int]$Matches[1] }
  $L.Add("DOCK_HEIGHT=$dockH")
  $L.Add("DOCK_HEIGHT_GE_160=$($dockH -ge 160)")

  $tabOk = $false
  $tabNote = 'NO_TABS'
  if ($tabs -ne [IntPtr]::Zero) {
    $sels = @()
    foreach ($sel in @(0, 2, 1, 0)) {
      [void][DockThemeProbe]::SendMessageW($tabs, 0x130C, [IntPtr]$sel, [IntPtr]::Zero)
      Start-Sleep -Milliseconds 200
      $sels += [DockThemeProbe]::SendMessageW($tabs, 0x130B, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
    }
    $tabOk = ($sels -contains 0) -and ($sels -contains 2) -and ($sels -contains 1)
    $tabNote = 'sels=' + ($sels -join ',')
  }
  $L.Add("TABS_PRESENT=$($tabs -ne [IntPtr]::Zero)")
  $L.Add("TABS_CLICKABLE=$tabOk")
  $L.Add("TABS_NOTE=$tabNote")

  if ($tabs -ne [IntPtr]::Zero) {
    [void][DockThemeProbe]::SendMessageW($tabs, 0x130C, [IntPtr]2, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
  }
  $plist = [DockThemeProbe]::FindChildById($hwnd, 1312)
  $plistVis = ($plist -ne [IntPtr]::Zero) -and [DockThemeProbe]::IsWindowVisible($plist)
  $L.Add("PROBLEMS_1312_PRESENT=$($plist -ne [IntPtr]::Zero)")
  $L.Add("PROBLEMS_1312_VISIBLE=$plistVis")
  if ($plist -ne [IntPtr]::Zero) {
    $L.Add("PROBLEMS_1312_SIZE=$([DockThemeProbe]::SizeOf($plist))")
    $L.Add("PROBLEMS_ITEMCOUNT=$([DockThemeProbe]::SendMessageW($plist, 0x1004, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32())")
  }
  $L.Add("POWERSHELL_5600_PRESENT=$($ps -ne [IntPtr]::Zero)")
  $L.Add("POWERSHELL_5600_VISIBLE=$(if ($ps -ne [IntPtr]::Zero) { [DockThemeProbe]::IsWindowVisible($ps) } else { $false })")
  $L.Add("PS_INPUT_5602_PRESENT=$($psi -ne [IntPtr]::Zero)")

  $alive = -not $proc.HasExited
  $L.Add("PROCESS_ALIVE_AFTER_LAYOUT=$alive")
  $layoutPass = $dockVis -and ($dockH -ge 160)
  $L.Add("THEME_VERDICT=$(if ($themePass) { 'THEME_PASS' } else { 'THEME_FAIL_OR_UNMEASURED' })")
  $L.Add("LAYOUT_VERDICT=$(if ($layoutPass) { 'LAYOUT_PASS' } elseif ($dockVis) { 'LAYOUT_COLLAPSED_LT_160' } else { 'LAYOUT_FAIL' })")
  $L.Add("TABS_VERDICT=$(if ($tabOk) { 'TABS_PASS' } else { 'TABS_FAIL' })")
  $overall = if ($themePass -and $layoutPass -and $tabOk) {
    'DOCK_THEME_LAYOUT_PASS'
  } elseif ($themePass -and $tabOk -and $dockVis) {
    'DOCK_THEME_PASS_LAYOUT_COLLAPSED'
  } else {
    'DOCK_PROBE_PARTIAL_OR_FAIL'
  }
  $L.Add("VERDICT=$overall")
}

$L | Set-Content -LiteralPath $receipt -Encoding UTF8
try {
  if (-not $proc.HasExited) {
    $proc.CloseMainWindow() | Out-Null
    $null = $proc.WaitForExit(8000)
  }
} catch {}
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Write-Host "RECEIPT=$receipt"
Get-Content -LiteralPath $receipt
exit 0
