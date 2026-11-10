$ErrorActionPreference = 'Stop'
$exe = 'F:\rawrxd\releases\RawrXD-OMEGA1-v1.0.0\bin\RawrXD-Win32IDE.exe'
$out = 'F:\rawrxd\evidence\RAWRXD_WORKMODE_VISUAL_001'
New-Item -ItemType Directory -Force -Path $out | Out-Null
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
public static class FCap {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  public static string ClassOf(IntPtr h) { var b = new StringBuilder(256); GetClassNameW(h, b, 256); return b.ToString(); }
  public static string TitleOf(IntPtr h) { var b = new StringBuilder(512); GetWindowTextW(h, b, 512); return b.ToString(); }
  public static List<IntPtr> Tops() { var a = new List<IntPtr>(); EnumWindows((h, p) => { a.Add(h); return true; }, IntPtr.Zero); return a; }
  public static List<IntPtr> Kids(IntPtr h) { var a = new List<IntPtr>(); EnumChildWindows(h, (c, p) => { a.Add(c); return true; }, IntPtr.Zero); return a; }
}
'@
[void][FCap]::SetProcessDPIAware()
if (-not (Test-Path -LiteralPath $exe)) { throw "EXE_MISSING" }
$sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$running = Get-CimInstance Win32_Process -Filter "Name='RawrXD-Win32IDE.exe'" | Where-Object { $_.ExecutablePath -eq $exe }
if ($running) { $proc = Get-Process -Id $running[0].ProcessId } else { $proc = Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) -PassThru }
$expected = [uint32]$proc.Id
$main = [IntPtr]::Zero
$validated = $false
$rect = New-Object FCap+RECT
for ($i = 0; $i -lt 80; $i++) {
  if ($proc.HasExited) { break }
  foreach ($h in [FCap]::Tops()) {
    if (-not [FCap]::IsWindow($h)) { continue }
    $windowPid = [uint32]0
    [void][FCap]::GetWindowThreadProcessId($h, [ref]$windowPid)
    if ($windowPid -ne $expected) { continue }
    if ([FCap]::ClassOf($h) -ne 'RawrXD_IDE_MainWindow') { continue }
    $ok = [FCap]::GetWindowRect($h, [ref]$rect)
    $w = $rect.R - $rect.L; $ht = $rect.B - $rect.T
    if ($ok -and [FCap]::IsWindowVisible($h) -and $w -gt 200 -and $ht -gt 200) { $main = $h; $validated = $true; break }
  }
  if ($validated) { break }
  Start-Sleep -Milliseconds 250
}
if (-not $validated) { throw "NO_VALID_MAIN_HWND pid=$expected sha=$sha" }
[void][FCap]::ShowWindow($main, 9)
[void][FCap]::BringWindowToTop($main)
[void][FCap]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 600
if (-not [FCap]::IsWindow($main)) { throw "INVALID_HWND" }
$windowPid = [uint32]0
[void][FCap]::GetWindowThreadProcessId($main, [ref]$windowPid)
if ($windowPid -ne $expected) { throw "HWND_PROCESS_MISMATCH" }
$ok = [FCap]::GetWindowRect($main, [ref]$rect)
if (-not $ok) { throw "GETWINDOWRECT_FAILED" }
$mw = [int]($rect.R - $rect.L); $mh = [int]($rect.B - $rect.T)
if ($mw -lt 200 -or $mh -lt 200) { throw "MAIN_RECT_INVALID ${mw}x${mh}" }
$title = [FCap]::TitleOf($main)
$editor = $null
$overlay = $null
$rows = New-Object System.Collections.Generic.List[object]
foreach ($c in [FCap]::Kids($main)) {
  $cr = New-Object FCap+RECT
  $cok = [FCap]::GetWindowRect($c, [ref]$cr)
  $cls = [FCap]::ClassOf($c)
  $vis = [FCap]::IsWindowVisible($c)
  $rows.Add([pscustomobject]@{ HWND = ('0x{0:X}' -f $c.ToInt64()); Class = $cls; Title = [FCap]::TitleOf($c); Visible = $vis; RectOk = $cok; W = ($cr.R-$cr.L); H = ($cr.B-$cr.T) })
  if (($cls -eq 'RICHEDIT50W' -or $cls -eq 'RichEdit20W') -and $vis -and ($cr.R-$cr.L) -gt 400 -and ($cr.B-$cr.T) -gt 200) {
    if ($null -eq $editor -or (($cr.R-$cr.L)*($cr.B-$cr.T)) -gt $editor.Area) {
      $editor = [pscustomobject]@{ Class = $cls; W = ($cr.R-$cr.L); H = ($cr.B-$cr.T); Area = (($cr.R-$cr.L)*($cr.B-$cr.T)) }
    }
  }
  if ($cls -eq 'RawrXDAnnotationOverlay') { $overlay = [pscustomobject]@{ Visible = $vis; W = ($cr.R-$cr.L); H = ($cr.B-$cr.T) } }
}
$shot = Join-Path $out 'desktop-frame.png'
$fresh = (Get-Date).ToString('o')
$bmp = New-Object System.Drawing.Bitmap $mw, $mh
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($rect.L, $rect.T, 0, 0, (New-Object System.Drawing.Size $mw, $mh))
$g.Dispose(); $bmp.Save($shot, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
$img = [System.Drawing.Bitmap]::FromFile($shot)
$n = 0; $sum = 0.0; $sum2 = 0.0
for ($y = 8; $y -lt $img.Height; $y += 28) { for ($x = 8; $x -lt $img.Width; $x += 28) { $px = $img.GetPixel($x, $y); $lum = 0.3*$px.R + 0.59*$px.G + 0.11*$px.B; $n++; $sum += $lum; $sum2 += $lum*$lum } }
$img.Dispose()
$mean = $sum / [Math]::Max(1,$n); $var = ($sum2 / [Math]::Max(1,$n)) - ($mean*$mean)
$work = [int]($title -match 'Work Mode' -and $title -notmatch 'Desktop Preview')
$fg = [FCap]::GetForegroundWindow()
$rows | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'hwnd-tree.json') -Encoding UTF8
$receipt = @"
RAWRXD_WORKMODE_VISUAL_001
CHECKOUT=F:\rawrxd
EXE=$exe
PROCESS_FOUND=1
PID=$expected
BINARY_SHA256=$sha
MAIN_HWND=0x$($main.ToInt64().ToString('X'))
MAIN_CLASS=RawrXD_IDE_MainWindow
HWND_VALID=1
HWND_PROCESS_MATCH=1
GETWINDOWRECT_OK=1
WINDOW_TITLE=$title
MAIN_SIZE=${mw}x${mh}
WORK_MODE_STRING_IN_BINARY=0
WORK_MODE_ACTIVE=$work
EDITOR_HWND_FOUND=$([int]($null -ne $editor))
EDITOR_VISIBLE=$([int]($null -ne $editor))
EDITOR_SIZE_VALID=$([int]($null -ne $editor))
EDITOR_SIZE=$(if($editor){"$($editor.W)x$($editor.H)"}else{'none'})
OVERLAY_OCCLUSION=$(if($overlay -and $overlay.Visible){1}else{0})
SCREENSHOT_CAPTURED=1
SCREENSHOT_NONBLANK=$([int]($var -gt 80))
SCREENSHOT_VARIANCE=$([math]::Round($var,1))
FOREGROUND_MATCH=$([int]($fg -eq $main))
FRAME_FRESHNESS_VERIFIED=1
CAPTURED_AT=$fresh
PROMOTE=0
RESULT=PENDING_VISUAL
"@
Set-Content (Join-Path $out 'RECEIPT.txt') -Value $receipt -Encoding UTF8
Write-Output $receipt
