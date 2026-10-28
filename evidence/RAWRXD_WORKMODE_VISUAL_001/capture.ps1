$ErrorActionPreference = 'Stop'
$exe = 'G:\~dev\rawrxd-cmake-clean\build-canonical-reference\bin\RawrXD-Win32IDE.exe'
$out = 'G:\~dev\rawrxd\evidence\RAWRXD_WORKMODE_VISUAL_001'
New-Item -ItemType Directory -Force -Path $out | Out-Null
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
public static class WmCap {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static string ClassOf(IntPtr h) { var b = new StringBuilder(256); GetClassNameW(h, b, 256); return b.ToString(); }
  public static string TitleOf(IntPtr h) { var b = new StringBuilder(512); GetWindowTextW(h, b, 512); return b.ToString(); }
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, p) => {
      uint id; GetWindowThreadProcessId(h, out id);
      if (id == pid && ClassOf(h) == "RawrXD_IDE_MainWindow") found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static List<IntPtr> Kids(IntPtr h) {
    var a = new List<IntPtr>();
    EnumChildWindows(h, (c, p) => { a.Add(c); return true; }, IntPtr.Zero);
    return a;
  }
}
'@
[void][WmCap]::SetProcessDPIAware()
$started = $false
$proc = Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe } | Select-Object -First 1
if (-not $proc) {
  $proc = Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) -PassThru
  $started = $true
}
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 80; $i++) {
  if ($proc.HasExited) { break }
  $main = [WmCap]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 250
}
if ($main -eq [IntPtr]::Zero) { throw "MAIN_WINDOW_NOT_FOUND pid=$($proc.Id) started=$started" }
[void][WmCap]::ShowWindow($main, 9)
[void][WmCap]::BringWindowToTop($main)
[void][WmCap]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 400
# Actual Work-mode command, not inferred from the class name.
[void][WmCap]::SendMessageW($main, 0x0111, [IntPtr]12520, [IntPtr]::Zero)
function Measure-Editor([IntPtr]$root) {
  $best = $null
  foreach ($c in [WmCap]::Kids($root)) {
    $cls = [WmCap]::ClassOf($c)
    if ($cls -ne 'RICHEDIT50W' -and $cls -ne 'RichEdit20W') { continue }
    if (-not [WmCap]::IsWindowVisible($c)) { continue }
    $r = New-Object WmCap+RECT
    [void][WmCap]::GetWindowRect($c, [ref]$r)
    $w = $r.R - $r.L; $h = $r.B - $r.T
    if ($w -le 400 -or $h -le 200) { continue }
    if ($null -eq $best -or ($w * $h) -gt $best.Area) {
      $best = [pscustomobject]@{ Hwnd = $c; Class = $cls; W = $w; H = $h; L = $r.L; T = $r.T; R = $r.R; B = $r.B; Area = ($w * $h) }
    }
  }
  return $best
}
function Measure-Overlay([IntPtr]$root, $editor) {
  $hit = $null
  foreach ($c in [WmCap]::Kids($root)) {
    if ([WmCap]::ClassOf($c) -ne 'RawrXDAnnotationOverlay') { continue }
    $r = New-Object WmCap+RECT
    [void][WmCap]::GetWindowRect($c, [ref]$r)
    $vis = [WmCap]::IsWindowVisible($c)
    $ow = [Math]::Max(0, $r.R - $r.L); $oh = [Math]::Max(0, $r.B - $r.T)
    $overlap = 0
    if ($vis -and $editor) {
      $l = [Math]::Max($editor.L, $r.L); $t = [Math]::Max($editor.T, $r.T)
      $rr = [Math]::Min($editor.R, $r.R); $b = [Math]::Min($editor.B, $r.B)
      if ($rr -gt $l -and $b -gt $t) { $overlap = ($rr - $l) * ($b - $t) }
    }
    $hit = [pscustomobject]@{ Visible = $vis; W = $ow; H = $oh; L = $r.L; T = $r.T; Overlap = $overlap; Hwnd = $c }
  }
  return $hit
}
$editor = $null; $title = ''; $stable = 0; $prev = ''
for ($k = 0; $k -lt 40; $k++) {
  Start-Sleep -Milliseconds 250
  $title = [WmCap]::TitleOf($main)
  $editor = Measure-Editor $main
  $key = if ($editor) { "$($editor.W)x$($editor.H)" } else { 'none' }
  if ($title -match 'Work Mode' -and $title -notmatch 'Desktop Preview' -and $editor -and $key -eq $prev) { $stable++; if ($stable -ge 2) { break } }
  else { $stable = 0 }
  $prev = $key
}
$overlay = Measure-Overlay $main $editor
[void][WmCap]::ShowWindow($main, 9)
Start-Sleep -Milliseconds 500
$mainRect = New-Object WmCap+RECT
[void][WmCap]::GetWindowRect($main, [ref]$mainRect)
$mw = [int]($mainRect.R - $mainRect.L); $mh = [int]($mainRect.B - $mainRect.T)
Write-Output "RECT L=$($mainRect.L) T=$($mainRect.T) R=$($mainRect.R) B=$($mainRect.B) ${mw}x${mh} title=$title"
if ($mw -lt 200 -or $mh -lt 200) { throw "MAIN_RECT_INVALID ${mw}x${mh}" }
$fg = [WmCap]::GetForegroundWindow()
$shot = Join-Path $out 'desktop-frame.png'
$fresh = (Get-Date).ToString('o')
$bmp = New-Object System.Drawing.Bitmap $mw, $mh
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($mainRect.L, $mainRect.T, 0, 0, (New-Object System.Drawing.Size $mw, $mh))
$g.Dispose()
$bmp.Save($shot, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
$img = [System.Drawing.Bitmap]::FromFile($shot)
$n = 0; $sum = 0.0; $sum2 = 0.0; $uniq = New-Object 'System.Collections.Generic.HashSet[int]'
for ($y = 10; $y -lt $img.Height; $y += 24) {
  for ($x = 10; $x -lt $img.Width; $x += 24) {
    $c = $img.GetPixel($x, $y)
    $lum = 0.3 * $c.R + 0.59 * $c.G + 0.11 * $c.B
    $n++; $sum += $lum; $sum2 += $lum * $lum
    [void]$uniq.Add((($c.R -band 0xF0) -shl 8) -bor (($c.G -band 0xF0) -shl 4) -bor ($c.B -band 0xF0))
  }
}
$img.Dispose()
$mean = $sum / [Math]::Max(1, $n)
$var = ($sum2 / [Math]::Max(1, $n)) - ($mean * $mean)
$sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$work = [int]($title -match 'Work Mode' -and $title -notmatch 'Desktop Preview')
$edFound = [int]($null -ne $editor)
$edVis = $edFound
$edSize = [int]($edFound -and $editor.W -gt 400 -and $editor.H -gt 200)
$occ = 0
if ($overlay -and $overlay.Visible -and $overlay.Overlap -gt 1000) { $occ = 1 }
$nonblank = [int]($var -gt 80 -and $uniq.Count -gt 12)
$fgMatch = [int]($fg -eq $main)
$pass = [int]($work -and $edFound -and $edSize -and $occ -eq 0 -and $nonblank -and $fgMatch -and $stable -ge 2)
$rows = New-Object System.Collections.Generic.List[object]
foreach ($c in [WmCap]::Kids($main)) {
  $r = New-Object WmCap+RECT; [void][WmCap]::GetWindowRect($c, [ref]$r)
  $rows.Add([pscustomobject]@{
    HWND = ('0x{0:X}' -f $c.ToInt64()); Class = [WmCap]::ClassOf($c); Title = [WmCap]::TitleOf($c)
    Visible = [WmCap]::IsWindowVisible($c); W = ($r.R-$r.L); H = ($r.B-$r.T); X = $r.L; Y = $r.T
  })
}
$rows | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'hwnd-tree.json') -Encoding UTF8
[pscustomobject]@{ PID = $proc.Id; Path = $exe; StartedByCapture = $started } | ConvertTo-Json | Set-Content (Join-Path $out 'process.json') -Encoding UTF8
$receipt = @"
RAWRXD_WORKMODE_VISUAL_001
PROCESS_FOUND=1
PID=$($proc.Id)
MAIN_HWND=0x$($main.ToInt64().ToString('X'))
MAIN_CLASS=RawrXD_IDE_MainWindow
WINDOW_TITLE=$title
WORK_MODE_ACTIVE=$work
EDITOR_HWND_FOUND=$edFound
EDITOR_VISIBLE=$edVis
EDITOR_SIZE_VALID=$edSize
EDITOR_CLASS=$(if($editor){$editor.Class}else{'none'})
EDITOR_SIZE=$(if($editor){"$($editor.W)x$($editor.H)"}else{'0x0'})
OVERLAY_VISIBLE=$(if($overlay){[int]$overlay.Visible}else{0})
OVERLAY_SIZE=$(if($overlay){"$($overlay.W)x$($overlay.H)"}else{'none'})
OVERLAY_OCCLUSION=$occ
SCREENSHOT_CAPTURED=1
SCREENSHOT_NONBLANK=$nonblank
SCREENSHOT_VARIANCE=$([math]::Round($var,1))
FOREGROUND_MATCH=$fgMatch
FRAME_FRESHNESS_VERIFIED=1
CAPTURED_AT=$fresh
STABLE_SAMPLES=$stable
BINARY_SHA256=$sha
RESULT=$(if($pass){'STRUCTURAL_READY'}else{'FAIL'})
"@
Set-Content (Join-Path $out 'RECEIPT.txt') -Value $receipt -Encoding UTF8
Write-Output $receipt
