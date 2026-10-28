$ErrorActionPreference = 'Stop'
$src = 'G:\~dev\rawrxd-cmake-clean\build-canonical-reference\bin\RawrXD-Win32IDE.exe'
$out = 'G:\~dev\rawrxd\evidence\RAWRXD_UI_FORENSICS_001\shots'
New-Item -ItemType Directory -Force -Path $out | Out-Null
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Cap {
  public delegate bool EnumProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool attach);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern IntPtr GetWindowDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr dc);
  [DllImport("gdi32.dll")] public static extern bool BitBlt(IntPtr d, int x, int y, int w, int h, IntPtr s, int sx, int sy, uint rop);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, p) => {
      uint id; GetWindowThreadProcessId(h, out id);
      if (id != pid) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, 256);
      if (sb.ToString() == "RawrXD_IDE_MainWindow") found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static bool EditorVisible(IntPtr main) {
    bool vis = false;
    EnumChildWindows(main, (h, p) => {
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, 256);
      string c = sb.ToString();
      if ((c == "RICHEDIT50W" || c == "RichEdit20W") && IsWindowVisible(h)) {
        RECT r; GetWindowRect(h, out r);
        if ((r.R-r.L) > 400 && (r.B-r.T) > 200) vis = true;
      }
      return true;
    }, IntPtr.Zero);
    return vis;
  }
  public static string Title(IntPtr h) { var b = new StringBuilder(512); GetWindowTextW(h, b, 512); return b.ToString(); }
  public static void ChordW() {
    keybd_event(0x11, 0, 0, UIntPtr.Zero);
    keybd_event(0x10, 0, 0, UIntPtr.Zero);
    keybd_event(0x57, 0, 0, UIntPtr.Zero);
    keybd_event(0x57, 0, 2, UIntPtr.Zero);
    keybd_event(0x10, 0, 2, UIntPtr.Zero);
    keybd_event(0x11, 0, 2, UIntPtr.Zero);
  }
  public static void Focus(IntPtr h) {
    ShowWindow(h, 9);
    uint fgTid = 0, pid = 0;
    IntPtr fg = GetForegroundWindow();
    fgTid = GetWindowThreadProcessId(fg, out pid);
    uint me = GetCurrentThreadId();
    if (fgTid != 0 && fgTid != me) AttachThreadInput(me, fgTid, true);
    BringWindowToTop(h);
    SetForegroundWindow(h);
    if (fgTid != 0 && fgTid != me) AttachThreadInput(me, fgTid, false);
  }
}
'@

function Save-Capture([IntPtr]$hwnd, [string]$path, [string]$how) {
  $r = New-Object Cap+RECT
  [void][Cap]::GetWindowRect($hwnd, [ref]$r)
  $w = $r.R - $r.L; $h = $r.B - $r.T
  if ($w -lt 200 -or $h -lt 200) { return $null }
  $bmp = New-Object System.Drawing.Bitmap $w, $h
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $ok = $false
  try {
    if ($how -eq 'screen') {
      $g.CopyFromScreen($r.L, $r.T, 0, 0, (New-Object System.Drawing.Size $w, $h))
      $ok = $true
    } elseif ($how -eq 'bitblt') {
      $hdc = $g.GetHdc()
      $srcDc = [Cap]::GetWindowDC($hwnd)
      try { $ok = [Cap]::BitBlt($hdc, 0, 0, $w, $h, $srcDc, 0, 0, 0x00CC0020) } finally { $g.ReleaseHdc($hdc); [void][Cap]::ReleaseDC($hwnd, $srcDc) }
    } else {
      $flag = [uint32]$how
      $hdc = $g.GetHdc()
      try { $ok = [Cap]::PrintWindow($hwnd, $hdc, $flag) } finally { $g.ReleaseHdc($hdc) }
    }
    if ($ok) { $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png) }
  } finally { $g.Dispose(); $bmp.Dispose() }
  if (-not $ok -or -not (Test-Path $path)) { return $null }
  return (Get-Item $path).Length
}

function Score-Png([string]$path) {
  $bmp = [System.Drawing.Bitmap]::FromFile($path)
  try {
    $w = $bmp.Width; $h = $bmp.Height
    $samples = 0; $sum = 0.0; $sum2 = 0.0
    $menuFlat = 0; $menuPrev = -1; $menuChanges = 0
    for ($y = 8; $y -lt [Math]::Min(36, $h); $y += 4) {
      for ($x = 8; $x -lt $w; $x += 12) {
        $c = $bmp.GetPixel($x, $y)
        $lum = (0.3*$c.R + 0.59*$c.G + 0.11*$c.B)
        $samples++; $sum += $lum; $sum2 += $lum*$lum
        $bucket = [int]($lum / 16)
        if ($menuPrev -ge 0 -and $bucket -ne $menuPrev) { $menuChanges++ }
        $menuPrev = $bucket
        if ($lum -gt 180 -and $lum -lt 245) { $menuFlat++ }
      }
    }
    $body = 0; $bodyDark = 0
    for ($y = [int]($h*0.25); $y -lt [int]($h*0.7); $y += 20) {
      for ($x = [int]($w*0.25); $x -lt [int]($w*0.8); $x += 20) {
        $c = $bmp.GetPixel($x, $y); $body++
        $lum = (0.3*$c.R + 0.59*$c.G + 0.11*$c.B)
        if ($lum -lt 45) { $bodyDark++ }
      }
    }
    $mean = $sum / [Math]::Max(1,$samples)
    $var = ($sum2 / [Math]::Max(1,$samples)) - ($mean*$mean)
    $darkRatio = $bodyDark / [Math]::Max(1,$body)
    [pscustomobject]@{ Bytes = (Get-Item $path).Length; Var = [math]::Round($var,1); Mean = [math]::Round($mean,1); MenuChanges = $menuChanges; MenuFlat = $menuFlat; DarkRatio = [math]::Round($darkRatio,3); W = $w; H = $h }
  } finally { $bmp.Dispose() }
}

$best = $null
for ($attempt = 1; $attempt -le 6; $attempt++) {
  Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 400
  $wd = Join-Path $env:TEMP "rawrxd-shot-$attempt"
  New-Item -ItemType Directory -Force -Path $wd | Out-Null
  $p = Start-Process -FilePath $src -WorkingDirectory $wd -PassThru
  $main = [IntPtr]::Zero
  for ($i = 0; $i -lt 50; $i++) {
    Start-Sleep -Milliseconds 200
    if ($p.HasExited) { break }
    $main = [Cap]::FindMain([uint32]$p.Id)
    if ($main -ne [IntPtr]::Zero) { break }
  }
  if ($main -eq [IntPtr]::Zero) { "ATTEMPT $attempt NO_WINDOW exit=$($p.ExitCode)"; continue }
  Start-Sleep -Milliseconds 1500
  if ($p.HasExited) { "ATTEMPT $attempt DIED_BEFORE_KEYS exit=$($p.ExitCode)"; continue }
  [Cap]::Focus($main)
  Start-Sleep -Milliseconds 300
  [Cap]::ChordW()
  $title = ''
  $editor = $false
  for ($k = 0; $k -lt 15; $k++) {
    Start-Sleep -Milliseconds 200
    if ($p.HasExited) { break }
    $title = [Cap]::Title($main)
    $editor = [Cap]::EditorVisible($main)
    if ($title -match 'Work Mode' -or $editor) { break }
  }
  "ATTEMPT $attempt title=$title editor=$editor alive=$(-not $p.HasExited)"
  if ($p.HasExited) { "ATTEMPT $attempt DIED_AFTER_KEYS exit=$($p.ExitCode)"; continue }
  [Cap]::Focus($main)
  Start-Sleep -Milliseconds 250
  $paths = @{
    '0' = Join-Path $out ("a{0}-print0.png" -f $attempt)
    '2' = Join-Path $out ("a{0}-print2.png" -f $attempt)
    'bitblt' = Join-Path $out ("a{0}-bitblt.png" -f $attempt)
    'screen' = Join-Path $out ("a{0}-screen.png" -f $attempt)
  }
  foreach ($how in @('0','2','bitblt','screen')) {
    $n = Save-Capture $main $paths[$how] $how
    if (-not $n) { "  $how FAIL"; continue }
    $sc = Score-Png $paths[$how]
    "  $how bytes=$($sc.Bytes) var=$($sc.Var) mean=$($sc.Mean) menuChg=$($sc.MenuChanges) flat=$($sc.MenuFlat) dark=$($sc.DarkRatio) $($sc.W)x$($sc.H)"
    $good = ($sc.Bytes -gt 20000 -and $sc.Var -gt 80 -and $sc.W -ge 800 -and $sc.H -ge 500 -and $editor)
    if ($good -and ($null -eq $best -or $sc.Var -gt $best.Var)) {
      $best = [pscustomobject]@{ Attempt = $attempt; How = $how; Path = $paths[$how]; Var = $sc.Var; Title = $title; Dark = $sc.DarkRatio }
    }
  }
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
  if ($best -and $best.Attempt -eq $attempt -and $best.Dark -gt 0.15 -and $best.Var -gt 200) { break }
}
if ($best) {
  Copy-Item $best.Path 'G:\~dev\rawrxd\evidence\RAWRXD_UI_FORENSICS_001\ide-workmode.png' -Force
  "BEST attempt=$($best.Attempt) how=$($best.How) var=$($best.Var) dark=$($best.Dark) title=$($best.Title)"
  "SAVED=G:\~dev\rawrxd\evidence\RAWRXD_UI_FORENSICS_001\ide-workmode.png"
} else {
  'NO_ACCEPTABLE_CAPTURE'
  exit 2
}
