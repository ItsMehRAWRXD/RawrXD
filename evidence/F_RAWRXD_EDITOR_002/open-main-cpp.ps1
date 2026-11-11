$ErrorActionPreference = 'Stop'
$src = 'F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe'
$proc = Start-Process -FilePath $src -WorkingDirectory (Split-Path $src) -PassThru
$ProcessId = $proc.Id
"LAUNCH=$ProcessId SHA=$((Get-FileHash -Algorithm SHA256 $src).Hash)"
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class MenuOpen {
  public delegate bool EnumProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern IntPtr GetMenu(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetMenuItemRect(IntPtr w, IntPtr m, uint i, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint data, UIntPtr extra);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextLengthW(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [DllImport("user32.dll")] public static extern IntPtr GetWindowDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr dc);
  [DllImport("gdi32.dll")] public static extern bool BitBlt(IntPtr d, int x, int y, int w, int h, IntPtr s, int sx, int sy, uint rop);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr extra; }
  public static void Focus(IntPtr h) {
    ShowWindow(h, 9);
    uint junk; uint fg = GetWindowThreadProcessId(GetForegroundWindow(), out junk);
    uint me = GetCurrentThreadId();
    if (fg != 0 && fg != me) AttachThreadInput(me, fg, true);
    BringWindowToTop(h); SetForegroundWindow(h);
    if (fg != 0 && fg != me) AttachThreadInput(me, fg, false);
  }
  public static void Click(int x, int y) {
    SetCursorPos(x, y);
    mouse_event(2, 0, 0, 0, UIntPtr.Zero);
    mouse_event(4, 0, 0, 0, UIntPtr.Zero);
  }
  public static void Key(ushort vk, bool up) {
    var i = new INPUT[1]; i[0].type = 1; i[0].ki.wVk = vk; i[0].ki.dwFlags = up ? 2u : 0u;
    SendInput(1, i, Marshal.SizeOf(typeof(INPUT)));
  }
  public static void Text(string s) {
    foreach (char ch in s) {
      var d = new INPUT[1]; var u = new INPUT[1];
      d[0].type = 1; u[0].type = 1;
      d[0].ki.wScan = ch; d[0].ki.dwFlags = 4;
      u[0].ki.wScan = ch; u[0].ki.dwFlags = 6;
      SendInput(1, d, Marshal.SizeOf(typeof(INPUT)));
      SendInput(1, u, Marshal.SizeOf(typeof(INPUT)));
    }
  }
  public static IntPtr Dialog(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, p) => {
      uint id; GetWindowThreadProcessId(h, out id);
      if (id != pid) return true;
      var cs = new StringBuilder(64); GetClassNameW(h, cs, 64);
      if (cs.ToString() == "#32770") found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static string EditorSample(IntPtr root) {
    string best = "";
    EnumChildWindows(root, (h, p) => {
      var cs = new StringBuilder(64); GetClassNameW(h, cs, 64);
      int n = GetWindowTextLengthW(h);
      if (n > 20) {
        var sb = new StringBuilder(160);
        GetWindowTextW(h, sb, sb.Capacity);
        string line = cs + " len=" + n + " " + sb.ToString().Replace("\r"," ").Replace("\n"," | ");
        if (n > best.Length) best = line;
      }
      return true;
    }, IntPtr.Zero);
    return best;
  }
}
'@
$hwnd = [IntPtr]::Zero
for ($i = 0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 200
  if ($proc.HasExited) { "DIED_EARLY=$($proc.ExitCode)"; exit 2 }
  $hwnd = (Get-Process -Id $ProcessId).MainWindowHandle
  if ($hwnd -ne [IntPtr]::Zero) { "WINDOW_TICK=$i"; break }
}
$p = Get-Process -Id $ProcessId
"PID=$($p.Id) HWND=0x$($hwnd.ToInt64().ToString('X')) PATH=$($p.Path) RESP=$($p.Responding)"
[MenuOpen]::Focus($hwnd)
Start-Sleep -Milliseconds 300
$menu = [MenuOpen]::GetMenu($hwnd)
$mr = New-Object MenuOpen+RECT
$got = [MenuOpen]::GetMenuItemRect($hwnd, $menu, 0, [ref]$mr)
"FILE_MENU=$got $($mr.L),$($mr.T)-$($mr.R),$($mr.B)"
if (-not $got) { 'NO_MENU_RECT'; exit 5 }
$cx = [int](($mr.L + $mr.R) / 2)
$cy = [int](($mr.T + $mr.B) / 2)
[MenuOpen]::Click($cx, $cy)
Start-Sleep -Milliseconds 300
[MenuOpen]::Key(0x4F, $false)
[MenuOpen]::Key(0x4F, $true)
$dlg = [IntPtr]::Zero
for ($i=0; $i -lt 20; $i++) {
  Start-Sleep -Milliseconds 150
  $dlg = [MenuOpen]::Dialog([uint32]$ProcessId)
  if ($dlg -ne [IntPtr]::Zero) { break }
}
"DIALOG=0x$($dlg.ToInt64().ToString('X'))"
if ($dlg -eq [IntPtr]::Zero) { 'NO_DIALOG'; exit 4 }
[MenuOpen]::Focus($dlg)
Start-Sleep -Milliseconds 200
[MenuOpen]::Text('F:\rawrxd\src\main.cpp')
[MenuOpen]::Key(0x0D, $false)
[MenuOpen]::Key(0x0D, $true)
for ($i=0; $i -lt 25; $i++) {
  Start-Sleep -Milliseconds 150
  if ((Get-Process -Id $ProcessId).MainWindowTitle -match 'main.cpp') { break }
}
$live = Get-Process -Id $ProcessId
"TITLE=$($live.MainWindowTitle) RESP=$($live.Responding)"
"EDITOR=$([MenuOpen]::EditorSample($hwnd))"
$wr = New-Object MenuOpen+RECT
[void][MenuOpen]::GetWindowRect($hwnd, [ref]$wr)
$w = $wr.R - $wr.L
$h = $wr.B - $wr.T
$bmp = New-Object System.Drawing.Bitmap $w, $h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
$dc = [MenuOpen]::GetWindowDC($hwnd)
$ok = [MenuOpen]::BitBlt($hdc, 0, 0, $w, $h, $dc, 0, 0, 0x00CC0020)
$g.ReleaseHdc($hdc)
[void][MenuOpen]::ReleaseDC($hwnd, $dc)
$shot = Join-Path $PSScriptRoot ("pid-$ProcessId-after-open.png")
if ($ok) { $bmp.Save($shot, [System.Drawing.Imaging.ImageFormat]::Png); "SHOT=$shot $((Get-Item $shot).Length)" }
$g.Dispose(); $bmp.Dispose()
