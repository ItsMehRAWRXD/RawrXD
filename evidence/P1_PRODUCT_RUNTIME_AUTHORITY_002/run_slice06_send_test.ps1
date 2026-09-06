# Slice 6 physical Send — ScreenPilot command-home
$ErrorActionPreference = 'Stop'
$env:RAWRXD_EVIDENCE_ROOT = 'f:\~dev\rawrxd\evidence'
$exe = 'F:\~dev\rawrxd\build_p1pra_win32ide\bin\RawrXD-Win32IDE.exe'
$log = 'f:\~dev\rawrxd\evidence\P1_PRODUCT_RUNTIME_AUTHORITY_002\RUN.log'

Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class UiSend {
  public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr hWndParent, EnumProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
  public const uint WM_CLOSE = 0x0010;
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr hWnd);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetDlgItem(IntPtr hDlg, int nIDDlgItem);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowText(IntPtr hWnd, string lpString);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")] public static extern IntPtr SendMessageText(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")] public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_COMMAND = 0x0111;
  public static IntPtr FindByCtrlId(IntPtr root, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(root, (h, p) => {
      if (GetDlgCtrlID(h) == id) { found = h; return false; }
      var sub = FindByCtrlId(h, id);
      if (sub != IntPtr.Zero) { found = sub; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
'@

Remove-Item $log -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $exe -PassThru
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 120 -and $main -eq [IntPtr]::Zero; $i++) {
  Start-Sleep -Milliseconds 500
  [UiSend]::EnumWindows([UiSend+EnumProc]{
    param($h, $lp)
    $sb = New-Object System.Text.StringBuilder 512
    [void][UiSend]::GetWindowText($h, $sb, $sb.Capacity)
    if ($sb.ToString() -like '*ScreenPilot*') { $script:main = $h; return $false }
    return $true
  }, [IntPtr]::Zero) | Out-Null
}
if ($main -eq [IntPtr]::Zero) {
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  throw 'ScreenPilot main window not found within 60s'
}
$composer = [IntPtr]::Zero
$sendBtn = [IntPtr]::Zero
for ($i = 0; $i -lt 180; $i++) {
  $composer = [UiSend]::FindByCtrlId($main, 12501)
  $sendBtn = [UiSend]::FindByCtrlId($main, 12502)
  if ($composer -ne [IntPtr]::Zero -and $sendBtn -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 500
}
if ($composer -eq [IntPtr]::Zero -or $sendBtn -eq [IntPtr]::Zero) {
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  throw "Command-home controls missing (composer=$composer send=$sendBtn)"
}
$cmdHost = [UiSend]::GetParent($sendBtn)
$composerDlg = [UiSend]::GetDlgItem($cmdHost, 12501)
Write-Host "composer_find=$composer composer_dlg=$composerDlg cmdHost=$cmdHost main=$main"
if ($composerDlg -ne [IntPtr]::Zero) { $composer = $composerDlg }
[void][UiSend]::SendMessageText($composer, [UiSend]::WM_SETTEXT, [IntPtr]::Zero, 'test')
$verify = New-Object System.Text.StringBuilder 64
[void][UiSend]::GetWindowText($composer, $verify, $verify.Capacity)
Write-Host "composer_text=$($verify.ToString())"
[void][UiSend]::SendMessage($cmdHost, [UiSend]::WM_COMMAND, [IntPtr]12502, $sendBtn)
Start-Sleep -Seconds 3
[void][UiSend]::PostMessage($main, [UiSend]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
Wait-Process -Id $p.Id -Timeout 30 -ErrorAction SilentlyContinue
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Get-Content $log
