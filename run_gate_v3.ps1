$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
public class Win32Api3 {
    [DllImport("user32.dll")] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
'@

$genDebug = "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\gen_debug.txt"
$stderrFile = "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\stderr_e2e.txt"
if (Test-Path $genDebug) { Remove-Item $genDebug -Force }
if (Test-Path $stderrFile) { Remove-Item $stderrFile -Force }

# Use Start-Process directly - window appears faster
$proc = Start-Process -FilePath "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe" -PassThru
Write-Host "PID=$($proc.Id)"

Start-Sleep -Seconds 12
$hwnd = [Win32Api3]::FindWindow("RawrXDWin32IDE", $null)
if ($hwnd -eq [IntPtr]::Zero) {
    Write-Host "WINDOW_NOT_FOUND"
    $proc.Kill()
    exit 1
}
[Win32Api3]::ShowWindow($hwnd, 1)
[Win32Api3]::SetForegroundWindow($hwnd)
Start-Sleep -Milliseconds 500
[Win32Api3]::SendMessage($hwnd, 0x0111, [IntPtr]3001, [IntPtr]::Zero)
Write-Host "SENT_WM_COMMAND_3001 HWND=$hwnd"

Start-Sleep -Seconds 50

$proc.Kill()
Write-Host "DONE"
