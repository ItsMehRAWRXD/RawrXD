$proc = Start-Process 'F:\~dev\rawrxd\win32ide_strict\build\Release\RawrXD-Win32IDE.exe' -PassThru
Start-Sleep -Seconds 3
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class Win32Send {
    [DllImport("user32.dll")]
    public static extern int SendMessage(IntPtr hWnd, uint Msg, uint wParam, uint lParam);
}
'@
[Win32Send]::SendMessage($proc.MainWindowHandle, 0x0111, 2001, 0)
Start-Sleep -Seconds 8
Stop-Process -Name RawrXD-Win32IDE -Force -ErrorAction SilentlyContinue
