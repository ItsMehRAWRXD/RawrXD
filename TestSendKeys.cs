using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

public class Win32Test {
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    public const int SW_SHOW = 5;

    public static void Main() {
        IntPtr ide = FindWindow(null, "RawrXD IDE  -  Untitled  -  Workspace");
        if (ide == IntPtr.Zero) {
            ide = FindWindow("RawrXD_IDE_Window", null);
        }
        if (ide == IntPtr.Zero) {
            Console.WriteLine("IDE window not found");
            return;
        }

        ShowWindow(ide, SW_SHOW);
        SetForegroundWindow(ide);
        System.Threading.Thread.Sleep(1000);

        Console.WriteLine("IDE window activated. Sending keys...");
        
        // Try to send text to the focused control
        SendKeys.SendWait("Get-Date");
        System.Threading.Thread.Sleep(500);
        SendKeys.SendWait("{ENTER}");
        System.Threading.Thread.Sleep(3000);

        Console.WriteLine("Keys sent. Check PowerShell output in the IDE window.");
    }
}
