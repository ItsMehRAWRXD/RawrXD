using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;
public class Finder {
    [DllImport("user32.dll", SetLastError=true)]
    static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll", SetLastError=true)]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll")]
    static extern int SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    public static IntPtr FindWindowByPid(int pid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((h, p) => {
            uint pid2;
            GetWindowThreadProcessId(h, out pid2);
            if (pid2 == (uint)pid) {
                var sb = new System.Text.StringBuilder(256);
                GetWindowText(h, sb, 256);
                if (sb.ToString().Contains("RawrXD")) { found = h; return false; }
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    public static void Send(int pid, int cmd) {
        var h = FindWindowByPid(pid);
        if (h == IntPtr.Zero) { Console.WriteLine("NOT_FOUND"); return; }
        Console.WriteLine("HW=" + h);
        SendMessage(h, 0x0111, (IntPtr)cmd, IntPtr.Zero);
        Console.WriteLine("SENT_COMMAND_" + cmd);
    }
}
