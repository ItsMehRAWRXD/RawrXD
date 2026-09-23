using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

class Win32Api {
    [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr FindWindowEx(IntPtr parent, IntPtr after, string cls, string title);
    [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, StringBuilder lParam);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}

class Program {
    static void Main() {
        var psi = new System.Diagnostics.ProcessStartInfo {
            FileName = @"F:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe",
            UseShellExecute = true
        };
        var proc = System.Diagnostics.Process.Start(psi);
        Thread.Sleep(2000);
        IntPtr hwnd = IntPtr.Zero;
        for (int i = 0; i < 20; i++) {
            hwnd = Win32Api.FindWindow("RawrXDWin32IDE", null);
            if (hwnd != IntPtr.Zero) break;
            Thread.Sleep(500);
        }
        if (hwnd == IntPtr.Zero) {
            Console.WriteLine("Window not found");
            proc.Kill();
            return;
        }
        Win32Api.ShowWindow(hwnd, 1);
        Win32Api.SetForegroundWindow(hwnd);
        Thread.Sleep(300);
        // Send WM_COMMAND for IDM_MODEL_LOCAL = 3001
        Win32Api.SendMessage(hwnd, 0x0111, (IntPtr)3001, IntPtr.Zero);
        Thread.Sleep(2000);
        // Read edit control text
        IntPtr edit = Win32Api.FindWindowEx(hwnd, IntPtr.Zero, "EDIT", null);
        if (edit == IntPtr.Zero) {
            Console.WriteLine("Edit control not found");
            proc.Kill();
            return;
        }
        int len = (int)Win32Api.SendMessage(edit, 0x000E, IntPtr.Zero, IntPtr.Zero);
        var sb = new StringBuilder(len + 1);
        Win32Api.SendMessage(edit, 0x000D, (IntPtr)(len + 1), sb);
        string text = sb.ToString();
        System.IO.File.WriteAllText(@"F:\~dev\rawrxd\win32ide_strict\build_v4\Release\gate2_output.txt", text);
        Console.WriteLine(text);
        proc.Kill();
    }
}
