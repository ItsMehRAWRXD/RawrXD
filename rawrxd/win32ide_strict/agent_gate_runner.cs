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
        string exePath = @"F:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe";
        string outputPath = @"F:\~dev\rawrxd\win32ide_strict\build_v4\Release\agent_gate_output.txt";
        string receiptPath = @"F:\~dev\rawrxd\win32ide_strict\build_v4\Release\cert_receipt_agentic.txt";

        Console.WriteLine("[AGENT_GATE_RUNNER] Launching RawrXD-Win32IDE...");
        var psi = new System.Diagnostics.ProcessStartInfo {
            FileName = exePath,
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

        // Send WM_COMMAND for IDM_AGENTIC_GATE = 4001
        Console.WriteLine("[AGENT_GATE_RUNNER] Sending WM_COMMAND(4001) for Agentic Gate...");
        Win32Api.SendMessage(hwnd, 0x0111, (IntPtr)4001, IntPtr.Zero);

        Console.WriteLine("[AGENT_GATE_RUNNER] Waiting for gate completion (max 600s)...");
        bool found = false;
        for (int i = 0; i < 600; i++) {
            Thread.Sleep(1000);
            if (System.IO.File.Exists(receiptPath)) {
                found = true;
                Console.WriteLine("[AGENT_GATE_RUNNER] Receipt found after " + i + "s");
                break;
            }
        }
        if (!found) {
            Console.WriteLine("[AGENT_GATE_RUNNER] Timeout waiting for receipt.");
        }

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
        System.IO.File.WriteAllText(outputPath, text);
        Console.WriteLine("[AGENT_GATE_RUNNER] Output saved to: " + outputPath);
        Console.WriteLine("--- BEGIN OUTPUT ---");
        Console.WriteLine(text);
        Console.WriteLine("--- END OUTPUT ---");

        // Also print receipt if exists
        if (System.IO.File.Exists(receiptPath)) {
            string receipt = System.IO.File.ReadAllText(receiptPath);
            Console.WriteLine("--- RECEIPT ---");
            Console.WriteLine(receipt);
        }
        proc.Kill();
    }
}
