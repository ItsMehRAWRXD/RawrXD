using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using System.Collections.Generic;

public class Win32Test {
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string lpszWindow);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool SetFocus(IntPtr hWnd);

    public const uint BM_CLICK = 0x00F5;
    public const int SW_SHOW = 5;

    public static string GetClass(IntPtr hwnd) {
        var sb = new StringBuilder(256);
        GetClassName(hwnd, sb, sb.Capacity);
        return sb.ToString();
    }

    public static string GetText(IntPtr hwnd) {
        int len = GetWindowTextLength(hwnd);
        if (len == 0) return "";
        var sb = new StringBuilder(len + 1);
        GetWindowText(hwnd, sb, sb.Capacity);
        return sb.ToString();
    }

    public static void Click(IntPtr hwnd) {
        PostMessage(hwnd, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    }

    public static void Focus(IntPtr hwnd) {
        SetFocus(hwnd);
    }

    public static void CollectControls(IntPtr parent, string className, string matchText, 
        List<IntPtr> results) {
        IntPtr child = IntPtr.Zero;
        while ((child = FindWindowEx(parent, child, null, null)) != IntPtr.Zero) {
            string cClass = GetClass(child);
            if (cClass == className) {
                string cText = GetText(child);
                if (matchText == "" || cText == matchText) {
                    results.Add(child);
                }
            }
            CollectControls(child, className, matchText, results);
        }
    }

    public static void CollectButtons(IntPtr parent, List<Tuple<IntPtr, string>> results) {
        IntPtr child = IntPtr.Zero;
        while ((child = FindWindowEx(parent, child, null, null)) != IntPtr.Zero) {
            string cClass = GetClass(child);
            if (cClass == "Button") {
                string cText = GetText(child);
                results.Add(Tuple.Create(child, cText));
            }
            CollectButtons(child, results);
        }
    }

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

        Console.WriteLine("IDE window: " + ide);

        // Find buttons
        var buttons = new List<Tuple<IntPtr, string>>();
        CollectButtons(ide, buttons);
        IntPtr executeBtn = IntPtr.Zero;
        IntPtr sendBtn = IntPtr.Zero;
        foreach (var b in buttons) {
            if (b.Item2 == "Execute") executeBtn = b.Item1;
            if (b.Item2 == "Send") sendBtn = b.Item1;
        }

        // Find empty Edits
        var emptyEdits = new List<IntPtr>();
        CollectControls(ide, "Edit", "", emptyEdits);
        Console.WriteLine("Empty Edits: " + emptyEdits.Count);

        // Find all RichEdits
        var richEdits = new List<IntPtr>();
        CollectControls(ide, "RichEdit20A", "", richEdits);
        Console.WriteLine("RichEdits: " + richEdits.Count);

        // Click on first empty Edit to focus it
        if (emptyEdits.Count >= 1) {
            Console.WriteLine("\n=== Testing PowerShell via SendKeys ===");
            Focus(emptyEdits[0]);
            System.Threading.Thread.Sleep(500);
            SendKeys.SendWait("Get-Date{ENTER}");
            System.Threading.Thread.Sleep(5000);

            foreach (var re in richEdits) {
                string output = GetText(re);
                if (output.Length > 0) {
                    Console.WriteLine("RichEdit " + re + " output: '" + output + "'");
                }
            }
        }

        // Click on second empty Edit for chat
        if (emptyEdits.Count >= 2) {
            Console.WriteLine("\n=== Testing Chat via SendKeys ===");
            Focus(emptyEdits[1]);
            System.Threading.Thread.Sleep(500);
            SendKeys.SendWait("Hello{ENTER}");
            System.Threading.Thread.Sleep(5000);

            foreach (var re in richEdits) {
                string output = GetText(re);
                if (output.Length > 0) {
                    Console.WriteLine("RichEdit " + re + " output: '" + output + "'");
                }
            }
        }
    }
}
