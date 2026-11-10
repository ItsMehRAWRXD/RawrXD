Add-Type -AssemblyName System.Windows.Forms

$signature = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;

public class Win32Test {
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

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

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool SetFocus(IntPtr hWnd);

    public const uint WM_SETTEXT = 0x000C;
    public const uint WM_GETTEXT = 0x000D;
    public const uint WM_GETTEXTLENGTH = 0x000E;
    public const uint BM_CLICK = 0x00F5;

    public static string GetText(IntPtr hwnd) {
        int len = GetWindowTextLength(hwnd);
        if (len == 0) return "";
        var sb = new StringBuilder(len + 1);
        GetWindowText(hwnd, sb, sb.Capacity);
        return sb.ToString();
    }

    public static string GetClass(IntPtr hwnd) {
        var sb = new StringBuilder(256);
        GetClassName(hwnd, sb, sb.Capacity);
        return sb.ToString();
    }

    public static void SetText(IntPtr hwnd, string text) {
        SendMessage(hwnd, WM_SETTEXT, IntPtr.Zero, text);
    }

    public static void Click(IntPtr hwnd) {
        PostMessage(hwnd, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    }

    public static void Focus(IntPtr hwnd) {
        SetFocus(hwnd);
    }
}

public class IDEController {
    public static IntPtr FindIdeWindow() {
        // Find by window title
        IntPtr hwnd = Win32Test.FindWindow(null, "RawrXD IDE  -  Untitled  -  Workspace");
        if (hwnd == IntPtr.Zero) {
            hwnd = Win32Test.FindWindow("RawrXD_IDE_Window", null);
        }
        return hwnd;
    }

    public static void TestPowerShell() {
        IntPtr ide = FindIdeWindow();
        if (ide == IntPtr.Zero) {
            Console.WriteLine("IDE window not found");
            return;
        }
        Console.WriteLine($"IDE window: {ide}");

        // Enumerate children to find PowerShell input and Execute button
        IntPtr psInput = IntPtr.Zero;
        IntPtr executeBtn = IntPtr.Zero;
        IntPtr psOutput = IntPtr.Zero;

        IntPtr child = IntPtr.Zero;
        while ((child = Win32Test.FindWindowEx(ide, child, null, null)) != IntPtr.Zero) {
            string className = Win32Test.GetClass(child);
            string text = Win32Test.GetText(child);
            Console.WriteLine($"  Child: {child} Class='{className}' Text='{text}'");

            if (className == "Edit" && text == "") {
                // Look for PowerShell input - it's an empty Edit in the lower section
                // Check siblings for PowerShell Console label
                if (psInput == IntPtr.Zero) psInput = child;
            }
            if (className == "Button" && text == "Execute") {
                executeBtn = child;
                Console.WriteLine($"    >>> Execute button: {child}");
            }
            if (className == "RichEdit20A") {
                if (psOutput == IntPtr.Zero) psOutput = child;
                Console.WriteLine($"    >>> RichEdit output: {child}");
            }
        }

        Console.WriteLine($"\nPowerShell input: {psInput}");
        Console.WriteLine($"Execute button: {executeBtn}");
        Console.WriteLine($"PowerShell output: {psOutput}");

        if (psInput != IntPtr.Zero && executeBtn != IntPtr.Zero) {
            Console.WriteLine("\n=== Testing PowerShell Execute ===");
            
            Win32Test.SetText(psInput, "Get-Date");
            Console.WriteLine("Sent 'Get-Date' to PowerShell input");
            
            Win32Test.Focus(psInput);
            
            Win32Test.Click(executeBtn);
            Console.WriteLine("Clicked Execute");

            System.Threading.Thread.Sleep(3000);

            if (psOutput != IntPtr.Zero) {
                string output = Win32Test.GetText(psOutput);
                Console.WriteLine($"\n=== PowerShell Output ===");
                Console.WriteLine(output);
                Console.WriteLine("=== End ===");
            }
        }
    }
}

[IDEController]::TestPowerShell()
"@

Add-Type -TypeDefinition $signature -ReferencedAssemblies System.Windows.Forms
