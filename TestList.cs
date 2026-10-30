using System;
using System.Runtime.InteropServices;
using System.Text;

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
    public const uint VK_RETURN = 0x0D;
    public const uint WM_KEYDOWN = 0x0100;
    public const uint WM_KEYUP = 0x0101;

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

    public static void ListAllDescendants(IntPtr parent, int depth) {
        IntPtr child = IntPtr.Zero;
        while ((child = FindWindowEx(parent, child, null, null)) != IntPtr.Zero) {
            string className = GetClass(child);
            string text = GetText(child);
            string indent = new string(' ', depth * 2);
            Console.WriteLine(indent + child + " Class='" + className + "' Text='" + (text.Length > 80 ? text.Substring(0, 80) + "..." : text) + "'");
            ListAllDescendants(child, depth + 1);
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
        Console.WriteLine("IDE window: " + ide);
        Console.WriteLine("\n=== All descendants ===");
        ListAllDescendants(ide, 0);
    }
}
