using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class TipUiPhase7b {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public const uint CB_GETCOUNT = 0x0146;
  public static long FindMainByPid(uint pid, string className) {
    long found = 0;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      if (cls.ToString() == className) { found = h.ToInt64(); return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static List<string> DumpChildren(long parent) {
    var rows = new List<string>();
    IntPtr hwnd = new IntPtr(parent);
    EnumChildWindows(hwnd, (h, l) => {
      var cls = new StringBuilder(256);
      var title = new StringBuilder(512);
      GetClassNameW(h, cls, 256);
      GetWindowTextW(h, title, 512);
      rows.Add("hwnd=0x" + h.ToInt64().ToString("X") + " class=" + cls + " title=" + title + " visible=" + (IsWindowVisible(h) ? "1" : "0"));
      return true;
    }, IntPtr.Zero);
    return rows;
  }
  public static int ComboItemCount(long parent) {
    int max = -1;
    IntPtr hwnd = new IntPtr(parent);
    EnumChildWindows(hwnd, (h, l) => {
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      if (cls.ToString().IndexOf("ComboBox", StringComparison.OrdinalIgnoreCase) >= 0) {
        int cnt = (int)SendMessageW(h, CB_GETCOUNT, IntPtr.Zero, IntPtr.Zero);
        if (cnt > max) max = cnt;
      }
      return true;
    }, IntPtr.Zero);
    return max;
  }
  public static bool PostCmd(long hwnd, uint msg, int cmd) {
    return PostMessageW(new IntPtr(hwnd), msg, new IntPtr(cmd), IntPtr.Zero);
  }
  public static List<string> FindTopByPid(uint pid, string needle) {
    var hits = new List<string>();
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var cls = new StringBuilder(256);
      var ttl = new StringBuilder(512);
      GetClassNameW(h, cls, 256);
      GetWindowTextW(h, ttl, 512);
      string c = cls.ToString();
      string t = ttl.ToString();
      if (t.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0 ||
          c.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) {
        hits.Add("0x" + h.ToInt64().ToString("X") + "|" + c + "|" + t);
      }
      return true;
    }, IntPtr.Zero);
    return hits;
  }
  public static bool HasClassOnPid(uint pid, string className) {
    bool found = false;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      if (cls.ToString() == className) { found = true; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
