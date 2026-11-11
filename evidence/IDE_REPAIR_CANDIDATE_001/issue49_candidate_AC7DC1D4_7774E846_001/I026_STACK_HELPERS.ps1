if (-not ('I49_74_STACK' -as [type])) {
Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class I49_74_STACK {
  public const uint WM_COMMAND=0x0111; public const uint WM_SETTEXT=0x000C; public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint EM_SETSEL=0x00B1; public const uint EM_REPLACESEL=0x00C2;
  public const uint KEYEVENTF_KEYUP=0x0002;
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; public uint padding1; public uint padding2;
  }
  public static int InputSize { get { return Marshal.SizeOf(typeof(INPUT)); } }
  public static uint KeyDown(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; return SendInput(1,a,InputSize); }
  public static uint KeyUp(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; a[0].ki.dwFlags=KEYEVENTF_KEYUP; return SendInput(1,a,InputSize); }
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,256);
      string c=sb.ToString();
      if(c=="RawrXD_IDE_Window"||c=="RawrXD_IDE_MainWindow"){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static IntPtr FindId(IntPtr root,int id){
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero);
    return f;
  }
  public static IntPtr FindEditId(IntPtr root,int id){
    var stack=new Stack<IntPtr>(); stack.Push(root);
    while(stack.Count>0){
      IntPtr cur=stack.Pop();
      var kids=new List<IntPtr>();
      EnumChildWindows(cur,(h,lp)=>{ kids.Add(h); return true; },IntPtr.Zero);
      foreach(var k in kids){
        var sb=new StringBuilder(64); GetClassNameW(k,sb,64);
        if(GetDlgCtrlID(k)==id && sb.ToString().IndexOf("Edit",StringComparison.OrdinalIgnoreCase)>=0) return k;
        stack.Push(k);
      }
    }
    return IntPtr.Zero;
  }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0) return "";
    if(n>120000) n=120000;
    var sb=new StringBuilder(n+2);
    SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb);
    return sb.ToString();
  }
  public static void FocusChat(IntPtr main, IntPtr chat){
    uint pid=0; uint ideTid=GetWindowThreadProcessId(main,out pid); uint myTid=GetCurrentThreadId();
    IntPtr fg=GetForegroundWindow(); uint pidFg=0; uint fgTid=(fg!=IntPtr.Zero)?GetWindowThreadProcessId(fg,out pidFg):(uint)0;
    if(fgTid!=0 && fgTid!=myTid && fgTid!=ideTid) AttachThreadInput(myTid,fgTid,true);
    if(ideTid!=0 && ideTid!=myTid) AttachThreadInput(myTid,ideTid,true);
    ShowWindow(main,9); BringWindowToTop(main); SetForegroundWindow(main); SetFocus(chat);
  }
  public static void DetachChat(IntPtr main){
    uint pid=0; uint ideTid=GetWindowThreadProcessId(main,out pid); uint myTid=GetCurrentThreadId();
    if(ideTid!=0 && ideTid!=myTid) AttachThreadInput(myTid,ideTid,false);
  }
  public static void SendCtrlEnter(IntPtr main, IntPtr chat){
    FocusChat(main,chat);
    System.Threading.Thread.Sleep(50);
    KeyDown(0x11); System.Threading.Thread.Sleep(40);
    KeyDown(0x0D); System.Threading.Thread.Sleep(80);
    KeyUp(0x0D); KeyUp(0x11);
    System.Threading.Thread.Sleep(50);
    DetachChat(main);
  }
}
"@
}
