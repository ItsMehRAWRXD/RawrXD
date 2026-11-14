using System; using System.Text; using System.Runtime.InteropServices;
public class H {
  public delegate bool EP(IntPtr h, IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern bool EnumWindows(EP lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EP lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr GetPropW(IntPtr h, string n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,string l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public static IntPtr FindMain(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true; var c=new StringBuilder(256); GetClassNameW(h,c,256); var s=c.ToString(); if(s=="RawrXD_IDE_MainWindow"||s=="RawrXD_IDE_Window"){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static bool Ready(IntPtr m){ return GetPropW(m,"RawrXD.MainMenuReady")!=IntPtr.Zero; }
  public static int Post(IntPtr h,int id){ return (h!=IntPtr.Zero&&IsWindow(h)&&PostMessageW(h,0x0111,(IntPtr)id,IntPtr.Zero))?1:0; }
  public static IntPtr FindTitle(uint pid,string needle){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true; var t=new StringBuilder(256); GetWindowTextW(h,t,256); if(t.ToString().IndexOf(needle,StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr ChildClass(IntPtr parent,string cls){ IntPtr f=IntPtr.Zero; EnumChildWindows(parent,(h,l)=>{ var c=new StringBuilder(64); GetClassNameW(h,c,64); if(string.Equals(c.ToString(),cls,StringComparison.OrdinalIgnoreCase)){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr ChildTitle(IntPtr parent,string needle){ IntPtr f=IntPtr.Zero; EnumChildWindows(parent,(h,l)=>{ var t=new StringBuilder(128); GetWindowTextW(h,t,128); if(t.ToString().IndexOf(needle,StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static int Fill(uint pid,string prompt){ IntPtr d=FindTitle(pid,"Bounded Agent Loop"); if(d==IntPtr.Zero) return 0; IntPtr e=ChildClass(d,"Edit"); if(e==IntPtr.Zero) return 0; SendMessageW(e,0x000C,IntPtr.Zero,prompt); IntPtr ok=ChildTitle(d,"Run Agent"); if(ok==IntPtr.Zero) ok=ChildTitle(d,"OK"); if(ok==IntPtr.Zero) return 0; SetForegroundWindow(d); SendMessageW(ok,0x00F5,IntPtr.Zero,IntPtr.Zero); return 1; }
  public static void Dismiss(uint pid){ IntPtr mb=FindTitle(pid,"Agent Error"); if(mb==IntPtr.Zero) mb=FindTitle(pid,"Error"); if(mb==IntPtr.Zero) return; IntPtr ok=ChildTitle(mb,"OK"); if(ok!=IntPtr.Zero) SendMessageW(ok,0x00F5,IntPtr.Zero,IntPtr.Zero); }
}
