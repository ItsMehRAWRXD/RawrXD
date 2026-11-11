using System; using System.Text; using System.Runtime.InteropServices;
public static class GTSTALE {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern int GetWindowTextLengthW(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetFocus();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, UIntPtr e);
  public const uint WM_COMMAND=0x0111, WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_CLOSE=0x0010;
  public const uint EM_SETSEL=0x00B1, EM_REPLACESEL=0x00C2, BM_CLICK=0x00F5;
  public const uint CB_GETCOUNT=0x0146, CB_GETLBTEXT=0x0148, CB_GETLBTEXTLEN=0x0149, CB_SETCURSEL=0x014E;
  public const int IDM_FILE_OPEN=2002, IDM_FILE_SAVEAS=2004, IDC_EDITOR=1001;
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr extra; }
  public static string ClassName(IntPtr h){ var s=new StringBuilder(128); GetClassNameW(h,s,s.Capacity); return s.ToString(); }
  public static string TitleOf(IntPtr h){ var s=new StringBuilder(512); GetWindowTextW(h,s,s.Capacity); return s.ToString(); }
  public static IntPtr FindMain(uint p){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p)return true; if(ClassName(h)=="RawrXD_IDE_Window"){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindEditor(IntPtr root){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,l)=>{ string c=ClassName(h); if(GetDlgCtrlID(h)==IDC_EDITOR && IsWindowVisible(h) && (c.IndexOf("RichEdit",StringComparison.OrdinalIgnoreCase)>=0 || c=="Edit")){ f=h; return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindAnyDialog(uint p){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p)return true; if(ClassName(h)=="#32770"&&IsWindowVisible(h)){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindDialogByTitle(uint p, string must){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p)return true; if(ClassName(h)=="#32770"&&IsWindowVisible(h)){ string t=TitleOf(h); if(t.IndexOf(must,StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;}} return true;},IntPtr.Zero); return f; }
  public static void Focus(IntPtr main, IntPtr ed){
    ShowWindow(main,9); SetForegroundWindow(main);
    RECT r; GetWindowRect(ed, out r);
    SetCursorPos((r.L+r.R)/2, (r.T+r.B)/2);
    mouse_event(0x0002,0,0,0,UIntPtr.Zero); mouse_event(0x0004,0,0,0,UIntPtr.Zero);
    uint gui=0; GetWindowThreadProcessId(main,out gui); uint me=GetCurrentThreadId();
    bool a=false; if(gui!=me)a=AttachThreadInput(me,gui,true);
    SetFocus(ed); if(a)AttachThreadInput(me,gui,false);
  }
  public static IntPtr FocusChord(IntPtr main, IntPtr ed, ushort a, ushort b){
    ShowWindow(main,9); SetForegroundWindow(main);
    RECT r; GetWindowRect(ed, out r);
    SetCursorPos((r.L+r.R)/2, (r.T+r.B)/2);
    mouse_event(0x0002,0,0,0,UIntPtr.Zero); mouse_event(0x0004,0,0,0,UIntPtr.Zero);
    uint gui=0; GetWindowThreadProcessId(main,out gui); uint me=GetCurrentThreadId();
    bool attached=false; if(gui!=me) attached=AttachThreadInput(me,gui,true);
    SetFocus(ed);
    var i=new INPUT[4]; for(int k=0;k<4;k++) i[k].type=1;
    i[0].ki.wVk=a; i[1].ki.wVk=b; i[2].ki.wVk=b; i[2].ki.dwFlags=2; i[3].ki.wVk=a; i[3].ki.dwFlags=2;
    SendInput(4,i,Marshal.SizeOf(typeof(INPUT)));
    System.Threading.Thread.Sleep(50);
    IntPtr f=GetFocus();
    if(attached) AttachThreadInput(me,gui,false);
    return f;
  }
  public static void EscapeKey(){
    var i=new INPUT[2]; i[0].type=1; i[0].ki.wVk=0x1B; i[1].type=1; i[1].ki.wVk=0x1B; i[1].ki.dwFlags=2;
    SendInput(2,i,Marshal.SizeOf(typeof(INPUT)));
  }
  public static string GetText(IntPtr h){ int len=SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero).ToInt32(); if(len<=0) len=GetWindowTextLengthW(h); if(len<=0)return ""; IntPtr buf=Marshal.AllocHGlobal((len+2)*2); try{ int got=SendMessageW(h,WM_GETTEXT,(IntPtr)(len+1),buf).ToInt32(); return got>0?Marshal.PtrToStringUni(buf)??"":""; } finally{ Marshal.FreeHGlobal(buf);} }
  public static void SetText(IntPtr h, string t){ SendMessageW(h,EM_SETSEL,IntPtr.Zero,(IntPtr)(-1)); SendMessageW(h,EM_REPLACESEL,(IntPtr)1,t??""); }
  public static IntPtr FindFileNameEdit(IntPtr dlg){
    IntPtr edit=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{ string c=ClassName(h); int id=GetDlgCtrlID(h); if((c=="Edit"||c.StartsWith("RichEdit"))&&(id==0x47C||id==0x480||id==0x3E9)&&IsWindowVisible(h)&&IsWindowEnabled(h)){edit=h;return false;} return true;},IntPtr.Zero);
    if(edit!=IntPtr.Zero) return edit;
    EnumChildWindows(dlg,(h,l)=>{ if(ClassName(h)=="ComboBoxEx32"){ EnumChildWindows(h,(c,q)=>{ if(ClassName(c)=="Edit"){edit=c;return false;} return true;},IntPtr.Zero); return edit==IntPtr.Zero;} return true;},IntPtr.Zero);
    return edit;
  }
  public static bool DriveFileDialog(IntPtr dlg, string path){
    if(dlg==IntPtr.Zero) return false; IntPtr edit=FindFileNameEdit(dlg); if(edit==IntPtr.Zero) return false;
    SetForegroundWindow(dlg); SetWindowTextW(edit,path); SendMessageW(edit,WM_SETTEXT,IntPtr.Zero,path);
    SendMessageW(edit,EM_SETSEL,IntPtr.Zero,(IntPtr)(-1)); SendMessageW(edit,EM_REPLACESEL,(IntPtr)1,path);
    IntPtr ok=IntPtr.Zero; EnumChildWindows(dlg,(h,l)=>{ if(GetDlgCtrlID(h)==1&&ClassName(h)=="Button"){ok=h;return false;} return true;},IntPtr.Zero);
    if(ok!=IntPtr.Zero){ PostMessageW(dlg,WM_COMMAND,(IntPtr)1,ok); SendMessageW(ok,BM_CLICK,IntPtr.Zero,IntPtr.Zero);} else PostMessageW(dlg,WM_COMMAND,(IntPtr)1,IntPtr.Zero);
    System.Threading.Thread.Sleep(250);
    if(IsWindowVisible(dlg)){ var i=new INPUT[2]; i[0].type=1; i[0].ki.wVk=0x0D; i[1].type=1; i[1].ki.wVk=0x0D; i[1].ki.dwFlags=2; SendInput(2,i,Marshal.SizeOf(typeof(INPUT))); }
    return true;
  }
  public static void ClickDialog(IntPtr dlg, int cmd){ if(dlg!=IntPtr.Zero) PostMessageW(dlg,WM_COMMAND,(IntPtr)cmd,IntPtr.Zero); }
  public static IntPtr FindComboWithText(IntPtr root, string needle){
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(root,(h,l)=>{
      string c=ClassName(h); if(c!="ComboBox" && c!="ComboBoxEx32") return true;
      int n=SendMessageW(h,CB_GETCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32();
      for(int i=0;i<n && i<300;i++){
        int tlen=SendMessageW(h,CB_GETLBTEXTLEN,(IntPtr)i,IntPtr.Zero).ToInt32(); if(tlen<=0) continue;
        IntPtr buf=Marshal.AllocHGlobal((tlen+2)*2);
        try { SendMessageW(h,CB_GETLBTEXT,(IntPtr)i,buf); string t=Marshal.PtrToStringUni(buf)??""; if(t.IndexOf(needle,StringComparison.OrdinalIgnoreCase)>=0){ found=h; return false; } }
        finally { Marshal.FreeHGlobal(buf); }
      }
      return true;
    },IntPtr.Zero);
    return found;
  }
  public static int SelectComboText(IntPtr combo, string needle){
    int n=SendMessageW(combo,CB_GETCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32();
    for(int i=0;i<n;i++){
      int tlen=SendMessageW(combo,CB_GETLBTEXTLEN,(IntPtr)i,IntPtr.Zero).ToInt32(); if(tlen<=0) continue;
      IntPtr buf=Marshal.AllocHGlobal((tlen+2)*2);
      try { SendMessageW(combo,CB_GETLBTEXT,(IntPtr)i,buf); string t=Marshal.PtrToStringUni(buf)??"";
        if(t.IndexOf(needle,StringComparison.OrdinalIgnoreCase)>=0){ SendMessageW(combo,CB_SETCURSEL,(IntPtr)i,IntPtr.Zero); return i; } }
      finally { Marshal.FreeHGlobal(buf); }
    }
    return -1;
  }
}
