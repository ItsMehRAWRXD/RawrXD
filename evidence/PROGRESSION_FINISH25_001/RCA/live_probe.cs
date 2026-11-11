using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
public class Rca {
  public delegate bool EW(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EW cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EW cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern int GetWindowTextLengthW(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetPropW(IntPtr h, string n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public const uint TCM_GETITEMCOUNT_CORRECT=0x1304, TCM_GETROWCOUNT=0x132C, TCM_WRONG=0x132C;
  public const uint EM_SETSEL=0x00B1, EM_REPLACESEL=0x00C2, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E;
  public const int IDC_EDITOR=1001, IDC_DOC_TABS=1030;
  public static string CN(IntPtr h){ var s=new StringBuilder(128); GetClassNameW(h,s,s.Capacity); return s.ToString(); }
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true;
      if(CN(h)=="RawrXD_IDE_Window"){ f=h; return false;} return true; }, IntPtr.Zero); return f; }
  public static void Main(string[] args){
    string exe=args[0], uni=args[1], outDir=args[2];
    var psi=new ProcessStartInfo(exe, "\""+uni+"\""){ UseShellExecute=false, WorkingDirectory=System.IO.Path.GetDirectoryName(exe) };
    var proc=Process.Start(psi);
    IntPtr main=IntPtr.Zero; for(int i=0;i<80 && main==IntPtr.Zero;i++){ Thread.Sleep(250); try{ proc.Refresh(); }catch{} if(proc.HasExited) break; main=FindMain((uint)proc.Id); }
    var sb=new StringBuilder();
    sb.AppendLine("PID="+proc.Id);
    sb.AppendLine("MAIN=0x"+main.ToString("X"));
    IntPtr editor=IntPtr.Zero, tabsProp=IntPtr.Zero, tabsId=IntPtr.Zero;
    if(main!=IntPtr.Zero){
      EnumChildWindows(main,(h,l)=>{
        int id=GetDlgCtrlID(h); string c=CN(h);
        if(id==IDC_EDITOR && editor==IntPtr.Zero && (c.IndexOf("RichEdit",StringComparison.OrdinalIgnoreCase)>=0 || c=="Edit")) editor=h;
        if(GetPropW(h,"RawrXDDocTabs")!=IntPtr.Zero) tabsProp=h;
        if(id==IDC_DOC_TABS && c.IndexOf("SysTabControl",StringComparison.OrdinalIgnoreCase)>=0){
          sb.AppendLine("CHILD_ID1030 hwnd=0x"+h.ToString("X")+" class="+c+" count1304="+SendMessageW(h,TCM_GETITEMCOUNT_CORRECT,IntPtr.Zero,IntPtr.Zero).ToInt32()+" rowcount132C="+SendMessageW(h,TCM_GETROWCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32());
          tabsId=h;
        }
        if(c.IndexOf("SysTabControl",StringComparison.OrdinalIgnoreCase)>=0){
          sb.AppendLine("TABCTRL hwnd=0x"+h.ToString("X")+" id="+GetDlgCtrlID(h)+" class="+c+" count1304="+SendMessageW(h,TCM_GETITEMCOUNT_CORRECT,IntPtr.Zero,IntPtr.Zero).ToInt32()+" rowcount132C="+SendMessageW(h,TCM_GETROWCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32()+" prop="+(GetPropW(h,"RawrXDDocTabs")!=IntPtr.Zero));
        }
        return true;
      }, IntPtr.Zero);
    }
    sb.AppendLine("EDITOR=0x"+editor.ToString("X")+" class="+(editor==IntPtr.Zero?"none":CN(editor)));
    sb.AppendLine("TABS_PROP=0x"+tabsProp.ToString("X"));
    sb.AppendLine("TABS_ID=0x"+tabsId.ToString("X"));
    if(tabsProp!=IntPtr.Zero){
      sb.AppendLine("PROP_MATCH_ID="+(tabsProp==tabsId));
      sb.AppendLine("PROP_count1304="+SendMessageW(tabsProp,TCM_GETITEMCOUNT_CORRECT,IntPtr.Zero,IntPtr.Zero).ToInt32());
      sb.AppendLine("PROP_rowcount132C="+SendMessageW(tabsProp,TCM_GETROWCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32());
    }
    Thread.Sleep(800);
    if(editor!=IntPtr.Zero){
      int len=GetWindowTextLengthW(editor);
      var t=new StringBuilder(len+8); GetWindowTextW(editor,t,t.Capacity);
      string got=t.ToString();
      sb.AppendLine("CLI_LOAD_TEXT="+got);
      sb.AppendLine("CLI_HAS_4F60="+(got.IndexOf((char)0x4F60)>=0));
      sb.Append("CLI_CPS=");
      foreach(char ch in got){ if(sb.Length>0){} sb.Append(((int)ch).ToString("X4")+" "); }
      sb.AppendLine();
      // Direct Unicode write probe
      SetWindowTextW(editor, "PROBE-"+(char)0x4F60+(char)0x597D+"-END");
      Thread.Sleep(100);
      len=GetWindowTextLengthW(editor); t=new StringBuilder(len+8); GetWindowTextW(editor,t,t.Capacity); got=t.ToString();
      sb.AppendLine("SETW_TEXT="+got);
      sb.AppendLine("SETW_HAS_4F60="+(got.IndexOf((char)0x4F60)>=0));
      SendMessageW(editor, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
      SendMessageW(editor, EM_REPLACESEL, (IntPtr)0, "REPL-"+(char)0x4F60+(char)0x597D+"-END");
      Thread.Sleep(100);
      len=GetWindowTextLengthW(editor); t=new StringBuilder(len+8); GetWindowTextW(editor,t,t.Capacity); got=t.ToString();
      sb.AppendLine("REPL_TEXT="+got);
      sb.AppendLine("REPL_HAS_4F60="+(got.IndexOf((char)0x4F60)>=0));
    }
    System.IO.File.WriteAllText(System.IO.Path.Combine(outDir,"LIVE_PROBE.txt"), sb.ToString());
    Console.Write(sb.ToString());
    try { proc.Kill(); } catch {}
  }
}
