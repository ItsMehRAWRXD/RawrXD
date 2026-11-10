param([Parameter(Mandatory)][string]$Exe,[Parameter(Mandatory)][string]$Sha256,[Parameter(Mandatory)][string]$EvidenceDir)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
if(-not ('RawrXD_T05Diag' -as [type])){Add-Type @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class RawrXD_T05Diag {
 [DllImport("user32.dll")] public static extern IntPtr FindWindowEx(IntPtr p,IntPtr c,string cls,string name);
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
 [DllImport("user32.dll")] public static extern IntPtr GetFocus();
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,IntPtr p);
 [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
 [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a,uint b,bool on);
 [DllImport("user32.dll")] public static extern bool GetGUIThreadInfo(uint id,ref GUITHREADINFO i);
 [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h,StringBuilder b,int n);
 [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h,uint m,IntPtr w,IntPtr l);
 [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h,uint m,IntPtr w,IntPtr l);
 [DllImport("user32.dll")] public static extern void keybd_event(byte v,byte s,uint f,UIntPtr e);
 [DllImport("user32.dll")] public static extern bool OpenClipboard(IntPtr h);
 [DllImport("user32.dll")] public static extern bool CloseClipboard();
 [DllImport("user32.dll")] public static extern IntPtr GetClipboardData(uint f);
 [DllImport("user32.dll")] public static extern int IsClipboardFormatAvailable(uint f);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr GlobalLock(IntPtr h);
 [DllImport("kernel32.dll")] public static extern bool GlobalUnlock(IntPtr h);
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
 [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint x,uint y,uint d,UIntPtr e);
 [StructLayout(LayoutKind.Sequential)] public struct GUITHREADINFO{public int cbSize;public int flags;public IntPtr hwndActive,hwndFocus,hwndCapture,hwndMenuOwner,hwndMoveSize,hwndCaret;public RECT rcCaret;}
 [StructLayout(LayoutKind.Sequential)] public struct RECT{public int l,t,r,b;}
 public static string Text(IntPtr h){int n=GetWindowTextLength(h);var b=new StringBuilder(Math.Max(n+1,2));GetWindowText(h,b,b.Capacity);return b.ToString();}
 public static void Focus(IntPtr main,IntPtr edit){uint c=GetCurrentThreadId(),t=GetWindowThreadProcessId(main,IntPtr.Zero);if(t!=0&&t!=c)AttachThreadInput(c,t,true);SetForegroundWindow(main);SetFocus(edit);if(t!=0&&t!=c)AttachThreadInput(c,t,false);}
 public static string FocusInfo(IntPtr main){uint t=GetWindowThreadProcessId(main,IntPtr.Zero);var i=new GUITHREADINFO();i.cbSize=Marshal.SizeOf(i);if(!GetGUIThreadInfo(t,ref i))return "GUIINFO_FAILED";return String.Format("focus=0x{0:X};active=0x{1:X};capture=0x{2:X}",i.hwndFocus.ToInt64(),i.hwndActive.ToInt64(),i.hwndCapture.ToInt64());}
 public static void Key(byte vk){keybd_event(vk,0,0,UIntPtr.Zero);keybd_event(vk,0,2,UIntPtr.Zero);}
 public static void Char(IntPtr h,char c){PostMessage(h,0x0102,(IntPtr)c,IntPtr.Zero);}
 public static int SetText(IntPtr h,string s){IntPtr p=Marshal.StringToHGlobalUni(s);try{return SendMessage(h,0x000C,IntPtr.Zero,p).ToInt32();}finally{Marshal.FreeHGlobal(p);}}
 public static int Replace(IntPtr h,string s){IntPtr p=Marshal.StringToHGlobalUni(s);try{return SendMessage(h,0x00C2,IntPtr.Zero,p).ToInt32();}finally{Marshal.FreeHGlobal(p);}}
 public static int Length(IntPtr h){return SendMessage(h,0x000E,IntPtr.Zero,IntPtr.Zero).ToInt32();}
 public static int Modify(IntPtr h){return SendMessage(h,0x00B8,IntPtr.Zero,IntPtr.Zero).ToInt32();}
 public static void CtrlV(){keybd_event(0x11,0,0,UIntPtr.Zero);keybd_event(0x56,0,0,UIntPtr.Zero);keybd_event(0x56,0,2,UIntPtr.Zero);keybd_event(0x11,0,2,UIntPtr.Zero);}
 public static string Clipboard(){if(IsClipboardFormatAvailable(13)==0||!OpenClipboard(IntPtr.Zero))return "NO_UNICODE_CLIPBOARD";try{IntPtr d=GetClipboardData(13);if(d==IntPtr.Zero)return "EMPTY_UNICODE_CLIPBOARD";IntPtr p=GlobalLock(d);if(p==IntPtr.Zero)return "LOCK_FAILED";try{string s=Marshal.PtrToStringUni(p);return s==null?"":s;}finally{GlobalUnlock(d);}}finally{CloseClipboard();}}
}
'@}
Import-Module "$PSScriptRoot\RawrXD.UIA.psm1" -Force
$s=Start-RawrSession -Exe $Exe -Sha256 $Sha256 -EvidenceDir $EvidenceDir
$e=Find-RawrControl $s -AutomationId '1202'; $p=Get-Process -Id $s.Pid; $h=[IntPtr]$e.Current.NativeWindowHandle
$rows=@(); function ReadUia(){try{return Get-RawrControlText $s $e}catch{return ''}}; function Row($phase){$script:rows+=[pscustomobject]@{Phase=$phase;Hwnd=('0x{0:X}' -f $h.ToInt64());Focus=[RawrXD_T05Diag]::FocusInfo($p.MainWindowHandle);Text=[RawrXD_T05Diag]::Text($h);Length=[RawrXD_T05Diag]::Length($h);Modify=[RawrXD_T05Diag]::Modify($h);UIA=(ReadUia)}}
Row 'before'
[RawrXD_T05Diag]::Focus($p.MainWindowHandle,$h); [RawrXD_T05Diag]::Key(0x58); Start-Sleep -Milliseconds 250; Row 'keyboard_X'
[System.Windows.Forms.Clipboard]::SetText('PASTE_X'); [RawrXD_T05Diag]::Focus($p.MainWindowHandle,$h); [RawrXD_T05Diag]::CtrlV(); Start-Sleep -Milliseconds 250; Row 'paste_ctrlv'
[RawrXD_T05Diag]::Char($h,'Z'); Start-Sleep -Milliseconds 100; Row 'wm_char'
$set=[RawrXD_T05Diag]::SetText($h,'SETTEXT_CONTROL_ONLY'); Start-Sleep -Milliseconds 100; Row "wm_settext_control_return_$set"
$rep=[RawrXD_T05Diag]::Replace($h,'REPLACESEL_CONTROL_ONLY'); Start-Sleep -Milliseconds 100; Row "em_replacesel_return_$rep"
$rows|ConvertTo-Json -Depth 6|Set-Content (Join-Path $EvidenceDir 'T05_input_matrix.json') -Encoding UTF8
$rows
