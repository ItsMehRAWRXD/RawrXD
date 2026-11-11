param(
  [Parameter(Mandatory)][string]$Exe,
  [Parameter(Mandatory)][string]$Sha256,
  [Parameter(Mandatory)][string]$EvidenceDir,
  [string]$Marker = 'RAWRXD_T10_UIA_REAL_MARKER_20261104'
)
$ErrorActionPreference='Stop'
Import-Module "F:\rawrxd\tools\uia\RawrXD.UIA.psm1" -Force
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$s=Start-RawrSession -Exe $Exe -Sha256 $Sha256 -EvidenceDir $EvidenceDir
$s2=$null
try {
  if(-not ('RawrXD_NativeFocus' -as [type])) {
    Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class RawrXD_NativeFocus {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc cb, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder b, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a,uint b,bool attach);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int l; public int t; public int r; public int b; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out RECT r);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h,out RECT r);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct GUITHREADINFO { public int cbSize; public uint flags; public IntPtr active; public IntPtr focus; public IntPtr capture; public IntPtr menu; public IntPtr move; public IntPtr caret; public RECT caretRect; }
  [DllImport("user32.dll")] public static extern bool GetGUIThreadInfo(uint id,ref GUITHREADINFO info);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint flags,uint dx,uint dy,uint data,UIntPtr extra);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int SendMessage(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")] public static extern int SendMessageText(IntPtr h,uint m,IntPtr w,StringBuilder l);
  public static string Text(IntPtr h) {
    const uint LEN=0x000E, GET=0x000D;
    int n=SendMessage(h,LEN,IntPtr.Zero,IntPtr.Zero); if(n<=0)return "";
    var b=new StringBuilder(n+1); SendMessageText(h,GET,(IntPtr)b.Capacity,b); return b.ToString();
  }
  public static IntPtr FindRichEdit(IntPtr root) {
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(root,(h,p)=>{var b=new StringBuilder(128);GetClassName(h,b,b.Capacity);var cn=b.ToString(); if(cn.StartsWith("RichEdit",StringComparison.OrdinalIgnoreCase)||cn.StartsWith("RICHEDIT",StringComparison.OrdinalIgnoreCase)){found=h;return false;}return true;},IntPtr.Zero);
    return found;
  }
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
  public static void TypeUnicode(string text) {
    foreach(char c in text) {
      keybd_event(0,(byte)(c & 0xff),4,UIntPtr.Zero);
      keybd_event(0,(byte)(c & 0xff),6,UIntPtr.Zero);
    }
  }
  public static void Paste() {
    keybd_event(0x11,0,0,UIntPtr.Zero); keybd_event(0x56,0,0,UIntPtr.Zero); keybd_event(0x56,0,2,UIntPtr.Zero); keybd_event(0x11,0,2,UIntPtr.Zero);
  }
  public static void Focus(IntPtr main, IntPtr edit) {
    uint current=GetCurrentThreadId(); uint foreground=GetWindowThreadProcessId(GetForegroundWindow(),IntPtr.Zero); uint target=GetWindowThreadProcessId(main,IntPtr.Zero);
    if(foreground!=0 && foreground!=current) AttachThreadInput(current,foreground,true);
    if(target!=0 && target!=current) AttachThreadInput(current,target,true);
    SetForegroundWindow(main); SetFocus(edit);
    if(target!=0 && target!=current) AttachThreadInput(current,target,false);
    if(foreground!=0 && foreground!=current) AttachThreadInput(current,foreground,false);
  }
  public static void ClickAndFocus(IntPtr main, IntPtr edit) {
    RECT r; if(!GetWindowRect(edit,out r)) throw new InvalidOperationException("GetWindowRect failed");
    int x=(r.l+r.r)/2, y=(r.t+r.b)/2; SetCursorPos(x,y); mouse_event(2,0,0,0,UIntPtr.Zero); mouse_event(4,0,0,0,UIntPtr.Zero); Focus(main,edit);
  }
  public static string FocusReport(IntPtr main, IntPtr edit) {
    RECT r; GetClientRect(edit,out r); uint tid=GetWindowThreadProcessId(main,IntPtr.Zero); var gi=new GUITHREADINFO{cbSize=Marshal.SizeOf(typeof(GUITHREADINFO))}; GetGUIThreadInfo(tid,ref gi);
    return String.Format("main=0x{0:X};editor=0x{1:X};focus=0x{2:X};active=0x{3:X};editorId={4};visible={5};enabled={6};client={7}x{8}",main.ToInt64(),edit.ToInt64(),gi.focus.ToInt64(),gi.active.ToInt64(),GetDlgCtrlID(edit),IsWindowVisible(edit),IsWindowEnabled(edit),r.r-r.l,r.b-r.t);
  }
}
'@
  }
  $editor=$null
try { $editor=Find-RawrControl $s -AutomationId '1001' } catch { $editor=$null }
if(-not $editor){
  try { $editor=Find-RawrControl $s -AutomationId '1001' -ClassName 'RICHEDIT50W' } catch { $editor=$null }
}
if(-not $editor){
  try { $editor=Find-RawrControl $s -AutomationId '1001' -ClassName 'RichEdit20W' } catch { $editor=$null }
}
if(-not $editor){ throw 'EDITOR_AUTOMATION_1001_NOT_FOUND' }
  $p=Get-Process -Id $s.Pid -ErrorAction Stop
  if($p.Path -ne $s.Exe){throw 'PID_EXECUTABLE_MISMATCH'}
  $hwnd=[IntPtr]$editor.Current.NativeWindowHandle
  if($hwnd -eq [IntPtr]::Zero){
    for($attempt=0;$attempt -lt 20 -and $hwnd -eq [IntPtr]::Zero;$attempt++){
      $hwnd=[RawrXD_NativeFocus]::FindRichEdit($p.MainWindowHandle)
      if($hwnd -eq [IntPtr]::Zero){Start-Sleep -Milliseconds 250}
    }
  }
  if($hwnd -eq [IntPtr]::Zero){throw 'NATIVE_RICHEDIT_NOT_FOUND'}
  [RawrXD_NativeFocus]::ClickAndFocus($p.MainWindowHandle,$hwnd)
  $focusBefore=[RawrXD_NativeFocus]::FocusReport($p.MainWindowHandle,$hwnd)
  Add-Type -AssemblyName System.Windows.Forms
  [System.Windows.Forms.Clipboard]::SetText($Marker)
  [RawrXD_NativeFocus]::Paste()
  $focusAfter=[RawrXD_NativeFocus]::FocusReport($p.MainWindowHandle,$hwnd)
  $editorText=''
  try { $editorText=Get-RawrControlText $s $editor } catch { $editorText=[RawrXD_NativeFocus]::Text($hwnd) }
  if($editorText -notlike "*$Marker*"){throw "EDITOR_MARKER_NOT_OBSERVED;FOCUS_BEFORE=$focusBefore;FOCUS_AFTER=$focusAfter"}
  # The native file-safety checkpoint is debounced; allow the timer to fire
  # before judging persistence rather than racing the autosave worker.
  Start-Sleep -Seconds 8
  $sessionPath=Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
  if(-not (Test-Path $sessionPath)){throw "AUTOSAVE_NOT_FOUND: $sessionPath"}
  $autosave=Get-Content $sessionPath -Raw
  if($autosave -notlike "*$Marker*"){throw 'AUTOSAVE_MARKER_NOT_FOUND'}
  $receipt=[ordered]@{Gate='T10';Result='AUTOSAVE_READY';CandidateSHA256=$s.SHA256;PID=$s.Pid;Marker=$Marker;SessionPath=$sessionPath;AutosaveSHA256=(Get-RawrHash $sessionPath);TimestampUtc=[DateTime]::UtcNow.ToString('o')}
  $receipt|ConvertTo-Json|Set-Content (Join-Path $EvidenceDir 't10-before-kill.json') -Encoding UTF8
  $p=Get-Process -Id $s.Pid -ErrorAction Stop
  if($p.Path -ne $s.Exe){throw 'PID_EXECUTABLE_MISMATCH'}
  $p.Kill();$p.WaitForExit(10000)|Out-Null
  if(-not $p.HasExited){throw 'HARD_KILL_FAILED'}
  $s2=Start-RawrSession -Exe $Exe -Sha256 $Sha256 -EvidenceDir $EvidenceDir
  Start-Sleep -Seconds 4
  $sessionAfterRestart=''
  $sessionContainsMarkerAfterRestart=$false
  if(Test-Path -LiteralPath $sessionPath){
    $sessionAfterRestart=Get-Content -LiteralPath $sessionPath -Raw
    $sessionContainsMarkerAfterRestart=$sessionAfterRestart -like "*$Marker*"
  }
  $root=Get-RawrRoot $s2
  $all=$root.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
  $recoveredElement=$null
  try { $recoveredElement=Find-RawrControl $s2 -AutomationId '1001' } catch { $recoveredElement=$null }
  if(-not $recoveredElement){
    try { $recoveredElement=Find-RawrControl $s2 -AutomationId '1001' -ClassName 'RICHEDIT50W' } catch { $recoveredElement=$null }
  }
  if(-not $recoveredElement){ throw 'RECOVERED_EDITOR_1001_NOT_FOUND' }
  $recovered=[IntPtr]$recoveredElement.Current.NativeWindowHandle
  $recoveredText=''
  try { $recoveredText=Get-RawrControlText $s2 $recoveredElement } catch { if($recovered -ne [IntPtr]::Zero){$recoveredText=[RawrXD_NativeFocus]::Text($recovered)} }
  $found=$recoveredText -like "*$Marker*"
  $result=if($found){'PASS'}else{'FAIL'}
  $final=[ordered]@{Gate='T10';Result=$result;CandidateSHA256=$s2.SHA256;PIDBefore=$s.Pid;PIDAfter=$s2.Pid;Marker=$Marker;EditorMarkerObserved=$true;AutosaveMarkerObserved=$true;HardKillConfirmed=$true;RecoveredEditorMarkerObserved=$found;RecoveredSessionMarkerObserved=$sessionContainsMarkerAfterRestart;RecoveredEditorTextLength=$recoveredText.Length;RecoveredSessionTextLength=$sessionAfterRestart.Length;SessionPath=$sessionPath;TimestampUtc=[DateTime]::UtcNow.ToString('o')}
  $final|ConvertTo-Json|Set-Content (Join-Path $EvidenceDir 'T10.receipt.json') -Encoding UTF8
  $final|ConvertTo-Json
  if($result -ne 'PASS'){exit 1}
} catch {
  $failure=[ordered]@{Gate='T10';Result='NOT_VERIFIED';CandidateSHA256=$s.SHA256;PID=$s.Pid;Error=$_.Exception.Message;TimestampUtc=[DateTime]::UtcNow.ToString('o')}
  $failure|ConvertTo-Json|Set-Content (Join-Path $EvidenceDir 'T10.receipt.json') -Encoding UTF8
  $failure|ConvertTo-Json
  exit 1
} finally {
  if($s2){
    $restart=Get-Process -Id $s2.Pid -ErrorAction SilentlyContinue
    if($restart){
      try { Stop-RawrTestProcess $s2 } catch { Write-Warning "Harness cleanup failed for PID $($s2.Pid): $($_.Exception.Message)" }
    }
  }
}


