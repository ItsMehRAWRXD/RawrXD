param(
  [Parameter(Mandatory)][string]$Exe,
  [Parameter(Mandatory)][string]$Sha256,
  [Parameter(Mandatory)][string]$EvidenceDir,
  [string]$Marker = 'RAWRXD_T10_UIA_REAL_MARKER_20261104'
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\RawrXD.UIA.psm1" -Force
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$s=Start-RawrSession -Exe $Exe -Sha256 $Sha256 -EvidenceDir $EvidenceDir
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
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int SendMessage(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")] public static extern int SendMessageText(IntPtr h,uint m,IntPtr w,StringBuilder l);
  public static string Text(IntPtr h) {
    const uint LEN=0x000E, GET=0x000D;
    int n=SendMessage(h,LEN,IntPtr.Zero,IntPtr.Zero); if(n<=0)return "";
    var b=new StringBuilder(n+1); SendMessageText(h,GET,(IntPtr)b.Capacity,b); return b.ToString();
  }
  public static IntPtr FindRichEdit(IntPtr root) {
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(root,(h,p)=>{var b=new StringBuilder(128);GetClassName(h,b,b.Capacity);if(b.ToString().StartsWith("RichEdit20",StringComparison.OrdinalIgnoreCase)){found=h;return false;}return true;},IntPtr.Zero);
    return found;
  }
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
  public static void TypeUnicode(string text) {
    foreach(char c in text) {
      keybd_event(0,(byte)(c & 0xff),4,UIntPtr.Zero);
      keybd_event(0,(byte)(c & 0xff),6,UIntPtr.Zero);
    }
  }
}
'@
  }
  $editor=Find-RawrControl $s -ClassName 'RichEdit20W'
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
  [RawrXD_NativeFocus]::SetForegroundWindow($p.MainWindowHandle)|Out-Null
  [RawrXD_NativeFocus]::SetFocus($hwnd)|Out-Null
  [RawrXD_NativeFocus]::TypeUnicode($Marker)
  $editorText=[RawrXD_NativeFocus]::Text($hwnd)
  if($editorText -notlike "*$Marker*"){throw 'EDITOR_MARKER_NOT_OBSERVED'}
  Start-Sleep -Seconds 3
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
  $root=Get-RawrRoot $s2
  $all=$root.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
  $recovered=[RawrXD_NativeFocus]::FindRichEdit((Get-Process -Id $s2.Pid).MainWindowHandle)
  $recoveredText=if($recovered -ne [IntPtr]::Zero){[RawrXD_NativeFocus]::Text($recovered)}else{''}
  $found=$recoveredText -like "*$Marker*"
  $result=if($found){'PASS'}else{'FAIL'}
  $final=[ordered]@{Gate='T10';Result=$result;CandidateSHA256=$s2.SHA256;PIDBefore=$s.Pid;PIDAfter=$s2.Pid;Marker=$Marker;EditorMarkerObserved=$true;RecoveredEditorMarkerObserved=$found;TimestampUtc=[DateTime]::UtcNow.ToString('o')}
  $final|ConvertTo-Json|Set-Content (Join-Path $EvidenceDir 'T10.receipt.json') -Encoding UTF8
  $final|ConvertTo-Json
} catch {
  $failure=[ordered]@{Gate='T10';Result='NOT_VERIFIED';CandidateSHA256=$s.SHA256;PID=$s.Pid;Error=$_.Exception.Message;TimestampUtc=[DateTime]::UtcNow.ToString('o')}
  $failure|ConvertTo-Json|Set-Content (Join-Path $EvidenceDir 'T10.receipt.json') -Encoding UTF8
  throw
}
