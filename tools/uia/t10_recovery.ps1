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
  public static IntPtr FindRichEdit(IntPtr root) {
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(root,(h,p)=>{var b=new StringBuilder(128);GetClassName(h,b,b.Capacity);if(b.ToString().StartsWith("RichEdit20",StringComparison.OrdinalIgnoreCase)){found=h;return false;}return true;},IntPtr.Zero);
    return found;
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
  Add-Type -AssemblyName System.Windows.Forms
  [System.Windows.Forms.SendKeys]::SendWait($Marker)
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
  $found=$false
  for($i=0;$i -lt $all.Count;$i++){try{$e=$all.Item($i);if($e.Current.ProcessId -eq $s2.Pid -and $e.Current.Name -like "*$Marker*"){$found=$true;break}}catch{}}
  $result=if($found){'PASS'}else{'FAIL'}
  $final=[ordered]@{Gate='T10';Result=$result;CandidateSHA256=$s2.SHA256;PIDBefore=$s.Pid;PIDAfter=$s2.Pid;Marker=$Marker;RecoveredMarkerObserved=$found;TimestampUtc=[DateTime]::UtcNow.ToString('o')}
  $final|ConvertTo-Json|Set-Content (Join-Path $EvidenceDir 'T10.receipt.json') -Encoding UTF8
  $final|ConvertTo-Json
} catch {
  $failure=[ordered]@{Gate='T10';Result='NOT_VERIFIED';CandidateSHA256=$s.SHA256;PID=$s.Pid;Error=$_.Exception.Message;TimestampUtc=[DateTime]::UtcNow.ToString('o')}
  $failure|ConvertTo-Json|Set-Content (Join-Path $EvidenceDir 'T10.receipt.json') -Encoding UTF8
  throw
}
