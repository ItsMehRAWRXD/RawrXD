# RawrXD native Windows UIAutomation controller. Windows PowerShell 5.1.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
if(-not ('RawrXD_UiaInput' -as [type])){Add-Type -ReferencedAssemblies System.Windows.Forms @'
using System; using System.Runtime.InteropServices;
public static class RawrXD_UiaInput {
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
 [DllImport("user32.dll")] public static extern void keybd_event(byte v,byte s,uint f,UIntPtr e);
 [StructLayout(LayoutKind.Sequential)] public struct RECT{public int l;public int t;public int r;public int b;}
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out RECT r);
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
 [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint x,uint y,uint d,UIntPtr e);
 public static void Paste(string t){System.Windows.Forms.Clipboard.SetText(t);keybd_event(0x11,0,0,UIntPtr.Zero);keybd_event(0x56,0,0,UIntPtr.Zero);keybd_event(0x56,0,2,UIntPtr.Zero);keybd_event(0x11,0,2,UIntPtr.Zero);}
 public static void Click(IntPtr h){RECT r;if(!GetWindowRect(h,out r))throw new InvalidOperationException("GetWindowRect failed");SetCursorPos((r.l+r.r)/2,(r.t+r.b)/2);mouse_event(2,0,0,0,UIntPtr.Zero);mouse_event(4,0,0,0,UIntPtr.Zero);}
}
'@}

function Get-RawrHash { param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}
function Assert-RawrCandidate { param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Sha256)
    $resolved=(Resolve-Path -LiteralPath $Path).Path; $actual=Get-RawrHash $resolved
    if($actual -ne $Sha256.ToUpperInvariant()){throw "Candidate SHA mismatch: expected $Sha256 actual $actual"}
    [pscustomobject]@{Path=$resolved;SHA256=$actual;Size=(Get-Item -LiteralPath $resolved).Length}
}
function Start-RawrSession { param([Parameter(Mandatory)][string]$Exe,[Parameter(Mandatory)][string]$Sha256,[string]$EvidenceDir)
    $id=Assert-RawrCandidate $Exe $Sha256
    if(-not $EvidenceDir){$EvidenceDir=Join-Path $PWD 'evidence-uia'}
    New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
    $p=Start-Process -FilePath $id.Path -WorkingDirectory (Split-Path $id.Path) -PassThru
    [pscustomobject]@{Pid=$p.Id;Exe=$id.Path;SHA256=$id.SHA256;Size=$id.Size;StartedUtc=[DateTime]::UtcNow.ToString('o');EvidenceDir=(Resolve-Path $EvidenceDir).Path}
}
function Get-RawrRoot { param([Parameter(Mandatory)]$Session,[int]$TimeoutSeconds=20)
    $until=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do { $p=Get-Process -Id $Session.Pid -ErrorAction SilentlyContinue
        if(-not $p){throw "RawrXD PID $($Session.Pid) exited"}; $p.Refresh()
        if($p.MainWindowHandle -ne [IntPtr]::Zero){$r=[System.Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle);if($r -and $r.Current.ProcessId -eq $Session.Pid){return $r}}
        Start-Sleep -Milliseconds 250
    } while([DateTime]::UtcNow -lt $until)
    throw "No main window for PID $($Session.Pid)"
}
function Find-RawrControl { param([Parameter(Mandatory)]$Session,[string]$Name,[string]$AutomationId,[string]$ClassName,[string]$ControlType)
    $root=Get-RawrRoot $Session; $all=$root.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
    for($i=0;$i -lt $all.Count;$i++){ $e=$all.Item($i);try{if($e.Current.ProcessId -ne $Session.Pid){continue};if($Name -and $e.Current.Name -ne $Name){continue};if($AutomationId -and $e.Current.AutomationId -ne $AutomationId){continue};if($ClassName -and $e.Current.ClassName -ne $ClassName){continue};if($ControlType -and $e.Current.ControlType.ProgrammaticName -ne "ControlType.$ControlType"){continue};return $e}catch [System.Windows.Automation.ElementNotAvailableException]{}}
    throw "Control not found in PID $($Session.Pid)"
}
function Get-RawrControlTree { param([Parameter(Mandatory)]$Session,[int]$Max=500)
    $root=Get-RawrRoot $Session;$all=$root.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition);$out=@()
    for($i=0;$i -lt [Math]::Min($all.Count,$Max);$i++){try{$e=$all.Item($i);if($e.Current.ProcessId -eq $Session.Pid){$out+=[pscustomobject]@{Name=$e.Current.Name;AutomationId=$e.Current.AutomationId;Class=$e.Current.ClassName;Type=$e.Current.ControlType.ProgrammaticName;Enabled=$e.Current.IsEnabled}}}catch{}}
    $out
}
function Set-RawrControlText { param([Parameter(Mandatory)]$Session,[Parameter(Mandatory)]$Element,[Parameter(Mandatory)][string]$Text)
    if($Element.Current.ProcessId -ne $Session.Pid){throw 'Cross-process control rejected'};$p=$null
    if($Element.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern,[ref]$p)){if($p.Current.IsReadOnly){throw 'Control is read-only'};$p.SetValue($Text);return}
    $p=Get-Process -Id $Session.Pid -ErrorAction Stop;$h=[IntPtr]$Element.Current.NativeWindowHandle
    if($h -eq [IntPtr]::Zero){throw 'No writable ValuePattern or native HWND'}
    if($p.Path -ne $Session.Exe){throw 'PID executable mismatch'}
    [RawrXD_UiaInput]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;[RawrXD_UiaInput]::SetFocus($h)|Out-Null
    [RawrXD_UiaInput]::Paste($Text)
}
function Invoke-RawrControl { param([Parameter(Mandatory)]$Session,[Parameter(Mandatory)]$Element)
    if($Element.Current.ProcessId -ne $Session.Pid -or -not $Element.Current.IsEnabled){throw 'Control identity/enabled check failed'};$p=$null
    if($Element.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern,[ref]$p)){$p.Invoke();return};if($Element.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern,[ref]$p)){$p.Select();return};$h=[IntPtr]$Element.Current.NativeWindowHandle;if($h -eq [IntPtr]::Zero){throw 'No supported invoke pattern or native HWND'};[RawrXD_UiaInput]::Click($h)
}
function Save-RawrScreenshot { param([Parameter(Mandatory)]$Session,[string]$Name='screen')
    $r=Get-RawrRoot $Session;$b=$r.Current.BoundingRectangle;$bmp=New-Object System.Drawing.Bitmap([int]$b.Width,[int]$b.Height);try{$g=[System.Drawing.Graphics]::FromImage($bmp);try{$g.CopyFromScreen([int]$b.X,[int]$b.Y,0,0,$bmp.Size)}finally{$g.Dispose()};$path=Join-Path $Session.EvidenceDir (($Name -replace '[^A-Za-z0-9_-]','_')+'.png');$bmp.Save($path,[System.Drawing.Imaging.ImageFormat]::Png);[pscustomobject]@{Path=$path;SHA256=(Get-RawrHash $path)}}finally{$bmp.Dispose()}
}
function Stop-RawrTestProcess { param([Parameter(Mandatory)]$Session)
    $p=Get-Process -Id $Session.Pid -ErrorAction Stop;if($p.Path -ne $Session.Exe){throw 'PID executable mismatch'};if($p.StartTime.ToUniversalTime() -lt [datetime]::Parse($Session.StartedUtc).AddSeconds(-2)){throw 'PID reuse suspected'};$p.Kill();$p.WaitForExit(10000)|Out-Null;if(-not $p.HasExited){throw 'termination failed'}
}
function Write-RawrReceipt { param([Parameter(Mandatory)]$Session,[Parameter(Mandatory)][string]$Gate,[Parameter(Mandatory)][ValidateSet('PASS','FAIL','NOT_VERIFIED')][string]$Result,[Parameter(Mandatory)][string]$Observed,[hashtable]$Artifacts=@{})
    $r=[ordered]@{Gate=$Gate;Result=$Result;Observed=$Observed;CandidateSHA256=$Session.SHA256;Executable=$Session.Exe;PID=$Session.Pid;TimestampUtc=[DateTime]::UtcNow.ToString('o');Artifacts=$Artifacts};$path=Join-Path $Session.EvidenceDir "$Gate.receipt.json";$r|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $path -Encoding UTF8;$path
}
Export-ModuleMember -Function *-Rawr*
