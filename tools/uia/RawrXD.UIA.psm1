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
 [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,IntPtr p);
 [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a,uint b,bool on);
 [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
 [DllImport("user32.dll")] public static extern void keybd_event(byte v,byte s,uint f,UIntPtr e);
 [StructLayout(LayoutKind.Sequential)] public struct RECT{public int l;public int t;public int r;public int b;}
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out RECT r);
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
 [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint x,uint y,uint d,UIntPtr e);
 [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p,EnumProc cb,IntPtr l);
 public delegate bool EnumProc(IntPtr h,IntPtr l);
 [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,System.Text.StringBuilder b,int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextLength(IntPtr h);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h,System.Text.StringBuilder b,int n);
 [DllImport("user32.dll")] public static extern IntPtr GetWindowLongPtr(IntPtr h,int i);
 [DllImport("user32.dll")] public static extern int SendMessage(IntPtr h,uint m,IntPtr w,IntPtr l);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,EntryPoint="SendMessageW")] public static extern IntPtr SendMessageText(IntPtr h,uint m,IntPtr w,System.Text.StringBuilder l);
 public static void Paste(string t){System.Windows.Forms.Clipboard.SetText(t);keybd_event(0x11,0,0,UIntPtr.Zero);keybd_event(0x56,0,0,UIntPtr.Zero);keybd_event(0x56,0,2,UIntPtr.Zero);keybd_event(0x11,0,2,UIntPtr.Zero);}
 public static void Clear(){keybd_event(0x11,0,0,UIntPtr.Zero);keybd_event(0x41,0,0,UIntPtr.Zero);keybd_event(0x41,0,2,UIntPtr.Zero);keybd_event(0x11,0,2,UIntPtr.Zero);keybd_event(0x2E,0,0,UIntPtr.Zero);keybd_event(0x2E,0,2,UIntPtr.Zero);}
 public static void Click(IntPtr h){RECT r;if(!GetWindowRect(h,out r))throw new InvalidOperationException("GetWindowRect failed");SetCursorPos((r.l+r.r)/2,(r.t+r.b)/2);mouse_event(2,0,0,0,UIntPtr.Zero);mouse_event(4,0,0,0,UIntPtr.Zero);}
 public static void Focus(IntPtr main,IntPtr edit){uint c=GetCurrentThreadId(),f=GetWindowThreadProcessId(GetForegroundWindow(),IntPtr.Zero),t=GetWindowThreadProcessId(main,IntPtr.Zero);if(f!=0&&f!=c)AttachThreadInput(c,f,true);if(t!=0&&t!=c)AttachThreadInput(c,t,true);SetForegroundWindow(main);SetFocus(edit);if(t!=0&&t!=c)AttachThreadInput(c,t,false);if(f!=0&&f!=c)AttachThreadInput(c,f,false);}
 public static IntPtr FindChildById(IntPtr root,int id){IntPtr found=IntPtr.Zero;EnumChildWindows(root,(h,l)=>{if(GetDlgCtrlID(h)==id){found=h;return false;}return true;},IntPtr.Zero);return found;}
 public static string Text(IntPtr h){int n=SendMessage(h,0x000E,IntPtr.Zero,IntPtr.Zero);if(n<=0)return "";var b=new System.Text.StringBuilder(n+1);SendMessageText(h,0x000D,(IntPtr)b.Capacity,b);return b.ToString();}
 public static string Class(IntPtr h){var b=new System.Text.StringBuilder(128);GetClassName(h,b,b.Capacity);return b.ToString();}
 public static int ReadOnly(IntPtr h){return SendMessage(h,0x00CE,IntPtr.Zero,IntPtr.Zero);}
 public static long Style(IntPtr h){return GetWindowLongPtr(h,-16).ToInt64();}
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
    if($h -eq [IntPtr]::Zero -and $Element.Current.AutomationId){$h=[RawrXD_UiaInput]::FindChildById($p.MainWindowHandle,[int]$Element.Current.AutomationId)}
    if($h -eq [IntPtr]::Zero){throw 'No writable ValuePattern or native HWND'}
    if($p.Path -ne $Session.Exe){throw 'PID executable mismatch'}
    [RawrXD_UiaInput]::Click($h);[RawrXD_UiaInput]::Focus($p.MainWindowHandle,$h)
    [RawrXD_UiaInput]::Clear();Start-Sleep -Milliseconds 75;[RawrXD_UiaInput]::Paste($Text);Start-Sleep -Milliseconds 150
}
function Get-RawrNativeDiagnostics { param([Parameter(Mandatory)]$Session,[Parameter(Mandatory)]$Element)
    $p=Get-Process -Id $Session.Pid -ErrorAction Stop;$h=[IntPtr]$Element.Current.NativeWindowHandle;if($h -eq [IntPtr]::Zero -and $Element.Current.AutomationId){$h=[RawrXD_UiaInput]::FindChildById($p.MainWindowHandle,[int]$Element.Current.AutomationId)}
    if($h -eq [IntPtr]::Zero){throw 'chat input native HWND unavailable'}
    $u='';try{$u=Get-RawrControlText $Session $Element}catch{}
    [pscustomobject]@{Hwnd=('0x{0:X}' -f $h.ToInt64());ControlId=[RawrXD_UiaInput]::GetDlgCtrlID($h);Class=[RawrXD_UiaInput]::Class($h);Style=('0x{0:X}' -f [RawrXD_UiaInput]::Style($h));ReadOnly=[RawrXD_UiaInput]::ReadOnly($h);Visible=[RawrXD_UiaInput]::IsWindowVisible($h);Enabled=[RawrXD_UiaInput]::IsWindowEnabled($h);NativeText=[RawrXD_UiaInput]::Text($h);UIAText=$u}
}
function Get-RawrControlText { param([Parameter(Mandatory)]$Session,[Parameter(Mandatory)]$Element)
    if($Element.Current.ProcessId -ne $Session.Pid){throw 'Cross-process control rejected'}
    $p=Get-Process -Id $Session.Pid -ErrorAction Stop
    $h=[IntPtr]$Element.Current.NativeWindowHandle
    if($h -eq [IntPtr]::Zero -and $Element.Current.AutomationId){$h=[RawrXD_UiaInput]::FindChildById($p.MainWindowHandle,[int]$Element.Current.AutomationId)}
    if($h -eq [IntPtr]::Zero){throw 'No native HWND for control text readback'}
    if($p.Path -ne $Session.Exe){throw 'PID executable mismatch'}
    [RawrXD_UiaInput]::Text($h)
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
