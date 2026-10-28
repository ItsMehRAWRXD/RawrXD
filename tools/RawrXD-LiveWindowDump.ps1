param(
    [string]$ProcessName = 'RawrXD-Win32IDE',
    [string]$OutputDirectory = (Join-Path $PWD ('RawrXD-UI-Dump-' + (Get-Date -Format 'yyyyMMdd-HHmmss')))
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path $OutputDirectory).Path
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$source = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
public static class NativeUiDump {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct WINDOWINFO {
      public uint cbSize; public RECT rcWindow; public RECT rcClient; public uint dwStyle, dwExStyle, dwWindowStatus, cxWindowBorders, cyWindowBorders; public ushort atomWindowType, wCreatorVersion;
    }
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr p);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumWindowsProc cb, IntPtr p);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
    [DllImport("user32.dll", SetLastError=true)] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int max);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int max);
    [DllImport("user32.dll")] public static extern bool GetWindowInfo(IntPtr h, ref WINDOWINFO i);
    [DllImport("user32.dll")] public static extern IntPtr GetWindow(IntPtr h, uint command);
    [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    public static string Class(IntPtr h) { var b=new StringBuilder(512); GetClassName(h,b,b.Capacity); return b.ToString(); }
    public static string Title(IntPtr h) { var b=new StringBuilder(1024); GetWindowText(h,b,b.Capacity); return b.ToString(); }
    public static List<IntPtr> Top() { var a=new List<IntPtr>(); EnumWindows((h,p)=>{a.Add(h);return true;},IntPtr.Zero); return a; }
    public static List<IntPtr> Children(IntPtr h) { var a=new List<IntPtr>(); EnumChildWindows(h,(c,p)=>{a.Add(c);return true;},IntPtr.Zero); return a; }
}
'@
Add-Type -TypeDefinition $source
try { [NativeUiDump]::SetProcessDPIAware() | Out-Null } catch {}
$allProcesses = @(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate)
$matches = @($allProcesses | Where-Object { $_.Name -like "*$ProcessName*" -or ($_.ExecutablePath -and [IO.Path]::GetFileNameWithoutExtension($_.ExecutablePath) -like "*$ProcessName*") })
if (-not $matches.Count) { throw "No running process matching '$ProcessName'. Start the executable and try again." }
$rootIds = @($matches | ForEach-Object { [int]$_.ProcessId })
$relatedIds = New-Object 'System.Collections.Generic.HashSet[int]'
foreach($id in $rootIds) { [void]$relatedIds.Add($id) }
do {
    $changed = $false
    foreach($proc in $allProcesses) {
        if($relatedIds.Contains([int]$proc.ParentProcessId) -and -not $relatedIds.Contains([int]$proc.ProcessId)) { [void]$relatedIds.Add([int]$proc.ProcessId); $changed = $true }
    }
} while($changed)
$processes = @($allProcesses | Where-Object { $relatedIds.Contains([int]$_.ProcessId) })
$processes | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'process-tree.json') -Encoding UTF8
$windows = New-Object System.Collections.Generic.List[object]
$top = [NativeUiDump]::Top()
$index = 0
foreach($h in $top) {
    $pidValue = [uint32]0
    [void][NativeUiDump]::GetWindowThreadProcessId($h,[ref]$pidValue)
    $rootRelated = $relatedIds.Contains([int]$pidValue)
    $children = [NativeUiDump]::Children($h)
    $hasRelatedChild = $false
    foreach($c in $children) {
        $cpid = [uint32]0; [void][NativeUiDump]::GetWindowThreadProcessId($c,[ref]$cpid)
        if($relatedIds.Contains([int]$cpid)) { $hasRelatedChild = $true; break }
    }
    if(-not ($rootRelated -or $hasRelatedChild)) { $index++; continue }
    $members = @($h) + @($children)
    $childOrder = 0
    foreach($w in $members) {
        $wpid = [uint32]0; $threadId = [NativeUiDump]::GetWindowThreadProcessId($w,[ref]$wpid)
        $wi = New-Object NativeUiDump+WINDOWINFO
        $wi.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type][NativeUiDump+WINDOWINFO])
        $ok = [NativeUiDump]::GetWindowInfo($w,[ref]$wi)
        $parent = [NativeUiDump]::GetParent($w)
        $owner = [NativeUiDump]::GetWindow($w,4)
        $dpi = 0; try { $dpi = [NativeUiDump]::GetDpiForWindow($w) } catch {}
        $windows.Add([pscustomobject]@{
            HWND = ('0x{0:X}' -f $w.ToInt64()); PID = $wpid; ThreadID = $threadId
            RootHWND = ('0x{0:X}' -f $h.ToInt64()); ParentHWND = ('0x{0:X}' -f $parent.ToInt64()); OwnerHWND = ('0x{0:X}' -f $owner.ToInt64())
            TopLevelZIndex = $index; DescendantEnumerationOrder = $childOrder
            Class = [NativeUiDump]::Class($w); Title = [NativeUiDump]::Title($w)
            Visible = [NativeUiDump]::IsWindowVisible($w); Enabled = [NativeUiDump]::IsWindowEnabled($w); Minimized = [NativeUiDump]::IsIconic($w)
            X = $(if($ok){$wi.rcWindow.Left}else{0}); Y = $(if($ok){$wi.rcWindow.Top}else{0})
            Width = $(if($ok){$wi.rcWindow.Right-$wi.rcWindow.Left}else{0}); Height = $(if($ok){$wi.rcWindow.Bottom-$wi.rcWindow.Top}else{0})
            ClientWidth = $(if($ok){$wi.rcClient.Right-$wi.rcClient.Left}else{0}); ClientHeight = $(if($ok){$wi.rcClient.Bottom-$wi.rcClient.Top}else{0})
            Style = ('0x{0:X8}' -f $wi.dwStyle); ExStyle = ('0x{0:X8}' -f $wi.dwExStyle); DPI = $dpi
        })
        $childOrder++
    }
    $index++
}
$windows | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'hwnd-tree.json') -Encoding UTF8
$windows | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'hwnd-tree.csv') -NoTypeInformation -Encoding UTF8
$roots = @($windows | Where-Object { $_.HWND -eq $_.RootHWND -and $relatedIds.Contains([int]$_.PID) })
foreach($r in $roots) {
    if($r.Width -le 0 -or $r.Height -le 0 -or $r.Minimized) { continue }
    $filename = 'window-{0}-{1}.png' -f $r.PID,($r.HWND -replace '^0x','')
    $dest = Join-Path $OutputDirectory $filename
    $bmp = $null; $graphics = $null
    try {
        $width = [Math]::Min([int]$r.Width,8192); $height = [Math]::Min([int]$r.Height,8192)
        $bmp = New-Object System.Drawing.Bitmap($width,$height)
        $graphics = [System.Drawing.Graphics]::FromImage($bmp)
        $hdc = $graphics.GetHdc()
        $printed = $false
        try { $printed = [NativeUiDump]::PrintWindow([IntPtr]([Convert]::ToInt64($r.HWND.Substring(2),16)),$hdc,2) }
        finally { $graphics.ReleaseHdc($hdc) }
        if($printed) { $bmp.Save($dest,[System.Drawing.Imaging.ImageFormat]::Png) }
        else {
            $graphics.CopyFromScreen([int]$r.X,[int]$r.Y,0,0,(New-Object System.Drawing.Size($width,$height)))
            $bmp.Save($dest,[System.Drawing.Imaging.ImageFormat]::Png)
        }
    } catch { Write-Warning "Screenshot failed for $($r.HWND): $_" }
    finally { if($graphics){$graphics.Dispose()};if($bmp){$bmp.Dispose()} }
}
$summary = @"
RawrXD live window dump
Created: $(Get-Date -Format o)
Process filter: $ProcessName
Related process count: $($processes.Count)
Window record count: $($windows.Count)
Top-level windows: $($roots.Count)
Note: EnumChildWindows includes descendants, not only direct children. DescendantEnumerationOrder is not a guaranteed sibling z-order.
A child HWND is not a child process. process-tree.json and hwnd-tree.json are independent captures.
PrintWindow may return a blank or stale frame for GPU-rendered surfaces.
"@
Set-Content -LiteralPath (Join-Path $OutputDirectory 'README.txt') -Value $summary -Encoding UTF8
Write-Output "DUMP_DIR=$OutputDirectory"
Write-Output "PROCESSES=$($processes.Count) WINDOWS=$($windows.Count) ROOTS=$($roots.Count)"
