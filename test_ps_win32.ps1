Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes -ErrorAction SilentlyContinue

$signature = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Win32 {
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool SetFocus(IntPtr hWnd);

    public const uint WM_SETTEXT = 0x000C;
    public const uint WM_GETTEXT = 0x000D;
    public const uint WM_GETTEXTLENGTH = 0x000E;
    public const uint BM_CLICK = 0x00F5;
}
"@

Add-Type -TypeDefinition $signature -ReferencedAssemblies System.Windows.Forms

# Find IDE window
$titleCondition = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::NameProperty, "RawrXD IDE  -  Untitled  -  Workspace")
$root = [System.Windows.Automation.AutomationElement]::RootElement
$ide = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $titleCondition)

if (-not $ide) {
    Write-Host "IDE window not found"
    exit 1
}

$hwnd = [System.IntPtr]$ide.Current.NativeWindowHandle
Write-Host "IDE window handle: $hwnd"

# Find PowerShell input (Edit with empty text, look for the one that's the input field)
# and Execute button by enumerating children
$psInputHwnd = [System.IntPtr]::Zero
$executeBtnHwnd = [System.IntPtr]::Zero
$psOutputHwnd = [System.IntPtr]::Zero

$callback = [Win32+EnumWindowsProc]{
    param($hwndChild, $lParam)
    $class = New-Object System.Text.StringBuilder 256
    [void][Win32]::GetClassName($hwndChild, $class, 256)
    $className = $class.ToString()
    
    $textLen = [Win32]::GetWindowTextLength($hwndChild)
    $text = New-Object System.Text.StringBuilder ($textLen + 1)
    [void][Win32]::GetWindowText($hwndChild, $text, $text.Capacity)
    $textStr = $text.ToString()
    
    if ($className -eq "Edit" -and $textStr.Length -eq 0) {
        # This could be PowerShell input - check if it's in the PowerShell section
        # The input is typically near the Execute button
        Write-Host "  Empty Edit found: $hwndChild"
        if ($psInputHwnd -eq [System.IntPtr]::Zero) {
            $psInputHwnd = $hwndChild
            Write-Host "    >>> Setting as PowerShell input candidate 1"
        } elseif ($psInputHwnd -ne $hwndChild -and $psOutputHwnd -eq [System.IntPtr]::Zero) {
            # Second empty Edit could be another input
        }
    }
    
    if ($className -eq "Button" -and $textStr -eq "Execute") {
        $executeBtnHwnd = $hwndChild
        Write-Host "  Execute button: $hwndChild"
    }
    
    if ($className -eq "RichEdit20A") {
        $psOutputHwnd = $hwndChild
        Write-Host "  RichEdit (output): $hwndChild"
    }
    
    return $true
}

[void][Win32]::EnumChildWindows($hwnd, $callback, [System.IntPtr]::Zero)

Write-Host "`nPowerShell input: $psInputHwnd"
Write-Host "Execute button: $executeBtnHwnd"
Write-Host "PowerShell output: $psOutputHwnd"

if ($psInputHwnd -ne [System.IntPtr]::Zero -and $executeBtnHwnd -ne [System.IntPtr]::Zero) {
    Write-Host "`n=== Testing PowerShell Execute ==="
    
    # Send text to PowerShell input
    $result = [Win32]::SendMessage($psInputHwnd, [Win32]::WM_SETTEXT, [System.IntPtr]::Zero, "Get-Date")
    Write-Host "WM_SETTEXT result: $result"
    
    # Set focus to input
    [Win32]::SetFocus($psInputHwnd) | Out-Null
    
    # Click Execute
    $clickResult = [Win32]::PostMessage($executeBtnHwnd, [Win32]::BM_CLICK, [System.IntPtr]::Zero, [System.IntPtr]::Zero)
    Write-Host "BM_CLICK result: $clickResult"
    
    Start-Sleep -Seconds 3
    
    # Read output
    if ($psOutputHwnd -ne [System.IntPtr]::Zero) {
        $textLen = [Win32]::GetWindowTextLength($psOutputHwnd)
        if ($textLen -gt 0) {
            $text = New-Object System.Text.StringBuilder ($textLen + 1)
            [void][Win32]::GetWindowText($psOutputHwnd, $text, $text.Capacity)
            Write-Host "`n=== PowerShell Output ==="
            Write-Host $text.ToString()
            Write-Host "=== End ==="
        } else {
            Write-Host "`nPowerShell output is empty (text length = 0)"
        }
    }
} else {
    Write-Host "Could not find required controls"
}

# Kill IDE
$proc = Get-Process -Id $ide.Current.ProcessId -ErrorAction SilentlyContinue
if ($proc) { $proc.Kill() }
