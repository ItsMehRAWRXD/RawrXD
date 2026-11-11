# T080 Debug - Editor text injection with thread attachment
Import-Module 'F:\rawrxd\tools\uia\RawrXD.UIA.psm1' -Force

$EM_SETSEL = 0x00B1
$EM_REPLACESEL = 0x00C2
$WM_GETTEXTLENGTH = 0x000E
$WM_SETTEXT = 0x000C

# Launch IDE
$p = Start-Process -FilePath 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -WorkingDirectory 'F:\rawrxd\build_t080\bin' -PassThru
Write-Host "IDE launched PID: $($p.Id)"
Start-Sleep -Seconds 5

# Connect via UIA
$s = Start-RawrSession -Exe 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -Sha256 'E198F94CF4FFAEC320840C36CE4E4A33A5234E929761A2BA71F7C1C64DD25290' -EvidenceDir 'F:\rawrxd\evidence\T080_DEBUG_THREAD_ATTACH'
$root = Get-RawrRoot $s -TimeoutSeconds 30
$mainHwnd = [IntPtr]$root.Current.NativeWindowHandle
Write-Host "Main HWND: $mainHwnd"

# Get IDE process thread ID
$proc = Get-Process -Id $s.Pid -ErrorAction Stop
$proc.Refresh()
$ideThreadId = [System.Diagnostics.Process]::GetCurrentProcess().Id  # our thread
# Get the IDE's main thread ID
$ideThreads = $proc.Threads
Write-Host "IDE threads: $($ideThreads.Count)"
foreach ($t in $ideThreads) {
    Write-Host "  Thread ID: $($t.Id), State: $($t.ThreadState)"
}
$mainThreadId = $ideThreads[0].Id

# Get our current thread ID
$ourThreadId = [System.Diagnostics.Process]::GetCurrentProcess().Id
# Actually we need our thread ID, not process. Let's use GetCurrentThreadId via P/Invoke
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class ThreadHelper {
    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentThreadId();
}
"@
$ourThreadId = [ThreadHelper]::GetCurrentThreadId()
Write-Host "Our thread ID: $ourThreadId, IDE main thread ID: $mainThreadId"

# Attach thread input
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
    [DllImport("user32.dll")]
    public static extern IntPtr GetFocus();
}
"@

$result = [Win32]::AttachThreadInput($ourThreadId, $mainThreadId, $true)
Write-Host "AttachThreadInput result: $result"

# Find editor control (ID 1202)
$editorHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1202)
if ($editorHwnd -eq [IntPtr]::Zero) {
    Write-Host "ERROR: Editor control (ID 1202) not found"
    exit 1
}
Write-Host "Editor HWND: $editorHwnd"

# Focus the editor
$focusResult = [RawrXD_UiaInput]::Focus($mainHwnd, $editorHwnd)
Write-Host "Focus result (void - no return)"

# Check what has focus
$focusedHwnd = [Win32]::GetFocus()
Write-Host "Focused HWND after Focus(): $focusedHwnd"

# Try EM_SETSEL then EM_REPLACESEL with thread attached
$result1 = [RawrXD_UiaInput]::SendMessage($editorHwnd, $EM_SETSEL, [IntPtr]0, [IntPtr](-1))
Write-Host "EM_SETSEL(0, -1) result: $result1"
Start-Sleep -Milliseconds 100

$testText = "int main() { return x; }"
$ptr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($testText)
try {
    $result2 = [RawrXD_UiaInput]::SendMessage($editorHwnd, $EM_REPLACESEL, [IntPtr]1, $ptr)
    Write-Host "EM_REPLACESEL(TRUE, '$testText') result: $result2"
} finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
}
Start-Sleep -Seconds 2

$len = [RawrXD_UiaInput]::SendMessage($editorHwnd, $WM_GETTEXTLENGTH, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host "Editor text length after EM_REPLACESEL: $len"

# Try WM_SETTEXT directly
$testText2 = "WM_SETTEXT direct test"
$ptr2 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($testText2)
try {
    $result3 = [RawrXD_UiaInput]::SendMessage($editorHwnd, $WM_SETTEXT, [IntPtr]::Zero, $ptr2)
    Write-Host "WM_SETTEXT result: $result3"
} finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr2)
}
Start-Sleep -Seconds 2

$len2 = [RawrXD_UiaInput]::SendMessage($editorHwnd, $WM_GETTEXTLENGTH, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host "Editor text length after WM_SETTEXT: $len2"

# Detach thread input
[Win32]::AttachThreadInput($ourThreadId, $mainThreadId, $false)

Write-Host "Debug complete"