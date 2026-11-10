# T080 Click-to-Line Verification - write code directly to editor
Import-Module 'F:\rawrxd\tools\uia\RawrXD.UIA.psm1' -Force

# Launch IDE
$p = Start-Process -FilePath 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -WorkingDirectory 'F:\rawrxd\build_t080\bin' -PassThru
Write-Host "IDE launched PID: $($p.Id)"
Start-Sleep -Seconds 5

# Connect via UIA
$s = Start-RawrSession -Exe 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -Sha256 'E198F94CF4FFAEC320840C36CE4E4A33A5234E929761A2BA71F7C1C64DD25290' -EvidenceDir 'F:\rawrxd\evidence\T080_DIRECT_WRITE_TEST'
$root = Get-RawrRoot $s -TimeoutSeconds 30
$mainHwnd = [IntPtr]$root.Current.NativeWindowHandle
Write-Host "Connected to IDE, main HWND: $mainHwnd"

# Find editor control (ID 1202)
$editorHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1202)
if ($editorHwnd -eq [IntPtr]::Zero) {
    Write-Host "ERROR: Editor control (ID 1202) not found"
    exit 1
}
Write-Host "Found editor control HWND: $editorHwnd"

# Write test code to editor
$testCode = "int main()" + [Environment]::NewLine + "{" + [Environment]::NewLine + "    return undeclared_variable_xyz;" + [Environment]::NewLine + "}" + [Environment]::NewLine
Write-Host "Writing test code to editor..."
Write-Host $testCode

# Use WM_SETTEXT to write to editor
$ptr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($testCode)
try {
    $result = [RawrXD_UiaInput]::SendMessage($editorHwnd, 0x000C, [IntPtr]::Zero, $ptr)  # WM_SETTEXT
    Write-Host "WM_SETTEXT result: $result"
} finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
}
Start-Sleep -Seconds 2

# Verify content was written
$len = [RawrXD_UiaInput]::SendMessage($editorHwnd, 0x000E, [IntPtr]::Zero, [IntPtr]::Zero)  # WM_GETTEXTLENGTH
Write-Host "Editor text length: $len"

# Find Problems panel tab (ID 1301) and select Problems tab (index 2)
$panelTabsHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1301)
if ($panelTabsHwnd -ne [IntPtr]::Zero) {
    Write-Host "Found panel tabs HWND: $panelTabsHwnd"
    $TCM_SETCURSEL = 0x130C
    $prev = [RawrXD_UiaInput]::SendMessage($panelTabsHwnd, $TCM_SETCURSEL, [IntPtr]2, [IntPtr]0)
    Write-Host "Selected Problems tab, result: $prev"
    Start-Sleep -Seconds 2
} else {
    Write-Host "Panel tabs not found"
}

# Find Problems list view (ID 1312)
$problemsListHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1312)
if ($problemsListHwnd -ne [IntPtr]::Zero) {
    Write-Host "Found Problems list HWND: $problemsListHwnd"
} else {
    Write-Host "Problems list not found"
}

# Trigger Build Project (WM_COMMAND 3014)
Write-Host "Triggering Build Project..."
$WM_COMMAND = 0x0111
$result = [RawrXD_UiaInput]::SendMessage($mainHwnd, $WM_COMMAND, [IntPtr]3014, [IntPtr]0)
Write-Host "Build Project result: $result"
Start-Sleep -Seconds 10

# Check Problems list for diagnostics
if ($problemsListHwnd -ne [IntPtr]::Zero) {
    $LVM_GETITEMCOUNT = 0x1000 + 4
    $count = [RawrXD_UiaInput]::SendMessage($problemsListHwnd, $LVM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero)
    Write-Host "Problems rows: $count"
    
    if ($count -gt 0) {
        # Get first row text
        $LVM_GETITEMTEXT = 0x1000 + 115
        $bufSize = 256
        $textBuf = New-Object System.Text.StringBuilder('', $bufSize)
        $lvItemSize = 48
        $lvItem = [byte[]]::new($lvItemSize)
        [System.BitConverter]::GetBytes(([int]1)).CopyTo($lvItem, 4)
        [System.BitConverter]::GetBytes(0).CopyTo($lvItem, 8)
        [System.BitConverter]::GetBytes(0).CopyTo($lvItem, 12)
        $ptr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("")
        [System.BitConverter]::GetBytes($ptr.ToInt64()).CopyTo($lvItem, 16)
        [System.BitConverter]::GetBytes($bufSize).CopyTo($lvItem, 24)
        $lpItem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($lvItemSize)
        [System.Runtime.InteropServices.Marshal]::Copy($lvItem, 0, $lpItem, $lvItemSize)
        try {
            $result = [RawrXD_UiaInput]::SendMessage($problemsListHwnd, $LVM_GETITEMTEXT, [IntPtr]0, $lpItem)
            Write-Host "First row text: '$($textBuf.ToString())'"
        } finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpItem)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
        }
        
        # Get first row rect for clicking
        $LVM_GETITEMRECT = 0x1000 + 42
        $rectSize = 16
        $rectBuf = [byte[]]::new($rectSize)
        $lpRect = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($rectSize)
        [System.Runtime.InteropServices.Marshal]::Copy($rectBuf, 0, $lpRect, $rectSize)
        try {
            $result = [RawrXD_UiaInput]::SendMessage($problemsListHwnd, $LVM_GETITEMRECT, [IntPtr]0, $lpRect)
            $left = [System.BitConverter]::ToInt32($rectBuf, 0)
            $top = [System.BitConverter]::ToInt32($rectBuf, 4)
            $right = [System.BitConverter]::ToInt32($rectBuf, 8)
            $bottom = [System.BitConverter]::ToInt32($rectBuf, 12)
            Write-Host "First row rect: L=$left T=$top R=$right B=$bottom"
            
            # Click on first row
            $clickX = ($left + $right) / 2
            $clickY = ($top + $bottom) / 2
            Write-Host "Clicking at ($clickX, $clickY)"
            [RawrXD_UiaInput]::SetCursorPos($clickX, $clickY)
            Start-Sleep -Milliseconds 100
            [RawrXD_UiaInput]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)
            [RawrXD_UiaInput]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
            Start-Sleep -Seconds 2
            Write-Host "Clicked first Problems row"
        } finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpRect)
        }
        
        # Check editor after click
        $editorLen = [RawrXD_UiaInput]::SendMessage($editorHwnd, 0x000E, [IntPtr]::Zero, [IntPtr]::Zero)
        Write-Host "Editor text length after click: $editorLen"
        
        $EM_GETSEL = 0x00B0
        $selStart = [RawrXD_UiaInput]::SendMessage($editorHwnd, $EM_GETSEL, [IntPtr]::Zero, [IntPtr]::Zero)
        Write-Host "Editor selection start: $selStart"
    }
}

Write-Host "T080 test complete"