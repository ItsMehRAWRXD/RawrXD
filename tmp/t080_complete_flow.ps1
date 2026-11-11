# T080 Click-to-Line Verification - complete flow with EM_REPLACESEL and Save
Import-Module 'F:\rawrxd\tools\uia\RawrXD.UIA.psm1' -Force

# RichEdit messages
$EM_SETSEL = 0x00B1
$EM_REPLACESEL = 0x00C2
$WM_GETTEXTLENGTH = 0x000E
$WM_COMMAND = 0x0111
$TCM_SETCURSEL = 0x130C
$LVM_FIRST = 0x1000
$LVM_GETITEMCOUNT = $LVM_FIRST + 4
$LVM_GETITEMTEXT = $LVM_FIRST + 115
$LVM_GETITEMRECT = $LVM_FIRST + 42

# Menu command IDs
$kFileOpenId = 102
$kFileSaveId = 103  # guess - need to verify
$kBuildProjectId = 3014

# Launch IDE
$p = Start-Process -FilePath 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -WorkingDirectory 'F:\rawrxd\build_t080\bin' -PassThru
Write-Host "IDE launched PID: $($p.Id)"
Start-Sleep -Seconds 5

# Connect via UIA
$s = Start-RawrSession -Exe 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -Sha256 'E198F94CF4FFAEC320840C36CE4E4A33A5234E929761A2BA71F7C1C64DD25290' -EvidenceDir 'F:\rawrxd\evidence\T080_COMPLETE_FLOW'
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

# Select all text in editor
[RawrXD_UiaInput]::SendMessage($editorHwnd, $EM_SETSEL, [IntPtr]0, [IntPtr](-1))
Start-Sleep -Milliseconds 100

# Replace selection with test code using EM_REPLACESEL
$testCode = "int main()" + [Environment]::NewLine + "{" + [Environment]::NewLine + "    return undeclared_variable_xyz;" + [Environment]::NewLine + "}" + [Environment]::NewLine
Write-Host "Writing test code to editor via EM_REPLACESEL..."
$ptr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($testCode)
try {
    $result = [RawrXD_UiaInput]::SendMessage($editorHwnd, $EM_REPLACESEL, [IntPtr]1, $ptr)  # TRUE = can undo
    Write-Host "EM_REPLACESEL result: $result"
} finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
}
Start-Sleep -Seconds 2

# Verify content
$len = [RawrXD_UiaInput]::SendMessage($editorHwnd, $WM_GETTEXTLENGTH, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host "Editor text length: $len"

# Save the file using Ctrl+S via SendKeys
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.SendKeys]::SendWait("^s")
Write-Host "Sent Ctrl+S to save file"
Start-Sleep -Seconds 3

# Check if save dialog appeared
$saveEditHwnd = [RawrXD_UiaInput]::FindChildById([IntPtr]::Zero, 1001)
if ($saveEditHwnd -ne [IntPtr]::Zero) {
    Write-Host "Found save dialog edit control (ID 1001)"
    # Set file name
    $fileName = "F:\rawrxd\T080_test_bad.cpp"
    [RawrXD_UiaInput]::SendMessageText($saveEditHwnd, 0x000C, [IntPtr]($fileName.Length * 2 + 2), $fileName)
    Start-Sleep -Seconds 1
    
    # Click Save button (ID 1 = IDOK)
    $saveBtnHwnd = [RawrXD_UiaInput]::FindChildById([IntPtr]::Zero, 1)
    if ($saveBtnHwnd -ne [IntPtr]::Zero) {
        Write-Host "Found Save button (ID 1)"
        [RawrXD_UiaInput]::SendMessage($saveBtnHwnd, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)
        Start-Sleep -Seconds 3
        Write-Host "Clicked Save button"
    }
} else {
    Write-Host "No save dialog appeared - file may already be named or save failed"
}

# Select Problems panel tab (ID 1301, index 2)
$panelTabsHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1301)
if ($panelTabsHwnd -ne [IntPtr]::Zero) {
    $TCM_SETCURSEL = 0x130C
    $prev = [RawrXD_UiaInput]::SendMessage($panelTabsHwnd, $TCM_SETCURSEL, [IntPtr]2, [IntPtr]0)
    Write-Host "Selected Problems tab, result: $prev"
    Start-Sleep -Seconds 2
}

# Find Problems list view (ID 1312)
$problemsListHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1312)
if ($problemsListHwnd -ne [IntPtr]::Zero) {
    Write-Host "Found Problems list HWND: $problemsListHwnd"
} else {
    Write-Host "Problems list not found"
}

# Trigger Build Project
Write-Host "Triggering Build Project..."
$WM_COMMAND = 0x0111
$result = [RawrXD_UiaInput]::SendMessage($mainHwnd, $WM_COMMAND, [IntPtr]3014, [IntPtr]0)
Write-Host "Build Project result: $result"
Start-Sleep -Seconds 10

# Check Problems list for diagnostics
if ($problemsListHwnd -ne [IntPtr]::Zero) {
    $count = [RawrXD_UiaInput]::SendMessage($problemsListHwnd, $LVM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero)
    Write-Host "Problems rows: $count"
    
    if ($count -gt 0) {
        Write-Host "SUCCESS: Compiler diagnostics found in Problems panel!"
        
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
            [RawrXD_UiaInput]::SendMessage($problemsListHwnd, $LVM_GETITEMTEXT, [IntPtr]0, $lpItem)
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
            [RawrXD_UiaInput]::SendMessage($problemsListHwnd, $LVM_GETITEMRECT, [IntPtr]0, $lpRect)
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
    } else {
        Write-Host "No Problems rows found - compiler may not have produced diagnostics"
    }
}

Write-Host "T080 test complete"