# T080 - Save As then Build
Import-Module 'F:\rawrxd\tools\uia\RawrXD.UIA.psm1' -Force

$EM_SETSEL = 0x00B1
$WM_GETTEXTLENGTH = 0x000E
$WM_COMMAND = 0x0111
$TCM_SETCURSEL = 0x130C
$LVM_FIRST = 0x1000
$LVM_GETITEMCOUNT = $LVM_FIRST + 4
$LVM_GETITEMRECT = $LVM_FIRST + 42

# Launch IDE
$p = Start-Process -FilePath 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -WorkingDirectory 'F:\rawrxd\build_t080\bin' -PassThru
Write-Host "IDE launched PID: $($p.Id)"
Start-Sleep -Seconds 5

$s = Start-RawrSession -Exe 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -Sha256 'E198F94CF4FFAEC320840C36CE4E4A33A5234E929761A2BA71F7C1C64DD25290' -EvidenceDir 'F:\rawrxd\evidence\T080_SAVE_AS_BUILD'
$root = Get-RawrRoot $s -TimeoutSeconds 30
$mainHwnd = [IntPtr]$root.Current.NativeWindowHandle

# Find editor control
$editorHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1202)
if ($editorHwnd -eq [IntPtr]::Zero) { Write-Host "ERROR: Editor not found"; exit 1 }
Write-Host "Editor HWND: $editorHwnd"

# Focus editor and select all
[RawrXD_UiaInput]::Focus($mainHwnd, $editorHwnd)
Start-Sleep -Seconds 1
[RawrXD_UiaInput]::SendMessage($editorHwnd, $EM_SETSEL, [IntPtr]0, [IntPtr](-1))
Start-Sleep -Milliseconds 100

# Paste test code
$testCode = "int main()" + [Environment]::NewLine + "{" + [Environment]::NewLine + "    return undeclared_variable_xyz;" + [Environment]::NewLine + "}" + [Environment]::NewLine
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Clipboard]::SetText($testCode)
[System.Windows.Forms.SendKeys]::SendWait("^v")
Start-Sleep -Seconds 2
$len = [RawrXD_UiaInput]::SendMessage($editorHwnd, $WM_GETTEXTLENGTH, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host "Editor text length: $len"

# Save As via Ctrl+Shift+S
Write-Host "Sending Ctrl+Shift+S for Save As..."
[System.Windows.Forms.SendKeys]::SendWait("^+s")
Start-Sleep -Seconds 3

# Check for save dialog
$saveEditHwnd = [RawrXD_UiaInput]::FindChildById([IntPtr]::Zero, 1001)
if ($saveEditHwnd -ne [IntPtr]::Zero) {
    Write-Host "Found save dialog edit (ID 1001)"
    $fileName = "F:\rawrxd\T080_test_bad.cpp"
    [RawrXD_UiaInput]::SendMessageText($saveEditHwnd, 0x000C, [IntPtr]($fileName.Length * 2 + 2), $fileName)
    Start-Sleep -Seconds 1
    $saveBtnHwnd = [RawrXD_UiaInput]::FindChildById([IntPtr]::Zero, 1)
    if ($saveBtnHwnd -ne [IntPtr]::Zero) {
        [RawrXD_UiaInput]::SendMessage($saveBtnHwnd, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)
        Start-Sleep -Seconds 3
        Write-Host "Save button clicked"
    }
} else {
    Write-Host "No save dialog found - trying WM_COMMAND for Save As"
    # Try various Save As command IDs
    foreach ($id in @(104, 105, 106, 107, 108, 109, 110)) {
        $result = [RawrXD_UiaInput]::SendMessage($mainHwnd, $WM_COMMAND, [IntPtr]$id, [IntPtr]0)
        Start-Sleep -Seconds 2
        $checkEdit = [RawrXD_UiaInput]::FindChildById([IntPtr]::Zero, 1001)
        if ($checkEdit -ne [IntPtr]::Zero) {
            Write-Host "Save As dialog found with command ID $id"
            $fileName = "F:\rawrxd\T080_test_bad.cpp"
            [RawrXD_UiaInput]::SendMessageText($checkEdit, 0x000C, [IntPtr]($fileName.Length * 2 + 2), $fileName)
            Start-Sleep -Seconds 1
            $saveBtn = [RawrXD_UiaInput]::FindChildById([IntPtr]::Zero, 1)
            if ($saveBtn -ne [IntPtr]::Zero) {
                [RawrXD_UiaInput]::SendMessage($saveBtn, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)
                Start-Sleep -Seconds 3
                Write-Host "Saved file via command ID $id"
            }
            break
        }
    }
}

# Select Problems panel
$panelTabsHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1301)
if ($panelTabsHwnd -ne [IntPtr]::Zero) {
    [RawrXD_UiaInput]::SendMessage($panelTabsHwnd, $TCM_SETCURSEL, [IntPtr]2, [IntPtr]0)
    Start-Sleep -Seconds 2
    Write-Host "Selected Problems tab"
}

# Find Problems list
$problemsListHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1312)
if ($problemsListHwnd -ne [IntPtr]::Zero) {
    Write-Host "Found Problems list HWND: $problemsListHwnd"
    
    # Trigger Build Project
    $result = [RawrXD_UiaInput]::SendMessage($mainHwnd, $WM_COMMAND, [IntPtr]3014, [IntPtr]0)
    Write-Host "Build Project result: $result"
    Start-Sleep -Seconds 10
    
    $count = [RawrXD_UiaInput]::SendMessage($problemsListHwnd, $LVM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero)
    Write-Host "Problems rows: $count"
    
    if ($count -gt 0) {
        Write-Host "SUCCESS: Compiler diagnostics found!"
        
        # Click first row
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
            $clickX = ($left + $right) / 2
            $clickY = ($top + $bottom) / 2
            Write-Host "Clicking first row at ($clickX, $clickY)"
            [RawrXD_UiaInput]::SetCursorPos($clickX, $clickY)
            Start-Sleep -Milliseconds 100
            [RawrXD_UiaInput]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)
            [RawrXD_UiaInput]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
            Start-Sleep -Seconds 2
            Write-Host "Clicked Problems row"
            
            $EM_GETSEL = 0x00B0
            $selStart = [RawrXD_UiaInput]::SendMessage($editorHwnd, $EM_GETSEL, [IntPtr]::Zero, [IntPtr]::Zero)
            Write-Host "Editor selection start: $selStart"
        } finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpRect)
        }
    }
}

Write-Host "T080 Save As + Build test complete"