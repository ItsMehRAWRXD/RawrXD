# T080 Debug - Clipboard paste into editor
Import-Module 'F:\rawrxd\tools\uia\RawrXD.UIA.psm1' -Force

$EM_SETSEL = 0x00B1
$WM_GETTEXTLENGTH = 0x000E

# Launch IDE
$p = Start-Process -FilePath 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -WorkingDirectory 'F:\rawrxd\build_t080\bin' -PassThru
Write-Host "IDE launched PID: $($p.Id)"
Start-Sleep -Seconds 5

# Connect via UIA
$s = Start-RawrSession -Exe 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -Sha256 'E198F94CF4FFAEC320840C36CE4E4A33A5234E929761A2BA71F7C1C64DD25290' -EvidenceDir 'F:\rawrxd\evidence\T080_DEBUG_CLIPBOARD'
$root = Get-RawrRoot $s -TimeoutSeconds 30
$mainHwnd = [IntPtr]$root.Current.NativeWindowHandle

# Find editor control (ID 1202)
$editorHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1202)
if ($editorHwnd -eq [IntPtr]::Zero) {
    Write-Host "ERROR: Editor control (ID 1202) not found"
    exit 1
}
Write-Host "Editor HWND: $editorHwnd"

# Focus the editor
[RawrXD_UiaInput]::Focus($mainHwnd, $editorHwnd)
Start-Sleep -Seconds 1

# Select all existing text
[RawrXD_UiaInput]::SendMessage($editorHwnd, $EM_SETSEL, [IntPtr]0, [IntPtr](-1))
Start-Sleep -Milliseconds 100

# Put test code on clipboard
Add-Type -AssemblyName System.Windows.Forms
$testCode = "int main()" + [Environment]::NewLine + "{" + [Environment]::NewLine + "    return undeclared_variable_xyz;" + [Environment]::NewLine + "}" + [Environment]::NewLine
[System.Windows.Forms.Clipboard]::SetText($testCode)
Write-Host "Test code copied to clipboard"

# Paste via Ctrl+V
[System.Windows.Forms.SendKeys]::SendWait("^v")
Start-Sleep -Seconds 2

# Check result
$len = [RawrXD_UiaInput]::SendMessage($editorHwnd, $WM_GETTEXTLENGTH, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host "Editor text length after clipboard paste: $len"

if ($len -gt 10) {
    Write-Host "SUCCESS: Text was pasted into editor!"
    
    # Now save the file
    [System.Windows.Forms.SendKeys]::SendWait("^s")
    Write-Host "Sent Ctrl+S to save"
    Start-Sleep -Seconds 3
    
    # Check if save dialog appeared
    $saveEditHwnd = [RawrXD_UiaInput]::FindChildById([IntPtr]::Zero, 1001)
    if ($saveEditHwnd -ne [IntPtr]::Zero) {
        Write-Host "Found save dialog edit control (ID 1001)"
        $fileName = "F:\rawrxd\T080_test_bad.cpp"
        [RawrXD_UiaInput]::SendMessageText($saveEditHwnd, 0x000C, [IntPtr]($fileName.Length * 2 + 2), $fileName)
        Start-Sleep -Seconds 1
        $saveBtnHwnd = [RawrXD_UiaInput]::FindChildById([IntPtr]::Zero, 1)
        if ($saveBtnHwnd -ne [IntPtr]::Zero) {
            [RawrXD_UiaInput]::SendMessage($saveBtnHwnd, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)
            Start-Sleep -Seconds 3
            Write-Host "Clicked Save button"
        }
    } else {
        Write-Host "No save dialog appeared"
    }
    
    # Select Problems panel tab
    $panelTabsHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1301)
    if ($panelTabsHwnd -ne [IntPtr]::Zero) {
        $TCM_SETCURSEL = 0x130C
        [RawrXD_UiaInput]::SendMessage($panelTabsHwnd, $TCM_SETCURSEL, [IntPtr]2, [IntPtr]0)
        Write-Host "Selected Problems tab"
        Start-Sleep -Seconds 2
    }
    
    # Find Problems list view
    $problemsListHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1312)
    if ($problemsListHwnd -ne [IntPtr]::Zero) {
        Write-Host "Found Problems list HWND: $problemsListHwnd"
        
        # Trigger Build Project
        $WM_COMMAND = 0x0111
        $result = [RawrXD_UiaInput]::SendMessage($mainHwnd, $WM_COMMAND, [IntPtr]3014, [IntPtr]0)
        Write-Host "Build Project result: $result"
        Start-Sleep -Seconds 10
        
        # Check Problems list
        $LVM_GETITEMCOUNT = 0x1000 + 4
        $count = [RawrXD_UiaInput]::SendMessage($problemsListHwnd, $LVM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero)
        Write-Host "Problems rows: $count"
        
        if ($count -gt 0) {
            Write-Host "SUCCESS: Compiler diagnostics found!"
            
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
                
                # Click first row
                $clickX = ($left + $right) / 2
                $clickY = ($top + $bottom) / 2
                Write-Host "Clicking at ($clickX, $clickY)"
                [RawrXD_UiaInput]::SetCursorPos($clickX, $clickY)
                Start-Sleep -Milliseconds 100
                [RawrXD_UiaInput]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)
                [RawrXD_UiaInput]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
                Start-Sleep -Seconds 2
                Write-Host "Clicked first Problems row"
                
                # Check editor position
                $EM_GETSEL = 0x00B0
                $selStart = [RawrXD_UiaInput]::SendMessage($editorHwnd, $EM_GETSEL, [IntPtr]::Zero, [IntPtr]::Zero)
                Write-Host "Editor selection start: $selStart"
            } finally {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpRect)
            }
        } else {
            Write-Host "No Problems rows found"
        }
    }
} else {
    Write-Host "FAILED: Text was not pasted into editor (length: $len)"
}

Write-Host "T080 clipboard test complete"