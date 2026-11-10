# T080 Click-to-Line Verification - using SendKeys for file dialog
Import-Module 'F:\rawrxd\tools\uia\RawrXD.UIA.psm1' -Force

# Launch IDE with test file as argument
$p = Start-Process -FilePath 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -ArgumentList 'F:\rawrxd\T080_test_bad.cpp' -WorkingDirectory 'F:\rawrxd\build_t080\bin' -PassThru
Write-Host "IDE launched PID: $($p.Id)"
Start-Sleep -Seconds 5

# Connect via UIA
$s = Start-RawrSession -Exe 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -Sha256 'E198F94CF4FFAEC320840C36CE4E4A33A5234E929761A2BA71F7C1C64DD25290' -EvidenceDir 'F:\rawrxd\evidence\T080_SENDKEYS_TEST'
$root = Get-RawrRoot $s -TimeoutSeconds 30
Write-Host "Connected to IDE"

# Send Ctrl+O to open file dialog
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.SendKeys]::SendWait("^o")
Write-Host "Sent Ctrl+O"
Start-Sleep -Seconds 3

# Find file dialog controls
$editHwnd = [RawrXD_UiaInput]::FindChildById([IntPtr]::Zero, 1001)
if ($editHwnd -ne [IntPtr]::Zero) {
    Write-Host "Found file dialog edit control (ID 1001)"
    [RawrXD_UiaInput]::SendMessageText($editHwnd, 0x000C, [IntPtr]('F:\rawrxd\T080_test_bad.cpp'.Length * 2 + 2), 'F:\rawrxd\T080_test_bad.cpp')
    Start-Sleep -Seconds 1
    
    $openBtnHwnd = [RawrXD_UiaInput]::FindChildById([IntPtr]::Zero, 1)
    if ($openBtnHwnd -ne [IntPtr]::Zero) {
        Write-Host "Found Open button (ID 1)"
        [RawrXD_UiaInput]::SendMessage($openBtnHwnd, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)
        Start-Sleep -Seconds 3
        Write-Host "Clicked Open button"
    } else {
        Write-Host "Open button not found"
    }
} else {
    Write-Host "File dialog edit control not found - listing top-level windows"
    # Try to find dialog windows
    $allWindows = New-Object System.Collections.ArrayList
    $callback = [System.Management.Automation.PSObject]::new()
    
    # Use EnumWindows via P/Invoke
    $enumProc = [RawrXD_UiaInput]::FindChildById
    Write-Host "Trying direct dialog search..."
    
    # Check if dialog is a child of main window
    $mainHwnd = [IntPtr]$root.Current.NativeWindowHandle
    $childEdit = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1001)
    if ($childEdit -ne [IntPtr]::Zero) {
        Write-Host "Found edit control as child of main window"
    } else {
        Write-Host "Not found as child of main window either"
    }
}

Write-Host "Done"