# Test EM_REPLACESEL on editor control
Import-Module 'F:\rawrxd\tools\uia\RawrXD.UIA.psm1' -Force

$EM_SETSEL = 0x00B1
$EM_REPLACESEL = 0x00C2
$WM_GETTEXTLENGTH = 0x000E

$p = Start-Process -FilePath 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -WorkingDirectory 'F:\rawrxd\build_t080\bin' -PassThru
Write-Host "IDE launched PID: $($p.Id)"
Start-Sleep -Seconds 5

$s = Start-RawrSession -Exe 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -Sha256 'E198F94CF4FFAEC320840C36CE4E4A33A5234E929761A2BA71F7C1C64DD25290' -EvidenceDir 'F:\rawrxd\evidence\T080_EM_REPLACESEL_TEST'
$root = Get-RawrRoot $s -TimeoutSeconds 30
$mainHwnd = [IntPtr]$root.Current.NativeWindowHandle

$editorHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1202)
Write-Host "Editor HWND: $editorHwnd"

# Get initial text length
$len0 = [RawrXD_UiaInput]::SendMessage($editorHwnd, $WM_GETTEXTLENGTH, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host "Initial text length: $len0"

# Select all
$result1 = [RawrXD_UiaInput]::SendMessage($editorHwnd, $EM_SETSEL, [IntPtr]0, [IntPtr](-1))
Write-Host "EM_SETSEL(0, -1) result: $result1"
Start-Sleep -Milliseconds 100

# Replace selection
$testText = "hello world"
$ptr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($testText)
try {
    $result2 = [RawrXD_UiaInput]::SendMessage($editorHwnd, $EM_REPLACESEL, [IntPtr]1, $ptr)
    Write-Host "EM_REPLACESEL(TRUE, 'hello world') result: $result2"
} finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
}
Start-Sleep -Seconds 2

# Check length after
$len1 = [RawrXD_UiaInput]::SendMessage($editorHwnd, $WM_GETTEXTLENGTH, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host "Text length after REPLACESEL: $len1"

# Try WM_SETTEXT directly
$testText2 = "WM_SETTEXT test"
$ptr2 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($testText2)
try {
    $result3 = [RawrXD_UiaInput]::SendMessage($editorHwnd, 0x000C, [IntPtr]::Zero, $ptr2)  # WM_SETTEXT
    Write-Host "WM_SETTEXT result: $result3"
} finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr2)
}
Start-Sleep -Seconds 2

$len2 = [RawrXD_UiaInput]::SendMessage($editorHwnd, $WM_GETTEXTLENGTH, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host "Text length after WM_SETTEXT: $len2"

Write-Host "EM_REPLACESEL test complete"