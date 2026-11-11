# T080 Debug - SendKeys direct input into focused editor
Import-Module 'F:\rawrxd\tools\uia\RawrXD.UIA.psm1' -Force

$EM_SETSEL = 0x00B1
$EM_REPLACESEL = 0x00C2
$WM_GETTEXTLENGTH = 0x000E

# Launch IDE
$p = Start-Process -FilePath 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -WorkingDirectory 'F:\rawrxd\build_t080\bin' -PassThru
Write-Host "IDE launched PID: $($p.Id)"
Start-Sleep -Seconds 5

# Connect via UIA
$s = Start-RawrSession -Exe 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -Sha256 'E198F94CF4FFAEC320840C36CE4E4A33A5234E929761A2BA71F7C1C64DD25290' -EvidenceDir 'F:\rawrxd\evidence\T080_DEBUG_SENDKEYS'
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

# Send text via SendKeys
Add-Type -AssemblyName System.Windows.Forms
$testText = "int main() { return x; }"
Write-Host "Sending text via SendKeys: $testText"
[System.Windows.Forms.SendKeys]::SendWait($testText)
Start-Sleep -Seconds 2

# Check if text was entered
$len = [RawrXD_UiaInput]::SendMessage($editorHwnd, $WM_GETTEXTLENGTH, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host "Editor text length after SendKeys: $len"

# Try sending Ctrl+A then typing
[System.Windows.Forms.SendKeys]::SendWait("^a")
Start-Sleep -Milliseconds 500
[System.Windows.Forms.SendKeys]::SendWait("int main() { return undeclared_variable_xyz; }")
Start-Sleep -Seconds 2
$len2 = [RawrXD_UiaInput]::SendMessage($editorHwnd, $WM_GETTEXTLENGTH, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host "Editor text length after Ctrl+A + type: $len2"

Write-Host "SendKeys test complete"