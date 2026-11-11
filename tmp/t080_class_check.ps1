# Check editor control class and try UIA text pattern
Import-Module 'F:\rawrxd\tools\uia\RawrXD.UIA.psm1' -Force

$p = Start-Process -FilePath 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -WorkingDirectory 'F:\rawrxd\build_t080\bin' -PassThru
Write-Host "IDE launched PID: $($p.Id)"
Start-Sleep -Seconds 5

$s = Start-RawrSession -Exe 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -Sha256 'E198F94CF4FFAEC320840C36CE4E4A33A5234E929761A2BA71F7C1C64DD25290' -EvidenceDir 'F:\rawrxd\evidence\T080_CLASS_CHECK'
$root = Get-RawrRoot $s -TimeoutSeconds 30
$mainHwnd = [IntPtr]$root.Current.NativeWindowHandle

# Find editor control
$editorHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1202)
if ($editorHwnd -ne [IntPtr]::Zero) {
    $class = [RawrXD_UiaInput]::Class($editorHwnd)
    Write-Host "Editor HWND: $editorHwnd, Class: $class"
    
    # Try UI Automation TextPattern
    $autoEl = [System.Windows.Automation.AutomationElement]::FromHandle($editorHwnd)
    if ($autoEl) {
        $textPattern = $null
        $found = $autoEl.TryGetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern, [ref]$textPattern)
        if ($found -and $textPattern) {
            $docRange = $textPattern.DocumentRange
            $text = $docRange.GetText(1000)
            Write-Host "TextPattern content: '$text'"
        } else {
            Write-Host "TextPattern not supported"
        }
        
        # Try ValuePattern
        $valPattern = $null
        $found2 = $autoEl.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$valPattern)
        if ($found2 -and $valPattern) {
            Write-Host "ValuePattern value: '$($valPattern.Current.Value)'"
            $valPattern.SetValue("int main() { return x; }")
            Start-Sleep -Seconds 2
            Write-Host "ValuePattern SetValue done"
        } else {
            Write-Host "ValuePattern not supported"
        }
    }
}

# Check panel tabs class
$panelTabsHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1301)
if ($panelTabsHwnd -ne [IntPtr]::Zero) {
    $class = [RawrXD_UiaInput]::Class($panelTabsHwnd)
    Write-Host "Panel tabs HWND: $panelTabsHwnd, Class: $class"
}

# Check Problems list class
$problemsHwnd = [RawrXD_UiaInput]::FindChildById($mainHwnd, 1312)
if ($problemsHwnd -ne [IntPtr]::Zero) {
    $class = [RawrXD_UiaInput]::Class($problemsHwnd)
    Write-Host "Problems list HWND: $problemsHwnd, Class: $class"
}

Write-Host "Class check complete"