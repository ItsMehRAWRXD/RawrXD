Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ProcessIdProperty,
    (Get-Process -Name "RawrXD-Win32IDE-Native" -ErrorAction SilentlyContinue | Select-Object -First 1).Id
)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if ($null -eq $win) { Write-Output "NO_WINDOW_VIA_UIA"; exit 1 }
Write-Output "WINDOW: $($win.Current.Name)"

# find all TabItem elements
$tabCond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::TabItem
)
$tabs = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tabCond)
Write-Output "TabItem count: $($tabs.Count)"
foreach ($t in $tabs) {
    $name = $t.Current.Name
    $cjk = $name -match '[\u4e00-\u9fff]'
    Write-Output ("  TAB: '{0}'  CJK={1}" -f $name, $cjk)
}

# also dump all Text/Button elements in the bottom region for context
Write-Output "--- All named elements (first 60) ---"
$allCond = [System.Windows.Automation.Condition]::TrueCondition
$all = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $allCond)
$n = 0
foreach ($e in $all) {
    $nm = $e.Current.Name
    if ($nm -and $nm.Length -gt 0) {
        $cjk = $nm -match '[\u4e00-\u9fff]'
        Write-Output ("  {0}: '{1}' CJK={2}" -f $e.Current.ControlType.ProgrammaticName, $nm, $cjk)
        $n++
        if ($n -ge 60) { break }
    }
}