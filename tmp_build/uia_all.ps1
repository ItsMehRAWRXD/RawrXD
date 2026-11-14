Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$proc = Get-Process -Name "RawrXD-Win32IDE-Native" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $proc) { Write-Output "GUI_NOT_RUNNING"; exit 1 }
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ProcessIdProperty, $proc.Id)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if ($null -eq $win) { Write-Output "NO_WINDOW"; exit 1 }

$allCond = [System.Windows.Automation.Condition]::TrueCondition
$all = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $allCond)
Write-Output "TOTAL_ELEMENTS=$($all.Count)"

$names = New-Object System.Collections.Generic.List[string]
foreach ($e in $all) {
    $nm = $e.Current.Name
    if ($nm -and $nm.Length -gt 0) { $names.Add($nm) }
}

Write-Output "=== Elements matching expected tab labels ==="
$expected = @('Output','Errors','Debug','Find Results','Build','Tasks','Terminal','ExtensionHost','Ollama','Deep2','IDE','Debugger','PowerShell','TERMINAL','OUTPUT','PROBLEMS','DEBUG CONSOLE','Breakpoints','Watch','Variables','Stack Trace','Memory','Chat')
foreach ($exp in $expected) {
    $hits = $names | Where-Object { $_ -like "*$exp*" }
    if ($hits) { foreach ($h in $hits) { Write-Output ("  FOUND '{0}'" -f $h) } }
    else { Write-Output ("  MISSING '{0}'" -f $exp) }
}

Write-Output "=== Any CJK anywhere? ==="
$cjkFound = $false
foreach ($n in $names) { if ($n -match '[\u4e00-\u9fff]') { Write-Output "  CJK: $n"; $cjkFound = $true } }
if (-not $cjkFound) { Write-Output "  NONE" }

Write-Output "=== All unique names (sorted) ==="
$names | Sort-Object -Unique | ForEach-Object { Write-Output "  | $_" }