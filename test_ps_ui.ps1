Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes -ErrorAction SilentlyContinue

$titleCondition = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::NameProperty, "RawrXD IDE  -  Untitled  -  Workspace")
$root = [System.Windows.Automation.AutomationElement]::RootElement
$ide = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $titleCondition)

if (-not $ide) {
    Write-Host "IDE window not found"
    exit 1
}

# Find PowerShell input by AutomationId 5002
$inputCond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::AutomationIdProperty, "5002")
$psInput = $ide.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $inputCond)

# Find Execute button by AutomationId 5010
$btnCond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::AutomationIdProperty, "5010")
$psExecute = $ide.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $btnCond)

if (-not $psExecute) {
    # Try finding by class Button
    $classCond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ClassNameProperty, "Button")
    $allBtns = $ide.FindAll([System.Windows.Automation.TreeScope]::Descendants, $classCond)
    Write-Host "Found $($allBtns.Count) Button-class controls:"
    foreach ($b in $allBtns) {
        Write-Host "  Name='$($b.Current.Name)' AutoId='$($b.Current.AutomationId)' Class='$($b.Current.ClassName)'"
        if ($b.Current.AutomationId -eq "5010") { $psExecute = $b }
    }
}

if ($psInput -and $psExecute) {
    Write-Host "`nFound PowerShell input and Execute button - testing..."
    
    # Type a command
    $valPattern = $psInput.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $valPattern.SetValue("Get-Date")
    Write-Host "Typed 'Get-Date' into PowerShell input"
    
    # Execute
    $invPattern = $psExecute.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
    $invPattern.Invoke()
    Write-Host "Clicked Execute"
    
    Start-Sleep -Seconds 3
    
    # Read output from RichEdit 5001
    $outCond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty, "5001")
    $psOutput = $ide.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $outCond)
    if ($psOutput) {
        $outPattern = $psOutput.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
        $text = $outPattern.Current.Value
        Write-Host "`n=== PowerShell Output ==="
        Write-Host $text
        Write-Host "=== End ==="
    }
} else {
    Write-Host "`npsInput found: $($null -ne $psInput)"
    Write-Host "psExecute found: $($null -ne $psExecute)"
}

# Kill the IDE
$proc = Get-Process -Id $ide.Current.ProcessId -ErrorAction SilentlyContinue
if ($proc) { $proc.Kill() }
