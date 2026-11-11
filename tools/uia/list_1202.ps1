param([Parameter(Mandatory)][string]$Exe,[Parameter(Mandatory)][string]$Sha256,[Parameter(Mandatory)][string]$EvidenceDir)
Import-Module "$PSScriptRoot\RawrXD.UIA.psm1" -Force
$s=Start-RawrSession -Exe $Exe -Sha256 $Sha256 -EvidenceDir $EvidenceDir
$root=Get-RawrRoot $s
$all=$root.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
$out=@()
for($i=0;$i -lt $all.Count;$i++){try{$x=$all.Item($i);if($x.Current.AutomationId -eq '1202'){$out+=[pscustomobject]@{Name=$x.Current.Name;Class=$x.Current.ClassName;HWND=$x.Current.NativeWindowHandle;Rect=($x.Current.BoundingRectangle|Out-String).Trim();Enabled=$x.Current.IsEnabled;Offscreen=$x.Current.IsOffscreen;Process=$x.Current.ProcessId}}}catch{}}
$out|ConvertTo-Json -Depth 4
