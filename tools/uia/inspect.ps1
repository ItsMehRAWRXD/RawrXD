param([Parameter(Mandatory)][string]$Exe,[Parameter(Mandatory)][string]$Sha256,[string]$EvidenceDir='.evidence-uia')
$ErrorActionPreference='Stop';Import-Module "$PSScriptRoot\RawrXD.UIA.psm1" -Force
$s=Start-RawrSession -Exe $Exe -Sha256 $Sha256 -EvidenceDir $EvidenceDir
try{$tree=@(Get-RawrControlTree $s);$tree|ConvertTo-Json -Depth 5|Set-Content (Join-Path $s.EvidenceDir 'controls.json') -Encoding UTF8;$shot=Save-RawrScreenshot $s -Name initial-window;Write-Host "PID=$($s.Pid) controls=$($tree.Count) screenshot=$($shot.Path)";Write-RawrReceipt $s 'DISCOVERY' 'NOT_VERIFIED' 'UIA tree captured; gate-specific acceptance not executed' @{Screenshot=$shot.Path;ControlTree='controls.json'}}catch{Write-RawrReceipt $s 'DISCOVERY' 'FAIL' $_.Exception.Message;throw}
