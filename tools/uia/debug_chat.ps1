Import-Module "$PSScriptRoot\RawrXD.UIA.psm1" -Force
$s=Start-RawrSession -Exe $args[0] -Sha256 $args[1] -EvidenceDir $args[2]
$e=Find-RawrControl $s -AutomationId '1202'
$before=Get-RawrNativeDiagnostics $s $e
Set-RawrControlText $s $e 'T05_INPUT_DIAGNOSTIC_MARKER'
Start-Sleep -Milliseconds 300
$after=Get-RawrNativeDiagnostics $s $e
[pscustomobject]@{Before=$before;After=$after}|ConvertTo-Json -Depth 5
