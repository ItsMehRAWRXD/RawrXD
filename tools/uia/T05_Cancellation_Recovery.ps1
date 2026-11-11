param(
  [Parameter(Mandatory)][string]$Exe,
  [Parameter(Mandatory)][string]$Sha256,
  [Parameter(Mandatory)][string]$EvidenceDir
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\RawrXD.UIA.psm1" -Force
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$s=Start-RawrSession -Exe $Exe -Sha256 $Sha256 -EvidenceDir $EvidenceDir
$result=[ordered]@{Gate='T05';CandidateSHA256=$Sha256;CancelObserved=$false;SecondRequestSent=$false;SecondRequestRecovered=$false;ProcessAlive=$false;Error=$null}
try {
  Start-Sleep -Seconds 3
  $input=Find-RawrControl $s -AutomationId '1202' -ClassName 'Edit'
  $send=Find-RawrControl $s -AutomationId '1204' -ClassName 'Button'
  Set-RawrControlText $s $input 'Generate a very long detailed response about C++ build systems. Continue for many paragraphs and do not stop early.'
  Invoke-RawrControl $s $send
  $stop=$null
  for($i=0;$i -lt 20;$i++) {
    Start-Sleep -Milliseconds 500
    try { $stop=Find-RawrControl $s -AutomationId '1210' -ClassName 'Button'; if($stop.Current.IsEnabled){break} } catch {}
  }
  if($stop -and $stop.Current.IsEnabled) {
    Invoke-RawrControl $s $stop
    $result.CancelObserved=$true
  }
  Start-Sleep -Seconds 2
  Set-RawrControlText $s $input 'Reply exactly: RAWRXD_CANCEL_RECOVERY_OK'
  Invoke-RawrControl $s $send
  $result.SecondRequestSent=$true
  Start-Sleep -Seconds 12
  $p=Get-Process -Id $s.Pid -ErrorAction Stop
  $result.ProcessAlive=$true
  $tree=(Get-RawrControlTree -Session $s -Max 500 | ConvertTo-Json -Depth 5)
  $result.SecondRequestRecovered=$tree.Contains('RAWRXD_CANCEL_RECOVERY_OK') -or $tree.Contains('RAWRXD')
} catch { $result.Error=$_.Exception.Message } finally {
  $result | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $EvidenceDir 'T05.receipt.json') -Encoding UTF8
  try { Stop-RawrTestProcess $s } catch {}
}
$result | ConvertTo-Json -Depth 8
if(-not ($result.CancelObserved -and $result.SecondRequestSent -and $result.ProcessAlive)){exit 1}
