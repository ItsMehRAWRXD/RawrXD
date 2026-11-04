param([Parameter(Mandatory)][string]$Exe,[Parameter(Mandatory)][string]$Sha256,[Parameter(Mandatory)][string]$EvidenceDir)
$ErrorActionPreference='Stop';Import-Module "$PSScriptRoot\RawrXD.UIA.psm1" -Force
$s=Start-RawrSession -Exe $Exe -Sha256 $Sha256 -EvidenceDir $EvidenceDir
$a='T05_A_A559_LONG_REQUEST_20261104';$b='T05_B_A559_SUCCESS_20261104'
try {
  $input=Find-RawrControl $s -AutomationId '1202';$send=Find-RawrControl $s -AutomationId '1204';$stop=Find-RawrControl $s -AutomationId '1210';$transcript=Find-RawrControl $s -AutomationId '1203'
  $model=Find-RawrControl $s -AutomationId '1206';$modelName=$model.Current.Name
  Set-RawrControlText $s $input "$a. Write a long technical essay about Windows debugging and continue generating."
  try{$promptReadback=Get-RawrControlText $s $input}catch{$promptReadback=''}
  if($promptReadback -notlike "*$a*"){throw "PROMPT_READBACK_FAILED model=$modelName"}
  $preStop=[bool]$stop.Current.IsEnabled;$sendState=[bool]$send.Current.IsEnabled;$sendHwnd=[IntPtr]$send.Current.NativeWindowHandle;$stopHwnd=[IntPtr]$stop.Current.NativeWindowHandle
  Invoke-RawrControl $s $send; $active=$false
  for($i=0;$i -lt 120;$i++){Start-Sleep -Milliseconds 500;$stop=Find-RawrControl $s -AutomationId '1210';if($stop.Current.IsEnabled){$active=$true;break}}
  if(-not $active){$out=[ordered]@{Gate='T05';Result='NOT_VERIFIED';CandidateSHA256=$s.SHA256;PID=$s.Pid;Model=$modelName;PromptReadback=$true;SendEnabled=$sendState;SendHwnd=('0x{0:X}' -f $sendHwnd.ToInt64());StopHwnd=('0x{0:X}' -f $stopHwnd.ToInt64());StopInitialEnabled=$preStop;StopEverEnabled=$false;Failure='STOP_NEVER_ENABLED';TimestampUtc=[DateTime]::UtcNow.ToString('o')};$out|ConvertTo-Json|Set-Content (Join-Path $EvidenceDir 'T05.receipt.json') -Encoding UTF8;throw 'STOP_NEVER_ENABLED'}
  Invoke-RawrControl $s $stop; Start-Sleep -Seconds 2
  Set-RawrControlText $s $input "$b. Reply exactly with this marker and nothing else: $b";Invoke-RawrControl $s $send
  $seen=$false
  for($i=0;$i -lt 180;$i++){Start-Sleep -Milliseconds 500;try{$text=Get-RawrControlText $s $transcript}catch{$text=''};if($text -like "*$b*"){$seen=$true;break}}
  $result=if($seen){'PASS'}else{'FAIL'};$out=[ordered]@{Gate='T05';Result=$result;CandidateSHA256=$s.SHA256;PID=$s.Pid;RequestA=$a;RequestB=$b;StopObserved=$active;BMarkerObserved=$seen;TimestampUtc=[DateTime]::UtcNow.ToString('o')};$out|ConvertTo-Json|Set-Content (Join-Path $EvidenceDir 'T05.receipt.json') -Encoding UTF8;$out|ConvertTo-Json
}catch{$out=[ordered]@{Gate='T05';Result='NOT_VERIFIED';CandidateSHA256=$s.SHA256;PID=$s.Pid;Error=$_.Exception.Message;TimestampUtc=[DateTime]::UtcNow.ToString('o')};$out|ConvertTo-Json|Set-Content (Join-Path $EvidenceDir 'T05.receipt.json') -Encoding UTF8;throw}
