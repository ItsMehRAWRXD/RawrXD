$ErrorActionPreference='Stop'
$path='C:\Users\Garrett\.cursor\projects\g-dev\agent-transcripts\8b161a97-3488-42e8-aee5-01939be9ee3d\8b161a97-3488-42e8-aee5-01939be9ee3d.jsonl'
$outG='F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001\_extract_G_E_defs.txt'
$outS='F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001\_extract_swarm_GE.txt'
$reader=[System.IO.StreamReader]::new($path)
$n=0
while(($line=$reader.ReadLine()) -ne $null){
  $n++
  if($line -match 'Complete Remaining IDE Finalization Checklist' -and $line -match 'G01'){
    $obj=$line|ConvertFrom-Json
    $text=$obj.message.content[0].text
    $idx=$text.IndexOf('GUI')
    if($idx -lt 0){ $idx=$text.IndexOf('G01') }
    $end=$text.IndexOf('Agentic')
    if($end -lt 0){ $end=$text.IndexOf('A01') }
    if($end -lt 0){ $end=[Math]::Min($text.Length, $idx+12000) }
    $len=[Math]::Max(0,$end-$idx)
    if($len -gt 20000){ $len=20000 }
    [System.IO.File]::WriteAllText($outG, $text.Substring($idx,$len))
    Write-Output "WROTE_G_E n=$n len=$len"
  }
  if($line -match 'Use a swarm and agents to complete ALL' -and $line -match 'G01'){
    $obj=$line|ConvertFrom-Json
    $text=$obj.message.content[0].text
    $idx=$text.IndexOf('G01')
    $end=$text.IndexOf('A01')
    if($end -lt 0){ $end=$text.IndexOf('Agentic') }
    if($end -lt 0){ $end=[Math]::Min($text.Length,$idx+8000) }
    $len=[Math]::Max(0,$end-$idx)
    [System.IO.File]::WriteAllText($outS, $text.Substring([Math]::Max(0,$idx-200), $len+200))
    Write-Output "WROTE_SWARM n=$n len=$len"
  }
}
$reader.Close()
Write-Output 'DONE'
