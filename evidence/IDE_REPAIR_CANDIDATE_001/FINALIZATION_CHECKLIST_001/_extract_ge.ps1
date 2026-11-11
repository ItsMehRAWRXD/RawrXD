$ErrorActionPreference='Stop'
$path='C:\Users\Garrett\.cursor\projects\g-dev\agent-transcripts\8b161a97-3488-42e8-aee5-01939be9ee3d\8b161a97-3488-42e8-aee5-01939be9ee3d.jsonl'
$out='F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001\_checklist_extract.txt'
$reader=[System.IO.StreamReader]::new($path)
$i=0
$found=$false
while(($line=$reader.ReadLine()) -ne $null){
  $i++
  if($line -notmatch 'Use a swarm and agents to complete ALL'){ continue }
  $o=$line | ConvertFrom-Json
  $text=$o.message.content[0].text
  $keep=@()
  foreach($ln in ($text -split "`n")){
    if($ln -match '^(B|G|E|A|I|T|P|H)\d{2}\b' -or $ln -match '37E64080|theme|Editor|GUI |four-panel|Required completion'){
      $keep += $ln
    }
  }
  Set-Content -Path $out -Value ("LINE=$i LEN=$($text.Length)`r`n"+($keep -join "`r`n")) -Encoding UTF8
  Write-Output "WROTE keep=$($keep.Count)"
  $found=$true
  break
}
$reader.Close()
if(-not $found){ Write-Output 'NOT_FOUND' }
