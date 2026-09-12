param(
  [Parameter(Mandatory=$true)][int]$Pid,
  [Parameter(Mandatory=$true)][string]$OutFile,
  [int]$PollMs=100
)
$peakWs=0L; $peakPm=0L
while($true){
  $p=Get-Process -Id $Pid -ErrorAction SilentlyContinue
  if(-not $p){break}
  if($p.WorkingSet64 -gt $peakWs){$peakWs=$p.WorkingSet64}
  if($p.PrivateMemorySize64 -gt $peakPm){$peakPm=$p.PrivateMemorySize64}
  Start-Sleep -Milliseconds $PollMs
}
@("PEAK_WORKING_SET_BYTES=$peakWs","PEAK_PRIVATE_BYTES=$peakPm") | Set-Content $OutFile
