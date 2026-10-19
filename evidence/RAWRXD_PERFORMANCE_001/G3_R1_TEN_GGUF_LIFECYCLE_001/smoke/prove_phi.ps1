$ErrorActionPreference = 'Continue'
$ev = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001'
$smoke = Join-Path $ev 'smoke'
$exe = 'G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1matrix.exe'
$port = 11435
$base = "http://127.0.0.1:$port"
$model = (Join-Path 'G:\~dev\rawrxd\_r1_iso\02_phi3_mini' 'Phi-3-mini-4k-instruct-q8_0.gguf')

Get-Process -Name 'RawrXD*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2
$env:RAWRXD_HOST_DECODE='1'; $env:RAWRXD_FORCE_CPU_INFERENCE='1'
$env:DEEP2_MINIMAL_ENHANCE='1'; $env:DEEP2_DUALSTICK_ARM='0'; $env:RAWRXD_NO_VULKAN='1'
$out = Join-Path $smoke 'phi_prove.out.txt'; $err = Join-Path $smoke 'phi_prove.err.txt'
Remove-Item $out,$err -EA SilentlyContinue
$p = Start-Process -FilePath $exe -ArgumentList '--headless','--local','--port',"$port",'--dir','G:\~dev\rawrxd' -WorkingDirectory (Split-Path $exe) -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -WindowStyle Hidden
$ok=$false
for($i=0;$i -lt 60;$i++){ try { $h=Invoke-WebRequest "$base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 2; if($h.StatusCode -eq 200){$ok=$true;break} } catch {}; Start-Sleep 1 }
if(-not $ok){ 'HEALTH_FAIL'; exit 1 }
$sd=Join-Path $env:TEMP 'rawrxd_r1_bodies'; New-Item -ItemType Directory -Force -Path $sd|Out-Null
function P($path,$json,$name){
  $bf=Join-Path $sd $name; $of=Join-Path $smoke $name
  [IO.File]::WriteAllText($bf,$json)
  $code=& curl.exe -sS -o $of -w '%{http_code}' -X POST "$base$path" -H 'Content-Type: application/json' --data-binary "@$bf" --max-time 1800 2>$null
  $body=if(Test-Path $of){[IO.File]::ReadAllText($of)}else{''}
  Write-Host "$name CODE=$code LEN=$($body.Length)"
  Write-Host ($body.Substring(0,[Math]::Min(200,$body.Length)))
  return [int]$code
}
$lj=(@{model=$model;modelPath=$model;path=$model}|ConvertTo-Json -Compress)
$gj=(@{prompt='Reply with exactly: OK';stream=$false;options=@{num_predict=8}}|ConvertTo-Json -Compress)
$c1=P '/api/model/load' $lj 'phi_load.json'
$c2=P '/api/generate' $gj 'phi_gen1.json'
$c3=P '/api/model/unload' '{}' 'phi_unload.json'
$c4=P '/api/model/load' $lj 'phi_reload.json'
$c5=P '/api/generate' $gj 'phi_gen2.json'
$alive=[bool](Get-Process -Id $p.Id -EA SilentlyContinue)
Write-Host "FINAL ALIVE=$alive $c1/$c2/$c3/$c4/$c5"
Select-String -Path $err -Pattern 'CIE|ProductOpen|GENERATE_|armed' | Select-Object -Last 30 | ForEach-Object { $_.Line }
if($alive){ Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
if($c1 -eq 200 -and $c2 -eq 200 -and $c3 -eq 200 -and $c4 -eq 200 -and $c5 -eq 200 -and $alive){ exit 0 } else { exit 2 }
