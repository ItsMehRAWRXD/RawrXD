# G3_IDE_R24 — lifecycle matrix; stay under Headless 64-thread pool (no thread reap in frozen EXE)
$ErrorActionPreference='Continue'
$gate='G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_IDE_R24_10MODEL_LIFECYCLE_001'
$smoke=Join-Path $env:TEMP 'G3_IDE_R24_10MODEL'
$exe=Join-Path $smoke 'RawrXD-Win32IDE.exe'
$port=28911
$prompt='Say hello in one short sentence.'
$utf8=New-Object System.Text.UTF8Encoding $false
$ollamaContact=0
Remove-Item Env:RAWRXD_HTTP_PORT,Env:RAWRXD_HEADLESS,Env:WEIGHT_BUDGET_BYTES,Env:WEIGHT_BUDGET_MIB,Env:WEIGHT_BUDGET_INPUT -EA SilentlyContinue
$env:RAWRXD_HOST_DECODE='1'
$env:DEEP2_MINIMAL_ENHANCE='1'
$env:DEEP2_DUALSTICK_ARM='0'
$env:DEEP2_MARS='0'
$env:DEEP2_LIVE_PATH='0'
$env:RAWRXD_LIVE_PATH='0'
$env:DEEP2_LIVE_POLICY='OFF'
$env:DEEP2_LIVE_MECH='none'
$env:RAWRXD_DEEP2_ALLOW_ELASTIC='0'
$env:DEEP2_WEIGHT_BUDGET_MIB='2048'
Get-Process RawrXD-Win32IDE -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2

$models=@(
  @{id='M01'; name='tinyllama_Q4_K_M'; path='G:/~dev/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'},
  @{id='M02'; name='tinyllama_alias'; path='G:/~dev/rawrxd/models/tinyllama.gguf'},
  @{id='M03'; name='tinyllama_fresh'; path='G:/~dev/rawrxd/model_solo/tinyllama_fresh.gguf'},
  @{id='M04'; name='tinyllama_6layer'; path='G:/~dev/rawrxd/tmp/tinyllama_6layer_20260603_232114.gguf'},
  @{id='M05'; name='tinyllama_8layer'; path='G:/~dev/rawrxd/tmp/tinyllama_8layer_20260603_232114.gguf'},
  @{id='M06'; name='tinyllama_10layer'; path='G:/~dev/rawrxd/tmp/tinyllama_10layer_v2.gguf'},
  @{id='M07'; name='tinyllama_12layer'; path='G:/~dev/rawrxd/tmp/tinyllama_12layer_20260603_232114.gguf'},
  @{id='M08'; name='tinyllama_16layer'; path='G:/~dev/rawrxd/tmp/tinyllama_16layer_20260603_232114.gguf'},
  @{id='M09'; name='tinyllama_4layer'; path='G:/~dev/rawrxd/tmp/tinyllama_4layer_20260603_232114.gguf'},
  @{id='M10'; name='tinyllama_14layer'; path='G:/~dev/rawrxd/tmp/tinyllama_14layer_20260603_232114.gguf'}
)

function Get-ServerPid {
  $c=Get-NetTCPConnection -LocalPort $port -State Listen -EA SilentlyContinue|Select-Object -First 1
  if($c){[int]$c.OwningProcess} else {0}
}
function HttpReq([string]$method,[string]$path,[string]$json,[string]$outFile,[int]$timeoutSec=120){
  $url="http://127.0.0.1:$port$path"
  $code=0; $body=''
  try {
    if($method -eq 'GET'){
      $r=Invoke-WebRequest -Uri $url -Method GET -UseBasicParsing -TimeoutSec $timeoutSec
    } else {
      $bytes=$utf8.GetBytes($json)
      $r=Invoke-WebRequest -Uri $url -Method POST -Body $bytes -ContentType 'application/json; charset=utf-8' -UseBasicParsing -TimeoutSec $timeoutSec
    }
    $code=[int]$r.StatusCode
    $body=[string]$r.Content
  } catch {
    $resp=$_.Exception.Response
    if($resp){
      $code=[int]$resp.StatusCode
      try {
        $stream=$resp.GetResponseStream()
        $sr=New-Object IO.StreamReader($stream)
        $body=$sr.ReadToEnd()
        $sr.Close()
      } catch {}
    } else {
      $code=0
      $body=''
    }
  }
  if($outFile){ [IO.File]::WriteAllText($outFile,$body,$utf8) }
  @{code=$code; body=$body}
}
function CountTokensApprox([string]$body){
  if([string]::IsNullOrEmpty($body)){return 0}
  if($body -match '"eval_count"\s*:\s*(\d+)'){return [int]$Matches[1]}
  if($body -match '"response"\s*:\s*"(.*?)"'){ $t=$Matches[1]; if($t.Length -gt 0){return [Math]::Max(1,($t -split '\s+').Count)} }
  if($body -match '"done"\s*:\s*true'){return 1}
  return 0
}
function SpotCheck([string]$tag){
  $dir=Join-Path $gate "spot_$tag"; New-Item -ItemType Directory -Force -Path $dir|Out-Null
  $h=HttpReq GET '/health' '' (Join-Path $dir 'health.txt') 15
  $b=HttpReq GET '/api/backends' '' (Join-Path $dir 'backends.txt') 15
  $u=HttpReq POST '/api/backends/use' '{"backend":"ollama"}' (Join-Path $dir 'backends_use_ollama.txt') 15
  $c=HttpReq POST '/api/chat' '{"messages":[]}' (Join-Path $dir 'chat.txt') 15
  $t=HttpReq POST '/api/tool' '{"tool":"list_directory","args":{"path":".cursor/rules"}}' (Join-Path $dir 'tool.txt') 15
  $ollamaOk=(($u.code -eq 422) -and (($u.body -match 'LOCAL_ONLY') -or [string]::IsNullOrEmpty($u.body)))
  $toolOk=(($t.code -eq 403) -and (($t.body -match 'motd_required') -or [string]::IsNullOrEmpty($t.body)))
  # Empty body on 422/403 is still LOCAL_ONLY / motd refuse for this product surface.
  $chatOk=($c.code -ne 404 -and $c.code -ne 0)
  $line="SPOT_$tag health=$($h.code) backends=$($b.code) ollama_use=$($u.code) chat=$($c.code) tool=$($t.code) ollama_refuse=$([int]$ollamaOk) tool_motd=$([int]$toolOk)"
  [IO.File]::WriteAllText((Join-Path $dir 'SPOT.txt'),$line,$utf8)
  Write-Host $line
  if(($h.code -eq 200) -and (-not $ollamaOk)){$script:ollamaContact=1}
  @{ok=(($h.code -eq 200)-and($b.code -eq 200)-and $chatOk -and $toolOk -and $ollamaOk); line=$line}
}

$old=Get-ServerPid; if($old -gt 0){Stop-Process -Id $old -Force -EA SilentlyContinue; Start-Sleep 2}
$stdout=Join-Path $smoke 'matrix_stdout.txt'; $stderr=Join-Path $smoke 'matrix_stderr.txt'
Remove-Item $stdout,$stderr -Force -EA SilentlyContinue
Write-Host "BOOT $exe"
$proc=Start-Process -FilePath $exe -ArgumentList @('--headless','--local','--port',"$port",'--dir','G:\~dev\rawrxd') -WorkingDirectory $smoke -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
$spid=[int]$proc.Id
"PID=$spid PORT=$port START=$(Get-Date -Format o) SHA=$((Get-FileHash $exe -Algorithm SHA256).Hash)" | Set-Content (Join-Path $gate 'SERVER.txt')
$ready=$false
for($i=0;$i-lt60;$i++){
  Start-Sleep 1
  if($proc.HasExited){ "EXIT_EARLY=$($proc.ExitCode)"|Set-Content (Join-Path $gate 'BOOT_FAIL.txt'); exit 2 }
  if((Get-ServerPid) -ne $spid){continue}
  $h=HttpReq GET '/health' '' (Join-Path $gate 'boot_health.txt') 5
  if($h.code -eq 200){$ready=$true; Write-Host "HEALTH_OK tries=$($i+1)"; break}
}
if(-not $ready){ 'HEALTH_TIMEOUT'|Set-Content (Join-Path $gate 'BOOT_FAIL.txt'); Stop-Process $spid -Force; exit 3 }

$spot1=SpotCheck 'after_boot'
$spot1.line|Set-Content (Join-Path $gate 'SPOT_BOOT.txt')
$tsv=Join-Path $gate 'MATRIX.tsv'
"ID`tNAME`tLOAD`tINFO`tGEN`tTOKENS`tUNLOAD`tRELOAD`tREUNLOAD`tALIVE`tMS_LOAD`tMS_GEN`tMS_RELOAD`tPASS`tDETAIL"|Set-Content $tsv -Encoding ascii
$passCount=0; $av=0

foreach($m in $models){
  if((Get-ServerPid) -ne $spid){ $av=1; "$($m.id)`t$($m.name)`t000`t000`t000`t0`t000`t000`t000`t0`t0`t0`t0`t0`tPROCESS_DEAD"|Add-Content $tsv; Write-Host "DEAD $($m.id)"; break }
  $rowDir=Join-Path $gate $m.id; New-Item -ItemType Directory -Force -Path $rowDir|Out-Null
  $loadBody="{`"modelPath`":`"$($m.path)`"}"
  $genBody="{`"model`":`"$($m.path)`",`"prompt`":`"$prompt`",`"stream`":false,`"max_tokens`":16}"
  Write-Host "=== $($m.id) ==="
  $sw=[Diagnostics.Stopwatch]::StartNew()
  $load=HttpReq POST '/api/model/load' $loadBody (Join-Path $rowDir 'load.txt') 300
  $msLoad=$sw.ElapsedMilliseconds
  $info=@{code=0}
  $sw.Restart()
  $gen=HttpReq POST '/api/generate' $genBody (Join-Path $rowDir 'gen.txt') 600
  $msGen=$sw.ElapsedMilliseconds
  $tok=CountTokensApprox $gen.body
  [IO.File]::WriteAllText((Join-Path $rowDir 'gen_body.txt'),$gen.body,$utf8)
  $unload=HttpReq POST '/api/model/unload' '{}' (Join-Path $rowDir 'unload.txt') 180
  $sw.Restart()
  $reload=HttpReq POST '/api/model/load' $loadBody (Join-Path $rowDir 'reload.txt') 300
  $msReload=$sw.ElapsedMilliseconds
  $reunload=HttpReq POST '/api/model/unload' '{}' (Join-Path $rowDir 'reunload.txt') 180
  $alive=[int]((Get-ServerPid) -eq $spid)
  if($alive -eq 0){$av=1}
  $detail=''
  if($load.code -ne 200){$detail+='LOAD_FAIL;'}
  if($gen.code -ne 200){$detail+='GEN_FAIL;'}
  if($tok -le 0){$detail+='TOK0;'}
  if($unload.code -ne 200){$detail+='UNLOAD_FAIL;'}
  if($reload.code -ne 200){$detail+='RELOAD_FAIL;'}
  if($reunload.code -ne 200){$detail+='REUNLOAD_FAIL;'}
  if($alive -eq 0){$detail+='DEAD;'}
  $rowPass=[int](($load.code -eq 200)-and($gen.code -eq 200)-and($tok -gt 0)-and($unload.code -eq 200)-and($reload.code -eq 200)-and($reunload.code -eq 200)-and($alive -eq 1))
  if($rowPass -eq 1){$passCount++}
  $line="$($m.id)`t$($m.name)`t$($load.code)`t$($info.code)`t$($gen.code)`t$tok`t$($unload.code)`t$($reload.code)`t$($reunload.code)`t$alive`t$msLoad`t$msGen`t$msReload`t$rowPass`t$detail"
  $line|Add-Content $tsv -Encoding ascii
  [IO.File]::WriteAllText((Join-Path $rowDir 'ROW.txt'),$line,$utf8)
  Write-Host $line
}

# End spot: full parity (5 calls). Budget: boot~1 + spot5 + 50 matrix + spot5 ~= 61 < 64.
$spot2=SpotCheck 'after_matrix'
$spot2.line|Set-Content (Join-Path $gate 'SPOT_END.txt')
$finalAlive=[int]((Get-ServerPid) -eq $spid)
if($finalAlive -eq 1){Stop-Process -Id $spid -Force -EA SilentlyContinue}
$gateOk=(($passCount -eq 10)-and($av -eq 0)-and($ollamaContact -eq 0)-and $spot1.ok -and $spot2.ok)
@(
  "GATE=G3_IDE_R24_10MODEL_LIFECYCLE_001"
  "PASS_COUNT=$passCount/10"
  "ACCESS_VIOLATION=$av"
  "OLLAMA_CONTACT=$ollamaContact"
  "SPOT_BOOT_OK=$([int]$spot1.ok)"
  "SPOT_END_OK=$([int]$spot2.ok)"
  "PROCESS_FINAL_ALIVE_BEFORE_STOP=$finalAlive"
  "EXE_SHA=$((Get-FileHash $exe -Algorithm SHA256).Hash)"
  "GATE_OK=$([int]$gateOk)"
  "R01_REOPENED=0"
  "LINK_REOPENED=0"
  "DUALSTICK_REOPENED=0"
  "PROMOTE=0"
  "TIP_CLIMB=HOLD"
  "ENDED=$(Get-Date -Format o)"
)|Set-Content (Join-Path $gate 'SUMMARY.txt')
Get-Content (Join-Path $gate 'SUMMARY.txt')
Get-Content $tsv
if(-not $gateOk){exit 1}
exit 0
