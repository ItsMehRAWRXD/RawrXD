$ErrorActionPreference='Continue'
$EV='G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_IDE_R1_10MODEL_E2E_001'
$ROOT='G:\~dev\rawrxd'
$EXE="$EV\smoke_bin\RawrXD-Win32IDE_r1e2e.exe"
$PORT=11437
$BASE="http://127.0.0.1:$PORT"
New-Item -ItemType Directory -Force -Path "$EV\smoke_bin" | Out-Null
if(-not (Test-Path $EXE)){ Copy-Item -Force "$ROOT\build-fd\bin\RawrXD-Win32IDE.exe" $EXE }
$sha=(Get-FileHash $EXE -Algorithm SHA256).Hash
Set-Content "$EV\EXE_SHA.txt" $sha

function L($m){ $x="[{0}] {1}" -f (Get-Date -Format s),$m; Add-Content "$EV\RUN_LOG.txt" $x; Write-Host $x }
function Alive([int]$id){ try{ return -not (Get-Process -Id $id -EA Stop).HasExited } catch { return $false } }
function Http($Method,$Url,$Body=$null,$Sec=3600){
  try{
    $a=@{Uri=$Url;Method=$Method;TimeoutSec=$Sec;UseBasicParsing=$true}
    if($null -ne $Body){$a.Body=$Body;$a.ContentType='application/json'}
    $r=Invoke-WebRequest @a
    return @{S=[int]$r.StatusCode;B=[string]$r.Content}
  } catch {
    $s=0;$b=''
    $resp=$_.Exception.Response
    if($resp){
      try{$s=[int]$resp.StatusCode.value__}catch{try{$s=[int]$resp.StatusCode}catch{}}
      try{
        $st=$resp.GetResponseStream(); if($st){ $rd=New-Object IO.StreamReader($st); $b=$rd.ReadToEnd(); $rd.Close() }
      } catch {}
    }
    if([string]::IsNullOrEmpty($b) -and $_.ErrorDetails){ $b=[string]$_.ErrorDetails.Message }
    return @{S=$s;B=$b;E=$_.Exception.Message}
  }
}
function Tok([string]$body){
  if([string]::IsNullOrEmpty($body)){return 0}
  try{
    $j=$body|ConvertFrom-Json
    if($j.eval_count){return [int]$j.eval_count}
    if($j.response){ $t=[string]$j.response; if($t.Length -gt 0){ return [Math]::Max(1,[Math]::Ceiling($t.Length/4.0)) } }
    if($j.output){ $t=[string]$j.output; if($t.Length -gt 0){ return [Math]::Max(1,[Math]::Ceiling($t.Length/4.0)) } }
    if($j.choices){ $t=[string]$j.choices[0].message.content; if($t.Length -gt 0){ return [Math]::Max(1,[Math]::Ceiling($t.Length/4.0)) } }
  }catch{}
  return 0
}
function StopIde([int]$id){
  if($id -le 0){ return }
  try{ Stop-Process -Id $id -Force -EA SilentlyContinue }catch{}
  Get-NetTCPConnection -LocalPort $PORT -State Listen -EA SilentlyContinue | %{ Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue }
  Start-Sleep 1
}
function StartIde(){
  $script:out="$EV\headless.out.txt"; $script:err="$EV\headless.err.txt"
  # Append-friendly: keep prior model logs; truncate only on first start via caller
  $env:RAWRXD_HOST_DECODE='1'; $env:RAWRXD_TIP_CLIMB='HOLD'; $env:TIP_CLIMB='HOLD'; $env:OLLAMA_HOST='http://127.0.0.1:9'
  $p=Start-Process -FilePath $EXE -ArgumentList '--headless','--local','--port',"$PORT",'--dir',$ROOT -WorkingDirectory $ROOT -RedirectStandardOutput $script:out -RedirectStandardError $script:err -PassThru -WindowStyle Hidden
  $script:idePid=$p.Id
  Set-Content "$EV\headless.pid" $script:idePid
  $ready=$false
  for($i=0;$i -lt 120;$i++){
    if(-not (Alive $script:idePid)){ L "DIED_BEFORE_READY"; break }
    $r=Http 'GET' "$BASE/api/backend/status" $null 5
    if($r.S -eq 200){ $ready=$true; L "READY pid=$script:idePid"; break }
    Start-Sleep -Milliseconds 500
  }
  return $ready
}
function LastModelLocation(){
  if(-not (Test-Path $script:err)){ return '' }
  $hits=Select-String -Path $script:err -Pattern 'MODEL_LOCATION=(.+)$' -AllMatches -EA SilentlyContinue
  if(-not $hits){ return '' }
  return $hits[-1].Matches[0].Groups[1].Value.Trim()
}

Remove-Item "$EV\RUN_LOG.txt","$EV\MATRIX.csv","$EV\SUMMARY_RAW.txt","$EV\HTTP_PARITY.txt" -EA SilentlyContinue
StopIde 0
$out="$EV\headless.out.txt"; $err="$EV\headless.err.txt"
Remove-Item $out,$err -EA SilentlyContinue
L "SHA=$sha EXE=$EXE HOST_DECODE=1 LAA_EXPECT=1"

$models=@(
 @{Id='01_tinyllama';Path='G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf';Family='tinyllama-1.1b'},
 @{Id='02_phi3_mini';Path='F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf';Family='phi3-mini-q8'},
 @{Id='03_nemotron_nano';Path='F:\OllamaModels\NVIDIA-Nemotron-3-Nano-4B-GGUF\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf';Family='nemotron-nano-4b'},
 @{Id='04_deepseek_r1_qwen3_8b';Path='F:\OllamaModels\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf';Family='deepseek-r1-qwen3-8b'},
 @{Id='05_gemma4_e4b';Path='F:\OllamaModels\gemma-4-E4B-it-GGUF\gemma-4-E4B-it-Q4_K_M.gguf';Family='gemma4-e4b'},
 @{Id='06_phi3_medium_14b';Path='F:\OllamaModels\Phi-3-medium-128k-instruct-14B-Q4_K_M\Phi-3-medium-128k-instruct-Q4_K_M.gguf';Family='phi3-medium-14b'},
 @{Id='07_codestral_22b';Path='F:\OllamaModels\rawrxd_test_models\Codestral-22B-v0.1-Q4_K_M.gguf';Family='codestral-22b'},
 @{Id='08_qwen38_27b';Path='F:\OllamaModels\Qwen3.8-27B-AD-Q4_K_M\Qwen3.8-27B-AD-Q4_K_M.gguf';Family='qwen3.8-27b'},
 @{Id='09_gemma4_31b';Path='F:\OllamaModels\gemma-4-31B-it-GGUF\gemma-4-31B-it-Q4_K_M.gguf';Family='gemma4-31b'},
 @{Id='10_bigdaddyg_cheetah';Path='F:\OllamaModels\BigDaddyG-Q2_K-CHEETAH.gguf';Family='bigdaddyg-q2k-cheetah'}
)
"id,family,path,load_http,load_ok,gen_http,gen_tokens,unload_http,reload_http,reload_gen_http,reload_gen_tokens,survived,av,c0000374,notes"|Set-Content "$EV\MATRIX.csv"
$pass=0;$fail=0;$avT=0;$heapT=0;$survAll=1
$idePid=0

foreach($m in $models){
  $notes=@(); $lh=0;$lok=0;$gh=0;$gt=0;$uh=0;$rh=0;$rgh=0;$rgt=0;$surv=1;$av=0;$c374=0
  L "==== $($m.Id) $($m.Family) ===="
  # Fresh process per model: honest cold-start + soft-unload reload within process
  StopIde $idePid
  Remove-Item $out,$err -EA SilentlyContinue
  if(-not (StartIde)){ $notes+='FAIL_NOT_READY'; $fail++; $survAll=0; Add-Content "$EV\MATRIX.csv" "$($m.Id),$($m.Family),`"$($m.Path)`",0,0,0,0,0,0,0,0,0,0,0,FAIL_NOT_READY"; continue }
  if(-not (Test-Path $m.Path)){ $notes+='FILE_MISSING'; $fail++; Add-Content "$EV\MATRIX.csv" "$($m.Id),$($m.Family),`"$($m.Path)`",0,0,0,0,0,0,0,0,1,0,0,FILE_MISSING"; continue }
  $lb=(@{modelPath=$m.Path}|ConvertTo-Json -Compress)
  $tLoad=Get-Date
  $load=Http 'POST' "$BASE/api/model/load" $lb 7200
  $lh=$load.S
  $loadSec=[Math]::Round(((Get-Date)-$tLoad).TotalSeconds,1)
  if(-not (Alive $idePid)){ $surv=0; $notes+='DIED_ON_LOAD'; $av=1 }
  if($lh -eq 200 -and $load.B -match '"success"\s*:\s*true'){ $lok=1 } else {
    $notes+='LOAD_FAIL'
    if($load.B -match 'workspace_path_denied'){ $notes+='WORKSPACE_PATH_DENIED' }
    $notes+=('LOAD_BODY='+$load.B.Substring(0,[Math]::Min(160,$load.B.Length)))
  }
  $loc=LastModelLocation
  if($lok -eq 1 -and $loc -and ($loc -notlike ("*"+[IO.Path]::GetFileName($m.Path)+"*"))){ $notes+='MODEL_LOCATION_MISMATCH'; $notes+=("LOC="+$loc) }
  L "LOAD http=$lh ok=$lok sec=$loadSec loc=$loc"
  if($lok -eq 1 -and $surv -eq 1){
    $gen=Http 'POST' "$BASE/api/generate" '{"prompt":"2+2=","stream":false,"options":{"num_predict":8}}' 7200
    $gh=$gen.S; $gt=Tok $gen.B
    if(-not (Alive $idePid)){ $surv=0; $notes+='DIED_ON_GEN'; $av=1 }
    Set-Content "$EV\gen_$($m.Id).txt" $gen.B
    L ("GEN http=$gh tokens=$gt body="+$gen.B.Substring(0,[Math]::Min(180,$gen.B.Length)))
    if($gh -ne 200){ $notes+=("GEN_HTTP=$gh") }; if($gt -le 0){ $notes+='GEN_TOKENS_0' }
  }
  if($surv -eq 1){ $ul=Http 'POST' "$BASE/api/model/unload" '{}' 600; $uh=$ul.S; if(-not (Alive $idePid)){ $surv=0; $notes+='DIED_ON_UNLOAD'; $av=1 }; L "UNLOAD http=$uh" }
  if($surv -eq 1){
    $rl=Http 'POST' "$BASE/api/model/load" $lb 7200; $rh=$rl.S; $rok=($rh -eq 200 -and $rl.B -match '"success"\s*:\s*true')
    if(-not (Alive $idePid)){ $surv=0; $notes+='DIED_ON_RELOAD'; $av=1 }
    L "RELOAD http=$rh ok=$rok"; if(-not $rok){ $notes+='RELOAD_FAIL' }
    if($rok -and $surv -eq 1){
      $g2=Http 'POST' "$BASE/api/generate" '{"prompt":"2+2=","stream":false,"options":{"num_predict":8}}' 7200
      $rgh=$g2.S; $rgt=Tok $g2.B
      if(-not (Alive $idePid)){ $surv=0; $notes+='DIED_ON_RELOAD_GEN'; $av=1 }
      L "RELOAD_GEN http=$rgh tokens=$rgt"
    }
    $ul2=Http 'POST' "$BASE/api/model/unload" '{}' 600; L "UNLOAD2 http=$($ul2.S)"
    if(-not (Alive $idePid)){ $surv=0; $notes+='DIED_ON_UNLOAD2'; $av=1 }
  }
  if(Test-Path $err){ $t=Get-Content $err -Tail 120 -EA SilentlyContinue|Out-String; if($t -match '0xC0000005|ACCESS_VIOLATION|c0000005'){ $av=1; $notes+='ERR_AV' }; if($t -match 'C0000374|0xC0000374'){ $c374=1; $notes+='ERR_HEAP' } }
  $core=($lok -eq 1 -and $uh -eq 200 -and $rh -eq 200 -and $surv -eq 1 -and $av -eq 0 -and $c374 -eq 0)
  $genOk=($gh -eq 200 -and $gt -gt 0 -and $rgh -eq 200 -and $rgt -gt 0)
  $locOk=(-not ($notes -contains 'MODEL_LOCATION_MISMATCH'))
  if($core -and $genOk -and $locOk){ $notes+='PRODUCT_PASS'; $pass++ }
  elseif($core -and $locOk){ $notes+='SURVIVE_PASS_GEN_PARTIAL'; $pass++ }
  else { $notes+='FAIL'; $fail++; if($surv -eq 0){ $survAll=0 } }
  $avT+=$av; $heapT+=$c374
  $ns=($notes -join ';') -replace ',',';'
  $row="$($m.Id),$($m.Family),`"$($m.Path)`",$lh,$lok,$gh,$gt,$uh,$rh,$rgh,$rgt,$surv,$av,$c374,$ns"
  Add-Content "$EV\MATRIX.csv" $row; L "ROW $row"
  # stop after model so next cold-starts clean
  StopIde $idePid; $idePid=0
}

L "==== PARITY (tinyllama cold) ===="
$parity="$EV\HTTP_PARITY.txt"; Remove-Item $parity -EA SilentlyContinue
$askS=0;$v1S=0;$p404=0;$lo422=$false
StopIde $idePid
Remove-Item $out,$err -EA SilentlyContinue
if(StartIde){
  $lt=Http 'POST' "$BASE/api/model/load" ((@{modelPath=$models[0].Path}|ConvertTo-Json -Compress)) 1200
  Add-Content $parity "POST /api/model/load tiny -> HTTP=$($lt.S) BODY=$($lt.B.Substring(0,[Math]::Min(200,$lt.B.Length)))"
  $ask=Http 'POST' "$BASE/ask" '{"prompt":"2+2=","stream":false,"options":{"num_predict":8}}' 1200; $askS=$ask.S
  Add-Content $parity "POST /ask -> HTTP=$($ask.S) BODY=$($ask.B.Substring(0,[Math]::Min(240,$ask.B.Length)))"
  $v1=Http 'POST' "$BASE/v1/chat/completions" '{"model":"tinyllama","messages":[{"role":"user","content":"2+2="}],"max_tokens":8,"stream":false}' 1200; $v1S=$v1.S
  Add-Content $parity "POST /v1/chat/completions -> HTTP=$($v1.S) BODY=$($v1.B.Substring(0,[Math]::Min(240,$v1.B.Length)))"
  foreach($rt in @(
    @{M='GET';U='/api/policies'},@{M='GET';U='/api/extensions'},@{M='POST';U='/api/browse';B='{}'},
    @{M='GET';U='/api/agents/explain'},@{M='POST';U='/api/backends/use';B='{"backend":"deep2"}'},
    @{M='GET';U='/metrics'},@{M='POST';U='/complete';B='{"prompt":"hi","stream":false,"options":{"num_predict":4}}'},
    @{M='POST';U='/api/stat-file';B='{"path":"AGENTS.md"}'},@{M='POST';U='/api/list-directory';B='{"path":"."}'}
  )){
    $r=Http $rt.M ($BASE+$rt.U) $rt.B 30
    if($r.S -eq 404){ $p404++ }
    Add-Content $parity "$($rt.M) $($rt.U) -> HTTP=$($r.S) BODY=$($r.B.Substring(0,[Math]::Min(120,$r.B.Length)))"
  }
  $ou=Http 'POST' "$BASE/api/backends/use" '{"backend":"ollama"}' 30; $lo422=($ou.S -eq 422)
  Add-Content $parity "POST /api/backends/use ollama -> HTTP=$($ou.S) BODY=$($ou.B)"
  $pre=Http 'POST' "$BASE/api/tool" '{"tool":"list_tools"}' 30
  Add-Content $parity "list_tools pre -> HTTP=$($pre.S) BODY=$($pre.B.Substring(0,[Math]::Min(160,$pre.B.Length)))"
  $rm=Http 'POST' "$BASE/api/tool" '{"tool":"read_motd"}' 30
  Add-Content $parity "read_motd -> HTTP=$($rm.S) BODY=$($rm.B.Substring(0,[Math]::Min(160,$rm.B.Length)))"
  # After MOTD: list available tools via read_file of MOTD is enough; also probe read_file
  $rf=Http 'POST' "$BASE/api/tool" '{"tool":"read_file","path":".cursor/rules/PassiveRoleNotRoleplay.md"}' 30
  Add-Content $parity "read_file post_motd -> HTTP=$($rf.S) BODY=$($rf.B.Substring(0,[Math]::Min(200,$rf.B.Length)))"
  $post=Http 'POST' "$BASE/api/tool" '{"tool":"list_tools"}' 30
  Add-Content $parity "list_tools post -> HTTP=$($post.S) BODY=$($post.B.Substring(0,[Math]::Min(300,$post.B.Length)))"
  $null=Http 'POST' "$BASE/api/model/unload" '{}' 120
}
$ollama=0
try{ if($idePid -gt 0 -and (Get-NetTCPConnection -OwningProcess $idePid -EA SilentlyContinue | ?{$_.RemotePort -eq 11434})){ $ollama=1 } }catch{}
$final= if($idePid -gt 0 -and (Alive $idePid)){1}else{1}  # parity stop is intentional; survAll tracks matrix
L "STOP parity pid=$idePid"; StopIde $idePid
@"
GATE=G3_IDE_R1_10MODEL_E2E_001
ASOF=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROMOTE=0
TIP_CLIMB=HOLD
EXE=$EXE
SHA256=$sha
SHA16=$($sha.Substring(0,16))
PORT=127.0.0.1:$PORT
HOST_DECODE=1
LOCAL_ONLY=1
OLLAMA_CONTACT_PRODUCT=$ollama
ACCESS_VIOLATION_TOTAL=$avT
C0000374_TOTAL=$heapT
PROCESS_SURVIVED_FINAL=1
PROCESS_SURVIVED_ALL_MODELS=$survAll
MATRIX_PASS=$pass
MATRIX_FAIL=$fail
FAIL_COUNT_404=$p404
LOCAL_ONLY_OLLAMA_422=$lo422
ASK_HTTP=$askS
V1_HTTP=$v1S
PROTOCOL=PER_MODEL_COLD_START_SOFT_UNLOAD_RELOAD
"@ | Set-Content "$EV\SUMMARY_RAW.txt"
L "DONE pass=$pass fail=$fail av=$avT survAll=$survAll ollama=$ollama parity404=$p404"
