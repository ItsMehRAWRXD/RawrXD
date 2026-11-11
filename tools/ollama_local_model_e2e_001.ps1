$ErrorActionPreference='Stop'
$root='F:\rawrxd'; $out=Join-Path $root 'evidence\OLLAMA_LOCAL_MODEL_E2E_001.json'
$tags=Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 20
$models=@($tags.models | Where-Object { $_.name -notmatch ':cloud$' } | ForEach-Object name | Sort-Object -Unique)
$results=[System.Collections.Generic.List[object]]::new()
foreach($model in $models){
  $sw=[Diagnostics.Stopwatch]::StartNew(); $row=[ordered]@{model=$model;status='FAIL';elapsed_ms=0;response='';error=''}
  try {
    $body=@{model=$model;prompt='Return exactly RAWRXD_MODEL_SMOKE_OK';stream=$false;options=@{temperature=0;num_predict=4}}|ConvertTo-Json -Compress
    $resp=Invoke-RestMethod 'http://127.0.0.1:11434/api/generate' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 120
    $text=[string]$resp.response; $row.response=($text -replace '\s+',' ').Trim(); $row.status=if($row.response -eq 'RAWRXD_MODEL_SMOKE_OK'){'PASS'}else{'FAIL_RESPONSE'}
  } catch { $row.status=if($_.Exception.Message -match 'timed out|timeout'){'TIMEOUT'}else{'ERROR'}; $row.error=$_.Exception.Message.Substring(0,[Math]::Min(240,$_.Exception.Message.Length)) }
  $sw.Stop(); $row.elapsed_ms=$sw.ElapsedMilliseconds; [void]$results.Add([pscustomobject]$row); Write-Output ("{0} {1} {2}ms" -f $model,$row.status,$row.elapsed_ms)
}
$pass=@($results|? status -eq PASS).Count; $fail=@($results|? status -ne PASS).Count
$receipt=[ordered]@{schema='RAWRXD_OLLAMA_LOCAL_MODEL_E2E_001';timestamp=(Get-Date).ToUniversalTime().ToString('o');endpoint='http://127.0.0.1:11434/api/generate';model_count=$models.Count;passed=$pass;failed=$fail;results=$results;verdict=if($fail -eq 0){'PASS'}else{'PARTIAL_NOT_CERTIFIED'}}
$receipt|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $out -Encoding UTF8
Write-Output ("SUMMARY models={0} passed={1} failed={2} receipt={3}" -f $models.Count,$pass,$fail,$out)
