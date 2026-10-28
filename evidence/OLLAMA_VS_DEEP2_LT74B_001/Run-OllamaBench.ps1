param([string]$Ev = 'G:\~dev\rawrxd\evidence\OLLAMA_VS_DEEP2_LT74B_001')
$ErrorActionPreference='Continue'
New-Item -ItemType Directory -Force -Path (Join-Path $Ev 'ollama') | Out-Null
$csv = Import-Csv (Join-Path $Ev 'ELIGIBLE_MODELS.csv')
$prompt = 'Say hi in one short sentence.'
$outCsv = Join-Path $Ev 'OLLAMA_MATRIX.csv'
"Name,ParamsB,EvalCount,EvalNs,PromptEvalCount,PromptEvalNs,TokPerSec,LoadDurNs,TotalMs,HttpOk,Disposition" | Set-Content $outCsv -Encoding ascii
# warmup server
curl.exe -s --max-time 5 http://127.0.0.1:11434/api/tags -o NUL
foreach ($r in $csv) {
  $name=$r.Name
  Write-Host "OLLAMA_BENCH $name"
  $safe = ($name -replace '[\\/:\*\?]','_')
  $bodyPath = Join-Path $Ev "ollama\$safe.body.json"
  $tmp = Join-Path $Ev "ollama\$safe.json"
  $bodyObj = [ordered]@{
    model = $name
    prompt = $prompt
    stream = $false
    options = [ordered]@{ num_predict = 32; temperature = 0 }
  }
  ($bodyObj | ConvertTo-Json -Compress -Depth 5) | Set-Content -LiteralPath $bodyPath -Encoding utf8NoBOM -ErrorAction SilentlyContinue
  if (-not (Test-Path $bodyPath)) {
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllText($bodyPath, ($bodyObj | ConvertTo-Json -Compress -Depth 5), $utf8)
  }
  $sw=[Diagnostics.Stopwatch]::StartNew()
  $cerr = Join-Path $Ev "ollama\$safe.curl.err"
  & curl.exe -sS --max-time 900 -H 'Content-Type: application/json' --data-binary "@$bodyPath" "http://127.0.0.1:11434/api/generate" -o $tmp 2>$cerr
  $sw.Stop()
  $line = "$name,$($r.ParamsB),0,0,0,0,0,0,$($sw.ElapsedMilliseconds),False,FAIL"
  try {
    if ((Test-Path $tmp) -and ((Get-Item $tmp).Length -gt 10)) {
      $j = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json
      $eval=[int64]$j.eval_count; $ens=[int64]$j.eval_duration
      $tps = if ($ens -gt 0) { [math]::Round(($eval * 1e9) / $ens, 3) } else { 0 }
      $ok = [bool]$j.done
      $disp = if ($ok -and $eval -gt 0) { 'PASS' } else { 'FAIL' }
      $line = "$name,$($r.ParamsB),$eval,$ens,$($j.prompt_eval_count),$($j.prompt_eval_duration),$tps,$($j.load_duration),$($sw.ElapsedMilliseconds),$ok,$disp"
    } else {
      $err = if (Test-Path $cerr) { Get-Content -Raw $cerr } else { 'empty' }
      Write-Host "FAIL empty response: $err"
    }
  } catch {
    Write-Host "PARSE_FAIL $_"
  }
  Add-Content $outCsv $line -Encoding ascii
  Write-Host $line
}
"OLLAMA_DONE $(Get-Date -Format o)" | Set-Content (Join-Path $Ev 'OLLAMA_DONE.txt')
Get-Content $outCsv